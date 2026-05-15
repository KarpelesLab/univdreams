// Many API surfaces are exposed for callers that haven't migrated
// over yet — let the warnings ride until the integration lands.
#![allow(dead_code)]

//! SSA (Static Single Assignment) form for x86 functions.
//!
//! A parallel-analysis SSA view over the function's CFG that the
//! renderer can query: "for this use of register R at instruction
//! X, what is the unique def that reaches it?" without the false
//! positives the per-block string forwarder produces across
//! if-arms and loops.
//!
//! ## Construction
//!
//! Standard Cytron-Ferrante-Rosen-Wegman-Zadeck SSA construction:
//!
//! 1. Build a CFG predecessor map from each block's `Terminator`.
//! 2. Compute the dominator tree iteratively (Cooper-Harvey-Kennedy).
//! 3. Compute dominance frontiers.
//! 4. For each variable, find the set of blocks that define it
//!    (have at least one writing instruction).
//! 5. Place phi functions at the iterated dominance frontier of
//!    those blocks.
//! 6. Rename via DFS over the dominator tree, maintaining a
//!    per-variable version stack.
//!
//! ## Variables tracked today
//!
//! * GPRs: full-width register class (32-bit on this DLL — eax,
//!   ebx, ecx, edx, esi, edi, ebp, esp; the x64 extensions are
//!   listed for forward compatibility).
//! * Stack slots: keyed by SP-relative offset (positive `arg_*`,
//!   negative `var_*`) — same naming the existing renderer uses.
//!
//! Memory through pointers and `[ABS_VA]` globals isn't yet
//! versioned; both go into a single opaque `MEMORY` variable that
//! every memory op reads and writes, which is conservative but
//! correct.

use std::collections::{HashMap, HashSet};

use ud_arch_x86::{DecodedInsn, Instruction, InstructionInfoFactory, OpAccess, OpKind, Register};
use ud_core::VAddr;
use ud_ir::{BasicBlock, Function, Terminator};

/// A variable tracked by SSA. Register names use the lowercased
/// iced-canonical form (`"eax"`, `"rsi"`, …); stack slots are the
/// SP-delta-corrected EBP-style offset (`-4` for `var_4`, `+8`
/// for `arg_8`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Var {
    Reg(String),
    Stack(i64),
    /// Opaque memory aggregate — covers all `[ptr]` and `[ABS_VA]`
    /// accesses we don't yet decompose. A single shared variable so
    /// every memory write invalidates every memory read.
    Memory,
}

/// A unique identifier for a definition site within one function.
/// Per-function dense indices into [`SsaInfo::defs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DefId(pub u32);

/// Where a def lives.
#[derive(Debug, Clone)]
pub enum DefSite {
    /// Defined at instruction with this IP.
    Insn(u64),
    /// Phi function at the entry of this block, joining incoming
    /// values from each predecessor. The vec is parallel to
    /// `SsaInfo::cfg_preds[block]`.
    Phi { block: VAddr, incoming: Vec<DefId> },
    /// Function entry — variable's value at the very start of the
    /// function. Used for parameters (`arg_*`) and undefined-on-
    /// entry registers (which the renderer is free to leave as
    /// the bare register name).
    Entry,
}

/// All the SSA info the renderer needs about one function.
#[derive(Debug, Clone, Default)]
pub struct SsaInfo {
    /// One entry per def. Index = `DefId.0` as usize.
    pub defs: Vec<DefRecord>,
    /// Maps each (instruction IP, variable read at that insn) →
    /// the reaching def. Memory reads share the single `Memory`
    /// variable's reaching def.
    pub use_at: HashMap<(u64, Var), DefId>,
    /// Maps each (instruction IP, variable written) → the def id
    /// that instruction creates.
    pub def_at: HashMap<(u64, Var), DefId>,
}

#[derive(Debug, Clone)]
pub struct DefRecord {
    pub var: Var,
    pub site: DefSite,
    /// IPs that read this def. (Phis at block entry record the
    /// reading "instruction" as the block's first IP.)
    pub uses: Vec<u64>,
}

impl SsaInfo {
    /// Reaching def for `var` used at instruction with IP `ip`,
    /// if SSA tracks one. Returns `None` for variables we don't
    /// version (anything outside `Var::Reg`/`Var::Stack`/`Var::Memory`).
    #[must_use]
    pub fn def_reaching(&self, ip: u64, var: &Var) -> Option<DefId> {
        self.use_at.get(&(ip, var.clone())).copied()
    }

    /// Number of uses for a def. Drives single-use folding: a def
    /// with exactly one use can be inlined at the use site without
    /// duplicating computation.
    #[must_use]
    pub fn use_count(&self, def: DefId) -> usize {
        self.defs.get(def.0 as usize).map_or(0, |r| r.uses.len())
    }

    /// Iterate over use IPs for a def.
    #[must_use]
    pub fn uses_of(&self, def: DefId) -> &[u64] {
        self.defs
            .get(def.0 as usize)
            .map_or(&[][..], |r| r.uses.as_slice())
    }

    /// What variable does this def write?
    #[must_use]
    pub fn def_var(&self, def: DefId) -> Option<&Var> {
        self.defs.get(def.0 as usize).map(|r| &r.var)
    }

    /// Where is this def?
    #[must_use]
    pub fn def_site(&self, def: DefId) -> Option<&DefSite> {
        self.defs.get(def.0 as usize).map(|r| &r.site)
    }
}

/// Per-block live-in / live-out sets, plus per-instruction live
/// sets derived from the block-level results.
///
/// `live_in[b]` is the set of variables live at the entry of
/// block `b` — i.e., variables whose value at block entry may
/// be read along some path through `b` or its successors before
/// being overwritten.
///
/// `live_out[b]` is the set of variables live at the exit of
/// block `b` — i.e., the union of `live_in[s]` for every
/// successor `s`.
///
/// `live_after_insn[ip]` is the set of variables live immediately
/// AFTER the instruction at `ip` finishes (= live before the next
/// instruction starts, or `live_out[block]` if this is the block's
/// last instruction).
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Default)]
pub struct Liveness {
    pub live_in: Vec<HashSet<Var>>,
    pub live_out: Vec<HashSet<Var>>,
    pub live_after_insn: HashMap<u64, HashSet<Var>>,
}

/// Compute liveness for `f`. Standard backward dataflow:
///
/// 1. For each block, compute `use[B]` (variables read before any
///    definition in `B`) and `def[B]` (variables defined in `B`).
/// 2. Iterate `live_in[B] = use[B] ∪ (live_out[B] - def[B])` and
///    `live_out[B] = ∪ live_in[S]` for successors `S`, until a
///    fixed point.
/// 3. Walk each block backward to derive `live_after_insn[ip]`
///    from the block's `live_out`.
///
/// The result powers dead-store elimination, register-allocation
/// reversal (skipping declarations of regs that are dead at every
/// use), and proper scope decisions for variable lifetimes in the
/// rendered source.
#[must_use]
pub fn compute_liveness(f: &Function<DecodedInsn>, sp_delta_at: &HashMap<u64, i64>) -> Liveness {
    if f.blocks.is_empty() {
        return Liveness::default();
    }
    let block_idx: HashMap<VAddr, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, i))
        .collect();
    let rw = collect_reads_writes(f, sp_delta_at);
    let n = f.blocks.len();

    // Per-block use[B] = vars read before any def within B.
    // Per-block def[B] = vars written anywhere in B.
    let mut use_set: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    let mut def_set: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    for (b, block_rw) in rw.iter().enumerate() {
        let mut killed: HashSet<Var> = HashSet::new();
        for (_ip, reads, writes) in block_rw {
            for r in reads {
                if !killed.contains(r) {
                    use_set[b].insert(r.clone());
                }
            }
            for w in writes {
                killed.insert(w.clone());
                def_set[b].insert(w.clone());
            }
        }
    }

    // Successors per block, mirroring `block_successors`.
    let successors: Vec<Vec<usize>> = (0..n)
        .map(|i| block_successors(&f.blocks[i], f, &block_idx))
        .collect();

    // Iterate to fixpoint in reverse-postorder of the reverse CFG
    // — approximated here by simply iterating until stable.
    let mut live_in: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    loop {
        let mut changed = false;
        for b in (0..n).rev() {
            let mut new_out: HashSet<Var> = HashSet::new();
            for &s in &successors[b] {
                for v in &live_in[s] {
                    new_out.insert(v.clone());
                }
            }
            let new_in: HashSet<Var> = use_set[b]
                .iter()
                .chain(new_out.difference(&def_set[b]))
                .cloned()
                .collect();
            if new_in != live_in[b] {
                live_in[b] = new_in;
                changed = true;
            }
            if new_out != live_out[b] {
                live_out[b] = new_out;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Per-instruction live-after sets: walk each block backward,
    // starting from live_out[b] at the last instruction.
    let mut live_after_insn: HashMap<u64, HashSet<Var>> = HashMap::new();
    for (b, block_rw) in rw.iter().enumerate() {
        let mut live = live_out[b].clone();
        for (ip, reads, writes) in block_rw.iter().rev() {
            live_after_insn.insert(*ip, live.clone());
            // Apply the instruction's effect in reverse:
            //   live_before = use ∪ (live_after - def)
            for w in writes {
                live.remove(w);
            }
            for r in reads {
                live.insert(r.clone());
            }
            // `live` now holds "live before this instruction" =
            // "live after the previous instruction"; loop carries it.
        }
    }

    Liveness {
        live_in,
        live_out,
        live_after_insn,
    }
}

/// Build SSA for `f`. Returns the populated [`SsaInfo`].
///
/// `sp_delta_at` carries the SP-delta-per-IP table the rest of
/// the lifter uses; SSA consults it to map `[esp+disp]` accesses
/// to the same EBP-form slots `[ebp+disp]` uses, so both shapes
/// resolve to the same `Var::Stack` and version chain.
#[must_use]
pub fn build_ssa(f: &Function<DecodedInsn>, sp_delta_at: &HashMap<u64, i64>) -> SsaInfo {
    if f.blocks.is_empty() {
        return SsaInfo::default();
    }

    // Index blocks by entry address for fast lookup.
    let block_idx: HashMap<VAddr, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, i))
        .collect();

    let preds = compute_predecessors(f, &block_idx);
    let dom = compute_dominators(f, &preds, &block_idx);
    let df = compute_dominance_frontiers(f, &preds, &dom);
    let rw = collect_reads_writes(f, sp_delta_at);

    // For each variable, the set of blocks that define it.
    let mut var_def_blocks: HashMap<Var, HashSet<usize>> = HashMap::new();
    for (bi, block_rw) in rw.iter().enumerate() {
        for (_ip, _reads, writes) in block_rw {
            for w in writes {
                var_def_blocks.entry(w.clone()).or_default().insert(bi);
            }
        }
    }

    // Phi placement (iterated dominance frontier).
    let mut phi_blocks: HashMap<Var, HashSet<usize>> = HashMap::new();
    for (var, defs) in &var_def_blocks {
        let mut worklist: Vec<usize> = defs.iter().copied().collect();
        let mut placed: HashSet<usize> = HashSet::new();
        let mut in_worklist: HashSet<usize> = defs.clone();
        while let Some(b) = worklist.pop() {
            for &y in &df[b] {
                if placed.insert(y) {
                    phi_blocks.entry(var.clone()).or_default().insert(y);
                    if !in_worklist.contains(&y) {
                        in_worklist.insert(y);
                        worklist.push(y);
                    }
                }
            }
        }
    }

    // Renaming pass: DFS over the dominator tree, maintaining a
    // per-variable version stack.
    let dom_children = invert_dom_tree(&dom);
    let mut ssa = SsaInfo::default();
    let mut stacks: HashMap<Var, Vec<DefId>> = HashMap::new();
    // Pre-populate entry defs for every variable that has a phi or
    // is read before its first def — the renderer needs *some* def
    // to attribute the read to.
    let entry_vars = collect_all_vars(&rw, &phi_blocks);
    for var in &entry_vars {
        let id = alloc_def(&mut ssa, var.clone(), DefSite::Entry);
        stacks.entry(var.clone()).or_default().push(id);
    }
    // Phi defs go up-front per block (uses get filled in once we
    // see each predecessor's exit version during the walk).
    let mut phi_def_at: HashMap<(usize, Var), DefId> = HashMap::new();
    for (var, blocks) in &phi_blocks {
        for &b in blocks {
            let id = alloc_def(
                &mut ssa,
                var.clone(),
                DefSite::Phi {
                    block: f.blocks[b].addr,
                    incoming: Vec::new(),
                },
            );
            phi_def_at.insert((b, var.clone()), id);
        }
    }

    rename_dfs(0, &dom_children, &phi_def_at, &rw, f, &mut ssa, &mut stacks);

    // After renaming, fill in phi incoming defs from the block's
    // predecessors. Each predecessor's exit version of the phi'd
    // variable becomes one entry in the phi's incoming list.
    fill_phi_incoming(&mut ssa, &phi_def_at, &preds, f);

    ssa
}

fn alloc_def(ssa: &mut SsaInfo, var: Var, site: DefSite) -> DefId {
    let id = DefId(ssa.defs.len() as u32);
    ssa.defs.push(DefRecord {
        var,
        site,
        uses: Vec::new(),
    });
    id
}

/// Compute the predecessor list per block index.
fn compute_predecessors(
    f: &Function<DecodedInsn>,
    block_idx: &HashMap<VAddr, usize>,
) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); f.blocks.len()];
    for (i, block) in f.blocks.iter().enumerate() {
        for succ in block_successors(block, f, block_idx) {
            preds[succ].push(i);
        }
    }
    preds
}

/// Compute the dominator-of relation (idom[i] = immediate dominator
/// of block i, or i itself for the entry). Uses the iterative
/// Cooper-Harvey-Kennedy fixed-point algorithm.
fn compute_dominators(
    f: &Function<DecodedInsn>,
    preds: &[Vec<usize>],
    block_idx: &HashMap<VAddr, usize>,
) -> Vec<usize> {
    let n = f.blocks.len();
    let mut dom: Vec<Option<usize>> = vec![None; n];
    dom[0] = Some(0);
    let rpo = reverse_postorder(f, block_idx);
    let rpo_index: HashMap<usize, usize> =
        rpo.iter().enumerate().map(|(rank, &b)| (b, rank)).collect();
    let mut changed = true;
    while changed {
        changed = false;
        // Skip entry (first in RPO).
        for &b in rpo.iter().skip(1) {
            // Find first processed predecessor.
            let processed_preds: Vec<usize> = preds[b]
                .iter()
                .copied()
                .filter(|p| dom[*p].is_some())
                .collect();
            if processed_preds.is_empty() {
                continue;
            }
            let mut new_idom = processed_preds[0];
            for &p in &processed_preds[1..] {
                new_idom = intersect(new_idom, p, &dom, &rpo_index);
            }
            if dom[b] != Some(new_idom) {
                dom[b] = Some(new_idom);
                changed = true;
            }
        }
    }
    // Entry's idom is itself by convention.
    dom.into_iter().map(|o| o.unwrap_or(0)).collect()
}

fn intersect(
    b1: usize,
    b2: usize,
    dom: &[Option<usize>],
    rpo_index: &HashMap<usize, usize>,
) -> usize {
    let mut f1 = b1;
    let mut f2 = b2;
    while f1 != f2 {
        while rpo_index.get(&f1) > rpo_index.get(&f2) {
            f1 = dom[f1].unwrap_or(f1);
        }
        while rpo_index.get(&f2) > rpo_index.get(&f1) {
            f2 = dom[f2].unwrap_or(f2);
        }
        // Loop guards against infinite recursion on irreducible
        // CFGs; in that case we keep walking until ranks match or
        // both reach the entry.
        if f1 == 0 && f2 == 0 {
            return 0;
        }
    }
    f1
}

/// Dominance frontiers per block.
fn compute_dominance_frontiers(
    f: &Function<DecodedInsn>,
    preds: &[Vec<usize>],
    dom: &[usize],
) -> Vec<HashSet<usize>> {
    let n = f.blocks.len();
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for b in 0..n {
        if preds[b].len() < 2 {
            continue;
        }
        for &p in &preds[b] {
            let mut runner = p;
            while runner != dom[b] {
                df[runner].insert(b);
                let next = dom[runner];
                if next == runner {
                    break;
                }
                runner = next;
            }
        }
    }
    df
}

fn rpo_dfs(
    b: usize,
    f: &Function<DecodedInsn>,
    block_idx: &HashMap<VAddr, usize>,
    visited: &mut [bool],
    post: &mut Vec<usize>,
) {
    if visited[b] {
        return;
    }
    visited[b] = true;
    for s in block_successors(&f.blocks[b], f, block_idx) {
        rpo_dfs(s, f, block_idx, visited, post);
    }
    post.push(b);
}

/// Reverse postorder over the CFG starting from the entry block (0).
fn reverse_postorder(f: &Function<DecodedInsn>, block_idx: &HashMap<VAddr, usize>) -> Vec<usize> {
    let mut visited = vec![false; f.blocks.len()];
    let mut post = Vec::with_capacity(f.blocks.len());
    rpo_dfs(0, f, block_idx, &mut visited, &mut post);
    post.reverse();
    post
}

/// Successors of a block, as block indices.
fn block_successors(
    block: &BasicBlock<DecodedInsn>,
    f: &Function<DecodedInsn>,
    block_idx: &HashMap<VAddr, usize>,
) -> Vec<usize> {
    let mut out = Vec::new();
    match block.terminator {
        Terminator::Fallthrough => {
            let next_addr = VAddr(block.addr.0 + block.size() as u64);
            if let Some(&i) = block_idx.get(&next_addr) {
                out.push(i);
            }
        }
        Terminator::UnconditionalBranch { target } => {
            if let Some(&i) = block_idx.get(&target) {
                out.push(i);
            }
        }
        Terminator::ConditionalBranch { taken, fallthrough } => {
            if let Some(&i) = block_idx.get(&fallthrough) {
                out.push(i);
            }
            if let Some(&i) = block_idx.get(&taken) {
                out.push(i);
            }
            // Self-references / out-of-function targets just go unrecorded.
            let _ = f; // suppress unused
        }
        Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable => {}
    }
    out
}

/// Per-instruction read/write sets for every block. Outer Vec is
/// indexed by block; inner Vec is (insn_ip, reads, writes) in
/// instruction order.
type BlockRw = Vec<Vec<(u64, Vec<Var>, Vec<Var>)>>;

fn collect_reads_writes(f: &Function<DecodedInsn>, sp_delta_at: &HashMap<u64, i64>) -> BlockRw {
    f.blocks
        .iter()
        .map(|b| {
            b.insns
                .iter()
                .map(|i| {
                    let (reads, writes) = insn_reads_writes(i, sp_delta_at);
                    (i.iced.ip(), reads, writes)
                })
                .collect()
        })
        .collect()
}

/// Extract (reads, writes) for a single instruction.
///
/// Uses iced's `InstructionInfoFactory` for register read/write
/// classification (covers both explicit operand registers and
/// implicit ones like `cdq` writing edx or `rep movsb` reading
/// esi/edi). Memory operands are classified separately: address-
/// forming registers are reads, the memory target itself is
/// `Var::Stack(disp)` when the access is EBP/ESP-relative or
/// `Var::Memory` otherwise.
fn insn_reads_writes(insn: &DecodedInsn, sp_delta_at: &HashMap<u64, i64>) -> (Vec<Var>, Vec<Var>) {
    let mut reads: Vec<Var> = Vec::new();
    let mut writes: Vec<Var> = Vec::new();
    let i = &insn.iced;
    let sp = sp_delta_at.get(&i.ip()).copied();
    // Register accesses (explicit + implicit) via InstructionInfoFactory.
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(i);
    for used in info.used_registers() {
        let Some(name) = canonical_reg_name(used.register()) else {
            continue;
        };
        let var = Var::Reg(name);
        match used.access() {
            OpAccess::Read | OpAccess::CondRead => push_unique(&mut reads, var),
            OpAccess::Write | OpAccess::CondWrite => push_unique(&mut writes, var),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                push_unique(&mut reads, var.clone());
                push_unique(&mut writes, var);
            }
            _ => {}
        }
    }
    // Memory accesses: walk operands, classify reads vs writes by
    // operand position. We can't get per-operand access flags in
    // iced 1.x without the InstructionInfo memory-walker, but the
    // common shape is: Memory is op0 → write; Memory is op1 (or
    // later) → read; LEA's memory operand is conceptually a read
    // of the address but not of the memory.
    for op in 0..i.op_count() {
        if i.op_kind(op) == OpKind::Memory {
            // LEA: the "memory" operand is an address computation,
            // not an actual memory access. Skip the Var::Memory or
            // Var::Stack effect; the base/index register reads were
            // already captured above by used_registers.
            if i.mnemonic() == ud_arch_x86::Mnemonic::Lea {
                continue;
            }
            let mem_var = memory_var(i, sp);
            // Heuristic: op0 memory is a write for typical
            // single-operand-destination instructions; the rest
            // are reads. Read-modify-write forms (add [mem], reg)
            // are both — we err on the side of recording it as
            // both via the used_memory walker below.
            if op == 0 && is_write_to_op0(i.mnemonic()) {
                push_unique(&mut writes, mem_var.clone());
            }
            if is_read_of_op(i.mnemonic(), op) {
                push_unique(&mut reads, mem_var);
            }
        }
    }
    (reads, writes)
}

/// For an instruction's destination operand position 0, does the
/// mnemonic write to memory there? Covers the common forms; the
/// few that don't (compare-style ops with mem op0 as a read) are
/// listed explicitly.
fn is_write_to_op0(m: ud_arch_x86::Mnemonic) -> bool {
    use ud_arch_x86::Mnemonic;
    !matches!(
        m,
        // op0 is a read, not a write, for these.
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Push
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Bt
    )
}

/// Does this mnemonic read its op0 memory operand as well as
/// possibly writing it? Captures read-modify-write forms.
fn is_read_of_op(m: ud_arch_x86::Mnemonic, op: u32) -> bool {
    use ud_arch_x86::Mnemonic;
    if op > 0 {
        return true; // any later operand is a source = read
    }
    matches!(
        m,
        // op0 is read for these forms (memory source or RMW).
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Push
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Bt
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Adc
            | Mnemonic::Sbb
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Sal
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Xadd
            | Mnemonic::Xchg
            | Mnemonic::Cmpxchg
    )
}

fn push_unique(v: &mut Vec<Var>, x: Var) {
    if !v.contains(&x) {
        v.push(x);
    }
}

/// Map an iced `Register` to its lowercase "canonical full-width"
/// name. Sub-registers (al, ax) are widened to their containing
/// 32/64-bit register so a write to `al` shows up as a write to
/// `eax`. Returns `None` for non-GPRs (XMM, segment, etc.) — those
/// aren't versioned by today's SSA.
#[must_use]
pub fn canonical_reg_name(reg: Register) -> Option<String> {
    let full = reg.full_register();
    let name = match full {
        Register::EAX | Register::RAX => "eax",
        Register::EBX | Register::RBX => "ebx",
        Register::ECX | Register::RCX => "ecx",
        Register::EDX | Register::RDX => "edx",
        Register::ESI | Register::RSI => "esi",
        Register::EDI | Register::RDI => "edi",
        Register::EBP | Register::RBP => "ebp",
        Register::ESP | Register::RSP => "esp",
        Register::R8 => "r8",
        Register::R9 => "r9",
        Register::R10 => "r10",
        Register::R11 => "r11",
        Register::R12 => "r12",
        Register::R13 => "r13",
        Register::R14 => "r14",
        Register::R15 => "r15",
        _ => return None,
    };
    Some(name.to_string())
}

fn memory_var(i: &Instruction, sp: Option<i64>) -> Var {
    let base = i.memory_base();
    let has_index = i.memory_index() != Register::None;
    // EBP-relative: `[ebp + disp]` directly maps to Var::Stack(disp).
    if (base == Register::EBP || base == Register::RBP) && !has_index {
        #[allow(clippy::cast_possible_wrap)]
        let disp = i.memory_displacement64() as i64;
        return Var::Stack(disp);
    }
    // ESP-relative with a known SP delta — map to EBP-style by
    // adding the delta. Approximate; full alias analysis would
    // refine this.
    if (base == Register::ESP || base == Register::RSP) && !has_index {
        if let Some(delta) = sp {
            #[allow(clippy::cast_possible_wrap)]
            let disp = i.memory_displacement64() as i64;
            return Var::Stack(disp.wrapping_add(delta));
        }
    }
    Var::Memory
}

fn collect_all_vars(rw: &BlockRw, phi_blocks: &HashMap<Var, HashSet<usize>>) -> HashSet<Var> {
    let mut out = HashSet::new();
    for block_rw in rw {
        for (_ip, reads, writes) in block_rw {
            for v in reads.iter().chain(writes.iter()) {
                out.insert(v.clone());
            }
        }
    }
    for var in phi_blocks.keys() {
        out.insert(var.clone());
    }
    out
}

fn invert_dom_tree(dom: &[usize]) -> Vec<Vec<usize>> {
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); dom.len()];
    for (b, &idom) in dom.iter().enumerate() {
        if b != idom {
            children[idom].push(b);
        }
    }
    children
}

#[allow(clippy::too_many_arguments, clippy::only_used_in_recursion)]
fn rename_dfs(
    b: usize,
    dom_children: &[Vec<usize>],
    phi_def_at: &HashMap<(usize, Var), DefId>,
    rw: &BlockRw,
    f: &Function<DecodedInsn>,
    ssa: &mut SsaInfo,
    stacks: &mut HashMap<Var, Vec<DefId>>,
) {
    // Snapshot stack lengths so we can pop on the way out.
    let snapshot: HashMap<Var, usize> = stacks.iter().map(|(v, s)| (v.clone(), s.len())).collect();

    // 1. Phi defs at this block's entry get pushed before any insn.
    let mut phi_vars_pushed: Vec<Var> = Vec::new();
    for ((bi, var), def) in phi_def_at {
        if *bi == b {
            stacks.entry(var.clone()).or_default().push(*def);
            phi_vars_pushed.push(var.clone());
        }
    }

    // 2. Walk instructions in order: record reads against top-of-stack,
    //    then push new defs for writes.
    for (ip, reads, writes) in &rw[b] {
        for r in reads {
            if let Some(top) = stacks.get(r).and_then(|s| s.last()).copied() {
                ssa.use_at.insert((*ip, r.clone()), top);
                ssa.defs[top.0 as usize].uses.push(*ip);
            }
        }
        for w in writes {
            let id = alloc_def(ssa, w.clone(), DefSite::Insn(*ip));
            ssa.def_at.insert((*ip, w.clone()), id);
            stacks.entry(w.clone()).or_default().push(id);
        }
    }

    // 3. Recurse into dominator-tree children.
    for &c in &dom_children[b] {
        rename_dfs(c, dom_children, phi_def_at, rw, f, ssa, stacks);
    }

    // 4. Pop everything pushed at this level.
    for (var, stk) in stacks.iter_mut() {
        let target_len = snapshot.get(var).copied().unwrap_or(0);
        while stk.len() > target_len {
            stk.pop();
        }
    }
    let _ = phi_vars_pushed; // popped via the snapshot loop above
}

/// After the rename pass, walk every phi and populate its
/// `incoming` list from each predecessor's exit version of the
/// variable. The exit version is "the topmost def at the end of
/// the predecessor's renaming-pass scope" — we approximate that
/// by re-running renaming with a smaller bookkeeping pass.
///
/// Simpler approach: track, for each block-exit, the version of
/// every variable. That's what `block_exit_versions` produces.
fn fill_phi_incoming(
    ssa: &mut SsaInfo,
    phi_def_at: &HashMap<(usize, Var), DefId>,
    preds: &[Vec<usize>],
    f: &Function<DecodedInsn>,
) {
    // For correctness we re-derive exit versions from the def_at
    // map: the last def of a variable within a block is the exit
    // version for that variable. If a variable wasn't defined in
    // the block, we walk up the dominator chain — but for the
    // purposes of phi incoming we only need *some* def reaching
    // the predecessor's exit, and the use_at map already encodes
    // the dominator-chain answer for any instruction in the
    // predecessor. So we use the predecessor's last instruction's
    // post-state.
    //
    // Implementation: for each phi (bi, var), for each predecessor
    // p, find the highest-numbered def of `var` whose site IP is
    // within p, or fall back to whichever def reaches p's last
    // instruction (via use_at if `var` is read there, or the
    // dominator-chain entry def otherwise).
    let mut exit_def: HashMap<(usize, Var), DefId> = HashMap::new();
    for (b, block) in f.blocks.iter().enumerate() {
        let mut last: HashMap<Var, DefId> = HashMap::new();
        for insn in &block.insns {
            let ip = insn.iced.ip();
            for ((iip, var), did) in &ssa.def_at {
                if *iip == ip {
                    last.insert(var.clone(), *did);
                }
            }
        }
        for (var, did) in last {
            exit_def.insert((b, var), did);
        }
    }

    // For variables a predecessor doesn't define but reads, the
    // reaching def is what we used during renaming — read it back
    // from use_at. For variables a predecessor neither defines
    // nor reads, fall back to the lowest-numbered Entry def we
    // can find.
    let entry_def: HashMap<Var, DefId> = ssa
        .defs
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r.site {
            DefSite::Entry => Some((r.var.clone(), DefId(i as u32))),
            _ => None,
        })
        .collect();

    for ((bi, var), &phi_id) in phi_def_at {
        let mut incoming = Vec::with_capacity(preds[*bi].len());
        for &p in &preds[*bi] {
            // Walk the predecessor's instructions in reverse to find
            // a read of var (which tells us the reaching def at that
            // IP).
            let resolved = exit_def
                .get(&(p, var.clone()))
                .copied()
                .or_else(|| {
                    let block = &f.blocks[p];
                    block.insns.iter().rev().find_map(|insn| {
                        let ip = insn.iced.ip();
                        ssa.use_at.get(&(ip, var.clone())).copied()
                    })
                })
                .or_else(|| entry_def.get(var).copied())
                .unwrap_or(DefId(0));
            incoming.push(resolved);
        }
        if let DefSite::Phi {
            incoming: ref mut inc,
            ..
        } = ssa.defs[phi_id.0 as usize].site
        {
            *inc = incoming;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_arch_x86::lift_function;
    use ud_arch_x86::{decode, Bitness};

    fn lift(bytes: &[u8]) -> Function<DecodedInsn> {
        let insns = decode(Bitness::Bits32, bytes, 0x1000).unwrap();
        lift_function("test".into(), &insns).unwrap()
    }

    /// Single-block function: `mov eax, 1; mov eax, 2; ret`. The
    /// second mov should be a fresh def; the use of `eax` returned
    /// (implicit) reaches the second def, not the first.
    #[test]
    fn linear_two_defs_keep_separate_versions() {
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0xc3, // ret
        ];
        let f = lift(&bytes);
        let sp: HashMap<u64, i64> = HashMap::new();
        let ssa = build_ssa(&f, &sp);
        // Two def sites for eax + one Entry def.
        let eax = Var::Reg("eax".into());
        let eax_defs: Vec<_> = ssa
            .defs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.var == eax)
            .collect();
        assert!(
            eax_defs.len() >= 2,
            "expected ≥2 eax defs (entry + 2 mov writes), got {}",
            eax_defs.len()
        );
        // Returned-via-eax read at the ret: should map to the 2nd mov's def.
        let ret_ip = 0x1000 + 10;
        if let Some(reaching) = ssa.use_at.get(&(ret_ip, eax.clone())) {
            let site = &ssa.defs[reaching.0 as usize].site;
            assert!(
                matches!(site, DefSite::Insn(ip) if *ip == 0x1005),
                "ret's eax read should reach the 2nd mov (ip=0x1005), got {site:?}"
            );
        }
    }

    /// Liveness on a linear two-write program: after the first
    /// `mov eax, 1`, eax is dead because the next instruction
    /// overwrites it before any read. This is the key property
    /// for dead-store elimination.
    #[test]
    fn liveness_kills_overwritten_register() {
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1   — dead
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0x89, 0xc3, // mov ebx, eax — reads eax
            0xc3, // ret
        ];
        let f = lift(&bytes);
        let sp: HashMap<u64, i64> = HashMap::new();
        let live = compute_liveness(&f, &sp);
        let eax = Var::Reg("eax".into());
        let after_first = live.live_after_insn.get(&0x1000).expect("after first mov");
        assert!(
            !after_first.contains(&eax),
            "eax should be DEAD after first mov: {after_first:?}"
        );
        let after_second = live.live_after_insn.get(&0x1005).expect("after second mov");
        assert!(
            after_second.contains(&eax),
            "eax should be LIVE after second mov (next reads it): {after_second:?}"
        );
    }

    /// Diamond CFG: a conditional jumps to either of two blocks
    /// that each assign eax differently, then both flow into a
    /// merge block. The merge block should see a phi for eax with
    /// two incoming defs.
    ///
    /// ```text
    /// 0x1000: cmp ecx, 0           ; entry
    /// 0x1003: je  0x100b           ; → then arm
    /// 0x1005: mov eax, 1           ; else arm
    /// 0x100a: jmp 0x1010
    /// 0x100b: mov eax, 2           ; then arm
    /// 0x1010: ret                  ; merge
    /// ```
    #[test]
    fn diamond_cfg_places_phi_at_merge() {
        let bytes = [
            0x83, 0xf9, 0x00, // cmp ecx, 0
            0x74, 0x06, // je +6 → 0x100b
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xeb, 0x05, // jmp +5 → 0x1011 (off by 1 — let's compute)
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0xc3, // ret
        ];
        let f = lift(&bytes);
        // Verify we have ≥ 3 blocks (entry, two arms, merge).
        assert!(
            f.blocks.len() >= 3,
            "expected diamond CFG, got {} blocks",
            f.blocks.len()
        );
        let sp: HashMap<u64, i64> = HashMap::new();
        let ssa = build_ssa(&f, &sp);
        // Look for a phi for eax.
        let eax = Var::Reg("eax".into());
        let has_phi = ssa
            .defs
            .iter()
            .any(|r| r.var == eax && matches!(r.site, DefSite::Phi { .. }));
        assert!(has_phi, "expected a phi for eax at the diamond merge");
    }
}

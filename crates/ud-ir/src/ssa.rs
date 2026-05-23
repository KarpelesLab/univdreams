//! Arch-agnostic SSA (Static Single Assignment) construction.
//!
//! Cytron-Ferrante-Rosen-Wegman-Zadeck SSA: CFG → dominators
//! (Cooper-Harvey-Kennedy) → dominance frontiers → phi
//! placement → DFS rename. Plus dataflow liveness for
//! consumers that need live-after-insn sets (dead-store
//! elimination, scope decisions).
//!
//! The algorithm is parametric over the instruction type
//! `I: ArchInsn` and a per-instruction reads/writes bridge.
//! The bridge is the only arch-specific decision the core
//! needs — everything else (CFG walk, dominator computation,
//! phi placement, rename, liveness dataflow) operates on the
//! IR's [`Function`] / [`Terminator`] / [`ArchInsn::addr`]
//! surface, which is already shape-agnostic.
//!
//! ## Variables tracked
//!
//! The [`Var`] enum models three classes of storage:
//!
//! * `Reg(String)` — a named register. Naming is the arch's
//!   choice; x86 uses lowercased iced full-width names
//!   (`"eax"`, `"rsi"`), BPF uses `"r0".."r10"`.
//! * `Stack(i64)` — a stack slot identified by a frame
//!   offset. x86 maps both `[ebp + N]` and SP-delta-corrected
//!   `[esp + M]` to the same EBP-relative offset; BPF maps
//!   `[r10 ± N]` directly.
//! * `Memory` — a single opaque aggregate covering every
//!   non-stack memory access. Conservative but correct:
//!   every memory write invalidates every memory read.
//!   Future refinement (per-aggregate / per-pointer
//!   versioning) plugs in here without touching the
//!   algorithmic core.
//!
//! ## Usage
//!
//! Each arch supplies a closure that classifies one
//! instruction's reads and writes:
//!
//! ```ignore
//! let rw = |insn: &MyInsn| -> (Vec<Var>, Vec<Var>) {
//!     // arch-specific extraction
//! };
//! let ssa = ud_ir::ssa::build_ssa(&function, rw);
//! let liveness = ud_ir::ssa::compute_liveness(&function, rw);
//! ```

use std::collections::{HashMap, HashSet};

use ud_core::VAddr;

use crate::{ArchInsn, BasicBlock, Function, Terminator};

/// A variable tracked by SSA.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Var {
    /// A named register. The string identity is the arch's
    /// canonical full-width name (so a write to `al`
    /// shows up as a write to `eax`).
    Reg(String),
    /// A stack slot identified by frame-relative offset.
    /// Sign convention: negatives are locals (`var_4` lives
    /// at `-4`), positives are call-frame args (`arg_8` at
    /// `+8`).
    Stack(i64),
    /// Opaque memory aggregate — covers every `[ptr]` and
    /// `[ABS_VA]` access the bridge can't decompose. A
    /// single shared variable so every memory write
    /// invalidates every memory read.
    Memory,
}

/// A unique identifier for a definition site within one
/// function. Per-function dense indices into [`SsaInfo::defs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DefId(pub u32);

/// Where a def lives.
#[derive(Debug, Clone)]
pub enum DefSite {
    /// Defined at the instruction with this IP.
    Insn(u64),
    /// Phi function at the entry of this block, joining
    /// incoming values from each predecessor. The vec is
    /// parallel to the block's predecessor list.
    Phi { block: VAddr, incoming: Vec<DefId> },
    /// Function entry — variable's value at the very start
    /// of the function. Used for parameters and undefined-
    /// on-entry registers (which the renderer is free to
    /// leave as the bare register name).
    Entry,
}

/// All the SSA info a consumer needs about one function.
#[derive(Debug, Clone, Default)]
pub struct SsaInfo {
    /// One entry per def. Index = `DefId.0` as usize.
    pub defs: Vec<DefRecord>,
    /// Maps each (instruction IP, variable read at that insn)
    /// → the reaching def. Memory reads share the single
    /// `Memory` variable's reaching def.
    pub use_at: HashMap<(u64, Var), DefId>,
    /// Maps each (instruction IP, variable written) → the
    /// def id that instruction creates.
    pub def_at: HashMap<(u64, Var), DefId>,
}

/// One def record.
#[derive(Debug, Clone)]
pub struct DefRecord {
    pub var: Var,
    pub site: DefSite,
    /// IPs that read this def. (Phis at block entry record
    /// the reading "instruction" as the block's first IP.)
    pub uses: Vec<u64>,
}

impl SsaInfo {
    /// Reaching def for `var` used at instruction with IP
    /// `ip`, if SSA tracks one. Returns `None` for variables
    /// the bridge doesn't surface.
    #[must_use]
    pub fn def_reaching(&self, ip: u64, var: &Var) -> Option<DefId> {
        self.use_at.get(&(ip, var.clone())).copied()
    }

    /// Number of uses for a def. Drives single-use folding.
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

/// Per-block live-in / live-out sets, plus per-instruction
/// live-after sets.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Default)]
pub struct Liveness {
    pub live_in: Vec<HashSet<Var>>,
    pub live_out: Vec<HashSet<Var>>,
    pub live_after_insn: HashMap<u64, HashSet<Var>>,
}

/// Per-instruction read/write sets for every block. Outer
/// Vec is indexed by block; inner Vec is `(insn_ip, reads,
/// writes)` in instruction order.
type BlockRw = Vec<Vec<(u64, Vec<Var>, Vec<Var>)>>;

/// Compute liveness for `f` using the per-instruction
/// reads/writes from `rw`. Standard backward dataflow.
#[must_use]
pub fn compute_liveness<I, F>(f: &Function<I>, rw: F) -> Liveness
where
    I: ArchInsn,
    F: Fn(&I) -> (Vec<Var>, Vec<Var>),
{
    if f.blocks.is_empty() {
        return Liveness::default();
    }
    let block_idx: HashMap<VAddr, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, i))
        .collect();
    let block_rw = collect_reads_writes(f, &rw);
    let n = f.blocks.len();

    // Per-block use[B] = vars read before any def within B.
    // Per-block def[B] = vars written anywhere in B.
    let mut use_set: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    let mut def_set: Vec<HashSet<Var>> = vec![HashSet::new(); n];
    for (b, brw) in block_rw.iter().enumerate() {
        let mut killed: HashSet<Var> = HashSet::new();
        for (_ip, reads, writes) in brw {
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

    let successors: Vec<Vec<usize>> = (0..n)
        .map(|i| block_successors(&f.blocks[i], &block_idx))
        .collect();

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

    let mut live_after_insn: HashMap<u64, HashSet<Var>> = HashMap::new();
    for (b, brw) in block_rw.iter().enumerate() {
        let mut live = live_out[b].clone();
        for (ip, reads, writes) in brw.iter().rev() {
            live_after_insn.insert(*ip, live.clone());
            for w in writes {
                live.remove(w);
            }
            for r in reads {
                live.insert(r.clone());
            }
        }
    }

    Liveness {
        live_in,
        live_out,
        live_after_insn,
    }
}

/// Build SSA for `f`. Returns the populated [`SsaInfo`].
#[must_use]
pub fn build_ssa<I, F>(f: &Function<I>, rw: F) -> SsaInfo
where
    I: ArchInsn,
    F: Fn(&I) -> (Vec<Var>, Vec<Var>),
{
    if f.blocks.is_empty() {
        return SsaInfo::default();
    }

    let block_idx: HashMap<VAddr, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr, i))
        .collect();

    let preds = compute_predecessors(f, &block_idx);
    let dom = compute_dominators(f, &preds, &block_idx);
    let df = compute_dominance_frontiers(&preds, &dom);
    let block_rw = collect_reads_writes(f, &rw);

    // For each variable, the set of blocks that define it.
    let mut var_def_blocks: HashMap<Var, HashSet<usize>> = HashMap::new();
    for (bi, brw) in block_rw.iter().enumerate() {
        for (_ip, _reads, writes) in brw {
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

    let dom_children = invert_dom_tree(&dom);
    let mut ssa = SsaInfo::default();
    let mut stacks: HashMap<Var, Vec<DefId>> = HashMap::new();
    let entry_vars = collect_all_vars(&block_rw, &phi_blocks);
    for var in &entry_vars {
        let id = alloc_def(&mut ssa, var.clone(), DefSite::Entry);
        stacks.entry(var.clone()).or_default().push(id);
    }
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

    rename_dfs(
        0,
        &dom_children,
        &phi_def_at,
        &block_rw,
        &mut ssa,
        &mut stacks,
    );
    fill_phi_incoming(&mut ssa, &phi_def_at, &preds, f);

    ssa
}

// ---------- internal helpers (all arch-agnostic) ----------

fn alloc_def(ssa: &mut SsaInfo, var: Var, site: DefSite) -> DefId {
    let id = DefId(ssa.defs.len() as u32);
    ssa.defs.push(DefRecord {
        var,
        site,
        uses: Vec::new(),
    });
    id
}

fn compute_predecessors<I: ArchInsn>(
    f: &Function<I>,
    block_idx: &HashMap<VAddr, usize>,
) -> Vec<Vec<usize>> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); f.blocks.len()];
    for (i, block) in f.blocks.iter().enumerate() {
        for succ in block_successors(block, block_idx) {
            preds[succ].push(i);
        }
    }
    preds
}

fn compute_dominators<I: ArchInsn>(
    f: &Function<I>,
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
        for &b in rpo.iter().skip(1) {
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
        if f1 == 0 && f2 == 0 {
            return 0;
        }
    }
    f1
}

fn compute_dominance_frontiers(preds: &[Vec<usize>], dom: &[usize]) -> Vec<HashSet<usize>> {
    let n = dom.len();
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

fn rpo_dfs<I: ArchInsn>(
    b: usize,
    f: &Function<I>,
    block_idx: &HashMap<VAddr, usize>,
    visited: &mut [bool],
    post: &mut Vec<usize>,
) {
    if visited[b] {
        return;
    }
    visited[b] = true;
    for s in block_successors(&f.blocks[b], block_idx) {
        rpo_dfs(s, f, block_idx, visited, post);
    }
    post.push(b);
}

fn reverse_postorder<I: ArchInsn>(
    f: &Function<I>,
    block_idx: &HashMap<VAddr, usize>,
) -> Vec<usize> {
    let mut visited = vec![false; f.blocks.len()];
    let mut post = Vec::with_capacity(f.blocks.len());
    rpo_dfs(0, f, block_idx, &mut visited, &mut post);
    post.reverse();
    post
}

fn block_successors<I: ArchInsn>(
    block: &BasicBlock<I>,
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
        }
        Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable => {}
    }
    out
}

fn collect_reads_writes<I, F>(f: &Function<I>, rw: &F) -> BlockRw
where
    I: ArchInsn,
    F: Fn(&I) -> (Vec<Var>, Vec<Var>),
{
    f.blocks
        .iter()
        .map(|b| {
            b.insns
                .iter()
                .map(|i| {
                    let (reads, writes) = rw(i);
                    (i.addr().0, reads, writes)
                })
                .collect()
        })
        .collect()
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

fn rename_dfs(
    b: usize,
    dom_children: &[Vec<usize>],
    phi_def_at: &HashMap<(usize, Var), DefId>,
    rw: &BlockRw,
    ssa: &mut SsaInfo,
    stacks: &mut HashMap<Var, Vec<DefId>>,
) {
    // Snapshot stack lengths so we can pop on the way out.
    let snapshot: HashMap<Var, usize> = stacks.iter().map(|(v, s)| (v.clone(), s.len())).collect();

    // 1. Phi defs at this block's entry get pushed before any insn.
    for ((bi, var), def) in phi_def_at {
        if *bi == b {
            stacks.entry(var.clone()).or_default().push(*def);
        }
    }

    // 2. Walk instructions in order: record reads against
    //    top-of-stack, then push new defs for writes.
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
        rename_dfs(c, dom_children, phi_def_at, rw, ssa, stacks);
    }

    // 4. Pop everything pushed at this level.
    for (var, stk) in stacks.iter_mut() {
        let target_len = snapshot.get(var).copied().unwrap_or(0);
        while stk.len() > target_len {
            stk.pop();
        }
    }
}

fn fill_phi_incoming<I: ArchInsn>(
    ssa: &mut SsaInfo,
    phi_def_at: &HashMap<(usize, Var), DefId>,
    preds: &[Vec<usize>],
    f: &Function<I>,
) {
    let mut exit_def: HashMap<(usize, Var), DefId> = HashMap::new();
    for (b, block) in f.blocks.iter().enumerate() {
        let mut last: HashMap<Var, DefId> = HashMap::new();
        for insn in &block.insns {
            let ip = insn.addr().0;
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
            let resolved = exit_def
                .get(&(p, var.clone()))
                .copied()
                .or_else(|| {
                    let block = &f.blocks[p];
                    block.insns.iter().rev().find_map(|insn| {
                        let ip = insn.addr().0;
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

    /// Minimal synthetic instruction for testing the generic
    /// algorithm without pulling in any arch crate. Carries
    /// pre-baked reads/writes and an address.
    #[derive(Debug, Clone)]
    struct TestInsn {
        addr: VAddr,
        reads: Vec<Var>,
        writes: Vec<Var>,
    }

    impl ArchInsn for TestInsn {
        fn addr(&self) -> VAddr {
            self.addr
        }
        fn original_bytes(&self) -> &[u8] {
            &[]
        }
        fn len_bytes(&self) -> usize {
            1
        }
    }

    fn rw(i: &TestInsn) -> (Vec<Var>, Vec<Var>) {
        (i.reads.clone(), i.writes.clone())
    }

    fn insn(addr: u64, reads: &[&str], writes: &[&str]) -> TestInsn {
        TestInsn {
            addr: VAddr(addr),
            reads: reads.iter().map(|s| Var::Reg((*s).into())).collect(),
            writes: writes.iter().map(|s| Var::Reg((*s).into())).collect(),
        }
    }

    fn block(addr: u64, insns: Vec<TestInsn>, term: Terminator) -> BasicBlock<TestInsn> {
        BasicBlock {
            addr: VAddr(addr),
            insns,
            terminator: term,
        }
    }

    fn func(blocks: Vec<BasicBlock<TestInsn>>) -> Function<TestInsn> {
        Function {
            addr: blocks.first().map_or(VAddr(0), |b| b.addr),
            name: "test".into(),
            blocks,
        }
    }

    #[test]
    fn empty_function_no_panic() {
        let f = func(Vec::new());
        let ssa = build_ssa(&f, rw);
        assert!(ssa.defs.is_empty());
        let live = compute_liveness(&f, rw);
        assert!(live.live_in.is_empty());
    }

    /// Linear single-block function. Two writes of `r0`
    /// produce two distinct defs; a read in the second
    /// instruction reaches the first def, not the entry.
    #[test]
    fn linear_two_defs_keep_separate_versions() {
        let f = func(vec![block(
            0,
            vec![
                insn(0, &[], &["r0"]),     // r0 = …
                insn(1, &["r0"], &["r1"]), // r1 = r0
                insn(2, &[], &["r0"]),     // r0 = …
                insn(3, &["r0"], &[]),     // (read r0)
            ],
            Terminator::Return,
        )]);
        let ssa = build_ssa(&f, rw);
        let r0 = Var::Reg("r0".into());
        // Read at ip=1 should reach the def at ip=0.
        let def_at_1 = ssa.use_at.get(&(1, r0.clone())).copied().expect("use at 1");
        assert!(
            matches!(
                ssa.defs[def_at_1.0 as usize].site,
                DefSite::Insn(ip) if ip == 0
            ),
            "expected ip=0 def to reach use at 1; got {:?}",
            ssa.defs[def_at_1.0 as usize].site
        );
        // Read at ip=3 should reach the def at ip=2 (NOT ip=0).
        let def_at_3 = ssa.use_at.get(&(3, r0)).copied().expect("use at 3");
        assert!(
            matches!(
                ssa.defs[def_at_3.0 as usize].site,
                DefSite::Insn(ip) if ip == 2
            ),
            "expected ip=2 def to reach use at 3; got {:?}",
            ssa.defs[def_at_3.0 as usize].site
        );
    }

    /// Diamond CFG: entry → {then, else} → merge. Both arms
    /// write r0; merge reads r0 — expect a phi.
    ///
    /// ```text
    ///   B0 (entry, cond branch)
    ///    ├── B1 (r0 = a) ──┐
    ///    └── B2 (r0 = b) ──┤
    ///                      ▼
    ///                    B3 (read r0; ret)
    /// ```
    #[test]
    fn diamond_cfg_places_phi_at_merge() {
        let f = func(vec![
            block(
                0,
                vec![insn(0, &["cond"], &[])],
                Terminator::ConditionalBranch {
                    taken: VAddr(20),
                    fallthrough: VAddr(10),
                },
            ),
            block(
                10,
                vec![insn(10, &[], &["r0"])],
                Terminator::UnconditionalBranch { target: VAddr(30) },
            ),
            block(
                20,
                vec![insn(20, &[], &["r0"])],
                Terminator::UnconditionalBranch { target: VAddr(30) },
            ),
            block(30, vec![insn(30, &["r0"], &[])], Terminator::Return),
        ]);
        let ssa = build_ssa(&f, rw);
        let r0 = Var::Reg("r0".into());
        let has_phi = ssa
            .defs
            .iter()
            .any(|r| r.var == r0 && matches!(r.site, DefSite::Phi { .. }));
        assert!(has_phi, "expected a phi for r0 at the diamond merge");
        // Read at ip=30 should resolve to the phi.
        let reaching = ssa.use_at.get(&(30, r0)).copied().expect("use at 30");
        assert!(
            matches!(ssa.defs[reaching.0 as usize].site, DefSite::Phi { .. }),
            "read at merge should reach the phi"
        );
    }

    /// Loop CFG: header dominates body, body back-edges to
    /// header. Header should get a phi for any variable
    /// written in the body.
    ///
    /// ```text
    ///   B0 (entry) ──┐
    ///                ▼
    ///                B1 (header, cond) ──→ B2 (exit)
    ///                ▲      │
    ///                │      ▼
    ///                └── B3 (body, r0 = …, jmp back)
    /// ```
    #[test]
    fn loop_back_edge_places_phi_at_header() {
        let f = func(vec![
            block(
                0,
                vec![insn(0, &[], &["r0"])], // initial def
                Terminator::Fallthrough,
            ),
            block(
                1,
                vec![insn(1, &["cond"], &[])],
                Terminator::ConditionalBranch {
                    taken: VAddr(2),
                    fallthrough: VAddr(3),
                },
            ),
            block(2, vec![insn(2, &[], &[])], Terminator::Return),
            block(
                3,
                vec![insn(3, &[], &["r0"])], // body redefines r0
                Terminator::UnconditionalBranch { target: VAddr(1) },
            ),
        ]);
        let ssa = build_ssa(&f, rw);
        let r0 = Var::Reg("r0".into());
        // Phi for r0 should land at the header (B1, addr=1).
        let phi_at_header = ssa.defs.iter().any(|r| {
            r.var == r0 && matches!(r.site, DefSite::Phi { block, .. } if block == VAddr(1))
        });
        assert!(
            phi_at_header,
            "expected a phi for r0 at the loop header (addr=1)"
        );
    }

    /// Liveness on a linear program: after an overwrite-
    /// before-read, the overwritten value is dead. This
    /// underwrites dead-store elimination.
    #[test]
    fn liveness_kills_overwritten_register() {
        let f = func(vec![block(
            0,
            vec![
                insn(0, &[], &["r0"]),     // r0 = … (dead — next overwrites)
                insn(1, &[], &["r0"]),     // r0 = …
                insn(2, &["r0"], &["r1"]), // r1 = r0
            ],
            Terminator::Return,
        )]);
        let live = compute_liveness(&f, rw);
        let r0 = Var::Reg("r0".into());
        let after_first = live.live_after_insn.get(&0).expect("after first");
        assert!(
            !after_first.contains(&r0),
            "r0 should be DEAD after first overwrite-before-read; got {after_first:?}"
        );
        let after_second = live.live_after_insn.get(&1).expect("after second");
        assert!(
            after_second.contains(&r0),
            "r0 should be LIVE after second write (next reads it); got {after_second:?}"
        );
    }

    /// Stack-slot Var lifetimes work the same as Reg ones —
    /// catches any accidental Reg-specific branching in the
    /// algorithm.
    #[test]
    fn stack_slots_get_versioned_too() {
        let f = func(vec![block(
            0,
            vec![
                TestInsn {
                    addr: VAddr(0),
                    reads: vec![],
                    writes: vec![Var::Stack(-4)],
                },
                TestInsn {
                    addr: VAddr(1),
                    reads: vec![Var::Stack(-4)],
                    writes: vec![Var::Reg("r0".into())],
                },
            ],
            Terminator::Return,
        )]);
        let ssa = build_ssa(&f, rw);
        let stack = Var::Stack(-4);
        let reach = ssa.use_at.get(&(1, stack)).copied().expect("use at 1");
        assert!(matches!(
            ssa.defs[reach.0 as usize].site,
            DefSite::Insn(ip) if ip == 0
        ));
    }
}

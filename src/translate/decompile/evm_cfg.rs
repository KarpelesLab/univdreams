//! Control-flow recovery for EVM bytecode: basic blocks, jump-target
//! resolution, internal functions, and frame-relative stack depths.
//!
//! EVM jumps take their target from the stack, and compiled
//! Solidity / Vyper uses that for everything: `if`, loops, and
//! internal calls, which push a return address before jumping to the
//! callee and come back with a `JUMP` to that address.
//!
//! 1. **Call seeds.** A block that pushes two `JUMPDEST` constants and
//!    jumps to the upper one (`PUSH ret; …args…; PUSH f; JUMP`) is a
//!    call: callee `f`, continuation `ret`, arguments = the items
//!    between them.
//! 2. **Per-function abstract interpretation.** Each function is
//!    analysed once, entered with `[ret, arg0, …]` where `ret` is a
//!    marker; the stack model tracks only `JUMPDEST` constants pushed
//!    inside the function. A `JUMP` to the marker is a return (its
//!    depth gives the return count); a `JUMP` to a constant is a
//!    local jump, or a further call when the constant is a known
//!    function entry with a return address below it. Call sites are
//!    summarised — the caller resumes at the continuation with the
//!    callee's return values — so analysis cost doesn't multiply
//!    along call chains. Rounds repeat until return counts and the
//!    call set stop changing.
//! 3. **Depths.** The same walk records each block's entry depth in
//!    its frame (slot 0 = the return address, then the arguments),
//!    giving every block a stable naming of its entry stack.

// Stack depths are bounded by the EVM's 1024-item limit, so the
// usize/i64 conversions between them can't wrap.
#![allow(clippy::cast_possible_wrap)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use crate::arch::evm::{DecodedInsn, InsnKind, OPCODE_TABLE, classify};

/// Distinct abstract entry stacks explored per block.
const MAX_STATES_PER_BLOCK: usize = 64;
/// Analysis rounds before giving up on a fixpoint.
const MAX_ROUNDS: usize = 32;
/// EVM stack limit.
const MAX_STACK: usize = 1024;
/// Arguments accepted below a spilled return address.
const MAX_BELOW: usize = 64;

/// How a basic block ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Term {
    Jump,
    JumpI,
    Halt,
    /// Runs into the next block (or off the end of a code segment).
    Fall,
}

#[derive(Debug, Clone)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
    /// Indices into the instruction list.
    pub insns: Range<usize>,
    pub term: Term,
}

/// What the `JUMP` ending a block does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JumpRole {
    /// Not analysed, or the target was never a known constant.
    Unknown,
    /// Intra-function jump to constant target(s).
    Local,
    /// Internal call; see [`Cfg::calls`].
    Call,
    /// Return from an internal function.
    Return,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallSite {
    /// Callee entry block.
    pub callee: usize,
    pub nargs: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FuncInfo {
    pub nargs: usize,
    /// Stack items left for the caller, counting a kept return
    /// address (see `keeps_ret`).
    pub nrets: Option<usize>,
    /// The function returns with `DUPn JUMP`, leaving its return
    /// address as the deepest returned item for the caller to pop
    /// (legacy solc does this for some getters).
    pub keeps_ret: bool,
    /// Every path ends in a halt (`REVERT`, `RETURN`, `STOP`, …) or in
    /// a call that never returns, so callers never resume: proxies'
    /// `_fallback()` / `_delegate()`, revert helpers.
    pub noreturn: bool,
    /// The function stores its return address to memory on entry and
    /// returns with `MLOAD; JUMP` (Vyper 0.2), so frame slot `nbelow`
    /// is free for other values after the first instruction.
    pub ret_spilled: bool,
    /// Arguments passed *below* the return address, which the callee
    /// pops after spilling it (Vyper 0.2 pushes the return address
    /// last). Frame slots `0..nbelow` hold them, slot `nbelow` the
    /// return address, then the `nargs` arguments above it.
    pub nbelow: usize,
}

impl FuncInfo {
    /// Stack items the caller passes, return address excluded.
    #[must_use]
    pub fn total_args(&self) -> usize {
        self.nbelow + self.nargs
    }
}

/// Function a block's depth was computed in: an internal function's
/// entry block, or `None` for the code reached from offset 0.
pub(crate) type FrameId = Option<usize>;

/// `(nbelow, nargs)` of an internal function's frame; `None` for the
/// root frame.
type FrameShape = Option<(usize, usize)>;

/// Entry depth of a block within its frame. For internal functions
/// slot 0 is the return address (after any [`FuncInfo::nbelow`]
/// arguments) and slots `1..=nargs` the arguments;
/// for the root frame slot 0 is the bottom of the EVM stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockDepth {
    pub frame: FrameId,
    pub depth: i64,
}

pub(crate) struct Cfg {
    pub blocks: Vec<Block>,
    pub by_start: HashMap<u64, usize>,
    pub reached: Vec<bool>,
    /// Resolved `JUMP` / `JUMPI` target blocks.
    pub targets: Vec<BTreeSet<usize>>,
    pub role: Vec<JumpRole>,
    pub calls: HashMap<usize, CallSite>,
    /// Continuations seen per call site. Usually one; a call inside a
    /// tail the optimizer shares between functions returns to each
    /// caller's own continuation.
    pub conts: HashMap<usize, BTreeSet<usize>>,
    /// Call sites whose return address is the frame's own: the callee
    /// returns straight to this function's caller.
    pub tail_calls: HashSet<usize>,
    /// Internal functions keyed by entry block.
    pub functions: BTreeMap<usize, FuncInfo>,
    /// Entry depth per block; `None` when unreached or inconsistent.
    pub depth: Vec<Option<BlockDepth>>,
    /// Structural predecessors: fall-through, `JUMPI`, local jumps and
    /// call → continuation (callee entries and returns excluded).
    pub preds: Vec<Vec<usize>>,
}

impl Cfg {
    pub fn block_at(&self, addr: u64) -> Option<usize> {
        self.by_start.get(&addr).copied()
    }

    /// Structural successors of `b`, as used for `preds`.
    fn succs(&self, b: usize) -> Vec<usize> {
        let blk = &self.blocks[b];
        let next = self.block_at(blk.end);
        let mut out = Vec::new();
        match blk.term {
            Term::Fall => out.extend(next),
            Term::JumpI => {
                out.extend(self.targets[b].iter().copied());
                out.extend(next);
            }
            Term::Jump => match self.role[b] {
                JumpRole::Local => out.extend(self.targets[b].iter().copied()),
                JumpRole::Call => out.extend(self.conts.get(&b).into_iter().flatten().copied()),
                JumpRole::Return | JumpRole::Unknown => {}
            },
            Term::Halt => {}
        }
        out
    }
}

/// A tracked stack item: a `JUMPDEST` constant pushed in this frame,
/// or the frame's own return address. Everything else is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Tag {
    Const(u64),
    /// A small constant that isn't a `JUMPDEST`: kept so masked
    /// targets (`PUSH4 0xffffffff; PUSH2 f; AND`) resolve.
    Num(u32),
    Ret,
    /// The frame's `k`th argument as passed in. A function that
    /// returns by jumping to one was given the wrong frame size: its
    /// real return address is that argument.
    Arg(u16),
    /// The result of `PC`: Vyper 0.2 computes return addresses as
    /// `PC + n`.
    Pc(u64),
}
type Item = Option<Tag>;

/// Split `insns` into basic blocks.
fn split_blocks(insns: &[DecodedInsn]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut start = 0;
    for i in 0..insns.len() {
        let ins = &insns[i];
        let next = insns.get(i + 1);
        let term = match classify(ins) {
            InsnKind::Jump => Some(Term::Jump),
            InsnKind::JumpI => Some(Term::JumpI),
            InsnKind::Halt => Some(Term::Halt),
            _ => None,
        };
        let boundary = next
            .is_none_or(|n| n.opcode == crate::arch::evm::JUMPDEST || n.addr.0 != ins.next_addr());
        if term.is_some() || boundary {
            blocks.push(Block {
                start: insns[start].addr.0,
                end: ins.next_addr(),
                insns: start..i + 1,
                term: term.unwrap_or(Term::Fall),
            });
            start = i + 1;
        }
    }
    blocks
}

fn step_item_stack(stack: &mut Vec<Item>, ins: &DecodedInsn, jumpdests: &HashSet<u64>) {
    match ins.opcode {
        0x58 => stack.push(Some(Tag::Pc(ins.addr.0))),
        0x01 => {
            // ADD: `PUSH1 n; PC; ADD` is a return address.
            let a = stack.pop().flatten();
            let b = stack.pop().flatten();
            let r = match (a, b) {
                (Some(Tag::Pc(p)), Some(Tag::Num(n))) | (Some(Tag::Num(n)), Some(Tag::Pc(p))) => {
                    Some(p + u64::from(n)).filter(|v| jumpdests.contains(v))
                }
                _ => None,
            };
            stack.push(r.map(Tag::Const));
        }
        0x5f..=0x7f => {
            stack.push(ins.push_value().and_then(|v| {
                if jumpdests.contains(&v) {
                    Some(Tag::Const(v))
                } else {
                    u32::try_from(v).ok().map(Tag::Num)
                }
            }));
        }
        0x16 => {
            // AND: solc 0.5–0.7 masks internal-function targets.
            let a = stack.pop().flatten();
            let b = stack.pop().flatten();
            let r = match (a, b) {
                (Some(Tag::Const(v)), Some(Tag::Num(m)))
                | (Some(Tag::Num(m)), Some(Tag::Const(v)))
                    if v & u64::from(m) == v =>
                {
                    Some(Tag::Const(v))
                }
                _ => None,
            };
            stack.push(r);
        }
        0x80..=0x8f => {
            let n = usize::from(ins.opcode - 0x80) + 1;
            let v = stack.len().checked_sub(n).and_then(|i| stack[i]);
            stack.push(v);
        }
        0x90..=0x9f => {
            let n = usize::from(ins.opcode - 0x90) + 1;
            let len = stack.len();
            if len > n {
                stack.swap(len - 1, len - 1 - n);
            } else if let Some(top) = stack.last_mut() {
                *top = None;
            }
        }
        _ => {
            let info = &OPCODE_TABLE[ins.opcode as usize];
            for _ in 0..info.pops {
                stack.pop();
            }
            for _ in 0..info.pushes {
                stack.push(None);
            }
        }
    }
}

/// Most iterations a counted loop is simulated for.
const MAX_LOOP_TRIPS: usize = MAX_STACK + 1;
/// Most blocks in a counted loop's body.
const MAX_LOOP_BLOCKS: usize = 4;

/// A loop whose stack effect is known: Vyper 0.2 saves its memory
/// frame on the stack around private calls (and returns arrays) with
/// loops that push or pop one word per iteration, over a pointer kept
/// in memory (`mstore(p, start)` right before the loop, then
/// `mload(mload(p))` / `mstore(mload(p), …)` and `p ± 0x20` until it
/// passes a constant bound). Abstract interpretation can't count the
/// trips, so without a summary the blocks after the loop would lose
/// their depth.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CountedLoop {
    /// Blocks visited before the first return to the loop's entry,
    /// entry included.
    body: BTreeSet<usize>,
    /// First block outside the body, where the loop ends.
    exit: usize,
    /// Net stack items the whole loop pushes (negative: pops).
    delta: i64,
}

/// Counted loops keyed by the block that initialises their pointer
/// and falls into them.
#[derive(Default)]
struct CountedLoops {
    by_init: HashMap<usize, CountedLoop>,
    /// `(body block, exit)` edges, which only a loop's summary takes.
    exits: HashSet<(usize, usize)>,
}

impl CountedLoops {
    fn find(blocks: &[Block], insns: &[DecodedInsn], by_start: &HashMap<u64, usize>) -> Self {
        let mut out = Self::default();
        for (b, blk) in blocks.iter().enumerate() {
            if blk.term != Term::Fall {
                continue;
            }
            let Some(&header) = by_start.get(&blk.end) else {
                continue;
            };
            let code = &insns[blk.insns.clone()];
            let [.., ptr, store] = code else {
                continue;
            };
            let Some(ptr) = ptr.push_value().filter(|_| store.opcode == 0x52) else {
                continue;
            };
            // The pointer's initial value, as the block computes it
            // (`mstore(p, start)`, or `mstore(p, mload(q))` after a
            // constant store to `q`).
            let mut init = Concrete::new(HashMap::new());
            if code.iter().any(|ins| init.step(ins, false).is_none()) {
                continue;
            }
            let Some(&start) = init.mem.get(&ptr) else {
                continue;
            };
            if let Some(l) = simulate_loop(blocks, insns, by_start, header, ptr, start) {
                for &x in &l.body {
                    out.exits.insert((x, l.exit));
                }
                out.by_init.insert(b, l);
            }
        }
        out
    }

    /// Whether the abstract walk may take the edge `from → to`.
    fn walks(&self, from: usize, to: usize) -> bool {
        !self.exits.contains(&(from, to))
    }
}

/// A concrete run over small constants: values that don't fit in a
/// `u64`, or come from outside, are unknown. The stack starts with
/// [`MAX_STACK`] unknown items, so its length tracks the net effect.
struct Concrete {
    stack: Vec<Option<u64>>,
    /// Memory words at known offsets.
    mem: HashMap<u64, u64>,
}

impl Concrete {
    fn new(mem: HashMap<u64, u64>) -> Self {
        Self {
            stack: vec![None; MAX_STACK],
            mem,
        }
    }

    /// The top item (`None` inside: unknown), or `None` on underflow.
    #[allow(clippy::option_option)]
    fn pop(&mut self) -> Option<Option<u64>> {
        self.stack.pop()
    }

    /// Execute one non-jump instruction. `None` gives up: a stack
    /// underflow, or (when `strict`) a memory write that could change a
    /// tracked word to an unknown value. Otherwise such writes forget
    /// the words they might touch.
    fn step(&mut self, ins: &DecodedInsn, strict: bool) -> Option<()> {
        match ins.opcode {
            0x5b => {}
            0x5f..=0x7f => self.stack.push(ins.push_value()),
            0x51 => {
                let a = self.pop()?;
                self.stack.push(a.and_then(|a| self.mem.get(&a).copied()));
            }
            0x52 => {
                let a = self.pop()?;
                let v = self.pop()?;
                match (a, v) {
                    (Some(a), Some(v)) => {
                        let clobbers = self.mem.keys().any(|&k| k != a && k.abs_diff(a) < 0x20);
                        if strict && clobbers {
                            return None;
                        }
                        self.mem.retain(|&k, _| k.abs_diff(a) >= 0x20);
                        self.mem.insert(a, v);
                    }
                    (Some(a), None) => {
                        let clobbers = self.mem.keys().any(|&k| k.abs_diff(a) < 0x20);
                        if strict && clobbers {
                            return None;
                        }
                        self.mem.retain(|&k, _| k.abs_diff(a) >= 0x20);
                    }
                    (None, _) if strict => return None,
                    (None, _) => self.mem.clear(),
                }
            }
            0x01 | 0x03 | 0x10 | 0x11 | 0x14 => {
                let a = self.pop()?;
                let c = self.pop()?;
                self.stack
                    .push(a.zip(c).and_then(|(a, c)| match ins.opcode {
                        0x01 => a.checked_add(c),
                        0x03 => a.checked_sub(c),
                        0x10 => Some(u64::from(a < c)),
                        0x11 => Some(u64::from(a > c)),
                        _ => Some(u64::from(a == c)),
                    }));
            }
            0x15 => {
                let a = self.pop()?;
                self.stack.push(a.map(|a| u64::from(a == 0)));
            }
            0x80..=0x8f => {
                let n = usize::from(ins.opcode - 0x80) + 1;
                let v = self.stack[self.stack.len().checked_sub(n)?];
                self.stack.push(v);
            }
            0x90..=0x9f => {
                let n = usize::from(ins.opcode - 0x90) + 1;
                let len = self.stack.len();
                self.stack.swap(len - 1, len.checked_sub(n + 1)?);
            }
            op => {
                // Other memory writes, and anything that calls out.
                if matches!(op, 0x37 | 0x39 | 0x3c | 0x3e | 0x53 | 0x5e | 0xf0..=0xff) {
                    if strict {
                        return None;
                    }
                    self.mem.clear();
                }
                let info = &OPCODE_TABLE[op as usize];
                for _ in 0..info.pops {
                    self.pop()?;
                }
                for _ in 0..info.pushes {
                    self.stack.push(None);
                }
            }
        }
        Some(())
    }
}

/// Run the loop entered at `header` concretely, with memory word `ptr`
/// holding `start` and every other value unknown. Gives up unless each
/// branch is decided by known values, the loop stays within a few
/// blocks, and nothing in it could change `ptr` behind its back.
fn simulate_loop(
    blocks: &[Block],
    insns: &[DecodedInsn],
    by_start: &HashMap<u64, usize>,
    header: usize,
    ptr: u64,
    start: u64,
) -> Option<CountedLoop> {
    let mut m = Concrete::new(HashMap::from([(ptr, start)]));
    let mut body: BTreeSet<usize> = BTreeSet::new();
    let mut looped = false;
    let mut b = header;
    for _ in 0..MAX_LOOP_TRIPS * MAX_LOOP_BLOCKS {
        if looped && !body.contains(&b) {
            return Some(CountedLoop {
                body,
                exit: b,
                delta: m.stack.len() as i64 - MAX_STACK as i64,
            });
        }
        if !looped {
            body.insert(b);
            if body.len() > MAX_LOOP_BLOCKS {
                return None;
            }
        }
        let blk = &blocks[b];
        let body_end = match blk.term {
            Term::Jump | Term::JumpI => blk.insns.end - 1,
            Term::Halt => return None,
            Term::Fall => blk.insns.end,
        };
        for ins in &insns[blk.insns.start..body_end] {
            m.step(ins, true)?;
        }
        // The pointer must stay known, or the trip count isn't.
        m.mem.get(&ptr)?;
        let next = by_start.get(&blk.end).copied();
        b = match blk.term {
            Term::Fall => next?,
            Term::JumpI => {
                let t = m.pop()??;
                let c = m.pop()??;
                if c == 0 { next? } else { *by_start.get(&t)? }
            }
            _ => *by_start.get(&m.pop()??)?,
        };
        looped |= b == header;
    }
    None
}

/// Which constants can be return addresses.
struct RetCandidates {
    /// `JUMPDEST`s that nothing falls through into (they follow a
    /// `JUMP` or a halt): where compilers put call continuations,
    /// which are only ever entered by returning. solc may reuse one
    /// for several calls.
    after_jump: HashSet<u64>,
    /// Constants some block jumps to directly; continuations are only
    /// ever reached by returning.
    direct: HashSet<u64>,
}

impl RetCandidates {
    fn new(blocks: &[Block], insns: &[DecodedInsn], jumpdests: &HashSet<u64>) -> Self {
        let after_jump = blocks
            .iter()
            .filter(|b| matches!(b.term, Term::Jump | Term::Halt) && jumpdests.contains(&b.end))
            .map(|b| b.end)
            .collect();
        Self {
            after_jump,
            direct: direct_jump_targets(blocks, insns, jumpdests),
        }
    }

    /// Topmost return address below a jump to `target`, as
    /// `(continuation, nargs)`. `stack` is after popping the target.
    /// An argument that happens to equal a `JUMPDEST` offset (Uniswap's
    /// `997` fee is one) fails the placement test.
    fn find(&self, stack: &[Item], target: u64) -> Option<(u64, usize)> {
        stack.iter().enumerate().rev().find_map(|(i, it)| match it {
            Some(Tag::Const(r))
                if *r != target && self.after_jump.contains(r) && !self.direct.contains(r) =>
            {
                Some((*r, stack.len() - 1 - i))
            }
            _ => None,
        })
    }
}

/// Constants consumed as a jump target by the block that pushes them.
fn direct_jump_targets(
    blocks: &[Block],
    insns: &[DecodedInsn],
    jumpdests: &HashSet<u64>,
) -> HashSet<u64> {
    let mut out = HashSet::new();
    for blk in blocks {
        if !matches!(blk.term, Term::Jump | Term::JumpI) {
            continue;
        }
        let mut stack: Vec<Item> = Vec::new();
        for ins in &insns[blk.insns.start..blk.insns.end - 1] {
            step_item_stack(&mut stack, ins, jumpdests);
        }
        if let Some(Some(Tag::Const(t))) = stack.pop() {
            out.insert(t);
        }
    }
    out
}

/// Calls visible within one block: `PUSH ret … PUSH f; JUMP`.
fn seed_calls(
    blocks: &[Block],
    insns: &[DecodedInsn],
    by_start: &HashMap<u64, usize>,
    jumpdests: &HashSet<u64>,
    rets: &RetCandidates,
) -> HashMap<usize, CallSite> {
    let mut calls = HashMap::new();
    for (b, blk) in blocks.iter().enumerate() {
        if blk.term != Term::Jump {
            continue;
        }
        let mut stack: Vec<Item> = Vec::new();
        for ins in &insns[blk.insns.start..blk.insns.end - 1] {
            step_item_stack(&mut stack, ins, jumpdests);
        }
        let Some(Some(Tag::Const(t))) = stack.pop() else {
            continue;
        };
        if let Some((_, nargs)) = rets.find(&stack, t) {
            calls.insert(
                b,
                CallSite {
                    callee: by_start[&t],
                    nargs,
                },
            );
        }
    }
    calls
}

/// What one frame's analysis learned.
#[derive(Default)]
struct FrameFacts {
    /// Entry depths seen per block.
    depths: HashMap<usize, BTreeSet<i64>>,
    /// Resolved jump targets per block.
    targets: Vec<(usize, usize)>,
    returns: HashSet<usize>,
    locals: HashSet<usize>,
    nrets: Option<usize>,
    keeps_ret: bool,
    /// Calls found during analysis (set up across blocks).
    new_calls: Vec<(usize, CallSite)>,
    /// Every call site this frame reached.
    reached_calls: Vec<CallSite>,
    /// `(call site, continuation)` pairs seen.
    conts: Vec<(usize, usize)>,
    tail_calls: HashSet<usize>,
    /// The frame returned by jumping to this argument.
    ret_via_arg: Option<u16>,
    /// Some jump's target couldn't be resolved, so the frame may
    /// return in a way the analysis didn't see.
    unresolved: bool,
    /// The return address was stored to memory.
    ret_spilled: bool,
    /// Most items popped from below the frame's initial stack.
    underflow: usize,
}

/// Abstract interpretation of one function body (or the root code at
/// offset 0 when `shape` is `None`). `shape` is `(nbelow, nargs)`.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn analyze_frame(
    blocks: &[Block],
    insns: &[DecodedInsn],
    by_start: &HashMap<u64, usize>,
    jumpdests: &HashSet<u64>,
    rets: &RetCandidates,
    entry: usize,
    shape: FrameShape,
    calls: &HashMap<usize, CallSite>,
    loops: &CountedLoops,
    functions: &BTreeMap<usize, FuncInfo>,
) -> FrameFacts {
    let mut facts = FrameFacts::default();
    let mut seen: HashMap<usize, HashSet<Vec<Item>>> = HashMap::new();
    let mut work: Vec<(usize, Vec<Item>)> = Vec::new();
    let enqueue = |work: &mut Vec<(usize, Vec<Item>)>,
                   seen: &mut HashMap<usize, HashSet<Vec<Item>>>,
                   b: usize,
                   s: Vec<Item>| {
        let set = seen.entry(b).or_default();
        if s.len() <= MAX_STACK && set.len() < MAX_STATES_PER_BLOCK && set.insert(s.clone()) {
            work.push((b, s));
        }
    };
    let initial: Vec<Item> = match shape {
        Some((below, n)) => std::iter::repeat_n(None, below)
            .chain(std::iter::once(Some(Tag::Ret)))
            .chain((0..n).map(|k| u16::try_from(k).ok().map(Tag::Arg)))
            .collect(),
        None => Vec::new(),
    };
    enqueue(&mut work, &mut seen, entry, initial);
    // Constant memory offsets the frame spilled its return address to
    // (Vyper 0.2 keeps it in memory and returns with `MLOAD; JUMP`).
    let mut ret_slots: HashSet<u64> = HashSet::new();
    let const_of = |it: Option<Tag>| match it {
        Some(Tag::Const(v)) => Some(v),
        Some(Tag::Num(v)) => Some(u64::from(v)),
        _ => None,
    };

    while let Some((b, mut stack)) = work.pop() {
        facts
            .depths
            .entry(b)
            .or_default()
            .insert(stack.len() as i64);
        let blk = &blocks[b];
        let body_end = match blk.term {
            Term::Jump | Term::JumpI => blk.insns.end - 1,
            _ => blk.insns.end,
        };
        for ins in &insns[blk.insns.start..body_end] {
            let n = stack.len();
            let needs = match ins.opcode {
                0x80..=0x8f => usize::from(ins.opcode - 0x80) + 1,
                0x90..=0x9f => usize::from(ins.opcode - 0x90) + 2,
                op => usize::from(OPCODE_TABLE[op as usize].pops),
            };
            if b == entry {
                // Arguments below the return address are popped on
                // entry, right after it is spilled.
                facts.underflow = facts.underflow.max(needs.saturating_sub(n));
            }
            match ins.opcode {
                0x52 if n >= 2 && stack[n - 2] == Some(Tag::Ret) => {
                    if let Some(off) = const_of(stack[n - 1]) {
                        ret_slots.insert(off);
                        facts.ret_spilled = true;
                    }
                    stack.truncate(n - 2);
                }
                0x51 if n >= 1
                    && const_of(stack[n - 1]).is_some_and(|o| ret_slots.contains(&o)) =>
                {
                    stack[n - 1] = Some(Tag::Ret);
                }
                _ => step_item_stack(&mut stack, ins, jumpdests),
            }
        }
        let next = by_start.get(&blk.end).copied();
        match blk.term {
            Term::Fall => {
                if let Some(l) = loops.by_init.get(&b) {
                    // Past the counted loop, with its pushes or pops.
                    let mut after = stack.clone();
                    let keep = after.len() as i64 + l.delta.min(0);
                    if let Ok(keep) = usize::try_from(keep) {
                        after.truncate(keep);
                        let pushed = usize::try_from(l.delta).unwrap_or(0);
                        after.extend(std::iter::repeat_n(None, pushed));
                        enqueue(&mut work, &mut seen, l.exit, after);
                    }
                }
                if let Some(nb) = next.filter(|&nb| loops.walks(b, nb)) {
                    enqueue(&mut work, &mut seen, nb, stack);
                }
            }
            Term::Halt => {}
            Term::JumpI => {
                let t = stack.pop().flatten();
                stack.pop();
                let falls = !always_taken(&insns[blk.insns.clone()]);
                if let Some(Tag::Const(v)) = t {
                    let tb = by_start[&v];
                    facts.targets.push((b, tb));
                    if loops.walks(b, tb) {
                        enqueue(&mut work, &mut seen, tb, stack.clone());
                    }
                } else {
                    facts.unresolved = true;
                }
                if falls && let Some(nb) = next.filter(|&nb| loops.walks(b, nb)) {
                    enqueue(&mut work, &mut seen, nb, stack);
                }
            }
            Term::Jump => {
                let t = stack.pop().flatten();
                let call = calls.get(&b).copied().or_else(|| {
                    // A call whose return address was pushed in an
                    // earlier block: the target is a known function
                    // entry, or the return address is the instruction
                    // right after this jump.
                    let Some(Tag::Const(v)) = t else { return None };
                    let tb = by_start[&v];
                    let (r, n) = rets.find(&stack, v)?;
                    if r != blk.end && !functions.contains_key(&tb) {
                        return None;
                    }
                    let site = CallSite {
                        callee: tb,
                        nargs: n,
                    };
                    facts.new_calls.push((b, site));
                    Some(site)
                });
                match (t, call) {
                    (_, Some(c)) => {
                        facts.reached_calls.push(c);
                        facts.targets.push((b, c.callee));
                        let callee = functions.get(&c.callee);
                        let callee_rets = callee.and_then(|f| f.nrets);
                        let below = callee.map_or(0, |f| f.nbelow);
                        // The callee's own frame size is authoritative
                        // once known (it may have been corrected).
                        let c = CallSite {
                            nargs: callee.map_or(c.nargs, |f| f.nargs),
                            ..c
                        };
                        // The return address sits just below the
                        // arguments; which one it is depends on the path
                        // when the call is in shared code.
                        let Some(ret_at) = stack.len().checked_sub(c.nargs + 1) else {
                            continue;
                        };
                        match stack[ret_at] {
                            Some(Tag::Const(r)) => {
                                let cont = by_start[&r];
                                facts.conts.push((b, cont));
                                if let Some(nrets) = callee_rets
                                    && let Some(base) = ret_at.checked_sub(below)
                                {
                                    stack.truncate(base);
                                    stack.extend(std::iter::repeat_n(None, nrets));
                                    enqueue(&mut work, &mut seen, cont, stack);
                                }
                            }
                            Some(Tag::Ret) => {
                                // Tail call: the callee returns for us.
                                facts.tail_calls.insert(b);
                                if let Some(nrets) = callee_rets
                                    && facts.nrets.is_none()
                                    && let Some(base) = ret_at.checked_sub(below)
                                {
                                    facts.nrets = Some(base + nrets);
                                }
                            }
                            _ => {}
                        }
                    }
                    (Some(Tag::Ret), None) => {
                        facts.returns.insert(b);
                        if facts.nrets.is_none() {
                            facts.nrets = Some(stack.len());
                        }
                        if stack.contains(&Some(Tag::Ret)) {
                            facts.keeps_ret = true;
                        }
                    }
                    (Some(Tag::Const(v)), None) => {
                        let tb = by_start[&v];
                        facts.locals.insert(b);
                        facts.targets.push((b, tb));
                        if loops.walks(b, tb) {
                            enqueue(&mut work, &mut seen, tb, stack);
                        }
                    }
                    (Some(Tag::Arg(k)), None) => {
                        facts.ret_via_arg.get_or_insert(k);
                        facts.unresolved = true;
                    }
                    // Unknown or non-`JUMPDEST` target.
                    (None | Some(Tag::Num(_) | Tag::Pc(_)), None) => facts.unresolved = true,
                }
            }
        }
    }
    facts
}

/// Vyper 0.2 jumps over code it never falls into (private functions
/// placed between dispatcher cases) with `PUSH1 0; ISZERO; PUSH2 skip;
/// JUMPI`, a conditional jump whose condition is always true.
fn always_taken(block: &[DecodedInsn]) -> bool {
    let [.., z, iszero, target, jumpi] = block else {
        return false;
    };
    z.opcode == 0x60
        && z.push_value() == Some(0)
        && iszero.opcode == 0x15
        && (0x60..=0x7f).contains(&target.opcode)
        && jumpi.opcode == 0x57
}

/// Flag the functions that never return: no return or tail call was
/// seen, every jump resolved, and every call they make either never
/// returns either or has its continuation analysed. Computed as a
/// greatest fixpoint, so mutually recursive dead ends qualify.
fn mark_noreturn(functions: &mut BTreeMap<usize, FuncInfo>, facts: &[(FrameId, FrameFacts)]) {
    let mut candidates: HashSet<usize> = facts
        .iter()
        .filter_map(|(id, f)| {
            let e = (*id)?;
            let info = functions.get(&e)?;
            (info.nrets.is_none()
                && f.returns.is_empty()
                && f.tail_calls.is_empty()
                && f.ret_via_arg.is_none()
                && !f.unresolved)
                .then_some(e)
        })
        .collect();
    loop {
        let failing: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|e| {
                let Some((_, f)) = facts.iter().find(|(id, _)| *id == Some(*e)) else {
                    return true;
                };
                !f.reached_calls.iter().all(|c| {
                    candidates.contains(&c.callee)
                        || functions.get(&c.callee).is_some_and(|i| i.nrets.is_some())
                })
            })
            .collect();
        if failing.is_empty() {
            break;
        }
        for e in failing {
            candidates.remove(&e);
        }
    }
    for e in candidates {
        if let Some(info) = functions.get_mut(&e) {
            info.noreturn = true;
        }
    }
}

/// Build the CFG for decoded code (`insns` in address order,
/// possibly spanning several segments).
#[allow(clippy::too_many_lines)]
pub(crate) fn build(insns: &[DecodedInsn]) -> Cfg {
    let blocks = split_blocks(insns);
    let by_start: HashMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start, i))
        .collect();
    let jumpdests: HashSet<u64> = insns
        .iter()
        .filter(|i| i.opcode == crate::arch::evm::JUMPDEST)
        .map(|i| i.addr.0)
        .collect();
    let n = blocks.len();
    let root = by_start.get(&0).copied();

    // Seeds count as calls wherever they're reached, but a function
    // only exists once one of its call sites is reached, so bytes that
    // never execute can't invent functions.
    let rets = RetCandidates::new(&blocks, insns, &jumpdests);
    let loops = CountedLoops::find(&blocks, insns, &by_start);
    let mut calls = seed_calls(&blocks, insns, &by_start, &jumpdests, &rets);
    let mut functions: BTreeMap<usize, FuncInfo> = BTreeMap::new();
    let mut facts: Vec<(FrameId, FrameFacts)> = Vec::new();
    for _round in 0..MAX_ROUNDS {
        let frames: Vec<(FrameId, usize, FrameShape)> = root
            .map(|r| (None, r, None))
            .into_iter()
            .chain(
                functions
                    .iter()
                    .map(|(&e, f)| (Some(e), e, Some((f.nbelow, f.nargs)))),
            )
            .collect();
        facts = frames
            .iter()
            .map(|&(id, entry, shape)| {
                let f = analyze_frame(
                    &blocks, insns, &by_start, &jumpdests, &rets, entry, shape, &calls, &loops,
                    &functions,
                );
                (id, f)
            })
            .collect();
        let mut changed = false;
        for (id, f) in &facts {
            if let Some(e) = id {
                let info = functions.get_mut(e).expect("frame of a known function");
                info.ret_spilled = f.ret_spilled;
                if f.ret_spilled && f.underflow > 0 && info.nbelow < MAX_BELOW {
                    // Popped below its frame: those items are arguments
                    // passed under the return address. The facts were
                    // computed on a too-small frame, so redo them.
                    info.nbelow = (info.nbelow + f.underflow).min(MAX_BELOW);
                    info.nrets = None;
                    changed = true;
                } else if info.nrets.is_none()
                    && let Some(k) = f.ret_via_arg
                {
                    // Return address found among the "arguments":
                    // everything below it belongs to the caller.
                    info.nargs = info.nargs.saturating_sub(usize::from(k) + 1);
                    changed = true;
                } else if info.nrets.is_none() && f.nrets.is_some() {
                    info.nrets = f.nrets;
                    info.keeps_ret = f.keeps_ret;
                    changed = true;
                }
            }
            // First view of a call site wins: a frame that strayed into
            // another function's code mustn't overwrite it.
            for &(b, site) in &f.new_calls {
                if let std::collections::hash_map::Entry::Vacant(v) = calls.entry(b) {
                    v.insert(site);
                    changed = true;
                }
            }
        }
        for (_, f) in &facts {
            for c in &f.reached_calls {
                if let std::collections::btree_map::Entry::Vacant(v) = functions.entry(c.callee) {
                    v.insert(FuncInfo {
                        nargs: c.nargs,
                        nrets: None,
                        keeps_ret: false,
                        noreturn: false,
                        ret_spilled: false,
                        nbelow: 0,
                    });
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    mark_noreturn(&mut functions, &facts);

    let mut reached = vec![false; n];
    let mut targets: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut role = vec![JumpRole::Unknown; n];
    let mut depth: Vec<Option<BlockDepth>> = vec![None; n];
    let mut conflicted: HashSet<usize> = HashSet::new();
    for (id, f) in &facts {
        for (&b, ds) in &f.depths {
            reached[b] = true;
            let here = (ds.len() == 1).then(|| BlockDepth {
                frame: *id,
                depth: *ds.iter().next().expect("one depth"),
            });
            match (depth[b], here) {
                (_, None) => {
                    conflicted.insert(b);
                }
                (None, Some(h)) => depth[b] = Some(h),
                (Some(prev), Some(h)) if prev != h => {
                    conflicted.insert(b);
                }
                _ => {}
            }
        }
        for &(b, t) in &f.targets {
            targets[b].insert(t);
        }
        for &b in &f.returns {
            role[b] = JumpRole::Return;
        }
        for &b in &f.locals {
            if role[b] == JumpRole::Unknown {
                role[b] = JumpRole::Local;
            }
        }
    }
    let mut conts: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    let mut tail_calls: HashSet<usize> = HashSet::new();
    for (_, f) in &facts {
        for &(b, c) in &f.conts {
            conts.entry(b).or_default().insert(c);
        }
        tail_calls.extend(&f.tail_calls);
    }
    for &b in calls.keys() {
        if reached[b] {
            role[b] = JumpRole::Call;
        }
    }
    for b in conflicted {
        depth[b] = None;
    }
    calls.retain(|b, _| reached[*b]);

    let mut cfg = Cfg {
        blocks,
        by_start,
        reached,
        targets,
        role,
        calls,
        conts,
        tail_calls,
        functions,
        depth,
        preds: vec![Vec::new(); n],
    };
    for b in 0..n {
        if cfg.reached[b] {
            for s in cfg.succs(b) {
                if !cfg.preds[s].contains(&b) {
                    cfg.preds[s].push(b);
                }
            }
        }
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::evm::decode_range;

    /// Root code calls an internal function with one argument that
    /// returns one value, then stops:
    ///
    /// ```text
    /// 00 PUSH1 0x0a      ; return address
    /// 02 PUSH1 0x07      ; argument
    /// 04 PUSH1 0x0d      ; callee
    /// 06 JUMP
    /// 07 ...             ; (data byte, unreachable)
    /// 0a JUMPDEST        ; continuation
    /// 0b POP
    /// 0c STOP
    /// 0d JUMPDEST        ; callee: [ret, arg]
    /// 0e PUSH1 0x01
    /// 10 ADD             ; [ret, arg+1]
    /// 11 SWAP1           ; [arg+1, ret]
    /// 12 JUMP
    /// ```
    fn call_fixture() -> Vec<u8> {
        vec![
            0x60, 0x0a, 0x60, 0x07, 0x60, 0x0d, 0x56, 0x00, 0x00, 0x00, 0x5b, 0x50, 0x00, 0x5b,
            0x60, 0x01, 0x01, 0x90, 0x56,
        ]
    }

    #[test]
    fn detects_call_and_return() {
        let code = call_fixture();
        let insns = decode_range(&code, 0);
        let cfg = build(&insns);
        let caller = cfg.block_at(0).unwrap();
        let callee = cfg.block_at(0x0d).unwrap();
        let cont = cfg.block_at(0x0a).unwrap();
        assert_eq!(cfg.calls.get(&caller), Some(&CallSite { callee, nargs: 1 }));
        assert_eq!(cfg.conts[&caller], BTreeSet::from([cont]));
        assert_eq!(cfg.role[callee], JumpRole::Return);
        assert_eq!(
            cfg.functions[&callee],
            FuncInfo {
                nargs: 1,
                nrets: Some(1),
                keeps_ret: false,
                noreturn: false,
                ret_spilled: false,
                nbelow: 0,
            }
        );
        // Continuation sees the one return value on the root stack.
        assert_eq!(
            cfg.depth[cont],
            Some(BlockDepth {
                frame: None,
                depth: 1
            })
        );
        assert_eq!(cfg.preds[cont], vec![caller]);
        assert!(!cfg.reached[cfg.block_at(0x07).unwrap()]);
    }

    #[test]
    fn two_callers_keep_their_return_addresses_apart() {
        // One callee (identity: 1 arg, 1 return) called from two sites;
        // the second call passes the first call's result along.
        let code = vec![
            0x60, 0x0b, 0x60, 0x01, 0x60, 0x15, 0x56, // 00..07 call #1
            0xfe, 0xfe, 0xfe, 0xfe, // 07..0b
            0x5b, 0x60, 0x13, 0x90, 0x60, 0x15, 0x56, // 0b..12 call #2
            0xfe, // 12
            0x5b, 0x00, // 13 cont #2: STOP
            0x5b, 0x90, 0x56, // 15 callee: SWAP1 JUMP
        ];
        let insns = decode_range(&code, 0);
        let cfg = build(&insns);
        let callee = cfg.block_at(0x15).unwrap();
        assert_eq!(cfg.role[callee], JumpRole::Return);
        assert_eq!(cfg.calls.len(), 2);
        // Both continuations are reached through the call summaries,
        // the second one only because the first call returned.
        for cont in [0x0b, 0x13] {
            assert!(cfg.reached[cfg.block_at(cont).unwrap()], "{cont:#x}");
        }
        assert_eq!(
            cfg.depth[cfg.block_at(0x13).unwrap()],
            Some(BlockDepth {
                frame: None,
                depth: 1
            })
        );
    }

    /// Vyper 0.2's calling convention: the return address is
    /// `PC + n`, pushed last (above the arguments); the callee spills
    /// it and its arguments to memory and returns with `MLOAD; JUMP`.
    #[test]
    fn vyper02_memory_return_address() {
        let code = vec![
            0x60, 0x07, // 00 PUSH1 7         ; argument
            0x60, 0x05, 0x58, 0x01, // 02 PUSH1 5; PC; ADD  ; = 0x09
            0x60, 0x0b, 0x56, // 06 PUSH1 callee; JUMP
            0x5b, 0x00, // 09 continuation: JUMPDEST STOP
            0x5b, // 0b callee
            0x60, 0x00, 0x52, // spill the return address to 0x00
            0x60, 0x20, 0x52, // and the argument to 0x20
            0x60, 0x2a, // return value
            0x60, 0x00, 0x51, 0x56, // MLOAD 0x00; JUMP
        ];
        let insns = decode_range(&code, 0);
        let cfg = build(&insns);
        let callee = cfg.block_at(0x0b).unwrap();
        let info = cfg.functions[&callee];
        assert_eq!((info.nbelow, info.nargs, info.nrets), (1, 0, Some(1)));
        assert!(info.ret_spilled && !info.noreturn);
        let cont = cfg.block_at(0x09).unwrap();
        assert_eq!(
            cfg.depth[cont],
            Some(BlockDepth {
                frame: None,
                depth: 1
            })
        );
    }

    /// Vyper 0.2's frame save / restore: push memory words
    /// `0x40..0xa0` with a pointer kept at 0, then pop them back from
    /// `0x80` down to `0x40`. Each loop's trip count is known, so the
    /// blocks after them keep their depth.
    #[test]
    fn counted_stack_loops() {
        let code = vec![
            0x60, 0x40, 0x60, 0x00, 0x52, // 00 mstore(0, 0x40)
            0x5b, 0x60, 0x00, 0x51, 0x51, // 05 push mload(mload(0))
            0x60, 0x20, 0x60, 0x00, 0x51, 0x01, 0x60, 0x00, 0x52, // 0a p += 0x20
            0x60, 0xa0, 0x60, 0x00, 0x51, 0x10, 0x15, 0x60, 0x20, 0x57, // 13 out: p >= 0xa0
            0x60, 0x05, 0x56, // 1d loop
            0x5b, 0x60, 0x80, 0x60, 0x00, 0x52, // 20 mstore(0, 0x80)
            0x5b, 0x60, 0x00, 0x51, 0x52, // 26 mstore(mload(0), pop)
            0x60, 0x20, 0x60, 0x00, 0x51, 0x03, 0x60, 0x00, 0x52, // 2b p -= 0x20
            0x60, 0x40, 0x60, 0x00, 0x51, 0x10, 0x15, 0x15, 0x60, 0x42,
            0x57, // 34 out: p < 0x40
            0x60, 0x26, 0x56, // 3f loop
            0x5b, 0x00, // 42
        ];
        let insns = decode_range(&code, 0);
        let cfg = build(&insns);
        let at = |a: u64| cfg.depth[cfg.block_at(a).unwrap()];
        let root = |depth| Some(BlockDepth { frame: None, depth });
        assert_eq!(at(0x20), root(3));
        assert_eq!(at(0x42), root(0));
        // The loop bodies themselves run at several depths.
        assert_eq!(at(0x05), None);
        assert_eq!(at(0x26), None);
        assert!(cfg.reached[cfg.block_at(0x1d).unwrap()]);
        assert_eq!(cfg.role[cfg.block_at(0x1d).unwrap()], JumpRole::Local);
        // A loop whose bound isn't a constant stays uncounted.
        let mut unknown = code.clone();
        unknown[0x14] = 0x35; // CALLDATALOAD in place of the bound
        unknown[0x13] = 0x5f; // (PUSH0)
        let cfg = build(&decode_range(&unknown, 0));
        assert_eq!(cfg.depth[cfg.block_at(0x20).unwrap()], None);
    }

    #[test]
    fn noreturn_callee() {
        // Root calls a function that always reverts; its continuation
        // is never reached.
        let code = vec![
            0x60, 0x06, 0x60, 0x08, 0x56, // 00 PUSH1 ret; PUSH1 f; JUMP
            0xfe, // 05
            0x5b, 0x00, // 06 continuation
            0x5b, 0x5f, 0x5f, 0xfd, // 08 f: REVERT(0, 0)
        ];
        let insns = decode_range(&code, 0);
        let cfg = build(&insns);
        let f = cfg.block_at(0x08).unwrap();
        assert!(cfg.functions[&f].noreturn);
        assert!(!cfg.reached[cfg.block_at(0x06).unwrap()]);
    }

    #[test]
    fn deep_call_chains_stay_cheap() {
        // f0 calls f1 calls f2 … calls f9, each from two sites: a
        // whole-program context-sensitive analysis would see 2^9
        // stacks at the innermost function. Per-function summaries
        // see one.
        let mut code = Vec::new();
        let depth = 10usize;
        // Function k at 0x10*k + 0x10; root at 0.
        // root: PUSH1 ret PUSH1 f0 JUMP ; ret: JUMPDEST STOP
        code.extend([0x60, 0x06, 0x60, 0x10, 0x56, 0xfe, 0x5b, 0x00]);
        code.resize(0x10, 0xfe);
        for k in 0..depth {
            let base = 0x10 * (k + 1);
            assert_eq!(code.len(), base);
            if k + 1 < depth {
                let callee = (0x10 * (k + 2)) as u8;
                let (r1, r2) = ((base + 6) as u8, (base + 12) as u8);
                // JUMPDEST PUSH1 r1 PUSH1 callee JUMP
                code.extend([0x5b, 0x60, r1, 0x60, callee, 0x56]);
                // r1: JUMPDEST PUSH1 r2 PUSH1 callee JUMP
                code.extend([0x5b, 0x60, r2, 0x60, callee, 0x56]);
                // r2: JUMPDEST JUMP (return)
                code.extend([0x5b, 0x56]);
            } else {
                code.extend([0x5b, 0x56]);
            }
            code.resize(base + 0x10, 0xfe);
        }
        let insns = decode_range(&code, 0);
        let cfg = build(&insns);
        assert_eq!(cfg.functions.len(), depth);
        assert!(cfg.functions.values().all(|f| f.nrets == Some(0)));
        assert!(cfg.reached[cfg.block_at(0x06).unwrap()]);
    }
}

//! Pattern recognition framework for x86 instruction streams.
//!
//! Decompilation lifts the same shapes over and over: stack-arg
//! calls, prologue/epilogue, push/pop pairs, zero-via-xor, tail
//! jumps to imports. Each shape used to live as an inline
//! `if let Some(_) = match_…` check in [`build_function`], which
//! was fine while there were three of them but stops scaling once
//! the catalog grows past a dozen.
//!
//! This module exposes a [`Pattern`] trait — each pattern produces
//! a [`Candidate`] when it tentatively matches at a given index,
//! and optionally vetoes the match in a second [`Pattern::confirm`]
//! pass that sees every other candidate. The [`apply_patterns`]
//! runner collects all tentative matches, runs confirmation,
//! resolves overlaps in priority order, and returns a map of
//! `start_index → Match` the emission loop can consult before
//! falling back to its inline pattern chain.
//!
//! ## Hypothesis-style detection
//!
//! Some patterns can match plausibly but be wrong. The classic
//! case: a `push ebp; mov ebp, esp` sequence looks like a function
//! prologue, but if the same shape appears mid-function it isn't.
//! Patterns express this by emitting a [`Candidate`] from
//! `tentative` and then rejecting bad ones in `confirm` (e.g. by
//! checking the address against a known function-entry set).
//!
//! ## Conflict resolution
//!
//! When two confirmed candidates overlap in instruction range, the
//! one with higher [`Candidate::priority`] wins; ties go to the
//! one consuming more instructions. The losing candidate is
//! discarded (no partial application). Patterns thus get to assert
//! "if I match here, claim these N instructions exclusively"
//! without coordinating with each other.
//!
//! [`build_function`]: crate::build_function

use std::collections::HashMap;

use ud_arch_x86::DecodedInsn;
use ud_ast::Stmt;

mod stack_arg_call;
mod tail_jmp;
mod xor_zero;

/// Context handed to every pattern. Carries the function-name map
/// for resolving direct call targets and the function-bounded
/// address range for tail-pattern detection. Bitness isn't needed
/// today — instructions already carry their decoded form via
/// `iced::Instruction::code_size()`. Add fields here when a
/// pattern justifies them.
pub struct PatternCtx<'a> {
    #[allow(dead_code)]
    pub fn_addr_start: u64,
    pub fn_addr_end: u64,
    pub name_at: &'a HashMap<u64, String>,
}

/// One tentative match produced by a pattern.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Human-readable pattern name, for diagnostics.
    pub pattern: &'static str,
    /// Index of the first instruction the candidate consumes.
    pub start: usize,
    /// Number of instructions the candidate consumes.
    pub consumed: usize,
    /// Sort key for conflict resolution. Higher is "more specific";
    /// typical scale is 0-1000.
    pub priority: u32,
    /// Statements to emit for the consumed range. The bytes of the
    /// stmts must concatenate to exactly the consumed range's
    /// `original_bytes` so the round-trip property holds.
    pub stmts: Vec<Stmt>,
}

/// Final form after `apply_patterns` resolves overlaps.
#[derive(Debug, Clone)]
pub struct AppliedMatch {
    pub consumed: usize,
    pub stmts: Vec<Stmt>,
}

/// A pattern is a stateless detector — given a context and an
/// instruction window, decide whether the pattern applies.
pub trait Pattern: Sync {
    /// Stable identifier for the pattern (used in [`Candidate`] and
    /// logs).
    fn name(&self) -> &'static str;

    /// Tentative single-position match. Implementations should be
    /// generous here: emit a [`Candidate`] whenever the syntactic
    /// shape fits. Confirmation runs in a second pass.
    fn tentative(&self, ctx: &PatternCtx, insns: &[DecodedInsn], start: usize)
        -> Option<Candidate>;

    /// Second-pass confirmation. The default returns `true` (every
    /// tentative match stands). Override to cross-check against the
    /// surrounding context — for example, "this only fires when the
    /// call target lands in a function-entry map" or "this prologue
    /// only confirms at addresses already known to be function
    /// starts".
    fn confirm(&self, _ctx: &PatternCtx, _cand: &Candidate, _all: &[Candidate]) -> bool {
        true
    }
}

/// The registered pattern catalog. Order doesn't matter — conflict
/// resolution uses priority.
fn registry() -> Vec<&'static dyn Pattern> {
    vec![
        &stack_arg_call::StackArgCall,
        &xor_zero::XorZero,
        &tail_jmp::TailJmp,
    ]
}

/// Run every registered pattern against `insns`, resolve overlaps,
/// and return the surviving matches keyed by their start index. The
/// emission loop should check this map at each instruction position
/// before its inline pattern chain.
pub fn apply_patterns(ctx: &PatternCtx, insns: &[DecodedInsn]) -> HashMap<usize, AppliedMatch> {
    let mut tentative: Vec<Candidate> = Vec::new();
    for p in registry() {
        for i in 0..insns.len() {
            if let Some(c) = p.tentative(ctx, insns, i) {
                tentative.push(c);
            }
        }
    }

    // Second pass: confirmation. A pattern may consult every other
    // tentative candidate to decide whether its own claim still
    // stands. Discard rejected ones.
    let confirmed: Vec<Candidate> = tentative
        .iter()
        .filter(|c| {
            registry()
                .iter()
                .find(|p| p.name() == c.pattern)
                .is_some_and(|p| p.confirm(ctx, c, &tentative))
        })
        .cloned()
        .collect();

    // Conflict resolution: sort by (priority desc, consumed desc,
    // start asc) and apply non-overlapping in that order.
    let mut sorted = confirmed;
    sorted.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then(b.consumed.cmp(&a.consumed))
            .then(a.start.cmp(&b.start))
    });

    let mut consumed = vec![false; insns.len()];
    let mut out: HashMap<usize, AppliedMatch> = HashMap::new();
    for cand in sorted {
        let end = cand.start.saturating_add(cand.consumed);
        if end > insns.len() {
            continue;
        }
        if (cand.start..end).any(|i| consumed[i]) {
            continue;
        }
        for slot in &mut consumed[cand.start..end] {
            *slot = true;
        }
        out.insert(
            cand.start,
            AppliedMatch {
                consumed: cand.consumed,
                stmts: cand.stmts,
            },
        );
    }
    out
}

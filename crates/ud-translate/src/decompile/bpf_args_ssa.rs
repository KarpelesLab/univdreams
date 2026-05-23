//! SSA-driven call-argument resolution for BPF.
//!
//! The per-block `RegTracker` in `decompile/bpf.rs` resets
//! at every label (a basic-block boundary), so any call
//! whose argument-prep crossed a CFG join loses its tracked
//! values. With proper SSA in place we can do better:
//! query the reaching def for `r1..r5` at the call's IP,
//! then walk the def's instruction back to a constant /
//! string / stack-ref we recognise.
//!
//! This module is the **fallback** layer. The per-block
//! tracker still runs first — its result wins when it has
//! one, because it sees register-copy chains the SSA query
//! sometimes can't recover from a single reaching def. SSA
//! resolution only fires for slots the tracker reported as
//! `None`. The combined effect is strictly additive: no
//! existing detection regresses, but unresolved args at
//! post-label call sites get a chance to surface.
//!
//! ## What we can resolve
//!
//! * `mov rN, imm` → the immediate as `"0x{imm:x}"`.
//! * `lddw rN, imm64` → the `.rodata` string at `imm64` if
//!   one fits, otherwise the hex address.
//! * `mov rN, rM` → recursive resolve of rM's reaching def
//!   at the mov's IP (bounded depth).
//! * `ldxdw rN, [r10 ± off]` → `[local_<off>]` /
//!   `[arg_<off>]` (same naming the lifter uses elsewhere).
//! * `add rN, imm` after a write that aliased r10 → folds
//!   into a `&local_<off>` pointer name.
//! * Function-entry register (the variable comes in via the
//!   ABI as an arg) → `arg_<N-1>` if N ∈ 1..=5.
//!
//! ## Phi joins
//!
//! When the reaching def is a phi (multiple predecessors
//! with different defs), we recursively resolve each
//! incoming def. If every incoming resolves to the same
//! string, we commit — both arms wrote the same constant /
//! aliased the same stack slot, so the join is unambiguous
//! at the value level. If any incoming returns `None` (we
//! couldn't classify it) or any two incoming differ, we
//! return `None` rather than guess.
//!
//! ## What we can't (yet)
//!
//! * Memory chases through pointers — `ldxdw rN, [rM+off]`
//!   for `rM != r10` resolves to the opaque `Memory` var,
//!   which SSA can't decompose without an alias model.
//!
//! Round-trip neutral: every output is a `Stmt::Comment`
//! string in the caller's pipeline.

use std::collections::HashMap;

use ud_arch_bpf::{DecodedInsn, InsnKind};
use ud_ir::ssa::{DefSite, SsaInfo, Var};
use ud_ir::Function;

use super::data_lookup::DataLookup;

/// Hard cap on recursive def-chain walks. Picked
/// generously; with proper SSA the chain length is bounded
/// by the function's instruction count, but a budget here
/// keeps a buggy SSA result from hanging the renderer.
const MAX_RESOLVE_DEPTH: usize = 8;

/// Resolve the value of `r{slot+1}` at the call instruction
/// `call_ip`, walking back through SSA reaching defs.
/// Returns the same string shape the per-block tracker
/// would have produced, so consumers can use the two
/// interchangeably.
///
/// `insns_by_addr` is a flat IP→insn lookup over the
/// function. The caller builds it once per function and
/// passes it in to avoid rescanning blocks on each call
/// site.
pub fn resolve_arg(
    ssa: &SsaInfo,
    insns_by_addr: &HashMap<u64, &DecodedInsn>,
    call_ip: u64,
    slot: usize,
    data: Option<&dyn DataLookup>,
) -> Option<String> {
    let reg = Var::Reg(format!("r{}", slot + 1));
    let def = ssa.def_reaching(call_ip, &reg)?;
    resolve_def(ssa, insns_by_addr, def, data, 0)
}

fn resolve_def(
    ssa: &SsaInfo,
    insns_by_addr: &HashMap<u64, &DecodedInsn>,
    def: ud_ir::ssa::DefId,
    data: Option<&dyn DataLookup>,
    depth: usize,
) -> Option<String> {
    if depth >= MAX_RESOLVE_DEPTH {
        return None;
    }
    let record = ssa.defs.get(def.0 as usize)?;
    match &record.site {
        DefSite::Insn(ip) => {
            let insn = *insns_by_addr.get(ip)?;
            resolve_insn(ssa, insns_by_addr, insn, &record.var, data, depth + 1)
        }
        DefSite::Phi { incoming, .. } => {
            resolve_phi_consensus(ssa, insns_by_addr, incoming, data, depth)
        }
        DefSite::Entry => {
            // ABI: r1..r5 are arg registers; r6..r9 are
            // callee-saved (presumed live but unnamed by
            // this layer); r0 is the return-value slot
            // (no incoming meaning). Stack-slot Entry
            // means a frame slot that pre-existed before
            // the function — render as the same `[local_*]`
            // shape the lifter uses.
            match &record.var {
                Var::Reg(r) => {
                    let n: u8 = r.strip_prefix('r')?.parse().ok()?;
                    if (1..=5).contains(&n) {
                        Some(format!("arg_{}", n - 1))
                    } else if n == 10 {
                        // r10 is the BPF frame pointer — invariant
                        // across the function. Return the literal
                        // name so `fold_stack_add` can recognise
                        // it as the pointer base.
                        Some("r10".into())
                    } else {
                        None
                    }
                }
                Var::Stack(off) => Some(format_stack_ref(*off, false)),
                Var::Memory => None,
            }
        }
    }
}

/// Phi consensus: commit a value when the **concrete**
/// incoming defs all resolve to the same string.
///
/// Phi-typed incomings (the def at the predecessor is
/// itself a phi at some other block) are SKIPPED, not
/// followed. Those almost always correspond to loop
/// back-edges: a loop header's phi has one incoming from
/// the pre-loop block (concrete) and one from the
/// back-edge (which is the phi itself, transitively).
/// Following the back-edge yields an infinite recursion
/// terminated by the depth budget — and the answer is
/// always `None`, which incorrectly kills consensus even
/// when the concrete def alone is the only value that can
/// reach the phi (because the loop body never writes the
/// variable).
///
/// Skipping phi-typed incomings means: when every "real"
/// def reaching the join agrees, we commit to that value;
/// the loop-back-edge arm is treated as "the same value
/// flowing around again", consistent with the loop body
/// not having an intervening write.
///
/// Returns `None` when no concrete incoming resolves, or
/// when two concrete incomings disagree.
fn resolve_phi_consensus(
    ssa: &SsaInfo,
    insns_by_addr: &HashMap<u64, &DecodedInsn>,
    incoming: &[ud_ir::ssa::DefId],
    data: Option<&dyn DataLookup>,
    depth: usize,
) -> Option<String> {
    let mut consensus: Option<String> = None;
    for &inc in incoming {
        let record = ssa.defs.get(inc.0 as usize)?;
        if matches!(record.site, DefSite::Phi { .. }) {
            // Loop back-edge / nested phi — skip.
            continue;
        }
        let resolved = resolve_def(ssa, insns_by_addr, inc, data, depth + 1)?;
        match &consensus {
            None => consensus = Some(resolved),
            Some(prev) if *prev == resolved => {}
            Some(_) => return None,
        }
    }
    consensus
}

fn resolve_insn(
    ssa: &SsaInfo,
    insns_by_addr: &HashMap<u64, &DecodedInsn>,
    insn: &DecodedInsn,
    _target_var: &Var,
    data: Option<&dyn DataLookup>,
    depth: usize,
) -> Option<String> {
    match insn.kind {
        InsnKind::Lddw => {
            let imm = insn.imm64?;
            if let Some(d) = data {
                if let Some(s) = super::bpf::read_inline_string(d, imm) {
                    return Some(s);
                }
            }
            Some(format!("0x{imm:x}"))
        }
        InsnKind::Alu32 | InsnKind::Alu64 => {
            let op_nibble = (insn.opcode >> 4) & 0xf;
            let is_reg_src = (insn.opcode & 0x08) != 0;
            match op_nibble {
                // MOV
                0xb => {
                    if is_reg_src {
                        // mov dst, src — recursively resolve
                        // src's reaching def at this insn's IP.
                        let src_reg = Var::Reg(format!("r{}", insn.src));
                        let src_def = ssa.def_reaching(insn.addr.0, &src_reg)?;
                        resolve_def(ssa, insns_by_addr, src_def, data, depth)
                    } else {
                        // mov dst, imm
                        #[allow(clippy::cast_sign_loss)]
                        Some(format!("0x{:x}", insn.imm as u32))
                    }
                }
                // ADD — only handle the "fold imm into a
                // known pointer-to-r10 alias" case. If the
                // dst's prior reaching def resolves to
                // `[local_<n>]` or `&local_<n>`, fold the
                // immediate into the offset; otherwise
                // give up.
                0x0 if !is_reg_src => {
                    let dst_reg = Var::Reg(format!("r{}", insn.dst));
                    // Find the def of dst that this add reads
                    // FROM (the dst's pre-add version, which
                    // by SSA is the def reaching this insn's
                    // use of dst).
                    let prior = ssa.def_reaching(insn.addr.0, &dst_reg)?;
                    let prior_val = resolve_def(ssa, insns_by_addr, prior, data, depth)?;
                    fold_stack_add(&prior_val, insn.imm)
                }
                _ => None,
            }
        }
        InsnKind::Load => {
            // ldxdw rN, [rM + off]
            if insn.src == 10 {
                Some(format_stack_ref(i64::from(insn.offset), false))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Mirror of `decompile/bpf.rs::render_stack_ref` for
/// `[r10 ± offset]`. Matches the bracketed `[local_<off>]`
/// shape used when not taking the address; the `&local_<off>`
/// shape when taking the address.
fn format_stack_ref(offset: i64, take_addr: bool) -> String {
    let prefix = if take_addr { "&" } else { "[" };
    let suffix = if take_addr { "" } else { "]" };
    if offset >= 0 {
        format!("{prefix}arg_{offset:x}{suffix}")
    } else {
        format!("{prefix}local_{:x}{suffix}", -offset)
    }
}

/// Fold an `add imm` into a known frame-pointer-relative
/// alias. Mirrors `decompile/bpf.rs::fold_stack_add` exactly
/// so the SSA resolver and the per-block tracker produce
/// identical text.
fn fold_stack_add(base: &str, delta: i32) -> Option<String> {
    if base == "r10" {
        if delta < 0 {
            return Some(format!("&local_{:x}", delta.unsigned_abs()));
        }
        return Some(format!("&arg_{delta:x}"));
    }
    if let Some(rest) = base.strip_prefix("&local_") {
        let cur = i64::from_str_radix(rest, 16).ok()?;
        let new = -cur + i64::from(delta);
        if new < 0 {
            return Some(format!("&local_{:x}", new.unsigned_abs()));
        }
        return Some(format!("&arg_{new:x}"));
    }
    if let Some(rest) = base.strip_prefix("&arg_") {
        let cur = i64::from_str_radix(rest, 16).ok()?;
        let new = cur + i64::from(delta);
        if new < 0 {
            return Some(format!("&local_{:x}", new.unsigned_abs()));
        }
        return Some(format!("&arg_{new:x}"));
    }
    None
}

/// Build a flat IP → instruction map for one function.
/// Caller calls this once per function and threads the
/// result through each call site's resolution.
#[must_use]
pub fn index_by_addr(f: &Function<DecodedInsn>) -> HashMap<u64, &DecodedInsn> {
    let mut out = HashMap::new();
    for block in &f.blocks {
        for insn in &block.insns {
            out.insert(insn.addr.0, insn);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_arch_bpf::{decode, BpfVariant};
    use ud_core::VAddr;
    use ud_ir::{BasicBlock, Terminator};

    fn lift_linear(bytes: &[u8]) -> Function<DecodedInsn> {
        let insns = decode(bytes, 0x1000, BpfVariant::Sbfv1).expect("decode");
        let term = match insns.last().map(|i| i.kind) {
            Some(InsnKind::Exit) => Terminator::Return,
            _ => Terminator::Fallthrough,
        };
        Function {
            addr: VAddr(0x1000),
            name: "test".into(),
            blocks: vec![BasicBlock {
                addr: VAddr(0x1000),
                insns,
                terminator: term,
            }],
        }
    }

    /// Trivial smoke: mov r1, 0x2a; call X. SSA resolution
    /// should report r1's value at the call as 0x2a.
    #[test]
    fn mov_imm_resolves_at_following_call() {
        let bytes = [
            0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r1, 42
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call 0
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1008, 0, None);
        assert_eq!(arg, Some("0x2a".into()));
    }

    /// Register-copy chain: mov r2, 7; mov r1, r2; call.
    /// Should resolve r1 = 0x7.
    #[test]
    fn mov_chain_resolves_through_two_hops() {
        let bytes = [
            0xb7, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, // mov64 r2, 7
            0xbf, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, r2
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1010, 0, None);
        assert_eq!(arg, Some("0x7".into()));
    }

    /// Stack-slot load: `ldxdw r1, [r10 - 8]; call`. r1
    /// should resolve to `[local_8]`.
    #[test]
    fn ldxdw_r10_stack_slot_resolves() {
        let bytes = [
            0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, // ldxdw r1, [r10 - 8]
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1008, 0, None);
        assert_eq!(arg, Some("[local_8]".into()));
    }

    /// Pointer-to-local: `mov r1, r10; add r1, -0x50; call`.
    /// r1 should resolve to `&local_50`.
    #[test]
    fn r10_arith_resolves_to_pointer_to_local() {
        let bytes = [
            0xbf, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, r10
            0x07, 0x01, 0x00, 0x00, 0xb0, 0xff, 0xff, 0xff, // add64 r1, -0x50
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1010, 0, None);
        assert_eq!(arg, Some("&local_50".into()));
    }

    /// Diamond CFG where both arms write the same constant
    /// to r1. The merge block has a phi for r1 with two
    /// incoming defs; both resolve to `"0x2a"`, so the
    /// consensus rule commits to that value.
    ///
    /// BPF's production `lift_function` only emits single-
    /// block functions today, so we construct the blocks
    /// directly here to exercise the phi path.
    #[test]
    fn phi_with_unanimous_incoming_commits_to_value() {
        // Slot layout (8 bytes each):
        //   0x1000  jeq r0, 0, +2      (skip to arm2 if zero)
        //   0x1008  mov64 r1, 0x2a     (arm1)
        //   0x1010  ja +1              (skip arm2)
        //   0x1018  mov64 r1, 0x2a     (arm2 — same value)
        //   0x1020  call 0             (merge)
        //   0x1028  exit
        let bytes = [
            0x15, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // jeq r0, 0, +2
            0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r1, 0x2a
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // ja +1
            0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r1, 0x2a
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let insns = decode(&bytes, 0x1000, BpfVariant::Sbfv1).expect("decode");
        // Slice into four blocks: entry, arm1, arm2, merge.
        let block_entry = BasicBlock {
            addr: VAddr(0x1000),
            insns: vec![insns[0].clone()],
            terminator: Terminator::ConditionalBranch {
                taken: VAddr(0x1018),
                fallthrough: VAddr(0x1008),
            },
        };
        let block_arm1 = BasicBlock {
            addr: VAddr(0x1008),
            insns: vec![insns[1].clone(), insns[2].clone()],
            terminator: Terminator::UnconditionalBranch {
                target: VAddr(0x1020),
            },
        };
        let block_arm2 = BasicBlock {
            addr: VAddr(0x1018),
            insns: vec![insns[3].clone()],
            terminator: Terminator::Fallthrough,
        };
        let block_merge = BasicBlock {
            addr: VAddr(0x1020),
            insns: vec![insns[4].clone(), insns[5].clone()],
            terminator: Terminator::Return,
        };
        let f = Function {
            addr: VAddr(0x1000),
            name: "diamond".into(),
            blocks: vec![block_entry, block_arm1, block_arm2, block_merge],
        };

        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1020, 0, None);
        assert_eq!(arg, Some("0x2a".into()));
    }

    /// Same diamond but with divergent values. Phi consensus
    /// must NOT commit — we can't tell which arm ran.
    #[test]
    fn phi_with_divergent_incoming_does_not_commit() {
        let bytes = [
            0x15, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // jeq r0, 0, +2
            0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov r1, 0x2a
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // ja +1
            0xb7, 0x01, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, // mov r1, 0x37 (different!)
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let insns = decode(&bytes, 0x1000, BpfVariant::Sbfv1).expect("decode");
        let f = Function {
            addr: VAddr(0x1000),
            name: "diamond".into(),
            blocks: vec![
                BasicBlock {
                    addr: VAddr(0x1000),
                    insns: vec![insns[0].clone()],
                    terminator: Terminator::ConditionalBranch {
                        taken: VAddr(0x1018),
                        fallthrough: VAddr(0x1008),
                    },
                },
                BasicBlock {
                    addr: VAddr(0x1008),
                    insns: vec![insns[1].clone(), insns[2].clone()],
                    terminator: Terminator::UnconditionalBranch {
                        target: VAddr(0x1020),
                    },
                },
                BasicBlock {
                    addr: VAddr(0x1018),
                    insns: vec![insns[3].clone()],
                    terminator: Terminator::Fallthrough,
                },
                BasicBlock {
                    addr: VAddr(0x1020),
                    insns: vec![insns[4].clone(), insns[5].clone()],
                    terminator: Terminator::Return,
                },
            ],
        };

        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1020, 0, None);
        assert_eq!(arg, None);
    }

    /// At entry, before any def of r1, r1 is the function
    /// argument `arg_0`. SSA tags the reaching def as
    /// `DefSite::Entry`.
    #[test]
    fn entry_register_resolves_to_arg_name() {
        let bytes = [
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call (uses r1 as arg)
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let ssa = super::super::bpf_ssa::build_bpf_ssa(&f);
        let ix = index_by_addr(&f);
        let arg = resolve_arg(&ssa, &ix, 0x1000, 0, None);
        assert_eq!(arg, Some("arg_0".into()));
    }
}

// No production caller wires BPF SSA yet — the unit tests
// exercise the surface but they're #[cfg(test)]-only, so the
// main binary sees every public item as dead. Drop the
// warning until the audit-readability arc (CPI arg flow,
// inline pubkey-cmp detection, dispatch-chain recovery)
// starts consuming it.
#![allow(dead_code)]

//! BPF SSA bridge.
//!
//! Thin wrapper that supplies arch-specific reads/writes
//! extraction (BPF opcode classification) to the generic
//! Cytron-Ferrante SSA core in [`ud_ir::ssa`]. Mirrors the
//! shape of the x86 wrapper in `decompile/ssa.rs` so future
//! arches plug in the same way.
//!
//! ## Mapping per BPF instruction class
//!
//! * **`Alu32` / `Alu64`**: Generally RMW — reads dst, writes
//!   dst, and reads src when `BPF_X` is set. Three carve-outs:
//!   - MOV (op nibble 0xb): write-only on dst.
//!   - NEG (op nibble 0x8): unary, no src.
//!   - END / byte-swap (op nibble 0xd): unary, no src.
//! * **`JmpCond` / `JmpCond32`**: read-only — reads dst,
//!   reads src when `BPF_X`, no writes.
//! * **`Jmp` (JA)**: no reads, no writes.
//! * **`Exit`**: reads r0 (the return value).
//! * **`Call` / `CallReg`**: BPF ABI is r1..r5 = args, r0 =
//!   return, r0..r5 caller-saved. We model the call as
//!   reading r1..r5 (and the target register for `CallReg`)
//!   and writing r0..r5 (so the post-call versions are
//!   fresh defs). r6..r9 are callee-saved and stay live.
//! * **`Load`**: reads src (address), writes dst. The memory
//!   side is `Var::Stack(offset)` when `src == r10` (frame
//!   pointer), `Var::Memory` otherwise.
//! * **`Store`**: reads dst (address), reads src (value),
//!   writes memory (Stack or Memory by the same rule).
//! * **`Lddw`**: writes dst, no reads.
//! * **`LddwSecondHalf`**: no reads, no writes (it's the
//!   high-32-bit continuation data of the previous slot).
//! * **`Endian`**: reads dst, writes dst (in-place byte
//!   swap).
//! * **`Unknown`**: conservatively empty — we'd rather
//!   under-report reads than fabricate them. The round-trip
//!   contract isn't affected; SSA queries against unknown
//!   ops simply return `None`.
//!
//! Stack slots are addressed as `[r10 ± offset]`. BPF's r10
//! is a fixed frame pointer (the runtime sets it once at
//! function entry and the verifier rejects writes), so we
//! don't need an SP-delta table the way x86 does.
//!
//! ## Public API
//!
//! Mirrors x86's: [`build_bpf_ssa`] and [`compute_bpf_liveness`]
//! take a `&Function<DecodedInsn>` and return the same
//! [`SsaInfo`] / [`Liveness`] types the renderer queries
//! through `ud_ir::ssa`.

use ud_arch_bpf::{DecodedInsn, InsnKind};
use ud_ir::ssa::{Liveness, SsaInfo, Var};
use ud_ir::Function;

/// Build SSA for a BPF function.
#[must_use]
pub fn build_bpf_ssa(f: &Function<DecodedInsn>) -> SsaInfo {
    ud_ir::ssa::build_ssa(f, insn_reads_writes)
}

/// Compute liveness for a BPF function.
#[must_use]
pub fn compute_bpf_liveness(f: &Function<DecodedInsn>) -> Liveness {
    ud_ir::ssa::compute_liveness(f, insn_reads_writes)
}

/// Extract `(reads, writes)` for one BPF instruction.
///
/// Pure function — every classification decision flows from
/// the opcode + dst + src + offset fields on `DecodedInsn`.
#[must_use]
pub fn insn_reads_writes(insn: &DecodedInsn) -> (Vec<Var>, Vec<Var>) {
    let dst = reg(insn.dst);
    let src = reg(insn.src);
    let is_reg_src = (insn.opcode & 0x08) != 0;
    let op_nibble = (insn.opcode >> 4) & 0xf;

    match insn.kind {
        InsnKind::Alu32 | InsnKind::Alu64 => alu_reads_writes(dst, src, is_reg_src, op_nibble),

        InsnKind::JmpCond | InsnKind::JmpCond32 => {
            let mut reads = vec![Var::Reg(dst)];
            if is_reg_src {
                reads.push(Var::Reg(src));
            }
            (reads, Vec::new())
        }

        InsnKind::Exit => (vec![Var::Reg("r0".into())], Vec::new()),

        InsnKind::Call => (caller_arg_regs(), caller_clobber_regs()),

        InsnKind::CallReg => {
            // Indirect call: target lives in some register.
            // On SBF the target register is encoded in src.
            let mut reads = caller_arg_regs();
            // src may already be in r1..r5; push_unique avoids
            // dup but isn't critical for correctness.
            push_unique(&mut reads, Var::Reg(src));
            (reads, caller_clobber_regs())
        }

        InsnKind::Load => {
            // ldxb/h/w/dw  dst, [src + offset]
            let mem = memory_var(insn.src, insn.offset);
            let reads = if insn.src == 10 {
                // `[r10 + off]` — stack-only, no Reg(r10) read
                // because r10 is a fixed frame pointer.
                vec![mem]
            } else {
                vec![Var::Reg(src), mem]
            };
            (reads, vec![Var::Reg(dst)])
        }

        InsnKind::Store => {
            // stxb/h/w/dw [dst + offset], src  (BPF_STX)
            // stb/h/w/dw  [dst + offset], imm  (BPF_ST)
            let mem = memory_var(insn.dst, insn.offset);
            let mut reads = Vec::new();
            if insn.dst != 10 {
                reads.push(Var::Reg(dst));
            }
            if is_reg_src {
                reads.push(Var::Reg(src));
            }
            (reads, vec![mem])
        }

        InsnKind::Lddw => (Vec::new(), vec![Var::Reg(dst)]),

        // JA (no operands), LDDW continuation data, and
        // anything the decoder couldn't classify all
        // contribute nothing to SSA flow.
        InsnKind::Jmp | InsnKind::LddwSecondHalf | InsnKind::Unknown => (Vec::new(), Vec::new()),

        InsnKind::Endian => (vec![Var::Reg(dst.clone())], vec![Var::Reg(dst)]),
    }
}

/// ALU read/write classification by op nibble.
fn alu_reads_writes(
    dst: String,
    src: String,
    is_reg_src: bool,
    op_nibble: u8,
) -> (Vec<Var>, Vec<Var>) {
    const OP_NEG: u8 = 0x8;
    const OP_MOV: u8 = 0xb;
    const OP_END: u8 = 0xd;

    match op_nibble {
        OP_MOV => {
            let mut reads = Vec::new();
            if is_reg_src {
                reads.push(Var::Reg(src));
            }
            (reads, vec![Var::Reg(dst)])
        }
        OP_NEG | OP_END => (vec![Var::Reg(dst.clone())], vec![Var::Reg(dst)]),
        _ => {
            let mut reads = vec![Var::Reg(dst.clone())];
            if is_reg_src {
                reads.push(Var::Reg(src));
            }
            (reads, vec![Var::Reg(dst)])
        }
    }
}

/// BPF arg registers per the v1 ABI.
fn caller_arg_regs() -> Vec<Var> {
    (1..=5).map(|n| Var::Reg(format!("r{n}"))).collect()
}

/// Caller-saved registers across a `call`. r6..r9 are
/// callee-saved and stay versioned through the call.
fn caller_clobber_regs() -> Vec<Var> {
    (0..=5).map(|n| Var::Reg(format!("r{n}"))).collect()
}

fn reg(n: u8) -> String {
    format!("r{n}")
}

/// Map a memory operand `[r<base> + offset]` to a `Var`.
/// Frame-pointer-relative accesses (`base == 10`) become
/// `Var::Stack(offset)`; everything else collapses to the
/// shared `Var::Memory` aggregate.
fn memory_var(base: u8, offset: i16) -> Var {
    if base == 10 {
        Var::Stack(i64::from(offset))
    } else {
        Var::Memory
    }
}

fn push_unique(v: &mut Vec<Var>, x: Var) {
    if !v.contains(&x) {
        v.push(x);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_arch_bpf::{decode, BpfVariant};
    use ud_ir::ssa::DefSite;

    /// Build a `Function<DecodedInsn>` from raw BPF bytes by
    /// running the arch decoder + a hand-rolled
    /// single-block-per-function lifter. We don't pull in
    /// `lift_function` here because BPF lifting (with proper
    /// CFG slicing on jumps) lives in another module that
    /// the SSA core shouldn't depend on for tests.
    fn lift_linear(bytes: &[u8]) -> Function<DecodedInsn> {
        use ud_core::VAddr;
        use ud_ir::{BasicBlock, Terminator};
        let insns = decode(bytes, 0x1000, BpfVariant::Sbfv1).expect("decode");
        let term = match insns.last().map(|i| i.kind) {
            Some(InsnKind::Exit) => Terminator::Return,
            _ => Terminator::Fallthrough,
        };
        let block = BasicBlock {
            addr: VAddr(0x1000),
            insns,
            terminator: term,
        };
        Function {
            addr: VAddr(0x1000),
            name: "test".into(),
            blocks: vec![block],
        }
    }

    #[test]
    fn mov_writes_only_dst() {
        // mov64 r1, 0x2a  ;  exit
        let bytes = [
            0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r1, 42
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let mov = &f.blocks[0].insns[0];
        let (reads, writes) = insn_reads_writes(mov);
        assert!(reads.is_empty(), "mov-imm should not read; got {reads:?}");
        assert_eq!(writes, vec![Var::Reg("r1".into())]);
    }

    #[test]
    fn add64_rmw_reads_and_writes_dst() {
        // add64 r1, r2  ;  exit
        let bytes = [
            0x0f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add64 r1, r2
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let f = lift_linear(&bytes);
        let add = &f.blocks[0].insns[0];
        let (reads, writes) = insn_reads_writes(add);
        // r1 read (RMW) + r2 read (BPF_X src)
        assert!(reads.contains(&Var::Reg("r1".into())));
        assert!(reads.contains(&Var::Reg("r2".into())));
        assert_eq!(writes, vec![Var::Reg("r1".into())]);
    }

    #[test]
    fn ldxdw_with_r10_resolves_to_stack_slot() {
        // ldxdw r0, [r10 - 0x8]  ;  exit
        let bytes = [
            0x79, 0xa0, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let f = lift_linear(&bytes);
        let ldx = &f.blocks[0].insns[0];
        let (reads, writes) = insn_reads_writes(ldx);
        assert!(reads.contains(&Var::Stack(-8)));
        assert!(!reads.contains(&Var::Reg("r10".into())));
        assert_eq!(writes, vec![Var::Reg("r0".into())]);
    }

    #[test]
    fn ldxdw_non_r10_uses_memory_aggregate() {
        // ldxdw r0, [r1 + 0x10]  ;  exit
        let bytes = [
            0x79, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let f = lift_linear(&bytes);
        let ldx = &f.blocks[0].insns[0];
        let (reads, _writes) = insn_reads_writes(ldx);
        assert!(reads.contains(&Var::Reg("r1".into())));
        assert!(reads.contains(&Var::Memory));
    }

    #[test]
    fn stxdw_with_r10_writes_stack_slot() {
        // stxdw [r10 - 0x8], r1  ;  exit
        let bytes = [
            0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let f = lift_linear(&bytes);
        let stx = &f.blocks[0].insns[0];
        let (reads, writes) = insn_reads_writes(stx);
        assert!(reads.contains(&Var::Reg("r1".into())));
        assert_eq!(writes, vec![Var::Stack(-8)]);
    }

    #[test]
    fn call_reads_arg_regs_and_writes_caller_saved() {
        // call 0  ;  exit
        let bytes = [
            0x85, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let f = lift_linear(&bytes);
        let call = &f.blocks[0].insns[0];
        let (reads, writes) = insn_reads_writes(call);
        for n in 1..=5 {
            assert!(reads.contains(&Var::Reg(format!("r{n}"))));
        }
        for n in 0..=5 {
            assert!(writes.contains(&Var::Reg(format!("r{n}"))));
        }
    }

    #[test]
    fn exit_reads_r0_only() {
        let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let f = lift_linear(&bytes);
        let exit = &f.blocks[0].insns[0];
        let (reads, writes) = insn_reads_writes(exit);
        assert_eq!(reads, vec![Var::Reg("r0".into())]);
        assert!(writes.is_empty());
    }

    #[test]
    fn lddw_writes_dst_no_reads() {
        // lddw r1, 0xdeadbeefcafebabe
        let bytes = [
            0x18, 0x01, 0x00, 0x00, 0xbe, 0xba, 0xfe, 0xca, // lddw r1, low32
            0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // continuation high32
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let f = lift_linear(&bytes);
        let lddw = &f.blocks[0].insns[0];
        assert_eq!(lddw.kind, InsnKind::Lddw);
        let (reads, writes) = insn_reads_writes(lddw);
        assert!(reads.is_empty());
        assert_eq!(writes, vec![Var::Reg("r1".into())]);
        // Continuation slot is data; no reads, no writes.
        let cont = &f.blocks[0].insns[1];
        assert_eq!(cont.kind, InsnKind::LddwSecondHalf);
        let (cr, cw) = insn_reads_writes(cont);
        assert!(cr.is_empty() && cw.is_empty());
    }

    /// End-to-end smoke: a tiny linear function builds a
    /// non-empty `SsaInfo` with the expected def at the mov.
    #[test]
    fn build_ssa_smoke() {
        let bytes = [
            0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r1, 42
            0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0, r1
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let f = lift_linear(&bytes);
        let ssa = build_bpf_ssa(&f);
        // The mov r0, r1 should have its r1 read mapped to
        // the def from the earlier `mov64 r1, 42`.
        let r1 = Var::Reg("r1".into());
        let reach = ssa
            .use_at
            .get(&(0x1008, r1))
            .copied()
            .expect("use at ip=0x1008");
        assert!(matches!(
            ssa.defs[reach.0 as usize].site,
            DefSite::Insn(ip) if ip == 0x1000
        ));
    }
}

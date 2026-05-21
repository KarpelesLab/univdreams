//! BPF argument / return-type inference (decompile L6b).
//!
//! BPF's calling convention is fixed by the verifier:
//! arguments arrive in r1..r5, the return value goes in r0,
//! and r6..r9 are callee-saved. So "what's this function's
//! argument arity?" reduces to "which of r1..r5 are *read
//! before they are written* on any reachable path?".
//!
//! The implementation here is a one-pass linear scan over the
//! function's `DecodedInsn` stream — flow-insensitive but
//! enough to find the common cases (the first instruction
//! typically reads r1; argument 2's first use is shortly
//! after). A full SSA / data-flow pass is L6a's territory
//! and would refine this for edge cases (e.g. a function that
//! writes r1 in a side branch before any read of r1 in the
//! same control-flow region).
//!
//! For the return type, we look for an explicit write to r0
//! anywhere in the body. If we find one, the function returns
//! a `u64`. Otherwise it's `void` (rendered as the AST's
//! `Type::Unknown` since the `.ud` source language doesn't
//! have a dedicated unit type).
//!
//! Round-trip safety: this layer only fills
//! `FnDecl.signature`. The `@asm` byte stream is untouched, so
//! the recompiled binary is byte-identical regardless of what
//! inference produces. Editing the rendered signature is
//! cosmetic — the lower path doesn't consume it.

use ud_arch_bpf::{DecodedInsn, InsnKind};
use ud_ast::{Param, Signature, Type};
use ud_ir::Function;

/// Infer a `Signature` for a BPF function. Returns `None` when
/// the function has no detectable arguments AND no detectable
/// return — i.e. the inference produced a `fn name()` form
/// that's no different from the existing default, so we skip
/// the AST-level addition.
#[must_use]
pub fn infer_bpf_signature(f: &Function<DecodedInsn>) -> Option<Signature> {
    let mut read_before_write = [false; 11];
    let mut written = [false; 11];

    for block in &f.blocks {
        for insn in &block.insns {
            for r in reads_of(insn) {
                if !written[r as usize] {
                    read_before_write[r as usize] = true;
                }
            }
            for w in writes_of(insn) {
                written[w as usize] = true;
            }
        }
    }

    // Consecutive r1..r5 that are read-before-written → arg
    // count. Stop at the first gap.
    let mut arity = 0;
    for r in 1..=5u8 {
        if read_before_write[r as usize] {
            arity = r;
        } else {
            break;
        }
    }

    // Return type: was r0 ever written on any path?
    let returns_u64 = written[0];

    if arity == 0 && !returns_u64 {
        return None;
    }

    let params = (0..arity)
        .map(|i| Param {
            name: format!("arg_{i}"),
            ty: Type::U64,
            location: Some(format!("r{}", i + 1)),
        })
        .collect();
    let return_type = if returns_u64 {
        Type::U64
    } else {
        Type::Unknown
    };
    Some(Signature {
        params,
        return_type,
    })
}

/// Registers read by `insn`. Returned as an arrayvec-shaped
/// `Vec<u8>` (BPF only ever reads up to 2 registers per
/// instruction, so the allocation is tiny). Callers can take
/// the union for liveness without worrying about double-
/// counting because the inference state is keyed by register
/// number.
#[allow(clippy::match_same_arms)]
fn reads_of(insn: &DecodedInsn) -> Vec<u8> {
    let class = insn.opcode & 0x07;
    let op_nibble = insn.opcode >> 4;
    let is_reg_src = (insn.opcode & 0x08) != 0;
    let mut out = Vec::new();
    match class {
        // BPF_LD (0x00) — unconditional load (LDDW + LD_ABS/IND).
        // LDDW writes dst, reads nothing. LD_ABS / LD_IND read
        // an implicit packet pointer (skb-relative) we ignore.
        0x00 => {}
        // BPF_LDX (0x01) — `ldxN dst, [src + offset]`. Reads
        // src.
        0x01 => out.push(insn.src),
        // BPF_ST (0x02) — `stN [dst + off], imm`. Reads dst
        // (memory base).
        0x02 => out.push(insn.dst),
        // BPF_STX (0x03) — `stxN [dst + off], src`. Reads both.
        0x03 => {
            out.push(insn.dst);
            out.push(insn.src);
        }
        // BPF_ALU{32,64} — reads dst when the op isn't MOV;
        // also reads src for register-source forms. MOV
        // overwrites dst without reading.
        0x04 | 0x07 => {
            // 0xb = MOV, 0xd = END (single-operand). For all
            // other op nibbles the destination is read.
            if !matches!(op_nibble, 0xb | 0xd) {
                out.push(insn.dst);
            }
            if is_reg_src {
                out.push(insn.src);
            }
        }
        // BPF_JMP / BPF_JMP32. CALL_IMM reads r1..r5 (we model
        // it as if it reads everything that might be an arg);
        // EXIT reads r0; everything else reads dst (and src
        // for register-source forms).
        0x05 | 0x06 => match insn.kind {
            InsnKind::Call => {
                // We don't know the callee's arity here; be
                // conservative and assume up to 5 args. The
                // arity-detection caller will winnow this
                // back when it considers only consecutive
                // r1..r5.
                out.extend_from_slice(&[1, 2, 3, 4, 5]);
            }
            InsnKind::CallReg => out.push(insn.dst),
            InsnKind::Exit => out.push(0),
            InsnKind::Jmp => {}
            _ => {
                out.push(insn.dst);
                if is_reg_src {
                    out.push(insn.src);
                }
            }
        },
        _ => {}
    }
    out.retain(|&r| r <= 10);
    out
}

/// Registers written by `insn`. BPF has a single write target
/// per instruction (the dst register), with a couple of
/// exceptions: stores don't write registers, exits don't, and
/// CALL writes r0 (the return value).
#[allow(clippy::match_same_arms)]
fn writes_of(insn: &DecodedInsn) -> Vec<u8> {
    let class = insn.opcode & 0x07;
    match class {
        // BPF_LD / BPF_LDX — write dst.
        0x00 | 0x01 => vec![insn.dst],
        // BPF_ST / BPF_STX — write memory, not a register.
        0x02 | 0x03 => Vec::new(),
        // BPF_ALU / BPF_ALU64 — write dst.
        0x04 | 0x07 => vec![insn.dst],
        // CALL writes r0 (the return value). EXIT writes
        // nothing. Conditional jumps write nothing.
        0x05 | 0x06 => match insn.kind {
            InsnKind::Call | InsnKind::CallReg => vec![0],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
    .into_iter()
    .filter(|&r| r <= 10)
    .collect()
}

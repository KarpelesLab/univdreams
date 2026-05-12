//! Pattern: render common SIMD / vector ops as assignment-form.
//!
//! Most of the DLL's hot path is MMX/SSE vector math — `paddw`,
//! `pxor`, `movq`, `psrlw`, etc. — that's left as raw `@asm` lines
//! by every other pattern. The data dependencies are still clear
//! to anyone who reads x86 SIMD, but the visual style clashes
//! with the lifted GP code: everything else reads as
//! `dst = src op X`, the vector ops read as `op dst, src`.
//!
//! This pattern lifts the common shapes to the same assignment
//! form so a function body has a consistent rendering. It's a
//! cosmetic pass — the bytes still encode the original
//! instructions and the operations remain vector / SIMD; the
//! source just doesn't switch styles mid-function.
//!
//! Recognised:
//!
//! * Vector moves — `movq`, `movd`, `movaps`, `movups`, `movdqa`,
//!   `movdqu`, `movss`, `movsd`, `movhps`, `movlps` →
//!   `dst = src`.
//! * Vector arithmetic — `paddb`, `paddw`, `paddd`, `psubb`,
//!   `psubw`, `psubd`, `pmullw`, `pmulhw`, `pmullw`, `paddusb`,
//!   `paddusw`, `psubusb`, `psubusw`, `paddsb`, `paddsw`,
//!   `psubsb`, `psubsw` → `dst = dst + src` / `dst - src` / `dst
//!   * src`.
//! * Vector logical — `pand`, `por`, `pxor`, `pandn` → `dst =
//!   dst & src` / `| src` / `^ src` / `& ~src`.
//! * Vector shift — `psllw`, `pslld`, `psllq`, `psrlw`, `psrld`,
//!   `psrlq`, `psraw`, `psrad` → `dst = dst << src` / `>> src`.
//! * SSE float arith — `addss`, `addsd`, `addps`, `addpd`,
//!   `subss`, `subsd`, `subps`, `subpd`, `mulss`, `mulsd`, etc.
//!
//! Not lifted (would mislead): shuffles (`shufps`, `pshufw`),
//! pack/unpack (`packuswb`, `punpcklbw`), conversions (`cvtsi2sd`,
//! `cvtps2dq`), maskmov, prefetch. Those need their actual
//! semantics spelled out; leaving them as `@asm` is honest.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct SimdExpr;

impl Pattern for SimdExpr {
    fn name(&self) -> &'static str {
        "simd_expr"
    }

    fn tentative(
        &self,
        _ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        let shape = classify(ins.iced.mnemonic())?;
        let full = format_intel(&ins.iced);
        let (prefix_len, kind) = match shape {
            Shape::Move(prefix) => (prefix.len(), Op::Move),
            Shape::Binary(prefix, op) => (prefix.len(), Op::Binary(op)),
        };
        let rest = full.get(prefix_len..)?;
        let (dst, src) = super::mov::split_two_operands(&full, &full[..prefix_len])?;
        let _ = rest;
        let new_src = match kind {
            Op::Move => src,
            Op::Binary(op) => format!("{dst} {op} {src}"),
        };
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            // Below the structural lifts and the GP `mov` (so a
            // mem_via_reg/lms fold still wins) but above the bare
            // `@asm` fallback.
            priority: 30,
            stmts: vec![Stmt::Move {
                dst,
                src: new_src,
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
}

enum Shape {
    Move(&'static str),
    Binary(&'static str, &'static str),
}

enum Op {
    Move,
    Binary(&'static str),
}

#[allow(clippy::too_many_lines)]
fn classify(m: Mnemonic) -> Option<Shape> {
    Some(match m {
        // Vector / FP moves: `<mnemonic> dst, src` → `dst = src`.
        Mnemonic::Movq => Shape::Move("movq "),
        Mnemonic::Movd => Shape::Move("movd "),
        Mnemonic::Movaps => Shape::Move("movaps "),
        Mnemonic::Movups => Shape::Move("movups "),
        Mnemonic::Movapd => Shape::Move("movapd "),
        Mnemonic::Movupd => Shape::Move("movupd "),
        Mnemonic::Movdqa => Shape::Move("movdqa "),
        Mnemonic::Movdqu => Shape::Move("movdqu "),
        Mnemonic::Movss => Shape::Move("movss "),
        Mnemonic::Movsd => Shape::Move("movsd "),
        Mnemonic::Movhps => Shape::Move("movhps "),
        Mnemonic::Movlps => Shape::Move("movlps "),
        Mnemonic::Movhpd => Shape::Move("movhpd "),
        Mnemonic::Movlpd => Shape::Move("movlpd "),

        // Packed integer add / sub / multiply.
        Mnemonic::Paddb => Shape::Binary("paddb ", "+"),
        Mnemonic::Paddw => Shape::Binary("paddw ", "+"),
        Mnemonic::Paddd => Shape::Binary("paddd ", "+"),
        Mnemonic::Paddq => Shape::Binary("paddq ", "+"),
        Mnemonic::Paddsb => Shape::Binary("paddsb ", "+"),
        Mnemonic::Paddsw => Shape::Binary("paddsw ", "+"),
        Mnemonic::Paddusb => Shape::Binary("paddusb ", "+"),
        Mnemonic::Paddusw => Shape::Binary("paddusw ", "+"),
        Mnemonic::Psubb => Shape::Binary("psubb ", "-"),
        Mnemonic::Psubw => Shape::Binary("psubw ", "-"),
        Mnemonic::Psubd => Shape::Binary("psubd ", "-"),
        Mnemonic::Psubq => Shape::Binary("psubq ", "-"),
        Mnemonic::Psubsb => Shape::Binary("psubsb ", "-"),
        Mnemonic::Psubsw => Shape::Binary("psubsw ", "-"),
        Mnemonic::Psubusb => Shape::Binary("psubusb ", "-"),
        Mnemonic::Psubusw => Shape::Binary("psubusw ", "-"),
        Mnemonic::Pmullw => Shape::Binary("pmullw ", "*"),
        Mnemonic::Pmulhw => Shape::Binary("pmulhw ", "*"),
        Mnemonic::Pmulhuw => Shape::Binary("pmulhuw ", "*"),
        Mnemonic::Pmuludq => Shape::Binary("pmuludq ", "*"),

        // Packed logical.
        Mnemonic::Pand => Shape::Binary("pand ", "&"),
        Mnemonic::Por => Shape::Binary("por ", "|"),
        Mnemonic::Pxor => Shape::Binary("pxor ", "^"),
        Mnemonic::Pandn => Shape::Binary("pandn ", "& ~"),

        // Packed shift (immediate or register count).
        Mnemonic::Psllw => Shape::Binary("psllw ", "<<"),
        Mnemonic::Pslld => Shape::Binary("pslld ", "<<"),
        Mnemonic::Psllq => Shape::Binary("psllq ", "<<"),
        Mnemonic::Psrlw => Shape::Binary("psrlw ", ">>"),
        Mnemonic::Psrld => Shape::Binary("psrld ", ">>"),
        Mnemonic::Psrlq => Shape::Binary("psrlq ", ">>"),
        Mnemonic::Psraw => Shape::Binary("psraw ", ">>"),
        Mnemonic::Psrad => Shape::Binary("psrad ", ">>"),

        // SSE scalar / packed float arithmetic.
        Mnemonic::Addss => Shape::Binary("addss ", "+"),
        Mnemonic::Addsd => Shape::Binary("addsd ", "+"),
        Mnemonic::Addps => Shape::Binary("addps ", "+"),
        Mnemonic::Addpd => Shape::Binary("addpd ", "+"),
        Mnemonic::Subss => Shape::Binary("subss ", "-"),
        Mnemonic::Subsd => Shape::Binary("subsd ", "-"),
        Mnemonic::Subps => Shape::Binary("subps ", "-"),
        Mnemonic::Subpd => Shape::Binary("subpd ", "-"),
        Mnemonic::Mulss => Shape::Binary("mulss ", "*"),
        Mnemonic::Mulsd => Shape::Binary("mulsd ", "*"),
        Mnemonic::Mulps => Shape::Binary("mulps ", "*"),
        Mnemonic::Mulpd => Shape::Binary("mulpd ", "*"),
        Mnemonic::Divss => Shape::Binary("divss ", "/"),
        Mnemonic::Divsd => Shape::Binary("divsd ", "/"),
        Mnemonic::Divps => Shape::Binary("divps ", "/"),
        Mnemonic::Divpd => Shape::Binary("divpd ", "/"),

        // SSE bitwise on float vectors.
        Mnemonic::Xorps => Shape::Binary("xorps ", "^"),
        Mnemonic::Xorpd => Shape::Binary("xorpd ", "^"),
        Mnemonic::Andps => Shape::Binary("andps ", "&"),
        Mnemonic::Andpd => Shape::Binary("andpd ", "&"),
        Mnemonic::Orps => Shape::Binary("orps ", "|"),
        Mnemonic::Orpd => Shape::Binary("orpd ", "|"),
        Mnemonic::Andnps => Shape::Binary("andnps ", "& ~"),
        Mnemonic::Andnpd => Shape::Binary("andnpd ", "& ~"),

        _ => return None,
    })
}

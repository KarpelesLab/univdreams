//! Pattern: 2-operand arithmetic / logical / shift → `@move`.
//!
//! Folds the canonical `dst op= src` shape: `add eax, 5`,
//! `sub esp, 8`, `and ebx, 0Fh`, `shl ecx, 3`, etc. Both operands
//! come from the iced formatter so memory references survive
//! verbatim.
//!
//! The lifted form uses `@move("dst", "dst OP src", [bytes])` so
//! the reader sees an explicit `eax = eax + 5` rather than a bare
//! `add eax, 5`. That keeps the AST shape uniform (every "produces
//! a value into dst" instruction shows up as `@move`) without
//! introducing a new directive.
//!
//! `cmp` / `test` are deliberately omitted — they set flags
//! without storing. Conditional adds / subs that depend on flag
//! input (`adc`, `sbb`) are also omitted; their semantic depends
//! on carry, which a pure "dst = dst + src" rendering would hide.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct Arith;

impl Pattern for Arith {
    fn name(&self) -> &'static str {
        "arith"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        let (prefix, op) = match ins.iced.mnemonic() {
            Mnemonic::Add => ("add ", "+"),
            Mnemonic::Sub => ("sub ", "-"),
            Mnemonic::And => ("and ", "&"),
            Mnemonic::Or => ("or ", "|"),
            Mnemonic::Xor => ("xor ", "^"),
            Mnemonic::Shl => ("shl ", "<<"),
            // x86 SHR/SAL share opcode bytes; iced canonicalises
            // to Shl above. Plain Shr is logical shift right.
            Mnemonic::Shr => ("shr ", ">>"),
            Mnemonic::Sar => ("sar ", ">>"), // arithmetic shift right
            // Rotates aren't strictly `op=` semantics but they
            // still produce a value into the destination; rendering
            // them as compound assignment preserves intent.
            Mnemonic::Rol => ("rol ", "<<<"),
            Mnemonic::Ror => ("ror ", ">>>"),
            _ => return None,
        };
        let (dst_raw, src_raw) = super::mov::split_two_operands(&format_intel(&ins.iced), prefix)?;
        let sp = ctx.sp_delta_at.get(&ins.iced.ip()).copied();
        let dst = ud_arch_x86::rename_operand_in_ctx(&dst_raw, sp);
        let src = ud_arch_x86::rename_operand_in_ctx(&src_raw, sp);
        // Render the assignment form so the destination's reuse is
        // explicit: `eax = eax + 5` (vs `add eax, 5`).
        let new_src = format!("{dst} {op} {src}");
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            // Below mov/lea so an arithmetic xor that's actually
            // zero (handled by XorZero, priority 100) still wins.
            priority: 40,
            stmts: vec![Stmt::Move {
                dst,
                src: new_src,
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
}

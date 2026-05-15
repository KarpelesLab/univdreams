//! Pattern: `movzx` / `movsx` → `@move`.
//!
//! x86 has separate mnemonics for "load a narrower memory operand
//! into a wider register":
//!
//! * `movzx reg32, byte ptr [...]` — zero-extend.
//! * `movsx reg32, word ptr [...]` — sign-extend.
//!
//! Both are still semantically a `dst := src` move; the size
//! mismatch in the rendered operand text (`movzx eax, byte ptr
//! [ebp+8]`) carries the extension semantics.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct MovExtend;

impl Pattern for MovExtend {
    fn name(&self) -> &'static str {
        "mov_extend"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        let prefix = match ins.iced.mnemonic() {
            Mnemonic::Movzx => "movzx ",
            Mnemonic::Movsx => "movsx ",
            Mnemonic::Movsxd => "movsxd ",
            _ => return None,
        };
        let (dst, src) = super::mov::split_two_operands(&format_intel(&ins.iced), prefix)?;
        let sp = ctx.sp_delta_at.get(&ins.iced.ip()).copied();
        let dst = ud_arch_x86::rename_operand_in_ctx(&dst, sp);
        let src = ud_arch_x86::rename_operand_in_ctx(&src, sp);
        // Preserve the extend mnemonic in the source operand so the
        // reader can tell zero-extend from sign-extend without
        // reading the bytes.
        let src = format!("{} {src}", prefix.trim_end());
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            priority: 50,
            stmts: vec![Stmt::Move {
                dst,
                src,
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
}

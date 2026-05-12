//! Pattern: single-instruction `mov dst, src` → `@move`.
//!
//! Every x86 backend emits a flood of `mov` instructions to shuffle
//! values between registers, locals, and globals. Folding each one
//! into a `@move(dst, src, [bytes])` directive lets a reader see
//! the data flow instead of one `mov`-prefixed `@asm` per line.
//!
//! Scope is intentionally narrow: only `Mnemonic::Mov` matches.
//! The MMX/SSE variants (`MOVQ`, `MOVD`, `MOVDQA`, …) have
//! different mnemonics in iced and stay as `@asm` for now —
//! they often imply more than a plain assignment and deserve
//! their own treatment.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct Mov;

impl Pattern for Mov {
    fn name(&self) -> &'static str {
        "mov"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        if ins.iced.mnemonic() != Mnemonic::Mov {
            return None;
        }
        let (dst, src) = split_two_operands(&format_intel(&ins.iced), "mov ")?;
        let sp = ctx.sp_delta_at.get(&ins.iced.ip()).copied();
        let dst = ud_arch_x86::rename_operand_in_ctx(&dst, sp);
        let src = ud_arch_x86::rename_operand_in_ctx(&src, sp);
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            // Low priority so higher-value lifts (calls, prologues,
            // etc.) win when they overlap.
            priority: 50,
            stmts: vec![Stmt::Move {
                dst,
                src,
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
}

/// Split `"<prefix> <dst>, <src>"` into `(dst, src)` strings,
/// trimmed of surrounding whitespace. Returns `None` if the text
/// doesn't have the expected prefix or doesn't contain a comma.
pub(super) fn split_two_operands(full: &str, prefix: &str) -> Option<(String, String)> {
    let rest = full.strip_prefix(prefix)?;
    let (dst, src) = rest.split_once(',')?;
    Some((dst.trim().to_string(), src.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use ud_arch_x86::{decode, Bitness};

    fn ctx() -> PatternCtx<'static> {
        let map: &'static HashMap<u64, String> = Box::leak(Box::new(HashMap::new()));
        let sp_map: &'static HashMap<u64, i64> = Box::leak(Box::new(HashMap::new()));
        PatternCtx {
            fn_addr_start: 0,
            fn_addr_end: u64::MAX,
            name_at: map,
            sp_delta_at: sp_map,
        }
    }

    #[test]
    fn lifts_mov_reg_reg() {
        let bytes = [0x89, 0xc3]; // mov ebx, eax
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = Mov.tentative(&ctx(), &insns, 0).expect("match");
        if let Some(Stmt::Move { dst, src, .. }) = c.stmts.first() {
            assert_eq!(dst, "ebx");
            assert_eq!(src, "eax");
        } else {
            panic!("expected Move");
        }
    }

    #[test]
    fn lifts_mov_mem_imm() {
        // `mov dword ptr [ebp-4], 5` — the `[ebp-4]` operand renames
        // to the source-language slot name `var_4` (Ghidra/IDA
        // convention), so the lift produces a Move whose dst is the
        // named slot, not the raw memory expression.
        let bytes = [0xc7, 0x45, 0xfc, 0x05, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = Mov.tentative(&ctx(), &insns, 0).expect("match");
        if let Some(Stmt::Move { dst, src, .. }) = c.stmts.first() {
            assert_eq!(dst, "var_4");
            assert_eq!(src, "5");
        }
    }

    #[test]
    fn skips_non_mov() {
        let bytes = [0x53]; // push ebx
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        assert!(Mov.tentative(&ctx(), &insns, 0).is_none());
    }
}

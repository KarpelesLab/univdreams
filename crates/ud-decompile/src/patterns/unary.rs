//! Pattern: single-operand `inc / dec / neg / not` → `@move`.
//!
//! These four instructions all "store-back into their operand" with
//! a simple unary transformation; folding them to `@move` puts them
//! in the same shape as the binary [`super::arith`] lifts.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct Unary;

impl Pattern for Unary {
    fn name(&self) -> &'static str {
        "unary"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        let (prefix, render): (&str, fn(&str) -> String) = match ins.iced.mnemonic() {
            Mnemonic::Inc => ("inc ", |d| format!("{d} + 1")),
            Mnemonic::Dec => ("dec ", |d| format!("{d} - 1")),
            Mnemonic::Neg => ("neg ", |d| format!("-{d}")),
            Mnemonic::Not => ("not ", |d| format!("~{d}")),
            _ => return None,
        };
        let full = format_intel(&ins.iced);
        let dst_raw = full.strip_prefix(prefix)?.trim().to_string();
        if dst_raw.is_empty() {
            return None;
        }
        let sp = ctx.sp_delta_at.get(&ins.iced.ip()).copied();
        let dst = ud_arch_x86::rename_operand_in_ctx(&dst_raw, sp);
        let src = render(&dst);
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

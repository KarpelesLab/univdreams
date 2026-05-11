//! Pattern: `imul` 2-/3-operand forms → `@move`.
//!
//! x86's `imul` has multiple shapes. The two productively
//! liftable ones in this pass are:
//!
//! * 2-operand: `imul reg, src` — `reg = reg * src`.
//! * 3-operand: `imul reg, src, imm` — `reg = src * imm`.
//!
//! The 1-operand form (`imul src` — accumulates into edx:eax) is
//! left as `@asm` since it has an implicit destination not visible
//! in the operand text.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct Imul;

impl Pattern for Imul {
    fn name(&self) -> &'static str {
        "imul"
    }

    fn tentative(
        &self,
        _ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        if ins.iced.mnemonic() != Mnemonic::Imul {
            return None;
        }
        let op_count = ins.iced.op_count();
        let full = format_intel(&ins.iced);
        let rest = full.strip_prefix("imul ")?;
        let parts: Vec<&str> = rest.split(',').map(str::trim).collect();
        let (dst, src) = match op_count {
            2 => {
                if parts.len() != 2 {
                    return None;
                }
                let dst = parts[0].to_string();
                let src = format!("{} * {}", parts[0], parts[1]);
                (dst, src)
            }
            3 => {
                if parts.len() != 3 {
                    return None;
                }
                let dst = parts[0].to_string();
                let src = format!("{} * {}", parts[1], parts[2]);
                (dst, src)
            }
            _ => return None,
        };
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

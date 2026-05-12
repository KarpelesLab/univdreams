//! Pattern: `lea reg, [addr_expr]` → `@move("reg", "&addr_expr",
//! [bytes])`.
//!
//! `lea` semantically computes the effective address rather than
//! loading from it — equivalent to `reg = &addr_expr` in C. Both
//! pointer arithmetic (compilers love `lea eax, [ebx*4+esi]` as
//! a multiply-add) and "take the address of a local" land here.
//!
//! Rendering as `@move(reg, &addr_expr)` lets the reader see the
//! `&` prefix as the LEA marker without losing the original
//! syntax.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct Lea;

impl Pattern for Lea {
    fn name(&self) -> &'static str {
        "lea"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        if ins.iced.mnemonic() != Mnemonic::Lea {
            return None;
        }
        let (dst, src) = super::mov::split_two_operands(&format_intel(&ins.iced), "lea ")?;
        let sp = ctx.sp_delta_at.get(&ins.iced.ip()).copied();
        // Prepend `&` so the address-of semantics are visible. The
        // address itself runs through slot renaming — `lea eax,
        // [ebp+8]` reads `eax = &arg_8`, which is the right level of
        // abstraction for a "pointer to local/arg" idiom.
        let src = format!("&{}", ud_arch_x86::rename_operand_in_ctx(&src, sp));
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            priority: 50,
            stmts: vec![Stmt::Move {
                dst: ud_arch_x86::rename_operand_in_ctx(&dst, sp),
                src,
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
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
    fn lifts_lea_reg_mem() {
        // lea eax, [ebx+ecx*4]
        let bytes = [0x8d, 0x04, 0x8b];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = Lea.tentative(&ctx(), &insns, 0).expect("match");
        if let Some(Stmt::Move { dst, src, .. }) = c.stmts.first() {
            assert_eq!(dst, "eax");
            assert!(src.starts_with('&'), "src should start with &, got {src}");
        }
    }
}

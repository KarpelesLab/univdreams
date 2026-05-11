//! Pattern: `xor reg, reg` → `reg = 0`.
//!
//! Every x86 compiler emits `xor reg, reg` rather than
//! `mov reg, 0` because it's one byte shorter. Folding it into a
//! `@move` directive makes the intent clear without losing the
//! original bytes.

use ud_arch_x86::{DecodedInsn, Mnemonic, OpKind};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct XorZero;

impl Pattern for XorZero {
    fn name(&self) -> &'static str {
        "xor_zero"
    }

    fn tentative(
        &self,
        _ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        if ins.iced.mnemonic() != Mnemonic::Xor {
            return None;
        }
        if ins.iced.op_count() != 2 {
            return None;
        }
        if ins.iced.op0_kind() != OpKind::Register || ins.iced.op1_kind() != OpKind::Register {
            return None;
        }
        let r0 = ins.iced.op0_register();
        let r1 = ins.iced.op1_register();
        if r0 != r1 {
            return None;
        }
        let reg_name = format!("{r0:?}").to_lowercase();
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            priority: 100,
            stmts: vec![Stmt::Move {
                dst: reg_name,
                src: "0".into(),
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
        PatternCtx {
            fn_addr_start: 0,
            fn_addr_end: u64::MAX,
            name_at: map,
        }
    }

    /// `xor eax, eax` → @move("eax", "0", [0x31, 0xc0])
    #[test]
    fn xor_eax_eax_zero() {
        let bytes = [0x31, 0xc0];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = XorZero.tentative(&ctx(), &insns, 0).expect("match");
        assert_eq!(c.consumed, 1);
        if let Some(Stmt::Move { dst, src, .. }) = c.stmts.first() {
            assert_eq!(dst, "eax");
            assert_eq!(src, "0");
        } else {
            panic!("expected Move");
        }
    }

    /// `xor eax, ebx` (different registers) doesn't match.
    #[test]
    fn skips_non_zeroing_xor() {
        let bytes = [0x31, 0xd8]; // xor eax, ebx
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        assert!(XorZero.tentative(&ctx(), &insns, 0).is_none());
    }
}

//! Pattern: load + modify + store through a scratch register.
//!
//! Three-instruction sibling of [`mem_via_reg`]: the compiler
//! routes a value through a register so it can be arithmetically
//! adjusted before being written back to memory. Common shapes:
//!
//! ```text
//! mov eax, [ebp+8]      ; load arg
//! add eax, 5            ; modify
//! mov [ebp-4], eax      ; store
//! ```
//!
//! Folded to `var_4 = arg_8 + 5` — one line, no scratch register
//! mentioned. Bytes for all three instructions are concatenated and
//! pinned on the Move so the lower path emits the original encoding
//! verbatim. The scratch register still gets loaded / modified by
//! the original bytes, so any later code that reads it still sees
//! the same value.
//!
//! Recognised modify ops: add / sub / and / or / xor / shl / shr /
//! sar / rol / ror — the same set the [`arith`] pattern handles.
//! Unary ops (inc / dec / neg / not) are folded analogously.
//!
//! Constraints (kept conservative for safety):
//!
//! * Strictly three adjacent instructions.
//! * Same scratch register in all three slots.
//! * The store's destination must be a memory operand — a
//!   register-to-register store would hide the second register
//!   write, which we avoid until we have proper lifetime analysis.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic, OpKind};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct LoadModifyStore;

impl Pattern for LoadModifyStore {
    fn name(&self) -> &'static str {
        "load_modify_store"
    }

    #[allow(clippy::too_many_lines)]
    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let load = insns.get(start)?;
        let modify = insns.get(start + 1)?;
        let store = insns.get(start + 2)?;
        if load.iced.mnemonic() != Mnemonic::Mov || store.iced.mnemonic() != Mnemonic::Mov {
            return None;
        }
        // Load: reg ← something.
        if load.iced.op0_kind() != OpKind::Register {
            return None;
        }
        let scratch = load.iced.op0_register();
        // Store: memory ← same reg.
        if store.iced.op0_kind() != OpKind::Memory
            || store.iced.op1_kind() != OpKind::Register
            || store.iced.op1_register() != scratch
        {
            return None;
        }
        // Modify: reg ← reg op X  (binary) or reg++/reg--/-reg/~reg (unary).
        if modify.iced.op0_kind() != OpKind::Register
            || modify.iced.op0_register() != scratch
        {
            return None;
        }
        let modify_text = format_intel(&modify.iced);
        let sp = ctx.sp_delta_at.get(&load.iced.ip()).copied();
        let modify_form = match modify.iced.mnemonic() {
            Mnemonic::Add => ModifyForm::Binary("+", "add "),
            Mnemonic::Sub => ModifyForm::Binary("-", "sub "),
            Mnemonic::And => ModifyForm::Binary("&", "and "),
            Mnemonic::Or => ModifyForm::Binary("|", "or "),
            Mnemonic::Xor => ModifyForm::Binary("^", "xor "),
            Mnemonic::Shl => ModifyForm::Binary("<<", "shl "),
            Mnemonic::Shr | Mnemonic::Sar => ModifyForm::Binary(">>", "shr "),
            Mnemonic::Rol => ModifyForm::Binary("<<<", "rol "),
            Mnemonic::Ror => ModifyForm::Binary(">>>", "ror "),
            Mnemonic::Inc => ModifyForm::Unary("+ 1"),
            Mnemonic::Dec => ModifyForm::Unary("- 1"),
            Mnemonic::Neg => ModifyForm::UnaryPrefix("-"),
            Mnemonic::Not => ModifyForm::UnaryPrefix("~"),
            _ => return None,
        };

        // Render the source-language operands. The load's source is
        // what we're starting with; the store's destination is where
        // the result lands. Both go through the SP-aware renamer so
        // stack slots show up by their named-slot form.
        let (_, load_src_raw) =
            super::mov::split_two_operands(&format_intel(&load.iced), "mov ")?;
        let (store_dst_raw, _) =
            super::mov::split_two_operands(&format_intel(&store.iced), "mov ")?;
        let load_src = ud_arch_x86::rename_operand_in_ctx(&load_src_raw, sp);
        let store_dst = ud_arch_x86::rename_operand_in_ctx(&store_dst_raw, sp);

        let new_src = match modify_form {
            ModifyForm::Binary(op_sym, op_prefix) => {
                let (_, x_raw) = super::mov::split_two_operands(&modify_text, op_prefix)?;
                let x = ud_arch_x86::rename_operand_in_ctx(&x_raw, sp);
                format!("{load_src} {op_sym} {x}")
            }
            ModifyForm::Unary(suffix) => format!("{load_src} {suffix}"),
            ModifyForm::UnaryPrefix(prefix) => format!("{prefix}{load_src}"),
        };

        let mut bytes = Vec::with_capacity(
            load.original_bytes.len() + modify.original_bytes.len() + store.original_bytes.len(),
        );
        bytes.extend_from_slice(&load.original_bytes);
        bytes.extend_from_slice(&modify.original_bytes);
        bytes.extend_from_slice(&store.original_bytes);

        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 3,
            // Above `mem_via_reg` (60) so a 3-insn LMS fold wins
            // over the bare-store fold when both apply. Still below
            // the structural lifts (calls / prologues) so they get
            // first crack at the window.
            priority: 70,
            stmts: vec![Stmt::Move {
                dst: store_dst,
                src: new_src,
                bytes,
            }],
        })
    }
}

enum ModifyForm {
    /// `<op-symbol>`, `<iced-prefix-with-trailing-space>` — produces
    /// `dst = src <op-symbol> X` where `X` is the modify
    /// instruction's second operand.
    Binary(&'static str, &'static str),
    /// Operand goes left of a textual suffix: `dst = src <suffix>`.
    /// Used for `inc` / `dec` which renders as `+ 1` / `- 1`.
    Unary(&'static str),
    /// Operand goes right of a textual prefix: `dst = <prefix>src`.
    /// Used for `neg` (`-src`) / `not` (`~src`).
    UnaryPrefix(&'static str),
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

    /// `mov eax, [ebp+8]; add eax, 5; mov [ebp-4], eax` folds to one
    /// Move that reads `var_4 = arg_8 + 5`.
    #[test]
    fn folds_load_add_store() {
        let bytes = [
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x83, 0xc0, 0x05, // add eax, 5
            0x89, 0x45, 0xfc, // mov [ebp-4], eax
        ];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = LoadModifyStore.tentative(&ctx(), &insns, 0).expect("match");
        assert_eq!(c.consumed, 3);
        let Some(Stmt::Move { dst, src, bytes: out }) = c.stmts.first() else {
            panic!("expected Stmt::Move");
        };
        assert_eq!(dst, "var_4");
        assert_eq!(src, "arg_8 + 5");
        assert_eq!(out, &bytes);
    }

    /// Unary form: `mov eax, [ebp+8]; inc eax; mov [ebp-4], eax` →
    /// `var_4 = arg_8 + 1`.
    #[test]
    fn folds_load_inc_store() {
        let bytes = [
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x40,             // inc eax
            0x89, 0x45, 0xfc, // mov [ebp-4], eax
        ];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = LoadModifyStore.tentative(&ctx(), &insns, 0).expect("match");
        let Some(Stmt::Move { dst, src, .. }) = c.stmts.first() else {
            panic!();
        };
        assert_eq!(dst, "var_4");
        assert_eq!(src, "arg_8 + 1");
    }

    /// Register-to-register store shouldn't fold (would hide the
    /// second register write).
    #[test]
    fn skips_reg_destination() {
        let bytes = [
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x83, 0xc0, 0x05, // add eax, 5
            0x89, 0xc3,       // mov ebx, eax
        ];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        assert!(LoadModifyStore.tentative(&ctx(), &insns, 0).is_none());
    }

    /// Mismatched scratch register: load uses eax but modify
    /// touches ecx — no fold.
    #[test]
    fn skips_mismatched_register() {
        let bytes = [
            0x8b, 0x45, 0x08, // mov eax, [ebp+8]
            0x83, 0xc1, 0x05, // add ecx, 5
            0x89, 0x4d, 0xfc, // mov [ebp-4], ecx
        ];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        assert!(LoadModifyStore.tentative(&ctx(), &insns, 0).is_none());
    }
}

//! Pattern: memory copy routed through a scratch register.
//!
//! x86 doesn't have memory-to-memory moves, so the compiler always
//! emits a load-into-register followed by a store-from-register for
//! any `[mem] = [other_mem]` copy. The two instructions are usually
//! adjacent:
//!
//! ```text
//! mov eax, [ebp+8]      ; load
//! mov [ebp-4], eax      ; store
//! ```
//!
//! This pattern folds the pair into a single `[ebp-4] = [ebp+8]`
//! Move (operand renaming makes that read `var_4 = arg_8`). Bytes
//! for both instructions are concatenated and pinned on the Move so
//! the lower path emits the original encoding verbatim.
//!
//! Constraints (kept conservative so the fold is always semantics-
//! preserving in straight-line code):
//!
//! * The first mov's destination must be a register; the second
//!   mov's source must be the same register.
//! * The second mov's destination must be a memory operand — folding
//!   when both sides are registers (`mov eax, X; mov ebx, eax`) is
//!   correct value-wise but hides the second register's write,
//!   which we don't want without proper lifetime tracking.
//! * The two `mov`s must be strictly adjacent — no intervening
//!   instruction may read or clobber the scratch register.
//!
//! The scratch register still gets loaded by the original bytes (we
//! pin them, after all), so any later code that reads it still
//! sees the loaded value — the fold is purely a source-language
//! abstraction over the byte-level routing.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic, OpKind};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct MemViaReg;

impl Pattern for MemViaReg {
    fn name(&self) -> &'static str {
        "mem_via_reg"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let load = insns.get(start)?;
        let store = insns.get(start + 1)?;
        if load.iced.mnemonic() != Mnemonic::Mov || store.iced.mnemonic() != Mnemonic::Mov {
            return None;
        }
        // First mov: dst must be a register.
        if load.iced.op0_kind() != OpKind::Register {
            return None;
        }
        let scratch = load.iced.op0_register();
        // Second mov: dst memory, src = the scratch register.
        if store.iced.op0_kind() != OpKind::Memory {
            return None;
        }
        if store.iced.op1_kind() != OpKind::Register
            || store.iced.op1_register() != scratch
        {
            return None;
        }
        // Build the source-language operands. The load's source is
        // what we're copying *from*; the store's destination is what
        // we're copying *to*. Both get slot renaming via the
        // SP-aware helper so `[ebp-4]` reads as `var_4`, etc.
        let (_, src) =
            super::mov::split_two_operands(&format_intel(&load.iced), "mov ")?;
        let (dst, _) =
            super::mov::split_two_operands(&format_intel(&store.iced), "mov ")?;
        let sp_load = ctx.sp_delta_at.get(&load.iced.ip()).copied();
        let sp_store = ctx.sp_delta_at.get(&store.iced.ip()).copied();
        let dst = ud_arch_x86::rename_operand_in_ctx(&dst, sp_store);
        let src = ud_arch_x86::rename_operand_in_ctx(&src, sp_load);
        let mut bytes =
            Vec::with_capacity(load.original_bytes.len() + store.original_bytes.len());
        bytes.extend_from_slice(&load.original_bytes);
        bytes.extend_from_slice(&store.original_bytes);
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 2,
            // Higher than the plain `mov` pattern (priority 50) so
            // the fold wins over the per-mov rendering. Below the
            // structural lifts (calls / prologues) so they get first
            // crack at the same insn window.
            priority: 60,
            stmts: vec![Stmt::Move { dst, src, bytes }],
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

    /// `mov eax, [ebp+8]; mov [ebp-4], eax` folds to one Move whose
    /// dst/src are the two memory operands (renamed) and whose bytes
    /// cover both instructions.
    #[test]
    fn folds_load_store_pair() {
        // 8b 45 08         mov eax, [ebp+8]
        // 89 45 fc         mov [ebp-4], eax
        let bytes = [0x8b, 0x45, 0x08, 0x89, 0x45, 0xfc];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        let c = MemViaReg.tentative(&ctx(), &insns, 0).expect("match");
        assert_eq!(c.consumed, 2);
        let Some(Stmt::Move { dst, src, bytes: out }) = c.stmts.first() else {
            panic!("expected Stmt::Move");
        };
        assert_eq!(dst, "var_4");
        assert_eq!(src, "arg_8");
        assert_eq!(out, &bytes);
    }

    /// Load + register-to-register move shouldn't fold — the second
    /// mov's destination isn't memory, so hiding the second register
    /// write would lose information.
    #[test]
    fn skips_reg_to_reg_store() {
        // 8b 45 08         mov eax, [ebp+8]
        // 89 c3            mov ebx, eax
        let bytes = [0x8b, 0x45, 0x08, 0x89, 0xc3];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        assert!(MemViaReg.tentative(&ctx(), &insns, 0).is_none());
    }

    /// Two unrelated movs through different registers shouldn't fold.
    #[test]
    fn skips_when_scratch_register_differs() {
        // 8b 45 08         mov eax, [ebp+8]
        // 89 5d fc         mov [ebp-4], ebx  (note: ebx, not eax)
        let bytes = [0x8b, 0x45, 0x08, 0x89, 0x5d, 0xfc];
        let insns = decode(Bitness::Bits32, &bytes, 0).unwrap();
        assert!(MemViaReg.tentative(&ctx(), &insns, 0).is_none());
    }
}

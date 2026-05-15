//! Pattern: adjacent `cmp/test` + `jcc` → one combined `@asm` line.
//!
//! When the CFG-level if-else detection finds an `if (cond)` shape
//! the two instructions get folded into a structural `@if_branch`
//! head with the cond text and the cmp+jcc bytes pinned. But many
//! compilers emit `cmp/test + jcc` pairs whose CFG shape doesn't fit
//! a single-arm or two-arm `if` — compound conditions, gotos into
//! deep merge points, switch-case lowering. Those previously stayed
//! as two separate `@asm` lines plus a `// -> { taken, fallthrough }`
//! comment.
//!
//! This pattern keeps the bytes intact while reducing the visual
//! noise: when the structural lift hasn't claimed them, render the
//! pair as a single combined `@asm("cmp X,Y; jcc T", [bytes])` line.
//! Pure cosmetic — no semantic change — but cuts the per-conditional
//! footprint from ~3 lines (two `@asm`s + a target-comment) to one.

use ud_arch_x86::{format_intel, DecodedInsn, FlowControl, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct CmpJcc;

impl Pattern for CmpJcc {
    fn name(&self) -> &'static str {
        "cmp_jcc"
    }

    fn tentative(
        &self,
        _ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let cmp = insns.get(start)?;
        if !matches!(cmp.iced.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
            return None;
        }
        let jcc = insns.get(start + 1)?;
        if jcc.iced.flow_control() != FlowControl::ConditionalBranch {
            return None;
        }
        if jcc.iced.near_branch_target() == 0 {
            return None;
        }

        let text = format!("{}; {}", format_intel(&cmp.iced), format_intel(&jcc.iced));
        let mut bytes = Vec::with_capacity(cmp.original_bytes.len() + jcc.original_bytes.len());
        bytes.extend_from_slice(&cmp.original_bytes);
        bytes.extend_from_slice(&jcc.original_bytes);

        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 2,
            // Lower than every structural lift (stack_arg_call=200,
            // mov=50, …) so a real `@if_branch` wins when the CFG
            // permits one. This pattern is a fallback for compound
            // conditions / goto-like branches.
            priority: 10,
            stmts: vec![Stmt::Asm { text, bytes }],
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

    /// `cmp eax, 1; je rel8` lifts as one combined `@asm` covering
    /// both instructions' bytes.
    #[test]
    fn lifts_adjacent_cmp_je() {
        // cmp eax,1   83 f8 01
        // je  +0      74 00
        let bytes = [0x83, 0xf8, 0x01, 0x74, 0x00];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let cand = CmpJcc.tentative(&ctx(), &insns, 0).expect("match");
        assert_eq!(cand.consumed, 2);
        let Some(Stmt::Asm {
            text,
            bytes: out_bytes,
        }) = cand.stmts.first()
        else {
            panic!("expected Stmt::Asm");
        };
        assert!(
            text.contains("cmp eax,1") && text.contains("je"),
            "got {text}"
        );
        assert_eq!(out_bytes, &bytes);
    }

    /// `cmp` alone without a jcc following doesn't match.
    #[test]
    fn rejects_cmp_without_jcc() {
        let bytes = [0x83, 0xf8, 0x01]; // cmp eax,1
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        assert!(CmpJcc.tentative(&ctx(), &insns, 0).is_none());
    }
}

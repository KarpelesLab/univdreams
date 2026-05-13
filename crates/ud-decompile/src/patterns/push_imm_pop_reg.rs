//! Pattern: `push IMM; pop REG` → `REG = IMM`.
//!
//! Compilers emit this 3-byte (`6a imm8` + 1-byte `pop reg`) or
//! 6-byte (`68 imm32` + 1-byte `pop reg`) idiom to load a small
//! constant into a register because it's smaller than the
//! equivalent `mov reg, imm32` (5 bytes for 32-bit imm, 7 bytes
//! for sign-extended imm32 in 64-bit mode). MSVC and old GCC use
//! it heavily for `eax = 1`, `eax = -1`, etc.
//!
//! Folding the pair into a single `Stmt::Move` recovers the
//! intent and shrinks two `@asm` lines into one assignment.

use ud_arch_x86::{DecodedInsn, Mnemonic, OpKind};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct PushImmPopReg;

impl Pattern for PushImmPopReg {
    fn name(&self) -> &'static str {
        "push_imm_pop_reg"
    }

    fn tentative(
        &self,
        _ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let push = insns.get(start)?;
        let pop = insns.get(start + 1)?;
        if push.iced.mnemonic() != Mnemonic::Push || pop.iced.mnemonic() != Mnemonic::Pop {
            return None;
        }
        if push.iced.op_count() != 1 || pop.iced.op_count() != 1 {
            return None;
        }
        // `pop` must land in a plain register.
        if pop.iced.op0_kind() != OpKind::Register {
            return None;
        }
        let reg = pop.iced.op0_register();
        // `push` must carry an immediate. The signed-imm kinds cover
        // the `6a XX` (imm8 sign-extended) and `68 XX XX XX XX`
        // (imm32) encodings the compiler actually picks.
        #[allow(clippy::cast_possible_wrap)]
        let imm = match push.iced.op0_kind() {
            OpKind::Immediate8 => i64::from(push.iced.immediate8() as i8),
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                push.iced.immediate8to64()
            }
            OpKind::Immediate16 => i64::from(push.iced.immediate16() as i16),
            OpKind::Immediate32 => i64::from(push.iced.immediate32() as i32),
            OpKind::Immediate32to64 => push.iced.immediate32to64(),
            OpKind::Immediate64 => push.iced.immediate64() as i64,
            _ => return None,
        };

        let reg_name = format!("{reg:?}").to_lowercase();
        let src = if imm < 0 {
            format!("-0x{:x}", imm.unsigned_abs())
        } else {
            format!("0x{imm:x}")
        };
        let mut bytes = Vec::with_capacity(push.original_bytes.len() + pop.original_bytes.len());
        bytes.extend_from_slice(&push.original_bytes);
        bytes.extend_from_slice(&pop.original_bytes);

        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 2,
            // Above MovExtend (50), Mov (50), Arith (50); above
            // StackArgCall's end-of-block synthetic `pushed_args`
            // (which only fires with >= 2 pushes) and below
            // StackArgCall's real call lift (200). 150 is the same
            // tier as TailJmp — a structural recognition that
            // re-shapes two instructions into one statement.
            priority: 150,
            stmts: vec![Stmt::Move {
                dst: reg_name,
                src,
                bytes,
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

    /// `push 1; pop eax` → `eax = 0x1`
    #[test]
    fn lifts_push_imm8_pop_eax() {
        let bytes = [0x6a, 0x01, 0x58];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let cand = PushImmPopReg.tentative(&ctx(), &insns, 0).expect("match");
        assert_eq!(cand.consumed, 2);
        let Stmt::Move { dst, src, bytes } = &cand.stmts[0] else {
            panic!("expected Move");
        };
        assert_eq!(dst, "eax");
        assert_eq!(src, "0x1");
        assert_eq!(bytes, &[0x6a, 0x01, 0x58]);
    }

    /// `push -1; pop ecx` → `ecx = -0x1`
    #[test]
    fn lifts_push_imm8_negative() {
        let bytes = [0x6a, 0xff, 0x59];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let cand = PushImmPopReg.tentative(&ctx(), &insns, 0).expect("match");
        let Stmt::Move { dst, src, .. } = &cand.stmts[0] else {
            panic!("expected Move");
        };
        assert_eq!(dst, "ecx");
        assert_eq!(src, "-0x1");
    }

    /// `push 0x12345678; pop edx` → `edx = 0x12345678`
    #[test]
    fn lifts_push_imm32_pop_edx() {
        let bytes = [0x68, 0x78, 0x56, 0x34, 0x12, 0x5a];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let cand = PushImmPopReg.tentative(&ctx(), &insns, 0).expect("match");
        let Stmt::Move { dst, src, .. } = &cand.stmts[0] else {
            panic!("expected Move");
        };
        assert_eq!(dst, "edx");
        assert_eq!(src, "0x12345678");
    }

    /// `push eax; pop ebx` doesn't match — it's a register copy,
    /// not a constant load. The existing mov-via-stack patterns
    /// can deal with that separately if needed.
    #[test]
    fn skips_push_reg_pop_reg() {
        let bytes = [0x50, 0x5b]; // push eax; pop ebx
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        assert!(PushImmPopReg.tentative(&ctx(), &insns, 0).is_none());
    }

    /// `push 1; xor eax,eax` — not a pop after; no match.
    #[test]
    fn skips_when_pop_missing() {
        let bytes = [0x6a, 0x01, 0x31, 0xc0];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        assert!(PushImmPopReg.tentative(&ctx(), &insns, 0).is_none());
    }

    /// 64-bit mode: `push 1; pop rax` (single-byte 58).
    #[test]
    fn lifts_in_64bit_mode() {
        let bytes = [0x6a, 0x01, 0x58];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let cand = PushImmPopReg.tentative(&ctx(), &insns, 0).expect("match");
        let Stmt::Move { dst, src, .. } = &cand.stmts[0] else {
            panic!("expected Move");
        };
        assert_eq!(dst, "rax");
        assert_eq!(src, "0x1");
    }
}

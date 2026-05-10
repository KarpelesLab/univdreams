//! MOS 6502 instruction decoder.
//!
//! Scope: the 151 official opcodes of the original NMOS 6502. The
//! decoder captures every input byte verbatim so concatenating the
//! `original_bytes` slices from a decode pass yields the input back
//! unchanged — the round-trip contract the rest of the crate stack
//! depends on.
//!
//! Illegal / undocumented opcodes (`$02`, `$03`, etc.) decode to
//! `Mnemonic::Illegal` with one byte of `original_bytes`. They
//! round-trip but render as `@asm("?? $XX", [0xXX])` in the AST.

#![allow(clippy::cast_possible_truncation)]

use ud_core::VAddr;
use ud_ir::ArchInsn;

mod table;

pub use table::{AddressingMode, Mnemonic, OpInfo};

/// One decoded 6502 instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    /// Virtual address where this instruction was decoded.
    pub addr: VAddr,
    /// The opcode mnemonic.
    pub mnemonic: Mnemonic,
    /// The addressing mode the opcode used.
    pub mode: AddressingMode,
    /// Decoded operand value. For `Immediate`/`ZeroPage`/`Relative`
    /// this is the single operand byte; for `Absolute*` it's the
    /// little-endian 16-bit operand. For `Implied`/`Accumulator`
    /// this is 0.
    pub operand: u16,
    /// The bytes the instruction occupied (1, 2, or 3). Includes
    /// the opcode byte. Concatenating these across a stream is
    /// byte-identical to the input.
    pub original_bytes: Vec<u8>,
}

impl ArchInsn for DecodedInsn {
    fn addr(&self) -> VAddr {
        self.addr
    }
    fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }
}

/// Errors returned by the 6502 decoder.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("truncated instruction at offset {offset}: opcode {opcode:#04x} needs {needs} operand byte(s), only {have} available")]
    Truncated {
        offset: usize,
        opcode: u8,
        needs: usize,
        have: usize,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Decode a single instruction starting at `bytes[0]`. Returns the
/// decoded instruction and the number of bytes it consumed.
pub fn decode_one(bytes: &[u8], addr: u64) -> Result<DecodedInsn> {
    if bytes.is_empty() {
        return Err(Error::Truncated {
            offset: 0,
            opcode: 0,
            needs: 1,
            have: 0,
        });
    }
    let opcode = bytes[0];
    let info = table::OPCODE_TABLE[opcode as usize];
    let needs = info.mode.operand_len();
    if bytes.len() < 1 + needs {
        return Err(Error::Truncated {
            offset: 0,
            opcode,
            needs,
            have: bytes.len() - 1,
        });
    }
    let operand = match needs {
        0 => 0,
        1 => u16::from(bytes[1]),
        2 => u16::from_le_bytes([bytes[1], bytes[2]]),
        _ => unreachable!("6502 operands are 0-2 bytes"),
    };
    let original_bytes = bytes[..=needs].to_vec();
    Ok(DecodedInsn {
        addr: VAddr(addr),
        mnemonic: info.mnemonic,
        mode: info.mode,
        operand,
        original_bytes,
    })
}

/// Decode an instruction stream linearly. Stops on the first
/// `Error::Truncated`.
pub fn decode_range(bytes: &[u8], start: u64) -> Result<Vec<DecodedInsn>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < bytes.len() {
        let insn = decode_one(&bytes[off..], start.wrapping_add(off as u64))?;
        off += insn.original_bytes.len();
        out.push(insn);
    }
    Ok(out)
}

/// Branch / call / return classification used by CFG construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    /// Conditional branch (`BNE`, `BEQ`, ...). The target is computed
    /// from the relative operand and the address of the *next*
    /// instruction.
    Branch { taken: u64, fallthrough: u64 },
    /// Unconditional jump (`JMP $nnnn`).
    JumpDirect { target: u64 },
    /// Indirect jump (`JMP ($nnnn)`).
    JumpIndirect,
    /// Direct call (`JSR $nnnn`).
    Call { target: u64, fallthrough: u64 },
    /// Return from subroutine / interrupt (`RTS`, `RTI`).
    Return,
    /// `BRK` — software interrupt. Acts like a return on the IRQ path.
    Break,
    /// Anything else.
    Other,
}

/// Classify an instruction for CFG purposes.
#[must_use]
pub fn classify(insn: &DecodedInsn) -> InsnKind {
    use Mnemonic as M;
    let next = insn.addr.0.wrapping_add(insn.original_bytes.len() as u64);
    match insn.mnemonic {
        M::BCC | M::BCS | M::BEQ | M::BMI | M::BNE | M::BPL | M::BVC | M::BVS => {
            let taken = next.wrapping_add(relative_offset(insn));
            InsnKind::Branch {
                taken,
                fallthrough: next,
            }
        }
        M::JMP if insn.mode == AddressingMode::Absolute => InsnKind::JumpDirect {
            target: u64::from(insn.operand),
        },
        M::JMP if insn.mode == AddressingMode::Indirect => InsnKind::JumpIndirect,
        M::JSR => InsnKind::Call {
            target: u64::from(insn.operand),
            fallthrough: next,
        },
        M::RTS | M::RTI => InsnKind::Return,
        M::BRK => InsnKind::Break,
        _ => InsnKind::Other,
    }
}

/// Sign-extended relative-branch displacement as a `u64` (wrapping
/// negative values into the high bits — exactly what
/// `wrapping_add` wants).
#[allow(clippy::cast_sign_loss)]
fn relative_offset(insn: &DecodedInsn) -> u64 {
    let off = insn.operand as i8;
    i64::from(off) as u64
}

/// Render `insn` as an Apple-II-monitor-style assembly line. Used by
/// the decompile path when emitting `@asm("text", [bytes])`.
#[must_use]
pub fn format_insn(insn: &DecodedInsn) -> String {
    let m = mnemonic_name(insn.mnemonic);
    let next = insn.addr.0.wrapping_add(insn.original_bytes.len() as u64);
    match insn.mode {
        AddressingMode::Implied => m.to_string(),
        AddressingMode::Accumulator => format!("{m} A"),
        AddressingMode::Immediate => format!("{m} #${:02X}", insn.operand),
        AddressingMode::ZeroPage => format!("{m} ${:02X}", insn.operand),
        AddressingMode::ZeroPageX => format!("{m} ${:02X},X", insn.operand),
        AddressingMode::ZeroPageY => format!("{m} ${:02X},Y", insn.operand),
        AddressingMode::Absolute => format!("{m} ${:04X}", insn.operand),
        AddressingMode::AbsoluteX => format!("{m} ${:04X},X", insn.operand),
        AddressingMode::AbsoluteY => format!("{m} ${:04X},Y", insn.operand),
        AddressingMode::Indirect => format!("{m} (${:04X})", insn.operand),
        AddressingMode::IndirectX => format!("{m} (${:02X},X)", insn.operand),
        AddressingMode::IndirectY => format!("{m} (${:02X}),Y", insn.operand),
        AddressingMode::Relative => {
            let tgt = next.wrapping_add(relative_offset(insn)) & 0xFFFF;
            format!("{m} ${tgt:04X}")
        }
        AddressingMode::IllegalOperand => format!("?? ${:02X}", insn.original_bytes[0]),
    }
}

#[allow(clippy::enum_glob_use, clippy::too_many_lines)]
fn mnemonic_name(m: Mnemonic) -> &'static str {
    use Mnemonic::*;
    match m {
        ADC => "ADC",
        AND => "AND",
        ASL => "ASL",
        BCC => "BCC",
        BCS => "BCS",
        BEQ => "BEQ",
        BIT => "BIT",
        BMI => "BMI",
        BNE => "BNE",
        BPL => "BPL",
        BRK => "BRK",
        BVC => "BVC",
        BVS => "BVS",
        CLC => "CLC",
        CLD => "CLD",
        CLI => "CLI",
        CLV => "CLV",
        CMP => "CMP",
        CPX => "CPX",
        CPY => "CPY",
        DEC => "DEC",
        DEX => "DEX",
        DEY => "DEY",
        EOR => "EOR",
        INC => "INC",
        INX => "INX",
        INY => "INY",
        JMP => "JMP",
        JSR => "JSR",
        LDA => "LDA",
        LDX => "LDX",
        LDY => "LDY",
        LSR => "LSR",
        NOP => "NOP",
        ORA => "ORA",
        PHA => "PHA",
        PHP => "PHP",
        PLA => "PLA",
        PLP => "PLP",
        ROL => "ROL",
        ROR => "ROR",
        RTI => "RTI",
        RTS => "RTS",
        SBC => "SBC",
        SEC => "SEC",
        SED => "SED",
        SEI => "SEI",
        STA => "STA",
        STX => "STX",
        STY => "STY",
        TAX => "TAX",
        TAY => "TAY",
        TSX => "TSX",
        TXA => "TXA",
        TXS => "TXS",
        TYA => "TYA",
        Illegal => "??",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_byte_identical_for_each_opcode() {
        // Build a synthetic stream that uses every opcode exactly once
        // with zero-filled operands. Decode it, concatenate
        // original_bytes, compare to the input.
        let mut input = Vec::new();
        for op in 0u8..=255 {
            let info = table::OPCODE_TABLE[op as usize];
            input.push(op);
            input.extend(std::iter::repeat_n(0u8, info.mode.operand_len()));
        }
        let insns = decode_range(&input, 0).expect("decode");
        let mut out = Vec::new();
        for i in &insns {
            out.extend_from_slice(&i.original_bytes);
        }
        assert_eq!(out, input, "decode then concat is not byte-identical");
    }

    #[test]
    fn classifies_jsr_rts_and_branches() {
        // JSR $1234 — opcode 0x20 lo hi
        let i = decode_one(&[0x20, 0x34, 0x12], 0x1000).unwrap();
        assert_eq!(i.mnemonic, Mnemonic::JSR);
        assert!(matches!(
            classify(&i),
            InsnKind::Call {
                target: 0x1234,
                fallthrough: 0x1003
            }
        ));

        // RTS — opcode 0x60
        let i = decode_one(&[0x60], 0x1000).unwrap();
        assert_eq!(classify(&i), InsnKind::Return);

        // BNE +4 — opcode 0xD0 0x04
        let i = decode_one(&[0xd0, 0x04], 0xff00).unwrap();
        assert!(matches!(
            classify(&i),
            InsnKind::Branch {
                taken: 0xff06,
                fallthrough: 0xff02
            }
        ));

        // BNE -2 (loop tightly) — opcode 0xD0 0xFE
        let i = decode_one(&[0xd0, 0xfe], 0xff00).unwrap();
        assert!(matches!(
            classify(&i),
            InsnKind::Branch {
                taken: 0xff00,
                fallthrough: 0xff02
            }
        ));
    }

    #[test]
    fn formats_apple1_style() {
        let i = decode_one(&[0xa9, 0x0d], 0xff00).unwrap();
        assert_eq!(format_insn(&i), "LDA #$0D");

        let i = decode_one(&[0x8d, 0x12, 0xd0], 0xff00).unwrap();
        assert_eq!(format_insn(&i), "STA $D012");

        let i = decode_one(&[0x6c, 0xfe, 0xff], 0xff00).unwrap();
        assert_eq!(format_insn(&i), "JMP ($FFFE)");

        let i = decode_one(&[0xd0, 0xfe], 0xff00).unwrap();
        assert_eq!(format_insn(&i), "BNE $FF00");
    }
}

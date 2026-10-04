//! The 6502 opcode table.
//!
//! Indexed by the opcode byte, each entry carries the mnemonic and
//! addressing mode. Mnemonics and modes follow the original NMOS
//! 6502; the 105 undocumented opcodes map to `Mnemonic::Illegal` so
//! a stream of arbitrary bytes always decodes.

/// One row in the opcode table.
#[derive(Debug, Clone, Copy)]
pub struct OpInfo {
    pub mnemonic: Mnemonic,
    pub mode: AddressingMode,
}

impl OpInfo {
    const fn new(mnemonic: Mnemonic, mode: AddressingMode) -> Self {
        Self { mnemonic, mode }
    }
}

/// 6502 mnemonics. `Illegal` covers every undocumented opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Mnemonic {
    ADC,
    AND,
    ASL,
    BCC,
    BCS,
    BEQ,
    BIT,
    BMI,
    BNE,
    BPL,
    BRK,
    BVC,
    BVS,
    CLC,
    CLD,
    CLI,
    CLV,
    CMP,
    CPX,
    CPY,
    DEC,
    DEX,
    DEY,
    EOR,
    INC,
    INX,
    INY,
    JMP,
    JSR,
    LDA,
    LDX,
    LDY,
    LSR,
    NOP,
    ORA,
    PHA,
    PHP,
    PLA,
    PLP,
    ROL,
    ROR,
    RTI,
    RTS,
    SBC,
    SEC,
    SED,
    SEI,
    STA,
    STX,
    STY,
    TAX,
    TAY,
    TSX,
    TXA,
    TXS,
    TYA,
    Illegal,
}

/// 6502 addressing modes. `IllegalOperand` is the mode assigned to
/// every undocumented opcode — it carries no operand bytes, matching
/// how this decoder treats an `Illegal` instruction as a single byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressingMode {
    Implied,
    Accumulator,
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    Indirect,
    IndirectX,
    IndirectY,
    Relative,
    IllegalOperand,
}

impl AddressingMode {
    /// Number of operand bytes after the opcode byte.
    #[must_use]
    pub const fn operand_len(self) -> usize {
        match self {
            AddressingMode::Implied
            | AddressingMode::Accumulator
            | AddressingMode::IllegalOperand => 0,
            AddressingMode::Immediate
            | AddressingMode::ZeroPage
            | AddressingMode::ZeroPageX
            | AddressingMode::ZeroPageY
            | AddressingMode::IndirectX
            | AddressingMode::IndirectY
            | AddressingMode::Relative => 1,
            AddressingMode::Absolute
            | AddressingMode::AbsoluteX
            | AddressingMode::AbsoluteY
            | AddressingMode::Indirect => 2,
        }
    }
}

use AddressingMode as A;
use Mnemonic as M;

const ILL: OpInfo = OpInfo::new(M::Illegal, A::IllegalOperand);

/// 256-entry opcode dispatch table. The unofficial opcodes (e.g. `$02`,
/// `$03`, `$04`) map to `ILL`.
///
/// Sourced from the standard 6502 opcode matrix (Wozniak, Eyes, Mensch).
pub const OPCODE_TABLE: [OpInfo; 256] = {
    let mut t = [ILL; 256];

    // ADC
    t[0x69] = OpInfo::new(M::ADC, A::Immediate);
    t[0x65] = OpInfo::new(M::ADC, A::ZeroPage);
    t[0x75] = OpInfo::new(M::ADC, A::ZeroPageX);
    t[0x6D] = OpInfo::new(M::ADC, A::Absolute);
    t[0x7D] = OpInfo::new(M::ADC, A::AbsoluteX);
    t[0x79] = OpInfo::new(M::ADC, A::AbsoluteY);
    t[0x61] = OpInfo::new(M::ADC, A::IndirectX);
    t[0x71] = OpInfo::new(M::ADC, A::IndirectY);

    // AND
    t[0x29] = OpInfo::new(M::AND, A::Immediate);
    t[0x25] = OpInfo::new(M::AND, A::ZeroPage);
    t[0x35] = OpInfo::new(M::AND, A::ZeroPageX);
    t[0x2D] = OpInfo::new(M::AND, A::Absolute);
    t[0x3D] = OpInfo::new(M::AND, A::AbsoluteX);
    t[0x39] = OpInfo::new(M::AND, A::AbsoluteY);
    t[0x21] = OpInfo::new(M::AND, A::IndirectX);
    t[0x31] = OpInfo::new(M::AND, A::IndirectY);

    // ASL
    t[0x0A] = OpInfo::new(M::ASL, A::Accumulator);
    t[0x06] = OpInfo::new(M::ASL, A::ZeroPage);
    t[0x16] = OpInfo::new(M::ASL, A::ZeroPageX);
    t[0x0E] = OpInfo::new(M::ASL, A::Absolute);
    t[0x1E] = OpInfo::new(M::ASL, A::AbsoluteX);

    // Branches (all relative, 2-byte)
    t[0x90] = OpInfo::new(M::BCC, A::Relative);
    t[0xB0] = OpInfo::new(M::BCS, A::Relative);
    t[0xF0] = OpInfo::new(M::BEQ, A::Relative);
    t[0x30] = OpInfo::new(M::BMI, A::Relative);
    t[0xD0] = OpInfo::new(M::BNE, A::Relative);
    t[0x10] = OpInfo::new(M::BPL, A::Relative);
    t[0x50] = OpInfo::new(M::BVC, A::Relative);
    t[0x70] = OpInfo::new(M::BVS, A::Relative);

    // BIT
    t[0x24] = OpInfo::new(M::BIT, A::ZeroPage);
    t[0x2C] = OpInfo::new(M::BIT, A::Absolute);

    // BRK
    t[0x00] = OpInfo::new(M::BRK, A::Implied);

    // Flag ops
    t[0x18] = OpInfo::new(M::CLC, A::Implied);
    t[0xD8] = OpInfo::new(M::CLD, A::Implied);
    t[0x58] = OpInfo::new(M::CLI, A::Implied);
    t[0xB8] = OpInfo::new(M::CLV, A::Implied);
    t[0x38] = OpInfo::new(M::SEC, A::Implied);
    t[0xF8] = OpInfo::new(M::SED, A::Implied);
    t[0x78] = OpInfo::new(M::SEI, A::Implied);

    // CMP
    t[0xC9] = OpInfo::new(M::CMP, A::Immediate);
    t[0xC5] = OpInfo::new(M::CMP, A::ZeroPage);
    t[0xD5] = OpInfo::new(M::CMP, A::ZeroPageX);
    t[0xCD] = OpInfo::new(M::CMP, A::Absolute);
    t[0xDD] = OpInfo::new(M::CMP, A::AbsoluteX);
    t[0xD9] = OpInfo::new(M::CMP, A::AbsoluteY);
    t[0xC1] = OpInfo::new(M::CMP, A::IndirectX);
    t[0xD1] = OpInfo::new(M::CMP, A::IndirectY);

    // CPX
    t[0xE0] = OpInfo::new(M::CPX, A::Immediate);
    t[0xE4] = OpInfo::new(M::CPX, A::ZeroPage);
    t[0xEC] = OpInfo::new(M::CPX, A::Absolute);

    // CPY
    t[0xC0] = OpInfo::new(M::CPY, A::Immediate);
    t[0xC4] = OpInfo::new(M::CPY, A::ZeroPage);
    t[0xCC] = OpInfo::new(M::CPY, A::Absolute);

    // DEC
    t[0xC6] = OpInfo::new(M::DEC, A::ZeroPage);
    t[0xD6] = OpInfo::new(M::DEC, A::ZeroPageX);
    t[0xCE] = OpInfo::new(M::DEC, A::Absolute);
    t[0xDE] = OpInfo::new(M::DEC, A::AbsoluteX);

    t[0xCA] = OpInfo::new(M::DEX, A::Implied);
    t[0x88] = OpInfo::new(M::DEY, A::Implied);

    // EOR
    t[0x49] = OpInfo::new(M::EOR, A::Immediate);
    t[0x45] = OpInfo::new(M::EOR, A::ZeroPage);
    t[0x55] = OpInfo::new(M::EOR, A::ZeroPageX);
    t[0x4D] = OpInfo::new(M::EOR, A::Absolute);
    t[0x5D] = OpInfo::new(M::EOR, A::AbsoluteX);
    t[0x59] = OpInfo::new(M::EOR, A::AbsoluteY);
    t[0x41] = OpInfo::new(M::EOR, A::IndirectX);
    t[0x51] = OpInfo::new(M::EOR, A::IndirectY);

    // INC
    t[0xE6] = OpInfo::new(M::INC, A::ZeroPage);
    t[0xF6] = OpInfo::new(M::INC, A::ZeroPageX);
    t[0xEE] = OpInfo::new(M::INC, A::Absolute);
    t[0xFE] = OpInfo::new(M::INC, A::AbsoluteX);

    t[0xE8] = OpInfo::new(M::INX, A::Implied);
    t[0xC8] = OpInfo::new(M::INY, A::Implied);

    // JMP / JSR
    t[0x4C] = OpInfo::new(M::JMP, A::Absolute);
    t[0x6C] = OpInfo::new(M::JMP, A::Indirect);
    t[0x20] = OpInfo::new(M::JSR, A::Absolute);

    // LDA
    t[0xA9] = OpInfo::new(M::LDA, A::Immediate);
    t[0xA5] = OpInfo::new(M::LDA, A::ZeroPage);
    t[0xB5] = OpInfo::new(M::LDA, A::ZeroPageX);
    t[0xAD] = OpInfo::new(M::LDA, A::Absolute);
    t[0xBD] = OpInfo::new(M::LDA, A::AbsoluteX);
    t[0xB9] = OpInfo::new(M::LDA, A::AbsoluteY);
    t[0xA1] = OpInfo::new(M::LDA, A::IndirectX);
    t[0xB1] = OpInfo::new(M::LDA, A::IndirectY);

    // LDX
    t[0xA2] = OpInfo::new(M::LDX, A::Immediate);
    t[0xA6] = OpInfo::new(M::LDX, A::ZeroPage);
    t[0xB6] = OpInfo::new(M::LDX, A::ZeroPageY);
    t[0xAE] = OpInfo::new(M::LDX, A::Absolute);
    t[0xBE] = OpInfo::new(M::LDX, A::AbsoluteY);

    // LDY
    t[0xA0] = OpInfo::new(M::LDY, A::Immediate);
    t[0xA4] = OpInfo::new(M::LDY, A::ZeroPage);
    t[0xB4] = OpInfo::new(M::LDY, A::ZeroPageX);
    t[0xAC] = OpInfo::new(M::LDY, A::Absolute);
    t[0xBC] = OpInfo::new(M::LDY, A::AbsoluteX);

    // LSR
    t[0x4A] = OpInfo::new(M::LSR, A::Accumulator);
    t[0x46] = OpInfo::new(M::LSR, A::ZeroPage);
    t[0x56] = OpInfo::new(M::LSR, A::ZeroPageX);
    t[0x4E] = OpInfo::new(M::LSR, A::Absolute);
    t[0x5E] = OpInfo::new(M::LSR, A::AbsoluteX);

    // NOP
    t[0xEA] = OpInfo::new(M::NOP, A::Implied);

    // ORA
    t[0x09] = OpInfo::new(M::ORA, A::Immediate);
    t[0x05] = OpInfo::new(M::ORA, A::ZeroPage);
    t[0x15] = OpInfo::new(M::ORA, A::ZeroPageX);
    t[0x0D] = OpInfo::new(M::ORA, A::Absolute);
    t[0x1D] = OpInfo::new(M::ORA, A::AbsoluteX);
    t[0x19] = OpInfo::new(M::ORA, A::AbsoluteY);
    t[0x01] = OpInfo::new(M::ORA, A::IndirectX);
    t[0x11] = OpInfo::new(M::ORA, A::IndirectY);

    // Stack
    t[0x48] = OpInfo::new(M::PHA, A::Implied);
    t[0x08] = OpInfo::new(M::PHP, A::Implied);
    t[0x68] = OpInfo::new(M::PLA, A::Implied);
    t[0x28] = OpInfo::new(M::PLP, A::Implied);

    // ROL
    t[0x2A] = OpInfo::new(M::ROL, A::Accumulator);
    t[0x26] = OpInfo::new(M::ROL, A::ZeroPage);
    t[0x36] = OpInfo::new(M::ROL, A::ZeroPageX);
    t[0x2E] = OpInfo::new(M::ROL, A::Absolute);
    t[0x3E] = OpInfo::new(M::ROL, A::AbsoluteX);

    // ROR
    t[0x6A] = OpInfo::new(M::ROR, A::Accumulator);
    t[0x66] = OpInfo::new(M::ROR, A::ZeroPage);
    t[0x76] = OpInfo::new(M::ROR, A::ZeroPageX);
    t[0x6E] = OpInfo::new(M::ROR, A::Absolute);
    t[0x7E] = OpInfo::new(M::ROR, A::AbsoluteX);

    // Returns
    t[0x40] = OpInfo::new(M::RTI, A::Implied);
    t[0x60] = OpInfo::new(M::RTS, A::Implied);

    // SBC
    t[0xE9] = OpInfo::new(M::SBC, A::Immediate);
    t[0xE5] = OpInfo::new(M::SBC, A::ZeroPage);
    t[0xF5] = OpInfo::new(M::SBC, A::ZeroPageX);
    t[0xED] = OpInfo::new(M::SBC, A::Absolute);
    t[0xFD] = OpInfo::new(M::SBC, A::AbsoluteX);
    t[0xF9] = OpInfo::new(M::SBC, A::AbsoluteY);
    t[0xE1] = OpInfo::new(M::SBC, A::IndirectX);
    t[0xF1] = OpInfo::new(M::SBC, A::IndirectY);

    // STA
    t[0x85] = OpInfo::new(M::STA, A::ZeroPage);
    t[0x95] = OpInfo::new(M::STA, A::ZeroPageX);
    t[0x8D] = OpInfo::new(M::STA, A::Absolute);
    t[0x9D] = OpInfo::new(M::STA, A::AbsoluteX);
    t[0x99] = OpInfo::new(M::STA, A::AbsoluteY);
    t[0x81] = OpInfo::new(M::STA, A::IndirectX);
    t[0x91] = OpInfo::new(M::STA, A::IndirectY);

    // STX
    t[0x86] = OpInfo::new(M::STX, A::ZeroPage);
    t[0x96] = OpInfo::new(M::STX, A::ZeroPageY);
    t[0x8E] = OpInfo::new(M::STX, A::Absolute);

    // STY
    t[0x84] = OpInfo::new(M::STY, A::ZeroPage);
    t[0x94] = OpInfo::new(M::STY, A::ZeroPageX);
    t[0x8C] = OpInfo::new(M::STY, A::Absolute);

    // Transfers
    t[0xAA] = OpInfo::new(M::TAX, A::Implied);
    t[0xA8] = OpInfo::new(M::TAY, A::Implied);
    t[0xBA] = OpInfo::new(M::TSX, A::Implied);
    t[0x8A] = OpInfo::new(M::TXA, A::Implied);
    t[0x9A] = OpInfo::new(M::TXS, A::Implied);
    t[0x98] = OpInfo::new(M::TYA, A::Implied);

    t
};

#[cfg(test)]
mod tests {
    use super::*;

    /// 151 official opcodes — the standard 6502 count. The rest are
    /// `Illegal`. A miscount here would mean one of the entries above
    /// is wrong (a duplicate, a hole, or a typo).
    #[test]
    fn exactly_151_official_opcodes() {
        let n = OPCODE_TABLE
            .iter()
            .filter(|info| info.mnemonic != Mnemonic::Illegal)
            .count();
        assert_eq!(n, 151, "expected 151 official 6502 opcodes, found {n}");
    }
}

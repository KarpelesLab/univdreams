//! Ethereum Virtual Machine bytecode: decoder, text assembler and
//! [`ArchCodec`](crate::arch::codec::ArchCodec) backend.
//!
//! EVM code is a flat byte string executed from offset 0. Every byte
//! is an opcode except the 1–32 immediate bytes trailing a `PUSHn`,
//! so a linear decode from offset 0 is also the EVM's own view of
//! which bytes are instructions (and which `JUMPDEST`s are valid).
//! Concatenating `original_bytes` across [`decode_range`] reproduces
//! the input exactly, including a `PUSHn` truncated by the end of the
//! code (the EVM reads the missing bytes as zero; we keep only what's
//! there).
//!
//! Text form, one instruction per line:
//!
//! * `ADD`, `JUMPDEST`, `PUSH0` — bare mnemonic.
//! * `PUSH2 0x01a3` — the immediate as hex, zero-padded to the
//!   push width so the width survives an edit of the value.
//! * `.byte 0x0c` — an unassigned opcode byte.
//!
//! Anything after `;` is a comment and ignored by [`assemble_one`].

#![allow(clippy::cast_possible_truncation)]

use std::fmt::Write as _;

use crate::common::VAddr;
use crate::ir::ArchInsn;

mod codec;
#[cfg(test)]
pub(crate) mod interp;
mod keccak;
mod table;

pub use codec::{EvmCodec, register};
pub use keccak::{keccak256, selector};
pub use table::{OPCODE_TABLE, OpInfo, opcode_by_name};

/// `JUMPDEST` opcode byte.
pub const JUMPDEST: u8 = 0x5b;
/// `PUSH1` opcode byte; `PUSHn` is `PUSH1 + n - 1`.
pub const PUSH1: u8 = 0x60;
/// `PUSH32` opcode byte.
pub const PUSH32: u8 = 0x7f;

/// One decoded EVM instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    /// Code offset of the opcode byte.
    pub addr: VAddr,
    /// The opcode byte.
    pub opcode: u8,
    /// The bytes the instruction occupies: opcode plus whatever
    /// immediate bytes were present.
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

impl DecodedInsn {
    /// Static opcode info.
    #[must_use]
    pub fn info(&self) -> &'static OpInfo {
        &OPCODE_TABLE[self.opcode as usize]
    }

    /// The `PUSHn` immediate bytes (empty for every other opcode).
    #[must_use]
    pub fn immediate(&self) -> &[u8] {
        &self.original_bytes[1..]
    }

    /// Whether this is a `PUSHn` whose immediate was cut short by the
    /// end of the code.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.original_bytes.len() < 1 + self.info().imm_len as usize
    }

    /// The pushed value for `PUSH0`..`PUSH32` when it fits in a
    /// `u64` (enough for any code offset or selector). `None` for
    /// non-push opcodes, truncated pushes and wider constants.
    #[must_use]
    pub fn push_value(&self) -> Option<u64> {
        if !(0x5f..=PUSH32).contains(&self.opcode) || self.is_truncated() {
            return None;
        }
        let imm = self.immediate();
        let significant = imm.iter().skip_while(|&&b| b == 0).count();
        if significant > 8 {
            return None;
        }
        Some(imm.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Offset of the following instruction.
    #[must_use]
    pub fn next_addr(&self) -> u64 {
        self.addr.0 + self.original_bytes.len() as u64
    }
}

/// Decode one instruction at `bytes[0]`, located at code offset
/// `addr`. Never fails on non-empty input: unassigned bytes and
/// truncated pushes still decode (see the module docs). Returns
/// `None` only for empty input.
#[must_use]
pub fn decode_one(bytes: &[u8], addr: u64) -> Option<DecodedInsn> {
    let &opcode = bytes.first()?;
    let len = (1 + OPCODE_TABLE[opcode as usize].imm_len as usize).min(bytes.len());
    Some(DecodedInsn {
        addr: VAddr(addr),
        opcode,
        original_bytes: bytes[..len].to_vec(),
    })
}

/// Decode `bytes` linearly, the first byte sitting at code offset
/// `start`.
#[must_use]
pub fn decode_range(bytes: &[u8], start: u64) -> Vec<DecodedInsn> {
    let mut out = Vec::new();
    let mut off = 0;
    while let Some(insn) = decode_one(&bytes[off..], start + off as u64) {
        off += insn.original_bytes.len();
        out.push(insn);
    }
    out
}

/// Canonical text for `insn` (see the module docs for the grammar).
#[must_use]
pub fn format_insn(insn: &DecodedInsn) -> String {
    let info = insn.info();
    if !info.is_defined() {
        return format!(".byte 0x{:02x}", insn.opcode);
    }
    if info.imm_len == 0 {
        return info.name.to_string();
    }
    let mut s = format!("{} 0x", info.name);
    for b in insn.immediate() {
        let _ = write!(s, "{b:02x}");
    }
    if insn.is_truncated() {
        let _ = write!(
            s,
            " ; truncated: {} of {} immediate bytes",
            insn.immediate().len(),
            info.imm_len
        );
    }
    s
}

/// Control-flow classification used for block / label discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InsnKind {
    /// `JUMP` — target is the top of the stack.
    Jump,
    /// `JUMPI` — conditional; falls through otherwise.
    JumpI,
    /// `JUMPDEST` — the only legal jump target.
    JumpDest,
    /// Halts the current call frame: `STOP`, `RETURN`, `REVERT`,
    /// `INVALID`, `SELFDESTRUCT`, or an unassigned opcode.
    Halt,
    /// Everything else.
    Other,
}

/// Classify `insn` for CFG purposes.
#[must_use]
pub fn classify(insn: &DecodedInsn) -> InsnKind {
    match insn.opcode {
        0x56 => InsnKind::Jump,
        0x57 => InsnKind::JumpI,
        JUMPDEST => InsnKind::JumpDest,
        0x00 | 0xf3 | 0xfd | 0xfe | 0xff => InsnKind::Halt,
        op if !OPCODE_TABLE[op as usize].is_defined() => InsnKind::Halt,
        _ => InsnKind::Other,
    }
}

/// Errors from [`assemble_one`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssembleError {
    #[error("empty instruction")]
    Empty,
    #[error("unknown mnemonic `{0}`")]
    UnknownMnemonic(String),
    #[error("`{mnemonic}` takes no operand")]
    UnexpectedOperand { mnemonic: String },
    #[error("`{mnemonic}` needs an immediate operand")]
    MissingOperand { mnemonic: String },
    #[error("bad immediate `{0}` (expected 0x-prefixed hex or decimal)")]
    BadImmediate(String),
    #[error("immediate `{text}` doesn't fit in {width} byte(s)")]
    ImmediateTooWide { text: String, width: usize },
}

/// Assemble one instruction from its text form. Inverse of
/// [`format_insn`] for every non-truncated instruction.
///
/// A hex immediate is left-padded to the push width, so `PUSH2 0x80`
/// and `PUSH2 0x0080` both produce `61 00 80`. Decimal immediates are
/// accepted for hand-written code but must fit in a `u128`.
pub fn assemble_one(text: &str) -> Result<Vec<u8>, AssembleError> {
    let code = text.split(';').next().unwrap_or("").trim();
    let mut parts = code.split_whitespace();
    let mnemonic = parts.next().ok_or(AssembleError::Empty)?;
    let operand = parts.next();
    if let Some(extra) = parts.next() {
        return Err(AssembleError::BadImmediate(extra.to_string()));
    }

    if mnemonic.eq_ignore_ascii_case(".byte") {
        let op = operand.ok_or_else(|| AssembleError::MissingOperand {
            mnemonic: mnemonic.to_string(),
        })?;
        let bytes = parse_immediate(op, 1)?;
        return Ok(bytes);
    }

    let opcode = opcode_by_name(mnemonic)
        .ok_or_else(|| AssembleError::UnknownMnemonic(mnemonic.to_string()))?;
    let width = OPCODE_TABLE[opcode as usize].imm_len as usize;
    match (width, operand) {
        (0, None) => Ok(vec![opcode]),
        (0, Some(_)) => Err(AssembleError::UnexpectedOperand {
            mnemonic: mnemonic.to_string(),
        }),
        (_, None) => Err(AssembleError::MissingOperand {
            mnemonic: mnemonic.to_string(),
        }),
        (_, Some(op)) => {
            let mut out = vec![opcode];
            out.extend(parse_immediate(op, width)?);
            Ok(out)
        }
    }
}

/// Parse an immediate into exactly `width` big-endian bytes.
fn parse_immediate(text: &str, width: usize) -> Result<Vec<u8>, AssembleError> {
    let too_wide = || AssembleError::ImmediateTooWide {
        text: text.to_string(),
        width,
    };
    let bad = || AssembleError::BadImmediate(text.to_string());

    let mut digits: Vec<u8> = Vec::new();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() {
            return Err(bad());
        }
        // Odd digit count: the leading nibble stands alone.
        let padded = if hex.len() % 2 == 1 {
            format!("0{hex}")
        } else {
            hex.to_string()
        };
        for pair in padded.as_bytes().chunks(2) {
            let s = std::str::from_utf8(pair).map_err(|_| bad())?;
            digits.push(u8::from_str_radix(s, 16).map_err(|_| bad())?);
        }
    } else {
        let n: u128 = text.parse().map_err(|_| bad())?;
        digits = n.to_be_bytes().to_vec();
    }

    let first_significant = digits.iter().position(|&b| b != 0).unwrap_or(digits.len());
    let significant = &digits[first_significant..];
    if significant.len() > width {
        return Err(too_wide());
    }
    let mut out = vec![0u8; width - significant.len()];
    out.extend_from_slice(significant);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solidity_prologue_decodes() {
        // PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO
        let bytes = [0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15];
        let insns = decode_range(&bytes, 0);
        let text: Vec<String> = insns.iter().map(format_insn).collect();
        assert_eq!(
            text,
            [
                "PUSH1 0x80",
                "PUSH1 0x40",
                "MSTORE",
                "CALLVALUE",
                "DUP1",
                "ISZERO"
            ]
        );
        assert_eq!(insns[2].addr, VAddr(4));
    }

    #[test]
    fn decode_concatenation_is_identity() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let insns = decode_range(&bytes, 0);
        let joined: Vec<u8> = insns
            .iter()
            .flat_map(|i| i.original_bytes.clone())
            .collect();
        assert_eq!(joined, bytes);
    }

    #[test]
    fn truncated_push_keeps_available_bytes() {
        let insns = decode_range(&[0x00, 0x63, 0xaa, 0xbb], 0);
        assert_eq!(insns.len(), 2);
        assert!(insns[1].is_truncated());
        assert_eq!(insns[1].original_bytes, [0x63, 0xaa, 0xbb]);
        assert_eq!(insns[1].push_value(), None);
        assert!(format_insn(&insns[1]).starts_with("PUSH4 0xaabb ; truncated"));
    }

    #[test]
    fn push_value_and_width() {
        let insn = decode_one(&[0x61, 0x01, 0xa3], 0).unwrap();
        assert_eq!(insn.push_value(), Some(0x01a3));
        assert_eq!(decode_one(&[0x5f], 0).unwrap().push_value(), Some(0));
        let wide = decode_one(&[0x7f; 33], 0).unwrap();
        assert_eq!(wide.push_value(), None);
    }

    #[test]
    fn assemble_inverts_format_for_every_opcode() {
        for op in 0..=255u8 {
            let mut bytes = vec![op];
            bytes.extend((0..OPCODE_TABLE[op as usize].imm_len).map(|i| i.wrapping_mul(37)));
            let insn = decode_one(&bytes, 0).unwrap();
            let text = format_insn(&insn);
            assert_eq!(assemble_one(&text).unwrap(), bytes, "{text}");
        }
    }

    #[test]
    fn assemble_pads_and_checks_width() {
        assert_eq!(assemble_one("push2 0x80").unwrap(), [0x61, 0x00, 0x80]);
        assert_eq!(assemble_one("PUSH1 255").unwrap(), [0x60, 0xff]);
        assert_eq!(assemble_one("PUSH1 0x80 ; comment").unwrap(), [0x60, 0x80]);
        assert_eq!(assemble_one("SHA3").unwrap(), [0x20]);
        assert!(matches!(
            assemble_one("PUSH1 0x100"),
            Err(AssembleError::ImmediateTooWide { .. })
        ));
        assert!(matches!(
            assemble_one("ADD 1"),
            Err(AssembleError::UnexpectedOperand { .. })
        ));
        assert!(matches!(
            assemble_one("PUSH4"),
            Err(AssembleError::MissingOperand { .. })
        ));
        assert!(matches!(
            assemble_one("RJUMP"),
            Err(AssembleError::UnknownMnemonic(_))
        ));
    }

    #[test]
    fn classify_control_flow() {
        let k = |b: u8| classify(&decode_one(&[b], 0).unwrap());
        assert_eq!(k(0x56), InsnKind::Jump);
        assert_eq!(k(0x57), InsnKind::JumpI);
        assert_eq!(k(0x5b), InsnKind::JumpDest);
        assert_eq!(k(0xfd), InsnKind::Halt);
        assert_eq!(k(0x0c), InsnKind::Halt);
        assert_eq!(k(0x01), InsnKind::Other);
    }
}

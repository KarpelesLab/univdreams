//! x86 architecture backend.
//!
//! Phase 1 scope: decode an x86 byte sequence into structured instructions
//! (via [`iced_x86`]), and provide two distinct emission paths:
//!
//! * [`emit_preserved`] — concatenate each instruction's original bytes
//!   captured at decode time. This is byte-identical by construction
//!   and is what the round-trip contract is built on.
//! * [`reencode_via_iced`] — feed the structured [`Instruction`]s back
//!   through `BlockEncoder`. This is *not* byte-identical for all real
//!   inputs: iced canonicalizes redundant prefixes (e.g. drops a `66`
//!   data16 override on a NOP that doesn't need it), so for compiler-
//!   emitted alignment NOPs and `.plt` padding the bytes will differ.
//!   Useful for "I edited an instruction" workflows in later phases,
//!   not for round-trip.
//!
//! 16- and 32-bit modes are exposed through [`Bitness`] and the same
//! API; the round-trip property is identical.

#![allow(clippy::cast_possible_truncation)]

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock,
};
use ud_core::VAddr;
use ud_ir::ArchInsn;

mod lift;
pub use lift::{lift_function, LiftError};

/// Errors produced by decode / encode / round-trip helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("instruction decoder rejected bytes at offset {offset}")]
    DecodeFailed { offset: usize },

    #[error("encoder rejected instructions: {0}")]
    Encode(String),

    #[error("round-trip diverged at offset {offset}: expected 0x{expected:02x}, got 0x{got:02x}")]
    ByteMismatch {
        offset: usize,
        expected: u8,
        got: u8,
    },

    #[error("round-trip length mismatch: input was {input} bytes, output is {output}")]
    LengthMismatch { input: usize, output: usize },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Bitness of an x86 decode/encode pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bitness {
    Bits16,
    Bits32,
    Bits64,
}

impl Bitness {
    fn as_u32(self) -> u32 {
        match self {
            Self::Bits16 => 16,
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

/// A single decoded instruction together with the exact bytes it
/// occupied in the source buffer.
///
/// `iced` is the structured form, useful for analysis (operand kinds,
/// branch targets, register usage, etc.). `original_bytes` is the byte
/// slice from the input — used by [`emit_preserved`] to re-emit a
/// byte-identical copy regardless of any encoding choices iced would
/// pick if asked to encode the structured form.
#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub iced: Instruction,
    pub original_bytes: Vec<u8>,
}

impl ArchInsn for DecodedInsn {
    fn addr(&self) -> VAddr {
        VAddr(self.iced.ip())
    }

    fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }
}

/// Decode `bytes` as a contiguous x86 instruction stream starting at
/// virtual address `rip`. Captures each instruction's exact bytes for
/// later byte-faithful re-emission.
///
/// Stops only when the buffer is exhausted. An invalid instruction is
/// a hard error — for code containing data-in-code, slice the
/// executable regions before calling.
pub fn decode(bitness: Bitness, bytes: &[u8], rip: u64) -> Result<Vec<DecodedInsn>> {
    let mut decoder = Decoder::with_ip(bitness.as_u32(), bytes, rip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let pos = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(Error::DecodeFailed { offset: pos });
        }
        let len = insn.len();
        let end = pos.saturating_add(len);
        if end > bytes.len() {
            return Err(Error::DecodeFailed { offset: pos });
        }
        out.push(DecodedInsn {
            iced: insn,
            original_bytes: bytes[pos..end].to_vec(),
        });
    }
    Ok(out)
}

/// Re-emit a decoded instruction stream using each instruction's
/// preserved original bytes. Byte-identical by construction.
#[must_use]
pub fn emit_preserved(insns: &[DecodedInsn]) -> Vec<u8> {
    let total: usize = insns.iter().map(|i| i.original_bytes.len()).sum();
    let mut out = Vec::with_capacity(total);
    for insn in insns {
        out.extend_from_slice(&insn.original_bytes);
    }
    out
}

/// Re-encode the structured instructions through iced's `BlockEncoder`.
///
/// **Warning**: this does not preserve redundant encoding choices. If
/// the input used a non-canonical encoding (redundant prefixes,
/// alignment NOPs with `66` data16 overrides, larger-than-necessary
/// displacement sizes), the output will differ from the input. Use
/// [`emit_preserved`] for byte-identical round-trip.
pub fn reencode_via_iced(bitness: Bitness, insns: &[DecodedInsn], rip: u64) -> Result<Vec<u8>> {
    let iced_insns: Vec<Instruction> = insns.iter().map(|i| i.iced).collect();
    let block = InstructionBlock::new(&iced_insns, rip);
    let result = BlockEncoder::encode(bitness.as_u32(), block, BlockEncoderOptions::NONE)
        .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(result.code_buffer)
}

/// Decode `bytes` and re-emit via [`emit_preserved`]; verify the result
/// equals the input. This is the format-agnostic round-trip property
/// for the x86 backend, and it must hold for every byte sequence we
/// claim to support.
pub fn roundtrip_bytes(bitness: Bitness, bytes: &[u8], rip: u64) -> Result<Vec<DecodedInsn>> {
    let insns = decode(bitness, bytes, rip)?;
    let emitted = emit_preserved(&insns);
    if emitted.len() != bytes.len() {
        return Err(Error::LengthMismatch {
            input: bytes.len(),
            output: emitted.len(),
        });
    }
    if let Some((offset, (&expected, &got))) = bytes
        .iter()
        .zip(&emitted)
        .enumerate()
        .find(|(_, (a, b))| a != b)
    {
        return Err(Error::ByteMismatch {
            offset,
            expected,
            got,
        });
    }
    Ok(insns)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `endbr64`: 0xf3 0x0f 0x1e 0xfa — gcc with -fcf-protection emits
    /// this at every function entry, so the fixtures all start with it.
    #[test]
    fn endbr64_roundtrips() {
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
    }

    #[test]
    fn prologue_roundtrips() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20
        let bytes = [
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
        ];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 3);
    }

    #[test]
    fn short_jump_roundtrips() {
        let bytes = [0xeb, 0x05];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    #[test]
    fn near_jump_roundtrips() {
        let bytes = [0xe9, 0x34, 0x12, 0x00, 0x00];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    #[test]
    fn call_rel32_roundtrips() {
        let bytes = [0xe8, 0x80, 0x00, 0x00, 0x00];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    #[test]
    fn xor_zero_idiom_roundtrips() {
        let bytes = [0x48, 0x31, 0xc0];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    /// Multi-byte NOP with the redundant 66 data16 prefix — the exact
    /// pattern compilers use for alignment, and the one that exposed
    /// iced's canonicalization issue. emit_preserved must keep it
    /// verbatim; reencode_via_iced is allowed to drop the 66.
    #[test]
    fn multibyte_nop_with_data16_prefix_preserved() {
        let bytes = [0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].original_bytes, bytes);

        // iced's encoder drops the redundant prefix; that's fine and
        // documented — the emit_preserved path is what guards round-trip.
        let reencoded = reencode_via_iced(Bitness::Bits64, &insns, 0x1000).unwrap();
        assert!(
            reencoded.len() <= bytes.len(),
            "iced should produce a shorter or equal canonical encoding"
        );
    }

    #[test]
    fn small_function_roundtrips() {
        let bytes = [
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x31, 0xc0, // xor eax, eax
            0x5d, // pop rbp
            0xc3, // ret
        ];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 6);
    }

    #[test]
    fn invalid_bytes_fail_decode() {
        let bytes = [0x06];
        assert!(matches!(
            roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000),
            Err(Error::DecodeFailed { .. })
        ));
    }
}

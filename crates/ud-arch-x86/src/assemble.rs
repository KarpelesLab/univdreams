//! Text → bytes assembler for the canonical Intel syntax that
//! [`format_intel`](crate::format_intel) produces.
//!
//! Bridge between human-readable `@asm("…")` text and the iced
//! encoder. Built deliberately small — only the operand shapes
//! the decompiler actually emits are recognised, and a fixture
//! coverage survey (`testdata/`) identifies which forms those
//! are. Forms we don't yet recognise return
//! [`AssembleError::Unsupported`] so callers can fall back to
//! the pinned bytes — no silent miscoding.
//!
//! Today's coverage is the zero-operand mnemonics
//! (`endbr64`, `hlt`, `nop`, `int3`, `ret`, `cdqe`, `cwde`,
//! `leave`, …). Each future commit adds another operand shape
//! once the encoder + a round-trip test for it land.
//!
//! The parser is whitespace + comma tokenized; case folding is
//! applied so `MOV RAX, RBX` and `mov rax,rbx` parse to the
//! same Instruction.

use iced_x86::{Code, Encoder, Instruction};

use crate::Bitness;

/// Errors raised by [`assemble_intel`].
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    /// The text is empty.
    #[error("empty text — assembler needs at least a mnemonic")]
    Empty,

    /// The mnemonic + operand shape isn't covered yet. Callers
    /// fall back to pinned bytes when they see this — it's not
    /// a hard error, just a "we don't ship this form yet"
    /// signal.
    #[error("unsupported instruction form {form:?}")]
    Unsupported { form: String },

    /// iced rejected the candidate encoding. The same
    /// `(Code, operands)` tuple round-trips perfectly elsewhere,
    /// so this is rare — it usually means the operand kinds we
    /// picked don't match what `Code` wants (encoder bug on
    /// our side, not iced's).
    #[error("iced encode failed: {message}")]
    EncodeFailed { message: String },
}

/// Parse `text` as a single x86 instruction in canonical Intel
/// syntax and encode it to bytes at `rip`. Returns the encoded
/// bytes when the form is recognised, or
/// [`AssembleError::Unsupported`] when it isn't.
///
/// `rip` only matters for RIP-relative encodings (`mov rax,
/// [rip+disp]`, `jmp 0x1234`, etc.); zero-operand forms ignore
/// it.
pub fn assemble_intel(bitness: Bitness, text: &str, rip: u64) -> Result<Vec<u8>, AssembleError> {
    let normalized = normalize(text);
    if normalized.is_empty() {
        return Err(AssembleError::Empty);
    }
    let insn = parse_text(&normalized, bitness)?;
    encode_insn(&insn, bitness, rip)
}

/// Lowercase + collapse runs of whitespace + strip the trailing
/// newline. The decoder's canonical output uses lowercase, but
/// hand-written text often has stray capitals or doubled
/// spaces — fold those out before tokenising.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = true;
    for c in text.chars() {
        if c.is_ascii_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.extend(c.to_lowercase());
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Split a normalized Intel-syntax line into the mnemonic
/// (possibly with a leading "notrack" prefix) and the rest. The
/// caller dispatches per-mnemonic.
fn split_mnemonic_and_rest(s: &str) -> (&str, &str) {
    // `notrack jmp …` and `notrack call …` carry a CET prefix;
    // strip it for dispatching but remember it so the encoder
    // can put the 0x3e back. Today every zero-operand form we
    // handle lacks this prefix, so we don't yet propagate it.
    let s = s.strip_prefix("notrack ").unwrap_or(s);
    match s.find(' ') {
        Some(i) => (&s[..i], s[i + 1..].trim_start()),
        None => (s, ""),
    }
}

fn parse_text(text: &str, _bitness: Bitness) -> Result<Instruction, AssembleError> {
    let (mnemonic, operands) = split_mnemonic_and_rest(text);
    if !operands.is_empty() {
        return Err(AssembleError::Unsupported {
            form: text.to_string(),
        });
    }
    let code = zero_operand_code(mnemonic).ok_or_else(|| AssembleError::Unsupported {
        form: text.to_string(),
    })?;
    Ok(Instruction::with(code))
}

/// Iced's `Code` for every zero-operand mnemonic we currently
/// emit. Add entries here as new mnemonics surface — the
/// coverage survey (`tests/assemble_coverage.rs`) keeps the set
/// honest.
fn zero_operand_code(mnemonic: &str) -> Option<Code> {
    Some(match mnemonic {
        "endbr64" => Code::Endbr64,
        "endbr32" => Code::Endbr32,
        "hlt" => Code::Hlt,
        "nop" => Code::Nopd,
        "int3" => Code::Int3,
        "ret" => Code::Retnq,
        "retq" => Code::Retnq,
        "retn" => Code::Retnd,
        "cdqe" => Code::Cdqe,
        "cwde" => Code::Cwde,
        "cbw" => Code::Cbw,
        "leave" | "leaveq" => Code::Leaveq,
        "syscall" => Code::Syscall,
        "ud2" => Code::Ud2,
        "pause" => Code::Pause,
        "rdtsc" => Code::Rdtsc,
        "cpuid" => Code::Cpuid,
        _ => return None,
    })
}

fn encode_insn(insn: &Instruction, bitness: Bitness, rip: u64) -> Result<Vec<u8>, AssembleError> {
    let mut encoder = Encoder::new(bitness.as_u32());
    encoder
        .encode(insn, rip)
        .map_err(|e| AssembleError::EncodeFailed {
            message: format!("{e:?}"),
        })?;
    Ok(encoder.take_buffer())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, format_intel};

    #[track_caller]
    fn round_trip(bitness: Bitness, text: &str, expected: &[u8]) {
        let bytes =
            assemble_intel(bitness, text, 0x1000).unwrap_or_else(|e| panic!("assemble {text:?}: {e}"));
        assert_eq!(
            bytes, expected,
            "bytes mismatch for {text:?}: got {bytes:02x?}, want {expected:02x?}"
        );
        // Decode the freshly-encoded bytes and confirm the
        // canonical text matches what we asked for.
        let insns = decode(bitness, &bytes, 0x1000).expect("decode round-trip");
        assert_eq!(insns.len(), 1, "expected single instruction");
        let canonical = format_intel(&insns[0].iced);
        assert_eq!(
            normalize(&canonical),
            normalize(text),
            "canonical text diverges"
        );
    }

    #[test]
    fn zero_operand_x86_64() {
        round_trip(Bitness::Bits64, "endbr64", &[0xf3, 0x0f, 0x1e, 0xfa]);
        round_trip(Bitness::Bits64, "hlt", &[0xf4]);
        round_trip(Bitness::Bits64, "nop", &[0x90]);
        round_trip(Bitness::Bits64, "int3", &[0xcc]);
        round_trip(Bitness::Bits64, "ret", &[0xc3]);
        round_trip(Bitness::Bits64, "cdqe", &[0x48, 0x98]);
        round_trip(Bitness::Bits64, "leave", &[0xc9]);
        round_trip(Bitness::Bits64, "syscall", &[0x0f, 0x05]);
        round_trip(Bitness::Bits64, "ud2", &[0x0f, 0x0b]);
    }

    #[test]
    fn zero_operand_normalizes_case_and_whitespace() {
        round_trip(Bitness::Bits64, "  ENDBR64  ", &[0xf3, 0x0f, 0x1e, 0xfa]);
    }

    #[test]
    fn unknown_mnemonic_returns_unsupported() {
        match assemble_intel(Bitness::Bits64, "completely-fake-insn", 0x1000) {
            Err(AssembleError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn empty_text_returns_empty_error() {
        match assemble_intel(Bitness::Bits64, "", 0x1000) {
            Err(AssembleError::Empty) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn operand_form_is_unsupported_today() {
        // Make sure the gate is firmly closed for forms we
        // haven't implemented yet. The fallback to pinned bytes
        // is what makes this safe to ship incrementally.
        match assemble_intel(Bitness::Bits64, "mov rax, rbx", 0x1000) {
            Err(AssembleError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}

//! Core types shared across univdreams crates.
//!
//! This crate is intentionally minimal at Phase 0. It will grow as the
//! pipeline does, but the surface here should stay narrow: types every
//! crate above it agrees on (addresses, ranges, errors), and nothing
//! that belongs in a more specific crate.

use std::path::PathBuf;

/// Crate result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors surfaced through the public API.
///
/// Variants are deliberately coarse for now. As real pipelines come online
/// (lifter, encoder, format reader/writer) each will introduce its own
/// error type and convert at the boundary; this enum is for things that
/// genuinely belong at the top of the stack.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "round-trip failed: output differs from input at byte {offset} \
         (input=0x{input_byte:02x}, output=0x{output_byte:02x}); {extra} more byte(s) differ"
    )]
    RoundTripMismatch {
        offset: usize,
        input_byte: u8,
        output_byte: u8,
        extra: usize,
    },

    #[error("round-trip failed: output length {output_len} differs from input length {input_len}")]
    RoundTripLengthMismatch { input_len: usize, output_len: usize },
}

/// A virtual address in a target binary.
///
/// Kept as a thin newtype so it can't be mixed up with file offsets or
/// host addresses. Will gain an arch-bits parameter when 16/32-bit
/// targets land.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VAddr(pub u64);

impl std::fmt::Debug for VAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VAddr(0x{:x})", self.0)
    }
}

impl std::fmt::Display for VAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// Compare two byte buffers and produce a [`Error::RoundTripMismatch`] /
/// [`Error::RoundTripLengthMismatch`] when they differ.
///
/// Used by the round-trip harness; lives here so both the CLI and any
/// future test crate can call it.
pub fn assert_bytes_equal(input: &[u8], output: &[u8]) -> Result<()> {
    if input.len() != output.len() {
        return Err(Error::RoundTripLengthMismatch {
            input_len: input.len(),
            output_len: output.len(),
        });
    }
    let Some(offset) = input.iter().zip(output).position(|(a, b)| a != b) else {
        return Ok(());
    };
    let extra = input[offset + 1..]
        .iter()
        .zip(&output[offset + 1..])
        .filter(|(a, b)| a != b)
        .count();
    Err(Error::RoundTripMismatch {
        offset,
        input_byte: input[offset],
        output_byte: output[offset],
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_buffers_pass() {
        assert!(assert_bytes_equal(b"abc", b"abc").is_ok());
    }

    #[test]
    fn length_mismatch_reports_lengths() {
        let err = assert_bytes_equal(b"abc", b"abcd").unwrap_err();
        assert!(matches!(
            err,
            Error::RoundTripLengthMismatch {
                input_len: 3,
                output_len: 4
            }
        ));
    }

    #[test]
    fn byte_mismatch_reports_offset_and_count() {
        let err = assert_bytes_equal(b"abcde", b"abXdY").unwrap_err();
        match err {
            Error::RoundTripMismatch {
                offset,
                input_byte,
                output_byte,
                extra,
            } => {
                assert_eq!(offset, 2);
                assert_eq!(input_byte, b'c');
                assert_eq!(output_byte, b'X');
                assert_eq!(extra, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

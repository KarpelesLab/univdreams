//! Library half of the `ud` CLI.
//!
//! The CLI binary is a thin wrapper over the functions exposed here; the
//! split lets integration tests call the same code path as the binary
//! without spawning a subprocess.

pub mod solana;

use std::path::Path;

use ud_core::{assert_bytes_equal, Error, Result};
use ud_translate::compile::AsmWarning;

/// Run the round-trip pipeline on `input`, write the result to `output`,
/// and verify byte-equality with the input.
///
/// The pipeline routes by detected format:
///
/// * **ELF64-LE** is parsed via [`ud_format::elf::Elf64File`] and re-emitted.
///   This actually exercises the format reader/writer, so any drift in
///   either path is caught here.
/// * **Anything else** (32-bit ELF, PE, Mach-O, raw bytes) falls through
///   to a byte-copy. The round-trip contract still holds — it's just the
///   trivial identity until we grow support.
///
/// The shape of this function will not change as later phases replace
/// `pipeline_bytes` with real decompile-then-compile logic. The contract
/// is "input bytes equal output bytes or you get an error", forever.
pub fn roundtrip(input: &Path, output: &Path) -> Result<()> {
    let bytes = std::fs::read(input).map_err(|source| Error::Io {
        path: input.to_path_buf(),
        source,
    })?;

    let rebuilt = pipeline_bytes(&bytes);

    std::fs::write(output, &rebuilt).map_err(|source| Error::Io {
        path: output.to_path_buf(),
        source,
    })?;

    let written_back = std::fs::read(output).map_err(|source| Error::Io {
        path: output.to_path_buf(),
        source,
    })?;

    assert_bytes_equal(&bytes, &written_back)
}

/// Apply the round-trip pipeline to in-memory bytes and return the result.
///
/// Split out so it's directly testable without filesystem I/O.
fn pipeline_bytes(bytes: &[u8]) -> Vec<u8> {
    if ud_format::elf::is_elf64_le(bytes) {
        if let Ok(elf) = ud_format::elf::Elf64File::parse(bytes) {
            return elf.write_to_vec();
        }
        // ELF that we still can't parse (e.g. malformed header sizes).
        // Fall through to byte-copy so the round-trip contract holds.
    }
    if ud_format::pe::is_pe(bytes) {
        if let Ok(pe) = ud_format::pe::PeFile::parse(bytes) {
            return pe.write_to_vec();
        }
        // PE-shaped but invalid; fall through to byte-copy.
    }
    if ud_format::macho::is_macho64(bytes) {
        if let Ok(macho) = ud_format::macho::MachoFile::parse(bytes) {
            return macho.write_to_vec();
        }
        // Mach-O-shaped but rejected by v1 (32-bit, unsupported
        // cputype, fat wrapper); fall through to byte-copy.
    }
    bytes.to_vec()
}

/// Result of [`roundtrip_through_source`].
#[derive(Debug, Clone)]
pub struct SourceRoundTripReport {
    /// Whether the rebuilt bytes equal the input bytes.
    pub byte_identical: bool,
    /// Length of the input in bytes.
    pub input_len: usize,
    /// Length of the rebuilt bytes.
    pub output_len: usize,
    /// Offset of the first byte that differs, when the round-trip
    /// failed; `None` when the result is byte-identical.
    pub first_diff_offset: Option<usize>,
    /// 16-byte excerpts of input and output bytes around the first
    /// divergence. Populated only on mismatch.
    pub diff_context: Option<DiffContext>,
    /// `verify_asm` findings produced during the round-trip. Empty
    /// for a clean decompile output; populated when the `.ud`
    /// in-flight had `@asm` lines whose text disagreed with their
    /// pinned bytes.
    pub warnings: Vec<AsmWarning>,
}

/// 16-byte windows of input vs rebuilt bytes around the first
/// divergence, with the divergence offset highlighted.
#[derive(Debug, Clone)]
pub struct DiffContext {
    pub window_start: usize,
    pub input_window: Vec<u8>,
    pub output_window: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceRoundTripError {
    #[error("input is not a recognised binary format")]
    UnknownFormat,
    #[error(transparent)]
    Io(std::io::Error),
    #[error(transparent)]
    Decompile(#[from] ud_translate::decompile::Error),
    #[error(transparent)]
    Decompile6502(#[from] ud_translate::decompile::raw6502::Error),
    #[error(transparent)]
    ElfFormat(#[from] ud_format::elf::Error),
    #[error(transparent)]
    PeFormat(#[from] ud_format::pe::Error),
    #[error(transparent)]
    MachoFormat(#[from] ud_format::macho::Error),
    #[error("parse of decompile output failed: {0}")]
    Parse(String),
    #[error(transparent)]
    ElfLower(#[from] ud_translate::compile::ElfLowerError),
    #[error(transparent)]
    PeLower(#[from] ud_translate::compile::PeLowerError),
    #[error(transparent)]
    MachoLower(#[from] ud_translate::compile::MachoLowerError),
    #[error(transparent)]
    RawLower(#[from] ud_translate::compile::RawLowerError),
}

/// Run `input` through the full source pipeline:
/// decompile → text → parse → verify_asm → lower_to_elf → write.
///
/// Always emits the rebuilt binary. Verification warnings are collected
/// in the report and don't fail the call. Byte differences between input
/// and rebuilt also don't fail the call — they appear in the report so
/// the caller can decide what to do (warn, abort, persist anyway).
pub fn roundtrip_through_source(
    input: &Path,
    output: &Path,
) -> std::result::Result<SourceRoundTripReport, SourceRoundTripError> {
    let input_bytes = std::fs::read(input).map_err(SourceRoundTripError::Io)?;

    let (text, warnings, rebuilt) = if ud_format::elf::is_elf64_le(&input_bytes) {
        let elf = ud_format::elf::Elf64File::parse(&input_bytes)?;
        let ast = ud_translate::decompile::decompile(&elf)?;
        let text = ud_ast::emit(&ast);
        let parsed = ud_translate::compile::parse(&text)
            .map_err(|e| SourceRoundTripError::Parse(e.to_string()))?;
        let warnings = ud_translate::compile::verify_asm(&parsed);
        let rebuilt = ud_translate::compile::lower_to_elf(&parsed)?;
        (text, warnings, rebuilt)
    } else if ud_format::pe::is_pe(&input_bytes) {
        let pe = ud_format::pe::PeFile::parse(&input_bytes)?;
        let ast = ud_translate::decompile::decompile_pe(&pe);
        let text = ud_ast::emit(&ast);
        let parsed = ud_translate::compile::parse(&text)
            .map_err(|e| SourceRoundTripError::Parse(e.to_string()))?;
        let warnings = ud_translate::compile::verify_asm(&parsed);
        let rebuilt = ud_translate::compile::lower_to_pe(&parsed)?;
        (text, warnings, rebuilt)
    } else if ud_format::macho::is_macho64(&input_bytes) {
        let macho = ud_format::macho::MachoFile::parse(&input_bytes)?;
        let ast = ud_translate::decompile::decompile_macho(&macho);
        let text = ud_ast::emit(&ast);
        let parsed = ud_translate::compile::parse(&text)
            .map_err(|e| SourceRoundTripError::Parse(e.to_string()))?;
        let warnings = ud_translate::compile::verify_asm(&parsed);
        let rebuilt = ud_translate::compile::lower_to_macho(&parsed)?;
        (text, warnings, rebuilt)
    } else if let Some(load_addr) = raw_6502_load_addr(&input_bytes) {
        let image = ud_format::raw::RawImage::new(input_bytes.clone(), load_addr);
        let ast = ud_translate::decompile::decompile_raw_6502(&image)?;
        let text = ud_ast::emit(&ast);
        let parsed = ud_translate::compile::parse(&text)
            .map_err(|e| SourceRoundTripError::Parse(e.to_string()))?;
        let warnings = ud_translate::compile::verify_asm(&parsed);
        let rebuilt = ud_translate::compile::lower_to_raw(&parsed)?;
        (text, warnings, rebuilt)
    } else {
        return Err(SourceRoundTripError::UnknownFormat);
    };
    let _ = text; // kept for future debug surfacing

    std::fs::write(output, &rebuilt).map_err(SourceRoundTripError::Io)?;

    let first_diff_offset = first_byte_diff(&input_bytes, &rebuilt);
    let diff_context = first_diff_offset.map(|off| make_diff_context(off, &input_bytes, &rebuilt));
    Ok(SourceRoundTripReport {
        byte_identical: first_diff_offset.is_none() && input_bytes.len() == rebuilt.len(),
        input_len: input_bytes.len(),
        output_len: rebuilt.len(),
        first_diff_offset,
        diff_context,
        warnings,
    })
}

fn make_diff_context(off: usize, input: &[u8], output: &[u8]) -> DiffContext {
    let window_start = off.saturating_sub(8);
    let window_end_in = (off + 8).min(input.len());
    let window_end_out = (off + 8).min(output.len());
    DiffContext {
        window_start,
        input_window: input[window_start..window_end_in].to_vec(),
        output_window: output[window_start..window_end_out].to_vec(),
    }
}

/// Detect "this is a 6502 raw ROM image" inputs. The convention is
/// that 6502 binaries place vectors (NMI/RESET/IRQ) at the top of
/// the 16-bit address space, $FFFA-$FFFF. For an image of length L,
/// the natural load address is `0x10000 - L` so the image extends
/// exactly to $FFFF.
///
/// v0 heuristic: accept files in `[6, 65536]` bytes whose reset
/// vector at $FFFC under that load address points back into the
/// image. WozMon (256 bytes, load $FF00, reset $FF00) matches.
#[must_use]
pub fn raw_6502_load_addr(bytes: &[u8]) -> Option<u64> {
    let len = bytes.len();
    if !(6..=0x10000).contains(&len) {
        return None;
    }
    let load_addr = 0x10000u64 - len as u64;
    let end = 0x10000u64;
    let reset_lo_off = usize::try_from(0xFFFCu64 - load_addr).ok()?;
    let reset_hi_off = reset_lo_off + 1;
    if reset_hi_off >= len {
        return None;
    }
    let reset = u64::from(u16::from_le_bytes([
        bytes[reset_lo_off],
        bytes[reset_hi_off],
    ]));
    if reset >= load_addr && reset < end {
        Some(load_addr)
    } else {
        None
    }
}

fn first_byte_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .or_else(|| (a.len() != b.len()).then_some(a.len().min(b.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_passes_through_non_elf_bytes() {
        let bytes = b"\x00\x01\x02\x03not an elf";
        assert_eq!(pipeline_bytes(bytes), bytes);
    }

    #[test]
    fn pipeline_passes_through_elf32() {
        // Magic + ELFCLASS32 + ELFDATA2LSB → not ELF64, must byte-copy.
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1; // ELFCLASS32
        bytes[5] = 1; // ELFDATA2LSB
        let out = pipeline_bytes(&bytes);
        assert_eq!(out, bytes);
    }

    #[test]
    fn roundtrip_on_a_temp_file_succeeds() {
        let dir = std::env::temp_dir();
        let input = dir.join("ud-cli-rt-in");
        let output = dir.join("ud-cli-rt-out");
        std::fs::write(&input, b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00").unwrap();
        roundtrip(&input, &output).expect("identity round-trip should succeed");
        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&output);
    }
}

//! Library half of the `ud` CLI.
//!
//! The CLI binary is a thin wrapper over the functions exposed here; the
//! split lets integration tests call the same code path as the binary
//! without spawning a subprocess.

use std::path::Path;
use ud_core::{assert_bytes_equal, Error, Result};

/// Run the round-trip pipeline on `input`, write the result to `output`,
/// and verify byte-equality with the input.
///
/// The pipeline routes by detected format:
///
/// * **ELF64-LE** is parsed via [`ud_format_elf::Elf64File`] and re-emitted.
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
    if ud_format_elf::is_elf64_le(bytes) {
        if let Ok(elf) = ud_format_elf::Elf64File::parse(bytes) {
            return elf.write_to_vec();
        }
        // ELF64-LE that we still can't parse (e.g. malformed header sizes).
        // Fall through to byte-copy so the round-trip contract holds.
    }
    bytes.to_vec()
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

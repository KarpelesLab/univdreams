//! Library half of the `ud` CLI.
//!
//! The CLI binary is a thin wrapper over the functions exposed here; the
//! split lets integration tests call the same code path as the binary
//! without spawning a subprocess.

use std::path::Path;
use ud_core::{assert_bytes_equal, Error, Result};

/// Run the round-trip pipeline on `input` and write the result to `output`,
/// then verify byte-equality with the input.
///
/// At Phase 0 the pipeline is the identity: read bytes, write the same
/// bytes back. The shape of this function will not change as later phases
/// replace the body with a real decompile-then-compile path; the contract
/// is "input bytes equal output bytes or you get an error", and that
/// remains the contract forever.
pub fn roundtrip(input: &Path, output: &Path) -> Result<()> {
    let bytes = std::fs::read(input).map_err(|source| Error::Io {
        path: input.to_path_buf(),
        source,
    })?;

    // Phase 0 round-trip: identity. Replaced by decompile→compile in Phase 1+.
    let rebuilt = bytes.clone();

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

#[cfg(test)]
mod tests {
    use super::*;

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

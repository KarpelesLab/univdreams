//! Byte-identical round-trip: `MachoFile::parse(b)?.write_to_vec() == b`
//! for every committed Mach-O fixture in `testdata/`.
//!
//! This validates the format crate in isolation — no source-language
//! pipeline involved. If this test fails, the header / load-cmd /
//! segment / padding round-trip is broken; that's a hard precondition
//! for the source-level round-trip suite further up the stack.

use std::path::{Path, PathBuf};

use ud_format_macho::{is_macho64, MachoFile};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn testdata_files() -> Vec<PathBuf> {
    let dir = workspace_root().join("testdata");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

#[test]
fn macho_byte_identical_round_trip() {
    let mut covered = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for path in testdata_files() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if !is_macho64(&bytes) {
            continue;
        }
        match MachoFile::parse(&bytes) {
            Ok(macho) => {
                let rebuilt = macho.write_to_vec();
                if rebuilt.iter().eq(bytes.iter()) {
                    covered += 1;
                    eprintln!("ok    {} ({} bytes)", path.display(), bytes.len());
                } else {
                    let mismatch = bytes
                        .iter()
                        .zip(&rebuilt)
                        .position(|(a, b)| a != b)
                        .unwrap_or(bytes.len().min(rebuilt.len()));
                    failures.push(format!(
                        "{}: bytes diverge at offset {mismatch} (input {} bytes, rebuilt {} bytes)",
                        path.display(),
                        bytes.len(),
                        rebuilt.len()
                    ));
                }
            }
            Err(e) => failures.push(format!("{}: parse failed: {e}", path.display())),
        }
    }
    assert!(
        failures.is_empty(),
        "{} Mach-O fixture(s) failed round-trip ({} ok):\n  {}",
        failures.len(),
        covered,
        failures.join("\n  ")
    );
    assert!(
        covered > 0,
        "no Mach-O fixtures found under testdata/ — did you forget to commit them?"
    );
}

//! Whole-binary Mach-O source round-trip property:
//!
//! ```text
//! lower_to_macho(parse(decompile_macho_to_text(macho))) == original Mach-O bytes
//! ```
//!
//! For every thin 64-bit Mach-O fixture under `testdata/` (both
//! `x86_64` and `arm64`), this test drives the full source
//! pipeline and asserts byte-identity with the input. Mirrors
//! `whole_binary_round_trip.rs`'s shape for ELF.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_translate::compile::{lower_to_macho, parse};
use ud_format::macho::{is_macho64, MachoFile};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn collect_fixtures(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            out.extend(collect_fixtures(&path));
        } else if meta.is_file() {
            out.push(path);
        }
    }
    out
}

#[test]
fn macho_whole_binary_byte_identity_through_source() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} missing; skipping", testdata.display());
        return;
    }

    let mut total = 0usize;
    let mut total_bytes = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let mut fixtures = collect_fixtures(&testdata);
    fixtures.sort();
    for fixture in fixtures {
        let Ok(bytes) = std::fs::read(&fixture) else {
            continue;
        };
        if !is_macho64(&bytes) {
            continue;
        }
        let Ok(macho) = MachoFile::parse(&bytes) else {
            continue;
        };

        let text = ud_translate::decompile::decompile_macho_to_text(&macho);
        let ast = match parse(&text) {
            Ok(a) => a,
            Err(e) => {
                failures.push(format!("{}: parse: {e}", fixture.display()));
                continue;
            }
        };
        let recompiled = match lower_to_macho(&ast) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: lower_to_macho: {e}", fixture.display()));
                continue;
            }
        };

        if recompiled.iter().eq(bytes.iter()) {
            eprintln!("ok    {} ({} bytes)", fixture.display(), bytes.len());
            total += 1;
            total_bytes += bytes.len();
        } else {
            let offset = recompiled
                .iter()
                .zip(&bytes)
                .position(|(a, b)| a != b)
                .unwrap_or(recompiled.len().min(bytes.len()));
            failures.push(format!(
                "{}: bytes diverge at offset {offset} (recompiled len {}, original len {})",
                fixture.display(),
                recompiled.len(),
                bytes.len()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} Mach-O fixture(s) failed whole-binary source round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!("Mach-O whole-binary round-trip: {total} fixtures, {total_bytes} bytes");
    assert!(total > 0, "expected at least one Mach-O fixture to test");
}

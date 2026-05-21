//! Whole-binary WASM source round-trip property:
//!
//! ```text
//! lower_to_wasm(parse(decompile_wasm_to_text(wasm))) == original WASM bytes
//! ```
//!
//! Plus the lower-level container property:
//!
//! ```text
//! WasmFile::parse(bytes).write_to_vec() == bytes
//! ```
//!
//! The decompile path emits opaque `@raw` blocks (one for the
//! 8-byte header and one per section), and the lower path
//! concatenates them in order — so byte-identity is the
//! contract every WASM fixture under `testdata/` must satisfy.

use std::path::{Path, PathBuf};

use ud_format::wasm::{is_wasm, WasmFile};
use ud_translate::compile::{lower_to_wasm, parse};
use ud_translate::decompile::decompile_wasm_to_text;

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
fn wasm_container_byte_identity() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} missing; skipping", testdata.display());
        return;
    }

    let mut total = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut fixtures = collect_fixtures(&testdata);
    fixtures.sort();

    for fixture in fixtures {
        let Ok(bytes) = std::fs::read(&fixture) else {
            continue;
        };
        if !is_wasm(&bytes) {
            continue;
        }
        let wasm = match WasmFile::parse(&bytes) {
            Ok(w) => w,
            Err(e) => {
                failures.push(format!("{}: parse: {e}", fixture.display()));
                continue;
            }
        };
        let rebuilt = wasm.write_to_vec();
        if rebuilt == bytes {
            eprintln!("ok    {} ({} bytes)", fixture.display(), bytes.len());
            total += 1;
        } else {
            failures.push(format!(
                "{}: container round-trip differs",
                fixture.display()
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} WASM fixture(s) failed container round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(total > 0, "expected at least one WASM fixture to test");
}

#[test]
fn wasm_whole_binary_byte_identity_through_source() {
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
        if !is_wasm(&bytes) {
            continue;
        }
        let wasm = match WasmFile::parse(&bytes) {
            Ok(w) => w,
            Err(e) => {
                failures.push(format!("{}: parse: {e}", fixture.display()));
                continue;
            }
        };

        let text = decompile_wasm_to_text(&wasm);
        let ast = match parse(&text) {
            Ok(a) => a,
            Err(e) => {
                failures.push(format!("{}: parse(ud): {e}", fixture.display()));
                continue;
            }
        };
        let recompiled = match lower_to_wasm(&ast) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: lower_to_wasm: {e}", fixture.display()));
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
        "{} WASM fixture(s) failed whole-binary source round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!("WASM whole-binary round-trip: {total} fixtures, {total_bytes} bytes");
    assert!(total > 0, "expected at least one WASM fixture to test");
}

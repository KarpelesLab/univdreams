//! Byte-identical round-trip property for BPF ELF inputs:
//!
//! ```text
//! lower_to_elf(parse(decompile_to_text(elf)))   ==   original ELF bytes
//! ```
//!
//! Mirrors `whole_binary_round_trip.rs` but filters on
//! `e_machine ∈ {EM_BPF, EM_SBF}` so the BPF arch path is
//! exercised against any committed BPF fixture (Linux eBPF
//! object files in `.o` form, Solana SBF `.so` shared objects).
//! The Solana fixtures aren't checked into the repo yet — see
//! `scripts/build-bpf-fixtures.sh` — so the test passes
//! silently when only `hello-clang-ebpf-linux.o` is present
//! and exercises the SBF code paths once those land.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_format::elf::{is_elf64_le, Elf64File, EM_BPF, EM_SBF};
use ud_translate::compile::{lower_to_elf, parse};

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
fn bpf_byte_identity_through_source() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} missing; skipping", testdata.display());
        return;
    }

    let mut total = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in collect_fixtures(&testdata) {
        let Ok(bytes) = std::fs::read(&fixture) else {
            continue;
        };
        if !is_elf64_le(&bytes) {
            continue;
        }
        let Ok(elf) = Elf64File::parse(&bytes) else {
            continue;
        };
        if elf.ehdr.e_machine != EM_BPF && elf.ehdr.e_machine != EM_SBF {
            continue;
        }

        let text = match ud_translate::decompile::decompile_to_text(&elf) {
            Ok(t) => t,
            Err(e) => {
                failures.push(format!("{}: decompile: {e}", fixture.display()));
                continue;
            }
        };
        let ast = match parse(&text) {
            Ok(a) => a,
            Err(e) => {
                failures.push(format!("{}: parse: {e}", fixture.display()));
                continue;
            }
        };
        let recompiled = match lower_to_elf(&ast) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: lower_to_elf: {e}", fixture.display()));
                continue;
            }
        };

        if recompiled != bytes {
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
            continue;
        }
        total += 1;
    }

    assert!(
        failures.is_empty(),
        "{} failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        total > 0,
        "expected at least one BPF/SBF fixture under testdata/ — none round-tripped"
    );
    eprintln!("bpf_byte_identity_through_source: {total} fixture(s) round-tripped");
}

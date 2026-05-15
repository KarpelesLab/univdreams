//! End-to-end source-language round-trip property:
//!
//! ```text
//! lower(parse(decompile_to_text(elf))) == per-function-bytes(elf)
//! ```
//!
//! For each x86_64 ELF fixture, we:
//!
//! 1. Decompile to canonical `.ud` text.
//! 2. Parse that text back into an AST.
//! 3. Lower each parsed function to bytes.
//! 4. Slice the original function bytes from the ELF and compare.
//!
//! Failure here means the source language has lost fidelity somewhere
//! along the way — text emit, parse, or lower. Passing means we can
//! round-trip a function's bytes through `.ud` source.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_translate::compile::{lower_functions, parse};
use ud_format_elf::{is_elf64_le, Elf64File, EM_X86_64};

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

fn slice_function_bytes(elf: &Elf64File, addr: u64, size: u64) -> Option<&[u8]> {
    if size == 0 {
        return None;
    }
    for (_, sh, data) in elf.sections() {
        let sh_end = sh.sh_addr.saturating_add(sh.sh_size);
        if sh.sh_addr <= addr && addr.saturating_add(size) <= sh_end {
            let offset = (addr - sh.sh_addr) as usize;
            let slice_end = offset + size as usize;
            if slice_end <= data.len() {
                return Some(&data[offset..slice_end]);
            }
        }
    }
    None
}

#[test]
fn source_round_trip_byte_identity_per_function() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} missing; skipping", testdata.display());
        return;
    }

    let mut total_funcs = 0usize;
    let mut total_bytes = 0usize;
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
        if elf.ehdr.e_machine != EM_X86_64 {
            continue;
        }

        // Decompile -> text -> parse.
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

        // Lower every parsed function to bytes; compare with original slice.
        let lowered = match lower_functions(&ast) {
            Ok(l) => l,
            Err(e) => {
                failures.push(format!("{}: lower: {e}", fixture.display()));
                continue;
            }
        };

        for lf in &lowered {
            let Some(addr) = lf.addr else {
                failures.push(format!(
                    "{}: function `{}` has no @addr; cannot locate ground-truth bytes",
                    fixture.display(),
                    lf.name
                ));
                continue;
            };
            let Some(original) = slice_function_bytes(&elf, addr, lf.bytes.len() as u64) else {
                failures.push(format!(
                    "{}: function `{}` at 0x{addr:x} not found in any executable section",
                    fixture.display(),
                    lf.name
                ));
                continue;
            };
            if lf.bytes.as_slice() != original {
                let offset = lf
                    .bytes
                    .iter()
                    .zip(original)
                    .position(|(a, b)| a != b)
                    .unwrap_or(lf.bytes.len().min(original.len()));
                failures.push(format!(
                    "{} :: {} (0x{addr:x}): bytes diverge at offset {offset} \
                     (recompiled len = {}, original len = {})",
                    fixture.display(),
                    lf.name,
                    lf.bytes.len(),
                    original.len()
                ));
                continue;
            }
            total_funcs += 1;
            total_bytes += lf.bytes.len();
        }

        eprintln!(
            "ok    {} ({} functions through source)",
            fixture.display(),
            lowered.len()
        );
    }

    assert!(
        failures.is_empty(),
        "{} function(s) failed source round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!("source round-trip: {total_funcs} functions, {total_bytes} bytes");
    assert!(total_funcs > 0, "expected at least one function to test");
}

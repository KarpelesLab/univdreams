//! Per-section source round-trip property:
//!
//! ```text
//! lower(parse(decompile_to_text(elf)))   ==   per-section-bytes(elf)
//! ```
//!
//! For each x86_64 ELF fixture, we decompile to canonical `.ud` text,
//! parse it back, lower every `@section` block to bytes, and compare
//! against the section's on-disk content. This is a strictly stronger
//! property than the per-function test: it catches drops in alignment
//! padding, gaps between functions, and content of non-text sections
//! (`.rodata`, `.dynamic`, `.data`, …) — anything the decompiler
//! captured as `@raw`.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_translate::compile::{lower_sections, parse};
use ud_format::elf::{is_elf64_le, Elf64File, EM_X86_64};

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

fn slice_section_bytes_by_name<'a>(elf: &'a Elf64File, name: &str) -> Option<&'a [u8]> {
    for (idx, _, data) in elf.sections() {
        if elf.section_name(idx) == Some(name) {
            return Some(data);
        }
    }
    None
}

#[test]
fn source_round_trip_byte_identity_per_section() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} missing; skipping", testdata.display());
        return;
    }

    let mut total_sections = 0usize;
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
        let lowered = match lower_sections(&ast) {
            Ok(l) => l,
            Err(e) => {
                failures.push(format!("{}: lower: {e}", fixture.display()));
                continue;
            }
        };

        for sec in &lowered {
            let Some(original) = slice_section_bytes_by_name(&elf, &sec.name) else {
                failures.push(format!(
                    "{}: section `{}` at 0x{:x} not found in original ELF",
                    fixture.display(),
                    sec.name,
                    sec.addr
                ));
                continue;
            };
            if sec.bytes.as_slice() != original {
                let offset = sec
                    .bytes
                    .iter()
                    .zip(original)
                    .position(|(a, b)| a != b)
                    .unwrap_or(sec.bytes.len().min(original.len()));
                failures.push(format!(
                    "{} :: section `{}` (0x{:x}): bytes diverge at offset {offset} \
                     (recompiled len = {}, original len = {})",
                    fixture.display(),
                    sec.name,
                    sec.addr,
                    sec.bytes.len(),
                    original.len()
                ));
                continue;
            }
            total_sections += 1;
            total_bytes += sec.bytes.len();
        }

        eprintln!(
            "ok    {} ({} sections through source)",
            fixture.display(),
            lowered.len()
        );
    }

    assert!(
        failures.is_empty(),
        "{} section(s) failed source round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    eprintln!("source round-trip: {total_sections} sections, {total_bytes} bytes");
    assert!(total_sections > 0, "expected at least one section to test");
}

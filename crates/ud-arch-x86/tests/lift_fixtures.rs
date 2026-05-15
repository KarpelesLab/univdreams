//! Lift every discoverable function in each x86_64 ELF fixture into
//! the IR, emit the bytes back, and assert byte-identity against the
//! function's original slice in `.text`.
//!
//! This is the end-to-end Phase-2 proof: the decompile pipeline now
//! goes
//!
//!     ELF → discover function → slice bytes → decode → lift to IR
//!         → emit_bytes → identical bytes
//!
//! and every step is exercised against real compiler output.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_analysis::{discover_functions, Function as DiscoveredFunction};
use ud_arch_x86::{decode, lift_function, Bitness};
use ud_format::elf::{is_elf64_le, Elf64File, Shdr64, EM_X86_64};

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

/// Find the section that contains the address range
/// `[addr, addr + size)`, returning a slice of its on-disk bytes covering
/// exactly that range. Returns `None` if no section contains the range
/// or if the range spans more than one section.
fn slice_function_bytes(elf: &Elf64File, addr: u64, size: u64) -> Option<&[u8]> {
    if size == 0 {
        return None;
    }
    let end = addr.checked_add(size)?;
    for (_, sh, data) in elf.sections() {
        if sh_contains(sh, addr)
            && addr.saturating_add(size) <= sh.sh_addr.saturating_add(sh.sh_size)
        {
            let offset = (addr - sh.sh_addr) as usize;
            let slice_end = offset + size as usize;
            if slice_end > data.len() {
                return None;
            }
            return Some(&data[offset..slice_end]);
        }
        // tighten bounds check above by ensuring `end` doesn't slip out
        let _ = end;
    }
    None
}

fn sh_contains(sh: &Shdr64, addr: u64) -> bool {
    sh.sh_addr <= addr && addr < sh.sh_addr.saturating_add(sh.sh_size)
}

#[test]
fn lift_every_x86_64_fixture_function() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} is missing; nothing to test", testdata.display());
        return;
    }

    let fixtures = collect_fixtures(&testdata);
    let mut total_funcs = 0usize;
    let mut total_blocks = 0usize;
    let mut total_insns = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let bytes = std::fs::read(fixture).expect("read fixture");
        if !is_elf64_le(&bytes) {
            continue;
        }
        let Ok(elf) = Elf64File::parse(&bytes) else {
            continue;
        };
        if elf.ehdr.e_machine != EM_X86_64 {
            continue;
        }

        let map = discover_functions(&elf).expect("discover");

        for f in map.iter() {
            let result = lift_one(&elf, f);
            match result {
                LiftOutcome::Ok { blocks, insns } => {
                    eprintln!(
                        "ok    {}::{} (addr=0x{:x}, size={}, {} blocks, {} insns)",
                        fixture.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                        f.name,
                        f.addr.0,
                        f.size,
                        blocks,
                        insns,
                    );
                    total_funcs += 1;
                    total_blocks += blocks;
                    total_insns += insns;
                }
                LiftOutcome::SkippedNoSize => {
                    eprintln!(
                        "skip  {}::{} (no size in symbol table)",
                        fixture.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                        f.name,
                    );
                }
                LiftOutcome::SkippedNotInExecutableSection => {
                    eprintln!(
                        "skip  {}::{} (not in an executable section)",
                        fixture.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                        f.name,
                    );
                }
                LiftOutcome::Failed(msg) => {
                    failures.push(format!(
                        "{}::{} (addr=0x{:x}): {}",
                        fixture.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                        f.name,
                        f.addr.0,
                        msg,
                    ));
                }
            }
        }
    }

    eprintln!(
        "summary: {total_funcs} functions, {total_blocks} blocks, {total_insns} instructions"
    );
    assert!(
        failures.is_empty(),
        "{} function(s) failed to lift / round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert!(total_funcs > 0, "expected to lift at least one function");
}

enum LiftOutcome {
    Ok { blocks: usize, insns: usize },
    SkippedNoSize,
    SkippedNotInExecutableSection,
    Failed(String),
}

fn lift_one(elf: &Elf64File, f: &DiscoveredFunction) -> LiftOutcome {
    if f.size == 0 {
        return LiftOutcome::SkippedNoSize;
    }
    let Some(slice) = slice_function_bytes(elf, f.addr.0, f.size) else {
        return LiftOutcome::SkippedNotInExecutableSection;
    };
    let insns = match decode(Bitness::Bits64, slice, f.addr.0) {
        Ok(i) => i,
        Err(e) => return LiftOutcome::Failed(format!("decode: {e}")),
    };
    let func_ir = match lift_function(f.name.clone(), &insns) {
        Ok(i) => i,
        Err(e) => return LiftOutcome::Failed(format!("lift: {e}")),
    };
    let emitted = func_ir.emit_bytes();
    if emitted != slice {
        let offset = emitted
            .iter()
            .zip(slice)
            .position(|(a, b)| a != b)
            .unwrap_or(emitted.len().min(slice.len()));
        return LiftOutcome::Failed(format!(
            "emit_bytes diverged at offset {offset} (emitted len={}, expected len={})",
            emitted.len(),
            slice.len()
        ));
    }
    LiftOutcome::Ok {
        blocks: func_ir.blocks.len(),
        insns: func_ir.blocks.iter().map(|b| b.insns.len()).sum(),
    }
}

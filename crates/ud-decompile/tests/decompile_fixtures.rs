//! Decompile each x86_64 ELF fixture to `.ud` and check the output's
//! shape against expected facts (function names present, deterministic
//! across runs, asm-line count matches the lifted instruction count).

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_format_elf::{is_elf64_le, Elf64File, EM_X86_64};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn decompile_fixture(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if !is_elf64_le(&bytes) {
        return None;
    }
    let elf = Elf64File::parse(&bytes).ok()?;
    if elf.ehdr.e_machine != EM_X86_64 {
        return None;
    }
    Some(ud_decompile::decompile(&elf).expect("decompile"))
}

#[test]
fn hello_fixture_decompiles_with_known_functions() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(out) = decompile_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };

    assert!(out.starts_with("@module {"), "missing module header");
    assert!(out.contains("arch:    \"x86_64\""), "missing arch line");
    assert!(out.contains("\nfn main() {"), "main not emitted");
    assert!(out.contains("\nfn _start() {"), "_start not emitted");
    assert!(
        out.contains("// note: `_init`"),
        "expected an explanatory note for _init (no recorded size)"
    );
}

#[test]
fn output_is_deterministic() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(a) = decompile_fixture(&path) else {
        return;
    };
    let b = decompile_fixture(&path).unwrap();
    assert_eq!(a, b, "decompile is non-deterministic");
}

#[test]
fn sqrt_fixture_emits_user_functions() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(out) = decompile_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };
    for required in &["fn main() {", "fn do_fac() {", "fn test_sqrt() {"] {
        assert!(
            out.contains(required),
            "missing `{required}` in decompile output"
        );
    }
}

/// The number of `@asm(` lines must equal the total instruction count
/// the lifter saw, across all emitted functions. This catches silent
/// drops if the emitter ever forgets a block or instruction.
#[test]
fn asm_line_count_matches_lifted_instruction_count() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(bytes) = std::fs::read(&path).ok() else {
        return;
    };
    let elf = Elf64File::parse(&bytes).expect("parse");
    let out = ud_decompile::decompile(&elf).expect("decompile");

    let asm_lines = out
        .lines()
        .filter(|l| l.trim_start().starts_with("@asm("))
        .count();

    // Re-lift via the analysis + arch-x86 path and total the
    // instruction count. The decompile output must match.
    let map = ud_analysis::discover_functions(&elf).expect("discover");
    let mut expected = 0usize;
    for f in map.iter() {
        if f.size == 0 {
            continue;
        }
        let Some(slice) = slice_function_bytes(&elf, f.addr.0, f.size) else {
            continue;
        };
        let insns =
            ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, slice, f.addr.0).expect("decode");
        expected += insns.len();
    }

    assert_eq!(
        asm_lines, expected,
        "@asm line count {asm_lines} differs from lifted instruction total {expected}"
    );
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

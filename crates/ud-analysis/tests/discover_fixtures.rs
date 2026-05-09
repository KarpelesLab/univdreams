//! Run function discovery on the workspace's binary fixtures and assert
//! that known names show up at expected addresses.
//!
//! The fixtures are not stripped, so the symbol-table source alone
//! should give us complete coverage. When `.eh_frame` and prologue
//! signals come online, the merged map should still contain at least
//! these names — additional sources may *add* coverage but should not
//! lose it.

use std::path::{Path, PathBuf};

use ud_analysis::{discover_from_symbol_tables, FunctionMap};
use ud_format_elf::{is_elf64_le, Elf64File, EM_X86_64};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn discover_fixture(path: &Path) -> Option<FunctionMap> {
    let bytes = std::fs::read(path).ok()?;
    if !is_elf64_le(&bytes) {
        return None;
    }
    let elf = Elf64File::parse(&bytes).ok()?;
    if elf.ehdr.e_machine != EM_X86_64 {
        return None;
    }
    let funcs = discover_from_symbol_tables(&elf).expect("symbol-table parse");
    let mut map = FunctionMap::new();
    for f in funcs {
        map.insert(f);
    }
    Some(map)
}

fn names(map: &FunctionMap) -> Vec<&str> {
    map.iter().map(|f| f.name.as_str()).collect()
}

#[test]
fn hello_fixture_has_main_and_start() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(map) = discover_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };
    let names = names(&map);
    eprintln!("hello functions: {names:?}");
    for required in &["_start", "main", "_init", "_fini"] {
        assert!(
            names.contains(required),
            "expected `{required}` in discovered functions, got {names:?}"
        );
    }

    // main should have a non-zero size and an address in the .text range.
    let main = map.iter().find(|f| f.name == "main").unwrap();
    assert!(main.size > 0, "main should have a recorded size");
    assert!(
        main.addr.0 >= 0x1000,
        "main address looks wrong: {}",
        main.addr
    );
}

#[test]
fn sqrt_fixture_has_user_functions() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(map) = discover_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };
    let names = names(&map);
    eprintln!("sqrt functions: {names:?}");
    for required in &["_start", "main", "do_fac", "test_sqrt"] {
        assert!(
            names.contains(required),
            "expected `{required}` in discovered functions, got {names:?}"
        );
    }
}

#[test]
fn imports_are_filtered_out() {
    // Functions like `printf` and `puts` are dynamic imports — they appear
    // in `.dynsym` but with `st_shndx = SHN_UNDEF` and `st_value = 0`.
    // Our discovery filter must reject them; including them would invent
    // function bodies for code that lives in libc, not in this binary.
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(map) = discover_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };
    for f in map.iter() {
        assert!(
            f.addr.0 != 0,
            "discovered function `{}` has address 0 — undefined import slipped through",
            f.name
        );
    }
}

//! Run function discovery on the workspace's binary fixtures and
//! assert that:
//!
//! * Known names from the symbol table show up at expected addresses.
//! * Imports (`U printf`, etc.) do not leak through.
//! * `.eh_frame` fills in sizes that the symbol table left at zero
//!   (typically `_init` / `_fini`).
//! * Functions covered by both sources record both in their provenance.

use std::path::{Path, PathBuf};

use ud_analysis::{discover_functions, FunctionMap, FunctionSource};
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
    Some(discover_functions(&elf).expect("discover"))
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

/// `.eh_frame` should add coverage that the symbol table doesn't
/// provide. Concretely on these fixtures: PLT trampolines have FDEs
/// (so stack unwinding can step through them) but no symbol-table
/// entry, so they only enter the map via the `.eh_frame` source.
///
/// gcc 13 at `-O0` does *not* emit FDEs for `_init` / `_fini`; those
/// are hand-written CRT assembly with no exception-handling needs. We
/// don't assert anything about them — covering them needs a future
/// prologue-pattern source.
#[test]
fn eh_frame_adds_coverage_beyond_symbol_table() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(map) = discover_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };

    let only_eh_frame: Vec<&str> = map
        .iter()
        .filter(|f| f.sources == [FunctionSource::EhFrame])
        .map(|f| f.name.as_str())
        .collect();

    assert!(
        !only_eh_frame.is_empty(),
        "expected at least one function discovered exclusively from .eh_frame; got none"
    );

    // Every PLT trampoline lives below 0x1100 in our PIE fixtures and
    // is named `sub_<addr>` because .eh_frame doesn't carry names. They
    // should all be eh_frame-only.
    for name in &only_eh_frame {
        assert!(
            name.starts_with("sub_"),
            "expected eh-frame-only function to use the default sub_<addr> naming, got `{name}`"
        );
    }
}

/// CRT helpers (`deregister_tm_clones`, `register_tm_clones`,
/// `__do_global_dtors_aux`, `frame_dummy`) are inserted by GCC's
/// linker into `.text` but are absent from `.symtab` and `.eh_frame`
/// for our fixtures. Signature matching has to be the source.
#[test]
fn crt_helpers_named_via_signatures() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(map) = discover_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };

    let by_source: std::collections::HashMap<&str, &Vec<FunctionSource>> =
        map.iter().map(|f| (f.name.as_str(), &f.sources)).collect();

    for required in &[
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "frame_dummy",
    ] {
        let sources = by_source
            .get(required)
            .unwrap_or_else(|| panic!("expected `{required}` discovered"));
        assert!(
            sources.contains(&FunctionSource::Signature),
            "expected `{required}` to be tagged Signature, got {sources:?}"
        );
    }
}

/// Functions covered by both .eh_frame and the symbol table should
/// record both sources, with the symbol-table name winning.
#[test]
fn merged_functions_record_both_sources() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(map) = discover_fixture(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };
    let main = map.iter().find(|f| f.name == "main").unwrap();
    assert!(
        main.sources.contains(&FunctionSource::SymTab)
            && main.sources.contains(&FunctionSource::EhFrame),
        "expected `main` to record both SymTab and EhFrame, got {:?}",
        main.sources
    );
}

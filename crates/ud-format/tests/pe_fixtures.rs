//! Direct round-trip tests of the PE reader/writer against the
//! workspace's binary fixtures under `testdata/`.

use std::path::{Path, PathBuf};

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
fn pe_fixtures_roundtrip_byte_identical() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} is missing; nothing to test", testdata.display());
        return;
    }

    let fixtures = collect_fixtures(&testdata);
    let mut covered = 0;
    let mut failures: Vec<(PathBuf, String)> = Vec::new();

    for fixture in &fixtures {
        let bytes = std::fs::read(fixture).expect("read fixture");
        // NE (16-bit Windows) binaries also carry an `MZ` header, which
        // is all `is_pe` checks — skip them here; they have their own
        // reader and round-trip path.
        if ud_format::ne::is_ne(&bytes) {
            continue;
        }
        if !ud_format::pe::is_pe(&bytes) {
            continue;
        }

        match ud_format::pe::PeFile::parse(&bytes) {
            Ok(file) => {
                let rebuilt = file.write_to_vec();
                if rebuilt == bytes {
                    eprintln!(
                        "ok  {}  ({} sections, machine 0x{:04x})",
                        fixture.display(),
                        file.sections.len(),
                        file.coff.machine
                    );
                    covered += 1;
                } else {
                    let offset = rebuilt
                        .iter()
                        .zip(&bytes)
                        .position(|(a, b)| a != b)
                        .unwrap_or(rebuilt.len().min(bytes.len()));
                    failures.push((
                        fixture.clone(),
                        format!(
                            "byte mismatch at offset {offset} \
                             (expected len={}, got len={})",
                            bytes.len(),
                            rebuilt.len()
                        ),
                    ));
                }
            }
            Err(e) => {
                failures.push((fixture.clone(), format!("parse failed: {e}")));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} PE fixture(s) failed:\n{}",
        failures.len(),
        failures
            .iter()
            .map(|(p, e)| format!("  {}: {}", p.display(), e))
            .collect::<Vec<_>>()
            .join("\n")
    );

    if covered == 0 {
        eprintln!("note: no PE fixtures found under {}", testdata.display());
    }
}

#[test]
fn coff_symbols_parse_from_mingw_fixture() {
    let path = workspace_root().join("testdata/sqrt-mingw15-O0.exe");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };
    let pe = ud_format::pe::PeFile::parse(&bytes).expect("parse");
    let symbols = pe.coff_symbols();
    assert!(
        !symbols.is_empty(),
        "fixture is mingw-with-symbols; expected non-empty COFF symbol table"
    );

    // mingw's CRT defines `main` directly; the expected names are
    // `do_fac`, `test_sqrt`, and `main`. Look for at least one of
    // them as a sanity check.
    let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
    let user_funcs = ["_main", "_do_fac", "_test_sqrt"];
    assert!(
        user_funcs.iter().any(|n| names.contains(n)),
        "expected at least one of {user_funcs:?} in COFF symbols, \
         got {} names — first few: {:?}",
        names.len(),
        &names[..names.len().min(20)]
    );
}

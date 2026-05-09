//! Integration test: round-trip every fixture under `testdata/` and assert
//! byte-equality. Fixtures are not committed (the `testdata/` directory is
//! gitignored), so the test gracefully no-ops when the directory is empty
//! or absent. This means a fresh checkout passes; a checkout with fixtures
//! exercises them.
//!
//! As Phase 1+ land, the round-trip body in `ud-cli` becomes real and this
//! same test starts catching regressions automatically — no per-fixture
//! plumbing needed.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at the crate. Walk up to the workspace root.
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
fn roundtrip_all_fixtures() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} is missing; nothing to test", testdata.display());
        return;
    }

    let fixtures = collect_fixtures(&testdata);
    if fixtures.is_empty() {
        eprintln!(
            "note: no fixtures under {}; nothing to test",
            testdata.display()
        );
        return;
    }

    let tmp = std::env::temp_dir().join("ud-cli-rt-fixtures");
    std::fs::create_dir_all(&tmp).expect("create temp dir for round-trip outputs");

    let mut failures = Vec::new();
    for fixture in &fixtures {
        let name = fixture
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("anon");
        let out = tmp.join(format!("{name}.rebuilt"));
        match ud_cli::roundtrip(fixture, &out) {
            Ok(()) => eprintln!("ok    {}", fixture.display()),
            Err(e) => {
                eprintln!("FAIL  {}: {}", fixture.display(), e);
                failures.push((fixture.clone(), e.to_string()));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "round-trip failed for {} fixture(s):\n{}",
        failures.len(),
        failures
            .iter()
            .map(|(p, e)| format!("  {}: {}", p.display(), e))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

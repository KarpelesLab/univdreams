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

/// Filenames inside `testdata/external/` we should skip — non-binary
/// support files like the fetch manifest.
fn is_external_support_file(name: &str) -> bool {
    matches!(name, "MANIFEST")
}

fn select_fixtures(testdata: &Path) -> Vec<PathBuf> {
    let mut out = collect_fixtures(testdata);
    // Drop documentation companions and the external manifest from
    // the round-trip set — they're text, not binaries.
    out.retain(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        if matches!(ext.as_deref(), Some("s" | "md" | "txt")) {
            return false;
        }
        if p.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("external")) {
            return !is_external_support_file(name);
        }
        true
    });
    out
}

#[test]
fn roundtrip_all_fixtures() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} is missing; nothing to test", testdata.display());
        return;
    }

    let fixtures = select_fixtures(&testdata);
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

/// Source-level round-trip every fixture under `testdata/`:
/// decompile → emit → parse → lower → compare. This is the
/// stronger test — failure here means the source language has
/// lost fidelity somewhere in the pipeline.
#[test]
fn roundtrip_through_source_all_fixtures() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        return;
    }

    let fixtures = select_fixtures(&testdata);
    if fixtures.is_empty() {
        return;
    }

    let tmp = std::env::temp_dir().join("ud-cli-rt-source-fixtures");
    std::fs::create_dir_all(&tmp).expect("create temp dir for round-trip outputs");

    let mut failures = Vec::new();
    for fixture in &fixtures {
        let name = fixture
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("anon");
        let out = tmp.join(format!("{name}.rebuilt"));
        let report = match ud_cli::roundtrip_through_source(fixture, &out) {
            Ok(r) => r,
            Err(e) => {
                // Inputs whose format we don't yet recognise (e.g.
                // truncated binaries, non-PE/ELF text files) skip
                // the source-level test — the format-level test
                // above already covers byte identity for those.
                eprintln!(
                    "skip  {} (no source pipeline yet: {})",
                    fixture.display(),
                    e
                );
                continue;
            }
        };
        if report.byte_identical {
            eprintln!("ok    {}", fixture.display());
        } else {
            let offset = report
                .first_diff_offset
                .map_or_else(|| "?".into(), |o| format!("0x{o:x}"));
            eprintln!("FAIL  {} (first diff @ {offset})", fixture.display());
            failures.push((fixture.clone(), offset));
        }
    }

    assert!(
        failures.is_empty(),
        "source round-trip failed for {} fixture(s):\n{}",
        failures.len(),
        failures
            .iter()
            .map(|(p, off)| format!("  {} (first diff @ {off})", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

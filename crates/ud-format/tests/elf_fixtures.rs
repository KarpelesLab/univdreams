//! Direct round-trip tests of the ELF64 reader/writer against the
//! workspace's binary fixtures under `testdata/`.
//!
//! Unlike the integration test in `ud-cli`, this one always goes through
//! `Elf64File::parse` + `write_to_vec` — no fallback path. A silent parse
//! failure is therefore a hard error here, while in `ud-cli` the
//! byte-copy fallback would mask it.

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
fn elf64_fixtures_roundtrip_byte_identical() {
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
        if !ud_format::elf::is_elf64_le(&bytes) {
            eprintln!("skip  {} (not ELF64-LE)", fixture.display());
            continue;
        }

        match ud_format::elf::Elf64File::parse(&bytes) {
            Ok(file) => {
                let rebuilt = file.write_to_vec();
                if rebuilt == bytes {
                    eprintln!("ok    {}", fixture.display());
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
        "{} ELF64 fixture(s) failed:\n{}",
        failures.len(),
        failures
            .iter()
            .map(|(p, e)| format!("  {}: {}", p.display(), e))
            .collect::<Vec<_>>()
            .join("\n")
    );

    if covered == 0 {
        eprintln!(
            "note: no ELF64-LE fixtures found under {}",
            testdata.display()
        );
    }
}

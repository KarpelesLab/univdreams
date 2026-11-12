//! Embeds Ghidra's SLEIGH specifications (`sleigh-specs/`) when the
//! `sleigh` feature is on: generates `$OUT_DIR/sleigh_specs.rs`, a
//! `&[(path, contents)]` table of every file under it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("sleigh-specs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("sleigh_specs.rs");
    println!("cargo:rerun-if-changed=sleigh-specs");
    let mut files = Vec::new();
    if std::env::var_os("CARGO_FEATURE_SLEIGH").is_some() {
        collect(&root, &root, &mut files);
    }
    files.sort();
    let mut code = String::from("&[\n");
    for (rel, abs) in &files {
        writeln!(code, "    ({rel:?}, include_str!({abs:?})),").unwrap();
    }
    code += "]\n";
    std::fs::write(out, code).unwrap();
}

/// Spec files under `dir`, as (path relative to `root` with `/`
/// separators, absolute path).
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, files);
            continue;
        }
        let spec = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "slaspec" | "sinc" | "pspec" | "ldefs"));
        if spec {
            let rel = path.strip_prefix(root).unwrap();
            let rel: Vec<_> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect();
            files.push((rel.join("/"), path.display().to_string()));
        }
    }
}

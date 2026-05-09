//! End-to-end source-language test: take each x86_64 ELF fixture,
//! decompile it through `ud-decompile`, parse the resulting `.ud` text
//! through `ud-compile`. The parser must accept everything the
//! decompiler emits — anything else means the two are out of sync.

use std::path::{Path, PathBuf};

use ud_ast::{Item, Stmt};
use ud_compile::parse;
use ud_format_elf::{is_elf64_le, Elf64File, EM_X86_64};

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
fn parser_accepts_every_decompile_output() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} missing; skipping", testdata.display());
        return;
    }

    let mut covered = 0;
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

        let source = match ud_decompile::decompile_to_text(&elf) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{} decompile: {e}", fixture.display()));
                continue;
            }
        };

        match parse(&source) {
            Ok(ast) => {
                eprintln!(
                    "ok    {} ({} module fields, {} items)",
                    fixture.display(),
                    ast.module.fields.len(),
                    ast.items.len(),
                );
                covered += 1;

                // Sanity: every Item::Function has at least one Stmt::Asm or
                // a comment. Empty bodies would mean the emitter or parser
                // dropped instructions silently.
                for item in &ast.items {
                    if let Item::Function(f) = item {
                        let has_content = f
                            .body
                            .iter()
                            .any(|s| matches!(s, Stmt::Asm { .. } | Stmt::Comment(_)));
                        assert!(
                            has_content,
                            "function `{}` parsed with an empty body",
                            f.name
                        );
                    }
                }
            }
            Err(e) => {
                failures.push(format!(
                    "{}: parse failed: {e}\n--- source excerpt ---\n{}",
                    fixture.display(),
                    source.lines().take(20).collect::<Vec<_>>().join("\n"),
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "parser rejected {} decompile output(s):\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(covered > 0, "expected to test at least one fixture");
}

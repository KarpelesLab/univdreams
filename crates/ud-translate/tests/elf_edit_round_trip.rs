//! Edit-then-lower for ELF: insert a `nop` into a function and
//! confirm `lower_to_elf` cascades the section-size delta through
//! shdrs, phdrs, padding, and the ELF header so the rebuilt
//! binary parses cleanly and the section header table is
//! self-consistent.
//!
//! This is the smoke test for the auto-resize cascade in
//! [`ud_translate::compile::build_elf64`]. Unedited input has zero deltas
//! and the existing whole-binary round-trip test covers that
//! path; here we deliberately grow `.text` by 1 byte and
//! re-parse the result.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_ast::{Item, Stmt};
use ud_translate::compile::{lower_to_elf, parse};
use ud_format::elf::Elf64File;

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

/// Insert a nop into the first eligible function in `.text` and
/// drop `addr` on every later function in the same section. Same
/// shape as `edit_friendly_layout.rs`'s picker.
fn pick_extendable_function(ast_items: &[Item]) -> Option<(usize, usize)> {
    for (sec_idx, item) in ast_items.iter().enumerate() {
        let Item::Section { name, items, .. } = item else {
            continue;
        };
        if name != ".text" {
            continue;
        }
        let last_raw_plus_one = items
            .iter()
            .rposition(|it| matches!(it, Item::Raw { .. }))
            .map_or(0, |i| i + 1);
        for (fn_idx, child) in items.iter().enumerate().skip(last_raw_plus_one) {
            if let Item::Function(f) = child {
                if f.body.iter().any(|s| {
                    matches!(
                        s,
                        Stmt::IfBranch { .. } | Stmt::Loop { .. } | Stmt::Switch { .. }
                    )
                }) {
                    continue;
                }
                let has_following_fn = items
                    .iter()
                    .skip(fn_idx + 1)
                    .any(|it| matches!(it, Item::Function(_)));
                if has_following_fn {
                    return Some((sec_idx, fn_idx));
                }
            }
        }
    }
    None
}

#[test]
fn nop_insertion_lowers_to_a_parseable_elf() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("note: {} missing; skipping", path.display());
        return;
    };
    let elf = Elf64File::parse(&bytes).expect("parse fixture");
    let text = ud_translate::decompile::decompile_to_text(&elf).expect("decompile");
    let mut ast = parse(&text).expect("parse .ud");

    let Some((sec_idx, fn_idx)) = pick_extendable_function(&ast.items) else {
        panic!("no extendable function found in .text");
    };

    {
        let Item::Section { items, .. } = &mut ast.items[sec_idx] else {
            unreachable!();
        };
        let Item::Function(f) = &mut items[fn_idx] else {
            unreachable!();
        };
        let insert_at = f.body.len().saturating_sub(1);
        f.body.insert(insert_at, Stmt::asm("nop", vec![0x90]));
        for it in items.iter_mut().skip(fn_idx + 1) {
            if let Item::Function(f) = it {
                f.addr = None;
            }
        }
    }

    let rebuilt = lower_to_elf(&ast).expect("lower_to_elf after edit");
    assert!(
        rebuilt.len() >= bytes.len(),
        "rebuilt {} should be at least the original size {}",
        rebuilt.len(),
        bytes.len(),
    );
    // The most important contract: the resulting bytes are still
    // a valid ELF that parses back through ud-format-elf without
    // overlap or out-of-range errors.
    Elf64File::parse(&rebuilt).expect("rebuilt ELF should parse");
}

#[test]
fn unedited_lower_to_elf_is_still_byte_identical() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("note: {} missing; skipping", path.display());
        return;
    };
    let elf = Elf64File::parse(&bytes).expect("parse fixture");
    let text = ud_translate::decompile::decompile_to_text(&elf).expect("decompile");
    let ast = parse(&text).expect("parse .ud");
    let rebuilt = lower_to_elf(&ast).expect("lower_to_elf without edits");
    assert_eq!(
        rebuilt, bytes,
        "auto-resize cascade must be a no-op for unedited input"
    );
}

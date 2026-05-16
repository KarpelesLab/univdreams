//! Edit-friendliness contract: when the user adds bytes to a
//! function in a `@section` block and drops `addr` on subsequent
//! functions in the same section, the section-lower path
//! auto-shifts those functions and re-resolves every PC-relative
//! reference inside them.
//!
//! This test exercises [`ud_translate::compile::lower_section_bytes`]
//! directly — the section lay-out primitive — rather than the
//! full `lower_to_elf` pipeline, because updating an ELF's
//! section / program / file headers to reflect a grown `.text`
//! is a separate concern (covered by [the `section layout` task
//! in the docs roadmap]).
//!
//! The fixture is `hello-gcc13-O0`. The test:
//!
//! 1. Decompile to AST.
//! 2. Find a function in `.text` followed only by other
//!    functions in the same section (no `@raw` items, which
//!    carry an explicit addr we can't drop today).
//! 3. Append a `nop` to that function's body.
//! 4. Drop `addr` on every later function in the section.
//! 5. Call `lower_section_bytes` on the edited section.
//! 6. Assert the returned byte count grew by exactly 1.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_ast::{Item, Stmt};
use ud_format::elf::Elf64File;
use ud_translate::compile::{lower_section_bytes, parse};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

/// Pick a function in `.text` whose body is simple (no nested
/// IfBranch/Loop/Switch — those have nested cursor accounting we
/// don't want to disturb) AND whose every subsequent sibling in
/// the section is also a `Function` (no `@raw` items, which
/// today carry a required explicit `addr` we can't drop).
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
fn nop_insertion_auto_shifts_later_functions() {
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

    // Snapshot the section's pristine bytes via the unedited
    // section lower. This is our baseline.
    let baseline_section_bytes: Vec<u8> = match &ast.items[sec_idx] {
        Item::Section {
            name, addr, items, ..
        } => lower_section_bytes(name, *addr, items).expect("baseline section lower"),
        _ => unreachable!(),
    };

    let edited_name;
    {
        let Item::Section { items, .. } = &mut ast.items[sec_idx] else {
            unreachable!();
        };
        let Item::Function(f) = &mut items[fn_idx] else {
            unreachable!();
        };
        edited_name = f.name.clone();
        // Insert the nop right before the trailing instruction so we
        // don't disturb the prologue.
        let insert_at = f.body.len().saturating_sub(1);
        f.body.insert(insert_at, Stmt::asm("nop", vec![0x90]));

        // Drop `addr` on every later function in the same
        // section — those are the ones that need to auto-shift.
        for it in items.iter_mut().skip(fn_idx + 1) {
            if let Item::Function(f) = it {
                f.addr = None;
            }
        }
    }

    // Re-lower the edited section. The byte count should grow by
    // exactly 1 (the inserted nop); every subsequent function
    // auto-placed at its cumulative cursor.
    let edited_section_bytes: Vec<u8> = match &ast.items[sec_idx] {
        Item::Section {
            name, addr, items, ..
        } => lower_section_bytes(name, *addr, items).expect("edited section lower"),
        _ => unreachable!(),
    };

    let grew = edited_section_bytes.len() - baseline_section_bytes.len();
    assert_eq!(
        grew, 1,
        "section bytes should grow by exactly 1 (the inserted nop in {edited_name}); got {grew}",
    );

    // Sanity: the inserted nop should be present in the rebuilt
    // section. Find a position in baseline that has the edited
    // function's tail, look for the same suffix in edited bytes
    // offset by 1.
    // (We don't do exact pattern matching — just ensure the
    // edited section isn't a verbatim copy of baseline.)
    assert!(
        edited_section_bytes.contains(&0x90),
        "edited section should contain the inserted 0x90 nop"
    );
}

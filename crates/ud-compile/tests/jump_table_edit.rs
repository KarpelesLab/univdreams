//! End-to-end contract for `@jump_table` editability:
//!
//! 1. Build a UdFile that places a function and an `@jump_table`
//!    in a section.
//! 2. Lower the section to bytes.
//! 3. Edit one case target.
//! 4. Re-lower — only the bytes covering that case slot change,
//!    by exactly the displacement the new target implies.
//!
//! The supported dispatch encodings (`gcc_pie_rel32`,
//! `msvc_va32`) both use 4-byte entries, so editing case `k`
//! touches bytes `[table_addr + 4*k, table_addr + 4*(k+1))`.

use ud_ast::{Item, JumpTableEntry};
use ud_compile::lower_section_bytes;

#[test]
fn editing_a_case_target_changes_only_that_slot_gcc_pie() {
    let items_before = vec![Item::JumpTable {
        addr: 0x2000,
        dispatch: "gcc_pie_rel32".into(),
        entries: vec![
            JumpTableEntry {
                case: 0,
                target: 0x117a,
            },
            JumpTableEntry {
                case: 1,
                target: 0x1183,
            },
            JumpTableEntry {
                case: 2,
                target: 0x118c,
            },
        ],
    }];
    let before = lower_section_bytes(".rodata", 0x2000, &items_before).unwrap();
    assert_eq!(before.len(), 12);

    let items_after = vec![Item::JumpTable {
        addr: 0x2000,
        dispatch: "gcc_pie_rel32".into(),
        entries: vec![
            JumpTableEntry {
                case: 0,
                target: 0x117a,
            },
            // case 1 retargeted from 0x1183 to 0x1190.
            JumpTableEntry {
                case: 1,
                target: 0x1190,
            },
            JumpTableEntry {
                case: 2,
                target: 0x118c,
            },
        ],
    }];
    let after = lower_section_bytes(".rodata", 0x2000, &items_after).unwrap();

    // Cases 0 and 2 unchanged; case 1 (bytes 4..8) differs.
    assert_eq!(&before[..4], &after[..4]);
    assert_ne!(&before[4..8], &after[4..8]);
    assert_eq!(&before[8..], &after[8..]);

    // Concretely, case 1 → 0x1190 with table_base 0x2000 gives
    // offset 0xfffff190 = -0xe70, encoded as 0x90, 0xf1, 0xff, 0xff.
    assert_eq!(&after[4..8], &[0x90, 0xf1, 0xff, 0xff]);
}

#[test]
fn editing_a_case_target_changes_only_that_slot_msvc() {
    let items_before = vec![Item::JumpTable {
        addr: 0x40_2000,
        dispatch: "msvc_va32".into(),
        entries: vec![
            JumpTableEntry {
                case: 0,
                target: 0x40_117a,
            },
            JumpTableEntry {
                case: 1,
                target: 0x40_1183,
            },
        ],
    }];
    let before = lower_section_bytes(".rdata", 0x40_2000, &items_before).unwrap();

    let items_after = vec![Item::JumpTable {
        addr: 0x40_2000,
        dispatch: "msvc_va32".into(),
        entries: vec![
            JumpTableEntry {
                case: 0,
                target: 0x40_117a,
            },
            JumpTableEntry {
                case: 1,
                target: 0x40_2200, // moved
            },
        ],
    }];
    let after = lower_section_bytes(".rdata", 0x40_2000, &items_after).unwrap();

    assert_eq!(&before[..4], &after[..4]);
    assert_eq!(&after[4..8], &[0x00, 0x22, 0x40, 0x00]);
}

//! `decompile_verified` compiles its output back before handing it out:
//! a function whose source wouldn't rebuild its bytes is kept as `@raw`.

use std::path::PathBuf;

use univdreams::format::elf::Elf64File;
use univdreams::translate::compile::{lower_to_elf, parse};
use univdreams::translate::decompile::{Verified, decompile_verified};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "testdata", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn verified(bytes: &[u8]) -> Verified {
    let elf = Elf64File::parse(bytes).expect("parse ELF");
    let verified = decompile_verified(&elf, bytes).expect("decompile");
    let text = univdreams::ast::emit(&verified.ast);
    let rebuilt = lower_to_elf(&parse(&text).expect("parse")).expect("lower");
    assert!(rebuilt == bytes, "differs after round-trip");
    verified
}

#[test]
fn fixtures_decompile_whole() {
    for name in [
        "hello-gcc13-O0",
        "loops-gcc14-O0",
        "loops-gcc14-O0-m32",
        "sqrt-gcc13-O0",
        "sqrt-gcc13-O0-m32",
        "sqrt-gcc14-O2",
        "switch-gcc14-O0",
        "sqrt-gcc14-O0-aarch64",
    ] {
        let v = verified(&fixture(name));
        assert!(v.opaque.is_none(), "{name}: {:?}", v.opaque);
        assert!(v.raw_functions.is_empty(), "{name}: {:?}", v.raw_functions);
    }
}

#[test]
fn undecodable_function_is_kept_as_bytes() {
    // `test_sqrt` starts at 0x1189; 0x06 isn't an x86-64 instruction.
    let mut bytes = fixture("sqrt-gcc13-O0");
    bytes[0x1189] = 0x06;
    let v = verified(&bytes);
    assert!(v.opaque.is_none(), "{:?}", v.opaque);
    let text = univdreams::ast::emit(&v.ast);
    assert!(
        text.contains("`test_sqrt` at 0x1189 kept as bytes"),
        "{text}"
    );
    assert!(text.contains("fn do_fac("), "other functions still decode");
}

#[test]
fn object_with_same_named_sections() {
    // g++ -O0 of two template instantiations: two COMDAT `.group`
    // sections, both named `.group`.
    let v = verified(&fixture("comdat-groups-gcc-O0.o"));
    assert!(v.opaque.is_none(), "{:?}", v.opaque);
}

#[cfg(feature = "sleigh")]
#[test]
fn arm_mapping_symbols_pick_thumb_arm_and_data() {
    // arm-none-eabi-gcc -O1: a Thumb function, an ARM one and a
    // literal pool, told apart by `$t`, `$a` and `$d`.
    let v = verified(&fixture("arm-thumb-interwork-gcc-O1.o"));
    assert!(v.opaque.is_none(), "{:?}", v.opaque);
    let text = univdreams::ast::emit(&v.ast);
    // Thumb `bx lr`, ARM `bx lr`, and the pool kept as data.
    assert!(text.contains("@asm(\"bx lr\", [0x70, 0x47])"), "{text}");
    assert!(
        text.contains("@asm(\"bx lr\", [0x1e, 0xff, 0x2f, 0xe1])"),
        "{text}"
    );
    assert!(
        text.contains("@asm(\".byte 0x68, 0x03, 0x9d, 0x36\""),
        "{text}"
    );
}

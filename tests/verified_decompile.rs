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

#[test]
fn pe_fixtures_decompile_whole() {
    for name in [
        "loops-mingw15-O0-i386.exe",
        "loops-mingw15-O0-x64.exe",
        "sqrt-mingw15-O0-x64.exe",
        "sqrt-mingw15-O0.exe",
    ] {
        let bytes = fixture(name);
        let pe = univdreams::format::pe::PeFile::parse(&bytes).expect("parse PE");
        let v = univdreams::translate::decompile::decompile_pe_verified(&pe);
        assert!(v.opaque.is_none(), "{name}: {:?}", v.opaque);
        let text = univdreams::ast::emit(&v.ast);
        let rebuilt = univdreams::translate::compile::lower_to_pe(&parse(&text).expect("parse"))
            .expect("lower");
        assert!(rebuilt == bytes, "{name}: differs after round-trip");
        assert!(text.contains("fn "), "{name}: no function lifted");
    }
}

#[test]
fn pe_function_that_does_not_compile_back_is_kept_as_bytes() {
    // A function whose bytes the x86 codec can't re-encode: the entry
    // point's first instruction patched to a `call rel32` whose target
    // wraps around the 32-bit address space.
    let mut bytes = fixture("sqrt-mingw15-O0.exe");
    let pe = univdreams::format::pe::PeFile::parse(&bytes).expect("parse PE");
    let entry = pe
        .rva_to_file_offset(pe.address_of_entry_point)
        .expect("entry offset");
    bytes[entry..entry + 5].copy_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x80]);
    let pe = univdreams::format::pe::PeFile::parse(&bytes).expect("parse PE");
    let v = univdreams::translate::decompile::decompile_pe_verified(&pe);
    assert!(v.opaque.is_none(), "{:?}", v.opaque);
    assert!(!v.raw_functions.is_empty(), "the patched function lifted");
    let text = univdreams::ast::emit(&v.ast);
    let rebuilt =
        univdreams::translate::compile::lower_to_pe(&parse(&text).expect("parse")).expect("lower");
    assert!(rebuilt == bytes, "differs after round-trip");
}

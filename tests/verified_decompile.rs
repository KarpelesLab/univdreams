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

//! Inputs of architectures without a decoder still round-trip byte for
//! byte: ELF keeps its structure with code as `@raw`, and unrecognised
//! headerless bytes become an opaque raw image.

use std::path::PathBuf;

use univdreams::format::elf::Elf64File;
use univdreams::translate::compile::{lower_to_elf, lower_to_raw, parse};
use univdreams::translate::decompile::{decompile_raw_opaque_to_text, decompile_to_text};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "testdata", name]
        .iter()
        .collect();
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `bytes` with its ELF `e_machine` (offset 18, little-endian) replaced.
fn with_machine(mut bytes: Vec<u8>, machine: u16) -> Vec<u8> {
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes
}

fn elf_round_trip(bytes: &[u8]) -> String {
    let elf = Elf64File::parse(bytes).expect("parse ELF");
    let text = decompile_to_text(&elf).expect("decompile");
    let ast = parse(&text).unwrap_or_else(|e| panic!("parse: {e}"));
    let rebuilt = lower_to_elf(&ast).unwrap_or_else(|e| panic!("lower: {e}"));
    assert!(rebuilt == bytes, "differs after round-trip");
    text
}

#[test]
fn elf_of_an_undecoded_architecture() {
    // Real ELF64 and ELF32 layouts, relabelled as CPUs with no decoder.
    for (name, machine, arch) in [
        ("sqrt-gcc13-O0", 164, "hexagon"),
        ("sqrt-gcc13-O0-m32", 40, "arm"),
        ("loops-gcc14-O0-m32", 8, "mips"),
    ] {
        let text = elf_round_trip(&with_machine(fixture(name), machine));
        assert!(text.contains(&format!("arch: \"{arch}\"")), "{name}");
        assert!(!text.contains("@asm("), "{name}: code should stay @raw");
    }
}

#[test]
fn elf_of_an_unnumbered_architecture() {
    let text = elf_round_trip(&with_machine(fixture("sqrt-gcc13-O0"), 0x7ffe));
    assert!(text.contains("arch: \"unknown\""));
}

#[test]
fn headerless_bytes() {
    // Larger than one @raw block, with a short last block.
    let bytes: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + i / 13).to_le_bytes()[0]).collect();
    for (arch, load) in [("unknown", 0), ("hexagon", 0x8000_0000)] {
        let text = decompile_raw_opaque_to_text(&bytes, arch, load);
        let ast = parse(&text).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(lower_to_raw(&ast).expect("lower"), bytes, "{arch}");
    }
    let text = decompile_raw_opaque_to_text(&[], "unknown", 0);
    assert_eq!(
        lower_to_raw(&parse(&text).unwrap()).unwrap(),
        Vec::<u8>::new()
    );
}

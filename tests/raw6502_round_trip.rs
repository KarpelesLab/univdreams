//! 6502 raw images round-trip through source byte for byte, whatever
//! lies around the code the decompiler finds.

use univdreams::format::raw::RawImage;
use univdreams::translate::compile::{lower_to_raw, parse};
use univdreams::translate::decompile::decompile_raw_6502_to_text;

fn round_trip(bytes: &[u8]) -> String {
    let load = 0x10000 - bytes.len() as u64;
    let text = decompile_raw_6502_to_text(&RawImage::new(bytes.to_vec(), load)).expect("decompile");
    let ast = parse(&text).unwrap_or_else(|e| panic!("parse: {e}\n{text}"));
    let rebuilt = lower_to_raw(&ast).unwrap_or_else(|e| panic!("lower: {e}\n{text}"));
    assert_eq!(rebuilt, bytes, "differs after round-trip:\n{text}");
    text
}

/// A 256-byte image at $FF00 with `code` at `at` and reset pointing there.
fn image(at: u8, code: &[u8]) -> Vec<u8> {
    let mut img = vec![0x02u8; 0x100]; // undocumented opcode: data
    let start = usize::from(at);
    img[start..start + code.len()].copy_from_slice(code);
    img[0xFC] = at;
    img[0xFD] = 0xFF;
    img
}

#[test]
fn wozmon() {
    round_trip(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/wozmon-apple1.bin"
        ))
        .unwrap(),
    );
}

#[test]
fn bytes_before_the_first_function() {
    // Reset at $FF40: $FF00..$FF40 is data the decompiler must keep.
    let text = round_trip(&image(0x40, &[0xEA, 0xEA, 0x4C, 0x40, 0xFF]));
    assert!(text.contains("@raw(0xff00"), "{text}");
}

#[test]
fn unnamed_zero_page_store() {
    // LDA #$01; STA $0D; RTS — `$0D = …` must parse back.
    let text = round_trip(&image(0x40, &[0xA9, 0x01, 0x85, 0x0D, 0x60]));
    assert!(text.contains("$0D = "), "{text}");
}

#[test]
fn instruction_cut_short_by_the_vectors() {
    // LDA $nnnn (3 bytes) starting at $FFF8 runs into the vectors.
    let mut img = image(0x40, &[0xEA, 0x60]);
    img[0xF8] = 0xAD;
    round_trip(&img);
}

#[test]
fn call_into_the_middle_of_an_instruction() {
    // JSR $FF43 lands inside `LDA #$EA` at $FF42 under the linear decode.
    round_trip(&image(0x40, &[0x20, 0x43, 0xFF, 0xA9, 0xEA, 0x60]));
}

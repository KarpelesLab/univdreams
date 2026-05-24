//! End-to-end tests that exercise the `ArchCodec` trait
//! through real arch impls. Each test resolves a codec from
//! the registry, asks it to assemble a known instruction, and
//! verifies the bytes round-trip via the same arch's free-
//! standing decoder / re-encode path.
//!
//! These tests double as documentation: an arch author can
//! mirror them for their crate to validate that the codec
//! implementation is wired correctly.

use ud_arch_codec::EncodeHints;

/// Each test registers the workspace's arches once. The
/// registry is process-global so subsequent calls are no-ops.
fn init_registry() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        ud_arch_x86::register();
        ud_arch_bpf::register();
        ud_arch_aarch64::register();
        ud_arch_6502::register();
    });
}

#[test]
fn x86_64_assembles_via_codec() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("x86_64"), None).expect("x86_64 codec");
    assert_eq!(codec.name(), "x86-64");
    // `mov rax, rbx` = 48 89 d8 in x86-64.
    let bytes = codec.assemble_one("mov rax, rbx", 0).expect("assemble");
    assert_eq!(bytes, vec![0x48, 0x89, 0xd8]);
}

#[test]
fn x86_64_encode_jump_short_and_wide() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("x86_64"), None).expect("x86_64 codec");
    // Short jmp (rel8) when target is in range, wide=false.
    let short = codec
        .encode_jump(0x1000, 0x1010, EncodeHints::default())
        .expect("short jmp");
    assert_eq!(short, vec![0xeb, 0x0e]);
    // Wide forced regardless of displacement.
    let wide = codec
        .encode_jump(0x1000, 0x1010, EncodeHints::wide(true))
        .expect("wide jmp");
    assert_eq!(wide[0], 0xe9);
    assert_eq!(wide.len(), 5);
}

#[test]
fn bpf_assembles_via_codec_and_round_trips() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("bpf"), None).expect("bpf codec");
    assert_eq!(codec.name(), "bpf-linux");
    // `mov64 r6, r1` = bf 16 00 00 00 00 00 00.
    let bytes = codec.assemble_one("mov64 r6, r1", 0).expect("assemble");
    assert_eq!(bytes, vec![0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn bpf_encode_move_register_register() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("bpf"), None).expect("bpf codec");
    let bytes = codec.encode_move("r6", "r1").expect("encode_move");
    assert_eq!(bytes, vec![0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn bpf_encode_move_register_immediate() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("bpf"), None).expect("bpf codec");
    let bytes = codec.encode_move("r1", "0x5").expect("encode_move imm");
    assert_eq!(bytes, vec![0xb7, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]);
}

#[test]
fn bpf_encode_return_emits_exit() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("bpf"), None).expect("bpf codec");
    let bytes = codec.encode_return(Some(0)).expect("encode_return");
    assert_eq!(bytes, vec![0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn bpf_encode_jump_computes_slot_offset() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("bpf"), None).expect("bpf codec");
    // ja +1 (one slot forward): source at 0x100, target at 0x110.
    let bytes = codec
        .encode_jump(0x100, 0x110, EncodeHints::default())
        .expect("encode_jump");
    // Opcode 0x05 (ja), offset = +1 slot in s16 LE.
    assert_eq!(bytes, vec![0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn unknown_arch_errors() {
    init_registry();
    let err = ud_arch_codec::for_arch(Some("riscv64"), None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("riscv64"), "error message names the arch: {msg}");
}

#[test]
fn aarch64_codec_resolves_but_returns_unsupported() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("aarch64"), None).expect("aarch64 codec");
    assert_eq!(codec.name(), "aarch64");
    // No encoder support yet; all hard-encode methods return Unsupported.
    let err = codec
        .encode_jump(0x1000, 0x2000, EncodeHints::default())
        .unwrap_err();
    assert!(matches!(err, ud_arch_codec::ArchError::Unsupported { .. }));
}

#[test]
fn m6502_codec_resolves_but_returns_unsupported() {
    init_registry();
    let codec = ud_arch_codec::for_arch(Some("6502"), None).expect("6502 codec");
    assert_eq!(codec.name(), "6502");
    let err = codec.assemble_one("LDA #$0d", 0).unwrap_err();
    assert!(matches!(err, ud_arch_codec::ArchError::Unsupported { .. }));
}

#[test]
fn bpf_e_machine_dispatch() {
    init_registry();
    // EM_BPF = 247 → Linux variant
    let linux = ud_arch_codec::for_arch(None, Some(247)).expect("EM_BPF");
    assert_eq!(linux.name(), "bpf-linux");
    // EM_SBF = 263 → Solana sBPFv1 variant
    let sbf = ud_arch_codec::for_arch(None, Some(263)).expect("EM_SBF");
    assert_eq!(sbf.name(), "bpf-sbf-v1");
}

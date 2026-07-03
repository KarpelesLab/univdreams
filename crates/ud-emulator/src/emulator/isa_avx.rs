//! AVX (VEX-encoded) instruction executor.
//!
//! Routed from `super::isa_int::Cpu::dispatch` when a `0xC4`
//! or `0xC5` byte appears with the high bit of the following
//! byte set (the VEX-vs-LES/LDS discriminator in 32-bit code).
//!
//! ## VEX prefix shapes
//!
//! ```text
//!   2-byte (0xC5):  R̅ vvvv L pp
//!                   | inverted REX.R; in 32-bit always 1.
//!                     inverted src-2 selector (4 bits).
//!                              0 = 128-bit / 1 = 256-bit.
//!                                01 = 66, 10 = F3, 11 = F2, 00 = NP.
//!                   Map is implicitly the `0F` escape (1).
//!
//!   3-byte (0xC4):  R̅ X̅ B̅ mmmmm   W vvvv L pp
//!                                | bit 7 of byte 2.
//!                                  inverted src-2 (4 bits).
//!                                          L / pp same as above.
//!                   mmmmm = 1 (`0F`), 2 (`0F 38`), 3 (`0F 3A`).
//!                   In 32-bit, R/X/B read inverted-1 (the real bit
//!                   value is 0 because high registers don't exist).
//! ```
//!
//! Trace-driven implementation: each AVX instruction MagicYUV
//! (or any other corpus codec) actually uses gets a handler
//! added; unimplemented opcodes trap with a structured opcode
//! id that captures `map`, `pp`, `L`, and the raw second byte,
//! so the next gap is obvious at trap-time.
//!
//! Reference: Intel® 64 and IA-32 Architectures Software
//! Developer's Manual, Volume 2A §2.3 (VEX prefix) and
//! Volume 2C (per-instruction pages).

use super::decode::{resolve_modrm32, Operand};
use super::isa_int::{Cpu, StepOk};
use super::mmu::Mmu;
use super::regs::Reg32;
use super::Trap;

/// Decoded VEX prefix — the architecturally-meaningful fields
/// after both forms collapse onto a common shape.
#[derive(Copy, Clone, Debug)]
struct Vex {
    /// Opcode map: `1` = `0F`, `2` = `0F 38`, `3` = `0F 3A`.
    map: u8,
    /// Compressed legacy prefix: `0` = none, `1` = `66`,
    /// `2` = `F3`, `3` = `F2`.
    pp: u8,
    /// Vector length: `0` = 128-bit, `1` = 256-bit.
    l: u8,
    /// `W` bit (only meaningful for 3-byte VEX; `false` for
    /// the 2-byte form). Read but not yet acted on — kept so
    /// handlers can pick W=1 vs W=0 variants when they arrive.
    #[allow(dead_code)]
    w: bool,
    /// Second source operand register selector (0..7 in
    /// 32-bit code — the high bit of the architectural 4-bit
    /// field is unused without REX).
    vvvv: u8,
}

impl Vex {
    fn from_c5(b1: u8) -> Self {
        // 2-byte VEX: byte 1 = R̅ vvvv L pp.
        Vex {
            map: 1, // implicit 0F escape
            pp: b1 & 0x3,
            l: (b1 >> 2) & 0x1,
            w: false,
            // vvvv field is inverted; mask back to 0..15.
            vvvv: (!(b1 >> 3)) & 0xF,
        }
    }

    fn from_c4(b1: u8, b2: u8) -> Self {
        // 3-byte VEX: byte 1 = R̅ X̅ B̅ mmmmm; byte 2 = W vvvv L pp.
        Vex {
            map: b1 & 0x1F,
            pp: b2 & 0x3,
            l: (b2 >> 2) & 0x1,
            w: (b2 & 0x80) != 0,
            vvvv: (!(b2 >> 3)) & 0xF,
        }
    }
}

/// Encode a VEX instruction for [`Trap::UndefinedOpcode`]
/// reporting. Layout (LSB first): `[opcode:8][L:1][pp:2][map:3]
/// [vvvv:4]`. Decode by hand from the trap:
///
/// ```text
///   opcode = (id      ) & 0xFF
///   L      = (id >>  8) & 0x1
///   pp     = (id >>  9) & 0x3
///   map    = (id >> 11) & 0x7
///   vvvv   = (id >> 14) & 0xF
/// ```
fn vex_opcode_id(vex: &Vex, opcode: u8) -> u32 {
    u32::from(opcode)
        | (u32::from(vex.l) << 8)
        | (u32::from(vex.pp) << 9)
        | (u32::from(vex.map) << 11)
        | (u32::from(vex.vvvv) << 14)
}

/// Dispatch a VEX-encoded instruction. `prefix_byte` is the
/// first byte (`0xC4` or `0xC5`); `entry_eip` is the EIP at the
/// start of the instruction (for trap reporting). On entry,
/// `cpu.regs.eip` points to the byte AFTER the prefix.
pub fn dispatch(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    prefix_byte: u8,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    cpu.bump_avx_count();
    let vex = match prefix_byte {
        0xC5 => {
            let b1 = cpu.fetch_imm8_pub(mmu)?;
            Vex::from_c5(b1)
        }
        0xC4 => {
            let b1 = cpu.fetch_imm8_pub(mmu)?;
            let b2 = cpu.fetch_imm8_pub(mmu)?;
            Vex::from_c4(b1, b2)
        }
        _ => unreachable!("dispatch called with non-VEX prefix {prefix_byte:#x}"),
    };
    let opcode = cpu.fetch_imm8_pub(mmu)?;

    match (vex.map, vex.pp, vex.l, opcode) {
        // 66 0F EF /r — VPXOR xmm1, xmm2, xmm3/m128
        //   dst = ModR/M.reg, src1 = vvvv, src2 = ModR/M.r/m
        //   dst = src1 ^ src2; VEX.128 zeroes the upper 128 of
        //   the destination YMM (Intel SDM §15.5).
        (1, 1, 0, 0xEF) => vpxor_128(cpu, mmu, &vex),
        // VEX.{128,256}.{66,F3,F2}.0F.WIG 70 /r ib — pshuf
        // family. The pp slot picks the variant:
        //   66 = VPSHUFD     (shuffle 4 dwords)
        //   F3 = VPSHUFHW    (shuffle high 4 words; low pass-through)
        //   F2 = VPSHUFLW    (shuffle low 4 words; high pass-through)
        // Single-source instruction — vvvv must be 1111.
        // ===== Per-lane SIMD-int family (VEX.NDS 128/256). =====
        // All of these have the same encoding shape — three
        // operands (`dst = vvvv ⊕ r/m`, src1 = vvvv,
        // src2 = ModR/M.r/m) — and only differ in the per-lane
        // operation. Dispatched through `vpbinop_*` which
        // performs the load + per-lane fan-out + zero-extend
        // (128-bit) or both-half application (256-bit).
        //
        //   PUNPCK*  60..62 / 68..6A / 6C..6D
        //   PACK*    63 / 67 / 6B
        //   PCMPGT   64..66
        //   PCMPEQ   74..76
        //   PADDQ            D4
        //   PMULLW           D5
        //   PSUBUSB/W        D8..D9
        //   PMINUB           DA
        //   PADDUSB/W        DC..DD
        //   PMAXUB           DE
        //   PAVGB            E0
        //   PAVGW            E3
        //   PMULHUW/PMULHW   E4..E5
        //   PSUBSB/W         E8..E9
        //   PMINSW           EA
        //   PADDSB/W         EC..ED
        //   PMAXSW           EE
        //   PMULUDQ          F4
        //   PMADDWD          F5
        //   PSADBW           F6
        //   PSUBB/W/D/Q      F8..FB
        //   PADDB/W/D        FC..FE
        (1, 1, 0, 0x60) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckLBW),
        (1, 1, 1, 0x60) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckLBW),
        (1, 1, 0, 0x61) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckLWD),
        (1, 1, 1, 0x61) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckLWD),
        (1, 1, 0, 0x62) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckLDQ),
        (1, 1, 1, 0x62) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckLDQ),
        (1, 1, 0, 0x63) => vpbinop_128(cpu, mmu, &vex, SimdOp::PackSSWB),
        (1, 1, 1, 0x63) => vpbinop_256(cpu, mmu, &vex, SimdOp::PackSSWB),
        (1, 1, 0, 0x64) => vpbinop_128(cpu, mmu, &vex, SimdOp::CmpGtB),
        (1, 1, 1, 0x64) => vpbinop_256(cpu, mmu, &vex, SimdOp::CmpGtB),
        (1, 1, 0, 0x65) => vpbinop_128(cpu, mmu, &vex, SimdOp::CmpGtW),
        (1, 1, 1, 0x65) => vpbinop_256(cpu, mmu, &vex, SimdOp::CmpGtW),
        (1, 1, 0, 0x66) => vpbinop_128(cpu, mmu, &vex, SimdOp::CmpGtD),
        (1, 1, 1, 0x66) => vpbinop_256(cpu, mmu, &vex, SimdOp::CmpGtD),
        (1, 1, 0, 0x67) => vpbinop_128(cpu, mmu, &vex, SimdOp::PackUSWB),
        (1, 1, 1, 0x67) => vpbinop_256(cpu, mmu, &vex, SimdOp::PackUSWB),
        (1, 1, 0, 0x68) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckHBW),
        (1, 1, 1, 0x68) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckHBW),
        (1, 1, 0, 0x69) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckHWD),
        (1, 1, 1, 0x69) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckHWD),
        (1, 1, 0, 0x6A) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckHDQ),
        (1, 1, 1, 0x6A) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckHDQ),
        (1, 1, 0, 0x6B) => vpbinop_128(cpu, mmu, &vex, SimdOp::PackSSDW),
        (1, 1, 1, 0x6B) => vpbinop_256(cpu, mmu, &vex, SimdOp::PackSSDW),
        (1, 1, 0, 0x6C) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckLQDQ),
        (1, 1, 1, 0x6C) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckLQDQ),
        (1, 1, 0, 0x6D) => vpbinop_128(cpu, mmu, &vex, SimdOp::UnpckHQDQ),
        (1, 1, 1, 0x6D) => vpbinop_256(cpu, mmu, &vex, SimdOp::UnpckHQDQ),
        (1, 1, 0, 0x74) => vpbinop_128(cpu, mmu, &vex, SimdOp::CmpEqB),
        (1, 1, 1, 0x74) => vpbinop_256(cpu, mmu, &vex, SimdOp::CmpEqB),
        (1, 1, 0, 0x75) => vpbinop_128(cpu, mmu, &vex, SimdOp::CmpEqW),
        (1, 1, 1, 0x75) => vpbinop_256(cpu, mmu, &vex, SimdOp::CmpEqW),
        (1, 1, 0, 0xD4) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddQ),
        (1, 1, 1, 0xD4) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddQ),
        (1, 1, 0, 0xD5) => vpbinop_128(cpu, mmu, &vex, SimdOp::MulLowW),
        (1, 1, 1, 0xD5) => vpbinop_256(cpu, mmu, &vex, SimdOp::MulLowW),
        (1, 1, 0, 0xD8) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubSatUB),
        (1, 1, 1, 0xD8) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubSatUB),
        (1, 1, 0, 0xD9) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubSatUW),
        (1, 1, 1, 0xD9) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubSatUW),
        (1, 1, 0, 0xDA) => vpbinop_128(cpu, mmu, &vex, SimdOp::MinUB),
        (1, 1, 1, 0xDA) => vpbinop_256(cpu, mmu, &vex, SimdOp::MinUB),
        (1, 1, 0, 0xDC) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddSatUB),
        (1, 1, 1, 0xDC) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddSatUB),
        (1, 1, 0, 0xDD) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddSatUW),
        (1, 1, 1, 0xDD) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddSatUW),
        (1, 1, 0, 0xDE) => vpbinop_128(cpu, mmu, &vex, SimdOp::MaxUB),
        (1, 1, 1, 0xDE) => vpbinop_256(cpu, mmu, &vex, SimdOp::MaxUB),
        (1, 1, 0, 0xE0) => vpbinop_128(cpu, mmu, &vex, SimdOp::AvgB),
        (1, 1, 1, 0xE0) => vpbinop_256(cpu, mmu, &vex, SimdOp::AvgB),
        (1, 1, 0, 0xE3) => vpbinop_128(cpu, mmu, &vex, SimdOp::AvgW),
        (1, 1, 1, 0xE3) => vpbinop_256(cpu, mmu, &vex, SimdOp::AvgW),
        (1, 1, 0, 0xE4) => vpbinop_128(cpu, mmu, &vex, SimdOp::MulHighUW),
        (1, 1, 1, 0xE4) => vpbinop_256(cpu, mmu, &vex, SimdOp::MulHighUW),
        (1, 1, 0, 0xE5) => vpbinop_128(cpu, mmu, &vex, SimdOp::MulHighSW),
        (1, 1, 1, 0xE5) => vpbinop_256(cpu, mmu, &vex, SimdOp::MulHighSW),
        (1, 1, 0, 0xE8) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubSatSB),
        (1, 1, 1, 0xE8) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubSatSB),
        (1, 1, 0, 0xE9) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubSatSW),
        (1, 1, 1, 0xE9) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubSatSW),
        (1, 1, 0, 0xEA) => vpbinop_128(cpu, mmu, &vex, SimdOp::MinSW),
        (1, 1, 1, 0xEA) => vpbinop_256(cpu, mmu, &vex, SimdOp::MinSW),
        (1, 1, 0, 0xEC) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddSatSB),
        (1, 1, 1, 0xEC) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddSatSB),
        (1, 1, 0, 0xED) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddSatSW),
        (1, 1, 1, 0xED) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddSatSW),
        (1, 1, 0, 0xEE) => vpbinop_128(cpu, mmu, &vex, SimdOp::MaxSW),
        (1, 1, 1, 0xEE) => vpbinop_256(cpu, mmu, &vex, SimdOp::MaxSW),
        (1, 1, 0, 0xF4) => vpbinop_128(cpu, mmu, &vex, SimdOp::MulUDQ),
        (1, 1, 1, 0xF4) => vpbinop_256(cpu, mmu, &vex, SimdOp::MulUDQ),
        (1, 1, 0, 0xF5) => vpbinop_128(cpu, mmu, &vex, SimdOp::MAddWD),
        (1, 1, 1, 0xF5) => vpbinop_256(cpu, mmu, &vex, SimdOp::MAddWD),
        (1, 1, 0, 0xF6) => vpbinop_128(cpu, mmu, &vex, SimdOp::SadBW),
        (1, 1, 1, 0xF6) => vpbinop_256(cpu, mmu, &vex, SimdOp::SadBW),
        (1, 1, 0, 0xF8) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubB),
        (1, 1, 1, 0xF8) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubB),
        (1, 1, 0, 0xF9) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubW),
        (1, 1, 1, 0xF9) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubW),
        (1, 1, 0, 0xFA) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubD),
        (1, 1, 1, 0xFA) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubD),
        (1, 1, 0, 0xFB) => vpbinop_128(cpu, mmu, &vex, SimdOp::SubQ),
        (1, 1, 1, 0xFB) => vpbinop_256(cpu, mmu, &vex, SimdOp::SubQ),
        (1, 1, 0, 0xFC) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddB),
        (1, 1, 1, 0xFC) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddB),
        (1, 1, 0, 0xFD) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddW),
        (1, 1, 1, 0xFD) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddW),
        (1, 1, 0, 0xFE) => vpbinop_128(cpu, mmu, &vex, SimdOp::AddD),
        (1, 1, 1, 0xFE) => vpbinop_256(cpu, mmu, &vex, SimdOp::AddD),
        (1, 1, 0, 0x70) => vpshuf_xmm(cpu, mmu, ShufKind::Dwords),
        (1, 1, 1, 0x70) => vpshuf_ymm(cpu, mmu, ShufKind::Dwords),
        (1, 2, 0, 0x70) => vpshuf_xmm(cpu, mmu, ShufKind::HighWords),
        (1, 2, 1, 0x70) => vpshuf_ymm(cpu, mmu, ShufKind::HighWords),
        (1, 3, 0, 0x70) => vpshuf_xmm(cpu, mmu, ShufKind::LowWords),
        (1, 3, 1, 0x70) => vpshuf_ymm(cpu, mmu, ShufKind::LowWords),
        // 256-bit and bitwise-int family. Opcodes DB/DF/EB/EF
        // are the VEX.NDS three-operand forms of PAND, PANDN,
        // POR and PXOR; per-lane bitwise ops where the lane
        // size doesn't matter (the math is the same for u128
        // halves).
        (1, 1, 1, 0xEF) => vpbitwise_256(cpu, mmu, &vex, BitwiseOp::Xor),
        (1, 1, 0, 0xDB) => vpbitwise_128(cpu, mmu, &vex, BitwiseOp::And),
        (1, 1, 1, 0xDB) => vpbitwise_256(cpu, mmu, &vex, BitwiseOp::And),
        (1, 1, 0, 0xDF) => vpbitwise_128(cpu, mmu, &vex, BitwiseOp::AndNot),
        (1, 1, 1, 0xDF) => vpbitwise_256(cpu, mmu, &vex, BitwiseOp::AndNot),
        (1, 1, 0, 0xEB) => vpbitwise_128(cpu, mmu, &vex, BitwiseOp::Or),
        (1, 1, 1, 0xEB) => vpbitwise_256(cpu, mmu, &vex, BitwiseOp::Or),
        // VEX.NDD.{128,256}.66.0F.WIG 71/72/73 /N ib — Group
        // 12/13/14 word/dword/qword shifts by an imm8 count.
        // Encoding: ModR/M.r/m = source xmm, vvvv = dest xmm,
        // mr.reg = subopcode (/2 = right-logical, /4 = right-
        // arithmetic, /6 = left-logical; /3 and /7 only used by
        // group 14 for the byte-shift PSRLDQ/PSLLDQ).
        (1, 1, 0, 0x71) => vex_group12_xmm(cpu, mmu, &vex),
        (1, 1, 1, 0x71) => vex_group12_ymm(cpu, mmu, &vex),
        (1, 1, 0, 0x72) => vex_group13_xmm(cpu, mmu, &vex),
        (1, 1, 1, 0x72) => vex_group13_ymm(cpu, mmu, &vex),
        (1, 1, 0, 0x73) => vex_group14_xmm(cpu, mmu, &vex),
        (1, 1, 1, 0x73) => vex_group14_ymm(cpu, mmu, &vex),
        // VEX.128.66.0F.WIG 6F /r — VMOVDQA xmm1, xmm2/m128.
        (1, 1, 0, 0x6F) => vmovdqa_load_128(cpu, mmu),
        // VEX.128.66.0F.WIG 7F /r — VMOVDQA xmm2/m128, xmm1.
        (1, 1, 0, 0x7F) => vmovdqa_store_128(cpu, mmu),
        // VEX.256.66.0F.WIG 76 /r — VPCMPEQD ymm1, ymm2, ymm3/m256.
        //   Per-32-bit-lane: dst = (src1 == src2) ? all-ones : 0.
        //   MagicYUV uses `vpcmpeqd ymm0,ymm0,ymm0` as a one-cycle
        //   way to materialize an all-ones YMM constant.
        (1, 1, 1, 0x76) => vpcmpeqd_256(cpu, mmu, &vex),
        // VEX.256.66.0F.WIG 6F /r — VMOVDQA ymm1, ymm2/m256.
        (1, 1, 1, 0x6F) => vmovdqa_load_256(cpu, mmu),
        // VEX.256.66.0F.WIG 7F /r — VMOVDQA ymm2/m256, ymm1.
        (1, 1, 1, 0x7F) => vmovdqa_store_256(cpu, mmu),
        // VEX.128.NP.0F.WIG 77 — VZEROUPPER. Zeroes the upper
        // 128 bits of every YMM register. No ModR/M follows.
        // Codecs sprinkle this after AVX work to avoid the
        // "AVX/SSE state transition" penalty on real silicon.
        (1, 0, 0, 0x77) => vzeroupper(cpu),
        // NP 0F 11 /r — VMOVUPS xmm2/m128, xmm1 (store).
        //   src = xmm[ModR/M.reg]; r/m is the destination.
        //   When r/m is a register, the upper 128 of that YMM
        //   is zeroed; memory store touches 16 bytes.
        (1, 0, 0, 0x11) => vmovups_store_128(cpu, mmu),
        // VEX.{128,256}.NP.0F.WIG 10 — VMOVUPS xmm/ymm load.
        // VEX.{128,256}.NP.0F.WIG 28 — VMOVAPS xmm/ymm load.
        // VEX.{128,256}.NP.0F.WIG 29 — VMOVAPS xmm/ymm store.
        // We treat aligned and unaligned forms identically —
        // the only difference on real silicon is the #GP on
        // misaligned operands, which corpus codecs don't rely
        // on.
        (1, 0, 0, 0x10) => vmovaps_load_128(cpu, mmu),
        (1, 0, 1, 0x10) => vmovaps_load_256(cpu, mmu),
        (1, 0, 1, 0x11) => vmovups_store_256(cpu, mmu),
        (1, 0, 0, 0x28) => vmovaps_load_128(cpu, mmu),
        (1, 0, 1, 0x28) => vmovaps_load_256(cpu, mmu),
        (1, 0, 0, 0x29) => vmovaps_store_128(cpu, mmu),
        (1, 0, 1, 0x29) => vmovups_store_256(cpu, mmu),
        // VEX.{128,256}.F3.0F.WIG 6F — VMOVDQU xmm/ymm load.
        // VEX.{128,256}.F3.0F.WIG 7F — VMOVDQU xmm/ymm store.
        (1, 2, 0, 0x6F) => vmovdqa_load_128(cpu, mmu),
        (1, 2, 1, 0x6F) => vmovdqa_load_256(cpu, mmu),
        (1, 2, 0, 0x7F) => vmovdqa_store_128(cpu, mmu),
        // VEX.128.66.0F3A.W0 20 /r ib — VPINSRB xmm1, xmm2,
        // r32/m8, imm8. Insert a byte from the GP source into
        // a specified lane of xmm1; xmm1 = vvvv otherwise.
        (3, 1, 0, 0x20) => vpinsrb_128(cpu, mmu, &vex),
        // VEX.128.66.0F.W0 C4 /r ib — VPINSRW xmm1, xmm2,
        // r32/m16, imm8.
        (1, 1, 0, 0xC4) => vpinsrw_128(cpu, mmu, &vex),
        // VEX.128.66.0F.W0 6E /r — VMOVD xmm1, r/m32 (load 32→xmm,
        // zero-extend; upper 96 zero, upper YMM zero).
        (1, 1, 0, 0x6E) => vmovd_load(cpu, mmu),
        // VEX.128.66.0F.W0 7E /r — VMOVD r/m32, xmm1 (store low 32).
        (1, 1, 0, 0x7E) => vmovd_store(cpu, mmu),
        // VEX.128.F3.0F.WIG 7E /r — VMOVQ xmm1, xmm2/m64 (load
        // 64 low, zero-extend rest).
        (1, 2, 0, 0x7E) => vmovq_load(cpu, mmu),
        // VEX.128.66.0F.WIG D6 /r — VMOVQ xmm2/m64, xmm1 (store low 64).
        (1, 1, 0, 0xD6) => vmovq_store(cpu, mmu),
        // VEX.128.66.0F3A.W0 14 /r ib — VPEXTRB r/m8, xmm, imm8.
        (3, 1, 0, 0x14) => vpextrb_128(cpu, mmu),
        // VEX.128.66.0F.W0 C5 /r ib — VPEXTRW r32, xmm, imm8.
        (1, 1, 0, 0xC5) => vpextrw_imm_128(cpu, mmu),
        // VEX.128.66.0F3A.W0 15 /r ib — VPEXTRW r/m16, xmm, imm8.
        (3, 1, 0, 0x15) => vpextrw_mem_128(cpu, mmu),
        // VEX.128.66.0F3A.W0 16 /r ib — VPEXTRD r/m32, xmm, imm8.
        (3, 1, 0, 0x16) => vpextrd_128(cpu, mmu),
        // VEX.128.66.0F.WIG D7 /r — VPMOVMSKB r32, xmm.
        (1, 1, 0, 0xD7) => vpmovmskb_128(cpu, mmu),
        // VEX.256.66.0F.WIG D7 /r — VPMOVMSKB r32, ymm.
        (1, 1, 1, 0xD7) => vpmovmskb_256(cpu, mmu),
        // VEX.{128,256}.66.0F38.W0 — VPBROADCAST family.
        //   78 = VPBROADCASTB  (byte)
        //   79 = VPBROADCASTW  (word)
        //   58 = VPBROADCASTD  (dword)
        //   59 = VPBROADCASTQ  (qword)
        // Source is xmm/mN (single lane); result fills the
        // destination by repetition.
        (2, 1, 0, 0x78) => vpbroadcast(cpu, mmu, BroadcastKind::B, false),
        (2, 1, 1, 0x78) => vpbroadcast(cpu, mmu, BroadcastKind::B, true),
        (2, 1, 0, 0x79) => vpbroadcast(cpu, mmu, BroadcastKind::W, false),
        (2, 1, 1, 0x79) => vpbroadcast(cpu, mmu, BroadcastKind::W, true),
        (2, 1, 0, 0x58) => vpbroadcast(cpu, mmu, BroadcastKind::D, false),
        (2, 1, 1, 0x58) => vpbroadcast(cpu, mmu, BroadcastKind::D, true),
        (2, 1, 0, 0x59) => vpbroadcast(cpu, mmu, BroadcastKind::Q, false),
        (2, 1, 1, 0x59) => vpbroadcast(cpu, mmu, BroadcastKind::Q, true),
        // VEX.256.66.0F38.W0 5A /r — VBROADCASTI128 ymm, m128.
        (2, 1, 1, 0x5A) => vbroadcasti128(cpu, mmu),
        // VEX.{128,256}.66.0F.WIG E7 /r — VMOVNTDQ m128/m256, xmm/ymm.
        // Non-temporal store; we treat it as a plain aligned
        // store since codecs only care about the bytes landing.
        (1, 1, 0, 0xE7) => vmovaps_store_128(cpu, mmu),
        (1, 1, 1, 0xE7) => vmovups_store_256(cpu, mmu),
        // VEX.{128,256}.NP.0F.WIG 2B /r — VMOVNTPS m128/m256, xmm/ymm.
        (1, 0, 0, 0x2B) => vmovaps_store_128(cpu, mmu),
        (1, 0, 1, 0x2B) => vmovups_store_256(cpu, mmu),
        (1, 2, 1, 0x7F) => vmovdqa_store_256(cpu, mmu),
        // VEX.LZ.{66,F3,F2}.0F38.W0 F7 /r — BMI2 shifts on GP
        // regs: SHLX (66), SARX (F3), SHRX (F2).
        //   dst   = ModR/M.reg
        //   value = ModR/M.r/m32
        //   count = vvvv register (low 5 bits)
        // Doesn't affect flags.
        (2, 1, 0, 0xF7) => bmi2_shift_x(cpu, mmu, &vex, ShiftKind::Shl),
        (2, 2, 0, 0xF7) => bmi2_shift_x(cpu, mmu, &vex, ShiftKind::Sar),
        (2, 3, 0, 0xF7) => bmi2_shift_x(cpu, mmu, &vex, ShiftKind::Shr),
        _ => {
            // Trace-driven gap reporting: pack (map, pp, L,
            // vvvv, opcode) into the trap so the next handler
            // to write is obvious at trap-time.
            Err(Trap::UndefinedOpcode {
                eip: entry_eip,
                opcode: vex_opcode_id(&vex, opcode),
            })
        }
    }
}

/// Resolve the (dst, src2_value) pair for a standard
/// "VEX 3-op SSE-shape" instruction.  Caller passes the
/// already-decoded `Vex` (so `src1 = xmm[vex.vvvv]`).
///
/// On entry `cpu.regs.eip` points at the ModR/M byte; on
/// return EIP has stepped past the ModR/M + SIB + displacement
/// the encoding required.
fn read_xmm_dst_and_src2(cpu: &mut Cpu, mmu: &Mmu) -> Result<(usize, u128), Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let dst = (mr.reg & 0x7) as usize;
    let src2 = match op {
        Operand::Reg32(_) => cpu.xmm[(mr.rm & 0x7) as usize],
        Operand::Mem32(addr) => {
            let bs = mmu.read(cpu.seg_translate(addr), 16)?;
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bs);
            u128::from_le_bytes(buf)
        }
    };
    Ok((dst, src2))
}

/// `VEX.128.66.0F.WIG EF /r` — VPXOR xmm1, xmm2, xmm3/m128.
fn vpxor_128(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (dst, src2) = read_xmm_dst_and_src2(cpu, mmu)?;
    let src1 = cpu.xmm[(vex.vvvv & 0x7) as usize];
    cpu.xmm[dst] = src1 ^ src2;
    // VEX.128 zeroes the upper 128 of the destination YMM.
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// Per-lane SIMD-int operation. The applier (`simd_op_apply`)
/// operates on two 128-bit halves independently; the VEX.256
/// variant just calls it twice.
#[derive(Copy, Clone)]
enum SimdOp {
    AddB,
    AddW,
    AddD,
    AddQ,
    SubB,
    SubW,
    SubD,
    SubQ,
    AddSatUB,
    AddSatUW,
    AddSatSB,
    AddSatSW,
    SubSatUB,
    SubSatUW,
    SubSatSB,
    SubSatSW,
    MinUB,
    MinSW,
    MaxUB,
    MaxSW,
    CmpEqB,
    CmpEqW,
    CmpGtB,
    CmpGtW,
    CmpGtD,
    MulLowW,
    MulHighUW,
    MulHighSW,
    MulUDQ,
    MAddWD,
    SadBW,
    AvgB,
    AvgW,
    PackSSWB,
    PackSSDW,
    PackUSWB,
    UnpckLBW,
    UnpckLWD,
    UnpckLDQ,
    UnpckLQDQ,
    UnpckHBW,
    UnpckHWD,
    UnpckHDQ,
    UnpckHQDQ,
}

#[inline]
fn lanes_u8(v: u128) -> [u8; 16] {
    v.to_le_bytes()
}
#[inline]
fn from_lanes_u8(a: [u8; 16]) -> u128 {
    u128::from_le_bytes(a)
}
#[inline]
fn lanes_u16(v: u128) -> [u16; 8] {
    let b = v.to_le_bytes();
    core::array::from_fn(|i| u16::from_le_bytes([b[2 * i], b[2 * i + 1]]))
}
#[inline]
fn from_lanes_u16(a: [u16; 8]) -> u128 {
    let mut b = [0u8; 16];
    for i in 0..8 {
        let w = a[i].to_le_bytes();
        b[2 * i] = w[0];
        b[2 * i + 1] = w[1];
    }
    u128::from_le_bytes(b)
}
#[inline]
fn lanes_u32(v: u128) -> [u32; 4] {
    let b = v.to_le_bytes();
    core::array::from_fn(|i| {
        u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
    })
}
#[inline]
fn from_lanes_u32(a: [u32; 4]) -> u128 {
    let mut b = [0u8; 16];
    for i in 0..4 {
        let w = a[i].to_le_bytes();
        b[4 * i..4 * i + 4].copy_from_slice(&w);
    }
    u128::from_le_bytes(b)
}
#[inline]
fn lanes_u64(v: u128) -> [u64; 2] {
    [v as u64, (v >> 64) as u64]
}
#[inline]
fn from_lanes_u64(a: [u64; 2]) -> u128 {
    u128::from(a[0]) | (u128::from(a[1]) << 64)
}

fn simd_op_apply(op: SimdOp, src1: u128, src2: u128) -> u128 {
    match op {
        SimdOp::AddB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| a[i].wrapping_add(b[i])))
        }
        SimdOp::AddW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| a[i].wrapping_add(b[i])))
        }
        SimdOp::AddD => {
            let a = lanes_u32(src1);
            let b = lanes_u32(src2);
            from_lanes_u32(core::array::from_fn(|i| a[i].wrapping_add(b[i])))
        }
        SimdOp::AddQ => {
            let a = lanes_u64(src1);
            let b = lanes_u64(src2);
            from_lanes_u64([a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])])
        }
        SimdOp::SubB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| a[i].wrapping_sub(b[i])))
        }
        SimdOp::SubW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| a[i].wrapping_sub(b[i])))
        }
        SimdOp::SubD => {
            let a = lanes_u32(src1);
            let b = lanes_u32(src2);
            from_lanes_u32(core::array::from_fn(|i| a[i].wrapping_sub(b[i])))
        }
        SimdOp::SubQ => {
            let a = lanes_u64(src1);
            let b = lanes_u64(src2);
            from_lanes_u64([a[0].wrapping_sub(b[0]), a[1].wrapping_sub(b[1])])
        }
        SimdOp::AddSatUB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| a[i].saturating_add(b[i])))
        }
        SimdOp::AddSatUW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| a[i].saturating_add(b[i])))
        }
        SimdOp::AddSatSB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| {
                (a[i] as i8).saturating_add(b[i] as i8) as u8
            }))
        }
        SimdOp::AddSatSW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                (a[i] as i16).saturating_add(b[i] as i16) as u16
            }))
        }
        SimdOp::SubSatUB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| a[i].saturating_sub(b[i])))
        }
        SimdOp::SubSatUW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| a[i].saturating_sub(b[i])))
        }
        SimdOp::SubSatSB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| {
                (a[i] as i8).saturating_sub(b[i] as i8) as u8
            }))
        }
        SimdOp::SubSatSW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                (a[i] as i16).saturating_sub(b[i] as i16) as u16
            }))
        }
        SimdOp::MinUB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| a[i].min(b[i])))
        }
        SimdOp::MaxUB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| a[i].max(b[i])))
        }
        SimdOp::MinSW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                ((a[i] as i16).min(b[i] as i16)) as u16
            }))
        }
        SimdOp::MaxSW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                ((a[i] as i16).max(b[i] as i16)) as u16
            }))
        }
        SimdOp::CmpEqB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(
                |i| if a[i] == b[i] { 0xFF } else { 0 },
            ))
        }
        SimdOp::CmpEqW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(
                |i| if a[i] == b[i] { 0xFFFF } else { 0 },
            ))
        }
        SimdOp::CmpGtB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| {
                if (a[i] as i8) > (b[i] as i8) {
                    0xFF
                } else {
                    0
                }
            }))
        }
        SimdOp::CmpGtW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                if (a[i] as i16) > (b[i] as i16) {
                    0xFFFF
                } else {
                    0
                }
            }))
        }
        SimdOp::CmpGtD => {
            let a = lanes_u32(src1);
            let b = lanes_u32(src2);
            from_lanes_u32(core::array::from_fn(|i| {
                if (a[i] as i32) > (b[i] as i32) {
                    0xFFFF_FFFF
                } else {
                    0
                }
            }))
        }
        SimdOp::MulLowW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| a[i].wrapping_mul(b[i])))
        }
        SimdOp::MulHighUW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                ((u32::from(a[i]) * u32::from(b[i])) >> 16) as u16
            }))
        }
        SimdOp::MulHighSW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                ((i32::from(a[i] as i16) * i32::from(b[i] as i16)) >> 16) as u16
            }))
        }
        SimdOp::MulUDQ => {
            // PMULUDQ: multiply low 32 of each 64-bit lane, full
            // 64-bit unsigned product.
            let a = lanes_u64(src1);
            let b = lanes_u64(src2);
            from_lanes_u64([
                u64::from(a[0] as u32) * u64::from(b[0] as u32),
                u64::from(a[1] as u32) * u64::from(b[1] as u32),
            ])
        }
        SimdOp::MAddWD => {
            // PMADDWD: per-pair (a[2k]*b[2k] + a[2k+1]*b[2k+1])
            // → 32-bit lane.
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u32(core::array::from_fn(|i| {
                let p0 = i32::from(a[2 * i] as i16) * i32::from(b[2 * i] as i16);
                let p1 = i32::from(a[2 * i + 1] as i16) * i32::from(b[2 * i + 1] as i16);
                p0.wrapping_add(p1) as u32
            }))
        }
        SimdOp::SadBW => {
            // PSADBW: sum of absolute differences of 8 bytes
            // → 16-bit result in low 16 of each 64-bit lane.
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            let mut sums = [0u16; 2];
            for half in 0..2 {
                let mut s: u32 = 0;
                for i in 0..8 {
                    let aa = a[half * 8 + i] as i16;
                    let bb = b[half * 8 + i] as i16;
                    s += (aa - bb).unsigned_abs() as u32;
                }
                sums[half] = s as u16;
            }
            from_lanes_u64([u64::from(sums[0]), u64::from(sums[1])])
        }
        SimdOp::AvgB => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            from_lanes_u8(core::array::from_fn(|i| {
                ((u16::from(a[i]) + u16::from(b[i]) + 1) >> 1) as u8
            }))
        }
        SimdOp::AvgW => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            from_lanes_u16(core::array::from_fn(|i| {
                ((u32::from(a[i]) + u32::from(b[i]) + 1) >> 1) as u16
            }))
        }
        SimdOp::PackSSWB => {
            // Pack 16 signed words → 16 signed bytes (saturated).
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            let mut out = [0u8; 16];
            for i in 0..8 {
                out[i] = (a[i] as i16).clamp(-128, 127) as i8 as u8;
                out[i + 8] = (b[i] as i16).clamp(-128, 127) as i8 as u8;
            }
            from_lanes_u8(out)
        }
        SimdOp::PackSSDW => {
            // Pack 8 signed dwords → 8 signed words (saturated).
            let a = lanes_u32(src1);
            let b = lanes_u32(src2);
            let mut out = [0u16; 8];
            for i in 0..4 {
                out[i] = (a[i] as i32).clamp(-32768, 32767) as i16 as u16;
                out[i + 4] = (b[i] as i32).clamp(-32768, 32767) as i16 as u16;
            }
            from_lanes_u16(out)
        }
        SimdOp::PackUSWB => {
            // Pack 16 signed words → 16 unsigned bytes (saturated to 0..255).
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            let mut out = [0u8; 16];
            for i in 0..8 {
                out[i] = (a[i] as i16).clamp(0, 255) as u8;
                out[i + 8] = (b[i] as i16).clamp(0, 255) as u8;
            }
            from_lanes_u8(out)
        }
        SimdOp::UnpckLBW => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            let mut out = [0u8; 16];
            for i in 0..8 {
                out[2 * i] = a[i];
                out[2 * i + 1] = b[i];
            }
            from_lanes_u8(out)
        }
        SimdOp::UnpckHBW => {
            let a = lanes_u8(src1);
            let b = lanes_u8(src2);
            let mut out = [0u8; 16];
            for i in 0..8 {
                out[2 * i] = a[i + 8];
                out[2 * i + 1] = b[i + 8];
            }
            from_lanes_u8(out)
        }
        SimdOp::UnpckLWD => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            let mut out = [0u16; 8];
            for i in 0..4 {
                out[2 * i] = a[i];
                out[2 * i + 1] = b[i];
            }
            from_lanes_u16(out)
        }
        SimdOp::UnpckHWD => {
            let a = lanes_u16(src1);
            let b = lanes_u16(src2);
            let mut out = [0u16; 8];
            for i in 0..4 {
                out[2 * i] = a[i + 4];
                out[2 * i + 1] = b[i + 4];
            }
            from_lanes_u16(out)
        }
        SimdOp::UnpckLDQ => {
            let a = lanes_u32(src1);
            let b = lanes_u32(src2);
            from_lanes_u32([a[0], b[0], a[1], b[1]])
        }
        SimdOp::UnpckHDQ => {
            let a = lanes_u32(src1);
            let b = lanes_u32(src2);
            from_lanes_u32([a[2], b[2], a[3], b[3]])
        }
        SimdOp::UnpckLQDQ => {
            let a = lanes_u64(src1);
            let b = lanes_u64(src2);
            from_lanes_u64([a[0], b[0]])
        }
        SimdOp::UnpckHQDQ => {
            let a = lanes_u64(src1);
            let b = lanes_u64(src2);
            from_lanes_u64([a[1], b[1]])
        }
    }
}

fn vpbinop_128(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex, op: SimdOp) -> Result<StepOk, Trap> {
    let (dst, src2) = read_xmm_dst_and_src2(cpu, mmu)?;
    let src1 = cpu.xmm[(vex.vvvv & 0x7) as usize];
    cpu.xmm[dst] = simd_op_apply(op, src1, src2);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

fn vpbinop_256(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex, op: SimdOp) -> Result<StepOk, Trap> {
    let (dst, s2l, s2h) = read_ymm_dst_and_src2(cpu, mmu)?;
    let s1 = (vex.vvvv & 0x7) as usize;
    cpu.xmm[dst] = simd_op_apply(op, cpu.xmm[s1], s2l);
    cpu.ymm_high[dst] = simd_op_apply(op, cpu.ymm_high[s1], s2h);
    Ok(StepOk::Continued)
}

/// Variant selector for the `0F 70 /r ib` PSHUF family. The pp
/// slot picks one of three shapes; per-128-bit-lane semantics
/// applied independently across both halves of a YMM.
#[derive(Copy, Clone)]
enum ShufKind {
    /// VPSHUFD — imm8 selects 4 source dword indices (0..3) for
    /// the 4 destination dwords.
    Dwords,
    /// VPSHUFLW — imm8 selects 4 source word indices (0..3)
    /// for the 4 low destination words; high 64 bits copied
    /// through unchanged.
    LowWords,
    /// VPSHUFHW — symmetric: indices apply to the high 4 words.
    HighWords,
}

fn pshuf_lane_128(src: u128, kind: ShufKind, imm: u8) -> u128 {
    match kind {
        ShufKind::Dwords => {
            let mut out: u128 = 0;
            for lane in 0..4 {
                let sel = ((imm >> (lane * 2)) & 0x3) as u32;
                let src_dw = ((src >> (sel * 32)) & 0xFFFF_FFFF) as u32;
                out |= u128::from(src_dw) << (lane * 32);
            }
            out
        }
        ShufKind::LowWords => {
            // Low 64 bits = shuffled words 0..3 from src's low 64.
            let low = src & 0xFFFF_FFFF_FFFF_FFFF;
            let high = src & (u128::from(u64::MAX) << 64);
            let mut new_low: u128 = 0;
            for lane in 0..4 {
                let sel = ((imm >> (lane * 2)) & 0x3) as u32;
                let src_w = ((low >> (sel * 16)) & 0xFFFF) as u16;
                new_low |= u128::from(src_w) << (lane * 16);
            }
            high | new_low
        }
        ShufKind::HighWords => {
            let low_pass = src & 0xFFFF_FFFF_FFFF_FFFF;
            let high = (src >> 64) & 0xFFFF_FFFF_FFFF_FFFF;
            let mut new_high: u128 = 0;
            for lane in 0..4 {
                let sel = ((imm >> (lane * 2)) & 0x3) as u32;
                let src_w = ((high >> (sel * 16)) & 0xFFFF) as u16;
                new_high |= u128::from(src_w) << (lane * 16);
            }
            (new_high << 64) | low_pass
        }
    }
}

fn vpshuf_xmm(cpu: &mut Cpu, mmu: &Mmu, kind: ShufKind) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let src: u128 = match op {
        Operand::Reg32(_) => cpu.xmm[(mr.rm & 0x7) as usize],
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            let bs = mmu.read(addr, 16)?;
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bs);
            u128::from_le_bytes(buf)
        }
    };
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = pshuf_lane_128(src, kind, imm);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

fn vpshuf_ymm(cpu: &mut Cpu, mmu: &Mmu, kind: ShufKind) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let (low, high): (u128, u128) = match op {
        Operand::Reg32(_) => {
            let idx = (mr.rm & 0x7) as usize;
            (cpu.xmm[idx], cpu.ymm_high[idx])
        }
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            let lo = mmu.read(addr, 16)?;
            let hi = mmu.read(addr.wrapping_add(16), 16)?;
            let mut lb = [0u8; 16];
            let mut hb = [0u8; 16];
            lb.copy_from_slice(&lo);
            hb.copy_from_slice(&hi);
            (u128::from_le_bytes(lb), u128::from_le_bytes(hb))
        }
    };
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = pshuf_lane_128(low, kind, imm);
    cpu.ymm_high[dst] = pshuf_lane_128(high, kind, imm);
    Ok(StepOk::Continued)
}

/// Discriminator for the PAND / PANDN / POR / PXOR family, all
/// of which have the same VEX.NDS three-operand encoding and
/// only differ in the per-lane bitwise op.
#[derive(Copy, Clone)]
enum BitwiseOp {
    And,
    AndNot,
    Or,
    Xor,
}

fn bitwise_apply(op: BitwiseOp, a: u128, b: u128) -> u128 {
    match op {
        BitwiseOp::And => a & b,
        // PANDN encoding: dest = NOT(src1) AND src2 — src1 is
        // the vvvv operand, src2 is r/m.
        BitwiseOp::AndNot => (!a) & b,
        BitwiseOp::Or => a | b,
        BitwiseOp::Xor => a ^ b,
    }
}

fn vpbitwise_128(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex, op: BitwiseOp) -> Result<StepOk, Trap> {
    let (dst, src2) = read_xmm_dst_and_src2(cpu, mmu)?;
    let src1 = cpu.xmm[(vex.vvvv & 0x7) as usize];
    cpu.xmm[dst] = bitwise_apply(op, src1, src2);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

fn vpbitwise_256(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex, op: BitwiseOp) -> Result<StepOk, Trap> {
    let (dst, src2_low, src2_high) = read_ymm_dst_and_src2(cpu, mmu)?;
    let src1_idx = (vex.vvvv & 0x7) as usize;
    cpu.xmm[dst] = bitwise_apply(op, cpu.xmm[src1_idx], src2_low);
    cpu.ymm_high[dst] = bitwise_apply(op, cpu.ymm_high[src1_idx], src2_high);
    Ok(StepOk::Continued)
}

/// BMI2 shift variant — the four arithmetic shifts a single
/// opcode dispatches between based on the legacy-prefix slot.
#[derive(Copy, Clone)]
enum ShiftKind {
    /// SHLX (logical left).
    Shl,
    /// SHRX (logical right).
    Shr,
    /// SARX (arithmetic right).
    Sar,
}

/// `VEX.LZ.{66,F3,F2}.0F38.W0 F7 /r` — BMI2 SHLX / SHRX / SARX.
/// 32-bit GP-register operation; no flags touched.
fn bmi2_shift_x(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex, kind: ShiftKind) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let value = match op {
        Operand::Reg32(r) => cpu.regs.get32(r),
        Operand::Mem32(addr) => mmu.load32(cpu.seg_translate(addr))?,
    };
    let count = cpu.regs.get32(Reg32::from_bits(vex.vvvv & 0x7)) & 31;
    let dst = Reg32::from_bits(mr.reg & 0x7);
    let result = match kind {
        ShiftKind::Shl => value.wrapping_shl(count),
        ShiftKind::Shr => value.wrapping_shr(count),
        ShiftKind::Sar => (value as i32).wrapping_shr(count) as u32,
    };
    cpu.regs.set32(dst, result);
    Ok(StepOk::Continued)
}

/// `VEX.128.0F.WIG 11 /r` — VMOVUPS xmm2/m128, xmm1 (store).
/// `ModR/M.reg` is the **source** xmm; `r/m` is the destination
/// (register form zeroes the destination's YMM-upper-128;
/// memory form writes 16 bytes — no alignment requirement, this
/// is the "unaligned" variant).
fn vmovups_store_128(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let src = cpu.xmm[(mr.reg & 0x7) as usize];
    match op {
        Operand::Reg32(_) => {
            let dst = (mr.rm & 0x7) as usize;
            cpu.xmm[dst] = src;
            cpu.ymm_high[dst] = 0;
        }
        Operand::Mem32(addr) => {
            mmu.write(cpu.seg_translate(addr), &src.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

/// VEX-encoded Group 12 / 13 / 14 (imm8 SIMD shifts) all use the
/// same NDD shape: `mr.rm` is the source register, `vvvv` is the
/// destination, `mr.reg` is the sub-opcode selector, and an
/// `imm8` immediately follows the ModR/M byte. Memory operands
/// aren't encodable in these forms.
fn read_group_shift_operands(
    cpu: &mut Cpu,
    mmu: &Mmu,
    vex: &Vex,
) -> Result<(usize, u8, usize, u32), Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    // ModR/M.r/m is the source reg (mod = 11 is the only legal
    // encoding for these forms). We accept any mod and treat
    // r/m as the register index — this matches what every codec
    // assembler emits in practice.
    let src = (mr.rm & 0x7) as usize;
    let dst = (vex.vvvv & 0x7) as usize;
    let sub = mr.reg & 0x7;
    let imm = u32::from(cpu.fetch_imm8_pub(mmu)?);
    Ok((src, sub, dst, imm))
}

/// Per-lane shift kind for the Group 12/13/14 helpers.
#[derive(Copy, Clone)]
enum LaneShift {
    /// Right logical (`/2`).
    Srl,
    /// Right arithmetic (`/4`).
    Sra,
    /// Left logical (`/6`).
    Sll,
}

fn shift_lanes_u16(v: u128, kind: LaneShift, count: u32) -> u128 {
    if count >= 16 {
        return match kind {
            // Right-arithmetic saturates to sign-extended fill
            // when count >= bit width.
            LaneShift::Sra => {
                let mut out: u128 = 0;
                for lane in 0..8 {
                    let shift = lane * 16;
                    let aa = ((v >> shift) & 0xFFFF) as u16 as i16;
                    let mask: u128 = if aa < 0 { 0xFFFF } else { 0 };
                    out |= mask << shift;
                }
                out
            }
            _ => 0,
        };
    }
    let mut out: u128 = 0;
    for lane in 0..8 {
        let shift = lane * 16;
        let aa = ((v >> shift) & 0xFFFF) as u16;
        let rr: u16 = match kind {
            LaneShift::Sll => aa.wrapping_shl(count),
            LaneShift::Srl => aa.wrapping_shr(count),
            LaneShift::Sra => (aa as i16).wrapping_shr(count) as u16,
        };
        out |= u128::from(rr) << shift;
    }
    out
}

fn shift_lanes_u32(v: u128, kind: LaneShift, count: u32) -> u128 {
    if count >= 32 {
        return match kind {
            LaneShift::Sra => {
                let mut out: u128 = 0;
                for lane in 0..4 {
                    let shift = lane * 32;
                    let aa = ((v >> shift) & 0xFFFF_FFFF) as u32 as i32;
                    let mask: u128 = if aa < 0 { 0xFFFF_FFFF } else { 0 };
                    out |= mask << shift;
                }
                out
            }
            _ => 0,
        };
    }
    let mut out: u128 = 0;
    for lane in 0..4 {
        let shift = lane * 32;
        let aa = ((v >> shift) & 0xFFFF_FFFF) as u32;
        let rr: u32 = match kind {
            LaneShift::Sll => aa.wrapping_shl(count),
            LaneShift::Srl => aa.wrapping_shr(count),
            LaneShift::Sra => (aa as i32).wrapping_shr(count) as u32,
        };
        out |= u128::from(rr) << shift;
    }
    out
}

fn shift_lanes_u64(v: u128, kind: LaneShift, count: u32) -> u128 {
    if count >= 64 {
        return match kind {
            LaneShift::Sra => {
                let mut out: u128 = 0;
                for lane in 0..2 {
                    let shift = lane * 64;
                    let aa = ((v >> shift) & u128::from(u64::MAX)) as u64 as i64;
                    let mask: u128 = if aa < 0 { u128::from(u64::MAX) } else { 0 };
                    out |= mask << shift;
                }
                out
            }
            _ => 0,
        };
    }
    let mut out: u128 = 0;
    for lane in 0..2 {
        let shift = lane * 64;
        let aa = ((v >> shift) & u128::from(u64::MAX)) as u64;
        let rr: u64 = match kind {
            LaneShift::Sll => aa.wrapping_shl(count),
            LaneShift::Srl => aa.wrapping_shr(count),
            LaneShift::Sra => (aa as i64).wrapping_shr(count) as u64,
        };
        out |= u128::from(rr) << shift;
    }
    out
}

/// 128-bit byte shift used by PSLLDQ / PSRLDQ (Group 14 /7 /3):
/// shift the whole 128-bit value by `count` bytes (saturates at
/// 16 to produce zero).
fn shift_lanes_byte_128(v: u128, kind: LaneShift, count: u32) -> u128 {
    let bytes = count.min(16);
    let bits = bytes * 8;
    match kind {
        LaneShift::Sll => {
            if bits >= 128 {
                0
            } else {
                v << bits
            }
        }
        LaneShift::Srl => {
            if bits >= 128 {
                0
            } else {
                v >> bits
            }
        }
        // PSRADQ is not encoded.
        LaneShift::Sra => unreachable!("byte shift has no arithmetic form"),
    }
}

fn group12_kind(sub: u8) -> Result<LaneShift, Trap> {
    match sub {
        2 => Ok(LaneShift::Srl),
        4 => Ok(LaneShift::Sra),
        6 => Ok(LaneShift::Sll),
        _ => Err(Trap::UndefinedOpcode {
            eip: 0,
            opcode: 0x71_0000 | u32::from(sub),
        }),
    }
}

fn group13_kind(sub: u8) -> Result<LaneShift, Trap> {
    match sub {
        2 => Ok(LaneShift::Srl),
        4 => Ok(LaneShift::Sra),
        6 => Ok(LaneShift::Sll),
        _ => Err(Trap::UndefinedOpcode {
            eip: 0,
            opcode: 0x72_0000 | u32::from(sub),
        }),
    }
}

fn vex_group12_xmm(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (src, sub, dst, imm) = read_group_shift_operands(cpu, mmu, vex)?;
    let kind = group12_kind(sub)?;
    cpu.xmm[dst] = shift_lanes_u16(cpu.xmm[src], kind, imm);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

fn vex_group12_ymm(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (src, sub, dst, imm) = read_group_shift_operands(cpu, mmu, vex)?;
    let kind = group12_kind(sub)?;
    cpu.xmm[dst] = shift_lanes_u16(cpu.xmm[src], kind, imm);
    cpu.ymm_high[dst] = shift_lanes_u16(cpu.ymm_high[src], kind, imm);
    Ok(StepOk::Continued)
}

fn vex_group13_xmm(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (src, sub, dst, imm) = read_group_shift_operands(cpu, mmu, vex)?;
    let kind = group13_kind(sub)?;
    cpu.xmm[dst] = shift_lanes_u32(cpu.xmm[src], kind, imm);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

fn vex_group13_ymm(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (src, sub, dst, imm) = read_group_shift_operands(cpu, mmu, vex)?;
    let kind = group13_kind(sub)?;
    cpu.xmm[dst] = shift_lanes_u32(cpu.xmm[src], kind, imm);
    cpu.ymm_high[dst] = shift_lanes_u32(cpu.ymm_high[src], kind, imm);
    Ok(StepOk::Continued)
}

fn vex_group14_xmm(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (src, sub, dst, imm) = read_group_shift_operands(cpu, mmu, vex)?;
    let result = match sub {
        2 => shift_lanes_u64(cpu.xmm[src], LaneShift::Srl, imm),
        6 => shift_lanes_u64(cpu.xmm[src], LaneShift::Sll, imm),
        3 => shift_lanes_byte_128(cpu.xmm[src], LaneShift::Srl, imm), // PSRLDQ
        7 => shift_lanes_byte_128(cpu.xmm[src], LaneShift::Sll, imm), // PSLLDQ
        _ => {
            return Err(Trap::UndefinedOpcode {
                eip: 0,
                opcode: 0x73_0000 | u32::from(sub),
            })
        }
    };
    cpu.xmm[dst] = result;
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

fn vex_group14_ymm(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (src, sub, dst, imm) = read_group_shift_operands(cpu, mmu, vex)?;
    let (low, high) = match sub {
        2 => (
            shift_lanes_u64(cpu.xmm[src], LaneShift::Srl, imm),
            shift_lanes_u64(cpu.ymm_high[src], LaneShift::Srl, imm),
        ),
        6 => (
            shift_lanes_u64(cpu.xmm[src], LaneShift::Sll, imm),
            shift_lanes_u64(cpu.ymm_high[src], LaneShift::Sll, imm),
        ),
        // PSRLDQ / PSLLDQ in the 256-bit form shift each 128-bit
        // lane independently — *not* the whole 256-bit value.
        3 => (
            shift_lanes_byte_128(cpu.xmm[src], LaneShift::Srl, imm),
            shift_lanes_byte_128(cpu.ymm_high[src], LaneShift::Srl, imm),
        ),
        7 => (
            shift_lanes_byte_128(cpu.xmm[src], LaneShift::Sll, imm),
            shift_lanes_byte_128(cpu.ymm_high[src], LaneShift::Sll, imm),
        ),
        _ => {
            return Err(Trap::UndefinedOpcode {
                eip: 0,
                opcode: 0x73_0000 | u32::from(sub),
            })
        }
    };
    cpu.xmm[dst] = low;
    cpu.ymm_high[dst] = high;
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.WIG 6F /r` — VMOVDQA xmm1, xmm2/m128 (load).
/// VEX.128 zeroes the upper 128 of the destination YMM.
fn vmovdqa_load_128(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let (dst, src2) = read_xmm_dst_and_src2(cpu, mmu)?;
    cpu.xmm[dst] = src2;
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.WIG 7F /r` — VMOVDQA xmm2/m128, xmm1 (store).
/// `ModR/M.reg` is the *source*. Register form zeroes the
/// destination's upper YMM-128.
fn vmovdqa_store_128(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let src = cpu.xmm[(mr.reg & 0x7) as usize];
    match op {
        Operand::Reg32(_) => {
            let dst = (mr.rm & 0x7) as usize;
            cpu.xmm[dst] = src;
            cpu.ymm_high[dst] = 0;
        }
        Operand::Mem32(addr) => {
            mmu.write(cpu.seg_translate(addr), &src.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

/// `VEX.128.NP.0F.WIG 77` — VZEROUPPER. No operands; just
/// clear the upper 128 of every YMM register.
fn vzeroupper(cpu: &mut Cpu) -> Result<StepOk, Trap> {
    cpu.ymm_high = [0u128; 8];
    Ok(StepOk::Continued)
}

/// Source-lane width selector for the VPBROADCAST family.
#[derive(Copy, Clone)]
enum BroadcastKind {
    B,
    W,
    D,
    Q,
}

/// Common VPBROADCAST{B,W,D,Q} helper. Reads a single lane from
/// the source (low lane of an xmm register or `mN` bytes from
/// memory), then fills the destination by repetition. When the
/// VEX.L bit is set, both 128-bit halves of the destination
/// YMM receive the same filled value.
fn vpbroadcast(
    cpu: &mut Cpu,
    mmu: &Mmu,
    kind: BroadcastKind,
    is_256: bool,
) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let dst = (mr.reg & 0x7) as usize;
    let lane: u128 = match (op, kind) {
        (Operand::Reg32(_), BroadcastKind::B) => cpu.xmm[(mr.rm & 0x7) as usize] & 0xFF,
        (Operand::Reg32(_), BroadcastKind::W) => cpu.xmm[(mr.rm & 0x7) as usize] & 0xFFFF,
        (Operand::Reg32(_), BroadcastKind::D) => cpu.xmm[(mr.rm & 0x7) as usize] & 0xFFFF_FFFF,
        (Operand::Reg32(_), BroadcastKind::Q) => {
            cpu.xmm[(mr.rm & 0x7) as usize] & ((1u128 << 64) - 1)
        }
        (Operand::Mem32(addr), BroadcastKind::B) => {
            let addr = cpu.seg_translate(addr);
            u128::from(mmu.read(addr, 1)?[0])
        }
        (Operand::Mem32(addr), BroadcastKind::W) => {
            let addr = cpu.seg_translate(addr);
            let b = mmu.read(addr, 2)?;
            u128::from(u16::from_le_bytes([b[0], b[1]]))
        }
        (Operand::Mem32(addr), BroadcastKind::D) => {
            let addr = cpu.seg_translate(addr);
            u128::from(mmu.load32(addr)?)
        }
        (Operand::Mem32(addr), BroadcastKind::Q) => {
            let addr = cpu.seg_translate(addr);
            u128::from(mmu.load64(addr)?)
        }
    };
    let low = match kind {
        BroadcastKind::B => {
            let v = lane as u8;
            from_lanes_u8([v; 16])
        }
        BroadcastKind::W => {
            let v = lane as u16;
            from_lanes_u16([v; 8])
        }
        BroadcastKind::D => {
            let v = lane as u32;
            from_lanes_u32([v; 4])
        }
        BroadcastKind::Q => {
            let v = lane as u64;
            from_lanes_u64([v; 2])
        }
    };
    cpu.xmm[dst] = low;
    cpu.ymm_high[dst] = if is_256 { low } else { 0 };
    Ok(StepOk::Continued)
}

/// `VEX.256.66.0F38.W0 5A /r` — VBROADCASTI128 ymm, m128.
/// Replicates a 128-bit memory operand into both halves of the
/// destination YMM. There is no register form.
fn vbroadcasti128(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let v: u128 = match op {
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            let bs = mmu.read(addr, 16)?;
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bs);
            u128::from_le_bytes(buf)
        }
        Operand::Reg32(_) => {
            return Err(Trap::UndefinedOpcode {
                eip: cpu.regs.eip.wrapping_sub(consumed as u32 + 3),
                opcode: 0x0F38_5A_00,
            })
        }
    };
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = v;
    cpu.ymm_high[dst] = v;
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.W0 6E /r` — VMOVD xmm1, r/m32. Loads 32 bits
/// into the low lane, zeroes the rest of the destination YMM.
fn vmovd_load(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let value: u32 = match op {
        Operand::Reg32(r) => cpu.regs.get32(r),
        Operand::Mem32(addr) => mmu.load32(cpu.seg_translate(addr))?,
    };
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = u128::from(value);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.W0 7E /r` — VMOVD r/m32, xmm1. Stores the
/// low 32 of xmm1 to the GP destination.
fn vmovd_store(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let value = cpu.xmm[(mr.reg & 0x7) as usize] as u32;
    match op {
        Operand::Reg32(r) => cpu.regs.set32(r, value),
        Operand::Mem32(addr) => mmu.store32(cpu.seg_translate(addr), value)?,
    }
    Ok(StepOk::Continued)
}

/// `VEX.128.F3.0F.WIG 7E /r` — VMOVQ xmm1, xmm2/m64. Loads 64
/// bits into the low lane; rest zero.
fn vmovq_load(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let low: u64 = match op {
        Operand::Reg32(_) => cpu.xmm[(mr.rm & 0x7) as usize] as u64,
        Operand::Mem32(addr) => mmu.load64(cpu.seg_translate(addr))?,
    };
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = u128::from(low);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.WIG D6 /r` — VMOVQ xmm2/m64, xmm1. Stores
/// low 64 of xmm1.
fn vmovq_store(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let low = cpu.xmm[(mr.reg & 0x7) as usize] as u64;
    match op {
        Operand::Reg32(_) => {
            let dst = (mr.rm & 0x7) as usize;
            cpu.xmm[dst] = u128::from(low);
            cpu.ymm_high[dst] = 0;
        }
        Operand::Mem32(addr) => {
            mmu.write(cpu.seg_translate(addr), &low.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

fn vpextrb_128(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let lane = (imm & 0xF) as usize;
    let v = cpu.xmm[(mr.reg & 0x7) as usize].to_le_bytes()[lane];
    match op {
        Operand::Reg32(r) => cpu.regs.set32(r, u32::from(v)),
        Operand::Mem32(addr) => mmu.write(cpu.seg_translate(addr), &[v])?,
    }
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.W0 C5 /r ib` — VPEXTRW r32, xmm, imm8.
fn vpextrw_imm_128(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    // r/m must be reg form for this encoding.
    let _bytes = cpu.peek_after_modrm(mmu, 16)?;
    cpu.advance_eip(1);
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let lane = (imm & 0x7) as usize;
    let words = lanes_u16(cpu.xmm[(mr.rm & 0x7) as usize]);
    cpu.regs
        .set32(Reg32::from_bits(mr.reg & 0x7), u32::from(words[lane]));
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F3A.W0 15 /r ib` — VPEXTRW r/m16, xmm, imm8.
fn vpextrw_mem_128(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let lane = (imm & 0x7) as usize;
    let words = lanes_u16(cpu.xmm[(mr.reg & 0x7) as usize]);
    let v = words[lane];
    match op {
        Operand::Reg32(r) => cpu.regs.set32(r, u32::from(v)),
        Operand::Mem32(addr) => {
            mmu.write(cpu.seg_translate(addr), &v.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F3A.W0 16 /r ib` — VPEXTRD r/m32, xmm, imm8.
fn vpextrd_128(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let lane = (imm & 0x3) as usize;
    let dwords = lanes_u32(cpu.xmm[(mr.reg & 0x7) as usize]);
    let v = dwords[lane];
    match op {
        Operand::Reg32(r) => cpu.regs.set32(r, v),
        Operand::Mem32(addr) => mmu.store32(cpu.seg_translate(addr), v)?,
    }
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.WIG D7 /r` — VPMOVMSKB r32, xmm. Extract the
/// MSB of each byte lane into a GP register.
fn vpmovmskb_128(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let _bytes = cpu.peek_after_modrm(mmu, 16)?;
    cpu.advance_eip(1);
    let bs = cpu.xmm[(mr.rm & 0x7) as usize].to_le_bytes();
    let mut mask: u32 = 0;
    for (i, b) in bs.iter().enumerate() {
        if (*b) & 0x80 != 0 {
            mask |= 1u32 << i;
        }
    }
    cpu.regs.set32(Reg32::from_bits(mr.reg & 0x7), mask);
    Ok(StepOk::Continued)
}

/// `VEX.256.66.0F.WIG D7 /r` — VPMOVMSKB r32, ymm.
fn vpmovmskb_256(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let _bytes = cpu.peek_after_modrm(mmu, 16)?;
    cpu.advance_eip(1);
    let idx = (mr.rm & 0x7) as usize;
    let low = cpu.xmm[idx].to_le_bytes();
    let high = cpu.ymm_high[idx].to_le_bytes();
    let mut mask: u32 = 0;
    for (i, b) in low.iter().enumerate() {
        if (*b) & 0x80 != 0 {
            mask |= 1u32 << i;
        }
    }
    for (i, b) in high.iter().enumerate() {
        if (*b) & 0x80 != 0 {
            mask |= 1u32 << (i + 16);
        }
    }
    cpu.regs.set32(Reg32::from_bits(mr.reg & 0x7), mask);
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F3A.W0 20 /r ib` — VPINSRB xmm1, xmm2, r32/m8, imm8.
fn vpinsrb_128(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let value: u8 = match op {
        Operand::Reg32(r) => cpu.regs.get32(r) as u8,
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            mmu.read(addr, 1)?[0]
        }
    };
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let lane = (imm & 0xF) as u32;
    let src1 = (vex.vvvv & 0x7) as usize;
    let mut bs = cpu.xmm[src1].to_le_bytes();
    bs[lane as usize] = value;
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = u128::from_le_bytes(bs);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// `VEX.128.66.0F.W0 C4 /r ib` — VPINSRW xmm1, xmm2, r32/m16, imm8.
fn vpinsrw_128(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let value: u16 = match op {
        Operand::Reg32(r) => cpu.regs.get32(r) as u16,
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            let b = mmu.read(addr, 2)?;
            u16::from_le_bytes([b[0], b[1]])
        }
    };
    let imm = cpu.fetch_imm8_pub(mmu)?;
    let lane = (imm & 0x7) as u32;
    let src1 = (vex.vvvv & 0x7) as usize;
    let mut words = lanes_u16(cpu.xmm[src1]);
    words[lane as usize] = value;
    let dst = (mr.reg & 0x7) as usize;
    cpu.xmm[dst] = from_lanes_u16(words);
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// `VEX.128.NP.0F.WIG 10/28 /r` — VMOVUPS/VMOVAPS xmm1, xmm2/m128.
fn vmovaps_load_128(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let (dst, src2) = read_xmm_dst_and_src2(cpu, mmu)?;
    cpu.xmm[dst] = src2;
    cpu.ymm_high[dst] = 0;
    Ok(StepOk::Continued)
}

/// `VEX.128.NP.0F.WIG 29 /r` — VMOVAPS xmm2/m128, xmm1 (store).
fn vmovaps_store_128(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let src = cpu.xmm[(mr.reg & 0x7) as usize];
    match op {
        Operand::Reg32(_) => {
            let dst = (mr.rm & 0x7) as usize;
            cpu.xmm[dst] = src;
            cpu.ymm_high[dst] = 0;
        }
        Operand::Mem32(addr) => {
            mmu.write(cpu.seg_translate(addr), &src.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

/// `VEX.256.NP.0F.WIG 10/28 /r` — VMOVUPS/VMOVAPS ymm load.
fn vmovaps_load_256(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let (dst, low, high) = read_ymm_dst_and_src2(cpu, mmu)?;
    cpu.xmm[dst] = low;
    cpu.ymm_high[dst] = high;
    Ok(StepOk::Continued)
}

/// `VEX.256.NP.0F.WIG 11/29 /r` — VMOVUPS/VMOVAPS ymm store.
fn vmovups_store_256(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let src = (mr.reg & 0x7) as usize;
    let low = cpu.xmm[src];
    let high = cpu.ymm_high[src];
    match op {
        Operand::Reg32(_) => {
            let dst = (mr.rm & 0x7) as usize;
            cpu.xmm[dst] = low;
            cpu.ymm_high[dst] = high;
        }
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            mmu.write(addr, &low.to_le_bytes())?;
            mmu.write(addr.wrapping_add(16), &high.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

/// Resolve `(dst_idx, src2_value_low, src2_value_high)` for a
/// 256-bit YMM "VEX 3-op SSE-shape" instruction.
fn read_ymm_dst_and_src2(cpu: &mut Cpu, mmu: &Mmu) -> Result<(usize, u128, u128), Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let dst = (mr.reg & 0x7) as usize;
    let (low, high) = match op {
        Operand::Reg32(_) => {
            let idx = (mr.rm & 0x7) as usize;
            (cpu.xmm[idx], cpu.ymm_high[idx])
        }
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            let bs_low = mmu.read(addr, 16)?;
            let bs_high = mmu.read(addr.wrapping_add(16), 16)?;
            let mut low = [0u8; 16];
            let mut high = [0u8; 16];
            low.copy_from_slice(&bs_low);
            high.copy_from_slice(&bs_high);
            (u128::from_le_bytes(low), u128::from_le_bytes(high))
        }
    };
    Ok((dst, low, high))
}

/// `VEX.256.66.0F.WIG 76 /r` — VPCMPEQD ymm1, ymm2, ymm3/m256.
/// Compares each 32-bit lane of `src1` and `src2`; equal lanes
/// in `dst` become all-ones, others zero.
fn vpcmpeqd_256(cpu: &mut Cpu, mmu: &Mmu, vex: &Vex) -> Result<StepOk, Trap> {
    let (dst, src2_low, src2_high) = read_ymm_dst_and_src2(cpu, mmu)?;
    let src1_idx = (vex.vvvv & 0x7) as usize;
    let src1_low = cpu.xmm[src1_idx];
    let src1_high = cpu.ymm_high[src1_idx];
    cpu.xmm[dst] = pcmpeqd_lanes_128(src1_low, src2_low);
    cpu.ymm_high[dst] = pcmpeqd_lanes_128(src1_high, src2_high);
    Ok(StepOk::Continued)
}

/// Per-32-bit-lane PCMPEQD on two 128-bit halves.
fn pcmpeqd_lanes_128(a: u128, b: u128) -> u128 {
    let mut out: u128 = 0;
    for lane in 0..4 {
        let shift = lane * 32;
        let aa = ((a >> shift) & 0xFFFF_FFFF) as u32;
        let bb = ((b >> shift) & 0xFFFF_FFFF) as u32;
        let mask: u128 = if aa == bb { 0xFFFF_FFFF } else { 0 };
        out |= mask << shift;
    }
    out
}

/// `VEX.256.66.0F.WIG 6F /r` — VMOVDQA ymm1, ymm2/m256 (load).
fn vmovdqa_load_256(cpu: &mut Cpu, mmu: &Mmu) -> Result<StepOk, Trap> {
    let (dst, low, high) = read_ymm_dst_and_src2(cpu, mmu)?;
    cpu.xmm[dst] = low;
    cpu.ymm_high[dst] = high;
    Ok(StepOk::Continued)
}

/// `VEX.256.66.0F.WIG 7F /r` — VMOVDQA ymm2/m256, ymm1 (store).
/// `ModR/M.reg` is the *source* ymm. MagicYUV uses
/// `vmovdqa [mem], ymm0` (with ymm0 freshly all-ones or
/// all-zero) to seed 32-byte runs in its working buffers.
fn vmovdqa_store_256(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let src = (mr.reg & 0x7) as usize;
    let low = cpu.xmm[src];
    let high = cpu.ymm_high[src];
    match op {
        Operand::Reg32(_) => {
            let dst = (mr.rm & 0x7) as usize;
            cpu.xmm[dst] = low;
            cpu.ymm_high[dst] = high;
        }
        Operand::Mem32(addr) => {
            let addr = cpu.seg_translate(addr);
            mmu.write(addr, &low.to_le_bytes())?;
            mmu.write(addr.wrapping_add(16), &high.to_le_bytes())?;
        }
    }
    Ok(StepOk::Continued)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vex_c5_decode_pp_l_vvvv() {
        // 2-byte VEX: 1110 0001 -> R̅=1, vvvv̅=1100 (architectural
        // vvvv = ~1100 & 0xF = 0011 = 3), L=0, pp=01 (66).
        let v = Vex::from_c5(0b1110_0001);
        assert_eq!(v.map, 1);
        assert_eq!(v.pp, 1);
        assert_eq!(v.l, 0);
        assert_eq!(v.vvvv, 3);
        assert!(!v.w);
    }

    #[test]
    fn vex_c4_decode_w_map() {
        // 3-byte VEX:
        //   byte1 = R̅ X̅ B̅ mmmmm  = 1 1 1 00010 -> map = 2 (0F 38)
        //   byte2 = W vvvv̅ L pp   = 1 1010 1 11 -> W=1,
        //         vvvv̅ = 1010 -> architectural vvvv = 0101 = 5,
        //         L=1, pp=11 (F2).
        let v = Vex::from_c4(0b1110_0010, 0b1101_0111);
        assert_eq!(v.map, 2);
        assert_eq!(v.pp, 3);
        assert_eq!(v.l, 1);
        assert!(v.w);
        assert_eq!(v.vvvv, 5);
    }

    #[test]
    fn vex_opcode_id_round_trip() {
        let v = Vex {
            map: 3,
            pp: 2,
            l: 1,
            w: true,
            vvvv: 0xA,
        };
        let id = vex_opcode_id(&v, 0x58);
        assert_eq!(id & 0xFF, 0x58);
        assert_eq!((id >> 8) & 1, 1);
        assert_eq!((id >> 9) & 0x3, 2);
        assert_eq!((id >> 11) & 0x7, 3);
        assert_eq!((id >> 14) & 0xF, 0xA);
    }
}

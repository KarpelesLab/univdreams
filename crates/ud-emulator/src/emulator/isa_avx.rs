//! AVX (VEX-encoded) instruction executor.
//!
//! Routed from [`super::isa_int::Cpu::dispatch`] when a `0xC4`
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

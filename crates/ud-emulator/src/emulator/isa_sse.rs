//! SSE / SSE2 instruction executor.
//!
//! Routed from [`super::isa_int::Cpu::dispatch_0f`] for the
//! second-byte ranges that overlap the SSE encoding space:
//!
//! ```text
//!   0F 10..1F        MOVUPS / MOVSS / MOVLPS / MOVHLPS / …
//!   0F 28..2F        MOVAPS / CVT* / UCOMISS / COMISS
//!   0F 50..5F        MOVMSKPS + math (SQRT / RCP / RSQRT /
//!                                     AND / OR / XOR / ANDN /
//!                                     ADD / MUL / SUB / MIN /
//!                                     DIV / MAX / CMP / CVT)
//!   0F C2/C4..C6     CMPPS / PINSRW / PEXTRW / SHUFPS
//! ```
//!
//! The 0x66 / 0xF2 / 0xF3 mandatory prefixes select between
//! lane widths (PS / PD / SS / SD); we track those in
//! [`super::isa_int::Cpu`]'s prefix state ([`Cpu::op_size_16`]
//! for `0x66`, [`Cpu::rep_prefix`] for `0xF2` / `0xF3`).
//!
//! New opcodes are added trace-driven: when a real codec
//! traps with `UndefinedOpcode { opcode: 0xF?? }`, look up the
//! mnemonic in the Intel SDM and add a match arm here.
//!
//! Reference: Intel® 64 and IA-32 Architectures Software
//! Developer's Manual, Volume 2A/2B per-instruction pages.

use super::decode::{resolve_modrm32, Operand};
use super::isa_int::{Cpu, StepOk};
use super::mmu::Mmu;
use super::Trap;

/// Discriminator for the SSE mandatory prefix attached to the
/// current instruction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SsePrefix {
    /// "No prefix" — packed-single semantics (PS).
    Np,
    /// `0x66` — packed-double semantics (PD).
    P66,
    /// `0xF3` — scalar-single semantics (SS).
    Pf3,
    /// `0xF2` — scalar-double semantics (SD).
    Pf2,
}

impl SsePrefix {
    fn current(cpu: &Cpu) -> Self {
        match (cpu.op_size_16(), cpu.rep_prefix_byte()) {
            (true, _) => SsePrefix::P66,
            (false, Some(0xF3)) => SsePrefix::Pf3,
            (false, Some(0xF2)) => SsePrefix::Pf2,
            _ => SsePrefix::Np,
        }
    }
}

/// Encode an SSE opcode for [`Trap::UndefinedOpcode`] reporting.
/// Includes the second byte and the mandatory prefix so the
/// trap log is unambiguous.
fn opcode_id(op2: u8, pfx: SsePrefix) -> u32 {
    let pfx_bits = match pfx {
        SsePrefix::Np => 0x0000,
        SsePrefix::P66 => 0x6600,
        SsePrefix::Pf3 => 0xF300,
        SsePrefix::Pf2 => 0xF200,
    };
    pfx_bits | 0x0F00 | u32::from(op2)
}

/// Dispatch a single SSE-encoded instruction. The `0x0F` byte
/// has already been consumed; `op2` is the second byte.
pub fn dispatch(cpu: &mut Cpu, mmu: &mut Mmu, op2: u8, entry_eip: u32) -> Result<StepOk, Trap> {
    cpu.sse_dispatch_count = cpu.sse_dispatch_count.wrapping_add(1);
    let pfx = SsePrefix::current(cpu);
    match (op2, pfx) {
        // 0F 12 /r — without prefix: MOVLPS / MOVHLPS.
        //   mod = 11 (register form): MOVHLPS xmm1, xmm2 — low 64
        //     of xmm1 := high 64 of xmm2.
        //   mod != 11 (memory form):   MOVLPS xmm, m64 — low 64
        //     of xmm := [mem]; high 64 unchanged.
        (0x12, SsePrefix::Np) => movlps_or_movhlps(cpu, mmu),
        // 0F 13 /r — MOVLPS m64, xmm (store low 64 to memory).
        // Reg form is reserved / not encoded.
        (0x13, SsePrefix::Np) => movlps_store(cpu, mmu),
        // 0F 17 /r — MOVHPS m64, xmm (store high 64 to memory).
        // Reg form reserved.
        (0x17, SsePrefix::Np) => movhps_store(cpu, mmu),
        // 0F 16 /r — without prefix: MOVHPS / MOVLHPS.
        //   mod = 11 (register form): MOVLHPS xmm1, xmm2 — high 64
        //     of xmm1 := low 64 of xmm2.
        //   mod != 11 (memory form):   MOVHPS xmm, m64 — high 64
        //     of xmm := [mem]; low 64 unchanged.
        (0x16, SsePrefix::Np) => movhps_or_movlhps(cpu, mmu),

        _ => Err(Trap::UndefinedOpcode {
            eip: entry_eip,
            opcode: opcode_id(op2, pfx),
        }),
    }
}

// ============================================================
// Per-instruction implementations
// ============================================================

/// `0F 12 /r` (no prefix). The `mod` field of the ModR/M byte
/// selects between MOVHLPS (register form) and MOVLPS (memory).
fn movlps_or_movhlps(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let dst_idx = (mr.reg & 0x7) as usize;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let new_low: u64 = match op {
        Operand::Reg32(_) => {
            // MOVHLPS — `r/m` encodes xmm[r/m]; we use its
            // high 64 bits.
            let src = cpu.xmm[(mr.rm & 0x7) as usize];
            (src >> 64) as u64
        }
        Operand::Mem32(addr) => {
            // MOVLPS — load 8 bytes from memory.
            mmu.load64(cpu.seg_translate(addr))?
        }
    };
    let prev = cpu.xmm[dst_idx];
    let high = (prev >> 64) as u64;
    cpu.xmm[dst_idx] = pack_lh(new_low, high);
    Ok(StepOk::Continued)
}

/// `0F 13 /r` (no prefix) — `MOVLPS m64, xmm`. Stores the low
/// 64 bits of the xmm register to the memory operand. The
/// register form (`mod = 11`) is reserved — Intel SDM lists no
/// encoding — so we trap it as a sub-opcode.
fn movlps_store(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let addr = match op {
        Operand::Mem32(a) => cpu.seg_translate(a),
        Operand::Reg32(_) => {
            return Err(Trap::UndefinedOpcode {
                eip: cpu.regs.eip.wrapping_sub(consumed as u32 + 2),
                opcode: 0x0F13,
            });
        }
    };
    let low = cpu.xmm[(mr.reg & 0x7) as usize] as u64;
    mmu.write(addr, &low.to_le_bytes())?;
    Ok(StepOk::Continued)
}

/// `0F 17 /r` (no prefix) — `MOVHPS m64, xmm`. Symmetric of
/// [`movlps_store`] for the high 64 bits.
fn movhps_store(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let addr = match op {
        Operand::Mem32(a) => cpu.seg_translate(a),
        Operand::Reg32(_) => {
            return Err(Trap::UndefinedOpcode {
                eip: cpu.regs.eip.wrapping_sub(consumed as u32 + 2),
                opcode: 0x0F17,
            });
        }
    };
    let high = (cpu.xmm[(mr.reg & 0x7) as usize] >> 64) as u64;
    mmu.write(addr, &high.to_le_bytes())?;
    Ok(StepOk::Continued)
}

/// `0F 16 /r` (no prefix). Symmetric counterpart of
/// [`movlps_or_movhlps`] — the `mod` field selects MOVLHPS
/// (register) vs MOVHPS (memory), and both write the high 64
/// bits.
fn movhps_or_movlhps(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let dst_idx = (mr.reg & 0x7) as usize;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.advance_eip(consumed as u32);
    let new_high: u64 = match op {
        Operand::Reg32(_) => {
            // MOVLHPS — `r/m` encodes xmm[r/m]; use its low 64.
            cpu.xmm[(mr.rm & 0x7) as usize] as u64
        }
        Operand::Mem32(addr) => mmu.load64(cpu.seg_translate(addr))?,
    };
    let prev = cpu.xmm[dst_idx];
    let low = prev as u64;
    cpu.xmm[dst_idx] = pack_lh(low, new_high);
    Ok(StepOk::Continued)
}

// ============================================================
// Helpers
// ============================================================

/// Pack two 64-bit halves into a 128-bit XMM value
/// (`low` at bits [63:0], `high` at bits [127:64]).
#[inline]
fn pack_lh(low: u64, high: u64) -> u128 {
    (u128::from(high) << 64) | u128::from(low)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::mmu::Perm;
    use crate::emulator::regs::Reg32;

    fn make_cpu() -> (Cpu, Mmu) {
        let mut mmu = Mmu::new();
        mmu.map(0x1000, 0x1000, Perm::R | Perm::W | Perm::X);
        let cpu = Cpu::new();
        (cpu, mmu)
    }

    /// `0F 12 C1` — MOVHLPS xmm0, xmm1: low 64 of xmm0 := high
    /// 64 of xmm1. High 64 of xmm0 is unchanged.
    #[test]
    fn movhlps_copies_high_half_into_low_half() {
        let (mut cpu, mut mmu) = make_cpu();
        cpu.regs.eip = 0x1000;
        cpu.xmm[0] = pack_lh(0xAAAA_AAAA_AAAA_AAAA, 0xDEAD_BEEF_DEAD_BEEF);
        cpu.xmm[1] = pack_lh(0x1111_1111_1111_1111, 0xCAFE_F00D_CAFE_F00D);
        // 0F 12 C1 = MOVHLPS xmm0, xmm1
        mmu.write_initializer(0x1000, &[0x0F, 0x12, 0xC1]).unwrap();
        let _ = cpu.step(&mut mmu).unwrap();
        assert_eq!(cpu.xmm[0] as u64, 0xCAFE_F00D_CAFE_F00D);
        assert_eq!((cpu.xmm[0] >> 64) as u64, 0xDEAD_BEEF_DEAD_BEEF);
        assert_eq!(cpu.sse_dispatch_count, 1);
    }

    /// `0F 12 06` — MOVLPS xmm0, [esi]: low 64 of xmm0 :=
    /// [esi]; high 64 of xmm0 unchanged.
    #[test]
    fn movlps_loads_low_half_from_memory() {
        let (mut cpu, mut mmu) = make_cpu();
        // Map a separate data page so the load doesn't read the
        // code stream.
        mmu.map(0x4000, 0x1000, Perm::R | Perm::W);
        let payload = 0x0123_4567_89AB_CDEF_u64;
        mmu.write_initializer(0x4000, &payload.to_le_bytes())
            .unwrap();
        cpu.regs.eip = 0x1000;
        cpu.regs.set32(Reg32::Esi, 0x4000);
        cpu.xmm[0] = pack_lh(0xAAAA_AAAA_AAAA_AAAA, 0xBBBB_BBBB_BBBB_BBBB);
        // 0F 12 06 = MOVLPS xmm0, [esi]
        mmu.write_initializer(0x1000, &[0x0F, 0x12, 0x06]).unwrap();
        let _ = cpu.step(&mut mmu).unwrap();
        assert_eq!(cpu.xmm[0] as u64, payload);
        assert_eq!((cpu.xmm[0] >> 64) as u64, 0xBBBB_BBBB_BBBB_BBBB);
    }
}

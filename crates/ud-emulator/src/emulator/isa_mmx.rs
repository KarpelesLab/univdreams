//! MMX instruction set executor (round-13 milestone).
//!
//! Round 7 scaffolded the MMX opcode space — `0F 60..6F`,
//! `0F 70..7F`, `0F D0..FF` — into a structured trap that
//! advances EIP past the instruction body so the trap log reads
//! as a clean to-do list. Round 13 lands the actual semantics
//! opcode-by-opcode.
//!
//! ## Scope
//!
//! The set covered here is the working subset Intel's
//! `IR50_32.DLL` exercises during the Indeo 5 P-frame decode
//! body of `cat_attack.avi`:
//!
//! * Move family — `MOVD`, `MOVQ`.
//! * Bitwise — `PXOR`, `PAND`, `PANDN`, `POR`, `EMMS`.
//! * Pack / unpack — `PUNPCKL{BW,WD,DQ}`, `PUNPCKH{BW,WD,DQ}`,
//!   `PACK{SSWB,SSDW,USWB}`.
//! * Arithmetic — `PADD{B,W,D,Q}`, `PSUB{B,W,D,Q}`,
//!   `PMULLW`, `PMULHW`, `PMADDWD`.
//! * Saturating arithmetic — `PADDS{B,W}`, `PSUBS{B,W}`,
//!   `PADDUS{B,W}`, `PSUBUS{B,W}`.
//! * Shifts — `PSL{LW,LD,LQ}` / `PSR{LW,LD,LQ}` / `PSR{AW,AD}`
//!   in both register-source and imm8 (group-12/13/14) forms.
//! * Compares — `PCMPEQ{B,W,D}`, `PCMPGT{B,W,D}`.
//! * Average — `PAVGB`, `PAVGW`.
//!
//! Each instruction is implemented from the Intel® 64 and IA-32
//! Architectures Software Developer's Manual, Volume 2A/2B
//! per-instruction reference. The tables below give the byte
//! mapping; if a real codec exercises an opcode we trap on,
//! adding a case is mechanical.
//!
//! Reference: Intel SDM Vol. 2A §2.1.5 (ModR/M) + Vol. 2A/2B
//! per-instruction pages (`PADDB` … `PXOR`).

use super::decode::{resolve_modrm32, ModRm, Operand};
use super::isa_int::{mmx_mnemonic, Cpu, StepOk};
use super::mmu::Mmu;
use super::Trap;

/// Resolve the (mm-reg, mm/m64) pair from a ModR/M byte for an
/// MMX instruction. Returns `(reg_idx, source_value)`. If the
/// `r/m` field is a memory operand, reads 8 bytes from the
/// effective address; if it's a register, returns the corresponding
/// `mm[r/m]` value.
///
/// `consumed` accounts for any SIB / displacement bytes; the
/// caller advances EIP by that amount.
fn read_modrm_mm_src(cpu: &mut Cpu, mmu: &Mmu, mr: ModRm) -> Result<(u8, u64, usize), Trap> {
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    let src = match op {
        Operand::Reg32(_) => {
            // For register-form, r/m encodes mm[r/m].
            cpu.mmx[mr.rm as usize]
        }
        Operand::Mem32(addr) => mmu.load64(cpu.seg_translate(addr))?,
    };
    Ok((mr.reg, src, consumed))
}

/// Compute (eip-after-modrm-resolution, write-target). Used by
/// MOVD / MOVQ stores where the destination is the r/m operand.
fn modrm_dst_addr_or_reg(cpu: &mut Cpu, mmu: &Mmu, mr: ModRm) -> Result<(MmxDst, usize), Trap> {
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    let dst = match op {
        Operand::Reg32(_) => MmxDst::MmxReg(mr.rm),
        Operand::Mem32(addr) => MmxDst::Mem(cpu.seg_translate(addr)),
    };
    Ok((dst, consumed))
}

/// Destination operand kind for MMX writes that may go to memory.
enum MmxDst {
    /// `mm[idx]` register.
    MmxReg(u8),
    /// Linear address (already segment-translated).
    Mem(u32),
}

/// Same as [`modrm_dst_addr_or_reg`] but the alternate operand is
/// a general-purpose register (used by `MOVD r/m32, mm` /
/// `MOVD mm, r/m32`).
fn modrm_dst_r32_or_mem(cpu: &mut Cpu, mmu: &Mmu, mr: ModRm) -> Result<(GpDst, usize), Trap> {
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    let dst = match op {
        Operand::Reg32(r) => GpDst::Reg32(r),
        Operand::Mem32(addr) => GpDst::Mem(cpu.seg_translate(addr)),
    };
    Ok((dst, consumed))
}

enum GpDst {
    Reg32(super::regs::Reg32),
    Mem(u32),
}

/// Read a 32-bit value from a `r/m32` for MOVD's `mm, r/m32`
/// form (zero-extended into the lower lane of the destination
/// MMX register).
fn read_modrm_r32_src(cpu: &mut Cpu, mmu: &Mmu, mr: ModRm) -> Result<(u32, usize), Trap> {
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    let v = match op {
        Operand::Reg32(r) => cpu.regs.get32(r),
        Operand::Mem32(addr) => mmu.load32(cpu.seg_translate(addr))?,
    };
    Ok((v, consumed))
}

// ---- per-byte SIMD lane primitives ----------------------------------

#[inline]
fn lanes_b(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}
#[inline]
fn pack_b(b: [u8; 8]) -> u64 {
    u64::from_le_bytes(b)
}
#[inline]
fn lanes_w(v: u64) -> [u16; 4] {
    let b = v.to_le_bytes();
    [
        u16::from_le_bytes([b[0], b[1]]),
        u16::from_le_bytes([b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
    ]
}
#[inline]
fn pack_w(w: [u16; 4]) -> u64 {
    let mut b = [0u8; 8];
    for i in 0..4 {
        b[i * 2..i * 2 + 2].copy_from_slice(&w[i].to_le_bytes());
    }
    u64::from_le_bytes(b)
}
#[inline]
fn lanes_d(v: u64) -> [u32; 2] {
    let b = v.to_le_bytes();
    [
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    ]
}
#[inline]
fn pack_d(d: [u32; 2]) -> u64 {
    let mut b = [0u8; 8];
    b[0..4].copy_from_slice(&d[0].to_le_bytes());
    b[4..8].copy_from_slice(&d[1].to_le_bytes());
    u64::from_le_bytes(b)
}

#[inline]
fn add_b(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = la[i].wrapping_add(lb[i]);
    }
    pack_b(o)
}
#[inline]
fn add_w(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = la[i].wrapping_add(lb[i]);
    }
    pack_w(o)
}
#[inline]
fn add_d(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_d(a), lanes_d(b));
    pack_d([la[0].wrapping_add(lb[0]), la[1].wrapping_add(lb[1])])
}
#[inline]
fn sub_b(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = la[i].wrapping_sub(lb[i]);
    }
    pack_b(o)
}
#[inline]
fn sub_w(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = la[i].wrapping_sub(lb[i]);
    }
    pack_w(o)
}
#[inline]
fn sub_d(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_d(a), lanes_d(b));
    pack_d([la[0].wrapping_sub(lb[0]), la[1].wrapping_sub(lb[1])])
}

// Saturating add/sub. Per Intel SDM PADDS / PADDUS / PSUBS / PSUBUS.
#[inline]
fn sat_i8(v: i32) -> i8 {
    v.clamp(i8::MIN as i32, i8::MAX as i32) as i8
}
#[inline]
fn sat_i16(v: i32) -> i16 {
    v.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}
#[inline]
fn sat_u8(v: i32) -> u8 {
    v.clamp(0, 0xFF) as u8
}
#[inline]
fn sat_u16(v: i32) -> u16 {
    v.clamp(0, 0xFFFF) as u16
}

#[inline]
fn paddsb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = sat_i8((la[i] as i8 as i32) + (lb[i] as i8 as i32)) as u8;
    }
    pack_b(o)
}
#[inline]
fn paddsw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = sat_i16((la[i] as i16 as i32) + (lb[i] as i16 as i32)) as u16;
    }
    pack_w(o)
}
#[inline]
fn paddusb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = sat_u8(la[i] as i32 + lb[i] as i32);
    }
    pack_b(o)
}
#[inline]
fn paddusw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = sat_u16(la[i] as i32 + lb[i] as i32);
    }
    pack_w(o)
}
#[inline]
fn psubsb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = sat_i8((la[i] as i8 as i32) - (lb[i] as i8 as i32)) as u8;
    }
    pack_b(o)
}
#[inline]
fn psubsw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = sat_i16((la[i] as i16 as i32) - (lb[i] as i16 as i32)) as u16;
    }
    pack_w(o)
}
#[inline]
fn psubusb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = sat_u8(la[i] as i32 - lb[i] as i32);
    }
    pack_b(o)
}
#[inline]
fn psubusw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = sat_u16(la[i] as i32 - lb[i] as i32);
    }
    pack_w(o)
}

// Compare: result lanes are 0xFF / 0xFFFF / 0xFFFFFFFF on true,
// 0 on false (Intel PCMPEQ / PCMPGT semantics).
#[inline]
fn pcmpeqb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = if la[i] == lb[i] { 0xFF } else { 0 };
    }
    pack_b(o)
}
#[inline]
fn pcmpeqw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = if la[i] == lb[i] { 0xFFFF } else { 0 };
    }
    pack_w(o)
}
#[inline]
fn pcmpeqd(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_d(a), lanes_d(b));
    let mut o = [0u32; 2];
    for i in 0..2 {
        o[i] = if la[i] == lb[i] { 0xFFFF_FFFF } else { 0 };
    }
    pack_d(o)
}
#[inline]
fn pcmpgtb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = if (la[i] as i8) > (lb[i] as i8) {
            0xFF
        } else {
            0
        };
    }
    pack_b(o)
}
#[inline]
fn pcmpgtw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = if (la[i] as i16) > (lb[i] as i16) {
            0xFFFF
        } else {
            0
        };
    }
    pack_w(o)
}
#[inline]
fn pcmpgtd(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_d(a), lanes_d(b));
    let mut o = [0u32; 2];
    for i in 0..2 {
        o[i] = if (la[i] as i32) > (lb[i] as i32) {
            0xFFFF_FFFF
        } else {
            0
        };
    }
    pack_d(o)
}

// Pack / unpack. Intel SDM PUNPCKL/H + PACKSS/PACKUS.
#[inline]
fn punpcklbw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    // Result = [a0,b0,a1,b1,a2,b2,a3,b3] (low halves interleaved)
    let mut o = [0u8; 8];
    for i in 0..4 {
        o[i * 2] = la[i];
        o[i * 2 + 1] = lb[i];
    }
    pack_b(o)
}
#[inline]
fn punpcklwd(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..2 {
        o[i * 2] = la[i];
        o[i * 2 + 1] = lb[i];
    }
    pack_w(o)
}
#[inline]
fn punpckldq(a: u64, b: u64) -> u64 {
    let la = lanes_d(a);
    let lb = lanes_d(b);
    pack_d([la[0], lb[0]])
}
#[inline]
fn punpckhbw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..4 {
        o[i * 2] = la[4 + i];
        o[i * 2 + 1] = lb[4 + i];
    }
    pack_b(o)
}
#[inline]
fn punpckhwd(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..2 {
        o[i * 2] = la[2 + i];
        o[i * 2 + 1] = lb[2 + i];
    }
    pack_w(o)
}
#[inline]
fn punpckhdq(a: u64, b: u64) -> u64 {
    let la = lanes_d(a);
    let lb = lanes_d(b);
    pack_d([la[1], lb[1]])
}

#[inline]
fn packsswb(a: u64, b: u64) -> u64 {
    // Saturate signed-i16 → signed-i8; low half from a, high half from b.
    let la = lanes_w(a);
    let lb = lanes_w(b);
    let mut o = [0u8; 8];
    for i in 0..4 {
        o[i] = sat_i8(la[i] as i16 as i32) as u8;
        o[4 + i] = sat_i8(lb[i] as i16 as i32) as u8;
    }
    pack_b(o)
}
#[inline]
fn packssdw(a: u64, b: u64) -> u64 {
    // Saturate signed-i32 → signed-i16; low half from a, high half from b.
    let la = lanes_d(a);
    let lb = lanes_d(b);
    let mut o = [0u16; 4];
    for i in 0..2 {
        o[i] = sat_i16(la[i] as i32) as u16;
        o[2 + i] = sat_i16(lb[i] as i32) as u16;
    }
    pack_w(o)
}
#[inline]
fn packuswb(a: u64, b: u64) -> u64 {
    // Saturate signed-i16 → unsigned-u8; low half from a, high from b.
    let la = lanes_w(a);
    let lb = lanes_w(b);
    let mut o = [0u8; 8];
    for i in 0..4 {
        o[i] = sat_u8(la[i] as i16 as i32);
        o[4 + i] = sat_u8(lb[i] as i16 as i32);
    }
    pack_b(o)
}

// Multiplies.
#[inline]
fn pmullw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        let prod = (la[i] as i16 as i32).wrapping_mul(lb[i] as i16 as i32);
        o[i] = prod as u16; // low 16 bits
    }
    pack_w(o)
}
#[inline]
fn pmulhw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        let prod = (la[i] as i16 as i32).wrapping_mul(lb[i] as i16 as i32);
        o[i] = (prod >> 16) as u16; // high 16 bits (signed)
    }
    pack_w(o)
}
#[inline]
fn pmaddwd(a: u64, b: u64) -> u64 {
    // Two i32 lanes, each = a[2i]*b[2i] + a[2i+1]*b[2i+1].
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u32; 2];
    for i in 0..2 {
        let p0 = (la[2 * i] as i16 as i32).wrapping_mul(lb[2 * i] as i16 as i32);
        let p1 = (la[2 * i + 1] as i16 as i32).wrapping_mul(lb[2 * i + 1] as i16 as i32);
        o[i] = p0.wrapping_add(p1) as u32;
    }
    pack_d(o)
}

// Average (round half-up). PAVGB / PAVGW.
#[inline]
fn pavgb(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_b(a), lanes_b(b));
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = ((la[i] as u16 + lb[i] as u16 + 1) >> 1) as u8;
    }
    pack_b(o)
}
#[inline]
fn pavgw(a: u64, b: u64) -> u64 {
    let (la, lb) = (lanes_w(a), lanes_w(b));
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = ((la[i] as u32 + lb[i] as u32 + 1) >> 1) as u16;
    }
    pack_w(o)
}

// Shifts. Per Intel SDM PSL{LW,LD,LQ} / PSR{LW,LD,LQ} / PSR{AW,AD}.
// Shift count >= lane bit-width zeroes the lanes (logical) or
// fills with sign bit (arithmetic).
#[inline]
fn psllw(a: u64, count: u64) -> u64 {
    if count >= 16 {
        return 0;
    }
    let la = lanes_w(a);
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = la[i] << count;
    }
    pack_w(o)
}
#[inline]
fn pslld(a: u64, count: u64) -> u64 {
    if count >= 32 {
        return 0;
    }
    let la = lanes_d(a);
    pack_d([la[0] << count, la[1] << count])
}
#[inline]
fn psllq(a: u64, count: u64) -> u64 {
    if count >= 64 {
        0
    } else {
        a << count
    }
}
#[inline]
fn psrlw(a: u64, count: u64) -> u64 {
    if count >= 16 {
        return 0;
    }
    let la = lanes_w(a);
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = la[i] >> count;
    }
    pack_w(o)
}
#[inline]
fn psrld(a: u64, count: u64) -> u64 {
    if count >= 32 {
        return 0;
    }
    let la = lanes_d(a);
    pack_d([la[0] >> count, la[1] >> count])
}
#[inline]
fn psrlq(a: u64, count: u64) -> u64 {
    if count >= 64 {
        0
    } else {
        a >> count
    }
}
#[inline]
fn psraw(a: u64, count: u64) -> u64 {
    let la = lanes_w(a);
    let cnt = count.min(15) as u32; // i16 saturates at 15 (sign-extended)
    let mut o = [0u16; 4];
    for i in 0..4 {
        o[i] = ((la[i] as i16) >> cnt) as u16;
    }
    pack_w(o)
}
#[inline]
fn psrad(a: u64, count: u64) -> u64 {
    let la = lanes_d(a);
    let cnt = count.min(31) as u32;
    pack_d([
        ((la[0] as i32) >> cnt) as u32,
        ((la[1] as i32) >> cnt) as u32,
    ])
}

// ---- per-opcode dispatch -------------------------------------------

/// Implement the MMX subset of the `0F` two-byte opcode space.
///
/// Returns `Ok(StepOk::Continued)` when the opcode is one of the
/// implemented forms; returns `Err(Trap::UnimplementedMmx)` for
/// any unmapped opcode in the MMX space, with EIP already
/// advanced past the instruction body. `entry_eip` is the EIP of
/// the opening `0F` byte.
///
/// The caller (the `0F`-escape dispatcher in `isa_int`) passes the
/// second opcode byte `op2`; this function also consumes the
/// ModR/M (and any imm8) when the named opcode requires it.
pub(crate) fn dispatch(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    op2: u8,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    let result = dispatch_inner(cpu, mmu, op2, entry_eip);
    if result.is_ok() {
        cpu.mmx_dispatch_count = cpu.mmx_dispatch_count.wrapping_add(1);
    }
    result
}

fn dispatch_inner(cpu: &mut Cpu, mmu: &mut Mmu, op2: u8, entry_eip: u32) -> Result<StepOk, Trap> {
    match op2 {
        // ---- 0F 60..6F: PUNPCKL / PCMPGT / PACKSS / PUNPCKH / MOVD / MOVQ
        0x60 => binop(cpu, mmu, punpcklbw),
        0x61 => binop(cpu, mmu, punpcklwd),
        0x62 => binop(cpu, mmu, punpckldq),
        0x63 => binop(cpu, mmu, packsswb),
        0x64 => binop(cpu, mmu, pcmpgtb),
        0x65 => binop(cpu, mmu, pcmpgtw),
        0x66 => binop(cpu, mmu, pcmpgtd),
        0x67 => binop(cpu, mmu, packuswb),
        0x68 => binop(cpu, mmu, punpckhbw),
        0x69 => binop(cpu, mmu, punpckhwd),
        0x6A => binop(cpu, mmu, punpckhdq),
        0x6B => binop(cpu, mmu, packssdw),
        // 0F 6E — MOVD mm, r/m32  (zero-extend into low lane)
        0x6E => {
            let mr = cpu.fetch_modrm(mmu)?;
            let (v, consumed) = read_modrm_r32_src(cpu, mmu, mr)?;
            cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
            cpu.mmx[mr.reg as usize] = v as u64;
            Ok(StepOk::Continued)
        }
        // 0F 6F — MOVQ mm, mm/m64
        0x6F => {
            let mr = cpu.fetch_modrm(mmu)?;
            let (reg, src, consumed) = read_modrm_mm_src(cpu, mmu, mr)?;
            cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
            cpu.mmx[reg as usize] = src;
            Ok(StepOk::Continued)
        }

        // ---- 0F 70..7F
        // 0F 71 — group 12: PSLLW/PSRLW/PSRAW imm8 (mr.reg disambiguates)
        0x71 => group12_shift(cpu, mmu),
        0x72 => group13_shift(cpu, mmu),
        0x73 => group14_shift(cpu, mmu),
        0x74 => binop(cpu, mmu, pcmpeqb),
        0x75 => binop(cpu, mmu, pcmpeqw),
        0x76 => binop(cpu, mmu, pcmpeqd),
        // 0F 77 — EMMS: clear MMX state.
        0x77 => {
            cpu.mmx = [0u64; 8];
            Ok(StepOk::Continued)
        }
        // 0F 7E — MOVD r/m32, mm
        0x7E => {
            let mr = cpu.fetch_modrm(mmu)?;
            let (dst, consumed) = modrm_dst_r32_or_mem(cpu, mmu, mr)?;
            cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
            let v = cpu.mmx[mr.reg as usize] as u32; // low 32 bits
            match dst {
                GpDst::Reg32(r) => cpu.regs.set32(r, v),
                GpDst::Mem(addr) => mmu.store32(addr, v)?,
            }
            Ok(StepOk::Continued)
        }
        // 0F 7F — MOVQ mm/m64, mm
        0x7F => {
            let mr = cpu.fetch_modrm(mmu)?;
            let (dst, consumed) = modrm_dst_addr_or_reg(cpu, mmu, mr)?;
            cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
            let v = cpu.mmx[mr.reg as usize];
            match dst {
                MmxDst::MmxReg(idx) => cpu.mmx[idx as usize] = v,
                MmxDst::Mem(addr) => mmu.store64(addr, v)?,
            }
            Ok(StepOk::Continued)
        }

        // ---- 0F D0..DF
        0xD1 => binop_count(cpu, mmu, psrlw),
        0xD2 => binop_count(cpu, mmu, psrld),
        0xD3 => binop_count(cpu, mmu, psrlq),
        0xD4 => {
            // PADDQ: single 64-bit add.
            binop(cpu, mmu, |a, b| a.wrapping_add(b))
        }
        0xD5 => binop(cpu, mmu, pmullw),
        0xD8 => binop(cpu, mmu, psubusb),
        0xD9 => binop(cpu, mmu, psubusw),
        0xDB => binop(cpu, mmu, |a, b| a & b), // PAND
        0xDC => binop(cpu, mmu, paddusb),
        0xDD => binop(cpu, mmu, paddusw),
        0xDF => binop(cpu, mmu, |a, b| (!a) & b), // PANDN

        // ---- 0F E0..EF
        0xE0 => binop(cpu, mmu, pavgb),
        0xE1 => binop_count(cpu, mmu, psraw),
        0xE2 => binop_count(cpu, mmu, psrad),
        0xE3 => binop(cpu, mmu, pavgw),
        0xE5 => binop(cpu, mmu, pmulhw),
        0xE8 => binop(cpu, mmu, psubsb),
        0xE9 => binop(cpu, mmu, psubsw),
        0xEB => binop(cpu, mmu, |a, b| a | b), // POR
        0xEC => binop(cpu, mmu, paddsb),
        0xED => binop(cpu, mmu, paddsw),
        0xEF => binop(cpu, mmu, |a, b| a ^ b), // PXOR

        // ---- 0F F0..FF
        0xF1 => binop_count(cpu, mmu, psllw),
        0xF2 => binop_count(cpu, mmu, pslld),
        0xF3 => binop_count(cpu, mmu, psllq),
        0xF5 => binop(cpu, mmu, pmaddwd),
        0xF8 => binop(cpu, mmu, sub_b),
        0xF9 => binop(cpu, mmu, sub_w),
        0xFA => binop(cpu, mmu, sub_d),
        0xFB => binop(cpu, mmu, |a, b| a.wrapping_sub(b)), // PSUBQ
        0xFC => binop(cpu, mmu, add_b),
        0xFD => binop(cpu, mmu, add_w),
        0xFE => binop(cpu, mmu, add_d),

        // Anything else in the MMX-mapped slots: structured trap.
        // Caller has already advanced past the opcode byte; we
        // additionally consume the ModR/M body so EIP lands at the
        // next instruction.
        _ => unimplemented_mmx_trap(cpu, mmu, op2, entry_eip),
    }
}

/// Generic "binary MMX op": reg-form takes `(mm, mm/m64)`, writes
/// the result back into `mm[reg]`. Used by every two-source
/// MMX arithmetic / logic instruction.
fn binop<F: Fn(u64, u64) -> u64>(cpu: &mut Cpu, mmu: &mut Mmu, f: F) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let (reg, src, consumed) = read_modrm_mm_src(cpu, mmu, mr)?;
    cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
    let dst = cpu.mmx[reg as usize];
    cpu.mmx[reg as usize] = f(dst, src);
    Ok(StepOk::Continued)
}

/// "Binary count-source" — same as [`binop`] but interprets the
/// source operand as a shift amount. The MMX shift instructions
/// take the FULL 64-bit value of the source as the count (per
/// Intel SDM); `f` picks the per-lane width.
fn binop_count<F: Fn(u64, u64) -> u64>(cpu: &mut Cpu, mmu: &mut Mmu, f: F) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let (reg, src, consumed) = read_modrm_mm_src(cpu, mmu, mr)?;
    cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
    let dst = cpu.mmx[reg as usize];
    cpu.mmx[reg as usize] = f(dst, src);
    Ok(StepOk::Continued)
}

/// `0F 71` group-12 — PSLLW/PSRLW/PSRAW imm8. The ModR/M's `mod`
/// must be `11` (register form only) and the `reg` field selects:
///
/// * `/2` — PSRLW
/// * `/4` — PSRAW
/// * `/6` — PSLLW
fn group12_shift(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    // Reg form only.
    let imm = cpu.fetch_imm8(mmu)? as u64;
    let target = mr.rm as usize;
    let v = cpu.mmx[target];
    let new = match mr.reg {
        2 => psrlw(v, imm),
        4 => psraw(v, imm),
        6 => psllw(v, imm),
        _ => return unimplemented_mmx_trap_no_advance(cpu, 0x71),
    };
    cpu.mmx[target] = new;
    Ok(StepOk::Continued)
}

/// `0F 72` group-13 — PSLLD/PSRLD/PSRAD imm8.
fn group13_shift(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let imm = cpu.fetch_imm8(mmu)? as u64;
    let target = mr.rm as usize;
    let v = cpu.mmx[target];
    let new = match mr.reg {
        2 => psrld(v, imm),
        4 => psrad(v, imm),
        6 => pslld(v, imm),
        _ => return unimplemented_mmx_trap_no_advance(cpu, 0x72),
    };
    cpu.mmx[target] = new;
    Ok(StepOk::Continued)
}

/// `0F 73` group-14 — PSLLQ/PSRLQ imm8.
fn group14_shift(cpu: &mut Cpu, mmu: &mut Mmu) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let imm = cpu.fetch_imm8(mmu)? as u64;
    let target = mr.rm as usize;
    let v = cpu.mmx[target];
    let new = match mr.reg {
        2 => psrlq(v, imm),
        6 => psllq(v, imm),
        _ => return unimplemented_mmx_trap_no_advance(cpu, 0x73),
    };
    cpu.mmx[target] = new;
    Ok(StepOk::Continued)
}

fn unimplemented_mmx_trap(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    op2: u8,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    let needs_modrm = op2 != 0x77;
    if needs_modrm {
        let mr = cpu.fetch_modrm(mmu)?;
        let bytes = cpu.peek_after_modrm(mmu, 16)?;
        let (_op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
        cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
    }
    Err(Trap::UnimplementedMmx {
        eip: entry_eip,
        opcode: 0x0F00 | u32::from(op2),
        mnemonic_hint: mmx_mnemonic(op2),
    })
}

fn unimplemented_mmx_trap_no_advance(_cpu: &mut Cpu, op2: u8) -> Result<StepOk, Trap> {
    Err(Trap::UnimplementedMmx {
        eip: 0,
        opcode: 0x0F00 | u32::from(op2),
        mnemonic_hint: mmx_mnemonic(op2),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_split_pack_b_roundtrip() {
        let v = 0x0102_0304_0506_0708u64;
        assert_eq!(pack_b(lanes_b(v)), v);
    }

    #[test]
    fn lane_split_pack_w_roundtrip() {
        let v = 0xCAFE_BABE_DEAD_BEEFu64;
        assert_eq!(pack_w(lanes_w(v)), v);
    }

    #[test]
    fn lane_split_pack_d_roundtrip() {
        let v = 0xCAFE_BABE_DEAD_BEEFu64;
        assert_eq!(pack_d(lanes_d(v)), v);
    }

    #[test]
    fn paddb_wraps_per_byte() {
        // 0xFF + 0x02 = 0x01 (wrap)
        let a = 0xFF_FF_FF_FF_FF_FF_FF_FFu64;
        let b = 0x02_02_02_02_02_02_02_02u64;
        let r = add_b(a, b);
        assert_eq!(r, 0x01_01_01_01_01_01_01_01);
    }

    #[test]
    fn paddusw_saturates_at_ffff() {
        let a = 0xFFFF_0000_FFFF_0000u64;
        let b = 0x0001_0001_FFFF_0001u64;
        let r = paddusw(a, b);
        // Lane-by-lane (LE order): a-lanes = [0,FFFF,0,FFFF], b-lanes = [1,FFFF,1,FFFF]
        // Sums = [1, FFFF saturated, 1, FFFF saturated].
        assert_eq!(r, 0xFFFF_0001_FFFF_0001);
    }

    #[test]
    fn psubsb_saturates_negative() {
        // Each lane of 0x80 (-128) - 0x01 = 0x80 (saturated).
        let a = 0x80_80_80_80_80_80_80_80u64;
        let b = 0x01_01_01_01_01_01_01_01u64;
        let r = psubsb(a, b);
        assert_eq!(r, 0x80_80_80_80_80_80_80_80);
    }

    #[test]
    fn pcmpeqd_yields_full_mask() {
        let a = 0x1111_2222_1111_2222u64;
        let r = pcmpeqd(a, a);
        assert_eq!(r, 0xFFFF_FFFF_FFFF_FFFF);
    }

    #[test]
    fn pcmpgtw_signed_compare() {
        // Lane 0: a=0x0001, b=0xFFFF (-1). 1 > -1 → 0xFFFF.
        // Lane 1: a=0x8000 (-32768), b=0x0000. -32768 > 0 → 0.
        let a = 0x0000_0000_0000_0001u64; // packed words [1,0,0,0]  (LE)
        let b = 0x0000_0000_0000_FFFFu64; // packed words [-1,0,0,0]
        let r = pcmpgtw(a, b);
        // Result lane 0 = 0xFFFF, others = 0.
        assert_eq!(r & 0xFFFF, 0xFFFF);
        assert_eq!(r >> 16, 0);
    }

    #[test]
    fn punpcklbw_interleaves_low_halves() {
        let a = 0x0807_0605_0403_0201u64; // bytes [01,02,03,04,05,06,07,08]
        let b = 0x1817_1615_1413_1211u64; // bytes [11,12,13,14,15,16,17,18]
        let r = punpcklbw(a, b);
        // Result: [a0,b0,a1,b1,a2,b2,a3,b3] = [01,11,02,12,03,13,04,14]
        assert_eq!(r, 0x1404_1303_1202_1101);
    }

    #[test]
    fn pmullw_low_16_bits() {
        let a = pack_w([2, 3, 4, 5]);
        let b = pack_w([10, 100, 1000, 10000]);
        // Products: [20, 300, 4000, 50000 wraps to 50000 fits in u16].
        let r = pmullw(a, b);
        assert_eq!(lanes_w(r), [20, 300, 4000, 50000u16]);
    }

    #[test]
    fn pmulhw_high_16_bits_signed() {
        // 0x4000 * 0x0002 = 0x8000_0000_low, high 16 = 0x0000. (signed)
        // 0x8000 * 0x0002 = 0xFFFF_0000_low, high 16 = 0xFFFF.
        let a = pack_w([0x4000, 0x8000, 0, 0]);
        let b = pack_w([0x0002, 0x0002, 0, 0]);
        let r = pmulhw(a, b);
        assert_eq!(lanes_w(r), [0x0000, 0xFFFF, 0, 0]);
    }

    #[test]
    fn pmaddwd_pairs_then_adds() {
        // a = [1,2,3,4], b = [10,20,30,40]
        // Lane 0 = 1*10 + 2*20 = 50; Lane 1 = 3*30 + 4*40 = 250.
        let a = pack_w([1, 2, 3, 4]);
        let b = pack_w([10, 20, 30, 40]);
        let r = pmaddwd(a, b);
        assert_eq!(lanes_d(r), [50, 250]);
    }

    #[test]
    fn psllw_imm_shifts_each_word() {
        let a = pack_w([1, 2, 3, 4]);
        let r = psllw(a, 4);
        assert_eq!(lanes_w(r), [16, 32, 48, 64]);
    }

    #[test]
    fn psrlw_imm_shifts_each_word() {
        let a = pack_w([0x1000, 0x2000, 0x3000, 0x4000]);
        let r = psrlw(a, 4);
        assert_eq!(lanes_w(r), [0x0100, 0x0200, 0x0300, 0x0400]);
    }

    #[test]
    fn psraw_imm_sign_extends() {
        let a = pack_w([0x8000, 0x7FFF, 0xFFFF, 0x0001]);
        let r = psraw(a, 1);
        assert_eq!(lanes_w(r), [0xC000, 0x3FFF, 0xFFFF, 0x0000]);
    }

    #[test]
    fn psllq_full_64_bit_shift() {
        assert_eq!(psllq(1, 32), 0x0000_0001_0000_0000);
        assert_eq!(psllq(1, 64), 0); // SDM: count >= 64 zeroes the lane
    }

    #[test]
    fn pavgb_rounds_half_up() {
        let a = 0x10_10_10_10_10_10_10_10u64;
        let b = 0x21_21_21_21_21_21_21_21u64;
        // (16 + 33 + 1) / 2 = 25
        let r = pavgb(a, b);
        assert_eq!(r, 0x19_19_19_19_19_19_19_19);
    }

    #[test]
    fn packuswb_saturates_words_to_unsigned_bytes() {
        // a = [0x00FF (255), 0x01FF (511 → 255), 0xFF00 (-256 → 0), 0x0000]
        // b = [0,0,0,0]
        let a = pack_w([0x00FF, 0x01FF, 0xFF00, 0x0000]);
        let b = pack_w([0, 0, 0, 0]);
        let r = packuswb(a, b);
        assert_eq!(r.to_le_bytes(), [0xFF, 0xFF, 0x00, 0x00, 0, 0, 0, 0]);
    }

    #[test]
    fn packsswb_saturates_words_to_signed_bytes() {
        // 0x0080 (+128) → +127 (0x7F); 0xFF80 (-128) → -128 (0x80).
        let a = pack_w([0x0080, 0xFF80, 0x0000, 0x0001]);
        let b = pack_w([0, 0, 0, 0]);
        let r = packsswb(a, b);
        let bytes = r.to_le_bytes();
        assert_eq!(bytes[0], 0x7F);
        assert_eq!(bytes[1], 0x80);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x01);
    }
}

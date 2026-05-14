//! Helpers used by the integer interpreter for decoding ModR/M
//! and SIB bytes, sign-extending immediates, and computing
//! effective addresses.
//!
//! Reference: Intel® 64 and IA-32 Architectures Software
//! Developer's Manual, Volume 2A §2.1.5 (ModR/M and SIB Bytes)
//! and §A.2 (Opcode Maps).
//!
//! No instruction-set tables live here — the executor in
//! [`super::isa_int`] uses a `match` on the opcode byte directly.
//! What lives here is the structured-interpretation of ModR/M
//! and SIB encodings, and the small set of operand-fetch
//! primitives the executor needs.

use super::mmu::Mmu;
use super::regs::{Reg32, Regs};
use super::Trap;

/// Decoded ModR/M byte.
#[derive(Copy, Clone, Debug)]
pub struct ModRm {
    /// `mod` field (bits 7:6). Two bits, 0..=3.
    pub mode: u8,
    /// The middle 3 bits — depending on the opcode this is either
    /// a `/r` register selector or a `/0../7` opcode extension.
    pub reg: u8,
    /// `r/m` field (bits 2:0).
    pub rm: u8,
}

impl ModRm {
    /// Split a ModR/M byte into (`mod`, reg, r/m).
    pub fn decode(b: u8) -> ModRm {
        ModRm {
            mode: (b >> 6) & 0b11,
            reg: (b >> 3) & 0b111,
            rm: b & 0b111,
        }
    }
}

/// Decoded SIB (scale-index-base) byte.
#[derive(Copy, Clone, Debug)]
pub struct Sib {
    pub scale: u8,
    pub index: u8,
    pub base: u8,
}

impl Sib {
    pub fn decode(b: u8) -> Sib {
        Sib {
            scale: (b >> 6) & 0b11,
            index: (b >> 3) & 0b111,
            base: b & 0b111,
        }
    }
}

/// An effective-address kind.
///
/// Either a register operand (no memory reference) or a memory
/// reference with a 32-bit linear address. Used by the executor's
/// "load this operand" / "store to this operand" helpers so the
/// switch on `mod` happens once during decode.
#[derive(Copy, Clone, Debug)]
pub enum Operand {
    Reg32(Reg32),
    Mem32(u32),
}

/// Sign-extend an 8-bit immediate to 32 bits.
pub const fn sign_ext_8_to_32(b: u8) -> u32 {
    b as i8 as i32 as u32
}

/// Sign-extend an 8-bit immediate to 16 bits.
pub const fn sign_ext_8_to_16(b: u8) -> u16 {
    b as i8 as i16 as u16
}

/// Sign-extend a 16-bit immediate to 32 bits.
pub const fn sign_ext_16_to_32(w: u16) -> u32 {
    w as i16 as i32 as u32
}

/// 32-bit-mode effective-address resolution.
///
/// Intel SDM Vol. 2A §2.1.5 Table 2-2 ("32-Bit Addressing Forms
/// with the ModR/M Byte"). Returns the resolved [`Operand`] and
/// the number of bytes consumed past the ModR/M byte (SIB +
/// displacement).
pub fn resolve_modrm32(
    modrm: ModRm,
    bytes_after_modrm: &[u8],
    regs: &Regs,
) -> Result<(Operand, usize), Trap> {
    if modrm.mode == 0b11 {
        return Ok((Operand::Reg32(Reg32::from_bits(modrm.rm)), 0));
    }

    let mut consumed = 0usize;
    let addr: u32;

    // r/m == 4 means a SIB byte follows.
    let (base_kind, sib) = if modrm.rm == 0b100 {
        let s = bytes_after_modrm
            .first()
            .ok_or(Trap::UndefinedOpcode { eip: 0, opcode: 0 })?;
        consumed += 1;
        (BaseKind::Sib, Some(Sib::decode(*s)))
    } else {
        (BaseKind::Rm(modrm.rm), None)
    };

    match modrm.mode {
        0b00 => {
            // Mod=00:
            //   r/m=5  → disp32 only (no register).
            //   r/m=4  → SIB; if SIB.base=5 then disp32 + (idx*scale)
            //   else   → [rm]
            match base_kind {
                BaseKind::Rm(5) => {
                    let disp = read_imm32(bytes_after_modrm, consumed)?;
                    consumed += 4;
                    addr = disp;
                }
                BaseKind::Rm(rm) => {
                    addr = regs.get32(Reg32::from_bits(rm));
                }
                BaseKind::Sib => {
                    let s = sib.unwrap();
                    addr = sib_base_at_mod0(s, bytes_after_modrm, &mut consumed, regs)?
                        .wrapping_add(sib_index_term(s, regs));
                }
            }
        }
        0b01 => {
            // Mod=01: [reg + disp8]; for SIB: [base + idx*s + disp8]
            let disp =
                sign_ext_8_to_32(*bytes_after_modrm.get(consumed).ok_or(unreachable_trap())?);
            consumed += 1;
            addr = match base_kind {
                BaseKind::Rm(rm) => regs.get32(Reg32::from_bits(rm)).wrapping_add(disp),
                BaseKind::Sib => {
                    let s = sib.unwrap();
                    regs.get32(Reg32::from_bits(s.base))
                        .wrapping_add(sib_index_term(s, regs))
                        .wrapping_add(disp)
                }
            };
        }
        0b10 => {
            // Mod=10: [reg + disp32]; SIB analog
            let disp = read_imm32(bytes_after_modrm, consumed)?;
            consumed += 4;
            addr = match base_kind {
                BaseKind::Rm(rm) => regs.get32(Reg32::from_bits(rm)).wrapping_add(disp),
                BaseKind::Sib => {
                    let s = sib.unwrap();
                    regs.get32(Reg32::from_bits(s.base))
                        .wrapping_add(sib_index_term(s, regs))
                        .wrapping_add(disp)
                }
            };
        }
        _ => unreachable!(),
    }

    Ok((Operand::Mem32(addr), consumed))
}

enum BaseKind {
    Rm(u8),
    Sib,
}

fn sib_index_term(sib: Sib, regs: &Regs) -> u32 {
    // index=4 means "no index" (special encoding per Intel SDM
    // Vol. 2A §2.1.5).
    if sib.index == 0b100 {
        0
    } else {
        regs.get32(Reg32::from_bits(sib.index))
            .wrapping_mul(1u32 << sib.scale)
    }
}

fn sib_base_at_mod0(
    sib: Sib,
    after: &[u8],
    consumed: &mut usize,
    regs: &Regs,
) -> Result<u32, Trap> {
    if sib.base == 0b101 {
        // Special: Mod=00 + SIB.base=5 → disp32, no base register
        let disp = read_imm32(after, *consumed)?;
        *consumed += 4;
        Ok(disp)
    } else {
        Ok(regs.get32(Reg32::from_bits(sib.base)))
    }
}

fn read_imm32(bytes: &[u8], offset: usize) -> Result<u32, Trap> {
    bytes
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(unreachable_trap())
}

fn unreachable_trap() -> Trap {
    // We only hit this if a caller passes too-short a slice; the
    // executor always passes a slice covering the whole instruction
    // by re-fetching from the MMU on demand.
    Trap::UndefinedOpcode { eip: 0, opcode: 0 }
}

/// Read the operand value as a 32-bit dword.
pub fn read_operand32(op: Operand, regs: &Regs, mmu: &Mmu) -> Result<u32, Trap> {
    match op {
        Operand::Reg32(r) => Ok(regs.get32(r)),
        Operand::Mem32(addr) => mmu.load32(addr),
    }
}

/// Write to the operand as a 32-bit dword.
pub fn write_operand32(
    op: Operand,
    value: u32,
    regs: &mut Regs,
    mmu: &mut Mmu,
) -> Result<(), Trap> {
    match op {
        Operand::Reg32(r) => {
            regs.set32(r, value);
            Ok(())
        }
        Operand::Mem32(addr) => mmu.store32(addr, value),
    }
}

/// Read the operand value as a 16-bit word. Treats `Reg32(r)` as
/// "low 16 bits of `r`" and `Mem32(addr)` as a 16-bit memory read.
/// Used by opcodes that took the operand-size override prefix
/// (`0x66`).
pub fn read_operand16(op: Operand, regs: &Regs, mmu: &Mmu) -> Result<u16, Trap> {
    match op {
        Operand::Reg32(r) => Ok(regs.get32(r) as u16),
        Operand::Mem32(addr) => mmu.load16(addr),
    }
}

/// Write to the operand as a 16-bit word. Preserves the upper 16
/// bits of a `Reg32` register; writes 2 bytes to memory.
pub fn write_operand16(
    op: Operand,
    value: u16,
    regs: &mut Regs,
    mmu: &mut Mmu,
) -> Result<(), Trap> {
    match op {
        Operand::Reg32(r) => {
            let prev = regs.get32(r);
            regs.set32(r, (prev & 0xFFFF_0000) | u32::from(value));
            Ok(())
        }
        Operand::Mem32(addr) => mmu.store16(addr, value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modrm_split() {
        let m = ModRm::decode(0b11_010_110); // mod=3, reg=2, rm=6
        assert_eq!(m.mode, 0b11);
        assert_eq!(m.reg, 2);
        assert_eq!(m.rm, 6);
    }

    #[test]
    fn sign_ext_helpers() {
        assert_eq!(sign_ext_8_to_32(0x7F), 0x0000_007F);
        assert_eq!(sign_ext_8_to_32(0xFF), 0xFFFF_FFFF);
        assert_eq!(sign_ext_16_to_32(0x8000), 0xFFFF_8000);
    }

    #[test]
    fn modrm_register_form_returns_reg_operand() {
        let m = ModRm::decode(0b11_000_011); // ebx
        let regs = Regs::new();
        let (op, n) = resolve_modrm32(m, &[], &regs).unwrap();
        assert_eq!(n, 0);
        match op {
            Operand::Reg32(Reg32::Ebx) => (),
            other => panic!("expected ebx, got {other:?}"),
        }
    }

    #[test]
    fn modrm_disp32_at_rm5() {
        // mod=00, rm=5 → disp32 absolute address
        let m = ModRm::decode(0b00_000_101);
        let regs = Regs::new();
        let bytes = [0x78, 0x56, 0x34, 0x12]; // disp32 = 0x12345678
        let (op, n) = resolve_modrm32(m, &bytes, &regs).unwrap();
        assert_eq!(n, 4);
        match op {
            Operand::Mem32(0x1234_5678) => (),
            other => panic!("expected Mem32(0x12345678), got {other:?}"),
        }
    }

    #[test]
    fn modrm_disp8_relative_to_register() {
        let m = ModRm::decode(0b01_000_011); // mod=01, rm=ebx
        let mut regs = Regs::new();
        regs.set32(Reg32::Ebx, 0x1000);
        let bytes = [0x10]; // disp8 = +0x10
        let (op, n) = resolve_modrm32(m, &bytes, &regs).unwrap();
        assert_eq!(n, 1);
        match op {
            Operand::Mem32(0x1010) => (),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn modrm_sib_with_index_scale() {
        // mod=00, rm=4 (SIB), SIB: scale=2 (×4), index=esi, base=ebx
        let m = ModRm::decode(0b00_000_100);
        let sib = (0b10 << 6) | (Reg32::Esi as u8) << 3 | (Reg32::Ebx as u8);
        let mut regs = Regs::new();
        regs.set32(Reg32::Ebx, 0x1000);
        regs.set32(Reg32::Esi, 0x10);
        let bytes = [sib];
        let (op, n) = resolve_modrm32(m, &bytes, &regs).unwrap();
        assert_eq!(n, 1);
        match op {
            Operand::Mem32(addr) => assert_eq!(addr, 0x1000 + 0x10 * 4),
            other => panic!("got {other:?}"),
        }
    }
}

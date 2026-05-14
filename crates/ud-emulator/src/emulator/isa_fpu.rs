//! x87 FPU executor — partial coverage tuned for Win32 codec
//! CRT init paths and the inner-loop float arithmetic the
//! codecs actually run.
//!
//! The full x87 ISA spans the 8 escape opcodes `0xD8..=0xDF`.
//! We model the subset codec DLLs touch:
//!
//! * `D9 /N m32` — FLD m32, FST/FSTP m32, FLDCW, FNSTCW,
//!   FLDENV/FNSTENV (treated as no-op).
//! * `D9 reg-form` — FLD ST(i), FXCH ST(i), FCHS, FABS,
//!   FRNDINT, FSQRT, FCOS, FSIN, FPATAN, FLD1, FLDZ,
//!   FLDPI etc.
//! * `DB /N m32` — FILD m32, FIST/FISTP m32, FNSTSW (some
//!   variants), FNCLEX, FINIT.
//! * `DD /N m64` — FLD m64, FST/FSTP m64, FFREE.
//! * `DD reg-form` — FFREE ST(i), FUCOM/FUCOMP.
//! * `D8/DC/DA/DE` — FADD/FSUB/FMUL/FDIV/FDIVR + register
//!   forms + integer-source variants.
//! * `DF E0` — FNSTSW AX.
//! * `DF /5` — FILD m64, `DF /7` — FISTP m64.
//!
//! The FPU stack is modelled as a fixed-size array of 8 `f64`
//! values plus a TOP pointer. We do NOT model the 80-bit
//! extended precision — `f64` is sufficient because every
//! codec we've encountered loads / stores via `FLD m32` or
//! `FLD m64` and never relies on the extra 16 mantissa bits
//! between transfers.
//!
//! Reference: Intel® 64 and IA-32 Architectures Software
//! Developer's Manual, Volume 1 §8 + Volume 2A "FLD",
//! "FSTP", "FILD", "FADD", "FSUB", "FMUL", "FDIV",
//! "FNSTSW", "FCHS", "FABS", "FCOM", "FUCOM", "FXCH",
//! "FRNDINT", "FSQRT".

use super::decode::{resolve_modrm32, Operand};
use super::isa_int::{Cpu, StepOk};
use super::mmu::Mmu;
use super::Trap;

/// FPU stack depth — the architectural x87 has eight ST(i)
/// registers.
pub const FPU_STACK_DEPTH: usize = 8;

/// Status-word C0 / C1 / C2 / C3 condition-code bit positions
/// (within the 16-bit FNSTSW value). Used by FCOM and friends.
pub const SW_C0: u16 = 1 << 8;
pub const SW_C1: u16 = 1 << 9;
pub const SW_C2: u16 = 1 << 10;
pub const SW_C3: u16 = 1 << 14;

/// FPU state attached to [`Cpu`] in round 21+. Eight
/// architectural ST(i) slots plus a top-of-stack pointer and
/// a status word. Tag word is implicit in [`FpuState::tag`]:
/// each entry is either `Empty` (free) or `Valid(f64)`.
#[derive(Clone, Debug)]
pub struct FpuState {
    /// Stack values in physical (not architectural) order.
    /// `regs[(top + i) & 7]` is `ST(i)` for i in 0..8.
    pub regs: [f64; FPU_STACK_DEPTH],
    /// Tag bits — `true` means the slot holds a valid value;
    /// `false` is the architectural "Empty" tag.
    pub tag_valid: [bool; FPU_STACK_DEPTH],
    /// Physical index of the architectural ST(0). Decremented
    /// (mod 8) by FLD-style pushes; incremented by FSTP-style
    /// pops.
    pub top: u8,
    /// Status word — only the C0..C3 condition codes and the
    /// busy / TOP fields matter for the codec workloads we
    /// drive. Cleared by FNCLEX / FINIT; updated by FCOM /
    /// FUCOM.
    pub sw: u16,
}

impl Default for FpuState {
    fn default() -> Self {
        Self::new()
    }
}

impl FpuState {
    pub fn new() -> Self {
        FpuState {
            regs: [0.0; FPU_STACK_DEPTH],
            tag_valid: [false; FPU_STACK_DEPTH],
            top: 0,
            sw: 0,
        }
    }

    /// Push a value onto ST(0). Top decrements (mod 8) and the
    /// new ST(0) gets `v`.
    pub fn push(&mut self, v: f64) {
        self.top = (self.top.wrapping_sub(1)) & 7;
        self.regs[self.top as usize] = v;
        self.tag_valid[self.top as usize] = true;
    }

    /// Pop and discard ST(0). Top increments (mod 8) and the
    /// freed slot is tagged Empty.
    pub fn pop(&mut self) -> f64 {
        let v = self.regs[self.top as usize];
        self.tag_valid[self.top as usize] = false;
        self.top = (self.top.wrapping_add(1)) & 7;
        v
    }

    /// Read ST(i) without modifying the stack.
    pub fn st(&self, i: u8) -> f64 {
        self.regs[((self.top + i) & 7) as usize]
    }

    /// Write ST(i) without modifying TOP (used by `FADD ST(i),
    /// ST(0)` family).
    pub fn set_st(&mut self, i: u8, v: f64) {
        let idx = ((self.top + i) & 7) as usize;
        self.regs[idx] = v;
        self.tag_valid[idx] = true;
    }

    /// Compare ST(0) with `other` and update C0/C2/C3 per
    /// Intel SDM "FCOM" semantics.
    pub fn set_cc_from_compare(&mut self, st0: f64, other: f64) {
        // Clear the four CC bits.
        self.sw &= !(SW_C0 | SW_C1 | SW_C2 | SW_C3);
        if st0.is_nan() || other.is_nan() {
            // Unordered: C3=C2=C0=1.
            self.sw |= SW_C0 | SW_C2 | SW_C3;
        } else if st0 > other {
            // st0 > other: C3=C2=C0=0.
        } else if st0 < other {
            self.sw |= SW_C0;
        } else {
            // equal
            self.sw |= SW_C3;
        }
    }
}

/// Dispatch one of the eight x87 escapes. `opcode` is the
/// first byte (D8..DF). On entry, [`Cpu::regs.eip`] points
/// past the opcode (the next byte is the ModR/M).
///
/// Returns `Ok(StepOk::Continued)` on success or a [`Trap`]
/// for unimplemented forms. The caller (the integer dispatch
/// table) is responsible for routing the opcodes to here.
pub fn dispatch(cpu: &mut Cpu, mmu: &mut Mmu, opcode: u8, entry_eip: u32) -> Result<StepOk, Trap> {
    let mr = cpu.fetch_modrm(mmu)?;
    let bytes = cpu.peek_after_modrm(mmu, 16)?;
    let (op, consumed) = resolve_modrm32(mr, &bytes, &cpu.regs)?;
    cpu.regs.eip = cpu.regs.eip.wrapping_add(consumed as u32);
    let op = cpu.seg_apply_pub(op);
    if mr.mode == 0b11 {
        return dispatch_reg_form(cpu, opcode, mr.reg, mr.rm, entry_eip);
    }
    let addr = match op {
        Operand::Mem32(a) => a,
        Operand::Reg32(_) => unreachable!(),
    };
    match opcode {
        0xD8 => fpu_d8_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xD9 => fpu_d9_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xDA => fpu_da_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xDB => fpu_db_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xDC => fpu_dc_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xDD => fpu_dd_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xDE => fpu_de_mem(cpu, mmu, mr.reg, addr, entry_eip),
        0xDF => fpu_df_mem(cpu, mmu, mr.reg, addr, entry_eip),
        _ => unreachable!(),
    }
}

/// Reg-form x87: `mode == 0b11`. The `reg` field of the
/// ModR/M selects an FPU operation; `rm` is ST(i).
fn dispatch_reg_form(
    cpu: &mut Cpu,
    opcode: u8,
    reg: u8,
    rm: u8,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    match opcode {
        0xD8 => {
            // D8 C0+i → FADD ST(0), ST(i); C8 → FMUL; D0 →
            // FCOM; D8 → FCOMP; E0 → FSUB; E8 → FSUBR;
            // F0 → FDIV; F8 → FDIVR.
            let st0 = cpu.fpu.st(0);
            let sti = cpu.fpu.st(rm);
            let r = match reg {
                0 => st0 + sti,
                1 => st0 * sti,
                2 => {
                    cpu.fpu.set_cc_from_compare(st0, sti);
                    return Ok(StepOk::Continued);
                }
                3 => {
                    cpu.fpu.set_cc_from_compare(st0, sti);
                    cpu.fpu.pop();
                    return Ok(StepOk::Continued);
                }
                4 => st0 - sti,
                5 => sti - st0,
                6 => st0 / sti,
                7 => sti / st0,
                _ => unreachable!(),
            };
            cpu.fpu.set_st(0, r);
            Ok(StepOk::Continued)
        }
        0xD9 => {
            // D9 C0+i → FLD ST(i); C8+i → FXCH; D0..D7 →
            // FNOP / undefined; D8..DF unused; E0..EF various
            // single-operand FPU ops (FCHS, FABS, FTST, FXAM,
            // FLD1, FLDL2T, FLDL2E, FLDPI, FLDLG2, FLDLN2,
            // FLDZ); F0..FF various (F2NXM1, FYL2X, FPTAN,
            // FPATAN, FXTRACT, FPREM1, FDECSTP, FINCSTP,
            // FPREM, FYL2XP1, FSQRT, FSINCOS, FRNDINT,
            // FSCALE, FSIN, FCOS).
            match (reg, rm) {
                (0, _) => {
                    // FLD ST(i)
                    let v = cpu.fpu.st(rm);
                    cpu.fpu.push(v);
                    Ok(StepOk::Continued)
                }
                (1, _) => {
                    // FXCH ST(i)
                    let v0 = cpu.fpu.st(0);
                    let vi = cpu.fpu.st(rm);
                    cpu.fpu.set_st(0, vi);
                    cpu.fpu.set_st(rm, v0);
                    Ok(StepOk::Continued)
                }
                (2, 0) => {
                    // FNOP (D9 D0)
                    Ok(StepOk::Continued)
                }
                (4, 0) => {
                    // FCHS — negate ST(0)
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(0, -v);
                    Ok(StepOk::Continued)
                }
                (4, 1) => {
                    // FABS
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(0, v.abs());
                    Ok(StepOk::Continued)
                }
                (4, 4) => {
                    // FTST — compare ST(0) with 0.0
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_cc_from_compare(v, 0.0);
                    Ok(StepOk::Continued)
                }
                (5, 0) => {
                    cpu.fpu.push(1.0);
                    Ok(StepOk::Continued)
                }
                (5, 1) => {
                    // FLDL2T = log2(10)
                    cpu.fpu.push(std::f64::consts::LOG2_10);
                    Ok(StepOk::Continued)
                }
                (5, 2) => {
                    // FLDL2E
                    cpu.fpu.push(std::f64::consts::LOG2_E);
                    Ok(StepOk::Continued)
                }
                (5, 3) => {
                    cpu.fpu.push(std::f64::consts::PI);
                    Ok(StepOk::Continued)
                }
                (5, 4) => {
                    // FLDLG2 = log10(2)
                    cpu.fpu.push(std::f64::consts::LOG10_2);
                    Ok(StepOk::Continued)
                }
                (5, 5) => {
                    // FLDLN2 = ln(2)
                    cpu.fpu.push(std::f64::consts::LN_2);
                    Ok(StepOk::Continued)
                }
                (5, 6) => {
                    cpu.fpu.push(0.0);
                    Ok(StepOk::Continued)
                }
                (7, 0) => {
                    // FPREM (D9 F8) — partial remainder. Real
                    // x87 is iterative (handles huge magnitudes
                    // by repeated reduction), but a single IEEE
                    // remainder ≤ |st1| matches what codecs
                    // actually use. Round 22.
                    let st0 = cpu.fpu.st(0);
                    let st1 = cpu.fpu.st(1);
                    if st1 != 0.0 {
                        cpu.fpu.set_st(0, st0 - (st0 / st1).trunc() * st1);
                    }
                    Ok(StepOk::Continued)
                }
                (7, 2) => {
                    // FSQRT (D9 FA)
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(0, v.sqrt());
                    Ok(StepOk::Continued)
                }
                (7, 4) => {
                    // FRNDINT (D9 FC) — round ST(0) to integer.
                    // Round-21 mis-labelled this at (6, 4); the
                    // wmpcdcs8-2001 mpg4c32.dll never reaches
                    // (6, 4), but we want the right reg/rm pair
                    // here since clippy lint coverage relies on
                    // matched sub-forms being authoritative.
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(0, v.round());
                    Ok(StepOk::Continued)
                }
                (7, 5) => {
                    // FSCALE (D9 FD) — ST(0) *= 2^trunc(ST(1)).
                    let st0 = cpu.fpu.st(0);
                    let st1 = cpu.fpu.st(1);
                    let scale = (st1.trunc() as i32).clamp(-1023, 1023);
                    let result = st0 * (2f64).powi(scale);
                    cpu.fpu.set_st(0, result);
                    Ok(StepOk::Continued)
                }
                (7, 6) => {
                    // FSIN (D9 FE) — ST(0) = sin(ST(0)). The
                    // mpg4c32 v3 ICDecompressBegin path uses
                    // FSIN/FCOS for the IDCT post-processing
                    // setup tables.
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(0, v.sin());
                    Ok(StepOk::Continued)
                }
                (7, 7) => {
                    // FCOS (D9 FF) — ST(0) = cos(ST(0)).
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(0, v.cos());
                    Ok(StepOk::Continued)
                }
                _ => Err(Trap::PrivilegedOpcode {
                    eip: entry_eip,
                    mnemonic: "x87 D9 reg-form (unimplemented sub-form)",
                }),
            }
        }
        0xDA => {
            // DA reg-form — FCMOVcc / FUCOMPP. Codecs rarely
            // hit these. Trap loud.
            Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "x87 DA reg-form (FCMOVcc / FUCOMPP) — not modelled",
            })
        }
        0xDB => {
            // DB reg-form — FCMOVNB/NE/NBE/NU + FNCLEX (DB E2)
            // + FNINIT (DB E3) + FUCOMI (DB E8..) + FCOMI
            // (DB F0..).
            match (reg, rm) {
                (4, 2) => {
                    // FNCLEX
                    cpu.fpu.sw = 0;
                    Ok(StepOk::Continued)
                }
                (4, 3) => {
                    // FNINIT
                    cpu.fpu = FpuState::new();
                    cpu.fpu_cw = 0x037F;
                    Ok(StepOk::Continued)
                }
                _ => Err(Trap::PrivilegedOpcode {
                    eip: entry_eip,
                    mnemonic: "x87 DB reg-form (unimplemented)",
                }),
            }
        }
        0xDC => {
            // DC C0+i → FADD ST(i), ST(0); C8 FMUL; E0 FSUBR;
            // E8 FSUB; F0 FDIVR; F8 FDIV.
            let st0 = cpu.fpu.st(0);
            let sti = cpu.fpu.st(rm);
            let r = match reg {
                0 => sti + st0,
                1 => sti * st0,
                2 => {
                    cpu.fpu.set_cc_from_compare(st0, sti);
                    return Ok(StepOk::Continued);
                }
                3 => {
                    cpu.fpu.set_cc_from_compare(st0, sti);
                    cpu.fpu.pop();
                    return Ok(StepOk::Continued);
                }
                4 => sti - st0,
                5 => st0 - sti,
                6 => sti / st0,
                7 => st0 / sti,
                _ => unreachable!(),
            };
            cpu.fpu.set_st(rm, r);
            Ok(StepOk::Continued)
        }
        0xDD => {
            // DD C0+i → FFREE ST(i); D0+i → FST ST(i);
            // D8+i → FSTP ST(i); E0+i → FUCOM ST(i);
            // E8+i → FUCOMP ST(i).
            match reg {
                0 => {
                    // FFREE — mark the slot Empty without
                    // popping.
                    let idx = ((cpu.fpu.top + rm) & 7) as usize;
                    cpu.fpu.tag_valid[idx] = false;
                    Ok(StepOk::Continued)
                }
                2 => {
                    // FST ST(i) ← ST(0)
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(rm, v);
                    Ok(StepOk::Continued)
                }
                3 => {
                    // FSTP ST(i)
                    let v = cpu.fpu.st(0);
                    cpu.fpu.set_st(rm, v);
                    cpu.fpu.pop();
                    Ok(StepOk::Continued)
                }
                4 => {
                    // FUCOM
                    let st0 = cpu.fpu.st(0);
                    let sti = cpu.fpu.st(rm);
                    cpu.fpu.set_cc_from_compare(st0, sti);
                    Ok(StepOk::Continued)
                }
                5 => {
                    let st0 = cpu.fpu.st(0);
                    let sti = cpu.fpu.st(rm);
                    cpu.fpu.set_cc_from_compare(st0, sti);
                    cpu.fpu.pop();
                    Ok(StepOk::Continued)
                }
                _ => Err(Trap::PrivilegedOpcode {
                    eip: entry_eip,
                    mnemonic: "x87 DD reg-form (unimplemented)",
                }),
            }
        }
        0xDE => {
            // DE matches DC but pops afterwards. Special: DE D9
            // is FCOMPP (compare + pop twice). DE C0+i FADDP.
            match (reg, rm) {
                (3, 1) => {
                    // FCOMPP — D9 — compare ST(0)/ST(1) then
                    // pop both
                    let st0 = cpu.fpu.st(0);
                    let st1 = cpu.fpu.st(1);
                    cpu.fpu.set_cc_from_compare(st0, st1);
                    cpu.fpu.pop();
                    cpu.fpu.pop();
                    Ok(StepOk::Continued)
                }
                _ => {
                    let st0 = cpu.fpu.st(0);
                    let sti = cpu.fpu.st(rm);
                    let r = match reg {
                        0 => sti + st0, // FADDP ST(i)
                        1 => sti * st0, // FMULP
                        4 => sti - st0, // FSUBRP
                        5 => st0 - sti, // FSUBP
                        6 => sti / st0, // FDIVRP
                        7 => st0 / sti, // FDIVP
                        _ => {
                            return Err(Trap::PrivilegedOpcode {
                                eip: entry_eip,
                                mnemonic: "x87 DE reg-form (bad sub-op)",
                            });
                        }
                    };
                    cpu.fpu.set_st(rm, r);
                    cpu.fpu.pop();
                    Ok(StepOk::Continued)
                }
            }
        }
        0xDF => {
            // DF E0 — FNSTSW AX. DF E8+i FUCOMI. DF F0+i FCOMI.
            match (reg, rm) {
                (4, 0) => {
                    // FNSTSW AX — copy SW to AX
                    let sw = cpu.fpu.sw;
                    let prev = cpu.regs.get32(super::regs::Reg32::Eax);
                    let new_eax = (prev & 0xFFFF_0000) | u32::from(sw);
                    cpu.regs.set32(super::regs::Reg32::Eax, new_eax);
                    Ok(StepOk::Continued)
                }
                _ => Err(Trap::PrivilegedOpcode {
                    eip: entry_eip,
                    mnemonic: "x87 DF reg-form (unimplemented)",
                }),
            }
        }
        _ => unreachable!(),
    }
}

// -------- memory-form helpers --------------------------------

/// `D8 /N m32` — single-precision arithmetic with ST(0).
fn fpu_d8_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    let bits = mmu.load32(addr)?;
    let v = f32::from_bits(bits) as f64;
    let st0 = cpu.fpu.st(0);
    let r = match sub {
        0 => st0 + v,
        1 => st0 * v,
        2 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            return Ok(StepOk::Continued);
        }
        3 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            cpu.fpu.pop();
            return Ok(StepOk::Continued);
        }
        4 => st0 - v,
        5 => v - st0,
        6 => st0 / v,
        7 => v / st0,
        _ => {
            return Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "x87 D8 mem (bad sub-op)",
            });
        }
    };
    cpu.fpu.set_st(0, r);
    Ok(StepOk::Continued)
}

/// `D9 /N m32` — FLD m32 / FST m32 / FSTP m32 / FLDENV /
/// FLDCW / FNSTENV / FNSTCW.
fn fpu_d9_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    match sub {
        0 => {
            // FLD m32
            let bits = mmu.load32(addr)?;
            let v = f32::from_bits(bits) as f64;
            cpu.fpu.push(v);
            Ok(StepOk::Continued)
        }
        2 => {
            // FST m32
            let v = cpu.fpu.st(0);
            mmu.store32(addr, (v as f32).to_bits())?;
            Ok(StepOk::Continued)
        }
        3 => {
            // FSTP m32
            let v = cpu.fpu.st(0);
            mmu.store32(addr, (v as f32).to_bits())?;
            cpu.fpu.pop();
            Ok(StepOk::Continued)
        }
        4 => {
            // FLDENV m28 — load env (CW/SW/TW + ip + dp). We
            // only honour the CW (first 4 bytes, low 16 bits).
            let cw = mmu.load16(addr)?;
            cpu.fpu_cw = cw;
            Ok(StepOk::Continued)
        }
        5 => {
            // FLDCW m16
            cpu.fpu_cw = mmu.load16(addr)?;
            Ok(StepOk::Continued)
        }
        6 => {
            // FNSTENV m28 — write back the CW + a zeroed
            // pad. The codec only reads the CW after FLDENV;
            // we don't need exact env semantics.
            mmu.store16(addr, cpu.fpu_cw)?;
            for off in 2..28u32 {
                mmu.store8(addr.wrapping_add(off), 0)?;
            }
            Ok(StepOk::Continued)
        }
        7 => {
            // FNSTCW m16
            mmu.store16(addr, cpu.fpu_cw)?;
            Ok(StepOk::Continued)
        }
        _ => Err(Trap::PrivilegedOpcode {
            eip: entry_eip,
            mnemonic: "x87 D9 mem (bad sub-op)",
        }),
    }
}

/// `DA /N m32` — integer-source single-precision arithmetic
/// with ST(0); operand is a 32-bit signed integer.
fn fpu_da_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    let v = mmu.load32(addr)? as i32 as f64;
    let st0 = cpu.fpu.st(0);
    let r = match sub {
        0 => st0 + v,
        1 => st0 * v,
        2 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            return Ok(StepOk::Continued);
        }
        3 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            cpu.fpu.pop();
            return Ok(StepOk::Continued);
        }
        4 => st0 - v,
        5 => v - st0,
        6 => st0 / v,
        7 => v / st0,
        _ => {
            return Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "x87 DA mem (bad sub-op)",
            });
        }
    };
    cpu.fpu.set_st(0, r);
    Ok(StepOk::Continued)
}

/// `DB /N m32` — integer load/store + FLD m80 (extended) +
/// FNCLEX/FINIT (covered by reg-form).
fn fpu_db_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    match sub {
        0 => {
            // FILD m32 — load signed int as f64
            let v = mmu.load32(addr)? as i32 as f64;
            cpu.fpu.push(v);
            Ok(StepOk::Continued)
        }
        2 => {
            // FIST m32
            let v = cpu.fpu.st(0).round() as i32;
            mmu.store32(addr, v as u32)?;
            Ok(StepOk::Continued)
        }
        3 => {
            // FISTP m32
            let v = cpu.fpu.st(0).round() as i32;
            mmu.store32(addr, v as u32)?;
            cpu.fpu.pop();
            Ok(StepOk::Continued)
        }
        5 => {
            // FLD m80 — load extended-precision. We approximate
            // by reading the 64-bit mantissa as f64.
            let lo = mmu.load32(addr)?;
            let hi = mmu.load32(addr.wrapping_add(4))?;
            let m64 = (u64::from(hi) << 32) | u64::from(lo);
            let exp = mmu.load16(addr.wrapping_add(8))?;
            // Convert: real f80 = (sign,exp[15],frac[63..0]).
            // We do a best-effort conversion: extract sign bit
            // from exp, extract the unbiased exponent, multiply
            // mantissa back together as f64.
            let sign = (exp >> 15) & 1;
            let unbiased = (exp & 0x7FFF) as i32 - 16383;
            let mantissa = (m64 as f64) / (1u64 << 63) as f64; // [0,2)
            let v_abs = mantissa * 2f64.powi(unbiased);
            let v = if sign != 0 { -v_abs } else { v_abs };
            cpu.fpu.push(v);
            Ok(StepOk::Continued)
        }
        7 => {
            // FSTP m80
            let v = cpu.fpu.st(0);
            // Best-effort encode: split into mantissa+exp.
            let bits = v.to_bits();
            let sign = (bits >> 63) & 1;
            let exp64 = ((bits >> 52) & 0x7FF) as i32;
            let frac52 = bits & 0x000F_FFFF_FFFF_FFFF;
            // Unbiased: f64 bias = 1023; f80 bias = 16383.
            let unbiased = exp64 - 1023;
            let exp80 = (unbiased + 16383) as u16 & 0x7FFF;
            // f80 mantissa has explicit integer bit (set on
            // normals) plus 63 fraction bits.
            let m64 = if exp64 == 0 {
                // subnormal/zero
                frac52 << 11
            } else {
                (1u64 << 63) | (frac52 << 11)
            };
            let lo = (m64 & 0xFFFF_FFFF) as u32;
            let hi = (m64 >> 32) as u32;
            let exp_word = ((sign as u16) << 15) | exp80;
            mmu.store32(addr, lo)?;
            mmu.store32(addr.wrapping_add(4), hi)?;
            mmu.store16(addr.wrapping_add(8), exp_word)?;
            cpu.fpu.pop();
            Ok(StepOk::Continued)
        }
        _ => Err(Trap::PrivilegedOpcode {
            eip: entry_eip,
            mnemonic: "x87 DB mem (bad sub-op)",
        }),
    }
}

/// `DC /N m64` — double-precision arithmetic with ST(0).
fn fpu_dc_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    let lo = mmu.load32(addr)?;
    let hi = mmu.load32(addr.wrapping_add(4))?;
    let bits = (u64::from(hi) << 32) | u64::from(lo);
    let v = f64::from_bits(bits);
    let st0 = cpu.fpu.st(0);
    let r = match sub {
        0 => st0 + v,
        1 => st0 * v,
        2 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            return Ok(StepOk::Continued);
        }
        3 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            cpu.fpu.pop();
            return Ok(StepOk::Continued);
        }
        4 => st0 - v,
        5 => v - st0,
        6 => st0 / v,
        7 => v / st0,
        _ => {
            return Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "x87 DC mem (bad sub-op)",
            });
        }
    };
    cpu.fpu.set_st(0, r);
    Ok(StepOk::Continued)
}

/// `DD /N m64` — FLD m64 / FST m64 / FSTP m64 / FRSTOR /
/// FNSAVE.
fn fpu_dd_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    match sub {
        0 => {
            // FLD m64
            let lo = mmu.load32(addr)?;
            let hi = mmu.load32(addr.wrapping_add(4))?;
            let bits = (u64::from(hi) << 32) | u64::from(lo);
            cpu.fpu.push(f64::from_bits(bits));
            Ok(StepOk::Continued)
        }
        2 => {
            // FST m64
            let bits = cpu.fpu.st(0).to_bits();
            mmu.store32(addr, (bits & 0xFFFF_FFFF) as u32)?;
            mmu.store32(addr.wrapping_add(4), (bits >> 32) as u32)?;
            Ok(StepOk::Continued)
        }
        3 => {
            // FSTP m64
            let bits = cpu.fpu.st(0).to_bits();
            mmu.store32(addr, (bits & 0xFFFF_FFFF) as u32)?;
            mmu.store32(addr.wrapping_add(4), (bits >> 32) as u32)?;
            cpu.fpu.pop();
            Ok(StepOk::Continued)
        }
        7 => {
            // FNSTSW m16
            mmu.store16(addr, cpu.fpu.sw)?;
            Ok(StepOk::Continued)
        }
        _ => Err(Trap::PrivilegedOpcode {
            eip: entry_eip,
            mnemonic: "x87 DD mem (bad sub-op)",
        }),
    }
}

/// `DE /N m16` — integer-source single-precision arithmetic.
fn fpu_de_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    let v = mmu.load16(addr)? as i16 as f64;
    let st0 = cpu.fpu.st(0);
    let r = match sub {
        0 => st0 + v,
        1 => st0 * v,
        2 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            return Ok(StepOk::Continued);
        }
        3 => {
            cpu.fpu.set_cc_from_compare(st0, v);
            cpu.fpu.pop();
            return Ok(StepOk::Continued);
        }
        4 => st0 - v,
        5 => v - st0,
        6 => st0 / v,
        7 => v / st0,
        _ => {
            return Err(Trap::PrivilegedOpcode {
                eip: entry_eip,
                mnemonic: "x87 DE mem (bad sub-op)",
            });
        }
    };
    cpu.fpu.set_st(0, r);
    Ok(StepOk::Continued)
}

/// `DF /N` — short-int arithmetic + 64-bit int load/store.
fn fpu_df_mem(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    sub: u8,
    addr: u32,
    entry_eip: u32,
) -> Result<StepOk, Trap> {
    match sub {
        0 => {
            // FILD m16
            let v = mmu.load16(addr)? as i16 as f64;
            cpu.fpu.push(v);
            Ok(StepOk::Continued)
        }
        2 => {
            // FIST m16
            let v = cpu.fpu.st(0).round() as i16;
            mmu.store16(addr, v as u16)?;
            Ok(StepOk::Continued)
        }
        3 => {
            // FISTP m16
            let v = cpu.fpu.st(0).round() as i16;
            mmu.store16(addr, v as u16)?;
            cpu.fpu.pop();
            Ok(StepOk::Continued)
        }
        5 => {
            // FILD m64
            let lo = mmu.load32(addr)?;
            let hi = mmu.load32(addr.wrapping_add(4))?;
            let v64 = ((u64::from(hi) << 32) | u64::from(lo)) as i64;
            cpu.fpu.push(v64 as f64);
            Ok(StepOk::Continued)
        }
        7 => {
            // FISTP m64
            let v = cpu.fpu.st(0).round() as i64;
            mmu.store32(addr, (v as u64 & 0xFFFF_FFFF) as u32)?;
            mmu.store32(addr.wrapping_add(4), ((v as u64) >> 32) as u32)?;
            cpu.fpu.pop();
            Ok(StepOk::Continued)
        }
        _ => Err(Trap::PrivilegedOpcode {
            eip: entry_eip,
            mnemonic: "x87 DF mem (bad sub-op)",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpu_push_pop_roundtrip() {
        let mut f = FpuState::new();
        assert!(!f.tag_valid[0]);
        f.push(3.5);
        f.push(7.0);
        assert_eq!(f.st(0), 7.0);
        assert_eq!(f.st(1), 3.5);
        let v = f.pop();
        assert_eq!(v, 7.0);
        assert_eq!(f.st(0), 3.5);
    }

    #[test]
    fn fpu_compare_sets_condition_codes() {
        let mut f = FpuState::new();
        f.set_cc_from_compare(2.0, 1.0);
        assert_eq!(f.sw & (SW_C0 | SW_C2 | SW_C3), 0);
        f.set_cc_from_compare(1.0, 2.0);
        assert_eq!(f.sw & SW_C0, SW_C0);
        f.set_cc_from_compare(2.0, 2.0);
        assert_eq!(f.sw & SW_C3, SW_C3);
        f.set_cc_from_compare(f64::NAN, 1.0);
        assert_eq!(f.sw & (SW_C0 | SW_C2 | SW_C3), SW_C0 | SW_C2 | SW_C3);
    }

    #[test]
    fn fpu_set_st_does_not_touch_top() {
        let mut f = FpuState::new();
        f.push(1.0);
        f.push(2.0);
        f.push(3.0);
        let top_before = f.top;
        f.set_st(1, 99.0);
        assert_eq!(f.top, top_before);
        assert_eq!(f.st(1), 99.0);
        assert_eq!(f.st(0), 3.0);
    }
}

//! AArch64 (ARM64) user-mode interpreter.
//!
//! A from-scratch fixed-width (4-byte little-endian) decoder + executor for
//! the integer / load-store / branch subset that a freestanding `clang`
//! binary or a libc `_start` touches. It shares the project's `u32` [`Mmu`]
//! (all regions mapped in the low 4 GiB) and surfaces the `SVC #0` gate as
//! [`Trap::Syscall`] for the Linux engine to service.
//!
//! Out of scope (added only if a target needs them): NEON/SIMD, atomics
//! (LDXR/STXR), the full system-register space (only `TPIDR_EL0` for TLS).

use super::isa_int::StepOk;
use super::{Mmu, Trap};

/// Default per-program instruction budget (mirrors the x86 `Cpu`).
const DEFAULT_LIMIT: u64 = 200_000_000;

/// The ARM64 condition flags (PSTATE.NZCV).
#[derive(Debug, Default, Clone, Copy)]
pub struct Nzcv {
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

/// An AArch64 user-mode CPU: 31 general registers (`x0..x30`), a dedicated
/// stack pointer, the program counter, condition flags, and `TPIDR_EL0`
/// (the thread pointer libc uses for TLS).
#[derive(Debug)]
pub struct Aarch64Cpu {
    /// `x0..x30`. There is no `x31`: register index 31 reads as the zero
    /// register (`XZR`) or the stack pointer depending on the instruction.
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: Nzcv,
    /// `TPIDR_EL0` — read via `MRS` for thread-local storage.
    pub tpidr: u64,
    pub instr_count: u64,
    instr_limit: u64,
}

impl Default for Aarch64Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Aarch64Cpu {
    #[must_use]
    pub fn new() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            nzcv: Nzcv::default(),
            tpidr: 0,
            instr_count: 0,
            instr_limit: DEFAULT_LIMIT,
        }
    }

    /// Set the instruction budget (0 disables the limit).
    pub fn set_instr_limit(&mut self, limit: u64) {
        self.instr_limit = if limit == 0 { u64::MAX } else { limit };
    }

    // ---- register access -------------------------------------------------

    /// Read `Xn`/`Wn` where index 31 is the **zero register**.
    #[inline]
    fn rd(&self, i: u32, sf: bool) -> u64 {
        let v = if i == 31 { 0 } else { self.x[i as usize] };
        if sf {
            v
        } else {
            v & 0xffff_ffff
        }
    }

    /// Write `Xn`/`Wn` where index 31 **discards** (zero register). A 32-bit
    /// write zero-extends into the full 64-bit register.
    #[inline]
    fn wr(&mut self, i: u32, sf: bool, v: u64) {
        if i == 31 {
            return;
        }
        self.x[i as usize] = if sf { v } else { v & 0xffff_ffff };
    }

    /// Read where index 31 is the **stack pointer** (address-form ops).
    #[inline]
    fn rd_sp(&self, i: u32, sf: bool) -> u64 {
        let v = if i == 31 { self.sp } else { self.x[i as usize] };
        if sf {
            v
        } else {
            v & 0xffff_ffff
        }
    }

    /// Write where index 31 is the **stack pointer**.
    #[inline]
    fn wr_sp(&mut self, i: u32, sf: bool, v: u64) {
        let v = if sf { v } else { v & 0xffff_ffff };
        if i == 31 {
            self.sp = v;
        } else {
            self.x[i as usize] = v;
        }
    }

    // ---- step ------------------------------------------------------------

    /// Execute one instruction. Returns [`StepOk::Continued`] normally;
    /// errors carry a [`Trap`] (memory fault, `SVC` gate, undefined opcode,
    /// or the instruction-limit guard).
    ///
    /// # Errors
    /// See [`Trap`].
    pub fn step(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        if self.instr_count >= self.instr_limit {
            return Err(Trap::InstructionLimitExceeded {
                eip: self.pc as u32,
                count: self.instr_count,
            });
        }
        self.instr_count += 1;

        let pc = self.pc as u32;
        let instr = mmu.load32(pc)?;
        // Default: advance to the next instruction. Branches overwrite `pc`.
        self.pc = self.pc.wrapping_add(4);
        self.exec(instr, mmu)
    }

    #[allow(clippy::too_many_lines)]
    fn exec(&mut self, instr: u32, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let op0 = (instr >> 25) & 0xf; // top-level encoding group (bits[28:25])

        // ---- Data processing -- immediate (op0 = 100x) -------------------
        if op0 == 0x8 || op0 == 0x9 {
            return self.dp_immediate(instr);
        }
        // ---- Branches, exception, system (op0 = 101x) --------------------
        if op0 == 0xa || op0 == 0xb {
            return self.branch_sys(instr, mmu);
        }
        // ---- Loads and stores (op0 = x1x0) -------------------------------
        if op0 & 0x5 == 0x4 {
            return self.load_store(instr, mmu);
        }
        // ---- Data processing -- register (op0 = x101) --------------------
        if op0 & 0x7 == 0x5 {
            return self.dp_register(instr);
        }

        Err(self.undef(instr))
    }

    fn undef(&self, instr: u32) -> Trap {
        Trap::UndefinedOpcode {
            eip: self.pc.wrapping_sub(4) as u32,
            opcode: instr,
        }
    }

    // ---- data-processing immediate ---------------------------------------

    fn dp_immediate(&mut self, instr: u32) -> Result<StepOk, Trap> {
        let sf = (instr >> 31) & 1 == 1;
        let rd = instr & 0x1f;
        let rn = (instr >> 5) & 0x1f;
        let grp = (instr >> 23) & 0x3f; // bits[28:23]

        match grp {
            // PC-relative addressing: ADR / ADRP (bits[28:24] = 10000)
            0b100000 | 0b100001 => {
                let immlo = (instr >> 29) & 0x3;
                let immhi = (instr >> 5) & 0x7ffff;
                let imm = sign_extend((u64::from(immhi) << 2) | u64::from(immlo), 21);
                let base = self.pc.wrapping_sub(4); // PC of this instruction
                let is_adrp = (instr >> 31) & 1 == 1;
                let val = if is_adrp {
                    (base & !0xfff).wrapping_add(imm << 12)
                } else {
                    base.wrapping_add(imm)
                };
                self.wr(rd, true, val);
                Ok(StepOk::Continued)
            }
            // Add/subtract (immediate) — bits[28:24] = 10001
            0b100010 | 0b100011 => {
                let sub = (instr >> 30) & 1 == 1;
                let setflags = (instr >> 29) & 1 == 1;
                let sh = (instr >> 22) & 1 == 1;
                let imm12 = (instr >> 10) & 0xfff;
                let imm = if sh {
                    u64::from(imm12) << 12
                } else {
                    u64::from(imm12)
                };
                let a = self.rd_sp(rn, sf);
                let (res, n, z, c, v) = if sub {
                    add_with_carry(a, !imm, 1, sf)
                } else {
                    add_with_carry(a, imm, 0, sf)
                };
                if setflags {
                    self.nzcv = Nzcv { n, z, c, v };
                    self.wr(rd, sf, res); // SUBS/ADDS: Rd is XZR-form
                } else {
                    self.wr_sp(rd, sf, res); // ADD/SUB: Rd is SP-form
                }
                Ok(StepOk::Continued)
            }
            // Logical (immediate)
            0b100100 => {
                let opc = (instr >> 29) & 0x3;
                let nbit = (instr >> 22) & 1;
                let immr = (instr >> 16) & 0x3f;
                let imms = (instr >> 10) & 0x3f;
                let datasize = if sf { 64 } else { 32 };
                let Some((imm, _)) = decode_bit_masks(nbit, imms, immr, true, datasize) else {
                    return Err(self.undef(instr));
                };
                let a = self.rd(rn, sf);
                let res = match opc {
                    0b00 | 0b11 => a & imm, // AND / ANDS
                    0b01 => a | imm,        // ORR
                    _ => a ^ imm,           // EOR
                };
                if opc == 0b11 {
                    self.set_logic_flags(res, sf);
                    self.wr(rd, sf, res);
                } else {
                    self.wr_sp(rd, sf, res); // non-flag logical: SP-form Rd
                }
                Ok(StepOk::Continued)
            }
            // Move wide (immediate): MOVN / MOVZ / MOVK
            0b100101 => {
                let opc = (instr >> 29) & 0x3;
                let hw = (instr >> 21) & 0x3;
                let imm16 = u64::from((instr >> 5) & 0xffff);
                let shift = hw * 16;
                let val = imm16 << shift;
                let res = match opc {
                    0b00 => !val,                                              // MOVN
                    0b10 => val,                                               // MOVZ
                    0b11 => (self.rd(rd, true) & !(0xffffu64 << shift)) | val, // MOVK
                    _ => return Err(self.undef(instr)),
                };
                self.wr(rd, sf, res);
                Ok(StepOk::Continued)
            }
            // Bitfield: SBFM / BFM / UBFM (covers LSL/LSR/ASR/UBFX/SXTB…)
            0b100110 => {
                let opc = (instr >> 29) & 0x3;
                let nbit = (instr >> 22) & 1;
                let immr = (instr >> 16) & 0x3f;
                let imms = (instr >> 10) & 0x3f;
                let datasize = if sf { 64 } else { 32 };
                let Some((wmask, tmask)) = decode_bit_masks(nbit, imms, immr, false, datasize)
                else {
                    return Err(self.undef(instr));
                };
                let src = self.rd(rn, sf);
                let dst = if opc == 0b01 { self.rd(rd, sf) } else { 0 };
                let bot = (dst & !wmask) | (ror_width(src, immr, datasize) & wmask);
                // top: sign bit for SBFM, dst for BFM, zeros for UBFM
                let top = if opc == 0b00 {
                    // SBFM: replicate bit imms
                    if (src >> imms) & 1 == 1 {
                        u64::MAX
                    } else {
                        0
                    }
                } else if opc == 0b01 {
                    dst
                } else {
                    0
                };
                let res = (top & !tmask) | (bot & tmask);
                self.wr(rd, sf, res);
                Ok(StepOk::Continued)
            }
            // Extract: EXTR (also ROR immediate alias)
            0b100111 => {
                let rm = (instr >> 16) & 0x1f;
                let imms = (instr >> 10) & 0x3f;
                let datasize = if sf { 64 } else { 32 };
                let lo = self.rd(rm, sf);
                let hi = self.rd(rn, sf);
                let res = if imms == 0 {
                    lo
                } else if datasize == 64 {
                    (hi << (64 - imms)) | (lo >> imms)
                } else {
                    let combined = (hi << 32) | (lo & 0xffff_ffff);
                    (combined >> imms) & 0xffff_ffff
                };
                self.wr(rd, sf, res);
                Ok(StepOk::Continued)
            }
            _ => Err(self.undef(instr)),
        }
    }

    // ---- data-processing register ----------------------------------------

    fn dp_register(&mut self, instr: u32) -> Result<StepOk, Trap> {
        let sf = (instr >> 31) & 1 == 1;
        let rd = instr & 0x1f;
        let rn = (instr >> 5) & 0x1f;
        let rm = (instr >> 16) & 0x1f;
        let op28_24 = (instr >> 24) & 0x1f;

        // Add/subtract (shifted / extended register): bits[28:24] = 01011
        if op28_24 == 0b01011 {
            let sub = (instr >> 30) & 1 == 1;
            let setflags = (instr >> 29) & 1 == 1;
            let extended = (instr >> 21) & 1 == 1;
            let a = self.rd_sp(rn, sf);
            let b = if extended {
                let option = (instr >> 13) & 0x7;
                let shift = (instr >> 10) & 0x7;
                extend_reg(self.rd(rm, true), option, shift, sf)
            } else {
                let shift_type = (instr >> 22) & 0x3;
                let amount = (instr >> 10) & 0x3f;
                shift_reg(self.rd(rm, sf), shift_type, amount, sf)
            };
            let (res, n, z, c, v) = if sub {
                add_with_carry(a, !b, 1, sf)
            } else {
                add_with_carry(a, b, 0, sf)
            };
            if setflags {
                self.nzcv = Nzcv { n, z, c, v };
                self.wr(rd, sf, res);
            } else {
                self.wr(rd, sf, res);
            }
            return Ok(StepOk::Continued);
        }

        // Logical (shifted register): bits[28:24] = 01010
        if op28_24 == 0b01010 {
            let opc = (instr >> 29) & 0x3;
            let shift_type = (instr >> 22) & 0x3;
            let nbit = (instr >> 21) & 1;
            let amount = (instr >> 10) & 0x3f;
            let a = self.rd(rn, sf);
            let mut b = shift_reg(self.rd(rm, sf), shift_type, amount, sf);
            if nbit == 1 {
                b = !b;
            }
            let res = match opc {
                0b00 | 0b11 => a & b, // AND / ANDS
                0b01 => a | b,        // ORR (MOV reg = ORR XZR, Rm)
                _ => a ^ b,           // EOR
            };
            if opc == 0b11 {
                self.set_logic_flags(res, sf);
            }
            self.wr(rd, sf, res);
            return Ok(StepOk::Continued);
        }

        // The remaining register groups share bits[28:21] = 11010xxx.
        let op28_21 = (instr >> 21) & 0xff;
        match op28_21 {
            // Add/subtract with carry: ADC / SBC
            0b11010000 => {
                let sub = (instr >> 30) & 1 == 1;
                let setflags = (instr >> 29) & 1 == 1;
                let cin = u64::from(self.nzcv.c);
                let a = self.rd(rn, sf);
                let b = self.rd(rm, sf);
                let (res, n, z, c, v) = if sub {
                    add_with_carry(a, !b, cin, sf)
                } else {
                    add_with_carry(a, b, cin, sf)
                };
                if setflags {
                    self.nzcv = Nzcv { n, z, c, v };
                }
                self.wr(rd, sf, res);
                Ok(StepOk::Continued)
            }
            // Conditional select: CSEL / CSINC / CSINV / CSNEG
            0b11010100 => {
                let cond = (instr >> 12) & 0xf;
                let o2 = (instr >> 10) & 0x1; // op2<0>
                let op = (instr >> 30) & 1; // 0=CSEL/CSINC, 1=CSINV/CSNEG
                let a = self.rd(rn, sf);
                let b = self.rd(rm, sf);
                let res = if self.cond_holds(cond) {
                    a
                } else {
                    match (op, o2) {
                        (0, 0) => b,                 // CSEL
                        (0, 1) => b.wrapping_add(1), // CSINC
                        (1, 0) => !b,                // CSINV
                        _ => (!b).wrapping_add(1),   // CSNEG
                    }
                };
                self.wr(rd, sf, res);
                Ok(StepOk::Continued)
            }
            // Conditional compare (register / immediate): CCMP / CCMN
            0b11010010 => {
                let sub = (instr >> 30) & 1 == 1;
                let cond = (instr >> 12) & 0xf;
                let imm_form = (instr >> 11) & 1 == 1;
                let nzcv = instr & 0xf;
                let a = self.rd(rn, sf);
                let b = if imm_form {
                    u64::from((instr >> 16) & 0x1f)
                } else {
                    self.rd(rm, sf)
                };
                if self.cond_holds(cond) {
                    let (_, n, z, c, v) = if sub {
                        add_with_carry(a, !b, 1, sf)
                    } else {
                        add_with_carry(a, b, 0, sf)
                    };
                    self.nzcv = Nzcv { n, z, c, v };
                } else {
                    self.nzcv = Nzcv {
                        n: nzcv & 0x8 != 0,
                        z: nzcv & 0x4 != 0,
                        c: nzcv & 0x2 != 0,
                        v: nzcv & 0x1 != 0,
                    };
                }
                Ok(StepOk::Continued)
            }
            // Data-processing (2 source): UDIV / SDIV / LSLV / LSRV / ASRV / RORV
            0b11010110 => {
                let opcode = (instr >> 10) & 0x3f;
                let a = self.rd(rn, sf);
                let b = self.rd(rm, sf);
                let res = match opcode {
                    0b000010 => self.div_u(a, b, sf),                   // UDIV
                    0b000011 => self.div_s(a, b, sf),                   // SDIV
                    0b001000 => shift_reg(a, 0, (b & 0x3f) as u32, sf), // LSLV
                    0b001001 => shift_reg(a, 1, (b & 0x3f) as u32, sf), // LSRV
                    0b001010 => shift_reg(a, 2, (b & 0x3f) as u32, sf), // ASRV
                    0b001011 => shift_reg(a, 3, (b & 0x3f) as u32, sf), // RORV
                    _ => return Err(self.undef(instr)),
                };
                self.wr(rd, sf, res);
                Ok(StepOk::Continued)
            }
            _ => {
                // Data-processing (3 source): MADD / MSUB (bits[28:24]=11011)
                if op28_24 == 0b11011 {
                    let ra = (instr >> 10) & 0x1f;
                    let o0 = (instr >> 15) & 1;
                    let a = self.rd(rn, sf);
                    let b = self.rd(rm, sf);
                    let acc = self.rd(ra, sf);
                    let prod = a.wrapping_mul(b);
                    let res = if o0 == 0 {
                        acc.wrapping_add(prod)
                    } else {
                        acc.wrapping_sub(prod)
                    };
                    self.wr(rd, sf, res);
                    return Ok(StepOk::Continued);
                }
                Err(self.undef(instr))
            }
        }
    }

    fn div_u(&self, a: u64, b: u64, sf: bool) -> u64 {
        if b == 0 {
            return 0;
        }
        if sf {
            a / b
        } else {
            u64::from((a as u32) / (b as u32))
        }
    }

    fn div_s(&self, a: u64, b: u64, sf: bool) -> u64 {
        if b == 0 {
            return 0;
        }
        if sf {
            (a as i64).wrapping_div(b as i64) as u64
        } else {
            ((a as i32).wrapping_div(b as i32)) as u32 as u64
        }
    }

    // ---- branches / exception / system -----------------------------------

    fn branch_sys(&mut self, instr: u32, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let top6 = (instr >> 26) & 0x3f;
        let here = self.pc.wrapping_sub(4); // PC of this instruction

        // Unconditional branch (immediate): B / BL
        if top6 & 0x1f == 0b00101 {
            let imm = sign_extend(u64::from(instr & 0x03ff_ffff), 26) << 2;
            if (instr >> 31) & 1 == 1 {
                self.x[30] = self.pc; // BL: link = return address
            }
            self.pc = here.wrapping_add(imm);
            return Ok(StepOk::Continued);
        }

        // Compare & branch: CBZ / CBNZ
        if (instr >> 25) & 0x3f == 0b011010 {
            let sf = (instr >> 31) & 1 == 1;
            let nz = (instr >> 24) & 1 == 1;
            let rt = instr & 0x1f;
            let imm = sign_extend(u64::from((instr >> 5) & 0x7ffff), 19) << 2;
            let val = self.rd(rt, sf);
            let take = if nz { val != 0 } else { val == 0 };
            if take {
                self.pc = here.wrapping_add(imm);
            }
            return Ok(StepOk::Continued);
        }

        // Test & branch: TBZ / TBNZ
        if (instr >> 25) & 0x3f == 0b011011 {
            let nz = (instr >> 24) & 1 == 1;
            let rt = instr & 0x1f;
            let bit = ((instr >> 31) & 1) << 5 | ((instr >> 19) & 0x1f);
            let imm = sign_extend(u64::from((instr >> 5) & 0x3fff), 14) << 2;
            let val = self.x.get(rt as usize).copied().unwrap_or(0);
            let set = (val >> bit) & 1 == 1;
            let take = if nz { set } else { !set };
            if take {
                self.pc = here.wrapping_add(imm);
            }
            return Ok(StepOk::Continued);
        }

        // Conditional branch (immediate): B.cond
        if (instr >> 24) & 0xff == 0b01010100 {
            let cond = instr & 0xf;
            let imm = sign_extend(u64::from((instr >> 5) & 0x7ffff), 19) << 2;
            if self.cond_holds(cond) {
                self.pc = here.wrapping_add(imm);
            }
            return Ok(StepOk::Continued);
        }

        // Exception generation: SVC / BRK / HLT
        if (instr >> 24) & 0xff == 0b11010100 {
            let opc = (instr >> 21) & 0x7;
            let ll = instr & 0x3;
            if opc == 0 && ll == 0b01 {
                // SVC #imm — the Linux engine reads x8/x0..x5 and resumes.
                return Err(Trap::Syscall { pc: self.pc });
            }
            // BRK (#opc=001) / HLT (#opc=010): stop as an undefined gate.
            return Err(self.undef(instr));
        }

        // System: MRS / MSR (register) — only TPIDR_EL0 is modelled.
        if (instr >> 22) & 0x3ff == 0b1101010100 {
            let l = (instr >> 21) & 1; // 1 = MRS (read sysreg)
            let rt = instr & 0x1f;
            let sysreg = (instr >> 5) & 0x7fff; // op0:op1:CRn:CRm:op2
                                                // TPIDR_EL0 = MRS x, S3_3_C13_C2_2 → encoded sysreg 0b11_011_1101_0010_010
            const TPIDR_EL0: u32 = 0b11_011_1101_0010_010;
            if sysreg == TPIDR_EL0 {
                if l == 1 {
                    self.wr(rt, true, self.tpidr);
                } else {
                    self.tpidr = self.rd(rt, true);
                }
                return Ok(StepOk::Continued);
            }
            // Other system regs / barriers (DSB/ISB/NOP): accept as no-ops.
            return Ok(StepOk::Continued);
        }

        // Hints / barriers in the system space (NOP, DMB, ISB, …): bits
        // [31:12] = 1101_0101_0000_0011_0010 → treat as no-op.
        if (instr >> 12) == 0b1101_0101_0000_0011_0010 {
            return Ok(StepOk::Continued);
        }

        // Unconditional branch (register): BR / BLR / RET
        if (instr >> 25) & 0x7f == 0b1101011 {
            let opc = (instr >> 21) & 0xf;
            let rn = (instr >> 5) & 0x1f;
            let target = self.rd(rn, true);
            match opc {
                0b0000 => self.pc = target, // BR
                0b0001 => {
                    self.x[30] = self.pc; // BLR: link
                    self.pc = target;
                }
                0b0010 => self.pc = target, // RET
                _ => return Err(self.undef(instr)),
            }
            return Ok(StepOk::Continued);
        }

        let _ = mmu;
        Err(self.undef(instr))
    }

    // ---- loads and stores ------------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn load_store(&mut self, instr: u32, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        // Load/store register pair: bits[29:27] = 101, bit26 = V(=0 int)
        if (instr >> 27) & 0x7 == 0b101 && (instr >> 26) & 1 == 0 {
            return self.ldst_pair(instr, mmu);
        }

        // LDR (literal, PC-relative): bits[29:24] = 011000
        if (instr >> 24) & 0x3f == 0b011000 {
            let opc = (instr >> 30) & 0x3;
            let rt = instr & 0x1f;
            let imm = sign_extend(u64::from((instr >> 5) & 0x7ffff), 19) << 2;
            let addr = self.pc.wrapping_sub(4).wrapping_add(imm) as u32;
            let val = match opc {
                0b00 => u64::from(mmu.load32(addr)?),                  // 32-bit
                0b01 => mmu.load64(addr)?,                             // 64-bit
                0b10 => sign_extend(u64::from(mmu.load32(addr)?), 32), // LDRSW
                _ => return Err(self.undef(instr)),
            };
            self.wr(rt, opc != 0b00, val);
            return Ok(StepOk::Continued);
        }

        // Load/store register (the 0x38/0x39-family). size = bits[31:30].
        let size = (instr >> 30) & 0x3;
        let v = (instr >> 26) & 1;
        if v != 0 {
            return Err(self.undef(instr)); // SIMD load/store not modelled
        }
        let opc = (instr >> 22) & 0x3;
        let rt = instr & 0x1f;
        let rn = (instr >> 5) & 0x1f;
        let unsigned_off = (instr >> 24) & 0x3 == 0b01;

        let base = self.rd_sp(rn, true);
        let (addr, writeback, wb_val) = if unsigned_off {
            let imm12 = u64::from((instr >> 10) & 0xfff) << size;
            (base.wrapping_add(imm12), false, 0)
        } else {
            // Unscaled / pre / post indexed — imm9 at bits[20:12].
            let imm9 = sign_extend(u64::from((instr >> 12) & 0x1ff), 9);
            let idx = (instr >> 10) & 0x3;
            let reg_offset = (instr >> 21) & 1 == 1 && idx == 0b10;
            if reg_offset {
                // Register offset form: bits[20:16]=Rm, option, S.
                let rm = (instr >> 16) & 0x1f;
                let option = (instr >> 13) & 0x7;
                let s = (instr >> 12) & 1;
                let amount = if s == 1 { size } else { 0 };
                let off = extend_reg(self.rd(rm, true), option, amount, true);
                (base.wrapping_add(off), false, 0)
            } else {
                match idx {
                    0b00 => (base.wrapping_add(imm9), false, 0), // LDUR/STUR (unscaled)
                    0b01 => (base, true, base.wrapping_add(imm9)), // post-index
                    0b11 => (base.wrapping_add(imm9), true, base.wrapping_add(imm9)), // pre-index
                    _ => return Err(self.undef(instr)),
                }
            }
        };

        // opc<1> selects load (1) vs store (0) for plain ld/st; opc=1x with
        // size<3 are sign-extending loads. Model the common cases.
        let is_load = opc & 0b10 != 0 || opc == 0b01;
        let a32 = addr as u32;
        if is_load {
            let raw = match size {
                0 => u64::from(mmu.load8(a32)?),
                1 => u64::from(mmu.load16(a32)?),
                2 => u64::from(mmu.load32(a32)?),
                _ => mmu.load64(a32)?,
            };
            // opc==01 → plain unsigned load; opc==10/11 → sign-extend to
            // 64/32-bit destination (LDRSB/LDRSH/LDRSW).
            let signed = opc == 0b10 || opc == 0b11;
            let val = if signed {
                let bits = 8u32 << size;
                let s = sign_extend(raw, bits);
                if opc == 0b11 {
                    s & 0xffff_ffff // sign-extend into Wt then zero-extend
                } else {
                    s
                }
            } else {
                raw
            };
            let is64 = (opc == 0b01 && size == 3) || opc == 0b10;
            self.wr(rt, is64, val);
        } else {
            let val = self.rd(rt, size == 3);
            match size {
                0 => mmu.store8(a32, val as u8)?,
                1 => mmu.store16(a32, val as u16)?,
                2 => mmu.store32(a32, val as u32)?,
                _ => mmu.store64(a32, val)?,
            }
        }
        if writeback {
            self.wr_sp(rn, true, wb_val);
        }
        Ok(StepOk::Continued)
    }

    fn ldst_pair(&mut self, instr: u32, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        let opc = (instr >> 30) & 0x3; // 00=32-bit, 10=64-bit
        let load = (instr >> 22) & 1 == 1;
        let mode = (instr >> 23) & 0x3; // 01=post,10=offset,11=pre
        let rt = instr & 0x1f;
        let rt2 = (instr >> 10) & 0x1f;
        let rn = (instr >> 5) & 0x1f;
        let is64 = opc == 0b10;
        let scale = if is64 { 3 } else { 2 };
        let imm7 = sign_extend(u64::from((instr >> 15) & 0x7f), 7) << scale;
        let base = self.rd_sp(rn, true);
        let addr = if mode == 0b01 {
            base
        } else {
            base.wrapping_add(imm7)
        };
        let size = if is64 { 8u32 } else { 4 };
        let a = addr as u32;
        if load {
            if is64 {
                self.wr(rt, true, mmu.load64(a)?);
                self.wr(rt2, true, mmu.load64(a.wrapping_add(size))?);
            } else {
                self.wr(rt, false, u64::from(mmu.load32(a)?));
                self.wr(rt2, false, u64::from(mmu.load32(a.wrapping_add(size))?));
            }
        } else if is64 {
            mmu.store64(a, self.rd(rt, true))?;
            mmu.store64(a.wrapping_add(size), self.rd(rt2, true))?;
        } else {
            mmu.store32(a, self.rd(rt, false) as u32)?;
            mmu.store32(a.wrapping_add(size), self.rd(rt2, false) as u32)?;
        }
        if mode == 0b01 || mode == 0b11 {
            self.wr_sp(rn, true, base.wrapping_add(imm7));
        }
        Ok(StepOk::Continued)
    }

    // ---- flags -----------------------------------------------------------

    fn set_logic_flags(&mut self, res: u64, sf: bool) {
        let n = if sf {
            (res >> 63) & 1 == 1
        } else {
            (res >> 31) & 1 == 1
        };
        let masked = if sf { res } else { res & 0xffff_ffff };
        self.nzcv = Nzcv {
            n,
            z: masked == 0,
            c: false,
            v: false,
        };
    }

    /// Evaluate an ARM condition code against the current flags.
    fn cond_holds(&self, cond: u32) -> bool {
        let f = self.nzcv;
        let base = match cond >> 1 {
            0b000 => f.z,                  // EQ/NE
            0b001 => f.c,                  // CS/CC
            0b010 => f.n,                  // MI/PL
            0b011 => f.v,                  // VS/VC
            0b100 => f.c && !f.z,          // HI/LS
            0b101 => f.n == f.v,           // GE/LT
            0b110 => (f.n == f.v) && !f.z, // GT/LE
            _ => true,                     // AL/NV
        };
        if cond & 1 == 1 && cond != 0b1111 {
            !base
        } else {
            base
        }
    }
}

// ---- free helpers --------------------------------------------------------

/// Sign-extend the low `bits` of `v` to 64 bits.
fn sign_extend(v: u64, bits: u32) -> u64 {
    if bits == 0 || bits >= 64 {
        return v;
    }
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

fn mask_bits(w: u32) -> u64 {
    if w >= 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}

/// Rotate the low `width` bits of `v` right by `r`.
fn ror_width(v: u64, r: u32, width: u32) -> u64 {
    let m = mask_bits(width);
    let v = v & m;
    if width == 0 {
        return v;
    }
    let r = r % width;
    if r == 0 {
        return v;
    }
    ((v >> r) | (v << (width - r))) & m
}

/// `ADD`/`SUB` core: `a + b + carry_in`, returning the result and the
/// N/Z/C/V flags it would set. For `sf == false` only the low 32 bits
/// participate.
fn add_with_carry(a: u64, b: u64, carry_in: u64, sf: bool) -> (u64, bool, bool, bool, bool) {
    if sf {
        let (s1, c1) = a.overflowing_add(b);
        let (s2, c2) = s1.overflowing_add(carry_in);
        let result = s2;
        let carry = c1 || c2;
        let sa = (a >> 63) & 1;
        let sb = (b >> 63) & 1;
        let sr = (result >> 63) & 1;
        let v = sa == sb && sa != sr;
        (result, sr == 1, result == 0, carry, v)
    } else {
        let a = a & 0xffff_ffff;
        let b = b & 0xffff_ffff;
        let sum = a + b + carry_in; // ≤ 2^33, fits u64
        let result = sum & 0xffff_ffff;
        let carry = (sum >> 32) & 1 == 1;
        let sa = (a >> 31) & 1;
        let sb = (b >> 31) & 1;
        let sr = (result >> 31) & 1;
        let v = sa == sb && sa != sr;
        (result, sr == 1, result == 0, carry, v)
    }
}

/// Apply a data-processing shift (`LSL/LSR/ASR/ROR`) to a register value.
fn shift_reg(v: u64, shift_type: u32, amount: u32, sf: bool) -> u64 {
    let width = if sf { 64 } else { 32 };
    let amount = amount % width;
    let v = if sf { v } else { v & 0xffff_ffff };
    let res = match shift_type {
        0b00 => v << amount, // LSL
        0b01 => v >> amount, // LSR
        0b10 => {
            // ASR — arithmetic, sign from the operand width.
            if sf {
                ((v as i64) >> amount) as u64
            } else {
                (((v as u32 as i32) >> amount) as u32) as u64
            }
        }
        _ => ror_width(v, amount, width), // ROR
    };
    if sf {
        res
    } else {
        res & 0xffff_ffff
    }
}

/// `ExtendReg`: extend `v` per the option field then shift left by
/// `shift`. Used by the add/sub extended-register and register-offset
/// load/store forms.
fn extend_reg(v: u64, option: u32, shift: u32, sf: bool) -> u64 {
    let extended = match option {
        0b000 => v & 0xff,           // UXTB
        0b001 => v & 0xffff,         // UXTH
        0b010 => v & 0xffff_ffff,    // UXTW
        0b011 => v,                  // UXTX / LSL
        0b100 => sign_extend(v, 8),  // SXTB
        0b101 => sign_extend(v, 16), // SXTH
        0b110 => sign_extend(v, 32), // SXTW
        _ => v,                      // SXTX
    };
    let res = extended << shift;
    if sf {
        res
    } else {
        res & 0xffff_ffff
    }
}

/// `DecodeBitMasks` (ARM ARM). Returns `(wmask, tmask)`. `immediate` is
/// `true` for the logical-immediate form (which forbids `imms == all-ones`).
fn decode_bit_masks(
    immn: u32,
    imms: u32,
    immr: u32,
    immediate: bool,
    datasize: u32,
) -> Option<(u64, u64)> {
    let combined = (immn << 6) | ((imms ^ 0x3f) & 0x3f);
    let len = 31i32 - (combined.leading_zeros() as i32); // highest set bit
    if len < 1 {
        return None;
    }
    let len = len as u32;
    let esize = 1u32 << len;
    if esize > datasize {
        return None;
    }
    let levels = mask_bits(len) as u32;
    if immediate && (imms & levels) == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let diff = s.wrapping_sub(r) & levels;
    let welem = mask_bits(s + 1);
    let telem = mask_bits(diff + 1);
    let wmask = replicate(ror_width(welem, r, esize), esize, datasize);
    let tmask = replicate(telem, esize, datasize);
    Some((wmask, tmask))
}

/// Replicate the low `esize` bits of `elem` across `datasize` bits.
fn replicate(elem: u64, esize: u32, datasize: u32) -> u64 {
    let elem = elem & mask_bits(esize);
    let mut result = 0u64;
    let mut pos = 0;
    while pos < datasize {
        result |= elem << pos;
        pos += esize;
    }
    if datasize >= 64 {
        result
    } else {
        result & mask_bits(datasize)
    }
}

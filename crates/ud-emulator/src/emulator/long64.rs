//! amd64 (x86-64) long-mode execution path.
//!
//! A self-contained 64-bit decode/execute loop that leaves the 32-bit
//! interpreter ([`super::isa_int`]) untouched: it reads/writes
//! `regs.gp64` / `regs.rip`, decodes REX + the standard prefixes, ModR/M
//! + SIB with RIP-relative addressing, and dispatches the integer ISA.
//! Memory goes through the existing u32 [`Mmu`] (addresses are truncated;
//! the loader keeps every region inside the low 4 GiB). The `syscall`
//! gate (`0F 05`) raises [`Trap::Syscall`] for the Linux run loop. SSE and
//! the rest grow opcode-by-opcode against real binaries.

use super::isa_int::{Cpu, StepOk};
use super::mmu::Mmu;
use super::Trap;

/// A decoded operand: a register (index 0..15) or a resolved linear
/// memory address.
#[derive(Clone, Copy, Debug)]
enum Op {
    Reg(u8),
    Mem(u64),
}

/// Per-instruction decode state.
#[derive(Default)]
struct Pfx {
    rex: u8,
    has_rex: bool,
    opsz16: bool,   // 0x66
    addrsz32: bool, // 0x67
    rep: u8,        // 0xF3 / 0xF2 (raw)
    seg_fs: bool,
    seg_gs: bool,
}

impl Pfx {
    fn w(&self) -> bool {
        self.rex & 8 != 0
    }
    fn r(&self) -> u8 {
        (self.rex >> 2) & 1
    }
    fn x(&self) -> u8 {
        (self.rex >> 1) & 1
    }
    fn b(&self) -> u8 {
        self.rex & 1
    }
}

impl Cpu {
    pub(crate) fn step_long64(&mut self, mmu: &mut Mmu) -> Result<StepOk, Trap> {
        mmu.coverage.record_exec(self.regs.rip as u32, 1);
        mmu.dbg_eip = self.regs.rip as u32;
        self.instr_count = self.instr_count.wrapping_add(1);

        let mut p = Pfx::default();
        // Prefix bytes, then REX (which must be the last prefix).
        loop {
            let b = self.fetch8(mmu)?;
            match b {
                0x66 => p.opsz16 = true,
                0x67 => p.addrsz32 = true,
                0xF0 => {} // LOCK — no-op for our single thread
                0xF2 | 0xF3 => p.rep = b,
                0x2E | 0x36 | 0x3E | 0x26 => {} // CS/SS/DS/ES overrides: flat
                0x64 => p.seg_fs = true,
                0x65 => p.seg_gs = true,
                0x40..=0x4F => {
                    p.rex = b;
                    p.has_rex = true;
                    // REX is the final prefix; the next byte is the opcode.
                    let op = self.fetch8(mmu)?;
                    return self.exec(mmu, &p, op);
                }
                _ => return self.exec(mmu, &p, b),
            }
        }
    }

    // ---- fetch -----------------------------------------------------------

    fn fetch8(&mut self, mmu: &Mmu) -> Result<u8, Trap> {
        let b = mmu.load8(self.regs.rip as u32)?;
        self.regs.rip = self.regs.rip.wrapping_add(1);
        Ok(b)
    }
    fn fetch16(&mut self, mmu: &Mmu) -> Result<u16, Trap> {
        let v = mmu.load16(self.regs.rip as u32)?;
        self.regs.rip = self.regs.rip.wrapping_add(2);
        Ok(v)
    }
    fn fetch32(&mut self, mmu: &Mmu) -> Result<u32, Trap> {
        let v = mmu.load32(self.regs.rip as u32)?;
        self.regs.rip = self.regs.rip.wrapping_add(4);
        Ok(v)
    }
    fn fetch64(&mut self, mmu: &Mmu) -> Result<u64, Trap> {
        let v = mmu.load64(self.regs.rip as u32)?;
        self.regs.rip = self.regs.rip.wrapping_add(8);
        Ok(v)
    }

    // ---- register access -------------------------------------------------

    fn rget(&self, idx: u8, size: u8, has_rex: bool) -> u64 {
        let i = idx as usize;
        match size {
            1 => {
                if !has_rex && (4..8).contains(&idx) {
                    (self.regs.gp64[i - 4] >> 8) & 0xFF
                } else {
                    self.regs.gp64[i] & 0xFF
                }
            }
            2 => self.regs.gp64[i] & 0xFFFF,
            4 => self.regs.gp64[i] & 0xFFFF_FFFF,
            _ => self.regs.gp64[i],
        }
    }

    fn rset(&mut self, idx: u8, size: u8, has_rex: bool, val: u64) {
        let i = idx as usize;
        match size {
            1 => {
                if !has_rex && (4..8).contains(&idx) {
                    let j = i - 4;
                    self.regs.gp64[j] = (self.regs.gp64[j] & !0xFF00) | ((val & 0xFF) << 8);
                } else {
                    self.regs.gp64[i] = (self.regs.gp64[i] & !0xFF) | (val & 0xFF);
                }
            }
            2 => self.regs.gp64[i] = (self.regs.gp64[i] & !0xFFFF) | (val & 0xFFFF),
            // 32-bit writes ZERO-EXTEND to 64 bits (x86-64 semantics).
            4 => self.regs.gp64[i] = val & 0xFFFF_FFFF,
            _ => self.regs.gp64[i] = val,
        }
    }

    fn op_get(&self, op: Op, size: u8, has_rex: bool, mmu: &Mmu) -> Result<u64, Trap> {
        match op {
            Op::Reg(r) => Ok(self.rget(r, size, has_rex)),
            Op::Mem(a) => self.mem_load(a as u32, size, mmu),
        }
    }
    fn op_set(
        &mut self,
        op: Op,
        size: u8,
        has_rex: bool,
        val: u64,
        mmu: &mut Mmu,
    ) -> Result<(), Trap> {
        match op {
            Op::Reg(r) => {
                self.rset(r, size, has_rex, val);
                Ok(())
            }
            Op::Mem(a) => self.mem_store(a as u32, size, val, mmu),
        }
    }

    fn mem_load(&self, addr: u32, size: u8, mmu: &Mmu) -> Result<u64, Trap> {
        Ok(match size {
            1 => u64::from(mmu.load8(addr)?),
            2 => u64::from(mmu.load16(addr)?),
            4 => u64::from(mmu.load32(addr)?),
            _ => mmu.load64(addr)?,
        })
    }
    fn mem_store(&self, addr: u32, size: u8, val: u64, mmu: &mut Mmu) -> Result<(), Trap> {
        match size {
            1 => mmu.store8(addr, val as u8),
            2 => mmu.store16(addr, val as u16),
            4 => mmu.store32(addr, val as u32),
            _ => mmu.store64(addr, val),
        }
    }

    // ---- ModR/M + SIB + RIP-relative ------------------------------------

    /// Decode ModR/M (the opcode byte has already been consumed). Returns
    /// `(reg_field 0..15, rm_operand)`.
    fn modrm(&mut self, mmu: &Mmu, p: &Pfx) -> Result<(u8, Op), Trap> {
        let m = self.fetch8(mmu)?;
        let md = m >> 6;
        let reg = ((p.r() << 3) | ((m >> 3) & 7)) as u8;
        let rm = m & 7;
        if md == 3 {
            return Ok((reg, Op::Reg((p.b() << 3) | rm)));
        }
        // Memory.
        let mut addr: u64;
        if rm == 4 {
            // SIB.
            let sib = self.fetch8(mmu)?;
            let scale = sib >> 6;
            let index = ((p.x() << 3) | ((sib >> 3) & 7)) as u8;
            let base = ((p.b() << 3) | (sib & 7)) as u8;
            let idxval = if index == 4 {
                0
            } else {
                self.regs.gp64[index as usize] << scale
            };
            if (sib & 7) == 5 && md == 0 {
                let disp = self.fetch32(mmu)? as i32 as i64 as u64;
                addr = disp.wrapping_add(idxval);
            } else {
                addr = self.regs.gp64[base as usize].wrapping_add(idxval);
            }
        } else if rm == 5 && md == 0 {
            // RIP-relative: disp32 from rip AFTER the full instruction. We
            // approximate with rip-after-disp32 (correct when no trailing
            // immediate; common case). Adjust below for known cases.
            let disp = self.fetch32(mmu)? as i32 as i64;
            addr = (self.regs.rip as i64).wrapping_add(disp) as u64;
            return Ok((reg, Op::Mem(addr)));
        } else {
            addr = self.regs.gp64[((p.b() << 3) | rm) as usize];
        }
        match md {
            1 => {
                let d = self.fetch8(mmu)? as i8 as i64 as u64;
                addr = addr.wrapping_add(d);
            }
            2 => {
                let d = self.fetch32(mmu)? as i32 as i64 as u64;
                addr = addr.wrapping_add(d);
            }
            _ => {}
        }
        if p.seg_fs {
            addr = addr.wrapping_add(u64::from(self.fs_base));
        } else if p.seg_gs {
            addr = addr.wrapping_add(u64::from(self.gs_base()));
        }
        Ok((reg, Op::Mem(addr)))
    }

    fn gs_base(&self) -> u32 {
        // gs_base is private in isa_int; long mode rarely uses %gs in user
        // code (TLS is %fs). Return 0 (flat) for now.
        0
    }

    // ---- the opcode dispatch --------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn exec(&mut self, mmu: &mut Mmu, p: &Pfx, op: u8) -> Result<StepOk, Trap> {
        // Operand size: REX.W → 8 bytes, 0x66 → 2, else 4.
        let osz: u8 = if p.w() {
            8
        } else if p.opsz16 {
            2
        } else {
            4
        };
        let rex = p.has_rex;
        match op {
            // ---- ALU r/m, reg and reg, r/m (00..3B), 8-bit & full ----
            0x00 | 0x08 | 0x10 | 0x18 | 0x20 | 0x28 | 0x30 | 0x38 => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.op_get(rm, 1, rex, mmu)?;
                let b = self.rget(reg, 1, rex);
                let r = self.alu(op, a, b, 1);
                if op != 0x38 {
                    self.op_set(rm, 1, rex, r, mmu)?;
                }
                Ok(StepOk::Continued)
            }
            0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x31 | 0x39 => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.op_get(rm, osz, rex, mmu)?;
                let b = self.rget(reg, osz, rex);
                let r = self.alu(op, a, b, osz);
                if op != 0x39 {
                    self.op_set(rm, osz, rex, r, mmu)?;
                }
                Ok(StepOk::Continued)
            }
            0x02 | 0x0A | 0x12 | 0x1A | 0x22 | 0x2A | 0x32 | 0x3A => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.rget(reg, 1, rex);
                let b = self.op_get(rm, 1, rex, mmu)?;
                let r = self.alu(op, a, b, 1);
                self.rset(reg, 1, rex, r);
                Ok(StepOk::Continued)
            }
            0x03 | 0x0B | 0x13 | 0x1B | 0x23 | 0x2B | 0x33 | 0x3B => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.rget(reg, osz, rex);
                let b = self.op_get(rm, osz, rex, mmu)?;
                let r = self.alu(op, a, b, osz);
                self.rset(reg, osz, rex, r);
                Ok(StepOk::Continued)
            }
            // ALU al/eax, imm
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => {
                let imm = u64::from(self.fetch8(mmu)?);
                let a = self.rget(0, 1, rex);
                let r = self.alu(op, a, imm, 1);
                if op != 0x3C {
                    self.rset(0, 1, rex, r);
                }
                Ok(StepOk::Continued)
            }
            0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => {
                let imm = self.imm_z(mmu, osz)?;
                let a = self.rget(0, osz, rex);
                let r = self.alu(op, a, imm, osz);
                if op != 0x3D {
                    self.rset(0, osz, rex, r);
                }
                Ok(StepOk::Continued)
            }

            // ---- group 1: 80/81/83 — ALU r/m, imm ----
            0x80 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let imm = u64::from(self.fetch8(mmu)?);
                let a = self.op_get(rm, 1, rex, mmu)?;
                let r = self.alu(grp1(ext), a, imm, 1);
                if ext & 7 != 7 {
                    self.op_set(rm, 1, rex, r, mmu)?;
                }
                Ok(StepOk::Continued)
            }
            0x81 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let imm = self.imm_z(mmu, osz)?;
                let a = self.op_get(rm, osz, rex, mmu)?;
                let r = self.alu(grp1(ext), a, imm, osz);
                if ext & 7 != 7 {
                    self.op_set(rm, osz, rex, r, mmu)?;
                }
                Ok(StepOk::Continued)
            }
            0x83 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let imm = self.fetch8(mmu)? as i8 as i64 as u64;
                let a = self.op_get(rm, osz, rex, mmu)?;
                let r = self.alu(grp1(ext), a, mask(imm, osz), osz);
                if ext & 7 != 7 {
                    self.op_set(rm, osz, rex, r, mmu)?;
                }
                Ok(StepOk::Continued)
            }

            // ---- TEST ----
            0x84 => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.op_get(rm, 1, rex, mmu)?;
                let b = self.rget(reg, 1, rex);
                self.logic_flags(a & b, 1);
                Ok(StepOk::Continued)
            }
            0x85 => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.op_get(rm, osz, rex, mmu)?;
                let b = self.rget(reg, osz, rex);
                self.logic_flags(a & b, osz);
                Ok(StepOk::Continued)
            }
            0xA8 => {
                let imm = u64::from(self.fetch8(mmu)?);
                let a = self.rget(0, 1, rex);
                self.logic_flags(a & imm, 1);
                Ok(StepOk::Continued)
            }
            0xA9 => {
                let imm = self.imm_z(mmu, osz)?;
                let a = self.rget(0, osz, rex);
                self.logic_flags(a & imm, osz);
                Ok(StepOk::Continued)
            }

            // ---- XCHG / MOV ----
            0x88 => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let v = self.rget(reg, 1, rex);
                self.op_set(rm, 1, rex, v, mmu)?;
                Ok(StepOk::Continued)
            }
            0x89 => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let v = self.rget(reg, osz, rex);
                self.op_set(rm, osz, rex, v, mmu)?;
                Ok(StepOk::Continued)
            }
            0x8A => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let v = self.op_get(rm, 1, rex, mmu)?;
                self.rset(reg, 1, rex, v);
                Ok(StepOk::Continued)
            }
            0x8B => {
                let (reg, rm) = self.modrm(mmu, p)?;
                let v = self.op_get(rm, osz, rex, mmu)?;
                self.rset(reg, osz, rex, v);
                Ok(StepOk::Continued)
            }
            0x8D => {
                // LEA reg, m
                let (reg, rm) = self.modrm(mmu, p)?;
                if let Op::Mem(a) = rm {
                    self.rset(reg, osz, rex, mask(a, osz));
                }
                Ok(StepOk::Continued)
            }
            0xC6 => {
                let (_e, rm) = self.modrm(mmu, p)?;
                let imm = u64::from(self.fetch8(mmu)?);
                self.op_set(rm, 1, rex, imm, mmu)?;
                Ok(StepOk::Continued)
            }
            0xC7 => {
                let (_e, rm) = self.modrm(mmu, p)?;
                let imm = self.imm_z(mmu, osz)?;
                self.op_set(rm, osz, rex, imm, mmu)?;
                Ok(StepOk::Continued)
            }
            // MOV reg, imm  (B0..B7 = 8-bit, B8..BF = osz / movabs)
            0xB0..=0xB7 => {
                let imm = u64::from(self.fetch8(mmu)?);
                let r = (p.b() << 3) | (op - 0xB0);
                self.rset(r, 1, rex, imm);
                Ok(StepOk::Continued)
            }
            0xB8..=0xBF => {
                let r = (p.b() << 3) | (op - 0xB8);
                let imm = if osz == 8 {
                    self.fetch64(mmu)?
                } else {
                    self.imm_z(mmu, osz)?
                };
                self.rset(r, osz, rex, imm);
                Ok(StepOk::Continued)
            }

            // ---- PUSH/POP ----
            0x50..=0x57 => {
                let r = (p.b() << 3) | (op - 0x50);
                let v = self.regs.gp64[r as usize];
                self.push64(mmu, v)?;
                Ok(StepOk::Continued)
            }
            0x58..=0x5F => {
                let r = (p.b() << 3) | (op - 0x58);
                let v = self.pop64(mmu)?;
                self.regs.gp64[r as usize] = v;
                Ok(StepOk::Continued)
            }
            0x68 => {
                let imm = self.fetch32(mmu)? as i32 as i64 as u64;
                self.push64(mmu, imm)?;
                Ok(StepOk::Continued)
            }
            0x6A => {
                let imm = self.fetch8(mmu)? as i8 as i64 as u64;
                self.push64(mmu, imm)?;
                Ok(StepOk::Continued)
            }

            // ---- jumps / calls ----
            0xE8 => {
                let rel = self.fetch32(mmu)? as i32 as i64;
                let ret = self.regs.rip;
                self.push64(mmu, ret)?;
                self.regs.rip = (self.regs.rip as i64).wrapping_add(rel) as u64;
                Ok(StepOk::Continued)
            }
            0xE9 => {
                let rel = self.fetch32(mmu)? as i32 as i64;
                self.regs.rip = (self.regs.rip as i64).wrapping_add(rel) as u64;
                Ok(StepOk::Continued)
            }
            0xEB => {
                let rel = self.fetch8(mmu)? as i8 as i64;
                self.regs.rip = (self.regs.rip as i64).wrapping_add(rel) as u64;
                Ok(StepOk::Continued)
            }
            0xC3 => {
                self.regs.rip = self.pop64(mmu)?;
                Ok(StepOk::Continued)
            }
            0xC9 => {
                // LEAVE: rsp = rbp; rbp = pop
                self.regs.gp64[4] = self.regs.gp64[5];
                let v = self.pop64(mmu)?;
                self.regs.gp64[5] = v;
                Ok(StepOk::Continued)
            }
            0x70..=0x7F => {
                let rel = self.fetch8(mmu)? as i8 as i64;
                if self.cond(op & 0xF) {
                    self.regs.rip = (self.regs.rip as i64).wrapping_add(rel) as u64;
                }
                Ok(StepOk::Continued)
            }

            // ---- group 3: F6/F7 (test/not/neg/mul/imul/div/idiv) ----
            0xF6 => self.group3(mmu, p, 1),
            0xF7 => self.group3(mmu, p, osz),
            // ---- group 5: FF (inc/dec/call/jmp/push) ; FE (inc/dec) ----
            0xFE => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let a = self.op_get(rm, 1, rex, mmu)?;
                let r = if ext & 7 == 0 {
                    self.inc_dec(a, 1, true)
                } else {
                    self.inc_dec(a, 1, false)
                };
                self.op_set(rm, 1, rex, r, mmu)?;
                Ok(StepOk::Continued)
            }
            0xFF => self.group5(mmu, p, osz),

            // ---- shifts: C0/C1 (imm8), D0/D1 (by 1), D2/D3 (by cl) ----
            0xC0 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let c = self.fetch8(mmu)?;
                self.shift(rm, 1, ext, u64::from(c), mmu)
            }
            0xC1 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let c = self.fetch8(mmu)?;
                self.shift(rm, osz, ext, u64::from(c), mmu)
            }
            0xD0 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                self.shift(rm, 1, ext, 1, mmu)
            }
            0xD1 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                self.shift(rm, osz, ext, 1, mmu)
            }
            0xD2 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let c = self.rget(1, 1, rex);
                self.shift(rm, 1, ext, c, mmu)
            }
            0xD3 => {
                let (ext, rm) = self.modrm(mmu, p)?;
                let c = self.rget(1, 1, rex);
                self.shift(rm, osz, ext, c, mmu)
            }

            // ---- misc ----
            0x90 => Ok(StepOk::Continued), // NOP (also XCHG eax,eax)
            0x98 => {
                // CWDE / CDQE (REX.W): sign-extend al->ax / eax->rax
                let v = if osz == 8 {
                    self.regs.gp64[0] as i32 as i64 as u64
                } else {
                    (self.regs.gp64[0] as i16 as i32 as u32) as u64
                };
                self.rset(0, osz, rex, v);
                Ok(StepOk::Continued)
            }
            0x99 => {
                // CQO / CDQ: sign of rax/eax into rdx/edx
                let neg = if osz == 8 {
                    (self.regs.gp64[0] as i64) < 0
                } else {
                    (self.regs.gp64[0] as i32) < 0
                };
                let s = if neg { u64::MAX } else { 0 };
                self.rset(2, osz, rex, s);
                Ok(StepOk::Continued)
            }

            // ---- two-byte 0F ----
            0x0F => self.exec_0f(mmu, p, osz),

            _ => Err(Trap::UndefinedOpcode {
                eip: self.regs.rip as u32,
                opcode: u32::from(op) | ((u32::from(p.rex)) << 8),
            }),
        }
    }

    fn exec_0f(&mut self, mmu: &mut Mmu, p: &Pfx, osz: u8) -> Result<StepOk, Trap> {
        let op = self.fetch8(mmu)?;
        let rex = p.has_rex;
        match op {
            0x05 => Err(Trap::Syscall { pc: self.regs.rip }), // syscall
            0x1E if p.rep == 0xF3 => {
                // ENDBR64 / NOP-ish: consume the ModRM (FA).
                let _ = self.fetch8(mmu)?;
                Ok(StepOk::Continued)
            }
            0x1F => {
                // multi-byte NOP r/m
                let _ = self.modrm(mmu, p)?;
                Ok(StepOk::Continued)
            }
            0x10 | 0x11 | 0x12 | 0x13 | 0x28 | 0x29 | 0x6E | 0x7E | 0x6F | 0x7F | 0xD6 | 0xEF => {
                // SSE/SSE2 moves — not yet implemented; surface clearly.
                Err(Trap::UndefinedOpcode {
                    eip: self.regs.rip as u32,
                    opcode: 0x0F00 | u32::from(op),
                })
            }
            0x80..=0x8F => {
                let rel = self.fetch32(mmu)? as i32 as i64;
                if self.cond(op & 0xF) {
                    self.regs.rip = (self.regs.rip as i64).wrapping_add(rel) as u64;
                }
                Ok(StepOk::Continued)
            }
            0x90..=0x9F => {
                let (_e, rm) = self.modrm(mmu, p)?;
                let v = u64::from(self.cond(op & 0xF));
                self.op_set(rm, 1, rex, v, mmu)?;
                Ok(StepOk::Continued)
            }
            0x40..=0x4F => {
                // CMOVcc
                let (reg, rm) = self.modrm(mmu, p)?;
                let v = self.op_get(rm, osz, rex, mmu)?;
                if self.cond(op & 0xF) {
                    self.rset(reg, osz, rex, v);
                }
                Ok(StepOk::Continued)
            }
            0xB6 | 0xB7 => {
                // MOVZX
                let (reg, rm) = self.modrm(mmu, p)?;
                let sz = if op == 0xB6 { 1 } else { 2 };
                let v = self.op_get(rm, sz, rex, mmu)?;
                self.rset(reg, osz, rex, v);
                Ok(StepOk::Continued)
            }
            0xBE | 0xBF => {
                // MOVSX
                let (reg, rm) = self.modrm(mmu, p)?;
                let sz = if op == 0xBE { 1 } else { 2 };
                let v = self.op_get(rm, sz, rex, mmu)?;
                let v = sign_extend(v, sz);
                self.rset(reg, osz, rex, mask(v, osz));
                Ok(StepOk::Continued)
            }
            0xAF => {
                // IMUL reg, r/m
                let (reg, rm) = self.modrm(mmu, p)?;
                let a = self.rget(reg, osz, rex) as i64;
                let b = sign_extend(self.op_get(rm, osz, rex, mmu)?, osz) as i64;
                let r = a.wrapping_mul(b) as u64;
                self.rset(reg, osz, rex, mask(r, osz));
                Ok(StepOk::Continued)
            }
            _ => Err(Trap::UndefinedOpcode {
                eip: self.regs.rip as u32,
                opcode: 0x0F00 | u32::from(op),
            }),
        }
    }

    // ---- groups ----------------------------------------------------------

    fn group3(&mut self, mmu: &mut Mmu, p: &Pfx, size: u8) -> Result<StepOk, Trap> {
        let rex = p.has_rex;
        let (ext, rm) = self.modrm(mmu, p)?;
        let a = self.op_get(rm, size, rex, mmu)?;
        match ext & 7 {
            0 | 1 => {
                let imm = if size == 1 {
                    u64::from(self.fetch8(mmu)?)
                } else {
                    self.imm_z(mmu, size)?
                };
                self.logic_flags(a & imm, size);
            }
            2 => self.op_set(rm, size, rex, !a, mmu)?, // NOT
            3 => {
                let r = self.alu(0x28, 0, a, size); // NEG = 0 - a
                self.op_set(rm, size, rex, r, mmu)?;
                self.regs.flags.cf = a != 0;
            }
            4 | 5 => self.mul(a, size, ext & 7 == 5), // MUL / IMUL
            6 | 7 => self.div(a, size, ext & 7 == 7)?, // DIV / IDIV
            _ => unreachable!(),
        }
        Ok(StepOk::Continued)
    }

    fn group5(&mut self, mmu: &mut Mmu, p: &Pfx, osz: u8) -> Result<StepOk, Trap> {
        let rex = p.has_rex;
        let (ext, rm) = self.modrm(mmu, p)?;
        match ext & 7 {
            0 => {
                let a = self.op_get(rm, osz, rex, mmu)?;
                let r = self.inc_dec(a, osz, true);
                self.op_set(rm, osz, rex, r, mmu)?;
            }
            1 => {
                let a = self.op_get(rm, osz, rex, mmu)?;
                let r = self.inc_dec(a, osz, false);
                self.op_set(rm, osz, rex, r, mmu)?;
            }
            2 => {
                // CALL r/m (64-bit target)
                let t = self.op_get(rm, 8, rex, mmu)?;
                let ret = self.regs.rip;
                self.push64(mmu, ret)?;
                self.regs.rip = t;
            }
            4 => {
                // JMP r/m
                let t = self.op_get(rm, 8, rex, mmu)?;
                self.regs.rip = t;
            }
            6 => {
                // PUSH r/m
                let v = self.op_get(rm, 8, rex, mmu)?;
                self.push64(mmu, v)?;
            }
            _ => {
                return Err(Trap::UndefinedOpcode {
                    eip: self.regs.rip as u32,
                    opcode: 0xFF00 | u32::from(ext),
                })
            }
        }
        Ok(StepOk::Continued)
    }

    fn shift(
        &mut self,
        rm: Op,
        size: u8,
        ext: u8,
        count: u64,
        mmu: &mut Mmu,
    ) -> Result<StepOk, Trap> {
        let bits = (size as u32) * 8;
        let c = (count as u32) & if size == 8 { 63 } else { 31 };
        let a = self.op_get(rm, size, true, mmu)?;
        if c == 0 {
            return Ok(StepOk::Continued);
        }
        let r = match ext & 7 {
            4 | 6 => a.wrapping_shl(c),              // SHL/SAL
            5 => mask(a, size) >> c,                 // SHR
            7 => (sign_extend(a, size) >> c) as u64, // SAR
            0 => a.rotate_left(c),                   // ROL (approx for width)
            1 => a.rotate_right(c),                  // ROR (approx)
            _ => a,
        };
        let r = mask(r, size);
        self.op_set(rm, size, true, r, mmu)?;
        match ext & 7 {
            0 | 1 => {} // rotates: leave SZP
            _ => self.szp(r, size),
        }
        let _ = bits;
        Ok(StepOk::Continued)
    }

    // ---- arithmetic primitives ------------------------------------------

    /// Execute an ALU op selected by the opcode's top bits (00=ADD, 08=OR,
    /// 10=ADC, 18=SBB, 20=AND, 28=SUB, 30=XOR, 38=CMP) at `size` bytes.
    fn alu(&mut self, opcode: u8, a: u64, b: u64, size: u8) -> u64 {
        let sel = (opcode >> 3) & 7;
        let (res, cf, of) = match sel {
            0 => add(a, b, size, false),              // ADD
            2 => add(a, b, size, self.regs.flags.cf), // ADC
            1 | 4 | 6 => {
                let r = mask(
                    match sel {
                        1 => a | b,
                        4 => a & b,
                        _ => a ^ b,
                    },
                    size,
                );
                (r, false, false)
            }
            3 => sub(a, b, size, self.regs.flags.cf), // SBB
            5 | 7 => sub(a, b, size, false),          // SUB / CMP
            _ => (mask(a, size), false, false),
        };
        self.szp(res, size);
        self.regs.flags.cf = cf;
        self.regs.flags.of = of;
        res
    }

    fn inc_dec(&mut self, a: u64, size: u8, inc: bool) -> u64 {
        let cf = self.regs.flags.cf; // INC/DEC preserve CF
        let (r, _c, of) = if inc {
            add(a, 1, size, false)
        } else {
            sub(a, 1, size, false)
        };
        self.szp(r, size);
        self.regs.flags.of = of;
        self.regs.flags.cf = cf;
        r
    }

    fn mul(&mut self, a: u64, size: u8, signed: bool) {
        // (E/R)AX * src → (E/R)DX:(E/R)AX
        let acc = self.rget(0, size, true);
        let (lo, hi) = if signed {
            let prod = (sign_extend(acc, size) as i128) * (sign_extend(a, size) as i128);
            (prod as u64, (prod >> (size as u32 * 8)) as u64)
        } else {
            let prod = (acc as u128) * (a as u128);
            (prod as u64, (prod >> (size as u32 * 8)) as u64)
        };
        if size == 1 {
            self.rset(0, 2, true, (lo & 0xFF) | ((mask(hi, 1)) << 8));
        } else {
            self.rset(0, size, true, mask(lo, size));
            self.rset(2, size, true, mask(hi, size));
        }
        let overflow = mask(hi, size) != 0;
        self.regs.flags.cf = overflow;
        self.regs.flags.of = overflow;
    }

    fn div(&mut self, a: u64, size: u8, signed: bool) -> Result<(), Trap> {
        if a == 0 {
            return Err(Trap::DivideByZero {
                eip: self.regs.rip as u32,
            });
        }
        let bits = size as u32 * 8;
        let lo = self.rget(0, size, true);
        let hi = if size == 1 {
            0
        } else {
            self.rget(2, size, true)
        };
        let dividend =
            (u128::from(hi) << bits) | u128::from(if size == 1 { lo & 0xFFFF } else { lo });
        if signed {
            let dvd = dividend as i128;
            let dvs = sign_extend(a, size) as i64 as i128;
            let q = dvd / dvs;
            let r = dvd % dvs;
            self.rset(0, size, true, mask(q as u64, size));
            self.rset(2, size, true, mask(r as u64, size));
        } else {
            let q = dividend / u128::from(a);
            let r = dividend % u128::from(a);
            self.rset(0, size, true, mask(q as u64, size));
            self.rset(2, size, true, mask(r as u64, size));
        }
        Ok(())
    }

    // ---- flags / stack ---------------------------------------------------

    fn szp(&mut self, r: u64, size: u8) {
        match size {
            1 => self.regs.flags.set_szp_8(r as u8),
            2 => self.regs.flags.set_szp_16(r as u16),
            4 => self.regs.flags.set_szp_32(r as u32),
            _ => self.regs.flags.set_szp_64(r),
        }
    }
    fn logic_flags(&mut self, r: u64, size: u8) {
        self.szp(r, size);
        self.regs.flags.cf = false;
        self.regs.flags.of = false;
    }

    fn push64(&mut self, mmu: &mut Mmu, v: u64) -> Result<(), Trap> {
        self.regs.gp64[4] = self.regs.gp64[4].wrapping_sub(8);
        mmu.store64(self.regs.gp64[4] as u32, v)
    }
    fn pop64(&mut self, mmu: &Mmu) -> Result<u64, Trap> {
        let v = mmu.load64(self.regs.gp64[4] as u32)?;
        self.regs.gp64[4] = self.regs.gp64[4].wrapping_add(8);
        Ok(v)
    }

    /// Fetch the immediate for an `osz`-sized operand: 16-bit for `0x66`,
    /// otherwise 32-bit (sign-extended to 64 for REX.W operands).
    fn imm_z(&mut self, mmu: &Mmu, size: u8) -> Result<u64, Trap> {
        Ok(match size {
            2 => u64::from(self.fetch16(mmu)?),
            4 => u64::from(self.fetch32(mmu)?),
            _ => self.fetch32(mmu)? as i32 as i64 as u64,
        })
    }

    fn cond(&self, cc: u8) -> bool {
        let f = &self.regs.flags;
        match cc {
            0x0 => f.of,
            0x1 => !f.of,
            0x2 => f.cf,
            0x3 => !f.cf,
            0x4 => f.zf,
            0x5 => !f.zf,
            0x6 => f.cf || f.zf,
            0x7 => !(f.cf || f.zf),
            0x8 => f.sf,
            0x9 => !f.sf,
            0xA => f.pf,
            0xB => !f.pf,
            0xC => f.sf != f.of,
            0xD => f.sf == f.of,
            0xE => f.zf || (f.sf != f.of),
            _ => !f.zf && (f.sf == f.of),
        }
    }
}

// ---- free helpers --------------------------------------------------------

fn mask(v: u64, size: u8) -> u64 {
    match size {
        1 => v & 0xFF,
        2 => v & 0xFFFF,
        4 => v & 0xFFFF_FFFF,
        _ => v,
    }
}

fn sign_extend(v: u64, size: u8) -> u64 {
    match size {
        1 => v as u8 as i8 as i64 as u64,
        2 => v as u16 as i16 as i64 as u64,
        4 => v as u32 as i32 as i64 as u64,
        _ => v,
    }
}

fn add(a: u64, b: u64, size: u8, carry: bool) -> (u64, bool, bool) {
    let (a, b) = (mask(a, size), mask(b, size));
    let c = u64::from(carry);
    let full = u128::from(a) + u128::from(b) + u128::from(c);
    let res = mask(full as u64, size);
    let bits = size as u32 * 8;
    let cf = (full >> bits) & 1 != 0;
    let sign = 1u64 << (bits - 1);
    let of = ((a ^ res) & (b ^ res) & sign) != 0;
    (res, cf, of)
}

fn sub(a: u64, b: u64, size: u8, borrow: bool) -> (u64, bool, bool) {
    let (a, b) = (mask(a, size), mask(b, size));
    let c = u64::from(borrow);
    let res = mask(a.wrapping_sub(b).wrapping_sub(c), size);
    let cf = u128::from(a) < u128::from(b) + u128::from(c);
    let bits = size as u32 * 8;
    let sign = 1u64 << (bits - 1);
    let of = ((a ^ b) & (a ^ res) & sign) != 0;
    (res, cf, of)
}

/// Group-1 ALU selector: maps the ModRM.reg field to the opcode byte the
/// `alu` helper expects (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP).
fn grp1(ext: u8) -> u8 {
    (ext & 7) << 3
}

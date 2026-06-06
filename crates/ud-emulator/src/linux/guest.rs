//! A minimal CPU abstraction the Linux engine + adapters speak to, so a
//! non-x86 back-end (the aarch64 interpreter) plugs into the same kernel.
//!
//! Registers are addressed by the **architecture's native index** (the
//! adapter and the CPU's impl agree on the numbering): x86 uses the
//! `rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15` order; aarch64 uses
//! `x0..x30`. Memory is *not* here — it stays on the shared [`Mmu`].

use crate::emulator::aarch64::Aarch64Cpu;
use crate::emulator::Cpu;

/// What the Linux engine needs from any guest CPU.
pub trait GuestCpu {
    /// Read general register `i` in the arch's native numbering.
    fn reg(&self, i: usize) -> u64;
    /// Write general register `i`.
    fn set_reg(&mut self, i: usize, v: u64);
    /// The program counter.
    fn pc(&self) -> u64;
    /// Set the program counter.
    fn set_pc(&mut self, v: u64);
}

/// The x86 interpreter exposes its 64-bit register file in long mode and
/// its 32-bit file otherwise (canonical i386 / amd64 register indices).
impl GuestCpu for Cpu {
    fn reg(&self, i: usize) -> u64 {
        if self.is_long64() {
            self.regs.gp64[i]
        } else {
            u64::from(self.regs.gp[i & 7])
        }
    }
    fn set_reg(&mut self, i: usize, v: u64) {
        if self.is_long64() {
            self.regs.gp64[i] = v;
        } else {
            self.regs.gp[i & 7] = v as u32;
        }
    }
    fn pc(&self) -> u64 {
        if self.is_long64() {
            self.regs.rip
        } else {
            u64::from(self.regs.eip)
        }
    }
    fn set_pc(&mut self, v: u64) {
        if self.is_long64() {
            self.regs.rip = v;
        } else {
            self.regs.eip = v as u32;
        }
    }
}

/// The aarch64 CPU: registers are simply `x0..x30`; index 31 maps to the
/// stack pointer (no canonical syscall arg uses it, but the engine may).
impl GuestCpu for Aarch64Cpu {
    fn reg(&self, i: usize) -> u64 {
        if i >= 31 {
            self.sp
        } else {
            self.x[i]
        }
    }
    fn set_reg(&mut self, i: usize, v: u64) {
        if i >= 31 {
            self.sp = v;
        } else {
            self.x[i] = v;
        }
    }
    fn pc(&self) -> u64 {
        self.pc
    }
    fn set_pc(&mut self, v: u64) {
        self.pc = v;
    }
}

//! Per-architecture Linux syscall adapters.
//!
//! The [`LinuxKernel`](super::LinuxKernel) is arch-agnostic: it works in
//! terms of a canonical [`Sysno`] and six `u64` arguments. A [`LinuxAbi`]
//! adapter bridges a concrete [`Cpu`] to it — it knows which registers
//! carry the syscall number / arguments / return value for its ABI, and
//! maps the architecture's syscall *numbers* (which differ wildly between
//! i386, x86-64 and aarch64) onto the canonical set.
//!
//! Only [`I386Abi`] is wired to a working CPU today (the interpreter is
//! 32-bit). The `x86-64` / `aarch64` number tables and register layouts
//! are provided so those adapters are a small addition once their CPU
//! back-ends exist — the kernel engine itself needs no changes.

use super::guest::GuestCpu;

/// Canonical syscall identity used inside the kernel engine. Per-arch
/// number tables map onto this; the engine switches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sysno {
    Read,
    Write,
    Readv,
    Writev,
    Open,
    Openat,
    Close,
    Lseek,
    Brk,
    Mmap,
    Munmap,
    Mprotect,
    Exit,
    ExitGroup,
    Fstat,
    Stat,
    Newfstatat,
    Uname,
    Getpid,
    Getppid,
    Gettid,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Access,
    Getcwd,
    Ioctl,
    ArchPrctl,
    SetTidAddress,
    SetRobustList,
    RtSigaction,
    RtSigprocmask,
    Time,
    ClockGettime,
    Gettimeofday,
    Futex,
    Getrandom,
    Readlinkat,
    /// Recognised but intentionally a no-op-success for static-binary
    /// startup (TLS / threading setup we don't model).
    Ignored,
}

/// The adapter a [`LinuxKernel`](super::LinuxKernel) talks to. Works over
/// a [`GuestCpu`] so any arch back-end plugs in.
pub trait LinuxAbi {
    /// Raw syscall number from the arch's number register.
    fn syscall_nr(&self, cpu: &dyn GuestCpu) -> u64;
    /// The six argument registers, in canonical order.
    fn syscall_args(&self, cpu: &dyn GuestCpu) -> [u64; 6];
    /// Write the return value (or `-errno`) to the arch's result register.
    fn set_return(&self, cpu: &mut dyn GuestCpu, ret: i64);
    /// Map a raw syscall number to the canonical [`Sysno`].
    fn map_syscall(&self, nr: u64) -> Option<Sysno>;
    /// Pointer width — 32 for i386, 64 for x86-64 / aarch64.
    fn ptr_bits(&self) -> u8;
}

/// Linux/i386 ABI: `int 0x80`, number in `eax`, args in
/// `ebx, ecx, edx, esi, edi, ebp`, return in `eax`. (Canonical x86 reg
/// indices: eax=0, ecx=1, edx=2, ebx=3, ebp=5, esi=6, edi=7.)
#[derive(Debug, Default, Clone, Copy)]
pub struct I386Abi;

impl LinuxAbi for I386Abi {
    fn syscall_nr(&self, cpu: &dyn GuestCpu) -> u64 {
        cpu.reg(0)
    }
    fn syscall_args(&self, cpu: &dyn GuestCpu) -> [u64; 6] {
        [
            cpu.reg(3),
            cpu.reg(1),
            cpu.reg(2),
            cpu.reg(6),
            cpu.reg(7),
            cpu.reg(5),
        ]
    }
    fn set_return(&self, cpu: &mut dyn GuestCpu, ret: i64) {
        cpu.set_reg(0, ret as u64);
    }
    fn map_syscall(&self, nr: u64) -> Option<Sysno> {
        Some(match nr {
            1 => Sysno::Exit,
            3 => Sysno::Read,
            4 => Sysno::Write,
            5 => Sysno::Open,
            6 => Sysno::Close,
            13 => Sysno::Time,
            19 => Sysno::Lseek,
            20 => Sysno::Getpid,
            24 => Sysno::Getuid,
            33 => Sysno::Access,
            45 => Sysno::Brk,
            49 => Sysno::Geteuid,
            47 => Sysno::Getgid,
            50 => Sysno::Getegid,
            54 => Sysno::Ioctl,
            64 => Sysno::Getppid,
            85 => Sysno::Ignored, // readlink — accept as "0 bytes" for now
            91 => Sysno::Munmap,
            122 => Sysno::Uname,
            125 => Sysno::Mprotect,
            145 => Sysno::Readv,
            146 => Sysno::Writev,
            174 => Sysno::RtSigaction,
            175 => Sysno::RtSigprocmask,
            183 => Sysno::Getcwd,
            192 => Sysno::Mmap,  // mmap2 (page-offset variant) — treated as mmap
            195 => Sysno::Stat,  // stat64
            197 => Sysno::Fstat, // fstat64
            224 => Sysno::Gettid,
            243 => Sysno::Ignored, // set_thread_area (TLS) — accept
            258 => Sysno::SetTidAddress,
            295 => Sysno::Openat,
            300 => Sysno::Newfstatat, // fstatat64
            311 => Sysno::SetRobustList,
            252 => Sysno::ExitGroup,
            265 => Sysno::ClockGettime,
            78 => Sysno::Gettimeofday,
            240 => Sysno::Futex,
            355 => Sysno::Getrandom,
            340 => Sysno::Ignored, // prlimit64
            305 => Sysno::Readlinkat,
            _ => return None,
        })
    }
    fn ptr_bits(&self) -> u8 {
        32
    }
}

/// Linux/x86-64 ABI table + register layout. Inert until the interpreter
/// gains 64-bit execution; provided so adding that arch is a small step.
#[derive(Debug, Default, Clone, Copy)]
pub struct Amd64Abi;

impl Amd64Abi {
    /// Map an x86-64 syscall number to the canonical [`Sysno`].
    #[must_use]
    pub fn map(nr: u64) -> Option<Sysno> {
        Some(match nr {
            0 => Sysno::Read,
            1 => Sysno::Write,
            2 => Sysno::Open,
            3 => Sysno::Close,
            4 => Sysno::Stat,
            5 => Sysno::Fstat,
            8 => Sysno::Lseek,
            9 => Sysno::Mmap,
            10 => Sysno::Mprotect,
            11 => Sysno::Munmap,
            12 => Sysno::Brk,
            13 => Sysno::RtSigaction,
            14 => Sysno::RtSigprocmask,
            16 => Sysno::Ioctl,
            19 => Sysno::Readv,
            20 => Sysno::Writev,
            21 => Sysno::Access,
            39 => Sysno::Getpid,
            60 => Sysno::Exit,
            63 => Sysno::Uname,
            79 => Sysno::Getcwd,
            102 => Sysno::Getuid,
            104 => Sysno::Getgid,
            107 => Sysno::Geteuid,
            108 => Sysno::Getegid,
            110 => Sysno::Getppid,
            158 => Sysno::ArchPrctl,
            186 => Sysno::Gettid,
            218 => Sysno::SetTidAddress,
            231 => Sysno::ExitGroup,
            257 => Sysno::Openat,
            262 => Sysno::Newfstatat,
            273 => Sysno::SetRobustList,
            228 => Sysno::ClockGettime,
            96 => Sysno::Gettimeofday,
            202 => Sysno::Futex,
            204 => Sysno::Ignored, // sched_getaffinity
            302 => Sysno::Ignored, // prlimit64
            318 => Sysno::Getrandom,
            334 => Sysno::Ignored, // rseq — restartable sequences, ignore
            267 => Sysno::Readlinkat,
            _ => return None,
        })
    }
}

/// Linux/x86-64 ABI: `syscall` (0F 05), number in `rax`, args in
/// `rdi, rsi, rdx, r10, r8, r9`, return in `rax`. (Canonical x86-64 reg
/// indices: rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7,
/// r8=8, r9=9, r10=10.)
impl LinuxAbi for Amd64Abi {
    fn syscall_nr(&self, cpu: &dyn GuestCpu) -> u64 {
        cpu.reg(0)
    }
    fn syscall_args(&self, cpu: &dyn GuestCpu) -> [u64; 6] {
        [
            cpu.reg(7),
            cpu.reg(6),
            cpu.reg(2),
            cpu.reg(10),
            cpu.reg(8),
            cpu.reg(9),
        ]
    }
    fn set_return(&self, cpu: &mut dyn GuestCpu, ret: i64) {
        cpu.set_reg(0, ret as u64);
    }
    fn map_syscall(&self, nr: u64) -> Option<Sysno> {
        Self::map(nr)
    }
    fn ptr_bits(&self) -> u8 {
        64
    }
}

/// Linux/aarch64 ABI table (generic Linux syscall numbers). Inert until
/// an aarch64 executor exists.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aarch64Abi;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::regs::Reg32;
    use crate::emulator::Cpu;

    #[test]
    fn i386_reads_nr_args_and_writes_return() {
        let mut cpu = Cpu::new();
        cpu.regs.set32(Reg32::Eax, 4); // write
        cpu.regs.set32(Reg32::Ebx, 1); // fd
        cpu.regs.set32(Reg32::Ecx, 0x1234); // buf
        cpu.regs.set32(Reg32::Edx, 3); // len
        let abi = I386Abi;
        assert_eq!(abi.syscall_nr(&cpu), 4);
        assert_eq!(abi.syscall_args(&cpu)[..4], [1, 0x1234, 3, 0][..4]);
        assert_eq!(abi.map_syscall(4), Some(Sysno::Write));
        assert_eq!(abi.map_syscall(1), Some(Sysno::Exit));
        assert_eq!(abi.map_syscall(45), Some(Sysno::Brk));
        assert_eq!(abi.map_syscall(9999), None);
        abi.set_return(&mut cpu, -38);
        assert_eq!(cpu.regs.get32(Reg32::Eax), (-38i32) as u32);
    }

    #[test]
    fn arch_tables_agree_on_common_calls() {
        // The canonical mapping must be consistent across arches.
        assert_eq!(Amd64Abi::map(1), Some(Sysno::Write));
        assert_eq!(Amd64Abi::map(60), Some(Sysno::Exit));
        assert_eq!(Aarch64Abi::map(64), Some(Sysno::Write));
        assert_eq!(Aarch64Abi::map(93), Some(Sysno::Exit));
    }
}

impl Aarch64Abi {
    /// Map an aarch64 (generic asm-generic) syscall number to [`Sysno`].
    #[must_use]
    pub fn map(nr: u64) -> Option<Sysno> {
        Some(match nr {
            17 => Sysno::Getcwd,
            29 => Sysno::Ioctl,
            48 => Sysno::Access, // faccessat (close enough for now)
            56 => Sysno::Openat,
            57 => Sysno::Close,
            63 => Sysno::Read,
            64 => Sysno::Write,
            65 => Sysno::Readv,
            66 => Sysno::Writev,
            79 => Sysno::Newfstatat,
            80 => Sysno::Fstat,
            93 => Sysno::Exit,
            94 => Sysno::ExitGroup,
            96 => Sysno::SetTidAddress,
            99 => Sysno::SetRobustList,
            134 => Sysno::RtSigaction,
            135 => Sysno::RtSigprocmask,
            160 => Sysno::Uname,
            172 => Sysno::Getpid,
            173 => Sysno::Getppid,
            174 => Sysno::Getuid,
            175 => Sysno::Geteuid,
            176 => Sysno::Getgid,
            177 => Sysno::Getegid,
            178 => Sysno::Gettid,
            214 => Sysno::Brk,
            215 => Sysno::Munmap,
            222 => Sysno::Mmap,
            226 => Sysno::Mprotect,
            113 => Sysno::ClockGettime,
            169 => Sysno::Gettimeofday,
            98 => Sysno::Futex,
            278 => Sysno::Getrandom,
            261 => Sysno::Ignored, // prlimit64
            78 => Sysno::Readlinkat,
            _ => return None,
        })
    }
}

/// Linux/aarch64 ABI: `svc #0`, number in `x8`, args in `x0..x5`,
/// return in `x0`. (Canonical aarch64 reg indices are simply `x0..x30`.)
impl LinuxAbi for Aarch64Abi {
    fn syscall_nr(&self, cpu: &dyn GuestCpu) -> u64 {
        cpu.reg(8)
    }
    fn syscall_args(&self, cpu: &dyn GuestCpu) -> [u64; 6] {
        [
            cpu.reg(0),
            cpu.reg(1),
            cpu.reg(2),
            cpu.reg(3),
            cpu.reg(4),
            cpu.reg(5),
        ]
    }
    fn set_return(&self, cpu: &mut dyn GuestCpu, ret: i64) {
        cpu.set_reg(0, ret as u64);
    }
    fn map_syscall(&self, nr: u64) -> Option<Sysno> {
        Self::map(nr)
    }
    fn ptr_bits(&self) -> u8 {
        64
    }
}

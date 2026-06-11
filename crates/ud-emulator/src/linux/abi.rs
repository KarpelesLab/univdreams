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
    Lstat,
    Newfstatat,
    Statx,
    Fcntl,
    Dup,
    Dup2,
    Dup3,
    Chdir,
    Fchdir,
    Faccessat,
    Umask,
    Fchmod,
    Fchmodat,
    Utimensat,
    Nanosleep,
    Poll,
    Ppoll,
    Pread64,
    Pwrite64,
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
    Readlink,
    Readlinkat,
    Getdents64,
    Mkdir,
    Mkdirat,
    Unlink,
    Unlinkat,
    Rmdir,
    Symlink,
    Symlinkat,
    Truncate,
    Ftruncate,
    Clone,
    Fork,
    Vfork,
    Execve,
    Wait4,
    Pipe,
    Pipe2,
    SchedYield,
    /// Recognised but intentionally a no-op-success for static-binary
    /// startup (TLS / threading setup we don't model).
    Ignored,
}

/// Byte offsets of the fields the kernel fills in a `stat` buffer, plus the
/// total struct size. The `stat` struct layout is architecture-specific
/// (i386 `stat64`, x86-64 `stat`, aarch64 `stat` all differ), so each ABI
/// reports its own. `st_mode`/`st_blksize`/`st_nlink` are written as `u32`,
/// `st_size`/`st_blocks` as `u64` (the union of all three layouts).
#[derive(Debug, Clone, Copy)]
pub struct StatLayout {
    pub size: usize,
    pub mode_off: usize,
    pub nlink_off: usize,
    pub size_off: usize,
    pub blksize_off: usize,
    pub blocks_off: usize,
    /// `st_dev` (8 bytes) and `st_ino` (8 bytes) offsets. The dynamic linker
    /// dedups libraries by `(dev, ino)`, so these must be unique per file or it
    /// aliases distinct `.so`s and drops their symbols.
    pub dev_off: usize,
    pub ino_off: usize,
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
    /// Field offsets + size of this ABI's `stat` buffer.
    fn stat_layout(&self) -> StatLayout;
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
            2 => Sysno::Fork,
            7 => Sysno::Wait4, // waitpid
            10 => Sysno::Unlink,
            11 => Sysno::Execve,
            12 => Sysno::Chdir,
            42 => Sysno::Pipe,
            114 => Sysno::Wait4,
            190 => Sysno::Vfork,
            331 => Sysno::Pipe2,
            39 => Sysno::Mkdir,
            40 => Sysno::Rmdir,
            41 => Sysno::Dup,
            55 => Sysno::Fcntl,
            60 => Sysno::Umask,
            63 => Sysno::Dup2,
            94 => Sysno::Fchmod,
            133 => Sysno::Fchdir,
            162 => Sysno::Nanosleep,
            168 => Sysno::Poll,
            180 => Sysno::Pread64,
            181 => Sysno::Pwrite64,
            196 => Sysno::Lstat,     // lstat64
            221 => Sysno::Fcntl,     // fcntl64
            267 => Sysno::Nanosleep, // clock_nanosleep
            306 => Sysno::Fchmodat,
            307 => Sysno::Faccessat,
            309 => Sysno::Ppoll,
            320 => Sysno::Utimensat,
            330 => Sysno::Dup3,
            383 => Sysno::Statx,
            439 => Sysno::Faccessat, // faccessat2
            83 => Sysno::Symlink,
            85 => Sysno::Readlink,
            92 => Sysno::Truncate,
            93 => Sysno::Ftruncate,
            193 => Sysno::Truncate,  // truncate64
            194 => Sysno::Ftruncate, // ftruncate64
            220 => Sysno::Getdents64,
            296 => Sysno::Mkdirat,
            301 => Sysno::Unlinkat,
            304 => Sysno::Symlinkat,
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
    fn stat_layout(&self) -> StatLayout {
        // struct stat64 (asm/stat.h): total 96 bytes.
        StatLayout {
            size: 96,
            mode_off: 16,
            nlink_off: 20,
            size_off: 44,
            blksize_off: 52,
            blocks_off: 56,
            dev_off: 0,
            ino_off: 88,
        }
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
            6 => Sysno::Lstat,
            7 => Sysno::Poll,
            8 => Sysno::Lseek,
            17 => Sysno::Pread64,
            18 => Sysno::Pwrite64,
            32 => Sysno::Dup,
            33 => Sysno::Dup2,
            35 => Sysno::Nanosleep,
            72 => Sysno::Fcntl,
            80 => Sysno::Chdir,
            81 => Sysno::Fchdir,
            91 => Sysno::Fchmod,
            95 => Sysno::Umask,
            230 => Sysno::Nanosleep, // clock_nanosleep → treat as nanosleep
            268 => Sysno::Fchmodat,
            269 => Sysno::Faccessat,
            271 => Sysno::Ppoll,
            280 => Sysno::Utimensat,
            292 => Sysno::Dup3,
            332 => Sysno::Statx,
            439 => Sysno::Faccessat, // faccessat2
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
            76 => Sysno::Truncate,
            77 => Sysno::Ftruncate,
            83 => Sysno::Mkdir,
            84 => Sysno::Rmdir,
            87 => Sysno::Unlink,
            88 => Sysno::Symlink,
            89 => Sysno::Readlink,
            217 => Sysno::Getdents64,
            258 => Sysno::Mkdirat,
            263 => Sysno::Unlinkat,
            266 => Sysno::Symlinkat,
            56 => Sysno::Clone,
            57 => Sysno::Fork,
            58 => Sysno::Vfork,
            59 => Sysno::Execve,
            61 => Sysno::Wait4,
            22 => Sysno::Pipe,
            293 => Sysno::Pipe2,
            24 => Sysno::SchedYield,
            28 => Sysno::Ignored, // madvise — advisory, safe to no-op
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
    fn stat_layout(&self) -> StatLayout {
        // struct stat (x86-64 asm/stat.h): total 144 bytes.
        StatLayout {
            size: 144,
            mode_off: 24,
            nlink_off: 16,
            size_off: 48,
            blksize_off: 56,
            blocks_off: 64,
            dev_off: 0,
            ino_off: 8,
        }
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
    fn stat_layouts_match_known_struct_sizes() {
        // The three ABIs report architecture-correct stat struct geometry.
        let i386 = I386Abi.stat_layout();
        assert_eq!((i386.size, i386.mode_off, i386.size_off), (96, 16, 44));
        let amd64 = Amd64Abi.stat_layout();
        assert_eq!((amd64.size, amd64.mode_off, amd64.size_off), (144, 24, 48));
        let a64 = Aarch64Abi.stat_layout();
        assert_eq!((a64.size, a64.mode_off, a64.size_off), (128, 16, 48));
        // Every field must fit inside its struct (u64 fields need 8 bytes).
        for l in [i386, amd64, a64] {
            assert!(l.size_off + 8 <= l.size && l.blocks_off + 8 <= l.size);
            assert!(l.mode_off + 4 <= l.size && l.nlink_off + 4 <= l.size);
        }
    }

    #[test]
    fn new_dir_syscall_numbers_map() {
        assert_eq!(I386Abi.map_syscall(220), Some(Sysno::Getdents64));
        assert_eq!(I386Abi.map_syscall(85), Some(Sysno::Readlink));
        assert_eq!(Amd64Abi::map(217), Some(Sysno::Getdents64));
        assert_eq!(Amd64Abi::map(83), Some(Sysno::Mkdir));
        assert_eq!(Aarch64Abi::map(61), Some(Sysno::Getdents64));
        assert_eq!(Aarch64Abi::map(35), Some(Sysno::Unlinkat));
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
            23 => Sysno::Dup,
            24 => Sysno::Dup3,
            25 => Sysno::Fcntl,
            29 => Sysno::Ioctl,
            48 => Sysno::Faccessat,
            49 => Sysno::Chdir,
            50 => Sysno::Fchdir,
            52 => Sysno::Fchmod,
            53 => Sysno::Fchmodat,
            56 => Sysno::Openat,
            67 => Sysno::Pread64,
            68 => Sysno::Pwrite64,
            73 => Sysno::Ppoll,
            88 => Sysno::Utimensat,
            101 => Sysno::Nanosleep,
            115 => Sysno::Nanosleep, // clock_nanosleep
            166 => Sysno::Umask,
            221 => Sysno::Execve,
            260 => Sysno::Wait4,
            59 => Sysno::Pipe2,
            291 => Sysno::Statx,
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
            45 => Sysno::Truncate,
            46 => Sysno::Ftruncate,
            61 => Sysno::Getdents64,
            34 => Sysno::Mkdirat,
            35 => Sysno::Unlinkat,
            36 => Sysno::Symlinkat,
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
    fn stat_layout(&self) -> StatLayout {
        // struct stat (arm64 asm-generic): total 128 bytes.
        StatLayout {
            size: 128,
            mode_off: 16,
            nlink_off: 20,
            size_off: 48,
            blksize_off: 56,
            blocks_off: 64,
            dev_off: 0,
            ino_off: 8,
        }
    }
}

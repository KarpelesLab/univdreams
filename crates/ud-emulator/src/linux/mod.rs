//! Linux user-mode personality: emulate *syscalls* so a static ELF
//! program runs in a fully isolated environment (its own memory + the
//! [`VirtualFs`](crate::context::VirtualFs)), the way [`crate::win32`]
//! emulates the Win32 API surface for PE programs.
//!
//! Split into an arch-agnostic **engine** ([`LinuxKernel`], here) and thin
//! per-architecture **adapters** ([`abi`]). The engine speaks a canonical
//! [`Sysno`](abi::Sysno) and six `u64` args; the adapter knows the arch's
//! register layout and number table. Only the i386 adapter is wired to a
//! working CPU today (the interpreter is 32-bit); x86-64 / aarch64 land as
//! additional adapters once their CPU back-ends exist.

pub mod abi;
pub mod guest;
#[cfg(feature = "kvm")]
pub mod kvm;
pub mod loader;
pub mod mem;

use std::collections::BTreeMap;

use crate::context::FileAccess;
use crate::emulator::Perm;
use crate::fsmount::MountTable;

use abi::{LinuxAbi, Sysno};
use guest::GuestCpu;
use mem::GuestMem;

// Negative errno values returned to the guest.
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;

/// A page size for `brk` / `mmap` rounding.
const PAGE: u32 = 0x1000;
/// Base of the anonymous-`mmap` bump arena (grows up).
const MMAP_BASE: u32 = 0x4000_0000;
const MMAP_LIMIT: u32 = 0x8000_0000;

/// What an open Linux file descriptor refers to.
#[derive(Debug, Clone)]
enum Fd {
    Stdin,
    Stdout,
    Stderr,
    /// A table-minted file handle (`MountTable`).
    Vfs(u32),
}

/// The arch-agnostic Linux kernel engine: process memory bookkeeping, the
/// file-descriptor table, captured stdout/stderr, and the exit status.
#[derive(Debug, Default)]
pub struct LinuxKernel {
    /// Program break (requested value) and the lowest unmapped page above
    /// the loaded image.
    brk: u32,
    brk_mapped: u32,
    /// Next free address in the anonymous-mmap arena.
    mmap_top: u32,
    fds: BTreeMap<i32, Fd>,
    next_fd: i32,
    /// Captured fd 1 / fd 2 output.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `Some(code)` once the program called exit / exit_group.
    pub exit_code: Option<i32>,
    /// Syscalls we don't implement, surfaced in the report (name + count).
    pub unsupported: BTreeMap<String, u64>,
    /// 64-bit guest? Set from the active ABI's pointer width; selects the
    /// width of kernel-written structs (`timespec`, `timeval`).
    ptr64: bool,
    /// Rolling counter feeding `getrandom` so output is deterministic.
    rng: u64,
    /// TID of the thread currently being serviced (the amd64 scheduler sets
    /// this before each dispatch; `gettid` returns it). `1` = main thread.
    pub current_tid: i32,
}

impl LinuxKernel {
    /// Initialise process state after the loader has mapped the image.
    /// `brk` is the page-aligned end of the highest `PT_LOAD`.
    pub fn init(&mut self, brk: u32) {
        self.brk = brk;
        self.brk_mapped = brk;
        self.mmap_top = MMAP_BASE;
        self.fds.clear();
        self.fds.insert(0, Fd::Stdin);
        self.fds.insert(1, Fd::Stdout);
        self.fds.insert(2, Fd::Stderr);
        self.next_fd = 3;
        self.current_tid = 1;
    }

    /// Service one syscall: read `(nr, args)` via `abi`, run it, write the
    /// result back. `vfs` backs the file-descriptor syscalls.
    pub fn dispatch(
        &mut self,
        abi: &dyn LinuxAbi,
        cpu: &mut dyn GuestCpu,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) {
        self.ptr64 = abi.ptr_bits() == 64;
        let nr = abi.syscall_nr(cpu);
        let a = abi.syscall_args(cpu);
        let Some(sys) = abi.map_syscall(nr) else {
            *self.unsupported.entry(format!("nr {nr}")).or_default() += 1;
            abi.set_return(cpu, ENOSYS);
            return;
        };
        let trace = std::env::var("UD_LINUX_TRACE").is_ok();
        // arch_prctl(ARCH_SET_FS=0x1002, base) installs the amd64 TLS base
        // on the CPU itself — handle it here where we hold the `cpu`.
        if sys == Sysno::ArchPrctl {
            if a[0] == 0x1002 {
                cpu.set_tls(a[1]);
            }
            if trace {
                eprintln!("syscall arch_prctl({:#x}, {:#x}) = 0", a[0], a[1]);
            }
            abi.set_return(cpu, 0);
            return;
        }
        let ret = self.run(sys, &a, mmu, vfs);
        if trace {
            eprintln!(
                "syscall {sys:?}({:#x}, {:#x}, {:#x}) = {ret:#x}",
                a[0], a[1], a[2]
            );
        }
        abi.set_return(cpu, ret);
    }

    #[allow(clippy::too_many_lines)]
    fn run(
        &mut self,
        sys: Sysno,
        a: &[u64; 6],
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let (a0, a1, a2) = (a[0] as u32, a[1] as u32, a[2] as u32);
        match sys {
            Sysno::Write => self.sys_write(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Writev => self.sys_writev(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Read => self.sys_read(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Open => self.sys_open(a0, a1, mmu, vfs),
            Sysno::Openat => self.sys_open(a1, a2, mmu, vfs), // ignore dirfd; absolute paths
            Sysno::Close => self.sys_close(a0 as i32, vfs),
            Sysno::Lseek => self.sys_lseek(a0 as i32, a1 as i32, a2, vfs),
            Sysno::Brk => self.sys_brk(a0, mmu),
            Sysno::Mmap => self.sys_mmap(a0, a1, a[3] as u32, a[4] as i32, mmu),
            Sysno::Munmap => 0, // accept; we never reclaim the bump arena
            Sysno::Mprotect => 0,
            Sysno::Exit | Sysno::ExitGroup => {
                self.exit_code = Some(a0 as i32);
                0
            }
            Sysno::Fstat | Sysno::Stat | Sysno::Newfstatat => self.sys_stat_zero(sys, a, mmu),
            Sysno::Uname => self.sys_uname(a0, mmu),
            Sysno::Getpid => 1,
            Sysno::Gettid => i64::from(self.current_tid),
            Sysno::Getppid => 0,
            Sysno::Getuid | Sysno::Geteuid | Sysno::Getgid | Sysno::Getegid => 0,
            Sysno::Time => 0,
            Sysno::ClockGettime => self.sys_clock_gettime(a1, mmu),
            Sysno::Gettimeofday => self.sys_gettimeofday(a0, mmu),
            Sysno::Futex => 0, // uncontended: report success
            Sysno::Getrandom => self.sys_getrandom(a0, a1, mmu),
            Sysno::Readlinkat => ENOENT, // no symlinks in the VFS
            Sysno::SchedYield => 0,
            // clone/futex are serviced by the amd64 thread scheduler; on the
            // single-threaded paths they degrade to "no threads".
            Sysno::Clone => ENOSYS,
            Sysno::Access => ENOENT,
            Sysno::Getcwd => self.sys_getcwd(a0, a1, mmu),
            Sysno::Ioctl => ENOTTY, // "not a terminal" → libc picks full buffering
            Sysno::ArchPrctl => 0,
            Sysno::SetTidAddress => 1,
            Sysno::SetRobustList | Sysno::RtSigaction | Sysno::RtSigprocmask | Sysno::Ignored => 0,
            // Defensive: any variant we forgot routes to ENOSYS with a log.
            #[allow(unreachable_patterns)]
            _ => {
                *self.unsupported.entry(format!("{sys:?}")).or_default() += 1;
                ENOSYS
            }
        }
    }

    // ---- file descriptors ------------------------------------------------

    fn sys_write(
        &mut self,
        fd: i32,
        buf: u32,
        len: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let data = match read_mem(mmu, buf, len as usize) {
            Some(d) => d,
            None => return EFAULT,
        };
        match self.fds.get(&fd) {
            Some(Fd::Stdout) => {
                self.stdout.extend_from_slice(&data);
                data.len() as i64
            }
            Some(Fd::Stderr) => {
                self.stderr.extend_from_slice(&data);
                data.len() as i64
            }
            Some(Fd::Vfs(h)) => vfs.write_handle(*h, &data).map_or(EBADF, |n| n as i64),
            Some(Fd::Stdin) | None => EBADF,
        }
    }

    fn sys_writev(
        &mut self,
        fd: i32,
        iov: u32,
        cnt: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let mut total = 0i64;
        for i in 0..cnt {
            let base = iov.wrapping_add(i.wrapping_mul(8));
            let (Ok(ptr), Ok(len)) = (mmu.load32(base), mmu.load32(base.wrapping_add(4))) else {
                return EFAULT;
            };
            let r = self.sys_write(fd, ptr, len, mmu, vfs);
            if r < 0 {
                return if total > 0 { total } else { r };
            }
            total += r;
        }
        total
    }

    fn sys_read(
        &mut self,
        fd: i32,
        buf: u32,
        len: u32,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        match self.fds.get(&fd) {
            Some(Fd::Stdin) => 0, // EOF — no stdin
            Some(Fd::Vfs(h)) => {
                let mut tmp = vec![0u8; len as usize];
                let n = vfs.read_handle(*h, &mut tmp).unwrap_or(0);
                if write_mem(mmu, buf, &tmp[..n]).is_none() {
                    return EFAULT;
                }
                n as i64
            }
            Some(Fd::Stdout) | Some(Fd::Stderr) | None => EBADF,
        }
    }

    fn sys_open(&mut self, path: u32, flags: u32, mmu: &dyn GuestMem, vfs: &mut MountTable) -> i64 {
        let Some(p) = read_cstr(mmu, path, 4096) else {
            return EFAULT;
        };
        // O_WRONLY=1, O_RDWR=2, O_CREAT=0x40 (i386/x86-64 share these).
        let access = match flags & 0x3 {
            0 => FileAccess::Read,
            1 => FileAccess::Write,
            _ => FileAccess::ReadWrite,
        };
        if flags & 0x40 != 0 {
            vfs.write_path(&p, Vec::new()); // O_CREAT: ensure it exists
        }
        match vfs.open(&p, access) {
            Some(h) => {
                let fd = self.next_fd;
                self.next_fd += 1;
                self.fds.insert(fd, Fd::Vfs(h));
                i64::from(fd)
            }
            None => ENOENT,
        }
    }

    fn sys_close(&mut self, fd: i32, vfs: &mut MountTable) -> i64 {
        match self.fds.remove(&fd) {
            Some(Fd::Vfs(h)) => {
                vfs.close(h);
                0
            }
            Some(_) => 0, // closing a std stream: accept
            None => EBADF,
        }
    }

    fn sys_lseek(&mut self, fd: i32, off: i32, whence: u32, vfs: &mut MountTable) -> i64 {
        match self.fds.get(&fd) {
            Some(Fd::Vfs(h)) => vfs
                .seek_handle(*h, off, whence as u8)
                .map_or(EINVAL, |p| p as i64),
            _ => EINVAL,
        }
    }

    // ---- memory ----------------------------------------------------------

    fn sys_brk(&mut self, new: u32, mmu: &mut dyn GuestMem) -> i64 {
        if new == 0 || new < self.brk {
            // Query, or a shrink we don't honour: report the current break.
            return i64::from(self.brk);
        }
        let want = page_up(new);
        if want > self.brk_mapped {
            mmu.map(
                self.brk_mapped,
                want.wrapping_sub(self.brk_mapped),
                Perm::R | Perm::W,
            );
            self.brk_mapped = want;
        }
        self.brk = new;
        i64::from(self.brk)
    }

    fn sys_mmap(
        &mut self,
        _addr: u32,
        len: u32,
        flags: u32,
        fd: i32,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        // MAP_ANONYMOUS = 0x20. We only serve anonymous mappings from a
        // bump arena; file-backed mmap (fd >= 0) is not modelled yet.
        if fd >= 0 && flags & 0x20 == 0 {
            return ENOSYS;
        }
        let size = page_up(len.max(1));
        let base = self.mmap_top;
        if base.checked_add(size).is_none_or(|end| end > MMAP_LIMIT) {
            return -12; // ENOMEM
        }
        mmu.map(base, size, Perm::R | Perm::W | Perm::X);
        self.mmap_top = base.wrapping_add(size);
        i64::from(base)
    }

    // ---- info ------------------------------------------------------------

    fn sys_uname(&self, buf: u32, mmu: &mut dyn GuestMem) -> i64 {
        // struct utsname: 6 × 65-byte NUL-padded fields.
        let fields = [
            "Linux",
            "univdreams",
            "5.15.0",
            "#1 univdreams",
            "i686",
            "(none)",
        ];
        for (i, s) in fields.iter().enumerate() {
            let off = buf.wrapping_add((i * 65) as u32);
            let mut bytes = s.as_bytes().to_vec();
            bytes.resize(65, 0);
            if write_mem(mmu, off, &bytes).is_none() {
                return EFAULT;
            }
        }
        0
    }

    fn sys_getcwd(&self, buf: u32, size: u32, mmu: &mut dyn GuestMem) -> i64 {
        let cwd = b"/\0";
        if (size as usize) < cwd.len() {
            return -34; // ERANGE
        }
        if write_mem(mmu, buf, cwd).is_none() {
            return EFAULT;
        }
        i64::from(buf)
    }

    fn sys_clock_gettime(&self, ts: u32, mmu: &mut dyn GuestMem) -> i64 {
        // struct timespec { time_t tv_sec; long tv_nsec; } — word size
        // follows the guest's pointer width. A fixed epoch is fine for the
        // programs we run (they only need monotonicity within a run, which
        // a constant trivially satisfies).
        self.write_time_pair(ts, 0, 0, mmu)
    }

    fn sys_gettimeofday(&self, tv: u32, mmu: &mut dyn GuestMem) -> i64 {
        if tv == 0 {
            return 0;
        }
        // struct timeval { time_t tv_sec; suseconds_t tv_usec; }
        self.write_time_pair(tv, 0, 0, mmu)
    }

    /// Write a two-field time struct (`tv_sec`, `tv_nsec`/`tv_usec`) at the
    /// guest's pointer width.
    fn write_time_pair(&self, addr: u32, sec: u64, frac: u64, mmu: &mut dyn GuestMem) -> i64 {
        let mut buf = Vec::new();
        if self.ptr64 {
            buf.extend_from_slice(&sec.to_le_bytes());
            buf.extend_from_slice(&frac.to_le_bytes());
        } else {
            buf.extend_from_slice(&(sec as u32).to_le_bytes());
            buf.extend_from_slice(&(frac as u32).to_le_bytes());
        }
        if write_mem(mmu, addr, &buf).is_none() {
            return EFAULT;
        }
        0
    }

    fn sys_getrandom(&mut self, buf: u32, len: u32, mmu: &mut dyn GuestMem) -> i64 {
        // Deterministic pseudo-random bytes from a SplitMix64-style counter
        // (reproducible across runs; not for cryptographic use).
        let mut out = Vec::with_capacity(len as usize);
        for _ in 0..len {
            self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            out.push((z ^ (z >> 31)) as u8);
        }
        if write_mem(mmu, buf, &out).is_none() {
            return EFAULT;
        }
        i64::from(len)
    }

    fn sys_stat_zero(&self, sys: Sysno, a: &[u64; 6], mmu: &mut dyn GuestMem) -> i64 {
        // Fill the caller's stat buffer with zeros and report success.
        // A zeroed stat reads as st_size=0, st_mode=0 — enough for libc's
        // buffering decision not to crash. Buffer pointer position differs
        // by syscall: fstat(fd, buf); stat(path, buf); newfstatat(dirfd,
        // path, buf, flags).
        let buf = match sys {
            Sysno::Newfstatat => a[2] as u32,
            _ => a[1] as u32,
        };
        let zero = [0u8; 144];
        if write_mem(mmu, buf, &zero).is_none() {
            return EFAULT;
        }
        0
    }
}

// ---- guest memory helpers ------------------------------------------------

fn read_mem(mmu: &dyn GuestMem, addr: u32, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(mmu.load8(addr.wrapping_add(i as u32)).ok()?);
    }
    Some(out)
}

fn write_mem(mmu: &mut dyn GuestMem, addr: u32, data: &[u8]) -> Option<()> {
    for (i, &b) in data.iter().enumerate() {
        mmu.store8(addr.wrapping_add(i as u32), b).ok()?;
    }
    Some(())
}

fn read_cstr(mmu: &dyn GuestMem, addr: u32, max: usize) -> Option<String> {
    let mut out = Vec::new();
    for i in 0..max as u32 {
        match mmu.load8(addr.wrapping_add(i)) {
            Ok(0) => return Some(String::from_utf8_lossy(&out).into_owned()),
            Ok(b) => out.push(b),
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

const fn page_up(addr: u32) -> u32 {
    addr.wrapping_add(PAGE - 1) & !(PAGE - 1)
}

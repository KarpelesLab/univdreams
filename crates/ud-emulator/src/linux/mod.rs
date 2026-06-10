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
use crate::fsmount::{MountTable, NodeKind};

use abi::{LinuxAbi, StatLayout, Sysno};
use guest::GuestCpu;
use mem::GuestMem;

// Negative errno values returned to the guest.
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;

/// `dirfd` value meaning "relative to the current working directory".
const AT_FDCWD: i32 = -100;

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
    /// A table-minted file handle (`MountTable`), plus the normalised path it
    /// was opened on (for `fstat` / `ftruncate`).
    Vfs {
        h: u32,
        path: String,
    },
    /// An open directory: its normalised path and the `getdents64` cursor (the
    /// index of the next entry to emit).
    Dir {
        path: String,
        pos: usize,
    },
    /// The read / write end of a pipe (index into `LinuxKernel::pipes`). Within
    /// one process this is an in-memory byte buffer.
    PipeRead(usize),
    PipeWrite(usize),
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
    /// Active file-backed mappings, for `MAP_SHARED` writeback on
    /// `munmap`/`msync`.
    file_maps: Vec<FileMapping>,
    /// Current working directory (normalised absolute path), for `getcwd` and
    /// relative-path / `AT_FDCWD` resolution. Defaults to `/`.
    cwd: String,
    /// Process file-mode creation mask (`umask`). Cosmetic — we don't enforce
    /// permissions — but tracked so `umask` returns the previous value.
    umask: u32,
    /// In-memory pipe buffers, referenced by [`Fd::PipeRead`] / [`Fd::PipeWrite`].
    pipes: Vec<std::collections::VecDeque<u8>>,
}

/// A file-backed `mmap` region we may need to flush back to the file.
#[derive(Debug, Clone)]
struct FileMapping {
    base: u32,
    len: u32,
    /// Mount path the bytes came from.
    path: String,
    /// File offset the mapping starts at.
    offset: u64,
    /// Bytes that were actually backed by file content (the rest is BSS).
    file_len: u32,
    /// `MAP_SHARED` and writable → changes flush back to the file.
    writeback: bool,
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
        self.cwd = "/".to_string();
        self.umask = 0o022;
        self.pipes.clear();
    }

    /// Read a NUL-terminated array of string pointers (`argv` / `envp`) from
    /// guest memory at `addr`, honouring the guest pointer width.
    pub fn read_str_array(&self, mmu: &dyn GuestMem, addr: u32) -> Vec<String> {
        let mut out = Vec::new();
        let step = if self.ptr64 { 8u32 } else { 4 };
        let mut p = addr;
        for _ in 0..4096 {
            let ptr = if self.ptr64 {
                mmu.load64(p).ok().map(|v| v as u32)
            } else {
                mmu.load32(p).ok()
            };
            match ptr {
                Some(0) | None => break,
                Some(sp) => {
                    if let Some(s) = read_cstr(mmu, sp, 4096) {
                        out.push(s);
                    }
                }
            }
            p = p.wrapping_add(step);
        }
        out
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
        let ret = self.run(sys, &a, mmu, vfs, abi.stat_layout());
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
        stat_layout: StatLayout,
    ) -> i64 {
        let (a0, a1, a2) = (a[0] as u32, a[1] as u32, a[2] as u32);
        match sys {
            Sysno::Write => self.sys_write(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Writev => self.sys_writev(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Read => self.sys_read(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Open => self.sys_openat(AT_FDCWD, a0, a1, mmu, vfs),
            Sysno::Openat => self.sys_openat(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Close => self.sys_close(a0 as i32, vfs),
            Sysno::Lseek => self.sys_lseek(a0 as i32, a1 as i32, a2, vfs),
            Sysno::Brk => self.sys_brk(a0, mmu),
            // mmap(addr, len, prot, flags, fd, offset). i386 uses mmap2 whose
            // offset is in pages; amd64 mmap's is in bytes.
            Sysno::Mmap => {
                let off = if self.ptr64 {
                    a[5]
                } else {
                    a[5].wrapping_mul(u64::from(PAGE))
                };
                self.sys_mmap(a0, a1, a2, a[3] as u32, a[4] as i32, off, mmu, vfs)
            }
            Sysno::Munmap => self.sys_munmap(a0, a1, mmu, vfs),
            Sysno::Mprotect => self.sys_mprotect(a0, a1, a2, mmu),
            Sysno::Exit | Sysno::ExitGroup => {
                self.exit_code = Some(a0 as i32);
                0
            }
            Sysno::Fstat | Sysno::Stat | Sysno::Lstat | Sysno::Newfstatat => {
                self.sys_stat(sys, a, mmu, vfs, stat_layout)
            }
            // statx(dirfd, path, flags, mask, buf)
            Sysno::Statx => self.sys_statx(a0 as i32, a1, a2, a[4] as u32, mmu, vfs),
            Sysno::Getdents64 => self.sys_getdents64(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Mkdir => self.sys_mkdirat(AT_FDCWD, a0, mmu, vfs),
            Sysno::Mkdirat => self.sys_mkdirat(a0 as i32, a1, mmu, vfs),
            Sysno::Unlink => self.sys_unlinkat(AT_FDCWD, a0, false, mmu, vfs),
            Sysno::Rmdir => self.sys_unlinkat(AT_FDCWD, a0, true, mmu, vfs),
            // unlinkat(dirfd, path, flags); AT_REMOVEDIR = 0x200.
            Sysno::Unlinkat => self.sys_unlinkat(a0 as i32, a1, a2 & 0x200 != 0, mmu, vfs),
            Sysno::Symlink => self.sys_symlinkat(a0, AT_FDCWD, a1, mmu, vfs),
            Sysno::Symlinkat => self.sys_symlinkat(a0, a1 as i32, a2, mmu, vfs),
            Sysno::Truncate => self.sys_truncate(a0, a[1], mmu, vfs),
            Sysno::Ftruncate => self.sys_ftruncate(a0 as i32, a[1], vfs),
            Sysno::Readlink => self.sys_readlinkat(AT_FDCWD, a0, a1, a2, mmu, vfs),
            Sysno::Readlinkat => self.sys_readlinkat(a0 as i32, a1, a2, a[3] as u32, mmu, vfs),
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
            Sysno::SchedYield => 0,
            Sysno::Nanosleep => 0, // time is frozen; sleeping is instantaneous
            Sysno::Poll | Sysno::Ppoll => self.sys_poll(a0, a1, mmu),
            // clone/futex are serviced by the amd64 thread scheduler; on the
            // single-threaded paths they degrade to "no threads".
            Sysno::Clone => ENOSYS,
            // access(path, mode) / faccessat(dirfd, path, mode, flags): we
            // don't enforce permissions, so "exists" == "accessible".
            Sysno::Access => self.sys_faccessat(AT_FDCWD, a0, mmu, vfs),
            Sysno::Faccessat => self.sys_faccessat(a0 as i32, a1, mmu, vfs),
            Sysno::Fcntl => self.sys_fcntl(a0 as i32, a1, a2),
            Sysno::Dup => self.sys_dup(a0 as i32),
            Sysno::Dup2 => self.sys_dup2(a0 as i32, a1 as i32, vfs),
            // dup3(old, new, flags) — flags (O_CLOEXEC) ignored.
            Sysno::Dup3 => self.sys_dup2(a0 as i32, a1 as i32, vfs),
            Sysno::Chdir => self.sys_chdir(a0, mmu, vfs),
            Sysno::Fchdir => self.sys_fchdir(a0 as i32),
            Sysno::Umask => {
                let old = self.umask;
                self.umask = a0 & 0o777;
                i64::from(old)
            }
            // We don't enforce file modes / times; accept these as success.
            Sysno::Fchmod | Sysno::Fchmodat | Sysno::Utimensat => 0,
            Sysno::Pread64 => self.sys_pread64(a0 as i32, a1, a2, a[3], vfs, mmu),
            Sysno::Pwrite64 => self.sys_pwrite64(a0 as i32, a1, a2, a[3], vfs, mmu),
            Sysno::Readv => self.sys_readv(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Pipe | Sysno::Pipe2 => self.sys_pipe(a0, mmu),
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
            Some(Fd::Vfs { h, .. }) => vfs.write_handle(*h, &data).map_or(EBADF, |n| n as i64),
            Some(&Fd::PipeWrite(i)) => {
                self.pipes[i].extend(data.iter().copied());
                data.len() as i64
            }
            Some(Fd::Stdin | Fd::Dir { .. } | Fd::PipeRead(_)) | None => EBADF,
        }
    }

    /// Read one `struct iovec` (`{base, len}`) from the array at `iov`. The
    /// element width follows the guest's pointer size: 16 bytes on 64-bit
    /// (`u64` base + `u64` len), 8 bytes on 32-bit.
    fn read_iovec(&self, iov: u32, i: u32, mmu: &dyn GuestMem) -> Option<(u32, u32)> {
        if self.ptr64 {
            let base = iov.wrapping_add(i.wrapping_mul(16));
            let ptr = mmu.load64(base).ok()?;
            let len = mmu.load64(base.wrapping_add(8)).ok()?;
            Some((ptr as u32, len as u32))
        } else {
            let base = iov.wrapping_add(i.wrapping_mul(8));
            let ptr = mmu.load32(base).ok()?;
            let len = mmu.load32(base.wrapping_add(4)).ok()?;
            Some((ptr, len))
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
            let Some((ptr, len)) = self.read_iovec(iov, i, mmu) else {
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
            Some(Fd::Vfs { h, .. }) => {
                let mut tmp = vec![0u8; len as usize];
                let n = vfs.read_handle(*h, &mut tmp).unwrap_or(0);
                if write_mem(mmu, buf, &tmp[..n]).is_none() {
                    return EFAULT;
                }
                n as i64
            }
            Some(&Fd::PipeRead(i)) => {
                let n = (len as usize).min(self.pipes[i].len());
                let bytes: Vec<u8> = self.pipes[i].drain(..n).collect();
                if write_mem(mmu, buf, &bytes).is_none() {
                    return EFAULT;
                }
                n as i64 // 0 when empty (treated as EOF in this single-process model)
            }
            // read() on a directory fd is EISDIR; the std streams are EBADF.
            Some(Fd::Dir { .. }) => EISDIR,
            Some(Fd::Stdout | Fd::Stderr | Fd::PipeWrite(_)) | None => EBADF,
        }
    }

    /// Resolve a guest path string against a `dirfd` (or the cwd for
    /// `AT_FDCWD`) into a normalised absolute path. Returns `None` on a bad
    /// pointer or an unknown `dirfd`.
    fn resolve_at(&self, dirfd: i32, path_ptr: u32, mmu: &dyn GuestMem) -> Option<String> {
        let p = read_cstr(mmu, path_ptr, 4096)?;
        if p.starts_with('/') {
            return Some(canonicalize("/", &p));
        }
        let base = if dirfd == AT_FDCWD {
            self.cwd.clone()
        } else {
            match self.fds.get(&dirfd) {
                Some(Fd::Dir { path, .. } | Fd::Vfs { path, .. }) => path.clone(),
                _ => return None,
            }
        };
        Some(canonicalize(&base, &p))
    }

    fn sys_openat(
        &mut self,
        dirfd: i32,
        path: u32,
        flags: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = self.resolve_at(dirfd, path, mmu) else {
            return EBADF;
        };
        // O_WRONLY=1, O_RDWR=2, O_CREAT=0x40 (i386/x86-64 share these).
        let access = match flags & 0x3 {
            0 => FileAccess::Read,
            1 => FileAccess::Write,
            _ => FileAccess::ReadWrite,
        };
        // A directory open (explicit O_DIRECTORY=0x10000, or the path simply is
        // one) gets a dir fd that serves getdents64 rather than a file handle.
        let is_dir = flags & 0x1_0000 != 0
            || vfs
                .stat_path(&p)
                .is_some_and(|att| matches!(att.kind, NodeKind::Dir));
        if is_dir {
            let fd = self.next_fd;
            self.next_fd += 1;
            self.fds.insert(fd, Fd::Dir { path: p, pos: 0 });
            return i64::from(fd);
        }
        if flags & 0x40 != 0 {
            vfs.write_path(&p, Vec::new()); // O_CREAT: ensure it exists
        }
        match vfs.open(&p, access) {
            Some(h) => {
                let fd = self.next_fd;
                self.next_fd += 1;
                self.fds.insert(fd, Fd::Vfs { h, path: p });
                i64::from(fd)
            }
            None => ENOENT,
        }
    }

    fn sys_close(&mut self, fd: i32, vfs: &mut MountTable) -> i64 {
        match self.fds.remove(&fd) {
            Some(Fd::Vfs { h, .. }) => {
                vfs.close(h);
                0
            }
            Some(_) => 0, // closing a std stream or dir fd: accept
            None => EBADF,
        }
    }

    fn sys_lseek(&mut self, fd: i32, off: i32, whence: u32, vfs: &mut MountTable) -> i64 {
        match self.fds.get(&fd) {
            Some(Fd::Vfs { h, .. }) => vfs
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

    #[allow(clippy::too_many_arguments)]
    fn sys_mmap(
        &mut self,
        addr: u32,
        len: u32,
        prot: u32,
        flags: u32,
        fd: i32,
        offset: u64,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        const MAP_SHARED: u32 = 0x1;
        const MAP_FIXED: u32 = 0x10;
        const MAP_ANONYMOUS: u32 = 0x20;
        let size = page_up(len.max(1));

        // Pick the base address: MAP_FIXED honors the request; otherwise grow
        // the bump arena.
        let base = if flags & MAP_FIXED != 0 {
            addr & !(PAGE - 1)
        } else {
            let b = self.mmap_top;
            if b.checked_add(size).is_none_or(|end| end > MMAP_LIMIT) {
                return -12; // ENOMEM
            }
            self.mmap_top = b.wrapping_add(size);
            b
        };

        if flags & MAP_ANONYMOUS != 0 || fd < 0 {
            // Anonymous: stays RWX (permissive) so JIT/stack/heap all work.
            mmu.map(base, size, Perm::R | Perm::W | Perm::X);
            return i64::from(base);
        }

        // File-backed: populate the region from the fd's file, then enforce
        // the requested protection.
        let path = match self.fds.get(&fd) {
            Some(Fd::Vfs { path, .. }) => path.clone(),
            _ => return EBADF,
        };
        // Map writable to populate, then read [offset, offset+len) from the file.
        mmu.map(base, size, Perm::R | Perm::W);
        let data = read_file_region(vfs, &path, offset, len as usize);
        let file_len = data.len() as u32;
        if write_mem(mmu, base, &data).is_none() {
            return EFAULT;
        }
        // Enforce the requested perms (text segments become R-X, etc.).
        mmu.map(base, size, prot_to_perm(prot));

        let writeback = (flags & MAP_SHARED != 0) && (prot & 0x2 != 0); // PROT_WRITE
        self.file_maps.push(FileMapping {
            base,
            len: size,
            path,
            offset,
            file_len,
            writeback,
        });
        i64::from(base)
    }

    fn sys_munmap(&mut self, addr: u32, len: u32, mmu: &dyn GuestMem, vfs: &mut MountTable) -> i64 {
        let end = addr.wrapping_add(page_up(len));
        // Flush + drop any file mapping that overlaps [addr, end).
        let overlapping: Vec<FileMapping> = self
            .file_maps
            .iter()
            .filter(|m| m.base < end && m.base.wrapping_add(m.len) > addr)
            .cloned()
            .collect();
        for m in &overlapping {
            self.flush_file_mapping(m, mmu, vfs);
        }
        self.file_maps
            .retain(|m| !(m.base < end && m.base.wrapping_add(m.len) > addr));
        // We don't reclaim the address range itself (bump arena), which is a
        // benign leak for our short-lived guests.
        0
    }

    fn sys_mprotect(&mut self, addr: u32, len: u32, prot: u32, mmu: &mut dyn GuestMem) -> i64 {
        let start = addr & !(PAGE - 1);
        let size = page_up(addr.wrapping_add(len)).wrapping_sub(start);
        mmu.map(start, size, prot_to_perm(prot));
        0
    }

    /// Write a `MAP_SHARED` mapping's current bytes back to its file (only the
    /// file-backed prefix, never the BSS tail).
    fn flush_file_mapping(&self, m: &FileMapping, mmu: &dyn GuestMem, vfs: &mut MountTable) {
        if !m.writeback || m.file_len == 0 {
            return;
        }
        let Some(bytes) = read_mem(mmu, m.base, m.file_len as usize) else {
            return;
        };
        if let Some(h) = vfs.open(&m.path, FileAccess::ReadWrite) {
            vfs.seek(h, m.offset);
            let _ = vfs.write_handle(h, &bytes);
            vfs.close(h);
        }
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
        let mut cwd = self.cwd.clone().into_bytes();
        cwd.push(0);
        if (size as usize) < cwd.len() {
            return -34; // ERANGE
        }
        if write_mem(mmu, buf, &cwd).is_none() {
            return EFAULT;
        }
        // getcwd returns the length including the NUL on Linux.
        cwd.len() as i64
    }

    fn sys_chdir(&mut self, path: u32, mmu: &dyn GuestMem, vfs: &mut MountTable) -> i64 {
        let Some(p) = self.resolve_at(AT_FDCWD, path, mmu) else {
            return EFAULT;
        };
        match vfs.stat_path(&p) {
            Some(a) if matches!(a.kind, NodeKind::Dir) => {
                self.cwd = p;
                0
            }
            Some(_) => ENOTDIR,
            None => ENOENT,
        }
    }

    fn sys_fchdir(&mut self, fd: i32) -> i64 {
        match self.fds.get(&fd) {
            Some(Fd::Dir { path, .. }) => {
                self.cwd = path.clone();
                0
            }
            Some(_) => ENOTDIR,
            None => EBADF,
        }
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

    /// `stat` / `fstat` / `newfstatat`: fill the caller's arch-specific stat
    /// buffer with the file's real kind + size. Buffer + subject differ by
    /// syscall: fstat(fd, buf); stat(path, buf); newfstatat(dirfd, path, buf,
    /// flags).
    fn sys_stat(
        &self,
        sys: Sysno,
        a: &[u64; 6],
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
        layout: StatLayout,
    ) -> i64 {
        // Resolve the subject and the destination buffer pointer. `perm` is the
        // file's real permission bits (so executability survives to the guest).
        let (kind, size, perm, buf) = match sys {
            Sysno::Fstat => {
                let buf = a[1] as u32;
                match self.fds.get(&(a[0] as i32)) {
                    // A char-device stat for the std streams + pipes keeps
                    // isatty()/libc buffering happy.
                    Some(
                        Fd::Stdin | Fd::Stdout | Fd::Stderr | Fd::PipeRead(_) | Fd::PipeWrite(_),
                    ) => (NodeKind::CharDevice, 0, 0o666, buf),
                    Some(Fd::Vfs { path, .. }) => {
                        let att = vfs.stat_path(path);
                        (
                            att.map_or(NodeKind::File, |x| x.kind),
                            att.map_or(0, |x| x.size),
                            att.map_or(0, |x| x.mode),
                            buf,
                        )
                    }
                    Some(Fd::Dir { path, .. }) => {
                        let path = path.clone();
                        let att = vfs.stat_path(&path);
                        (
                            NodeKind::Dir,
                            att.map_or(0, |x| x.size),
                            att.map_or(0, |x| x.mode),
                            buf,
                        )
                    }
                    None => return EBADF,
                }
            }
            sys => {
                // stat/lstat(path, buf) | newfstatat(dirfd, path, buf, flags).
                // AT_SYMLINK_NOFOLLOW = 0x100 (set by glibc's lstat()).
                let (dirfd, path_ptr, buf, nofollow) = if sys == Sysno::Newfstatat {
                    (a[0] as i32, a[1] as u32, a[2] as u32, a[3] & 0x100 != 0)
                } else {
                    (AT_FDCWD, a[0] as u32, a[1] as u32, sys == Sysno::Lstat)
                };
                let Some(p) = self.resolve_at(dirfd, path_ptr, mmu) else {
                    return EBADF;
                };
                // stat/newfstatat follow symlinks; lstat (or AT_SYMLINK_NOFOLLOW)
                // does not.
                let att = if nofollow {
                    vfs.stat_path(&p)
                } else {
                    vfs.stat_follow(&p)
                };
                match att {
                    Some(att) => (att.kind, att.size, att.mode, buf),
                    None => return ENOENT,
                }
            }
        };
        self.write_stat(buf, kind, size, perm, layout, mmu)
    }

    /// `statx(dirfd, path, flags, mask, buf)`: fill the architecture-independent
    /// `struct statx` (256 bytes) with the file's kind + size. musl uses statx
    /// for `stat`/`lstat` on modern kernels.
    fn sys_statx(
        &self,
        dirfd: i32,
        path: u32,
        flags: u32,
        buf: u32,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = self.resolve_at(dirfd, path, mmu) else {
            return EBADF;
        };
        // AT_SYMLINK_NOFOLLOW = 0x100.
        let att = if flags & 0x100 != 0 {
            vfs.stat_path(&p)
        } else {
            vfs.stat_follow(&p)
        };
        let Some(att) = att else {
            return ENOENT;
        };
        let mode = stat_mode(att.kind, att.mode) as u16;
        let mut b = [0u8; 256];
        // STATX_BASIC_STATS = 0x7ff (type,mode,nlink,uid,gid,atime,mtime,ctime,
        // ino,size,blocks).
        b[0..4].copy_from_slice(&0x7ffu32.to_le_bytes()); // stx_mask
        b[4..8].copy_from_slice(&512u32.to_le_bytes()); // stx_blksize
        b[16..20].copy_from_slice(&1u32.to_le_bytes()); // stx_nlink
        b[28..30].copy_from_slice(&mode.to_le_bytes()); // stx_mode
        b[40..48].copy_from_slice(&att.size.to_le_bytes()); // stx_size
        b[48..56].copy_from_slice(&att.size.div_ceil(512).to_le_bytes()); // stx_blocks
        if write_mem(mmu, buf, &b).is_none() {
            return EFAULT;
        }
        0
    }

    /// `access`/`faccessat`: we don't enforce permissions, so a path that
    /// exists is accessible.
    fn sys_faccessat(
        &self,
        dirfd: i32,
        path: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = self.resolve_at(dirfd, path, mmu) else {
            return EBADF;
        };
        if vfs.stat_path(&p).is_some() {
            0
        } else {
            ENOENT
        }
    }

    /// Serialise a stat struct (zeros except the fields we model) per `layout`.
    /// `perm` is the file's permission bits; if zero we fall back to a sensible
    /// default for the node kind.
    fn write_stat(
        &self,
        buf: u32,
        kind: NodeKind,
        size: u64,
        perm: u32,
        layout: StatLayout,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        let mode = stat_mode(kind, perm);
        let mut b = vec![0u8; layout.size];
        let put32 = |b: &mut [u8], off: usize, v: u32| {
            b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let put64 = |b: &mut [u8], off: usize, v: u64| {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        put32(&mut b, layout.mode_off, mode);
        put32(&mut b, layout.nlink_off, 1);
        put64(&mut b, layout.size_off, size);
        put32(&mut b, layout.blksize_off, 512);
        put64(&mut b, layout.blocks_off, size.div_ceil(512));
        if write_mem(mmu, buf, &b).is_none() {
            return EFAULT;
        }
        0
    }

    /// `getdents64(fd, dirp, count)`: emit `linux_dirent64` records for the
    /// open directory's entries (plus `.`/`..`), resuming from the fd's cursor.
    fn sys_getdents64(
        &mut self,
        fd: i32,
        dirp: u32,
        count: u32,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(Fd::Dir { path, pos }) = self.fds.get(&fd) else {
            return ENOTDIR;
        };
        let (path, start) = (path.clone(), *pos);
        let entries = match vfs.readdir_path(&path) {
            Ok(e) => e,
            Err(_) => return ENOTDIR,
        };
        // `.` and `..` lead, then the directory's own entries.
        let mut all: Vec<(String, NodeKind)> = vec![
            (".".to_string(), NodeKind::Dir),
            ("..".to_string(), NodeKind::Dir),
        ];
        all.extend(entries.into_iter().map(|e| (e.name, e.kind)));

        let mut off = 0u32;
        let mut idx = start;
        while idx < all.len() {
            let (name, kind) = &all[idx];
            let namelen = name.len() + 1; // include trailing NUL
            let reclen = (((19 + namelen) + 7) & !7) as u32; // align8(d_ino..d_name + NUL)
            if off + reclen > count {
                break;
            }
            let rec_base = dirp.wrapping_add(off);
            let d_type: u8 = match kind {
                NodeKind::Dir => 4,
                NodeKind::CharDevice => 2,
                NodeKind::Symlink => 10,
                NodeKind::File => 8,
            };
            // d_ino (8) | d_off (8) | d_reclen (2) | d_type (1) | name | NUL
            let mut rec = Vec::with_capacity(reclen as usize);
            rec.extend_from_slice(&((idx as u64) + 1).to_le_bytes());
            rec.extend_from_slice(&((idx as u64) + 1).to_le_bytes());
            rec.extend_from_slice(&(reclen as u16).to_le_bytes());
            rec.push(d_type);
            rec.extend_from_slice(name.as_bytes());
            rec.resize(reclen as usize, 0); // NUL + alignment padding
            if write_mem(mmu, rec_base, &rec).is_none() {
                return EFAULT;
            }
            off += reclen;
            idx += 1;
        }
        // No progress on a non-empty request → the buffer is too small.
        if off == 0 && start < all.len() {
            return EINVAL;
        }
        if let Some(Fd::Dir { pos, .. }) = self.fds.get_mut(&fd) {
            *pos = idx;
        }
        i64::from(off)
    }

    fn sys_mkdirat(
        &mut self,
        dirfd: i32,
        path: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = self.resolve_at(dirfd, path, mmu) else {
            return EBADF;
        };
        vfs.mkdir_path(&p, 0o755).map_or(EINVAL, |()| 0)
    }

    fn sys_unlinkat(
        &mut self,
        dirfd: i32,
        path: u32,
        is_rmdir: bool,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = self.resolve_at(dirfd, path, mmu) else {
            return EBADF;
        };
        let r = if is_rmdir {
            vfs.rmdir_path(&p)
        } else {
            vfs.unlink_path(&p)
        };
        r.map_or(ENOENT, |()| 0)
    }

    fn sys_symlinkat(
        &mut self,
        target: u32,
        dirfd: i32,
        linkpath: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let (Some(t), Some(l)) = (
            read_cstr(mmu, target, 4096),
            self.resolve_at(dirfd, linkpath, mmu),
        ) else {
            return EFAULT;
        };
        vfs.symlink_path(&t, &l).map_or(EINVAL, |()| 0)
    }

    fn sys_truncate(
        &mut self,
        path: u32,
        len: u64,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = read_cstr(mmu, path, 4096) else {
            return EFAULT;
        };
        vfs.truncate_path(&p, len).map_or(ENOENT, |()| 0)
    }

    fn sys_ftruncate(&mut self, fd: i32, len: u64, vfs: &mut MountTable) -> i64 {
        match self.fds.get(&fd) {
            Some(Fd::Vfs { path, .. }) => {
                let path = path.clone();
                vfs.truncate_path(&path, len).map_or(EINVAL, |()| 0)
            }
            Some(Fd::Dir { .. }) => EISDIR,
            _ => EBADF,
        }
    }

    /// `readlink(path, buf, size)` / `readlinkat(dirfd, path, buf, size)`:
    /// resolve a symlink (overlay-backed) into the caller's buffer.
    fn sys_readlinkat(
        &self,
        dirfd: i32,
        path: u32,
        buf: u32,
        size: u32,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let Some(p) = self.resolve_at(dirfd, path, mmu) else {
            return EBADF;
        };
        let target = match vfs.readlink_path(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => return EINVAL,
            Err(_) => return ENOENT,
        };
        let bytes = target.as_bytes();
        let n = bytes.len().min(size as usize);
        if write_mem(mmu, buf, &bytes[..n]).is_none() {
            return EFAULT;
        }
        n as i64
    }

    // ---- fd table ops ----------------------------------------------------

    /// `fcntl(fd, cmd, arg)`: enough for musl/busybox startup. We don't model
    /// O_CLOEXEC / file-status flags (no exec yet), so the descriptor-flag
    /// commands are accepted and queried as 0; `F_DUPFD` duplicates the fd.
    fn sys_fcntl(&mut self, fd: i32, cmd: u32, _arg: u32) -> i64 {
        if !self.fds.contains_key(&fd) {
            return EBADF;
        }
        match cmd {
            0 | 1030 => self.sys_dup(fd), // F_DUPFD / F_DUPFD_CLOEXEC
            1 | 3 => 0,                   // F_GETFD / F_GETFL → no flags
            2 | 4 => 0,                   // F_SETFD / F_SETFL → accept
            _ => 0,                       // other commands: accept
        }
    }

    /// Allocate the lowest free fd ≥ 3 and put `value` there.
    fn install_fd(&mut self, value: Fd) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, value);
        fd
    }

    /// `pipe`/`pipe2(fds)`: create an in-memory pipe and write the read/write
    /// fd pair to `fds[0]`/`fds[1]`.
    fn sys_pipe(&mut self, fds_ptr: u32, mmu: &mut dyn GuestMem) -> i64 {
        let idx = self.pipes.len();
        self.pipes.push(std::collections::VecDeque::new());
        let rfd = self.install_fd(Fd::PipeRead(idx));
        let wfd = self.install_fd(Fd::PipeWrite(idx));
        if write_mem(mmu, fds_ptr, &(rfd as u32).to_le_bytes()).is_none()
            || write_mem(mmu, fds_ptr.wrapping_add(4), &(wfd as u32).to_le_bytes()).is_none()
        {
            return EFAULT;
        }
        0
    }

    fn sys_dup(&mut self, oldfd: i32) -> i64 {
        match self.fds.get(&oldfd).cloned() {
            Some(v) => i64::from(self.install_fd(v)),
            None => EBADF,
        }
    }

    fn sys_dup2(&mut self, oldfd: i32, newfd: i32, vfs: &mut MountTable) -> i64 {
        let Some(v) = self.fds.get(&oldfd).cloned() else {
            return EBADF;
        };
        if oldfd == newfd {
            return i64::from(newfd);
        }
        // Close whatever currently occupies newfd.
        if let Some(Fd::Vfs { h, .. }) = self.fds.remove(&newfd) {
            vfs.close(h);
        }
        self.fds.insert(newfd, v);
        if newfd >= self.next_fd {
            self.next_fd = newfd + 1;
        }
        i64::from(newfd)
    }

    /// `poll`/`ppoll`: we don't block, and regular files / the std streams are
    /// always ready. Set each `revents` to its requested `events` and report
    /// the count of ready fds.
    fn sys_poll(&self, fds: u32, nfds: u32, mmu: &mut dyn GuestMem) -> i64 {
        // struct pollfd { int fd; short events; short revents; } — 8 bytes.
        let mut ready = 0i64;
        for i in 0..nfds {
            let base = fds.wrapping_add(i.wrapping_mul(8));
            let Ok(events) = mmu.load16(base.wrapping_add(4)) else {
                return EFAULT;
            };
            if write_mem(mmu, base.wrapping_add(6), &events.to_le_bytes()).is_none() {
                return EFAULT;
            }
            if events != 0 {
                ready += 1;
            }
        }
        ready
    }

    fn sys_pread64(
        &self,
        fd: i32,
        buf: u32,
        len: u32,
        offset: u64,
        vfs: &mut MountTable,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        let path = match self.fds.get(&fd) {
            Some(Fd::Vfs { path, .. }) => path.clone(),
            Some(Fd::Dir { .. }) => return EISDIR,
            _ => return EBADF,
        };
        let data = read_file_region(vfs, &path, offset, len as usize);
        if write_mem(mmu, buf, &data).is_none() {
            return EFAULT;
        }
        data.len() as i64
    }

    fn sys_pwrite64(
        &self,
        fd: i32,
        buf: u32,
        len: u32,
        offset: u64,
        vfs: &mut MountTable,
        mmu: &dyn GuestMem,
    ) -> i64 {
        let path = match self.fds.get(&fd) {
            Some(Fd::Vfs { path, .. }) => path.clone(),
            Some(Fd::Dir { .. }) => return EISDIR,
            _ => return EBADF,
        };
        let Some(data) = read_mem(mmu, buf, len as usize) else {
            return EFAULT;
        };
        if let Some(h) = vfs.open(&path, FileAccess::ReadWrite) {
            vfs.seek(h, offset);
            let n = vfs.write_handle(h, &data).unwrap_or(0);
            vfs.close(h);
            n as i64
        } else {
            EBADF
        }
    }

    /// `readv(fd, iov, cnt)`: scatter read into the iovec array (mirror of
    /// `sys_writev`).
    fn sys_readv(
        &mut self,
        fd: i32,
        iov: u32,
        cnt: u32,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let mut total = 0i64;
        for i in 0..cnt {
            let Some((ptr, len)) = self.read_iovec(iov, i, mmu) else {
                return EFAULT;
            };
            let r = self.sys_read(fd, ptr, len, mmu, vfs);
            if r < 0 {
                return if total > 0 { total } else { r };
            }
            total += r;
            if (r as u32) < len {
                break; // short read: stop
            }
        }
        total
    }
}

/// Compose a Unix `st_mode` from a node kind and its permission bits. A zero
/// `perm` (filesystem reported nothing) falls back to a sensible default —
/// importantly keeping the execute bits a shell checks before `execve`.
fn stat_mode(kind: NodeKind, perm: u32) -> u32 {
    let type_bits = match kind {
        NodeKind::Dir => 0o040_000,
        NodeKind::Symlink => 0o120_000,
        NodeKind::CharDevice => 0o020_000,
        NodeKind::File => 0o100_000,
    };
    let perm = if perm & 0o7777 != 0 {
        perm & 0o7777
    } else {
        match kind {
            NodeKind::Dir => 0o755,
            NodeKind::Symlink => 0o777,
            _ => 0o644,
        }
    };
    type_bits | perm
}

/// Resolve a (possibly relative) `path` against `base` (an absolute dir),
/// collapsing `.` / `..` and `//` into a clean absolute path. An absolute
/// `path` ignores `base`.
fn canonicalize(base: &str, path: &str) -> String {
    let mut comps: Vec<&str> = Vec::new();
    let first = if path.starts_with('/') { "" } else { base };
    for seg in first.split('/').chain(path.split('/')) {
        match seg {
            "" | "." => {}
            ".." => {
                comps.pop();
            }
            other => comps.push(other),
        }
    }
    if comps.is_empty() {
        return "/".to_string();
    }
    let mut s = String::with_capacity(path.len() + base.len() + 1);
    for c in &comps {
        s.push('/');
        s.push_str(c);
    }
    s
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

/// Map mmap `PROT_*` bits (READ=1, WRITE=2, EXEC=4) to MMU [`Perm`]. A
/// `PROT_NONE` mapping still gets `R` so the guest can fault-free probe it
/// (we don't model `PROT_NONE` guard pages).
fn prot_to_perm(prot: u32) -> Perm {
    let mut p = Perm::R;
    if prot & 0x2 != 0 {
        p = p | Perm::W;
    }
    if prot & 0x4 != 0 {
        p = p | Perm::X;
    }
    p
}

/// Read up to `len` bytes of `path` starting at `offset` from the mount table
/// (for file-backed `mmap`). Returns the bytes available (may be shorter than
/// `len` at EOF).
fn read_file_region(vfs: &mut MountTable, path: &str, offset: u64, len: usize) -> Vec<u8> {
    let Some(h) = vfs.open(path, FileAccess::Read) else {
        return Vec::new();
    };
    vfs.seek(h, offset);
    let mut out = Vec::with_capacity(len);
    let mut buf = vec![0u8; 64 * 1024];
    while out.len() < len {
        let want = (len - out.len()).min(buf.len());
        match vfs.read_handle(h, &mut buf[..want]) {
            Some(0) | None => break,
            Some(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    vfs.close(h);
    out
}

#[cfg(test)]
mod tests {
    use super::canonicalize;

    #[test]
    fn canonicalize_resolves_dots_and_relatives() {
        assert_eq!(canonicalize("/", "."), "/");
        assert_eq!(canonicalize("/", "etc"), "/etc");
        assert_eq!(canonicalize("/usr", "bin"), "/usr/bin");
        assert_eq!(canonicalize("/usr/bin", ".."), "/usr");
        assert_eq!(canonicalize("/usr/bin", "../lib"), "/usr/lib");
        assert_eq!(canonicalize("/a/b/c", "../../x"), "/a/x");
        // An absolute path ignores the base.
        assert_eq!(canonicalize("/usr", "/etc/hosts"), "/etc/hosts");
        // Collapse redundant separators and `.` segments.
        assert_eq!(canonicalize("/", "a//b/./c"), "/a/b/c");
        // `..` past the root clamps at root.
        assert_eq!(canonicalize("/", "../.."), "/");
    }
}

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
    /// A host-proxied network socket (index into `LinuxKernel::sockets`).
    Socket(usize),
}

/// State of a host-proxied guest socket. The guest runs its own protocol (HTTP,
/// TLS, DNS); we just shuttle bytes to a real host socket.
#[derive(Debug, Default)]
enum SocketState {
    /// `socket()` created but not yet connected/bound.
    Pending {
        ty: i32,
    },
    Tcp(std::net::TcpStream),
    Udp(std::net::UdpSocket),
    #[default]
    Closed,
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
    /// Host-proxied sockets, referenced by [`Fd::Socket`]. Only usable when
    /// `net_enabled` (the CLI's opt-in `--net`).
    sockets: Vec<SocketState>,
    /// Per-socket `O_NONBLOCK` flag (parallel to `sockets`). musl/libfetch set
    /// it via `SOCK_NONBLOCK` and toggle it with `fcntl(F_SETFL)`; we report it
    /// back through `F_GETFL` and use it to give `connect` non-blocking
    /// (`EINPROGRESS`) semantics, which the apk fetch state machine depends on.
    sock_nonblock: Vec<bool>,
    /// Allow the guest to open real host network sockets. Off by default.
    pub net_enabled: bool,
    /// Interactive mode (the CLI's `--interactive`): fd 0 reads the host
    /// terminal through the line discipline, fd 1/2 write straight to the host,
    /// and the tty `ioctl`s report a real terminal. Off by default (batch runs
    /// keep stdin=EOF and buffered stdout).
    pub interactive: bool,
    /// Guest tty settings (the Linux `struct termios`), driving the line
    /// discipline. `ICANON`/`ECHO`/`ISIG` in `c_lflag` select cooked vs raw.
    termios: Termios,
    /// Cooked input not yet consumed by the guest — the line discipline yields a
    /// whole line, which byte-at-a-time guest reads drain across calls.
    stdin_buf: std::collections::VecDeque<u8>,
    /// Host terminal size for `TIOCGWINSZ` (rows, cols); the CLI fills it in.
    /// `(0, 0)` falls back to 24×80.
    pub term_size: (u16, u16),
    /// Installed signal dispositions, by signal number (`rt_sigaction`).
    /// Absent = SIG_DFL. Used to deliver SIGINT from Ctrl-C.
    sigactions: BTreeMap<i32, SigAction>,
    /// Currently blocked signal mask (`rt_sigprocmask`); saved/restored across
    /// a signal frame.
    sig_mask: u64,
    /// A signal raised by the line discipline (Ctrl-C) that the run loop must
    /// deliver to the guest after the current syscall returns.
    pub pending_signal: Option<i32>,
    /// Shared channel to a background host-stdin reader (interactive KVM only).
    /// When present, `read_host_stdin` drains it instead of reading stdin
    /// directly, and an **async** terminal signal (the guest isn't in a `read`)
    /// arrives via `input.pending`. Absent ⇒ the synchronous fallback path.
    pub input: Option<std::sync::Arc<InteractiveInput>>,
}

/// Shared host-stdin channel for interactive mode. A background reader thread
/// (spawned by the KVM run loop) reads the raw host terminal and pushes bytes
/// here; the kernel line discipline drains them. The reader also turns terminal
/// signals into **async** ones (and the run loop kicks the vCPU out of
/// `KVM_RUN`), so a CPU-bound guest not in a `read` can still be interrupted:
/// VINTR (Ctrl-C) → SIGINT, VQUIT (Ctrl-\) → SIGQUIT, and a host window resize →
/// SIGWINCH (with the new size published in `win_rows`/`win_cols`).
#[derive(Debug, Default)]
pub struct InteractiveInput {
    state: std::sync::Mutex<InputState>,
    cv: std::sync::Condvar,
    /// Guest `ISIG` enabled — mirrors `c_lflag & ISIG`, updated on `TCSETS`.
    pub isig: std::sync::atomic::AtomicBool,
    /// Guest VINTR byte (default Ctrl-C = 3), updated on `TCSETS`.
    pub vintr: std::sync::atomic::AtomicU8,
    /// Guest VQUIT byte (default Ctrl-\ = 0x1c), updated on `TCSETS`.
    pub vquit: std::sync::atomic::AtomicU8,
    /// Pending async signals as a bitmask: bit `(sig-1)` set ⇒ `sig` pending.
    /// Consumed lowest-first by the run loop.
    pub pending: std::sync::atomic::AtomicU64,
    /// Live terminal size (rows, cols) tracked across SIGWINCH; `TIOCGWINSZ`
    /// reads it. Zero ⇒ fall back to the kernel's `term_size`.
    pub win_rows: std::sync::atomic::AtomicU16,
    pub win_cols: std::sync::atomic::AtomicU16,
    /// Set to ask the reader thread to exit at its next poll tick.
    pub stop: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Default)]
struct InputState {
    buf: std::collections::VecDeque<u8>,
    closed: bool,
}

/// Outcome of pulling one byte from the interactive input channel.
enum InByte {
    Byte(u8),
    Closed,
    Interrupted,
}

impl InteractiveInput {
    /// Push a byte read from the host terminal; wake any waiting reader.
    pub fn push(&self, b: u8) {
        self.state.lock().unwrap().buf.push_back(b);
        self.cv.notify_all();
    }
    /// Mark host stdin closed (EOF); wake any waiting reader.
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.cv.notify_all();
    }
    /// Raise async signal `sig`; wake any waiting reader. Set under the state
    /// lock so a reader parked in `next_byte` can't miss the wakeup.
    pub fn raise(&self, sig: i32) {
        let _g = self.state.lock().unwrap();
        self.pending.fetch_or(
            1u64 << ((sig - 1) as u64),
            std::sync::atomic::Ordering::SeqCst,
        );
        self.cv.notify_all();
    }
    /// Pop the lowest-numbered pending async signal, if any.
    pub fn take(&self) -> Option<i32> {
        use std::sync::atomic::Ordering::SeqCst;
        loop {
            let cur = self.pending.load(SeqCst);
            if cur == 0 {
                return None;
            }
            let sig = cur.trailing_zeros() as i32 + 1;
            let next = cur & !(1u64 << (sig - 1) as u64);
            if self
                .pending
                .compare_exchange(cur, next, SeqCst, SeqCst)
                .is_ok()
            {
                return Some(sig);
            }
        }
    }
    /// Block until a byte is available, the channel closes, or a signal is
    /// raised.
    fn next_byte(&self) -> InByte {
        let mut st = self.state.lock().unwrap();
        loop {
            if self.pending.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                return InByte::Interrupted;
            }
            if let Some(b) = st.buf.pop_front() {
                return InByte::Byte(b);
            }
            if st.closed {
                return InByte::Closed;
            }
            st = self.cv.wait(st).unwrap();
        }
    }
    /// Non-blocking pop of one buffered byte (raw-mode drain).
    fn try_byte(&self) -> Option<u8> {
        self.state.lock().unwrap().buf.pop_front()
    }
}

/// The Linux kernel `struct termios` (the 36-byte `TCGETS` layout: four 32-bit
/// flag words, a line discipline byte, then 19 control characters).
#[derive(Debug, Clone, Copy)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 19],
}

impl Default for Termios {
    fn default() -> Self {
        // Standard Linux cooked-tty defaults: CR→NL + flow control on input,
        // post-process + NL→CRNL on output, CS8, and the canonical local flags
        // (ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN).
        let mut cc = [0u8; 19];
        cc[0] = 0x03; // VINTR  = Ctrl-C
        cc[1] = 0x1c; // VQUIT  = Ctrl-\
        cc[2] = 0x7f; // VERASE = DEL
        cc[4] = 0x04; // VEOF   = Ctrl-D
        cc[6] = 0x01; // VMIN   = 1
        Self {
            iflag: 0x100 | 0x400 | 0x4000, // ICRNL | IXON | IUTF8
            oflag: 0x1 | 0x4,              // OPOST | ONLCR
            cflag: 0xbf,                   // B38400 | CS8 | CREAD | HUPCL-ish
            lflag: 0x8a3b,
            line: 0,
            cc,
        }
    }
}

/// A stored `rt_sigaction` disposition.
#[derive(Debug, Clone, Copy)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// The complete per-process kernel state — everything that a `fork` child gets
/// its own copy of and that a context switch must save/restore. The shared
/// resources a process *references* (pipe/socket buffers, the captured stdout,
/// the tty) live in [`LinuxKernel`] directly and are NOT duplicated here; only
/// the per-process *view* (the fd table, memory layout, cwd, signal state) is.
///
/// Produced by [`LinuxKernel::proc_snapshot`] (a clone of the live state) and
/// installed by [`LinuxKernel::proc_restore`] (a move). The synchronous `fork`
/// path holds one across a child's run; the scheduler stores one per process.
#[derive(Clone)]
pub struct ProcState {
    fds: BTreeMap<i32, Fd>,
    next_fd: i32,
    brk: u32,
    brk_mapped: u32,
    mmap_top: u32,
    file_maps: Vec<FileMapping>,
    cwd: String,
    umask: u32,
    /// Installed signal dispositions — per-process (each `execve` and `fork`
    /// gets its own; a child's `rt_sigaction` must not leak into the parent).
    sigactions: BTreeMap<i32, SigAction>,
    sig_mask: u64,
    pending_signal: Option<i32>,
    current_tid: i32,
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
        self.sockets.clear();
    }

    /// Clone the live per-process kernel state (fd table, memory layout, cwd,
    /// umask, signal dispositions/mask). Pipes, sockets and the captured output
    /// streams are shared, not copied. Pair with [`Self::proc_restore`] to roll
    /// the parent back after a synchronous child runs, or to seed a `fork`
    /// child's [`ProcState`].
    pub fn proc_snapshot(&self) -> ProcState {
        ProcState {
            fds: self.fds.clone(),
            next_fd: self.next_fd,
            brk: self.brk,
            brk_mapped: self.brk_mapped,
            mmap_top: self.mmap_top,
            file_maps: self.file_maps.clone(),
            cwd: self.cwd.clone(),
            umask: self.umask,
            sigactions: self.sigactions.clone(),
            sig_mask: self.sig_mask,
            pending_signal: self.pending_signal,
            current_tid: self.current_tid,
        }
    }

    /// Install a [`ProcState`] as the live per-process state (a move). Used to
    /// restore a parent after its child runs, and by the scheduler to switch in
    /// a process.
    pub fn proc_restore(&mut self, s: ProcState) {
        self.fds = s.fds;
        self.next_fd = s.next_fd;
        self.brk = s.brk;
        self.brk_mapped = s.brk_mapped;
        self.mmap_top = s.mmap_top;
        self.file_maps = s.file_maps;
        self.cwd = s.cwd;
        self.umask = s.umask;
        self.sigactions = s.sigactions;
        self.sig_mask = s.sig_mask;
        self.pending_signal = s.pending_signal;
        self.current_tid = s.current_tid;
    }

    /// Reset the memory layout for an `execve` that reuses this kernel: the new
    /// program gets a fresh brk and mmap arena and no inherited file mappings,
    /// but **keeps** the fd table and cwd (execve inherits them — shells set up
    /// redirections between fork and exec).
    pub fn exec_reset(&mut self, brk: u32) {
        self.brk = brk;
        self.brk_mapped = brk;
        self.mmap_top = MMAP_BASE;
        self.file_maps.clear();
    }

    /// Attach the background host-stdin reader (interactive KVM only) and seed
    /// it with the current tty ISIG/VINTR so it knows when Ctrl-C is a signal.
    pub fn attach_input(&mut self, input: std::sync::Arc<InteractiveInput>) {
        use std::sync::atomic::Ordering::SeqCst;
        input.isig.store(self.termios.lflag & 0x1 != 0, SeqCst);
        input.vintr.store(self.termios.cc[0], SeqCst);
        input.vquit.store(self.termios.cc[1], SeqCst);
        input.win_rows.store(self.term_size.0, SeqCst);
        input.win_cols.store(self.term_size.1, SeqCst);
        self.input = Some(input);
    }

    /// Mirror the guest tty's ISIG/VINTR/VQUIT into the background reader after a
    /// `TCSETS`, so it tracks whether Ctrl-C / Ctrl-\ raise a signal or are bytes.
    fn sync_input_termios(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        if let Some(input) = &self.input {
            input.isig.store(self.termios.lflag & 0x1 != 0, SeqCst);
            input.vintr.store(self.termios.cc[0], SeqCst);
            input.vquit.store(self.termios.cc[1], SeqCst);
        }
    }

    /// Consume a pending signal from either the synchronous line discipline
    /// (`pending_signal`, set while the guest was in a `read`) or the async
    /// background reader (`input.pending`, raised between instructions).
    pub fn take_pending_signal(&mut self) -> Option<i32> {
        if let Some(input) = &self.input {
            if let Some(sig) = input.take() {
                return Some(sig);
            }
        }
        self.pending_signal.take()
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
            Sysno::Mremap => self.sys_mremap(a0, a1, a2, a[3] as u32, mmu),
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
            // link(old, new) / linkat(olddir, old, newdir, new, flags): a hard
            // link. apk uses it for package files that are hardlink aliases.
            Sysno::Link => self.sys_linkat(AT_FDCWD, a0, AT_FDCWD, a1, mmu, vfs),
            Sysno::Linkat => self.sys_linkat(a0 as i32, a1, a2 as i32, a[3] as u32, mmu, vfs),
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
            Sysno::Poll => self.sys_poll(a0, a1, i64::from(a2 as i32), mmu),
            Sysno::Ppoll => {
                let tmo = self.poll_timeout_from_timespec(a2, mmu);
                self.sys_poll(a0, a1, tmo, mmu)
            }
            // select(nfds, r, w, e, timeval) — libfetch waits for socket
            // write-readiness here before sending its HTTP request.
            Sysno::Select => {
                let tmo = self.poll_timeout_from_timeval(a[4] as u32, mmu);
                self.sys_select(a0, a1, a2, a[3] as u32, tmo, mmu)
            }
            // pselect6(nfds, r, w, e, timespec, sigmask)
            Sysno::Pselect6 => {
                let tmo = self.poll_timeout_from_timespec(a[4] as u32, mmu);
                self.sys_select(a0, a1, a2, a[3] as u32, tmo, mmu)
            }
            // clone/futex are serviced by the amd64 thread scheduler; on the
            // single-threaded paths they degrade to "no threads".
            Sysno::Clone => ENOSYS,
            // access(path, mode) / faccessat(dirfd, path, mode, flags): we
            // don't enforce permissions, so "exists" == "accessible".
            Sysno::Access => self.sys_faccessat(AT_FDCWD, a0, mmu, vfs),
            Sysno::Faccessat => self.sys_faccessat(a0 as i32, a1, mmu, vfs),
            // rename(old, new) / renameat[2](olddirfd, old, newdirfd, new): apk
            // downloads each index to a temp file then renames it into place.
            // We don't model ownership, so chown/fchown/lchown/fchownat succeed.
            Sysno::Chown => 0,
            Sysno::Rename => self.sys_renameat(AT_FDCWD, a0, AT_FDCWD, a1, mmu, vfs),
            Sysno::Renameat | Sysno::Renameat2 => {
                self.sys_renameat(a0 as i32, a1, a2 as i32, a[3] as u32, mmu, vfs)
            }
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
            // fallocate(fd, mode, offset, len): preallocate ⇒ ensure the file is
            // at least offset+len long (apk reserves space before extracting).
            Sysno::Fallocate => self.sys_fallocate(a0 as i32, a[2], a[3], vfs),
            Sysno::CopyFileRange => self.sys_copy_file_range(
                a0 as i32,
                a1,
                a2 as i32,
                a[3] as u32,
                a[4] as u32,
                mmu,
                vfs,
            ),
            Sysno::Readv => self.sys_readv(a0 as i32, a1, a2, mmu, vfs),
            Sysno::Pipe | Sysno::Pipe2 => self.sys_pipe(a0, mmu),
            Sysno::Flock => 0, // single process: locks always succeed
            Sysno::Statfs | Sysno::Fstatfs => self.sys_statfs(a1, mmu),
            // ---- host-proxied network sockets (opt-in `--net`) ----
            Sysno::Socket => self.sys_socket(a0 as i32, a1 as i32),
            Sysno::Connect => self.sys_connect(a0 as i32, a1, a2, mmu),
            Sysno::Sendto => self.sys_sendto(a0 as i32, a1, a2, a[4] as u32, a[5] as u32, mmu),
            Sysno::Recvfrom => self.sys_recvfrom(a0 as i32, a1, a2, a[4] as u32, a[5] as u32, mmu),
            Sysno::Sendmsg => self.sys_sendmsg(a0 as i32, a1, mmu),
            Sysno::Recvmsg => self.sys_recvmsg(a0 as i32, a1, mmu),
            Sysno::Setsockopt => 0, // accept all socket options
            Sysno::Getsockopt => self.sys_getsockopt(a[3] as u32, a[4] as u32, mmu),
            Sysno::Getsockname | Sysno::Getpeername => self.sys_getsockname(a1, a2, mmu),
            Sysno::Shutdown => self.sys_shutdown(a0 as i32),
            Sysno::Bind => 0,        // accept (we don't model listening servers)
            Sysno::Listen => ENOSYS, // no inbound connections
            Sysno::Accept => ENOSYS,
            Sysno::Getcwd => self.sys_getcwd(a0, a1, mmu),
            Sysno::Ioctl => self.sys_ioctl(a0 as i32, a1, a2, mmu),
            Sysno::ArchPrctl => 0,
            Sysno::SetTidAddress => 1,
            Sysno::RtSigaction => self.sys_rt_sigaction(a0 as i32, a1, a2, mmu),
            Sysno::RtSigprocmask => self.sys_rt_sigprocmask(a0 as i32, a1, a2, mmu),
            // rt_sigreturn is completed by the KVM run loop (it needs the vCPU to
            // restore the saved context); here it's an unreachable no-op.
            Sysno::RtSigreturn => 0,
            Sysno::SetRobustList | Sysno::Ignored => 0,
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
                if self.interactive {
                    self.write_host(false, &data);
                } else {
                    self.stdout.extend_from_slice(&data);
                }
                data.len() as i64
            }
            Some(Fd::Stderr) => {
                if self.interactive {
                    self.write_host(true, &data);
                } else {
                    self.stderr.extend_from_slice(&data);
                }
                data.len() as i64
            }
            Some(Fd::Vfs { h, .. }) => vfs.write_handle(*h, &data).map_or(EBADF, |n| n as i64),
            Some(&Fd::PipeWrite(i)) => {
                self.pipes[i].extend(data.iter().copied());
                data.len() as i64
            }
            Some(&Fd::Socket(i)) => self.socket_send(i, &data),
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

    /// Parse a `struct msghdr` at `msg`, returning `(msg_name, msg_namelen,
    /// addr-of-msg_namelen, msg_iov, msg_iovlen)` at the guest's pointer width.
    fn read_msghdr(&self, mmu: &dyn GuestMem, msg: u32) -> Option<(u32, u32, u32, u32, u32)> {
        if self.ptr64 {
            let name = mmu.load64(msg).ok()? as u32;
            let namelen_addr = msg.wrapping_add(8);
            let namelen = mmu.load32(namelen_addr).ok()?;
            let iov = mmu.load64(msg.wrapping_add(16)).ok()? as u32;
            let iovlen = mmu.load64(msg.wrapping_add(24)).ok()? as u32;
            Some((name, namelen, namelen_addr, iov, iovlen))
        } else {
            let name = mmu.load32(msg).ok()?;
            let namelen_addr = msg.wrapping_add(4);
            let namelen = mmu.load32(namelen_addr).ok()?;
            let iov = mmu.load32(msg.wrapping_add(8)).ok()?;
            let iovlen = mmu.load32(msg.wrapping_add(12)).ok()?;
            Some((name, namelen, namelen_addr, iov, iovlen))
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

    /// Terminal `ioctl`s. In interactive mode, fd 0/1/2 are a real tty: report
    /// and accept termios, window size, and the common no-op requests so
    /// `isatty()` is true and shells configure the line discipline. Everything
    /// else (and any ioctl on a non-tty fd) stays `ENOTTY`.
    fn sys_ioctl(&mut self, fd: i32, req: u32, arg: u32, mmu: &mut dyn GuestMem) -> i64 {
        let is_std = matches!(self.fds.get(&fd), Some(Fd::Stdin | Fd::Stdout | Fd::Stderr));
        if !self.interactive || !is_std {
            return ENOTTY;
        }
        match req {
            0x5401 => {
                // TCGETS
                let t = self.termios;
                let mut b = [0u8; 36];
                b[0..4].copy_from_slice(&t.iflag.to_le_bytes());
                b[4..8].copy_from_slice(&t.oflag.to_le_bytes());
                b[8..12].copy_from_slice(&t.cflag.to_le_bytes());
                b[12..16].copy_from_slice(&t.lflag.to_le_bytes());
                b[16] = t.line;
                b[17..36].copy_from_slice(&t.cc);
                if write_mem(mmu, arg, &b).is_none() {
                    return EFAULT;
                }
                0
            }
            0x5402 | 0x5403 | 0x5404 => {
                // TCSETS / TCSETSW / TCSETSF
                let Some(b) = read_mem(mmu, arg, 36) else {
                    return EFAULT;
                };
                let rd = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
                self.termios.iflag = rd(0);
                self.termios.oflag = rd(4);
                self.termios.cflag = rd(8);
                self.termios.lflag = rd(12);
                self.termios.line = b[16];
                self.termios.cc.copy_from_slice(&b[17..36]);
                self.sync_input_termios();
                0
            }
            0x5413 => {
                // TIOCGWINSZ → struct winsize { ws_row, ws_col, ws_xpixel, ws_ypixel }
                // Prefer the live size the reader tracks across SIGWINCH.
                let (mut rows, mut cols) = self.input.as_ref().map_or(self.term_size, |i| {
                    use std::sync::atomic::Ordering::SeqCst;
                    (i.win_rows.load(SeqCst), i.win_cols.load(SeqCst))
                });
                if rows == 0 {
                    rows = 24;
                }
                if cols == 0 {
                    cols = 80;
                }
                let mut b = [0u8; 8];
                b[0..2].copy_from_slice(&rows.to_le_bytes());
                b[2..4].copy_from_slice(&cols.to_le_bytes());
                if write_mem(mmu, arg, &b).is_none() {
                    return EFAULT;
                }
                0
            }
            0x540f => {
                // TIOCGPGRP → report a stub foreground process group
                let _ = write_mem(mmu, arg, &1i32.to_le_bytes());
                0
            }
            0x541b => {
                // FIONREAD → bytes currently buffered for the guest
                let n = self.stdin_buf.len() as i32;
                let _ = write_mem(mmu, arg, &n.to_le_bytes());
                0
            }
            // TIOCSWINSZ, TIOCSPGRP, TCSBRK, TIOCSCTTY, TCFLSH, … → accept.
            0x5410 | 0x5414 | 0x5409 | 0x540b | 0x540e => 0,
            _ => 0, // other tty ioctls on a tty fd: accept rather than error
        }
    }

    /// `rt_sigaction`: store the disposition so the KVM signal path can deliver
    /// it (amd64 `struct kernel_sigaction`: handler, flags, restorer, mask — four
    /// 8-byte words). i386 isn't a signal-delivery target, so it stays a no-op.
    fn sys_rt_sigaction(&mut self, sig: i32, act: u32, oldact: u32, mmu: &mut dyn GuestMem) -> i64 {
        if !self.ptr64 {
            return 0;
        }
        if oldact != 0 {
            let prev = self.sigactions.get(&sig).copied().unwrap_or(SigAction {
                handler: 0,
                flags: 0,
                restorer: 0,
                mask: 0,
            });
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&prev.handler.to_le_bytes());
            b[8..16].copy_from_slice(&prev.flags.to_le_bytes());
            b[16..24].copy_from_slice(&prev.restorer.to_le_bytes());
            b[24..32].copy_from_slice(&prev.mask.to_le_bytes());
            let _ = write_mem(mmu, oldact, &b);
        }
        if act != 0 {
            let Some(b) = read_mem(mmu, act, 32) else {
                return EFAULT;
            };
            let rd = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            self.sigactions.insert(
                sig,
                SigAction {
                    handler: rd(0),
                    flags: rd(8),
                    restorer: rd(16),
                    mask: rd(24),
                },
            );
        }
        0
    }

    /// `rt_sigprocmask`: track the blocked-signal mask (a single 64-bit word for
    /// signals 1..64) so a signal frame can save/restore it.
    fn sys_rt_sigprocmask(
        &mut self,
        how: i32,
        set: u32,
        oldset: u32,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        if oldset != 0 {
            let _ = write_mem(mmu, oldset, &self.sig_mask.to_le_bytes());
        }
        if set != 0 {
            if let Some(b) = read_mem(mmu, set, 8) {
                let m = u64::from_le_bytes(b.try_into().unwrap());
                match how {
                    0 => self.sig_mask |= m,  // SIG_BLOCK
                    1 => self.sig_mask &= !m, // SIG_UNBLOCK
                    2 => self.sig_mask = m,   // SIG_SETMASK
                    _ => {}
                }
            }
        }
        0
    }

    /// The stored disposition for `sig` (`handler, flags, restorer, mask`), or
    /// `None` for the default (SIG_DFL). For the KVM signal path.
    pub fn signal_disposition(&self, sig: i32) -> Option<(u64, u64, u64, u64)> {
        self.sigactions
            .get(&sig)
            .map(|s| (s.handler, s.flags, s.restorer, s.mask))
    }

    /// Current blocked-signal mask; the KVM signal path saves it into a frame
    /// and restores it on `rt_sigreturn`.
    pub fn sig_mask(&self) -> u64 {
        self.sig_mask
    }

    /// Replace the blocked-signal mask (used by `rt_sigreturn`).
    pub fn set_sig_mask(&mut self, mask: u64) {
        self.sig_mask = mask;
    }

    /// Write guest output straight to the host terminal in interactive mode.
    /// Since the host tty is in raw mode, we perform the guest's `OPOST|ONLCR`
    /// translation (`\n` → `\r\n`) ourselves so lines don't stair-step.
    fn write_host(&self, is_err: bool, data: &[u8]) {
        use std::io::Write;
        let onlcr = self.termios.oflag & 0x1 != 0 && self.termios.oflag & 0x4 != 0;
        let buf: std::borrow::Cow<[u8]> = if onlcr && data.contains(&b'\n') {
            let mut v = Vec::with_capacity(data.len() + 8);
            for &b in data {
                if b == b'\n' {
                    v.push(b'\r');
                }
                v.push(b);
            }
            std::borrow::Cow::Owned(v)
        } else {
            std::borrow::Cow::Borrowed(data)
        };
        if is_err {
            let mut e = std::io::stderr().lock();
            let _ = e.write_all(&buf);
            let _ = e.flush();
        } else {
            let mut o = std::io::stdout().lock();
            let _ = o.write_all(&buf);
            let _ = o.flush();
        }
    }

    /// Interactive line discipline: read host stdin and turn it into bytes for
    /// the guest, honoring the guest `termios`. The host terminal is in raw mode
    /// (the CLI set it), so we do cooked-mode echo/editing here.
    ///
    /// Returns the bytes to deliver (empty = EOF), or `None` when Ctrl-C raised a
    /// pending SIGINT and the read should fail with `EINTR`.
    fn read_host_stdin(&mut self, max: usize) -> Option<Vec<u8>> {
        use std::io::{Read, Write};
        let cooked = self.termios.lflag & 0x2 != 0; // ICANON
        let echo = self.termios.lflag & 0x8 != 0; // ECHO
        let isig = self.termios.lflag & 0x1 != 0; // ISIG

        // Background-reader path: bytes arrive from the host-stdin thread, which
        // also intercepts VINTR (when ISIG) into an async SIGINT. The line
        // discipline (echo/editing) still runs here on the guest's behalf.
        if let Some(input) = self.input.clone() {
            let mut out = std::io::stdout().lock();
            if !cooked {
                // Raw: block for ≥1 byte, then drain whatever else is buffered.
                let first = match input.next_byte() {
                    InByte::Byte(b) => b,
                    InByte::Closed => return Some(Vec::new()),
                    InByte::Interrupted => return None,
                };
                let mut v = vec![first];
                while v.len() < max.max(1) {
                    match input.try_byte() {
                        Some(b) => v.push(b),
                        None => break,
                    }
                }
                return Some(v);
            }
            // Cooked: assemble one line with local echo + minimal editing.
            let mut line: Vec<u8> = Vec::new();
            loop {
                let b = match input.next_byte() {
                    InByte::Byte(b) => b,
                    InByte::Closed => return Some(line),
                    InByte::Interrupted => return None,
                };
                match b {
                    0x04 => return Some(line), // VEOF (Ctrl-D)
                    b'\r' | b'\n' => {
                        line.push(b'\n');
                        if echo {
                            let _ = out.write_all(b"\r\n");
                            let _ = out.flush();
                        }
                        return Some(line);
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() && echo {
                            let _ = out.write_all(b"\x08 \x08");
                            let _ = out.flush();
                        }
                    }
                    c => {
                        line.push(c);
                        if echo {
                            let _ = out.write_all(&[c]);
                            let _ = out.flush();
                        }
                        if line.len() >= max {
                            return Some(line);
                        }
                    }
                }
            }
        }

        // Fallback: read host stdin directly (no background reader attached).
        let mut stdin = std::io::stdin().lock();
        let mut out = std::io::stdout().lock();
        if !cooked {
            // Raw: hand over whatever bytes are available (blocking for ≥1).
            let mut tmp = vec![0u8; max.max(1)];
            let n = stdin.read(&mut tmp).unwrap_or(0);
            if isig && tmp[..n].contains(&0x03) {
                self.pending_signal = Some(2); // SIGINT
                return None;
            }
            return Some(tmp[..n].to_vec());
        }
        // Cooked: assemble one line with local echo + minimal editing.
        let mut line: Vec<u8> = Vec::new();
        loop {
            let mut b = [0u8; 1];
            match stdin.read(&mut b) {
                Ok(0) | Err(_) => return Some(line), // host EOF
                Ok(_) => {}
            }
            match b[0] {
                0x03 if isig => {
                    let _ = out.write_all(b"^C\r\n");
                    let _ = out.flush();
                    self.pending_signal = Some(2); // SIGINT
                    return None;
                }
                0x04 => {
                    // Ctrl-D: EOF on an empty line, else deliver what's typed.
                    return Some(line);
                }
                b'\r' | b'\n' => {
                    line.push(b'\n');
                    if echo {
                        let _ = out.write_all(b"\r\n");
                        let _ = out.flush();
                    }
                    return Some(line);
                }
                0x7f | 0x08 => {
                    if line.pop().is_some() && echo {
                        let _ = out.write_all(b"\x08 \x08");
                        let _ = out.flush();
                    }
                }
                c => {
                    line.push(c);
                    if echo {
                        let _ = out.write_all(&[c]);
                        let _ = out.flush();
                    }
                    if line.len() >= max {
                        return Some(line);
                    }
                }
            }
        }
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
            Some(Fd::Stdin) => {
                if !self.interactive {
                    return 0; // EOF — no stdin in batch mode
                }
                if self.stdin_buf.is_empty() {
                    match self.read_host_stdin(len as usize) {
                        None => return -4,                   // EINTR (a pending signal will follow)
                        Some(d) if d.is_empty() => return 0, // EOF
                        Some(d) => self.stdin_buf.extend(d),
                    }
                }
                let n = (len as usize).min(self.stdin_buf.len());
                let bytes: Vec<u8> = self.stdin_buf.drain(..n).collect();
                if write_mem(mmu, buf, &bytes).is_none() {
                    return EFAULT;
                }
                n as i64
            }
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
            Some(&Fd::Socket(i)) => {
                let mut tmp = vec![0u8; len as usize];
                let n = self.socket_recv(i, &mut tmp);
                if n < 0 {
                    return n;
                }
                if write_mem(mmu, buf, &tmp[..n as usize]).is_none() {
                    return EFAULT;
                }
                n
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

    /// `renameat`: the mount layer has no native rename, so move the file by
    /// copy + unlink. Same-mount only (the common case: temp → final in the
    /// ext4 root); good enough for apk's atomic-index install.
    fn sys_renameat(
        &mut self,
        olddirfd: i32,
        oldp: u32,
        newdirfd: i32,
        newp: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let (Some(old), Some(new)) = (
            self.resolve_at(olddirfd, oldp, mmu),
            self.resolve_at(newdirfd, newp, mmu),
        ) else {
            return EBADF;
        };
        if old == new {
            return 0;
        }
        // Prefer the backend's native rename: atomic and symlink-preserving.
        if vfs.rename_path(&old, &new).is_ok() {
            return 0;
        }
        // Fallback (cross-mount / no native rename): copy the bytes then unlink.
        // This can't preserve a symlink, but the native path covers same-mount
        // renames, which is where symlinks are involved.
        let Some(data) = vfs.read_file(&old) else {
            return -2; // ENOENT
        };
        let _ = vfs.truncate_path(&new, 0); // drop stale bytes if the target exists
        let Some(h) = vfs.open(&new, FileAccess::Write) else {
            return -13; // EACCES (read-only mount / bad path)
        };
        vfs.write_handle(h, &data);
        vfs.close(h);
        let _ = vfs.unlink_path(&old);
        0
    }

    /// `linkat`: create a hard link via the backend's native hardlink (shares
    /// the inode). Falls back to copying the file when that's unavailable
    /// (cross-mount / non-ext backend) — apk only needs both paths to exist
    /// with the same content.
    fn sys_linkat(
        &mut self,
        olddirfd: i32,
        oldp: u32,
        newdirfd: i32,
        newp: u32,
        mmu: &dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let (Some(old), Some(new)) = (
            self.resolve_at(olddirfd, oldp, mmu),
            self.resolve_at(newdirfd, newp, mmu),
        ) else {
            return EBADF;
        };
        if vfs.hardlink_path(&old, &new).is_ok() {
            return 0;
        }
        let Some(data) = vfs.read_file(&old) else {
            return -2; // ENOENT
        };
        let _ = vfs.truncate_path(&new, 0);
        let Some(h) = vfs.open(&new, FileAccess::Write) else {
            return -13; // EACCES
        };
        vfs.write_handle(h, &data);
        vfs.close(h);
        0
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
        // Follow symlinks to the final target (unless O_NOFOLLOW=0x20000), so the
        // opening e.g. `libz.so.1 -> libz.so.1.3.1` reads the real file rather
        // than the link's target string.
        let p = if flags & 0x2_0000 == 0 {
            vfs.resolve_symlinks(&p)
        } else {
            p
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
            Some(Fd::Socket(i)) => {
                // Drop the host socket (close the connection).
                self.sockets[i] = SocketState::Closed;
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
            // Newly-grown heap must read as zero (Linux guarantees it). On a
            // fresh address space the pages already are, but after an `execve`
            // over dirty memory they hold stale bytes, so zero them explicitly.
            mmu.map_zeroed(
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
            // Anonymous: fresh zero pages (RWX so JIT/stack/heap all work).
            // Zeroing matters when MAP_FIXED overlays a previously file-backed
            // region — e.g. the dynamic linker zeroing a segment's `.bss` tail.
            mmu.map_zeroed(base, size, Perm::R | Perm::W | Perm::X);
            return i64::from(base);
        }

        // File-backed: populate the region from the fd's file, then enforce
        // the requested protection.
        let path = match self.fds.get(&fd) {
            Some(Fd::Vfs { path, .. }) => path.clone(),
            _ => return EBADF,
        };
        // Zero the region first, then overlay the file bytes: a segment with
        // memsz > filesz (a shared library's `.bss` tail) must read as zero. On
        // a fresh address space the pages are already zero, but after an
        // `execve` reuses dirty memory they hold stale bytes — which corrupts
        // zero-initialized globals (e.g. libpython) and crashes the program.
        mmu.map_zeroed(base, size, Perm::R | Perm::W);
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

    /// `mremap(old, old_size, new_size, flags, new_addr)`. In the flat-memory
    /// model a shrink keeps the base (surplus pages stay mapped, harmless); a
    /// grow extends in place when the region is the top of the arena, otherwise
    /// (with `MREMAP_MAYMOVE`) allocates a fresh region and copies the contents.
    fn sys_mremap(
        &mut self,
        old_addr: u32,
        old_size: u32,
        new_size: u32,
        flags: u32,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        const MREMAP_MAYMOVE: u32 = 1;
        let rwx = Perm::R | Perm::W | Perm::X;
        let old_sz = page_up(old_size.max(1));
        let new_sz = page_up(new_size.max(1));
        if new_sz <= old_sz {
            return i64::from(old_addr);
        }
        let extra = new_sz - old_sz;
        // Grow in place if this mapping ends exactly at the arena top.
        if old_addr.wrapping_add(old_sz) == self.mmap_top
            && self
                .mmap_top
                .checked_add(extra)
                .is_some_and(|e| e <= MMAP_LIMIT)
        {
            mmu.map_zeroed(self.mmap_top, extra, rwx);
            self.mmap_top = self.mmap_top.wrapping_add(extra);
            return i64::from(old_addr);
        }
        if flags & MREMAP_MAYMOVE == 0 {
            return -12; // ENOMEM — can't grow in place, caller forbade moving
        }
        let base = self.mmap_top;
        if base.checked_add(new_sz).is_none_or(|e| e > MMAP_LIMIT) {
            return -12;
        }
        self.mmap_top = base.wrapping_add(new_sz);
        mmu.map_zeroed(base, new_sz, rwx);
        // Copy the live bytes; the tail past `old_size` stays zero.
        if let Some(data) = read_mem(mmu, old_addr, old_size as usize) {
            let _ = write_mem(mmu, base, &data);
        }
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
        // Resolve the subject + destination buffer. `perm` is the file's real
        // permission bits; `ino` is a stable per-path inode (the dynamic linker
        // dedups libraries by inode, so distinct files must differ).
        let (kind, size, perm, ino, buf) = match sys {
            Sysno::Fstat => {
                let fd = a[0] as i32;
                let buf = a[1] as u32;
                match self.fds.get(&fd) {
                    // A char-device stat for the std streams + pipes keeps
                    // isatty()/libc buffering happy.
                    Some(
                        Fd::Stdin
                        | Fd::Stdout
                        | Fd::Stderr
                        | Fd::PipeRead(_)
                        | Fd::PipeWrite(_)
                        | Fd::Socket(_),
                    ) => (NodeKind::CharDevice, 0, 0o666, u64::from(fd as u32), buf),
                    Some(Fd::Vfs { path, .. } | Fd::Dir { path, .. }) => {
                        let path = path.clone();
                        let att = vfs.stat_path(&path);
                        (
                            att.map_or(NodeKind::File, |x| x.kind),
                            att.map_or(0, |x| x.size),
                            att.map_or(0, |x| x.mode),
                            inode_of(att, &path),
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
                // does not. Inode keys on the resolved (followed) path so a link
                // and its target share an inode, as on a real FS.
                let target = if nofollow {
                    p.clone()
                } else {
                    vfs.resolve_symlinks(&p)
                };
                let att = vfs.stat_path(&target);
                match att {
                    Some(att) => (
                        att.kind,
                        att.size,
                        att.mode,
                        inode_of(Some(att), &target),
                        buf,
                    ),
                    None => return ENOENT,
                }
            }
        };
        self.write_stat(buf, kind, size, perm, ino, layout, mmu)
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
        let target = if flags & 0x100 != 0 {
            p.clone()
        } else {
            vfs.resolve_symlinks(&p)
        };
        let Some(att) = vfs.stat_path(&target) else {
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
        b[32..40].copy_from_slice(&inode_of(Some(att), &target).to_le_bytes()); // stx_ino
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
    #[allow(clippy::too_many_arguments)]
    fn write_stat(
        &self,
        buf: u32,
        kind: NodeKind,
        size: u64,
        perm: u32,
        ino: u64,
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
        put64(&mut b, layout.dev_off, 1); // st_dev: a single synthetic device
        put64(&mut b, layout.ino_off, ino);
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
    fn sys_fcntl(&mut self, fd: i32, cmd: u32, arg: u32) -> i64 {
        // O_NONBLOCK is 0o4000 = 0x800 on every Linux/x86 ABI we run.
        const O_NONBLOCK: u32 = 0x800;
        let sock_idx = match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => Some(i),
            Some(_) => None,
            None => return EBADF,
        };
        match cmd {
            0 | 1030 => self.sys_dup(fd), // F_DUPFD / F_DUPFD_CLOEXEC
            1 => 0,                       // F_GETFD → no descriptor flags
            3 => {
                // F_GETFL: report O_RDWR plus real O_NONBLOCK for sockets so the
                // caller's "is this non-blocking?" bookkeeping stays consistent.
                match sock_idx {
                    Some(i) if self.sock_nonblock[i] => 2 | i64::from(O_NONBLOCK),
                    Some(_) => 2, // O_RDWR
                    None => 0,
                }
            }
            2 => 0, // F_SETFD → accept
            4 => {
                // F_SETFL: honor O_NONBLOCK toggles on sockets (libfetch clears
                // it before the blocking request/response transfer).
                if let Some(i) = sock_idx {
                    let nb = arg & O_NONBLOCK != 0;
                    self.sock_nonblock[i] = nb;
                    if let SocketState::Tcp(s) = &self.sockets[i] {
                        let _ = s.set_nonblocking(nb);
                    }
                }
                0
            }
            _ => 0, // other commands: accept
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

    // ---- host-proxied sockets -------------------------------------------

    fn sys_socket(&mut self, domain: i32, ty: i32) -> i64 {
        if !self.net_enabled {
            return -13; // EACCES — networking is opt-in (`--net`)
        }
        // AF_INET=2, AF_INET6=10. SOCK_STREAM=1, SOCK_DGRAM=2 (low bits; the
        // upper bits carry SOCK_NONBLOCK=0x800 / SOCK_CLOEXEC=0x80000).
        if domain != 2 && domain != 10 {
            return -97; // EAFNOSUPPORT
        }
        let idx = self.sockets.len();
        self.sockets.push(SocketState::Pending { ty: ty & 0xff });
        self.sock_nonblock.push(ty & 0x800 != 0);
        i64::from(self.install_fd(Fd::Socket(idx)))
    }

    fn sys_connect(&mut self, fd: i32, addr: u32, len: u32, mmu: &dyn GuestMem) -> i64 {
        let idx = match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => i,
            _ => return EBADF,
        };
        let Some(sa) = read_sockaddr(mmu, addr, len) else {
            return EINVAL;
        };
        let ty = match &self.sockets[idx] {
            SocketState::Pending { ty, .. } => *ty,
            _ => return -56, // EISCONN
        };
        if ty == 2 {
            // UDP: bind an ephemeral local socket and remember the peer.
            match std::net::UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect(sa).map(|()| s)) {
                Ok(s) => {
                    self.sockets[idx] = SocketState::Udp(s);
                    0
                }
                Err(_) => -111, // ECONNREFUSED
            }
        } else {
            // TCP: we connect synchronously (blocking) under the hood, but a
            // guest that opened the socket `SOCK_NONBLOCK` expects `connect` to
            // return EINPROGRESS and then drive POLLOUT → getsockopt(SO_ERROR)
            // → write. Honor that: complete the connect, mark the host stream
            // non-blocking, and report EINPROGRESS so the fetch state machine
            // proceeds to send its request.
            match std::net::TcpStream::connect(sa) {
                Ok(s) => {
                    let nb = self.sock_nonblock[idx];
                    let _ = s.set_nonblocking(nb);
                    self.sockets[idx] = SocketState::Tcp(s);
                    if nb {
                        -115 // EINPROGRESS
                    } else {
                        0
                    }
                }
                Err(_) => -111,
            }
        }
    }

    /// Send `data` over a connected socket. Returns bytes sent or `-errno`
    /// (EAGAIN when the socket is non-blocking and the send buffer is full).
    fn socket_send(&mut self, idx: usize, data: &[u8]) -> i64 {
        use std::io::Write;
        match &mut self.sockets[idx] {
            SocketState::Tcp(s) => s.write(data).map_or_else(io_errno, |n| n as i64),
            SocketState::Udp(s) => s.send(data).map_or_else(io_errno, |n| n as i64),
            _ => -107, // ENOTCONN
        }
    }

    /// Receive into `buf` from a connected socket. Returns bytes (0 at EOF) or
    /// `-errno` (EAGAIN when non-blocking and no data is queued).
    fn socket_recv(&mut self, idx: usize, buf: &mut [u8]) -> i64 {
        use std::io::Read;
        match &mut self.sockets[idx] {
            SocketState::Tcp(s) => s.read(buf).map_or_else(io_errno, |n| n as i64),
            SocketState::Udp(s) => s.recv(buf).map_or_else(io_errno, |n| n as i64),
            _ => -107,
        }
    }

    /// Real `POLLIN` readiness of a socket via a non-blocking `MSG_PEEK`.
    /// Returns `(readable, hung_up)` and always restores blocking mode so the
    /// subsequent `read` blocks normally. `readable` is true when data is
    /// queued or the peer has closed (so the caller's `read` returns 0/EOF).
    fn socket_pollin(&self, idx: usize) -> (bool, bool) {
        use std::io::ErrorKind::WouldBlock;
        let restore = self.sock_nonblock[idx]; // leave the socket as the guest set it
        let mut probe = [0u8; 1];
        match &self.sockets[idx] {
            SocketState::Tcp(s) => {
                let _ = s.set_nonblocking(true);
                let r = s.peek(&mut probe);
                let _ = s.set_nonblocking(restore);
                match r {
                    Ok(0) => (true, true),  // peer closed: readable + HUP
                    Ok(_) => (true, false), // data queued
                    Err(e) if e.kind() == WouldBlock => (false, false),
                    Err(_) => (true, true), // error: let read surface it
                }
            }
            SocketState::Udp(s) => {
                let _ = s.set_nonblocking(true);
                let r = s.peek_from(&mut probe);
                let _ = s.set_nonblocking(restore);
                match r {
                    Ok(_) => (true, false),
                    Err(e) if e.kind() == WouldBlock => (false, false),
                    Err(_) => (true, true),
                }
            }
            _ => (false, false),
        }
    }

    fn sys_sendto(
        &mut self,
        fd: i32,
        buf: u32,
        len: u32,
        dest: u32,
        destlen: u32,
        mmu: &dyn GuestMem,
    ) -> i64 {
        let idx = match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => i,
            _ => return EBADF,
        };
        let Some(data) = read_mem(mmu, buf, len as usize) else {
            return EFAULT;
        };
        // sendto with an explicit destination: bind a UDP socket lazily (apk's
        // DNS sends without a prior connect) and send the datagram.
        if dest != 0 && destlen != 0 {
            let Some(sa) = read_sockaddr(mmu, dest, destlen) else {
                return EINVAL;
            };
            if matches!(self.sockets[idx], SocketState::Pending { ty: 2, .. }) {
                match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => self.sockets[idx] = SocketState::Udp(s),
                    Err(_) => return -111,
                }
            }
            if let SocketState::Udp(s) = &self.sockets[idx] {
                return s.send_to(&data, sa).map_or(-111, |n| n as i64);
            }
        }
        self.socket_send(idx, &data)
    }

    /// `sendmsg`/`recvmsg`: handle the common single-buffer datagram shape by
    /// extracting `msg_name` (peer) + the first iovec and routing to
    /// `sendto`/`recvfrom`. (musl's DNS resolver uses these.)
    fn sys_sendmsg(&mut self, fd: i32, msg: u32, mmu: &mut dyn GuestMem) -> i64 {
        let Some((name, namelen, _, iov, iovlen)) = self.read_msghdr(mmu, msg) else {
            return EFAULT;
        };
        // Sum the iovecs into one datagram.
        let mut data = Vec::new();
        for i in 0..iovlen {
            if let Some((p, l)) = self.read_iovec(iov, i, mmu) {
                if let Some(chunk) = read_mem(mmu, p, l as usize) {
                    data.extend_from_slice(&chunk);
                }
            }
        }
        // Stage the datagram in guest-independent form, then reuse sys_sendto by
        // writing nothing — instead send directly.
        let idx = match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => i,
            _ => return EBADF,
        };
        if name != 0 && namelen != 0 {
            if let Some(sa) = read_sockaddr(mmu, name, namelen) {
                if matches!(self.sockets[idx], SocketState::Pending { ty: 2, .. }) {
                    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
                        self.sockets[idx] = SocketState::Udp(s);
                    }
                }
                if let SocketState::Udp(s) = &self.sockets[idx] {
                    return s.send_to(&data, sa).map_or(-111, |n| n as i64);
                }
            }
        }
        self.socket_send(idx, &data)
    }

    fn sys_recvmsg(&mut self, fd: i32, msg: u32, mmu: &mut dyn GuestMem) -> i64 {
        let Some((name, _, namelen_ptr, iov, _iovlen)) = self.read_msghdr(mmu, msg) else {
            return EFAULT;
        };
        let idx = match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => i,
            _ => return EBADF,
        };
        // Receive into the first iovec (datagrams fit one buffer in practice).
        let Some((ptr, cap)) = self.read_iovec(iov, 0, mmu) else {
            return EFAULT;
        };
        let mut tmp = vec![0u8; cap as usize];
        let n = if let SocketState::Udp(s) = &self.sockets[idx] {
            match s.recv_from(&mut tmp) {
                Ok((n, peer)) => {
                    if name != 0 {
                        write_sockaddr(mmu, name, namelen_ptr, peer);
                    }
                    n as i64
                }
                Err(_) => -111,
            }
        } else {
            self.socket_recv(idx, &mut tmp)
        };
        if n < 0 {
            return n;
        }
        if write_mem(mmu, ptr, &tmp[..n as usize]).is_none() {
            return EFAULT;
        }
        n
    }

    fn sys_recvfrom(
        &mut self,
        fd: i32,
        buf: u32,
        len: u32,
        src: u32,
        srclen: u32,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        let idx = match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => i,
            _ => return EBADF,
        };
        let mut tmp = vec![0u8; len as usize];
        // recvfrom on an unconnected UDP socket returns the peer in `src`.
        let n = if let SocketState::Udp(s) = &self.sockets[idx] {
            match s.recv_from(&mut tmp) {
                Ok((n, peer)) => {
                    if src != 0 && srclen != 0 {
                        write_sockaddr(mmu, src, srclen, peer);
                    }
                    n as i64
                }
                Err(_) => -111,
            }
        } else {
            self.socket_recv(idx, &mut tmp)
        };
        if n < 0 {
            return n;
        }
        if write_mem(mmu, buf, &tmp[..n as usize]).is_none() {
            return EFAULT;
        }
        n
    }

    fn sys_getsockopt(&self, optval: u32, optlen: u32, mmu: &mut dyn GuestMem) -> i64 {
        // Report success/no-error for the common SO_ERROR probe after connect.
        if optval != 0 && optlen != 0 {
            let _ = write_mem(mmu, optval, &0u32.to_le_bytes());
        }
        0
    }

    fn sys_getsockname(&self, addr: u32, addrlen: u32, mmu: &mut dyn GuestMem) -> i64 {
        // A minimal AF_INET sockaddr (0.0.0.0:0) — enough for callers that just
        // read the family.
        if addr != 0 && addrlen != 0 {
            let mut sa = [0u8; 16];
            sa[0] = 2; // AF_INET (little-endian sa_family low byte)
            let _ = write_mem(mmu, addr, &sa);
            let _ = write_mem(mmu, addrlen, &16u32.to_le_bytes());
        }
        0
    }

    fn sys_shutdown(&mut self, fd: i32) -> i64 {
        match self.fds.get(&fd) {
            Some(&Fd::Socket(i)) => {
                if let SocketState::Tcp(s) = &self.sockets[i] {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
                0
            }
            _ => EBADF,
        }
    }

    /// `statfs`/`fstatfs`: report a large, mostly-free filesystem so callers
    /// (e.g. apk's free-space check) proceed.
    fn sys_statfs(&self, buf: u32, mmu: &mut dyn GuestMem) -> i64 {
        // struct statfs is arch-specific but the leading fields line up enough:
        // f_type(8) f_bsize(8) f_blocks(8) f_bfree(8) f_bavail(8) f_files(8)
        // f_ffree(8) f_fsid(8) f_namelen(8) f_frsize(8) ...
        let mut b = [0u8; 120];
        let put =
            |b: &mut [u8], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put(&mut b, 0, 0xEF53); // f_type = EXT4_SUPER_MAGIC
        put(&mut b, 8, 4096); // f_bsize
        put(&mut b, 16, 1 << 20); // f_blocks (4 GiB)
        put(&mut b, 24, 1 << 19); // f_bfree
        put(&mut b, 32, 1 << 19); // f_bavail
        put(&mut b, 40, 1 << 18); // f_files
        put(&mut b, 48, 1 << 17); // f_ffree
        put(&mut b, 64, 255); // f_namelen
        put(&mut b, 72, 4096); // f_frsize
        if write_mem(mmu, buf, &b).is_none() {
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
    /// `ppoll` carries its timeout as a `struct timespec *`; a null pointer
    /// means "wait forever" (we return -1). Reads the two longs at pointer
    /// width and collapses them to whole milliseconds for [`sys_poll`].
    fn poll_timeout_from_timespec(&self, ts: u32, mmu: &dyn GuestMem) -> i64 {
        if ts == 0 {
            return -1;
        }
        let (sec, nsec) = if self.ptr64 {
            (
                mmu.load64(ts).unwrap_or(0),
                mmu.load64(ts.wrapping_add(8)).unwrap_or(0),
            )
        } else {
            (
                u64::from(mmu.load32(ts).unwrap_or(0)),
                u64::from(mmu.load32(ts.wrapping_add(4)).unwrap_or(0)),
            )
        };
        (sec.saturating_mul(1000) + nsec / 1_000_000) as i64
    }

    /// `select` carries its timeout as a `struct timeval *` (seconds +
    /// microseconds); a null pointer means "wait forever" (-1).
    fn poll_timeout_from_timeval(&self, tv: u32, mmu: &dyn GuestMem) -> i64 {
        if tv == 0 {
            return -1;
        }
        let (sec, usec) = if self.ptr64 {
            (
                mmu.load64(tv).unwrap_or(0),
                mmu.load64(tv.wrapping_add(8)).unwrap_or(0),
            )
        } else {
            (
                u64::from(mmu.load32(tv).unwrap_or(0)),
                u64::from(mmu.load32(tv.wrapping_add(4)).unwrap_or(0)),
            )
        };
        (sec.saturating_mul(1000) + usec / 1000) as i64
    }

    /// Per-fd readiness for `select`: sockets report real readability (peek)
    /// and connected-writability; everything else is always ready.
    fn select_ready(&self, fd: i32, want_r: bool, want_w: bool) -> (bool, bool) {
        match self.fds.get(&fd) {
            Some(&Fd::Socket(idx)) => {
                let w = want_w
                    && matches!(self.sockets[idx], SocketState::Tcp(_) | SocketState::Udp(_));
                let r = want_r && self.socket_pollin(idx).0;
                (r, w)
            }
            Some(_) => (want_r, want_w), // files/pipes/std streams: always ready
            None => (false, false),
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn sys_select(
        &self,
        nfds: u32,
        readfds: u32,
        writefds: u32,
        exceptfds: u32,
        timeout_ms: i64,
        mmu: &mut dyn GuestMem,
    ) -> i64 {
        let nfds = nfds.min(1024);
        let word_bytes: u32 = if self.ptr64 { 8 } else { 4 };
        let start = std::time::Instant::now();
        let deadline_ms: u128 = if timeout_ms < 0 {
            120_000
        } else {
            timeout_ms as u128
        };
        loop {
            let mut ready_r: Vec<u32> = Vec::new();
            let mut ready_w: Vec<u32> = Vec::new();
            let mut count = 0i64;
            for fd in 0..nfds {
                let want_r = readfds != 0 && fdset_test(mmu, readfds, fd, word_bytes);
                let want_w = writefds != 0 && fdset_test(mmu, writefds, fd, word_bytes);
                if !want_r && !want_w {
                    continue;
                }
                let (rok, wok) = self.select_ready(fd as i32, want_r, want_w);
                if rok {
                    ready_r.push(fd);
                    count += 1;
                }
                if wok {
                    ready_w.push(fd);
                    count += 1;
                }
            }
            if count > 0 || timeout_ms == 0 || start.elapsed().as_millis() >= deadline_ms {
                if readfds != 0 {
                    fdset_write(mmu, readfds, nfds, &ready_r, word_bytes);
                }
                if writefds != 0 {
                    fdset_write(mmu, writefds, nfds, &ready_w, word_bytes);
                }
                if exceptfds != 0 {
                    fdset_write(mmu, exceptfds, nfds, &[], word_bytes); // no exceptions
                }
                return count;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    fn sys_poll(&self, fds: u32, nfds: u32, timeout_ms: i64, mmu: &mut dyn GuestMem) -> i64 {
        // struct pollfd { int fd; short events; short revents; } — 8 bytes.
        const POLLIN: u16 = 0x001;
        const POLLOUT: u16 = 0x004;
        const POLLHUP: u16 = 0x010;
        const POLLNVAL: u16 = 0x020;
        // Files/pipes/std streams are always ready; sockets report *real*
        // readiness (peek for POLLIN, connected ⇒ writable) so a client that
        // polls before writing isn't told to read an empty socket. Block until
        // an fd is ready or the timeout elapses; a negative timeout means wait
        // forever, which we cap so a wedged guest can't hang the host.
        let start = std::time::Instant::now();
        let deadline_ms: u128 = if timeout_ms < 0 {
            120_000
        } else {
            timeout_ms as u128
        };
        loop {
            let mut ready = 0i64;
            for i in 0..nfds {
                let base = fds.wrapping_add(i.wrapping_mul(8));
                let (Ok(fd_raw), Ok(events)) = (mmu.load32(base), mmu.load16(base.wrapping_add(4)))
                else {
                    return EFAULT;
                };
                let fd = fd_raw as i32;
                let mut revents = 0u16;
                match self.fds.get(&fd) {
                    Some(&Fd::Socket(idx)) => {
                        if events & POLLOUT != 0
                            && matches!(
                                self.sockets[idx],
                                SocketState::Tcp(_) | SocketState::Udp(_)
                            )
                        {
                            revents |= POLLOUT;
                        }
                        if events & POLLIN != 0 {
                            let (readable, hup) = self.socket_pollin(idx);
                            if readable {
                                revents |= POLLIN;
                            }
                            if hup {
                                revents |= POLLHUP;
                            }
                        }
                    }
                    Some(_) => revents = events, // files/pipes/std: always ready
                    None => revents = POLLNVAL,
                }
                if write_mem(mmu, base.wrapping_add(6), &revents.to_le_bytes()).is_none() {
                    return EFAULT;
                }
                if revents != 0 {
                    ready += 1;
                }
            }
            if ready > 0 || timeout_ms == 0 {
                return ready;
            }
            if start.elapsed().as_millis() >= deadline_ms {
                return 0;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
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

    /// `fallocate(fd, mode, offset, len)`: in the grow-on-write model there's
    /// no real preallocation, so just ensure the file is at least `offset+len`
    /// long and report success. apk reserves space before extracting a file.
    fn sys_fallocate(&mut self, fd: i32, offset: u64, len: u64, vfs: &mut MountTable) -> i64 {
        let path = match self.fds.get(&fd) {
            Some(Fd::Vfs { path, .. }) => path.clone(),
            Some(Fd::Dir { .. }) => return EISDIR,
            _ => return EBADF,
        };
        let want = offset.saturating_add(len);
        let cur = vfs.stat_path(&path).map_or(0, |a| a.size);
        if want > cur {
            let _ = vfs.truncate_path(&path, want);
        }
        0
    }

    /// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)`: copy bytes
    /// between two open files. NULL offset pointers use (and advance) each fd's
    /// own position; non-NULL ones are read/written in guest memory (`loff_t`).
    fn sys_copy_file_range(
        &mut self,
        fd_in: i32,
        off_in: u32,
        fd_out: i32,
        off_out: u32,
        len: u32,
        mmu: &mut dyn GuestMem,
        vfs: &mut MountTable,
    ) -> i64 {
        let (in_h, in_path) = match self.fds.get(&fd_in) {
            Some(Fd::Vfs { h, path }) => (*h, path.clone()),
            _ => return EBADF,
        };
        let (out_h, out_path) = match self.fds.get(&fd_out) {
            Some(Fd::Vfs { h, path }) => (*h, path.clone()),
            _ => return EBADF,
        };
        let len = (len as usize).min(64 << 20); // cap a single call at 64 MiB

        // Read the source bytes (explicit offset or the fd's position).
        let data = if off_in == 0 {
            let mut buf = vec![0u8; len];
            let n = vfs.read_handle(in_h, &mut buf).unwrap_or(0);
            buf.truncate(n);
            buf
        } else {
            let off = mmu.load64(off_in).unwrap_or(0);
            let d = read_file_region(vfs, &in_path, off, len);
            let _ = mmu.store64(off_in, off + d.len() as u64);
            d
        };
        if data.is_empty() {
            return 0;
        }

        // Write to the destination (explicit offset or the fd's position).
        let n = if off_out == 0 {
            vfs.write_handle(out_h, &data).unwrap_or(0)
        } else if let Some(h) = vfs.open(&out_path, FileAccess::ReadWrite) {
            let off = mmu.load64(off_out).unwrap_or(0);
            vfs.seek(h, off);
            let w = vfs.write_handle(h, &data).unwrap_or(0);
            vfs.close(h);
            let _ = mmu.store64(off_out, off + w as u64);
            w
        } else {
            return EBADF;
        };
        n as i64
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

/// Test bit `fd` in a guest `fd_set` (an array of `long`s at `set`).
fn fdset_test(mmu: &dyn GuestMem, set: u32, fd: u32, word_bytes: u32) -> bool {
    let bits = word_bytes * 8;
    let waddr = set.wrapping_add((fd / bits) * word_bytes);
    let word = if word_bytes == 8 {
        mmu.load64(waddr).unwrap_or(0)
    } else {
        u64::from(mmu.load32(waddr).unwrap_or(0))
    };
    word & (1u64 << (fd % bits)) != 0
}

/// Overwrite a guest `fd_set` so exactly the fds in `ready` are set, covering
/// `nfds` descriptors (the kernel rewrites the caller's sets in place).
fn fdset_write(mmu: &mut dyn GuestMem, set: u32, nfds: u32, ready: &[u32], word_bytes: u32) {
    let bits = word_bytes * 8;
    let nwords = nfds.div_ceil(bits);
    let mut words = vec![0u64; nwords as usize];
    for &fd in ready {
        words[(fd / bits) as usize] |= 1u64 << (fd % bits);
    }
    for (i, w) in words.iter().enumerate() {
        let waddr = set.wrapping_add(i as u32 * word_bytes);
        let _ = write_mem(mmu, waddr, &w.to_le_bytes()[..word_bytes as usize]);
    }
}

/// Map a host socket I/O error to a guest `-errno`. `WouldBlock` becomes
/// EAGAIN so a non-blocking guest retries rather than treating it as fatal.
fn io_errno(e: std::io::Error) -> i64 {
    use std::io::ErrorKind::{BrokenPipe, ConnectionReset, WouldBlock};
    match e.kind() {
        WouldBlock => -11,       // EAGAIN
        BrokenPipe => -32,       // EPIPE
        ConnectionReset => -104, // ECONNRESET
        _ => -111,               // ECONNREFUSED / generic
    }
}

/// Parse a guest `sockaddr` (`AF_INET` / `AF_INET6`) into a host
/// [`std::net::SocketAddr`]. Port and address are network byte order.
fn read_sockaddr(mmu: &dyn GuestMem, addr: u32, len: u32) -> Option<std::net::SocketAddr> {
    let buf = read_mem(mmu, addr, (len as usize).clamp(8, 28))?;
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    match family {
        2 => {
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Some(std::net::SocketAddr::new(ip.into(), port))
        }
        10 if buf.len() >= 24 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[8..24]);
            Some(std::net::SocketAddr::new(
                std::net::Ipv6Addr::from(o).into(),
                port,
            ))
        }
        _ => None,
    }
}

/// Write a host [`std::net::SocketAddr`] back into a guest `sockaddr` plus its
/// length (for `recvfrom`'s source-address out-param).
fn write_sockaddr(mmu: &mut dyn GuestMem, addr: u32, addrlen_ptr: u32, peer: std::net::SocketAddr) {
    let mut buf = vec![0u8; if peer.is_ipv6() { 28 } else { 16 }];
    buf[2..4].copy_from_slice(&peer.port().to_be_bytes());
    match peer {
        std::net::SocketAddr::V4(a) => {
            buf[0] = 2;
            buf[4..8].copy_from_slice(&a.ip().octets());
        }
        std::net::SocketAddr::V6(a) => {
            buf[0] = 10;
            buf[8..24].copy_from_slice(&a.ip().octets());
        }
    }
    let _ = write_mem(mmu, addr, &buf);
    let _ = write_mem(mmu, addrlen_ptr, &(buf.len() as u32).to_le_bytes());
}

/// A stable, non-zero inode number for a path. The dynamic linker dedups
/// libraries by `(st_dev, st_ino)`, so distinct files must report distinct
/// inodes (returning 0 for everything aliases all `.so`s into one and drops
/// their symbols). Keyed on the resolved path so a symlink and its target
/// share an inode, as on a real filesystem.
fn path_inode(path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    h.finish() | 1 // never zero
}

/// The real filesystem inode if the backend reported one, else a stable hash
/// of the path (synthetic `/proc`/`/dev` and the in-memory root report 0).
fn inode_of(att: Option<crate::fsmount::Attrs>, path: &str) -> u64 {
    match att {
        Some(a) if a.inode != 0 => a.inode,
        _ => path_inode(path),
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

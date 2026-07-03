//! Opt-in **KVM acceleration** for the amd64 Linux personality.
//!
//! Instead of the software interpreter decoding each instruction, the guest's
//! x86-64 code runs *natively* inside a hardware VM (`/dev/kvm`), and the same
//! [`LinuxKernel`](super::LinuxKernel) services its syscalls. Only the
//! execution backend changes — the kernel, loader, and VFS are reused verbatim
//! through the [`GuestMem`](super::mem::GuestMem) / [`GuestCpu`](super::guest::GuestCpu)
//! traits.
//!
//! ## How a syscall is trapped
//!
//! There is no guest kernel. We enable `SYSCALL` (`EFER.SCE`) but point
//! `LSTAR` at a 4-byte trampoline we write into guest memory: `hlt ; sysretq`.
//! A userspace `syscall` enters the trampoline at CPL 0, the `hlt` causes a
//! `KVM_EXIT_HLT`, we read the guest registers, run the syscall, write the
//! return value, and resume — the trampoline's `sysretq` returns to userspace
//! right after the original `syscall`.
//!
//! ## Memory
//!
//! One flat 4 GiB guest-physical region, identity-mapped to guest-virtual with
//! 2 MiB pages (everything the personality uses — non-PIE text at `0x400000`,
//! the stack under `0xC000_0000`, the mmap arena at `0x4000_0000` — fits the
//! low 4 GiB). The host backs it lazily (anonymous `MAP_NORESERVE`).
//!
//! Availability: Linux host, x86-64, `/dev/kvm` accessible. The runner returns
//! an `Err(String)` if KVM can't be set up, so the caller falls back to the
//! interpreter.

#![cfg(all(feature = "kvm", target_os = "linux", target_arch = "x86_64"))]
// The only `unsafe` in the crate lives here: mmap of guest memory + the
// `/dev/kvm` ioctl wrappers. Every block carries a `// SAFETY:` note.
#![allow(unsafe_code)]

use kvm_bindings::{
    kvm_msr_entry, kvm_segment, kvm_userspace_memory_region, Msrs, KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls::{Kvm, VcpuExit};

use crate::emulator::Trap;
use crate::fsmount::MountTable;

use super::abi::{Amd64Abi, LinuxAbi, Sysno};
use super::guest::GuestCpu;
use super::loader;
use super::mem::GuestMem;
use super::{BlockReason, InteractiveInput, LinuxKernel};

// ---- guest-physical layout (all below the 0x400000 image base) -------------
const PML4: u64 = 0x1000;
const PDPT: u64 = 0x2000;
const PD_BASE: u64 = 0x3000; // four PD pages: 0x3000..0x7000
const TRAMP: u64 = 0x8000; // hlt ; sysretq
const MEM_SIZE: u64 = 0x1_0000_0000; // 4 GiB

// page-table entry flags
const PTE_P: u64 = 1 << 0;
const PTE_RW: u64 = 1 << 1;
const PTE_US: u64 = 1 << 2;
const PTE_PS: u64 = 1 << 7; // 2 MiB page in a PD entry

// model-specific registers
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;

/// A flat, host-mmap-backed guest-physical region that the syscall kernel
/// reads and writes (the guest CPU mutates it directly while running).
struct KvmMem {
    base: *mut u8,
    size: usize,
    /// Every page ever written by the *host* side (the ELF loader, syscall
    /// result buffers) — invisible to KVM's guest-write dirty log. A `fork`'s
    /// parent snapshot must include these (e.g. a child's big `execve` overwrites
    /// the parent's loaded `.text`/`.data`), else they'd be lost on restore.
    /// Tracked cheaply via `last_host_page`.
    host_pages: std::collections::HashSet<u32>,
    last_host_page: u32,
}

impl KvmMem {
    fn new(size: usize) -> Result<Self, String> {
        // SAFETY: standard anonymous mmap; `base` owned until Drop munmaps it.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(format!(
                "mmap {size:#x} guest memory failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            base: base.cast::<u8>(),
            size,
            host_pages: std::collections::HashSet::new(),
            last_host_page: u32::MAX,
        })
    }

    /// Copy one 4 KiB guest page out to a host buffer.
    fn read_page(&self, page: u32) -> Box<[u8; 4096]> {
        let mut buf = Box::new([0u8; 4096]);
        let gpa = u64::from(page) * 4096;
        // SAFETY: `page` indexes within the 4 GiB region (callers pass page
        // numbers derived from in-range addresses).
        unsafe {
            std::ptr::copy_nonoverlapping(self.host_ptr(gpa), buf.as_mut_ptr(), 4096);
        }
        buf
    }

    /// Overwrite one 4 KiB guest page from a host buffer.
    fn write_page(&mut self, page: u32, data: &[u8; 4096]) {
        let gpa = u64::from(page) * 4096;
        // SAFETY: as `read_page`.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.host_ptr(gpa), 4096);
        }
    }

    /// Drop the backing pages so the region reads zero again, for recycling a
    /// reaped process's window before a new process reuses it. `MADV_DONTNEED`
    /// on an anonymous mapping zero-fills on the next fault. Also clears the
    /// host-write tracking. (Used by the scheduler's window recycler — landing
    /// next in P1 — and the isolation test.)
    #[allow(dead_code)]
    fn madv_dontneed(&mut self) {
        // SAFETY: `base`/`size` are our own mmap; MADV_DONTNEED is non-destructive
        // to the mapping (only its resident pages).
        unsafe {
            libc::madvise(
                self.base.cast::<libc::c_void>(),
                self.size,
                libc::MADV_DONTNEED,
            );
        }
        self.host_pages.clear();
        self.last_host_page = u32::MAX;
    }

    /// Record host-written pages in `host_pages` (cheap `last_host_page` dedup
    /// for sequential writes), so a fork snapshot can include them.
    #[inline]
    fn mark(&mut self, addr: u32, len: usize) {
        if len == 0 {
            return;
        }
        let first = addr >> 12;
        let last = addr.wrapping_add(len as u32 - 1) >> 12;
        for page in first..=last {
            if page != self.last_host_page {
                self.host_pages.insert(page);
                self.last_host_page = page;
            }
        }
    }

    #[inline]
    fn check(&self, addr: u32, n: usize) -> Result<usize, Trap> {
        let a = addr as usize;
        if a.checked_add(n).is_none_or(|end| end > self.size) {
            return Err(Trap::MemoryFault { addr });
        }
        Ok(a)
    }

    #[inline]
    fn host_ptr(&self, gpa: u64) -> *mut u8 {
        // SAFETY: callers keep `gpa` inside the region.
        unsafe { self.base.add(gpa as usize) }
    }

    /// Write a raw `u64` at a guest-physical address (page-table / setup use).
    fn poke64(&mut self, gpa: u64, v: u64) {
        // SAFETY: `gpa` is one of the fixed low setup addresses, in-range.
        unsafe { self.host_ptr(gpa).cast::<u64>().write_unaligned(v) }
    }

    fn poke_bytes(&mut self, gpa: u64, data: &[u8]) {
        // SAFETY: setup writes stay within the region.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.host_ptr(gpa), data.len());
        }
    }
}

impl Drop for KvmMem {
    fn drop(&mut self) {
        // SAFETY: `base`/`size` came from our own mmap.
        unsafe {
            libc::munmap(self.base.cast::<libc::c_void>(), self.size);
        }
    }
}

macro_rules! load_impl {
    ($name:ident, $ty:ty) => {
        fn $name(&self, addr: u32) -> Result<$ty, Trap> {
            let a = self.check(addr, std::mem::size_of::<$ty>())?;
            // SAFETY: bounds checked; x86 host permits unaligned reads.
            Ok(unsafe { self.base.add(a).cast::<$ty>().read_unaligned() })
        }
    };
}
macro_rules! store_impl {
    ($name:ident, $ty:ty) => {
        fn $name(&mut self, addr: u32, value: $ty) -> Result<(), Trap> {
            let a = self.check(addr, std::mem::size_of::<$ty>())?;
            self.mark(addr, std::mem::size_of::<$ty>());
            // SAFETY: bounds checked; x86 host permits unaligned writes.
            unsafe { self.base.add(a).cast::<$ty>().write_unaligned(value) };
            Ok(())
        }
    };
}

impl GuestMem for KvmMem {
    load_impl!(load8, u8);
    load_impl!(load16, u16);
    load_impl!(load32, u32);
    load_impl!(load64, u64);
    store_impl!(store8, u8);
    store_impl!(store16, u16);
    store_impl!(store32, u32);
    store_impl!(store64, u64);

    fn map(&mut self, _addr: u32, _size: u32, _perm: crate::emulator::Perm) {
        // The whole 4 GiB is always present/identity-mapped; nothing to do.
    }

    fn map_zeroed(&mut self, addr: u32, size: u32, _perm: crate::emulator::Perm) {
        // Anonymous mapping: zero the range even if it held file data (e.g. the
        // dynamic linker overlaying a `.bss` tail).
        if let Ok(a) = self.check(addr, size as usize) {
            self.mark(addr, size as usize);
            // SAFETY: bounds checked above.
            unsafe { std::ptr::write_bytes(self.base.add(a), 0, size as usize) };
        }
    }

    fn write_initializer(&mut self, addr: u32, data: &[u8]) -> Result<(), Trap> {
        let a = self.check(addr, data.len())?;
        self.mark(addr, data.len());
        // SAFETY: bounds checked above.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(a), data.len()) };
        Ok(())
    }
}

/// A syscall-time view of the guest registers (a snapshot of `kvm_regs` plus a
/// pending `%fs` base). The kernel reads args / writes the return value
/// through [`GuestCpu`]; the runner syncs it back to the vCPU afterwards.
struct KvmCpu {
    regs: kvm_bindings::kvm_regs,
    fs_base: u64,
    fs_dirty: bool,
}

impl GuestCpu for KvmCpu {
    fn reg(&self, i: usize) -> u64 {
        // Canonical amd64 index → kvm_regs field.
        let r = &self.regs;
        match i {
            0 => r.rax,
            1 => r.rcx,
            2 => r.rdx,
            3 => r.rbx,
            4 => r.rsp,
            5 => r.rbp,
            6 => r.rsi,
            7 => r.rdi,
            8 => r.r8,
            9 => r.r9,
            10 => r.r10,
            11 => r.r11,
            12 => r.r12,
            13 => r.r13,
            14 => r.r14,
            _ => r.r15,
        }
    }
    fn set_reg(&mut self, i: usize, v: u64) {
        let r = &mut self.regs;
        match i {
            0 => r.rax = v,
            1 => r.rcx = v,
            2 => r.rdx = v,
            3 => r.rbx = v,
            4 => r.rsp = v,
            5 => r.rbp = v,
            6 => r.rsi = v,
            7 => r.rdi = v,
            8 => r.r8 = v,
            9 => r.r9 = v,
            10 => r.r10 = v,
            11 => r.r11 = v,
            12 => r.r12 = v,
            13 => r.r13 = v,
            14 => r.r14 = v,
            _ => r.r15 = v,
        }
    }
    fn pc(&self) -> u64 {
        self.regs.rip
    }
    fn set_pc(&mut self, v: u64) {
        self.regs.rip = v;
    }
    fn set_tls(&mut self, base: u64) {
        self.fs_base = base;
        self.fs_dirty = true;
    }
}

/// Build the page tables for a per-process window whose guest-physical backing
/// starts at `base`. The structures sit at the window's low offsets
/// (`base+PML4`, `base+PDPT`, `base+PD_BASE`) and map guest-virtual `[0, 4 GiB)`
/// to guest-physical `[base, base+4 GiB)` with user-accessible 2 MiB pages — so
/// every process sees the same flat GVA layout while living in its own GPA
/// window. `CR3` for the window is `base + PML4`. `poke64` addresses are host
/// offsets *within* the window (unchanged); only the stored physical addresses
/// carry `base`.
fn build_page_tables(mem: &mut KvmMem, base: u64) {
    mem.poke64(PML4, (base + PDPT) | PTE_P | PTE_RW | PTE_US);
    for i in 0..4u64 {
        mem.poke64(
            PDPT + i * 8,
            (base + PD_BASE + i * 0x1000) | PTE_P | PTE_RW | PTE_US,
        );
    }
    for k in 0..4u64 {
        let pd = PD_BASE + k * 0x1000;
        for j in 0..512u64 {
            let phys = base + (k * 0x4000_0000) + j * 0x20_0000;
            mem.poke64(pd + j * 8, phys | PTE_P | PTE_RW | PTE_US | PTE_PS);
        }
    }
}

/// A flat 64-bit user segment descriptor cache entry.
fn user_segment(selector: u16, code: bool) -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: 0xf_ffff,
        selector,
        type_: if code { 0xb } else { 0x3 }, // code:ER+A / data:RW+A
        present: 1,
        dpl: 3,
        db: u8::from(!code), // data segs set D/B; 64-bit code clears it (L=1)
        s: 1,
        l: u8::from(code),
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

/// The signal we use to kick the vCPU thread out of `KVM_RUN` so an async
/// terminal signal can be delivered between guest instructions.
const KICK_SIG: libc::c_int = libc::SIGUSR1;

/// Set by the host `SIGWINCH` handler; the reader polls it to re-read the
/// terminal size and forward a `SIGWINCH` to the guest.
static WINCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn kick_handler(_sig: libc::c_int) {}
extern "C" fn winch_handler(_sig: libc::c_int) {
    WINCH.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Install our host signal handlers exactly once: the no-op `SIGUSR1` kick (no
/// `SA_RESTART`, so a kick makes the in-flight `KVM_RUN` return `EINTR`) and the
/// `SIGWINCH` flag-setter that drives terminal-resize forwarding.
fn install_host_handlers() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: process-wide handlers for our own signals; both are
        // async-signal-safe (a no-op and a single atomic store).
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = kick_handler as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0; // no SA_RESTART → interrupt KVM_RUN
            libc::sigaction(KICK_SIG, &sa, std::ptr::null_mut());

            let mut sw: libc::sigaction = std::mem::zeroed();
            sw.sa_sigaction = winch_handler as *const () as usize;
            libc::sigemptyset(&mut sw.sa_mask);
            sw.sa_flags = libc::SA_RESTART;
            libc::sigaction(libc::SIGWINCH, &sw, std::ptr::null_mut());
        }
    });
}

/// Background reader guard: stops the host-stdin reader thread when the run
/// loop returns (the thread wakes within one poll tick and exits).
struct ReaderGuard(std::sync::Arc<InteractiveInput>);
impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.0.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Forward an async signal to the guest: flag it on `input` and kick the vCPU
/// thread out of `KVM_RUN` so it's delivered between guest instructions.
fn raise_and_kick(input: &InteractiveInput, main_tid: u64, sig: i32) {
    input.raise(sig);
    // SAFETY: directed kick to the vCPU thread; KICK_SIG has a no-op handler
    // installed process-wide.
    unsafe {
        libc::pthread_kill(main_tid as libc::pthread_t, KICK_SIG);
    }
}

/// Spawn the background host-stdin reader for interactive mode. It reads the raw
/// host terminal and pushes bytes into `input`; while the guest has `ISIG` set it
/// turns VINTR (Ctrl-C) → SIGINT and VQUIT (Ctrl-\) → SIGQUIT, and it forwards a
/// host window resize → SIGWINCH. Each is flagged on `input` and the vCPU thread
/// (`main_tid`) is kicked out of `KVM_RUN`, so even a CPU-bound guest not in a
/// `read` is interrupted. Exits on host EOF or `input.stop`.
fn spawn_stdin_reader(input: std::sync::Arc<InteractiveInput>, main_tid: u64) {
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering::SeqCst;
        let mut pfd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut buf = [0u8; 256];
        loop {
            if input.stop.load(SeqCst) {
                return;
            }
            // A pending terminal resize (host SIGWINCH): re-read the size and
            // forward SIGWINCH to the guest so TUIs redraw.
            if WINCH.swap(false, SeqCst) {
                // SAFETY: TIOCGWINSZ into a local winsize.
                let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                let r = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
                if r == 0 {
                    input.win_rows.store(ws.ws_row, SeqCst);
                    input.win_cols.store(ws.ws_col, SeqCst);
                }
                raise_and_kick(&input, main_tid, 28); // SIGWINCH
            }
            // Poll with a timeout so `stop`/resize are still observed when no key
            // is pressed. SAFETY: one valid pollfd, count 1.
            let pr = unsafe { libc::poll(&mut pfd, 1, 100) };
            if pr <= 0 {
                continue; // timeout (0) or EINTR (-1): re-check flags
            }
            // SAFETY: read into a local buffer of known length.
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                input.close(); // host EOF or error
                return;
            }
            for &b in &buf[..n as usize] {
                let isig = input.isig.load(SeqCst);
                if isig && b == input.vintr.load(SeqCst) {
                    // Echo `^C` like a real tty (host is raw, so we do it).
                    // SAFETY: write to stdout fd.
                    unsafe { libc::write(libc::STDOUT_FILENO, b"^C\r\n".as_ptr().cast(), 4) };
                    raise_and_kick(&input, main_tid, 2); // SIGINT
                } else if isig && b == input.vquit.load(SeqCst) {
                    // SAFETY: write to stdout fd.
                    unsafe { libc::write(libc::STDOUT_FILENO, b"^\\\r\n".as_ptr().cast(), 4) };
                    raise_and_kick(&input, main_tid, 3); // SIGQUIT
                } else {
                    input.push(b);
                }
            }
        }
    });
}

/// Run an amd64 static ELF under KVM, servicing its syscalls through `kernel`.
/// Returns the process exit code.
///
/// # Errors
/// `Err(String)` if KVM is unavailable or the guest faults unexpectedly; the
/// caller falls back to the software interpreter.
pub fn run(
    kernel: &mut LinuxKernel,
    vfs: &mut MountTable,
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<i32, String> {
    let trace = std::env::var("UD_LINUX_TRACE").is_ok();

    // --- guest memory + load the ELF through the shared loader ---
    let mut mem = KvmMem::new(MEM_SIZE as usize)?;
    // Dynamic binaries read their interpreter from the guest rootfs (`vfs`).
    let image = loader::load_elf(&mut mem, Some(vfs), bytes, argv, envp)
        .map_err(|e| format!("ELF load: {e}"))?;
    kernel.init(image.brk);

    build_page_tables(&mut mem, 0);
    mem.poke_bytes(TRAMP, &[0xF4, 0x48, 0x0F, 0x07]); // hlt ; sysretq

    // --- KVM: VM, memory slot, vCPU ---
    let kvm = Kvm::new().map_err(|e| format!("open /dev/kvm: {e}"))?;
    let vm = kvm.create_vm().map_err(|e| format!("KVM_CREATE_VM: {e}"))?;
    let region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE,
        userspace_addr: mem.base as u64,
        // Log dirty pages so a synchronous `fork` child's native writes can be
        // rolled back from a parent snapshot (kernel-side writes use the CoW
        // path in `KvmMem`).
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };
    // SAFETY: `mem` outlives the VM; the region is a valid mmap of `memory_size`.
    unsafe {
        vm.set_user_memory_region(region)
            .map_err(|e| format!("KVM_SET_USER_MEMORY_REGION: {e}"))?;
    }
    let mut vcpu = vm
        .create_vcpu(0)
        .map_err(|e| format!("KVM_CREATE_VCPU: {e}"))?;

    // Advertise the host's CPUID so glibc's ifunc resolvers pick the real
    // CPU's feature set (which the real CPU then executes natively). Also read
    // the XSAVE-valid XCR0 mask (CPUID leaf 0xD, subleaf 0) so we can enable
    // exactly the state components the host supports.
    let mut xcr0: u64 = 0x1; // x87, always valid
    if let Ok(cpuid) = kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES) {
        for e in cpuid.as_slice() {
            if e.function == 0xD && e.index == 0 {
                xcr0 = u64::from(e.eax) | (u64::from(e.edx) << 32);
            }
        }
        vcpu.set_cpuid2(&cpuid)
            .map_err(|e| format!("KVM_SET_CPUID2: {e}"))?;
    }

    // --- long mode, CPL 3, paging ---
    let mut sregs = vcpu.get_sregs().map_err(|e| format!("get_sregs: {e}"))?;
    sregs.cr3 = PML4;
    // Enable the CR4 feature gates for everything the host CPUID advertises,
    // so an instruction the guest selects on a CPUID bit doesn't #UD:
    //   PAE | OSFXSR | OSXMMEXCPT | FSGSBASE | OSXSAVE
    // (FSGSBASE → rd/wrfsbase; OSXSAVE → xgetbv/xsave.)
    sregs.cr4 = 0x20 | 0x200 | 0x400 | 0x1_0000 | 0x4_0000;
    sregs.cr0 = 0x8000_0033; // PG | NE | ET | MP | PE
    sregs.efer = 0x100 | 0x400 | 0x1; // LME | LMA | SCE
    sregs.cs = user_segment(0x33, true);
    let data = user_segment(0x2b, false);
    sregs.ds = data;
    sregs.es = data;
    sregs.fs = data;
    sregs.gs = data;
    sregs.ss = data;
    vcpu.set_sregs(&sregs)
        .map_err(|e| format!("set_sregs: {e}"))?;

    // XCR0 = host-supported state mask (x87 | SSE | AVX | …) so `xgetbv`
    // reports it and the guest may use those SIMD widths natively. With
    // OSXSAVE set above, this keeps glibc's feature detection self-consistent.
    let mut xcrs = vcpu.get_xcrs().map_err(|e| format!("get_xcrs: {e}"))?;
    xcrs.nr_xcrs = 1;
    xcrs.xcrs[0].xcr = 0;
    xcrs.xcrs[0].value = xcr0 | 0x1; // bit 0 (x87) is mandatory
    vcpu.set_xcrs(&xcrs).map_err(|e| format!("set_xcrs: {e}"))?;

    // SYSCALL/SYSRET MSRs: LSTAR → trampoline; STAR selectors line up with the
    // CPL-3 segments above (sysret loads CS=0x33, SS=0x2b).
    let msrs = Msrs::from_entries(&[
        kvm_msr_entry {
            index: MSR_LSTAR,
            data: TRAMP,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_STAR,
            data: (0x20u64 << 48) | (0x10u64 << 32),
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_SFMASK,
            data: 0x700, // clear TF | IF | DF in the handler
            ..Default::default()
        },
    ])
    .map_err(|e| format!("build MSRs: {e:?}"))?;
    vcpu.set_msrs(&msrs).map_err(|e| format!("set_msrs: {e}"))?;

    let abi = Amd64Abi;

    // Interactive mode: spawn the background host-stdin reader and arm the vCPU
    // kick so an async terminal signal can interrupt a CPU-bound process. The
    // guard stops the thread when `run` returns.
    let reader = if kernel.interactive {
        install_host_handlers();
        // SAFETY: pthread_self has no preconditions; it identifies this vCPU
        // thread for the reader's directed kick.
        let main_tid = unsafe { libc::pthread_self() } as u64;
        let input = std::sync::Arc::new(InteractiveInput::default());
        kernel.attach_input(input.clone());
        spawn_stdin_reader(input.clone(), main_tid);
        Some(input)
    } else {
        None
    };
    let _reader_guard = reader.clone().map(ReaderGuard);

    // Process 1 is the initial program: it owns the loaded window (slot 0, GPA
    // 0). The scheduler multiplexes it and its `fork` descendants on this one
    // vCPU, each in its own address-space window (distinct GPA + CR3).
    kernel.scheduler = true;
    let mut p0 = Proc::new(1, 0, 0, mem, kernel.proc_snapshot());
    p0.regs.rip = u64::from(image.entry);
    p0.regs.rsp = u64::from(image.stack_ptr);
    p0.regs.rflags = 0x2;

    // `sregs` already holds the CPL3 long-mode template; the scheduler only
    // varies cr3 + fs.base per context switch.
    schedule(&vm, &mut vcpu, kernel, vfs, &abi, sregs, p0, reader, trace)
}

/// Build a `wait4` status word from an exit code (`WIFEXITED` form).
fn wait_status(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// Words saved in our signal frame: the 16 GP registers, rip, rflags, and the
/// pre-signal blocked mask.
const SIG_CTX_WORDS: u32 = 19;

/// Whether a signal's **default** (SIG_DFL) action terminates the process. The
/// defaults that don't — child/continue/stop/resize/urgent — are treated as
/// *ignore* here (no job control on the synchronous-fork model, so the stop
/// signals are dropped rather than suspending): SIGCHLD(17) SIGCONT(18)
/// SIGSTOP(19) SIGTSTP(20) SIGTTIN(21) SIGTTOU(22) SIGURG(23) SIGWINCH(28).
fn default_terminates(sig: i32) -> bool {
    !matches!(sig, 17 | 18 | 19 | 20 | 21 | 22 | 23 | 28)
}

/// Deliver `sig` to the guest. SIG_IGN → drop (`Ok(None)`); SIG_DFL → terminate
/// (`Ok(Some(status))`) or drop, per the signal's default action; a handler →
/// build an amd64 signal frame on the guest stack and point the vCPU at it. The
/// interrupted syscall's result (rax, already `-EINTR`) is saved in the frame,
/// so a handler that returns resumes right after it via `rt_sigreturn`.
fn deliver_signal(
    vcpu: &mut kvm_ioctls::VcpuFd,
    mem: &mut KvmMem,
    kernel: &mut LinuxKernel,
    sig: i32,
) -> Result<Option<i32>, String> {
    let (handler, _flags, restorer, mask) = match kernel.signal_disposition(sig) {
        None | Some((0, ..)) => {
            // SIG_DFL: terminate or (resize/child/stop) ignore.
            return Ok(default_terminates(sig).then_some(128 + sig));
        }
        Some((1, ..)) => return Ok(None), // SIG_IGN → drop
        Some(d) => d,
    };
    let r = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
    // Frame below the 128-byte red zone: 16-aligned context, with the restorer
    // address just below it (the "return address" the handler's `ret` pops).
    let ctx_addr = (r.rsp - 128 - u64::from(SIG_CTX_WORDS) * 8) & !0xFu64;
    let frame_base = ctx_addr - 8; // %16 == 8, as on a normal `call`
    let _ = mem.store64(frame_base as u32, restorer);
    let words = [
        r.rax,
        r.rbx,
        r.rcx,
        r.rdx,
        r.rsi,
        r.rdi,
        r.rbp,
        r.rsp,
        r.r8,
        r.r9,
        r.r10,
        r.r11,
        r.r12,
        r.r13,
        r.r14,
        r.r15,
        r.rip,
        r.rflags,
        kernel.sig_mask(),
    ];
    for (i, w) in words.iter().enumerate() {
        let _ = mem.store64(ctx_addr as u32 + i as u32 * 8, *w);
    }
    // Block this signal (and the handler's sa_mask) while it runs.
    kernel.set_sig_mask(kernel.sig_mask() | mask | 1u64 << ((sig - 1) as u64));
    let mut nr = r;
    nr.rip = handler;
    nr.rsp = frame_base;
    nr.rdi = sig as u64; // signum
    nr.rsi = ctx_addr; // siginfo* (a shell SIGINT handler ignores it)
    nr.rdx = ctx_addr; // ucontext*
    vcpu.set_regs(&nr).map_err(|e| format!("set_regs: {e}"))?;
    Ok(None)
}

/// Complete `rt_sigreturn`: restore the registers + blocked mask saved by
/// [`deliver_signal`], so the guest resumes exactly where the signal interrupted
/// it (with the interrupted syscall's `-EINTR` in rax).
fn handle_sigreturn(
    vcpu: &mut kvm_ioctls::VcpuFd,
    mem: &KvmMem,
    kernel: &mut LinuxKernel,
) -> Result<(), String> {
    let r = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
    let ctx = r.rsp as u32; // rsp points at the saved context (pretcode popped)
    let rd = |i: u32| mem.load64(ctx + i * 8).unwrap_or(0);
    let mut nr = r;
    nr.rax = rd(0);
    nr.rbx = rd(1);
    nr.rcx = rd(2);
    nr.rdx = rd(3);
    nr.rsi = rd(4);
    nr.rdi = rd(5);
    nr.rbp = rd(6);
    nr.rsp = rd(7);
    nr.r8 = rd(8);
    nr.r9 = rd(9);
    nr.r10 = rd(10);
    nr.r11 = rd(11);
    nr.r12 = rd(12);
    nr.r13 = rd(13);
    nr.r14 = rd(14);
    nr.r15 = rd(15);
    nr.rip = rd(16);
    nr.rflags = rd(17);
    kernel.set_sig_mask(rd(18));
    vcpu.set_regs(&nr).map_err(|e| format!("set_regs: {e}"))?;
    Ok(())
}

/// Page indices the guest has dirtied in `slot` since the last call (reading
/// clears the log). Empty on error — the resident set just covers fewer pages.
fn dirty_pages(vm: &kvm_ioctls::VmFd, slot: u32) -> Vec<u32> {
    let Ok(bitmap) = vm.get_dirty_log(slot, MEM_SIZE as usize) else {
        return Vec::new();
    };
    let mut pages = Vec::new();
    for (w, &word) in bitmap.iter().enumerate() {
        if word == 0 {
            continue;
        }
        for bit in 0..64u32 {
            if word & (1u64 << bit) != 0 {
                pages.push(w as u32 * 64 + bit);
            }
        }
    }
    pages
}

/// Read a NUL-terminated C string from guest memory (capped).
fn read_cstr_kvm(mem: &KvmMem, addr: u32) -> Option<String> {
    let mut bytes = Vec::new();
    let mut a = addr;
    for _ in 0..4096 {
        let b = mem.load8(a).ok()?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        a = a.wrapping_add(1);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Replace the current process image **in place**: load `path argv…` over the
/// live guest memory and reset the vCPU to its entry, so the new program runs
/// natively on KVM (rather than handing it to the interpreter). One level of
/// `#!` shebang is resolved. Returns false if the program can't be read/loaded;
/// the caller then makes `execve` fail.
fn exec_in_place(
    vcpu: &mut kvm_ioctls::VcpuFd,
    mem: &mut KvmMem,
    kernel: &mut LinuxKernel,
    vfs: &mut MountTable,
    fs_base: &mut u64,
    path: &str,
    argv: &[String],
    envp: &[String],
) -> bool {
    let mut path = path.to_string();
    let mut argv = argv.to_vec();
    let bytes = loop {
        let Some(bytes) = vfs.read_file(&path) else {
            return false;
        };
        if !bytes.starts_with(b"#!") {
            break bytes;
        }
        // Shebang: re-exec the named interpreter with the script as its argument.
        let end = bytes
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(bytes.len());
        let line = String::from_utf8_lossy(&bytes[2..end]);
        let mut parts = line.split_whitespace();
        let Some(interp) = parts.next().map(ToString::to_string) else {
            return false;
        };
        let mut new_argv = vec![interp.clone()];
        if let Some(arg) = parts.next() {
            new_argv.push(arg.to_string());
        }
        new_argv.push(path.clone());
        new_argv.extend(argv.iter().skip(1).cloned());
        argv = new_argv;
        path = interp;
    };
    if !crate::linux::loader::is_runnable(&bytes) {
        return false;
    }
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let envp_refs: Vec<&str> = envp.iter().map(String::as_str).collect();
    let Ok(image) = loader::load_elf(mem, Some(vfs), &bytes, &argv_refs, &envp_refs) else {
        return false;
    };
    kernel.exec_reset(image.brk);
    // SysV entry state: zeroed GP regs, fresh TLS base (the program sets its own).
    let regs = kvm_bindings::kvm_regs {
        rip: u64::from(image.entry),
        rsp: u64::from(image.stack_ptr),
        rflags: 0x2,
        ..Default::default()
    };
    if vcpu.set_regs(&regs).is_err() {
        return false;
    }
    *fs_base = 0;
    if let Ok(mut s) = vcpu.get_sregs() {
        s.fs.base = 0;
        let _ = vcpu.set_sregs(&s);
    }
    true
}

/// Maximum concurrent live processes (each owns a 4 GiB guest-physical window;
/// `MAX_SLOTS * 4 GiB` of guest-physical address space). Slots of reaped
/// processes are recycled, so this bounds *concurrency*, not total forks.
const MAX_SLOTS: u32 = 16;

/// Why a process is parked, and how the scheduler wakes it.
enum Block {
    /// Interactive stdin `read` with no complete input yet (woken by the reader).
    Stdin,
    /// `nanosleep` until the deadline.
    Timer(std::time::Instant),
    /// `wait4` with a live child that hasn't exited (woken when one does).
    Wait4,
    /// `read` on an empty pipe with the write end still open (woken on write /
    /// last-writer-close). Carries the pipe index.
    Pipe(usize),
}

enum PState {
    Runnable,
    Blocked(Block),
    /// Exited; the `wait4`-encoded status awaits the parent's reap.
    Zombie(i32),
}

/// One live guest process multiplexed onto the single vCPU. While a process is
/// *running* its register/kernel state lives in the vCPU/`LinuxKernel`; while it
/// is parked, the saved copy lives here.
struct Proc {
    pid: i32,
    ppid: i32,
    state: PState,
    /// This process's address-space window (own mmap + KVM slot at `gpa`).
    win: KvmMem,
    slot: u32,
    gpa: u64,
    /// Pages this process has populated (guest-dirty accumulator ∪ host writes),
    /// copied to a `fork` child. Reset on `execve`.
    resident: std::collections::HashSet<u32>,
    /// Saved vCPU GP registers (canonical CPL3 userspace state while parked).
    regs: kvm_bindings::kvm_regs,
    fs_base: u64,
    /// Saved per-process kernel state (fds, brk, cwd, signal dispositions…).
    kstate: super::ProcState,
    /// Live child pids (for `wait4` / `ECHILD`).
    children: Vec<i32>,
}

impl Proc {
    fn new(pid: i32, ppid: i32, slot: u32, win: KvmMem, kstate: super::ProcState) -> Self {
        Proc {
            pid,
            ppid,
            state: PState::Runnable,
            win,
            slot,
            gpa: u64::from(slot) * MEM_SIZE,
            resident: std::collections::HashSet::new(),
            regs: kvm_bindings::kvm_regs::default(),
            fs_base: 0,
            kstate,
            children: Vec::new(),
        }
    }
}

/// Allocate and register a fresh window for `slot` (guest-physical base
/// `slot*4 GiB`): a zeroed mmap with its own page tables + trampoline.
fn new_window(vm: &kvm_ioctls::VmFd, slot: u32) -> Result<KvmMem, String> {
    let gpa = u64::from(slot) * MEM_SIZE;
    let mut win = KvmMem::new(MEM_SIZE as usize)?;
    build_page_tables(&mut win, gpa);
    win.poke_bytes(TRAMP, &[0xF4, 0x48, 0x0F, 0x07]); // hlt ; sysretq
    let region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: gpa,
        memory_size: MEM_SIZE,
        userspace_addr: win.base as u64,
        flags: KVM_MEM_LOG_DIRTY_PAGES,
    };
    // SAFETY: `win` outlives the slot (removed on reap before drop); region
    // matches the mmap.
    unsafe {
        vm.set_user_memory_region(region)
            .map_err(|e| format!("KVM_SET_USER_MEMORY_REGION(slot {slot}): {e}"))?;
    }
    Ok(win)
}

/// Remove a reaped process's KVM slot so its window can be dropped (munmap'd)
/// without leaving a dangling mapping. The slot number is then free to reuse.
fn drop_slot(vm: &kvm_ioctls::VmFd, slot: u32, gpa: u64) {
    let region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: gpa,
        memory_size: 0, // size 0 removes the slot
        userspace_addr: 0,
        flags: 0,
    };
    // SAFETY: removing our own slot; no vCPU references this GPA (CR3 isolation).
    unsafe {
        let _ = vm.set_user_memory_region(region);
    }
}

/// Switch the vCPU to `p`: its CR3, fs.base and GP registers. The `sregs`
/// template already carries the CPL3 long-mode segments, so a parked process
/// (saved at a canonical userspace point) resumes in userspace.
fn switch_in(
    vcpu: &mut kvm_ioctls::VcpuFd,
    sregs: &mut kvm_bindings::kvm_sregs,
    p: &Proc,
) -> Result<(), String> {
    sregs.cr3 = p.gpa + PML4;
    sregs.fs.base = p.fs_base;
    vcpu.set_sregs(sregs)
        .map_err(|e| format!("switch set_sregs: {e}"))?;
    vcpu.set_regs(&p.regs)
        .map_err(|e| format!("switch set_regs: {e}"))?;
    Ok(())
}

/// Trampoline-time registers (at the `hlt`, RCX = return address, R11 = saved
/// RFLAGS) → a canonical CPL3 userspace state that *resumes after* the syscall.
/// Used for a `fork` child (rax already set to 0 by the caller) and for
/// complete-then-park syscalls (`nanosleep`).
fn resume_after(r: kvm_bindings::kvm_regs) -> kvm_bindings::kvm_regs {
    let mut n = r;
    n.rip = r.rcx;
    n.rflags = r.r11;
    n
}

/// As `resume_after`, but resumes *at* the `syscall` instruction so it re-runs
/// (RCX points just past it; `syscall` is 2 bytes). Used for rewind-blocking
/// syscalls (`read`, `wait4`) whose result depends on data available on re-run.
fn resume_retry(r: kvm_bindings::kvm_regs) -> kvm_bindings::kvm_regs {
    let mut n = r;
    n.rip = r.rcx.wrapping_sub(2);
    n.rflags = r.r11;
    n
}

/// The cooperative scheduler: multiplex `procs` onto the one vCPU, switching at
/// syscall blocking points and preemption kicks, until process 1 exits.
#[allow(clippy::too_many_arguments)]
fn schedule(
    vm: &kvm_ioctls::VmFd,
    vcpu: &mut kvm_ioctls::VcpuFd,
    kernel: &mut LinuxKernel,
    vfs: &mut MountTable,
    abi: &Amd64Abi,
    mut sregs: kvm_bindings::kvm_sregs,
    p0: Proc,
    reader: Option<std::sync::Arc<InteractiveInput>>,
    trace: bool,
) -> Result<i32, String> {
    use std::collections::HashMap;
    let mut procs: HashMap<i32, Proc> = HashMap::new();
    procs.insert(p0.pid, p0);
    let mut next_pid = 2i32;
    let mut next_slot = 1u32;
    let mut free_slots: Vec<u32> = Vec::new();
    let mut order: Vec<i32> = vec![1]; // round-robin order (stable pids)
    let mut loaded: Option<i32> = None;
    let mut cur = 1i32;

    loop {
        // --- wake blocked processes whose condition is satisfiable ---
        let now = std::time::Instant::now();
        let input_ready = reader.as_ref().is_some_and(|i| i.has_input());
        for p in procs.values_mut() {
            if let PState::Blocked(b) = &p.state {
                let wake = match b {
                    Block::Timer(t) => *t <= now,
                    Block::Stdin => input_ready,
                    Block::Wait4 => false, // woken inline when a child exits
                    Block::Pipe(i) => kernel.pipe_readable(*i),
                };
                if wake {
                    p.state = PState::Runnable;
                }
            }
        }

        // --- pick the next runnable process (round-robin from `cur`) ---
        let pick = pick_runnable(&order, &procs, cur);
        let idx = match pick {
            Some(p) => p,
            None => {
                if procs.values().all(|p| matches!(p.state, PState::Zombie(_))) {
                    return Ok(procs.get(&1).map_or(0, |p| match p.state {
                        PState::Zombie(st) => (st >> 8) & 0xff,
                        _ => 0,
                    }));
                }
                idle_wait(&procs, reader.as_deref());
                continue;
            }
        };

        // --- context switch if needed ---
        if loaded != Some(idx) {
            if let Some(l) = loaded {
                if let Some(p) = procs.get_mut(&l) {
                    p.kstate = kernel.proc_snapshot();
                }
            }
            let ks = procs[&idx].kstate.clone();
            kernel.proc_restore(ks);
            kernel.set_ids(procs[&idx].pid, procs[&idx].ppid);
            switch_in(vcpu, &mut sregs, &procs[&idx])?;
            loaded = Some(idx);
        }
        cur = idx;

        // --- run `cur` until it yields (blocks / exits / is preempted) ---
        'run: loop {
            let exit = match vcpu.run() {
                Ok(e) => e,
                Err(e) if e.errno() == libc::EINTR => {
                    // Preemption / async-signal kick. Only act at CPL3 (the
                    // trampoline must finish its sysret first).
                    let in_user = vcpu.get_sregs().map(|s| s.cs.dpl == 3).unwrap_or(true);
                    if !in_user {
                        continue 'run;
                    }
                    // Deliver a pending (async) signal to `cur`.
                    if let Some(sig) = kernel.take_pending_signal() {
                        let win = &mut procs.get_mut(&cur).unwrap().win;
                        if let Some(status) = deliver_signal(vcpu, win, kernel, sig)? {
                            exit_proc(&mut procs, vm, &mut free_slots, cur, status);
                            loaded = None;
                            break 'run;
                        }
                    }
                    // Yield the CPU (preemption): save `cur`'s registers and
                    // reschedule. `loaded` stays `Some(cur)`, so if the
                    // round-robin re-picks `cur` (nothing else runnable) the
                    // switch is skipped; the switch path saves its kstate if a
                    // different process is chosen.
                    procs.get_mut(&cur).unwrap().regs =
                        vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
                    break 'run;
                }
                Err(e) => return Err(format!("KVM_RUN: {e}")),
            };
            match exit {
                VcpuExit::Hlt => {
                    let r = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
                    let mut kcpu = KvmCpu {
                        regs: r,
                        fs_base: procs[&cur].fs_base,
                        fs_dirty: false,
                    };
                    let yielded = service_syscall(
                        vm,
                        vcpu,
                        kernel,
                        vfs,
                        abi,
                        &mut procs,
                        &mut order,
                        &mut next_pid,
                        &mut next_slot,
                        &mut free_slots,
                        cur,
                        &mut kcpu,
                    )?;
                    match yielded {
                        Yield::Continue => {
                            // Deliver a signal raised during the syscall (sync
                            // Ctrl-C while in a blocking read, etc.).
                            if let Some(sig) = kernel.take_pending_signal() {
                                let win = &mut procs.get_mut(&cur).unwrap().win;
                                if let Some(status) = deliver_signal(vcpu, win, kernel, sig)? {
                                    exit_proc(&mut procs, vm, &mut free_slots, cur, status);
                                    loaded = None;
                                    break 'run;
                                }
                            }
                        }
                        Yield::Park => {
                            loaded = None;
                            break 'run;
                        }
                        Yield::Exited => {
                            loaded = None;
                            break 'run;
                        }
                    }
                }
                VcpuExit::Shutdown => {
                    let at = vcpu
                        .get_regs()
                        .ok()
                        .map_or(String::new(), |r| format!(" at rip={:#x}", r.rip));
                    if trace {
                        eprintln!("kvm: guest (pid {cur}) triple-faulted{at}");
                    }
                    return Err(format!("guest triple-faulted (KVM_EXIT_SHUTDOWN){at}"));
                }
                VcpuExit::FailEntry(reason, c) => {
                    return Err(format!("KVM_EXIT_FAIL_ENTRY reason={reason:#x} cpu={c}"));
                }
                VcpuExit::InternalError => return Err("KVM_EXIT_INTERNAL_ERROR".into()),
                other => return Err(format!("unexpected KVM exit: {other:?}")),
            }
        }
    }
}

/// Round-robin pick: the first `Runnable` process at or after `cur` in `order`.
fn pick_runnable(
    order: &[i32],
    procs: &std::collections::HashMap<i32, Proc>,
    cur: i32,
) -> Option<i32> {
    let n = order.len();
    let start = order.iter().position(|&p| p == cur).map_or(0, |i| i + 1);
    for k in 0..n {
        let pid = order[(start + k) % n];
        if let Some(p) = procs.get(&pid) {
            if matches!(p.state, PState::Runnable) {
                return Some(pid);
            }
        }
    }
    None
}

/// Block the scheduler when nothing is runnable: wait for the earliest timer
/// deadline, or for interactive input, whichever comes first.
fn idle_wait(procs: &std::collections::HashMap<i32, Proc>, reader: Option<&InteractiveInput>) {
    let now = std::time::Instant::now();
    let earliest = procs
        .values()
        .filter_map(|p| match &p.state {
            PState::Blocked(Block::Timer(t)) => Some(*t),
            _ => None,
        })
        .min();
    let timeout = earliest.map(|t| t.saturating_duration_since(now));
    match reader {
        Some(input) => input.wait_for_input(timeout),
        None => {
            if let Some(d) = timeout {
                if !d.is_zero() {
                    std::thread::sleep(d.min(std::time::Duration::from_millis(50)));
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Mark `pid` a zombie with exit `code`, free its window/slot, and wake its
/// parent if it was waiting. Keeps the (windowless) zombie in the table until
/// the parent reaps it via `wait4`.
fn exit_proc(
    procs: &mut std::collections::HashMap<i32, Proc>,
    vm: &kvm_ioctls::VmFd,
    free_slots: &mut Vec<u32>,
    pid: i32,
    code: i32,
) {
    let (ppid, slot, gpa) = {
        let p = procs.get(&pid).unwrap();
        (p.ppid, p.slot, p.gpa)
    };
    // Free the window now (a zombie never runs again); keep slot 0 (process 1).
    if slot != 0 {
        drop_slot(vm, slot, gpa);
        free_slots.push(slot);
    }
    if let Some(p) = procs.get_mut(&pid) {
        p.state = PState::Zombie(wait_status(code));
    }
    // Wake a parent parked in wait4.
    if let Some(parent) = procs.get_mut(&ppid) {
        if matches!(parent.state, PState::Blocked(Block::Wait4)) {
            parent.state = PState::Runnable;
        }
    }
}

/// What `service_syscall` did with the current process.
enum Yield {
    /// Stay on `cur` and keep running it.
    Continue,
    /// `cur` parked (its saved regs/kstate are set); reschedule.
    Park,
    /// `cur` exited; reschedule.
    Exited,
}

/// Service one syscall for `cur` (at the `hlt` trampoline). Returns whether the
/// process keeps running, parked, or exited.
#[allow(clippy::too_many_arguments)]
fn service_syscall(
    vm: &kvm_ioctls::VmFd,
    vcpu: &mut kvm_ioctls::VcpuFd,
    kernel: &mut LinuxKernel,
    vfs: &mut MountTable,
    abi: &Amd64Abi,
    procs: &mut std::collections::HashMap<i32, Proc>,
    order: &mut Vec<i32>,
    next_pid: &mut i32,
    next_slot: &mut u32,
    free_slots: &mut Vec<u32>,
    cur: i32,
    kcpu: &mut KvmCpu,
) -> Result<Yield, String> {
    let r = kcpu.regs;
    match abi.map_syscall(abi.syscall_nr(kcpu)) {
        Some(Sysno::Fork | Sysno::Vfork) => {
            do_fork(
                vm, vcpu, kernel, procs, order, next_pid, next_slot, free_slots, cur, &r,
            )?;
            Ok(Yield::Continue)
        }
        // `clone` without CLONE_VM is a `fork`; with it (a thread) stays ENOSYS.
        Some(Sysno::Clone) => {
            let flags = abi.syscall_args(kcpu)[0];
            if flags & 0x100 == 0 {
                do_fork(
                    vm, vcpu, kernel, procs, order, next_pid, next_slot, free_slots, cur, &r,
                )?;
            } else {
                kcpu.regs.rax = (-38i64) as u64; // ENOSYS
                vcpu.set_regs(&kcpu.regs)
                    .map_err(|e| format!("set_regs: {e}"))?;
            }
            Ok(Yield::Continue)
        }
        Some(Sysno::Wait4) => do_wait4(vcpu, kernel, abi, procs, order, cur, kcpu, &r),
        Some(Sysno::Execve) => {
            let a = abi.syscall_args(kcpu);
            let (path, argv, envp) = {
                let win = &procs[&cur].win;
                let path = read_cstr_kvm(win, a[0] as u32).unwrap_or_default();
                let argv = kernel.read_str_array(win, a[1] as u32);
                let envp = kernel.read_str_array(win, a[2] as u32);
                (path, argv, envp)
            };
            let p = procs.get_mut(&cur).unwrap();
            if exec_in_place(
                vcpu,
                &mut p.win,
                kernel,
                vfs,
                &mut p.fs_base,
                &path,
                &argv,
                &envp,
            ) {
                p.resident.clear();
            } else {
                kcpu.regs.rax = (-2i64) as u64; // ENOENT
                vcpu.set_regs(&kcpu.regs)
                    .map_err(|e| format!("set_regs: {e}"))?;
            }
            Ok(Yield::Continue)
        }
        Some(Sysno::Exit | Sysno::ExitGroup) => {
            let code = abi.syscall_args(kcpu)[0] as i32;
            exit_proc(procs, vm, free_slots, cur, code);
            Ok(Yield::Exited)
        }
        Some(Sysno::RtSigreturn) => {
            let win = &procs[&cur].win;
            handle_sigreturn(vcpu, win, kernel)?;
            Ok(Yield::Continue)
        }
        _ => {
            {
                let win = &mut procs.get_mut(&cur).unwrap().win;
                kernel.dispatch(abi, kcpu, win, vfs);
            }
            // A blocking syscall asked to park (stdin read / nanosleep).
            if let Some(reason) = kernel.block_request.take() {
                let p = procs.get_mut(&cur).unwrap();
                p.regs = match &reason {
                    // Re-run the read on wake.
                    BlockReason::Stdin | BlockReason::Pipe(_) => resume_retry(r),
                    BlockReason::Timer(_) => {
                        let mut nr = resume_after(r); // nanosleep completes (rax=0)
                        nr.rax = 0;
                        nr
                    }
                };
                p.state = match reason {
                    BlockReason::Stdin => PState::Blocked(Block::Stdin),
                    BlockReason::Timer(t) => PState::Blocked(Block::Timer(t)),
                    BlockReason::Pipe(i) => PState::Blocked(Block::Pipe(i)),
                };
                p.kstate = kernel.proc_snapshot();
                return Ok(Yield::Park);
            }
            if let Some(code) = kernel.exit_code.take() {
                exit_proc(procs, vm, free_slots, cur, code);
                return Ok(Yield::Exited);
            }
            vcpu.set_regs(&kcpu.regs)
                .map_err(|e| format!("set_regs: {e}"))?;
            if kcpu.fs_dirty {
                procs.get_mut(&cur).unwrap().fs_base = kcpu.fs_base;
                // Update only fs.base on the *current* sregs — the vCPU is at the
                // CPL0 trampoline here, so we must not clobber its CS with the
                // CPL3 template (that would fault the pending `sysretq`).
                let mut s = vcpu.get_sregs().map_err(|e| format!("get_sregs: {e}"))?;
                s.fs.base = kcpu.fs_base;
                vcpu.set_sregs(&s).map_err(|e| format!("set_sregs: {e}"))?;
            }
            Ok(Yield::Continue)
        }
    }
}

/// `fork`/`vfork`: allocate the child's window, rebuild its page tables, copy the
/// parent's resident data pages, clone the kernel state, and add it to the table
/// as Runnable. The parent gets the child pid; the child resumes after `fork`
/// returning 0.
#[allow(clippy::too_many_arguments)]
fn do_fork(
    vm: &kvm_ioctls::VmFd,
    vcpu: &mut kvm_ioctls::VcpuFd,
    kernel: &mut LinuxKernel,
    procs: &mut std::collections::HashMap<i32, Proc>,
    order: &mut Vec<i32>,
    next_pid: &mut i32,
    next_slot: &mut u32,
    free_slots: &mut Vec<u32>,
    cur: i32,
    r: &kvm_bindings::kvm_regs,
) -> Result<(), String> {
    let slot = match free_slots.pop() {
        Some(s) => s,
        None if *next_slot < MAX_SLOTS => {
            let s = *next_slot;
            *next_slot += 1;
            s
        }
        None => {
            // Too many live processes — fail the fork with EAGAIN.
            let mut pr = *r;
            pr.rax = (-11i64) as u64;
            vcpu.set_regs(&pr).map_err(|e| format!("set_regs: {e}"))?;
            return Ok(());
        }
    };
    let mut child_win = new_window(vm, slot)?;
    let child_pid = *next_pid;
    *next_pid += 1;

    // Copy the parent's populated data pages (skip page tables 1..8 / null page).
    let (child_resident, parent_fs) = {
        let parent = procs.get_mut(&cur).unwrap();
        for pg in dirty_pages(vm, parent.slot) {
            parent.resident.insert(pg);
        }
        let mut pages: std::collections::HashSet<u32> = parent.resident.clone();
        pages.extend(parent.win.host_pages.iter().copied());
        pages.retain(|&p| p >= 9);
        for &pg in &pages {
            let data = parent.win.read_page(pg);
            child_win.write_page(pg, &data);
        }
        parent.children.push(child_pid);
        (pages, parent.fs_base)
    };

    let mut child = Proc::new(child_pid, cur, slot, child_win, kernel.proc_snapshot());
    kernel.fork_dup_pipes(); // child inherits a copy of every pipe end
    child.resident = child_resident;
    child.fs_base = parent_fs;
    let mut cr = resume_after(*r);
    cr.rax = 0;
    child.regs = cr;
    procs.insert(child_pid, child);
    order.push(child_pid);

    // Parent keeps running; `fork` returns the child pid.
    let mut pr = *r;
    pr.rax = child_pid as u64;
    vcpu.set_regs(&pr).map_err(|e| format!("set_regs: {e}"))?;
    Ok(())
}

/// `wait4(pid, wstatus, options)`: reap a matching zombie child (writing its
/// status), return `ECHILD` if there are no matching children, or park
/// (`Block::Wait4`) until one exits (unless `WNOHANG`).
#[allow(clippy::too_many_arguments)]
fn do_wait4(
    vcpu: &mut kvm_ioctls::VcpuFd,
    kernel: &mut LinuxKernel,
    abi: &Amd64Abi,
    procs: &mut std::collections::HashMap<i32, Proc>,
    order: &mut Vec<i32>,
    cur: i32,
    kcpu: &mut KvmCpu,
    r: &kvm_bindings::kvm_regs,
) -> Result<Yield, String> {
    let a = abi.syscall_args(kcpu);
    let target = a[0] as i64; // <=0 → any child; >0 → that pid
    let wstatus = a[1] as u32;
    let options = a[2] as i32;

    let children = procs[&cur].children.clone();
    let mut zombie: Option<(i32, i32)> = None;
    let mut any_live = false;
    for &cpid in &children {
        if target > 0 && target as i32 != cpid {
            continue;
        }
        match procs.get(&cpid).map(|p| &p.state) {
            Some(PState::Zombie(st)) => {
                zombie = Some((cpid, *st));
                break;
            }
            Some(_) => any_live = true,
            None => {}
        }
    }

    if let Some((cpid, st)) = zombie {
        if wstatus != 0 {
            let win = &mut procs.get_mut(&cur).unwrap().win;
            let _ = win.store32(wstatus, st as u32);
        }
        procs.remove(&cpid);
        order.retain(|&p| p != cpid);
        let p = procs.get_mut(&cur).unwrap();
        p.children.retain(|&c| c != cpid);
        kcpu.regs.rax = cpid as u64;
        vcpu.set_regs(&kcpu.regs)
            .map_err(|e| format!("set_regs: {e}"))?;
        return Ok(Yield::Continue);
    }
    if any_live {
        if options & 1 != 0 {
            // WNOHANG: nothing to report yet.
            kcpu.regs.rax = 0;
            vcpu.set_regs(&kcpu.regs)
                .map_err(|e| format!("set_regs: {e}"))?;
            return Ok(Yield::Continue);
        }
        let p = procs.get_mut(&cur).unwrap();
        p.regs = resume_retry(*r);
        p.state = PState::Blocked(Block::Wait4);
        p.kstate = kernel.proc_snapshot();
        return Ok(Yield::Park);
    }
    // No children at all.
    kcpu.regs.rax = (-10i64) as u64; // ECHILD
    vcpu.set_regs(&kcpu.regs)
        .map_err(|e| format!("set_regs: {e}"))?;
    Ok(Yield::Continue)
}

#[cfg(test)]
mod window_tests {
    //! Validate the per-process address-space model the scheduler relies on:
    //! distinct guest-physical windows + per-window page tables + a `CR3` swap
    //! give isolated address spaces on one vCPU, and a recycled window reads
    //! zero. This is the make-or-break memory mechanic for the scheduler.
    use super::*;
    use crate::linux::mem::GuestMem;
    use kvm_bindings::kvm_userspace_memory_region;

    fn kvm_ok() -> bool {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
    }

    #[test]
    fn per_process_windows_isolate_and_recycle() {
        if !kvm_ok() {
            eprintln!("SKIP: /dev/kvm not accessible");
            return;
        }
        let gva_code: u32 = 0x40_0000;
        let gva_data: u32 = 0x50_0000;
        // `mov byte [0x500000], 0xAA ; syscall` — write a marker, then trap.
        let prog = [
            0xC6u8, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00, 0xAA, // mov byte [0x500000],0xAA
            0x0F, 0x05, // syscall
        ];
        let tramp = [0xF4u8, 0x48, 0x0F, 0x07]; // hlt ; sysretq

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        // Two windows at distinct guest-physical bases: 0 and 4 GiB.
        let bases = [0u64, MEM_SIZE];
        let mut wins: Vec<KvmMem> = Vec::new();
        for (slot, &base) in bases.iter().enumerate() {
            let mut mem = KvmMem::new(MEM_SIZE as usize).unwrap();
            build_page_tables(&mut mem, base);
            mem.poke_bytes(TRAMP, &tramp);
            mem.poke_bytes(u64::from(gva_code), &prog);
            let region = kvm_userspace_memory_region {
                slot: slot as u32,
                guest_phys_addr: base,
                memory_size: MEM_SIZE,
                userspace_addr: mem.base as u64,
                flags: KVM_MEM_LOG_DIRTY_PAGES,
            };
            // SAFETY: `mem` outlives the VM in this test; region matches the mmap.
            unsafe { vm.set_user_memory_region(region).unwrap() };
            wins.push(mem);
        }

        let mut vcpu = vm.create_vcpu(0).unwrap();
        let mut sregs = vcpu.get_sregs().unwrap();
        sregs.cr4 = 0x20; // PAE
        sregs.cr0 = 0x8000_0033; // PG|NE|ET|MP|PE
        sregs.efer = 0x100 | 0x400 | 0x1; // LME|LMA|SCE
        sregs.cs = user_segment(0x33, true);
        let data = user_segment(0x2b, false);
        sregs.ds = data;
        sregs.es = data;
        sregs.fs = data;
        sregs.gs = data;
        sregs.ss = data;
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: MSR_LSTAR,
                data: TRAMP,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_STAR,
                data: (0x20u64 << 48) | (0x10u64 << 32),
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_SFMASK,
                data: 0x700,
                ..Default::default()
            },
        ])
        .unwrap();
        vcpu.set_msrs(&msrs).unwrap();

        let mut run_in = |vcpu: &mut kvm_ioctls::VcpuFd, base: u64| {
            sregs.cr3 = base + PML4;
            vcpu.set_sregs(&sregs).unwrap();
            let regs = kvm_bindings::kvm_regs {
                rip: u64::from(gva_code),
                rsp: 0x60_0000,
                rflags: 0x2,
                ..Default::default()
            };
            vcpu.set_regs(&regs).unwrap();
            match vcpu.run().unwrap() {
                VcpuExit::Hlt => {}
                other => panic!("unexpected exit running window @ {base:#x}: {other:?}"),
            }
        };

        // Run in window 0 → marker lands in window 0 only.
        run_in(&mut vcpu, bases[0]);
        assert_eq!(
            wins[0].load8(gva_data).unwrap(),
            0xAA,
            "window 0 got the write"
        );
        assert_eq!(wins[1].load8(gva_data).unwrap(), 0x00, "window 1 isolated");

        // Run in window 1 → marker lands in window 1; window 0 unchanged.
        run_in(&mut vcpu, bases[1]);
        assert_eq!(
            wins[1].load8(gva_data).unwrap(),
            0xAA,
            "window 1 got the write"
        );
        assert_eq!(
            wins[0].load8(gva_data).unwrap(),
            0xAA,
            "window 0 kept its own"
        );

        // Recycle window 0: MADV_DONTNEED must zero the backing for reuse.
        wins[0].madv_dontneed();
        assert_eq!(
            wins[0].load8(gva_data).unwrap(),
            0x00,
            "recycled window reads zero"
        );
    }
}

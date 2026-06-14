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
use super::LinuxKernel;

/// Instruction budget handed to a nested interpreter run of an `execve`'d
/// program (the child of a `fork`). Generous — the typical case is a small
/// post-install trigger (`busybox`), not a long-running service.
const NESTED_BUDGET: u64 = 200_000_000_000;

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
    /// While a `fork` child is running, the parent's original content of every
    /// 4 KiB page the kernel writes on the child's behalf (syscall result
    /// buffers). Lets [`run_kvm_child`] roll those writes back so the suspended
    /// parent's memory is undisturbed. Empty / inert outside a child.
    recording: bool,
    child_saved: std::collections::HashMap<u32, Box<[u8; 4096]>>,
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
            recording: false,
            child_saved: std::collections::HashMap::new(),
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

    /// Zero one 4 KiB guest page (used to restore a page the child first
    /// populated — it was zero in the parent).
    fn zero_page(&mut self, page: u32) {
        let gpa = u64::from(page) * 4096;
        // SAFETY: as `read_page`.
        unsafe {
            std::ptr::write_bytes(self.host_ptr(gpa), 0, 4096);
        }
    }

    /// Copy-on-write hook for kernel-side writes during a fork child: save each
    /// touched page's pre-write (parent) content the first time it's written.
    #[inline]
    fn mark(&mut self, addr: u32, len: usize) {
        if !self.recording || len == 0 {
            return;
        }
        let first = addr >> 12;
        let last = addr.wrapping_add(len as u32 - 1) >> 12;
        for page in first..=last {
            if !self.child_saved.contains_key(&page) {
                let snap = self.read_page(page);
                self.child_saved.insert(page, snap);
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

/// Build the 2 MiB identity page tables covering `[0, 4 GiB)`, user-accessible.
fn build_page_tables(mem: &mut KvmMem) {
    mem.poke64(PML4, PDPT | PTE_P | PTE_RW | PTE_US);
    for i in 0..4u64 {
        mem.poke64(
            PDPT + i * 8,
            (PD_BASE + i * 0x1000) | PTE_P | PTE_RW | PTE_US,
        );
    }
    for k in 0..4u64 {
        let pd = PD_BASE + k * 0x1000;
        for j in 0..512u64 {
            let phys = (k * 0x4000_0000) + j * 0x20_0000;
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

    build_page_tables(&mut mem);
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

    // --- entry registers ---
    // The SysV entry state zeroes the GP registers (notably RDX = 0, the
    // `rtld_fini` slot glibc reads — x86 reset would otherwise leave the CPU
    // signature in RDX, which glibc would register as a bogus atexit handler).
    let regs = kvm_bindings::kvm_regs {
        rip: u64::from(image.entry),
        rsp: u64::from(image.stack_ptr),
        rflags: 0x2,
        ..Default::default()
    };
    vcpu.set_regs(&regs).map_err(|e| format!("set_regs: {e}"))?;

    let abi = Amd64Abi;
    let mut fs_base: u64 = 0;
    // Synchronous-fork bookkeeping: child PIDs, reaped-but-unwaited statuses,
    // and a persistent snapshot of the parent's content for every guest-dirtied
    // page (so a fork child's native writes can be rolled back).
    let mut next_pid: i32 = 2;
    let mut zombies: Vec<(i32, i32)> = Vec::new();
    let mut psnap: std::collections::HashMap<u32, Box<[u8; 4096]>> =
        std::collections::HashMap::new();

    // --- run loop: native execution until a syscall (hlt trampoline), the
    // program exits, or the guest faults. ---
    loop {
        match vcpu.run().map_err(|e| format!("KVM_RUN: {e}"))? {
            VcpuExit::Hlt => {
                // A `syscall` reached the trampoline; service it through the
                // shared kernel, then `sysretq` (already at rip) resumes guest
                // userspace right after the original `syscall`.
                let r = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
                let mut kcpu = KvmCpu {
                    regs: r,
                    fs_base,
                    fs_dirty: false,
                };
                match abi.map_syscall(abi.syscall_nr(&kcpu)) {
                    // fork/vfork: run the child to completion synchronously in
                    // this same vCPU (it execs almost immediately), record it as
                    // a zombie, then return its PID to the parent.
                    Some(Sysno::Fork | Sysno::Vfork) => {
                        let pid = next_pid;
                        next_pid += 1;
                        let status = run_kvm_child(
                            &vm,
                            &mut vcpu,
                            &mut mem,
                            kernel,
                            vfs,
                            &abi,
                            &mut fs_base,
                            &mut psnap,
                        )?;
                        zombies.push((pid, wait_status(status)));
                        let mut pr = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
                        pr.rax = pid as u64;
                        vcpu.set_regs(&pr).map_err(|e| format!("set_regs: {e}"))?;
                    }
                    // wait4: the child already ran, so a zombie is waiting.
                    Some(Sysno::Wait4) => {
                        let a = abi.syscall_args(&kcpu);
                        let ret = if let Some((cpid, st)) = zombies.pop() {
                            if a[1] != 0 {
                                let _ = mem.store32(a[1] as u32, st as u32);
                            }
                            i64::from(cpid)
                        } else {
                            -10 // ECHILD
                        };
                        kcpu.regs.rax = ret as u64;
                        vcpu.set_regs(&kcpu.regs)
                            .map_err(|e| format!("set_regs: {e}"))?;
                    }
                    // The main process execs itself: become the new program.
                    Some(Sysno::Execve) => {
                        return Ok(exec_run(&mem, kernel, vfs, &kcpu, &abi));
                    }
                    _ => {
                        kernel.dispatch(&abi, &mut kcpu, &mut mem, vfs);
                        if let Some(code) = kernel.exit_code {
                            return Ok(code);
                        }
                        vcpu.set_regs(&kcpu.regs)
                            .map_err(|e| format!("set_regs: {e}"))?;
                        if kcpu.fs_dirty {
                            fs_base = kcpu.fs_base;
                            let mut s = vcpu.get_sregs().map_err(|e| format!("get_sregs: {e}"))?;
                            s.fs.base = fs_base;
                            vcpu.set_sregs(&s).map_err(|e| format!("set_sregs: {e}"))?;
                        }
                    }
                }
            }
            VcpuExit::Shutdown => {
                let at = vcpu
                    .get_regs()
                    .ok()
                    .map_or(String::new(), |r| format!(" at rip={:#x}", r.rip));
                if trace {
                    eprintln!("kvm: guest triple-faulted{at}");
                }
                return Err(format!("guest triple-faulted (KVM_EXIT_SHUTDOWN){at}"));
            }
            VcpuExit::FailEntry(reason, cpu) => {
                return Err(format!("KVM_EXIT_FAIL_ENTRY reason={reason:#x} cpu={cpu}"));
            }
            VcpuExit::InternalError => return Err("KVM_EXIT_INTERNAL_ERROR".into()),
            other => return Err(format!("unexpected KVM exit: {other:?}")),
        }
    }
}

/// Build a `wait4` status word from an exit code (`WIFEXITED` form).
fn wait_status(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// Page indices the guest has dirtied since the last call (reading clears the
/// log). Empty on error — the snapshot just covers fewer pages.
fn dirty_pages(vm: &kvm_ioctls::VmFd) -> Vec<u32> {
    let Ok(bitmap) = vm.get_dirty_log(0, MEM_SIZE as usize) else {
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

/// Service an `execve`: load `path argv…` from the guest and run it to
/// completion in a fresh interpreter [`Sandbox`](crate::Sandbox) sharing the
/// same root filesystem. Returns the program's exit code (127 if it can't be
/// loaded). The KVM engine has no in-place loader, so the exec'd image runs on
/// the software interpreter — fine for the small post-install triggers apk runs.
fn exec_run(
    mem: &KvmMem,
    kernel: &mut LinuxKernel,
    vfs: &mut MountTable,
    kcpu: &KvmCpu,
    abi: &Amd64Abi,
) -> i32 {
    let a = abi.syscall_args(kcpu);
    let Some(path) = read_cstr_kvm(mem, a[0] as u32) else {
        return 127;
    };
    let argv = kernel.read_str_array(mem, a[1] as u32);
    let envp = kernel.read_str_array(mem, a[2] as u32);
    match crate::runtime::exec_nested(vfs, &path, &argv, &envp, NESTED_BUDGET) {
        Some((code, out, err)) => {
            kernel.stdout.extend_from_slice(&out);
            kernel.stderr.extend_from_slice(&err);
            code
        }
        None => 127,
    }
}

/// Run a `fork`/`vfork` child to completion in the **same** vCPU, then restore
/// the parent. The child sees `rax = 0` and runs until it `execve`s (the common
/// case — handed to [`exec_run`]) or exits. Per-process kernel state (fd table,
/// brk, cwd) is snapshotted and rolled back so the parent is unaffected; the
/// child does only a few fd ops before exec, so guest memory needs no copy.
/// Returns the child's exit code.
#[allow(clippy::too_many_arguments)]
fn run_kvm_child(
    vm: &kvm_ioctls::VmFd,
    vcpu: &mut kvm_ioctls::VcpuFd,
    mem: &mut KvmMem,
    kernel: &mut LinuxKernel,
    vfs: &mut MountTable,
    abi: &Amd64Abi,
    fs_base: &mut u64,
    psnap: &mut std::collections::HashMap<u32, Box<[u8; 4096]>>,
) -> Result<i32, String> {
    let snap = kernel.proc_snapshot();
    let parent_regs = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
    let parent_fs = *fs_base;

    // Capture the parent's content of every page the guest has dirtied since the
    // last fork (all pages, on the first). `get_dirty_log` also clears the log,
    // so the post-child read below reports only the child's native writes.
    for page in dirty_pages(vm) {
        psnap.insert(page, mem.read_page(page));
    }

    // Record (copy-on-write) every page the kernel writes for the child, so we
    // can roll those writes back and leave the parent's memory untouched.
    mem.child_saved.clear();
    mem.recording = true;

    // The child returns 0 from fork; everything else carries over.
    let mut cregs = parent_regs;
    cregs.rax = 0;
    vcpu.set_regs(&cregs)
        .map_err(|e| format!("set_regs: {e}"))?;

    let status = loop {
        match vcpu.run().map_err(|e| format!("KVM_RUN(child): {e}"))? {
            VcpuExit::Hlt => {
                let r = vcpu.get_regs().map_err(|e| format!("get_regs: {e}"))?;
                let mut kcpu = KvmCpu {
                    regs: r,
                    fs_base: *fs_base,
                    fs_dirty: false,
                };
                match abi.map_syscall(abi.syscall_nr(&kcpu)) {
                    Some(Sysno::Execve) => break exec_run(mem, kernel, vfs, &kcpu, abi),
                    Some(Sysno::Exit | Sysno::ExitGroup) => {
                        break abi.syscall_args(&kcpu)[0] as i32;
                    }
                    // A child that forks again isn't supported; fail it.
                    Some(Sysno::Fork | Sysno::Vfork) => {
                        kcpu.regs.rax = (-38i64) as u64; // ENOSYS
                        vcpu.set_regs(&kcpu.regs)
                            .map_err(|e| format!("set_regs: {e}"))?;
                    }
                    _ => {
                        kernel.dispatch(abi, &mut kcpu, mem, vfs);
                        if let Some(code) = kernel.exit_code.take() {
                            break code;
                        }
                        vcpu.set_regs(&kcpu.regs)
                            .map_err(|e| format!("set_regs: {e}"))?;
                        if kcpu.fs_dirty {
                            *fs_base = kcpu.fs_base;
                            let mut s = vcpu.get_sregs().map_err(|e| format!("get_sregs: {e}"))?;
                            s.fs.base = *fs_base;
                            vcpu.set_sregs(&s).map_err(|e| format!("set_sregs: {e}"))?;
                        }
                    }
                }
            }
            VcpuExit::Shutdown => break 139, // treat a child fault as a crash
            other => return Err(format!("unexpected KVM exit in child: {other:?}")),
        }
    };

    // Roll the parent back. First the child's *native* writes (from the dirty
    // log) using the parent snapshot — a page the child first populated wasn't
    // in the parent, so it's zeroed. Then the child's *kernel-side* writes from
    // the exact copy-on-write record (authoritative, so applied last).
    mem.recording = false;
    let saved = std::mem::take(&mut mem.child_saved);
    for page in dirty_pages(vm) {
        match psnap.get(&page) {
            Some(orig) => mem.write_page(page, orig),
            None => mem.zero_page(page),
        }
    }
    for (page, orig) in &saved {
        mem.write_page(*page, orig);
    }
    kernel.proc_restore(snap);
    vcpu.set_regs(&parent_regs)
        .map_err(|e| format!("set_regs: {e}"))?;
    if *fs_base != parent_fs {
        *fs_base = parent_fs;
        let mut s = vcpu.get_sregs().map_err(|e| format!("get_sregs: {e}"))?;
        s.fs.base = parent_fs;
        vcpu.set_sregs(&s).map_err(|e| format!("set_sregs: {e}"))?;
    }
    Ok(status)
}

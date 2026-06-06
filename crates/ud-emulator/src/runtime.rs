//! Top-level [`Sandbox`] — owns the MMU, the CPU, the Win32 stub
//! registry, and the per-emulator host state, and exposes the
//! "load this DLL and call its DllMain" workflow that the
//! integration tests + future codec wrapper layers drive.
//!
//! This is the highest-level public entry point in the crate.
//! Round-1 exposed [`Sandbox::load`] + [`Sandbox::call_dll_main`];
//! round-2 adds the generic [`Sandbox::call_export`] helper that
//! the `vfw32` host stubs use to invoke the codec's `DriverProc`
//! synchronously.

use crate::emulator::{mmu::Perm, Cpu, Mmu};
use crate::pe::{Image, Loader};
use crate::win32::{
    call_guest, run_until_sentinel as run_until_sentinel_free, vfw32, HostState, Registry,
    DATA_IMPORT_BASE,
};

/// `DllMain` reason code: process is loading the DLL.
pub const DLL_PROCESS_ATTACH: u32 = 1;
/// `DllMain` reason code: process is unloading the DLL.
pub const DLL_PROCESS_DETACH: u32 = 0;

/// Default region the loader can use as the kernel32 heap arena.
/// Shrunk to the lower 96 MiB of the 0x6000_0000-0x7000_0000
/// quarter so the upper half stays free for Apple framework DLLs
/// that hard-code preferred image bases in 0x66XX_XXXX-0x68XX_XXXX
/// (quicktime.qts at 0x6680_0000, the .qtx codecs at 0x677X_XXXX,
/// qtcf.dll at 0x6864_0000, AAS CoreVideo / CoreAudioToolbox /
/// CFNetwork at similar addresses). When the VFS-DLL fallback
/// loader maps a dependent at its preferred base, the heap arena
/// no longer collides.
const HEAP_ARENA_START: u32 = 0x6000_0000;
const HEAP_ARENA_END: u32 = 0x6600_0000;

/// Const-arena region — read-only canned strings handed back from
/// `GetCommandLineA` / `GetEnvironmentStrings` etc.
const CONST_ARENA_START: u32 = 0x7000_0000;
const CONST_ARENA_END: u32 = 0x7010_0000;

/// Data-import slot region — see [`crate::win32::DATA_IMPORT_BASE`].
/// Holds 4-byte values backing CRT data imports like
/// `msvcrt!_adjust_fdiv`. 4 KiB is plenty.
const DATA_IMPORT_REGION_SIZE: u32 = 0x0000_1000;

/// Default guest stack region — plenty of room above the heap.
const STACK_BOTTOM: u32 = 0x9000_0000;
const STACK_SIZE: u32 = 0x0010_0000; // 1 MiB
const STACK_TOP: u32 = STACK_BOTTOM + STACK_SIZE;

/// Thread-stack arena. `CreateThread` carves a 64 KiB region
/// out of this pool per spawned thread, walking down from the
/// top. 0x8000_0000 .. 0x9000_0000 = 256 MiB → ~4096 aux
/// threads, plenty for codec / installer corpora.
const THREAD_STACK_POOL_BOTTOM: u32 = 0x8000_0000;
const THREAD_STACK_POOL_SIZE: u32 = 0x1000_0000; // 256 MiB
const THREAD_STACK_POOL_TOP: u32 = THREAD_STACK_POOL_BOTTOM + THREAD_STACK_POOL_SIZE;

/// Thread Environment Block — Windows places its TEB at
/// `0x7FFD_E000` historically. We map a 4 KiB page here and
/// stage the SEH chain head (`FS:[0]`) to `0xFFFF_FFFF` ("end of
/// chain"). Real Windows fills many more fields; for the codec
/// CRT init we only need a writable page so the codec's SEH
/// `__try` setup can save the prior chain head, write its own,
/// and restore on exit.
const TEB_BASE: u32 = 0x7FFD_E000;
const TEB_SIZE: u32 = 0x0000_1000; // 4 KiB
/// `EXCEPTION_REGISTRATION_RECORD*` initialiser at FS:[0].
const SEH_END_OF_CHAIN: u32 = 0xFFFF_FFFF;

/// Per-thread TIB pool. `CreateThread` carves a 4 KiB TIB out
/// of this pool per spawned thread, walking down from the
/// top. 256 KiB → 64 aux thread TIBs, well above any plausible
/// codec / installer thread count.
const TIB_POOL_BOTTOM: u32 = 0x7FFC_0000;
const TIB_POOL_SIZE: u32 = 0x0001_E000; // ~120 KiB → 30 TIBs
const TIB_POOL_TOP: u32 = TIB_POOL_BOTTOM + TIB_POOL_SIZE;

/// Child-process pools. `CreateProcessA` loads each spawned PE
/// at [`CHILD_IMAGE_BASE_START`] + N * `CHILD_IMAGE_STRIDE` and
/// gives each child a private 16 MiB heap arena out of
/// `[CHILD_HEAP_POOL_START, CHILD_HEAP_POOL_END)`. Picked above
/// the parent's mapped regions but below TEB / stack-pool
/// addresses to keep guest pointers easy to read in traces.
const CHILD_IMAGE_BASE_START: u32 = 0x1000_0000;
const CHILD_HEAP_POOL_START: u32 = 0xA000_0000;
const CHILD_HEAP_POOL_SIZE: u32 = 0x1000_0000; // 256 MiB → 16 children
const CHILD_HEAP_POOL_END: u32 = CHILD_HEAP_POOL_START + CHILD_HEAP_POOL_SIZE;

/// One sandbox instance per loaded codec DLL.
pub struct Sandbox {
    pub mmu: Mmu,
    pub cpu: Cpu,
    pub registry: Registry,
    pub host: HostState,
    /// Linux personality state (fd table, brk/mmap, captured output, exit
    /// code). Default/empty for Windows runs; populated by
    /// [`Sandbox::load_linux_elf`].
    pub linux: crate::linux::LinuxKernel,
    /// `e_machine` of the loaded Linux ELF (selects the run loop / ABI).
    /// `0` until [`Sandbox::load_linux_elf`] runs.
    pub linux_machine: u16,
    /// The aarch64 CPU, allocated lazily when an `EM_AARCH64` image loads
    /// (the x86 [`Cpu`] cannot host that ISA).
    pub aarch64: Option<Box<crate::emulator::aarch64::Aarch64Cpu>>,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox {
    /// Borrow the always-on coverage map populated by the
    /// interpreter. Records every dispatched instruction's
    /// entry EIP plus every guest memory write. See
    /// [`crate::coverage::CoverageMap`] for the consumer
    /// surface.
    #[must_use]
    pub fn coverage(&self) -> &crate::coverage::CoverageMap {
        &self.mmu.coverage
    }

    /// Mutable accessor for the coverage map — useful for
    /// per-export resets (`coverage_mut().clear()`) between
    /// runs of the same sandbox.
    pub fn coverage_mut(&mut self) -> &mut crate::coverage::CoverageMap {
        &mut self.mmu.coverage
    }

    /// Borrow the emulation-context layer (virtual filesystem,
    /// virtual registry, future surfaces). Always present;
    /// the per-surface options decide whether the guest
    /// observes synthetic state or the fail-soft Win32
    /// default. See [`crate::context::Context`].
    #[must_use]
    pub fn context(&self) -> &crate::context::Context {
        &self.host.context
    }

    /// Mutable accessor for the context.
    pub fn context_mut(&mut self) -> &mut crate::context::Context {
        &mut self.host.context
    }

    /// Builder: attach a virtual filesystem so guest file-API
    /// calls land in-memory instead of fail-soft no-ops. See
    /// [`crate::VirtualFs`] for the stage-some-files / capture-
    /// what's-written workflow.
    #[must_use]
    pub fn with_vfs(mut self, vfs: crate::context::VirtualFs) -> Self {
        self.host.context.vfs = Some(vfs);
        self
    }

    /// Builder: attach a virtual registry so guest `Reg*` calls
    /// observe analyst-staged keys and writes land in-memory.
    /// See [`crate::VirtualRegistry`].
    #[must_use]
    pub fn with_registry(mut self, reg: crate::context::VirtualRegistry) -> Self {
        self.host.context.registry = Some(reg);
        self
    }

    /// Create a fresh sandbox with the heap arena and stack
    /// pre-mapped, the kernel32 stub set registered, and the
    /// CPU's `esp` pointing at a freshly-allocated stack.
    pub fn new() -> Self {
        let mut mmu = Mmu::new();
        // Heap arena (R+W+X). Old codecs (e.g. Cinepak) ship
        // architecture-specific inner-loop assembly that they
        // copy into `malloc`'d memory at init time and then call.
        // On real Windows, `HeapAlloc(GetProcessHeap, ...)` returns
        // executable memory by default; modelling the same is
        // simpler than chasing per-codec `VirtualProtect(PAGE_EXEC)`
        // calls. Bytes still respect `mmu.write_initializer`'s
        // perm rules; only the X bit is broader.
        mmu.map(
            HEAP_ARENA_START,
            HEAP_ARENA_END - HEAP_ARENA_START,
            Perm::R | Perm::W | Perm::X,
        );
        // Const-arena for canned strings (R+W mapped; the caller
        // ABI treats it as R-only — we use write_initializer for
        // population, then any reads honour the perm bits).
        mmu.map(
            CONST_ARENA_START,
            CONST_ARENA_END - CONST_ARENA_START,
            Perm::R | Perm::W,
        );
        // Data-import slot region (R+W) — holds the 4-byte
        // values backing CRT data imports like
        // `msvcrt!_adjust_fdiv`. Seeded with each registered
        // import's `initial` value.
        mmu.map(DATA_IMPORT_BASE, DATA_IMPORT_REGION_SIZE, Perm::R | Perm::W);
        // Stack (R+W)
        mmu.map(STACK_BOTTOM, STACK_SIZE, Perm::R | Perm::W);
        // Thread-stack pool (R+W). `CreateThread` carves
        // 64 KiB stacks out of the top of this pool, walking
        // down with each thread.
        mmu.map(
            THREAD_STACK_POOL_BOTTOM,
            THREAD_STACK_POOL_SIZE,
            Perm::R | Perm::W,
        );
        // Stub-thunk region (R-only, zeroed). The run loop
        // detects `eip == thunk_addr` via `Registry::is_thunk`
        // *before* hitting the MMU, so execution still routes
        // to the stub regardless of the X bit — but codecs that
        // *read* a function pointer's bytes (a hot-patch /
        // forwarder probe; CamStudio does this in DllMain) need
        // a mapped region behind the address. Zeros pass every
        // standard "is this byte E9/EB/CC/C3?" introspection.
        mmu.map(crate::win32::THUNK_BASE, 0x1_0000, Perm::R);
        // TEB / FS-segment data (R+W). Initialise FS:[0] = -1
        // (no SEH handler installed) and FS:[0x18] = TEB self
        // pointer per the Windows TEB ABI used by Win32 CRTs.
        mmu.map(TEB_BASE, TEB_SIZE, Perm::R | Perm::W);
        mmu.write_initializer(TEB_BASE, &SEH_END_OF_CHAIN.to_le_bytes())
            .expect("seed TEB FS:[0]");
        mmu.write_initializer(TEB_BASE + 0x18, &TEB_BASE.to_le_bytes())
            .expect("seed TEB FS:[0x18] (self pointer)");
        // Per-thread TIB pool (R+W). `CreateThread` carves a
        // fresh TIB out of this pool for each spawned thread,
        // setting the new thread's FS base to its own TIB.
        mmu.map(TIB_POOL_BOTTOM, TIB_POOL_SIZE, Perm::R | Perm::W);
        // KUSER_SHARED_DATA + the high-memory TEB scan shelf.
        // QT's QTMLInitInternals walks the usermode region
        // (0x7F000000..0x7FFFFFFF) looking for per-thread TEBs
        // — Windows allocates TEBs from the top of usermode
        // memory down in 64 KiB increments, and Apple's code
        // probes each candidate 64 KiB-aligned address for a
        // TEB self-pointer signature. The probe runs DOWN the
        // region until it finds an unmapped page, so map the
        // full 16 MiB shelf zero-filled (R+W since codecs
        // sometimes write sentinel bytes back). 0x7FFE_0000 is
        // the conventional KUSER_SHARED_DATA base; zero-fill
        // for SystemTime / NtSystemRoot is fine for codecs
        // that only consult these for diagnostic logging.
        mmu.map(0x7F00_0000, 0x00FC_0000, Perm::R | Perm::W); // 0x7F00_0000..0x7FFC_0000
        mmu.map(0x7FFD_F000, 0x0002_1000, Perm::R | Perm::W); // 0x7FFD_F000..0x8000_0000
                                                              // Child-process heap pool (R+W+X). Each `CreateProcessA`
                                                              // carves a 16 MiB heap arena from this region for the
                                                              // spawned child.
        mmu.map(
            CHILD_HEAP_POOL_START,
            CHILD_HEAP_POOL_SIZE,
            Perm::R | Perm::W | Perm::X,
        );
        // FS:[0x30] would be the PEB pointer — we leave it 0
        // until a codec actually dereferences it.

        let mut cpu = Cpu::new();
        cpu.regs.set_esp(STACK_TOP - 0x100); // leave a guard at the top
        cpu.set_fs_base(TEB_BASE);

        let mut registry = Registry::new();
        registry.register_all();
        // Seed data-import slot values into the mapped region.
        for (_dll, _name, d) in registry.data_imports() {
            mmu.write_initializer(d.addr, &d.initial.to_le_bytes())
                .expect("seed data import");
        }

        let mut host = HostState::new(HEAP_ARENA_START, HEAP_ARENA_END)
            .with_const_arena(CONST_ARENA_START, CONST_ARENA_END)
            .with_thread_stack_pool(THREAD_STACK_POOL_BOTTOM, THREAD_STACK_POOL_TOP)
            .with_tib_pool(TIB_POOL_BOTTOM, TIB_POOL_TOP)
            .with_child_arena(
                CHILD_IMAGE_BASE_START,
                CHILD_HEAP_POOL_START,
                CHILD_HEAP_POOL_END,
            );
        // Bootstrap thread's TIB lives at the runtime-owned
        // TEB_BASE (already mapped + seeded above) — mirror
        // its address into ThreadState so SetLastError /
        // GetLastError can also write through `fs:[0x34]`.
        if let Some(t) = host.threads.get_mut(&1) {
            t.tib_addr = TEB_BASE;
        }

        // Pre-register the system DLLs whose stub registries we
        // ship as "loaded modules". Real Windows always has these
        // available, and codec CRTs commonly probe them via
        // `GetModuleHandleW(L"KERNEL32.DLL")` before walking their
        // exports (e.g. lagarith's `_CRT_INIT` rolls back its heap
        // and bails if `KERNEL32.DLL`'s handle comes back NULL).
        // The handles are synthetic, distinct, non-zero values in
        // the otherwise-unmapped `0x7800_0000..0x7900_0000` band.
        // Codecs use these handles for identity comparisons and
        // as opaque arguments to `GetProcAddress`; the band is
        // clear of every other mapped region (heap, const arena,
        // TEB, stack, VirtualAlloc range, thunk space) so a
        // codec that tries to *walk* the handle as if it were a
        // PE image gets a clean `MemoryFault` rather than
        // accidentally hitting some other arena.
        for (i, dll) in [
            "kernel32.dll",
            "user32.dll",
            "gdi32.dll",
            "advapi32.dll",
            "ole32.dll",
            "shell32.dll",
            "shlwapi.dll",
            "comctl32.dll",
            "winmm.dll",
            "msvcrt.dll",
            "msvcr71.dll",
            "msvcr80.dll",
            "msvcr90.dll",
            "pncrt.dll",
            "mfplat.dll",
            "version.dll",
            "vfw32.dll",
        ]
        .iter()
        .enumerate()
        {
            let handle = 0x7800_0000u32.wrapping_add((i as u32) * 0x10_0000);
            host.modules.insert((*dll).to_string(), handle);
        }

        // Round 35 — pre-register the canonical DirectShow memory
        // allocator class factory in the in-process class-factory
        // cache.  Codecs that internally call
        // `CoCreateInstance(CLSID_MemoryAllocator, NULL, _,
        // IID_IMemAllocator, &alloc)` (e.g. mpg4ds32 from inside
        // `IMemInputPin::GetAllocator`) will now hit our host
        // factory rather than the round-34 baseline
        // `CLASS_E_CLASSNOTAVAILABLE` (`0x80040111`) miss.  CLSID
        // value sourced from Windows SDK header `axextend.h`.
        if let Ok(factory) =
            crate::com::mint_host_mem_allocator_class_factory(&mut host, &mut mmu, &mut registry)
        {
            host.com
                .register_class_factory(crate::com::CLSID_MEMORY_ALLOCATOR, factory);
        }

        Sandbox {
            mmu,
            cpu,
            registry,
            host,
            linux: crate::linux::LinuxKernel::default(),
            linux_machine: 0,
            aarch64: None,
        }
    }

    /// A bare sandbox for the **Linux** personality: a fresh empty MMU and
    /// CPU with none of the Win32 arenas / TEB / stub registry mapped. The
    /// ELF loader maps the program's own segments and stack; syscalls are
    /// serviced by [`Self::run_linux`].
    #[must_use]
    pub fn new_linux() -> Self {
        Sandbox {
            mmu: Mmu::new(),
            cpu: Cpu::new(),
            registry: Registry::new(),
            host: HostState::default(),
            linux: crate::linux::LinuxKernel::default(),
            linux_machine: 0,
            aarch64: None,
        }
    }

    /// Load a static Linux ELF executable: map its `PT_LOAD` segments and
    /// stack, prime the CPU (flat 32-bit, `esp`/`eip`), and initialise the
    /// kernel's process state. Ensures a [`VirtualFs`](crate::context::VirtualFs)
    /// is attached so file syscalls have somewhere to land.
    ///
    /// # Errors
    /// [`crate::Error::NeLoader`]-style wrapping of a
    /// [`crate::linux::loader::LoadError`] (bad ELF, dynamic, etc.).
    pub fn load_linux_elf(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<crate::linux::loader::ElfImage, crate::Error> {
        use ud_format::elf::{EM_386, EM_AARCH64, EM_X86_64};
        let argv = [name];
        let envp: [&str; 0] = [];
        let image = crate::linux::loader::load_static(&mut self.mmu, bytes, &argv, &envp)
            .map_err(|e| crate::Error::NeLoader(e.to_string()))?;
        self.linux_machine = image.machine;
        match image.machine {
            EM_X86_64 => {
                // x86-64 long mode on the shared x86 CPU.
                self.cpu.set_code16(false);
                self.cpu.set_long64(true);
                self.cpu.regs.gp64 = [0; 16];
                self.cpu.regs.gp64[4] = u64::from(image.stack_ptr); // rsp
                self.cpu.regs.rip = u64::from(image.entry);
            }
            EM_AARCH64 => {
                let mut cpu = Box::new(crate::emulator::aarch64::Aarch64Cpu::new());
                cpu.sp = u64::from(image.stack_ptr);
                cpu.pc = u64::from(image.entry);
                self.aarch64 = Some(cpu);
            }
            // EM_386 and anything else default to the 32-bit path.
            _ => {
                debug_assert_eq!(image.machine, EM_386);
                self.cpu.set_code16(false);
                self.cpu.set_long64(false);
                self.cpu.regs.set_esp(image.stack_ptr);
                self.cpu.regs.eip = image.entry;
            }
        }
        self.linux.init(image.brk);
        self.host
            .context
            .vfs
            .get_or_insert_with(crate::context::VirtualFs::new);
        Ok(image)
    }

    /// Run the loaded Linux program until it calls `exit`/`exit_group`,
    /// faults, or hits the instruction budget. Returns the exit code.
    /// Captured stdout/stderr and any unsupported syscalls live in
    /// `self.linux`.
    ///
    /// # Errors
    /// [`crate::Error::Trap`] for a CPU fault that isn't the syscall gate.
    pub fn run_linux(&mut self) -> Result<i32, crate::Error> {
        use ud_format::elf::{EM_AARCH64, EM_X86_64};
        let mut vfs = self
            .host
            .context
            .vfs
            .take()
            .unwrap_or_else(crate::context::VirtualFs::new);
        let result = match self.linux_machine {
            EM_X86_64 => self.run_linux_amd64(&mut vfs),
            EM_AARCH64 => self.run_linux_aarch64(&mut vfs),
            _ => self.run_linux_i386(&mut vfs),
        };
        self.host.context.vfs = Some(vfs);
        result
    }

    /// i386 run loop: services the `int 0x80` gate via [`I386Abi`].
    fn run_linux_i386(&mut self, vfs: &mut crate::context::VirtualFs) -> Result<i32, crate::Error> {
        use crate::emulator::isa_int::StepOk;
        use crate::emulator::Trap;
        let abi = crate::linux::abi::I386Abi;
        let budget = self.host.instruction_budget.unwrap_or(u64::MAX);
        loop {
            if self.cpu.instr_count >= budget {
                break Ok(self.linux.exit_code.unwrap_or(-1));
            }
            match self.cpu.step(&mut self.mmu) {
                Ok(StepOk::Continued) => {}
                Ok(StepOk::Halted) => break Ok(self.linux.exit_code.unwrap_or(0)),
                Err(Trap::SoftwareInterrupt { num: 0x80, .. }) => {
                    self.linux.dispatch(&abi, &mut self.cpu, &mut self.mmu, vfs);
                    if let Some(code) = self.linux.exit_code {
                        break Ok(code);
                    }
                }
                Err(t) => break Err(crate::Error::Trap(t)),
            }
        }
    }

    /// x86-64 run loop: steps the long-mode CPU and services the `syscall`
    /// gate ([`Trap::Syscall`]) via [`Amd64Abi`].
    fn run_linux_amd64(
        &mut self,
        vfs: &mut crate::context::VirtualFs,
    ) -> Result<i32, crate::Error> {
        use crate::emulator::isa_int::StepOk;
        use crate::emulator::Trap;
        let abi = crate::linux::abi::Amd64Abi;
        let budget = self.host.instruction_budget.unwrap_or(u64::MAX);
        let trace = std::env::var("UD_LINUX_TRACE").is_ok();
        loop {
            if self.cpu.instr_count >= budget {
                break Ok(self.linux.exit_code.unwrap_or(-1));
            }
            let rip = self.cpu.regs.rip;
            match self.cpu.step(&mut self.mmu) {
                Ok(StepOk::Continued) => {}
                Ok(StepOk::Halted) => break Ok(self.linux.exit_code.unwrap_or(0)),
                Err(Trap::Syscall { .. }) => {
                    self.linux.dispatch(&abi, &mut self.cpu, &mut self.mmu, vfs);
                    if let Some(code) = self.linux.exit_code {
                        break Ok(code);
                    }
                }
                Err(t) => {
                    if trace {
                        eprintln!(
                            "amd64 trap at rip={rip:#018x} (#{}): {t}",
                            self.cpu.instr_count
                        );
                    }
                    break Err(crate::Error::Trap(t));
                }
            }
        }
    }

    /// aarch64 run loop: steps the [`Aarch64Cpu`] and services the `svc`
    /// gate ([`Trap::Syscall`]) via [`Aarch64Abi`].
    fn run_linux_aarch64(
        &mut self,
        vfs: &mut crate::context::VirtualFs,
    ) -> Result<i32, crate::Error> {
        use crate::emulator::isa_int::StepOk;
        use crate::emulator::Trap;
        let abi = crate::linux::abi::Aarch64Abi;
        let budget = self.host.instruction_budget.unwrap_or(u64::MAX);
        let Some(cpu) = self.aarch64.as_mut() else {
            return Err(crate::Error::NeLoader("no aarch64 CPU loaded".into()));
        };
        loop {
            if cpu.instr_count >= budget {
                break Ok(self.linux.exit_code.unwrap_or(-1));
            }
            match cpu.step(&mut self.mmu) {
                Ok(StepOk::Continued) => {}
                Ok(StepOk::Halted) => break Ok(self.linux.exit_code.unwrap_or(0)),
                Err(Trap::Syscall { .. }) => {
                    self.linux.dispatch(&abi, cpu.as_mut(), &mut self.mmu, vfs);
                    if let Some(code) = self.linux.exit_code {
                        break Ok(code);
                    }
                }
                Err(t) => break Err(crate::Error::Trap(t)),
            }
        }
    }

    /// Builder-style seed setter for the `msvcrt!rand` LCG.
    ///
    /// PRNG state for `msvcrt!rand` calls from sandboxed codec
    /// code.  Default `1` matches MSVC's documented "no `srand`
    /// called yet" initial value.  Set via `with_rand_seed` /
    /// `set_rand_seed` for reproducible encode output: two
    /// sandboxes seeded identically produce identical `rand`
    /// sequences, which makes encode regression tests
    /// deterministic across runs.
    ///
    /// The guest's own `msvcrt!srand(seed)` call writes to the
    /// same field, so the codec may re-seed at any time; in that
    /// case [`Self::rand_seed`] will report whatever value the
    /// codec last installed.
    ///
    /// Round 55.
    pub fn with_rand_seed(mut self, seed: u32) -> Self {
        self.host.rand_state = seed;
        self
    }

    /// Set the `msvcrt!rand` LCG state at runtime.
    ///
    /// Same contract as [`Self::with_rand_seed`], but mutates an
    /// already-constructed sandbox — useful for tests that drive
    /// multiple encode runs with different seeds, or for fuzzing
    /// harnesses that want to force the codec into a known state
    /// before each iteration.
    ///
    /// Round 55.
    pub fn set_rand_seed(&mut self, seed: u32) {
        self.host.rand_state = seed;
    }

    /// Override the value `kernel32!GetCommandLineA` returns to
    /// the guest. The string is stashed (NUL-terminated) in the
    /// host's const arena and a pointer to it is parked at
    /// `command_line_ptr`. Installer-class binaries consult
    /// this to pick up `/quiet`, `/qn`, `/S` and similar
    /// silent-install flags.
    pub fn set_command_line(&mut self, cmdline: &str) -> Result<(), crate::Error> {
        let mut bytes = cmdline.as_bytes().to_vec();
        bytes.push(0);
        let addr = self
            .host
            .arena_const_alloc(bytes.len() as u32)
            .map_err(crate::Error::Win32)?;
        self.mmu.write_initializer(addr, &bytes)?;
        self.host.command_line_ptr = addr;
        Ok(())
    }

    /// Read the current `msvcrt!rand` LCG state.
    ///
    /// Reflects whatever the host or the guest last wrote: a
    /// fresh sandbox returns `1` (MSVC's documented "no `srand`
    /// called yet" initial value); after host
    /// [`Self::set_rand_seed`] / [`Self::with_rand_seed`] returns
    /// that value; after a guest `msvcrt!srand(s)` call returns
    /// `s`; after any number of `msvcrt!rand` calls returns the
    /// post-step LCG state.
    ///
    /// Round 55.
    pub fn rand_seed(&self) -> u32 {
        self.host.rand_state
    }

    /// Load a PE32 image from `bytes`, mapping it into the
    /// sandbox's MMU. The returned [`Image`] holds the entry
    /// point + export table.
    ///
    /// Strict-resolution: any IAT entry the
    /// [`crate::win32::Registry`] doesn't satisfy is a hard
    /// load-time error. Use [`Sandbox::load_fail_soft`] for
    /// EXEs whose import list exceeds the codec-class stub
    /// surface (installers, GUI apps, etc.).
    pub fn load(&mut self, name: &str, bytes: &[u8]) -> Result<Image, crate::Error> {
        let mut loader = Loader::new(&mut self.mmu, &mut self.registry, &mut self.host);
        let img = loader.load(name, bytes)?;
        // Record primary module base so `GetModuleHandleA(NULL)`
        // returns the right value.
        self.host.primary_module_base = img.image_base;
        // Also record the loaded module under its filename so
        // `GetModuleHandleA("name.dll")` finds it. Lower-cased,
        // matching the lookup in `stub_get_module_handle_a` /
        // `_w`.
        self.host
            .modules
            .insert(name.to_ascii_lowercase(), img.image_base);
        // Cache exports for later re-resolution (e.g. the MSI
        // CustomAction pump that loads a Binary-table DLL once
        // then dispatches multiple named entries against the
        // same image).
        self.host
            .loaded_dll_exports
            .insert(img.image_base, img.exports.clone());
        Ok(img)
    }

    /// VFS-DLL fallback load: walk the primary PE's import
    /// directory, look up every dependent DLL the host stub
    /// registry doesn't know about in the sandbox VFS, and
    /// (recursively) load each one at a fresh image base
    /// before loading the primary. The dependent DLL's exports
    /// are registered in the [`Registry`] so subsequent IAT
    /// resolution against the primary picks them up. Each
    /// dependent's `DllMain(PROCESS_ATTACH)` is invoked after
    /// it loads (best-effort: any trap is recorded in
    /// `host.debug_log` and the load continues).
    ///
    /// Returns the primary [`Image`] plus the list of
    /// `(dll, name)` import pairs that *still* resolved to a
    /// fail-soft trap thunk after all VFS deps were loaded.
    /// These name the missing host-side APIs (e.g. CoreVideo
    /// internals we haven't shimmed) that the next iteration
    /// of stub work would target.
    ///
    /// Cycle-safe: a `currently_loading` set prevents A→B→A
    /// from looping. Search order for a dependent DLL is the
    /// list returned by [`crate::win32::dll_vfs_search_paths`].
    pub fn load_with_deps(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(Image, Vec<(String, String)>), crate::Error> {
        let mut loading: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        loading.insert(name.to_ascii_lowercase());
        self.preload_deps(bytes, &mut loading)?;
        loading.remove(&name.to_ascii_lowercase());
        // Now load the primary in fail-soft. If the PE's
        // preferred image base collides with something already
        // mapped (very common for Apple binaries that all hard-
        // code 0x10000000 / 0x66800000), force a rebased load
        // at a fresh slot from next_dll_image_base — otherwise
        // map_sections_at would overwrite the prior occupant's
        // sections, breaking the previously loaded module.
        let parsed = crate::pe::header::parse(bytes)?;
        let preferred = parsed.optional.image_base;
        let image_size = parsed.optional.size_of_image;
        if !self.mmu.region_is_unmapped(preferred, image_size) {
            let aligned = (image_size + 0xFFFF) & !0xFFFF;
            let base = self.host.next_dll_image_base;
            self.host.next_dll_image_base = base.saturating_add(aligned);
            let mut options = crate::pe::LoadOptions {
                imports: crate::pe::imports::ResolveMode::FailSoft,
                fail_soft_log: Some(Vec::new()),
                target_image_base: Some(base),
            };
            let mut loader = Loader::new(&mut self.mmu, &mut self.registry, &mut self.host);
            let img = loader.load_with_options(name, bytes, &mut options)?;
            self.host.primary_module_base = img.image_base;
            self.host
                .modules
                .insert(name.to_ascii_lowercase(), img.image_base);
            // Register exports against the canonical name so
            // GetProcAddress + IAT lookups resolve.
            for (export_name, rva) in &img.exports {
                self.registry.register_guest_export(
                    name,
                    export_name,
                    img.image_base.wrapping_add(*rva),
                );
            }
            self.host
                .loaded_dll_exports
                .insert(img.image_base, img.exports.clone());
            return Ok((img, options.fail_soft_log.unwrap_or_default()));
        }
        self.load_fail_soft(name, bytes)
    }

    /// Recursive helper: walk `bytes`'s import directory, for
    /// each not-yet-loaded, non-stub DLL look it up in the VFS,
    /// load it at a fresh image base in fail-soft mode, register
    /// its exports, then invoke its `DllMain(PROCESS_ATTACH)`.
    fn preload_deps(
        &mut self,
        bytes: &[u8],
        loading: &mut std::collections::BTreeSet<String>,
    ) -> Result<(), crate::Error> {
        use crate::pe;
        let parsed = match pe::header::parse(bytes) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let imported = pe::imports::list_imported_dlls(&parsed, bytes).unwrap_or_default();
        for dll in imported {
            let dll_lc = dll.to_ascii_lowercase();
            if loading.contains(&dll_lc) {
                continue; // cycle — already on the load stack
            }
            if crate::win32::is_host_stub_dll(&dll_lc) {
                continue; // kernel32 / user32 / etc. are stubbed
            }
            if self.host.modules.contains_key(&dll_lc) {
                continue; // already loaded
            }
            // Look up in VFS.
            let bytes_dep = {
                let vfs = match self.host.context.vfs.as_ref() {
                    Some(v) => v,
                    None => continue,
                };
                let mut found: Option<Vec<u8>> = None;
                for prefix in crate::win32::dll_vfs_search_paths() {
                    let p = format!("{prefix}{dll_lc}");
                    if let Some(b) = vfs.read(&p) {
                        found = Some(b.to_vec());
                        break;
                    }
                }
                match found {
                    Some(b) => b,
                    None => continue,
                }
            };
            // Recurse before loading this one — DFS order.
            loading.insert(dll_lc.clone());
            self.preload_deps(&bytes_dep, loading)?;
            // Prefer the PE's preferred image base when it's
            // free — relocations can subtly break codecs that
            // store absolute addresses in spots the .reloc
            // table doesn't cover (Apple's QT framework code
            // does this in a couple of spots). If the preferred
            // base would collide with something already mapped,
            // fall back to a fresh slot from next_dll_image_base.
            let parsed_dep = pe::header::parse(&bytes_dep)?;
            let preferred = parsed_dep.optional.image_base;
            let image_size = parsed_dep.optional.size_of_image;
            let aligned = (image_size + 0xFFFF) & !0xFFFF;
            let preferred_free = self.mmu.region_is_unmapped(preferred, image_size);
            let base = if preferred_free {
                preferred
            } else {
                let b = self.host.next_dll_image_base;
                self.host.next_dll_image_base = b.saturating_add(aligned);
                b
            };
            let mut options = pe::LoadOptions {
                imports: pe::imports::ResolveMode::FailSoft,
                fail_soft_log: Some(Vec::new()),
                target_image_base: Some(base),
            };
            let mut loader = Loader::new(&mut self.mmu, &mut self.registry, &mut self.host);
            let img = match loader.load_with_options(&dll_lc, &bytes_dep, &mut options) {
                Ok(i) => i,
                Err(e) => {
                    self.host
                        .debug_log
                        .push(format!("vfs-dll {dll_lc}: load failed: {e}"));
                    loading.remove(&dll_lc);
                    continue;
                }
            };
            // Register the dep's exports so the primary's IAT
            // can patch through. Same dll-name normalisation
            // the import resolver uses.
            for (export_name, rva) in &img.exports {
                let addr = img.image_base.wrapping_add(*rva);
                self.registry
                    .register_guest_export(&dll_lc, export_name, addr);
            }
            self.host
                .loaded_dll_exports
                .insert(img.image_base, img.exports.clone());
            self.host.modules.insert(dll_lc.clone(), img.image_base);
            self.host
                .debug_log
                .push(format!("vfs-dll {dll_lc}: loaded at {base:#010x}"));
            // Invoke DllMain. Skip data-only DLLs (no DllMain
            // export AND AddressOfEntryPoint == 0 — common for
            // ICU resource bundles and similar). Errors from
            // dep DllMain don't abort the parent load: most QT
            // codecs reach their Component Manager entry without
            // ever calling the framework DLL's TLS-touching
            // init paths, so a half-init dep is often workable.
            let has_dll_main = img.exports.contains_key("DllMain");
            let has_entry = parsed_dep.optional.address_of_entry_point != 0;
            if has_dll_main || has_entry {
                if let Err(e) = self.call_dll_main(&img, DLL_PROCESS_ATTACH) {
                    self.host
                        .debug_log
                        .push(format!("vfs-dll {dll_lc}: DllMain trapped: {e}"));
                }
            } else {
                self.host
                    .debug_log
                    .push(format!("vfs-dll {dll_lc}: data-only DLL, no DllMain"));
            }
            loading.remove(&dll_lc);
        }
        Ok(())
    }

    /// Load a PE32 image in fail-soft import-resolution mode.
    /// Imports the codec-class stub registry doesn't satisfy
    /// get a trap-on-call fallback thunk so the load succeeds.
    /// Returns the loaded [`Image`] plus the list of
    /// `(dll, name)` pairs that received a fallback — i.e.
    /// the set of APIs the operator now knows the binary uses
    /// but we don't yet stub.
    ///
    /// Intended for the install-monitor workflow: load
    /// QuickTimeInstaller.exe with fail-soft, drive the entry
    /// point, watch the trap stream for the next missing API.
    pub fn load_fail_soft(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<(Image, Vec<(String, String)>), crate::Error> {
        let mut options = crate::pe::LoadOptions {
            imports: crate::pe::imports::ResolveMode::FailSoft,
            fail_soft_log: Some(Vec::new()),
            target_image_base: None,
        };
        let mut loader = Loader::new(&mut self.mmu, &mut self.registry, &mut self.host);
        let img = loader.load_with_options(name, bytes, &mut options)?;
        self.host.primary_module_base = img.image_base;
        self.host
            .modules
            .insert(name.to_ascii_lowercase(), img.image_base);
        // Cache exports so re-resolution against the loaded DLL
        // (MSI CA pump, multiple GetProcAddress lookups) finds
        // them.
        self.host
            .loaded_dll_exports
            .insert(img.image_base, img.exports.clone());
        Ok((img, options.fail_soft_log.unwrap_or_default()))
    }

    /// Synchronously call `DllMain(hModule, fdwReason, lpvReserved)`
    /// inside the emulator and return the dword `eax` value at
    /// the point the function returned to the synthetic
    /// `RET_SENTINEL`.
    ///
    /// The DllMain ABI is stdcall (callee-cleanup), so we push
    /// `lpvReserved` first, then `fdwReason`, then `hModule`,
    /// then the return-address sentinel. The callee's `RET 12`
    /// (or equivalent) cleans the args.
    ///
    /// Resolution: prefer the `DllMain` named export (Indeo
    /// codecs); fall back to the PE `AddressOfEntryPoint`
    /// (mpg4c32.dll and other CRT-startup-driven DLLs that
    /// don't export `DllMain` by name). Both expose the same
    /// stdcall (HINSTANCE, DWORD, LPVOID) ABI.
    pub fn call_dll_main(&mut self, image: &Image, reason: u32) -> Result<u32, crate::Error> {
        let h_module = image.image_base;
        let lpv_reserved = 0u32;
        // Always prefer the PE `AddressOfEntryPoint` for DLLs: the
        // OS loader calls THAT (typically `_DllMainCRTStartup`, the
        // linker-generated wrapper) and it in turn runs the CRT
        // init (_CRT_INIT / _initterm) before invoking the user's
        // DllMain. Some DLLs additionally *export* a function
        // literally named "DllMain" — qts does — but that's the
        // bare user function, NOT the CRT wrapper. Calling it
        // directly bypasses CRT init: FLS/TLS slot allocation,
        // env block setup, etc., never run, and downstream
        // qtmlclient!EnterMovies spins in an infinite
        // `_getptd()` retry loop hitting `TlsGetValue(TLS_OUT_OF_INDEXES)`.
        // Fall back to a `DllMain` export only when the PE has
        // no entry point at all (rare; old hand-written DLLs).
        let target = if image.entry_point != 0 {
            image.entry_point
        } else {
            image.export("DllMain").unwrap_or(0)
        };
        if target == 0 {
            return Err(crate::Error::Win32(
                crate::win32::Win32Error::InvalidArgument {
                    stub: "call_dll_main",
                    reason: format!(
                        "no DllMain export and no PE entry point in {:?}",
                        image.name
                    ),
                },
            ));
        }
        call_guest(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            target,
            &[h_module, reason, lpv_reserved],
        )
    }

    /// Pump any deferred MSI CustomActions that the msiexec
    /// walker queued during a previous `CreateProcessA(msiexec.exe)`
    /// dispatch. For each pending DLL CA: load the Binary-table
    /// DLL bytes into the sandbox at a fresh image base, set
    /// up an `MsiSession` so the msi.dll stubs can answer
    /// property queries against the walker's snapshot, and
    /// call the CA's named export with `MSIHANDLE = 1`.
    /// EXE / script CAs are logged + skipped (unsupported).
    ///
    /// Returns the number of CAs successfully executed (CAs
    /// that trapped or returned non-zero are counted as
    /// attempted; the failure is captured in `host.debug_log`).
    pub fn pump_pending_msi_install(&mut self) -> usize {
        let Some(pending) = self.host.pending_msi_install.take() else {
            return 0;
        };
        // Set up the in-process MSI session with our property
        // snapshot. The MSIHANDLE is just an opaque token; we
        // use 1 since there's at most one install at a time.
        self.host.msi_session = Some(crate::win32::MsiSession {
            handle: 1,
            properties: pending.properties.clone(),
            target_paths: pending
                .properties
                .iter()
                .filter(|(k, _)| k.chars().next().is_some_and(char::is_uppercase))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        });
        let mut executed = 0;
        for ca in pending.actions {
            // Only DLL CAs of type 1 (immediate) / 0xC01 (deferred)
            // and similar in-process DLL shapes are runnable here.
            let kind = ca.action_type & 0x3F;
            if kind != 1 && kind != 17 {
                self.host.debug_log.push(format!(
                    "msiexec CA {:?}: skipped, type {:#x} (kind {:#x}) not a DLL CA",
                    ca.name, ca.action_type, kind
                ));
                continue;
            }
            // For kind == 1 the Source column is a Binary-table
            // key, for kind == 17 it's a File-table key. We
            // only have Binary streams cached here.
            let Some(bytes) = pending.binaries.get(&ca.source).cloned() else {
                self.host.debug_log.push(format!(
                    "msiexec CA {:?}: Binary {:?} not in table, skipping",
                    ca.name, ca.source
                ));
                continue;
            };
            // Load the DLL at a fresh image base. We register
            // the loaded bytes against `ca.source` so subsequent
            // CAs that reference the same binary share the load.
            let dll_key = ca.source.to_ascii_lowercase();
            let img = if let Some(&base) = self.host.modules.get(&dll_key) {
                // Already loaded — synthesise an Image from the
                // cached exports.
                let exports = self
                    .host
                    .loaded_dll_exports
                    .get(&base)
                    .cloned()
                    .unwrap_or_default();
                crate::pe::Image {
                    name: ca.source.clone(),
                    image_base: base,
                    entry_point: base,
                    size_of_image: 0,
                    sections: Vec::new(),
                    exports,
                }
            } else {
                // Install-time DLLs (QTInstallCode, QTMSISupport,
                // SxsUninstallCA, AppleApplicationSupport_CustomActions)
                // share Apple's standard 0x10000000 preferred base.
                // If we let them grab that, qtmlclient.dll has to
                // rebase later and its absolute-addressed
                // dispatcher slots break. Force-rebase install
                // DLLs to next_dll_image_base so the preferred
                // base stays free for the post-install runtime
                // bring-up.
                let parsed = match crate::pe::header::parse(&bytes) {
                    Ok(p) => p,
                    Err(e) => {
                        self.host.debug_log.push(format!(
                            "msiexec CA {:?}: parse {:?} failed: {e}",
                            ca.name, ca.source
                        ));
                        continue;
                    }
                };
                let image_size = parsed.optional.size_of_image;
                let aligned = (image_size + 0xFFFF) & !0xFFFF;
                let install_base = self.host.next_dll_image_base;
                self.host.next_dll_image_base = install_base.saturating_add(aligned);
                let mut options = crate::pe::LoadOptions {
                    imports: crate::pe::imports::ResolveMode::FailSoft,
                    fail_soft_log: Some(Vec::new()),
                    target_image_base: Some(install_base),
                };
                let mut loader = Loader::new(&mut self.mmu, &mut self.registry, &mut self.host);
                let img = match loader.load_with_options(&ca.source, &bytes, &mut options) {
                    Ok(i) => i,
                    Err(e) => {
                        self.host.debug_log.push(format!(
                            "msiexec CA {:?}: load {:?} failed: {e}",
                            ca.name, ca.source
                        ));
                        continue;
                    }
                };
                self.host.primary_module_base = img.image_base;
                self.host
                    .modules
                    .insert(ca.source.to_ascii_lowercase(), img.image_base);
                self.host
                    .loaded_dll_exports
                    .insert(img.image_base, img.exports.clone());
                for (name, rva) in &img.exports {
                    self.registry.register_guest_export(
                        &ca.source,
                        name,
                        img.image_base.wrapping_add(*rva),
                    );
                }
                // Best-effort DllMain.
                if let Err(e) = self.call_dll_main(&img, crate::DLL_PROCESS_ATTACH) {
                    self.host.debug_log.push(format!(
                        "msiexec CA {:?}: {} DllMain trapped: {e}",
                        ca.name, ca.source
                    ));
                }
                img
            };
            let Some(rva) = img.exports.get(&ca.target).copied() else {
                self.host.debug_log.push(format!(
                    "msiexec CA {:?}: export {:?} not in {:?}",
                    ca.name, ca.target, ca.source
                ));
                continue;
            };
            let entry = img.image_base.wrapping_add(rva);
            // Call the CA's entry with MSIHANDLE = 1.
            self.host.debug_log.push(format!(
                "msiexec CA {:?}: calling {:?}({:?})",
                ca.name, ca.target, 1
            ));
            // Clear sticky exit_requested from the prior CA's
            // TerminateProcess / ExitProcess so the next
            // run_until_sentinel doesn't bail immediately.
            self.host.exit_requested = None;
            match crate::win32::call_guest(
                &mut self.cpu,
                &mut self.mmu,
                &mut self.registry,
                &mut self.host,
                entry,
                &[1],
            ) {
                Ok(rc) => {
                    let signed = rc as i32;
                    self.host.debug_log.push(format!(
                        "msiexec CA {:?}: {:?} returned {rc:#x} ({signed})",
                        ca.name, ca.target
                    ));
                    executed += 1;
                }
                Err(e) => {
                    self.host.debug_log.push(format!(
                        "msiexec CA {:?}: {:?} trapped: {e}",
                        ca.name, ca.target
                    ));
                }
            }
        }
        self.host.msi_session = None;
        executed
    }

    /// Generic stdcall guest-call helper. Resolves `name` against
    /// `image`'s export table, pushes `args` right-to-left + the
    /// `RET_SENTINEL`, and runs until the callee returns.
    /// Returns `eax`.
    ///
    /// Used both internally (by [`Self::call_dll_main`]) and by
    /// future codec adapter layers that need to drive arbitrary
    /// codec exports — `DriverProc`, `MyCodecGetVersion`,
    /// `MyCodecExtraInit`, etc. The round-2 `vfw32::ic_*` host
    /// surface uses [`crate::win32::call_guest`] directly with
    /// the codec's `DriverProc` VA.
    pub fn call_export(
        &mut self,
        image: &Image,
        name: &str,
        args: &[u32],
    ) -> Result<u32, crate::Error> {
        let target = image.export(name).ok_or_else(|| {
            crate::Error::Win32(crate::win32::Win32Error::InvalidArgument {
                stub: "call_export",
                reason: format!("export {name:?} not found in {:?}", image.name),
            })
        })?;
        call_guest(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            target,
            args,
        )
    }

    /// Call the image's PE entry point (`AddressOfEntryPoint`).
    /// For an EXE this is the CRT startup, which expects no
    /// arguments and never returns under normal Windows
    /// semantics (it calls `ExitProcess`). Here it runs until
    /// the runtime returns to the synthetic `RET_SENTINEL` or
    /// hits a trap (e.g. unresolved import, instruction limit).
    pub fn call_entry_point(&mut self, image: &Image) -> Result<u32, crate::Error> {
        if image.entry_point == 0 {
            return Err(crate::Error::Win32(
                crate::win32::Win32Error::InvalidArgument {
                    stub: "call_entry_point",
                    reason: format!("no PE entry point in {:?}", image.name),
                },
            ));
        }
        call_guest(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            image.entry_point,
            &[],
        )
    }

    /// Load a 16-bit Windows NE module in fail-soft mode: every
    /// imported ordinal is wired to a trap-on-call thunk, so the run
    /// stops at the first Win16 API the stub surface doesn't cover
    /// (the NE analogue of [`Self::load_fail_soft`]). Returns the
    /// [`crate::ne::NeImage`] describing how to enter it.
    ///
    /// # Errors
    /// Returns [`crate::Error::NeLoader`] if the bytes are not a valid
    /// NE or a segment fails to map.
    pub fn load_ne_fail_soft(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<crate::ne::NeImage, crate::Error> {
        // Register the Win16 API stub surface so the loader's
        // relocation pass resolves known ordinals (KERNEL.91, …) to
        // real stubs and only falls back to trap-on-call for the rest.
        crate::win16::register_all(&mut self.registry);
        let image = crate::ne::load_ne(&mut self.mmu, &mut self.registry, bytes)
            .map_err(|e| crate::Error::NeLoader(e.to_string()))?;
        self.host
            .modules
            .insert(name.to_ascii_lowercase(), crate::ne::WIN16_SEG_BASE);
        // Stage the module's own bytes in the VFS at the path
        // GetModuleFileName reports (C:\SITEX10.EXE), so an installer that
        // opens and reads itself (to copy its payload out by file offset)
        // sees the real image rather than an empty file. Gated: with the
        // real bytes present the installer's *file-based* integrity check
        // runs (and currently faults), so only do this when explicitly
        // driving the install — the default path keeps reaching the dialog.
        if std::env::var("UD_NE_PATCH_TAMPER").is_ok() {
            self.host
                .context
                .vfs
                .get_or_insert_with(Default::default)
                .write_path("C:\\SITEX10.EXE", bytes.to_vec());
        }
        // Parse string + general resources for LoadString / FindResource.
        if let Ok(ne) = ud_format::ne::NeFile::parse(bytes) {
            self.host.string_resources = ne.string_resources();
            self.host.resources = ne
                .resources()
                .into_iter()
                .map(|r| {
                    let off = r.file_offset as usize;
                    let len = r.length as usize;
                    let data = bytes.get(off..off + len).unwrap_or(&[]).to_vec();
                    crate::win16::LoadedResource {
                        type_id: r.type_id,
                        name_id: r.name_id,
                        data,
                    }
                })
                .collect();
        }
        // SITEX10's installer runs a self-integrity / anti-tamper check
        // early in InitInstance that CRCs its own loaded segments and
        // compares against stored values; our memory layout (synthetic
        // import selectors patched in by relocation) can never match, so it
        // aborts with "This copy of Setup has been changed without
        // authorization". With UD_NE_PATCH_TAMPER=1, redirect the two
        // leading `jnz <err>` (75 05) of the verify routine (seg2:0x2e01,
        // 0x2e21) to their pass targets so the check succeeds. In-memory
        // only — the on-disk file is untouched.
        if std::env::var("UD_NE_PATCH_TAMPER").is_ok() {
            let seg2 = crate::ne::WIN16_SEG_BASE + crate::ne::WIN16_SEG_STRIDE;
            for (off, rel) in [(0x2e01u32, 0x14u8), (0x2e21, 0x29)] {
                let lin = seg2 + off;
                if self.mmu.load8(lin) == Ok(0x75) {
                    let _ = self.mmu.store8(lin, 0xEB);
                    let _ = self.mmu.store8(lin + 1, rel);
                }
            }
        }
        Ok(image)
    }

    /// Drive a loaded NE module's entry point in 16-bit segmented
    /// mode. Primes the CPU's selectors, `CS:IP`, `SS:SP` and DGROUP
    /// data segments from `image`, pushes a far-return sentinel, then
    /// runs until the entry returns or — in fail-soft mode — traps at
    /// the first imported Win16 call. Mirrors [`Self::call_entry_point`].
    ///
    /// # Errors
    /// Propagates any CPU trap (including the fail-soft
    /// [`crate::emulator::Trap::UnresolvedImport`] that marks the first
    /// unimplemented Win16 API).
    pub fn call_ne_entry(&mut self, image: &crate::ne::NeImage) -> Result<u32, crate::Error> {
        use crate::emulator::isa_int::{Seg, RET_SENTINEL};
        use crate::emulator::regs::Reg32;

        // Enter 16-bit segmented mode and install the selector table.
        self.cpu.set_code16(true);
        for &(sel, base) in &image.selectors {
            self.cpu.define_selector(sel, base);
        }
        // Far-return sentinel selector → RET_SENTINEL linear address.
        self.cpu
            .define_selector(crate::ne::SENTINEL_SELECTOR, RET_SENTINEL);

        // Initial stack, then push a far-return sentinel (CS:IP) so a
        // top-level RETF halts the run loop.
        self.cpu.set_ss_sp(image.init_ss, image.init_sp);
        self.cpu
            .push16(&mut self.mmu, crate::ne::SENTINEL_SELECTOR)?;
        self.cpu.push16(&mut self.mmu, 0)?;

        // DGROUP: DS/ES point at the automatic data segment.
        if image.auto_data != 0 {
            self.cpu.load_segment(Seg::Ds, image.auto_data);
            self.cpu.load_segment(Seg::Es, image.auto_data);
        }
        self.cpu.set_cs_ip(image.entry_cs, image.entry_ip);

        // Reset the bootstrap thread to a clean runnable state — the
        // same hygiene `call_guest` applies before a top-level entry.
        if self.host.active_tid == 1 {
            let quantum = self.host.scheduler.quantum_default;
            let t = self.host.cur_thread_mut();
            t.status = crate::sched::ThreadStatus::Ready;
            t.wait = None;
            t.quantum_remaining = quantum;
        }
        self.host.exit_requested = None;

        run_until_sentinel_free(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
        )?;
        Ok(self.cpu.regs.get32(Reg32::Eax))
    }

    /// Drive the CPU until `eip == RET_SENTINEL`, dispatching to
    /// Win32 stubs whenever `eip` lands on a registered thunk
    /// address. Thin wrapper over [`crate::win32::run_until_sentinel`]
    /// kept for API stability.
    pub fn run_until_sentinel(&mut self) -> Result<(), crate::Error> {
        run_until_sentinel_free(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
        )
    }

    // ---- vfw32 IC* convenience wrappers ------------------------------

    /// Mark `image` as the codec the next [`Self::ic_open`] call
    /// should target.
    ///
    /// Round 2 supports a single codec image per sandbox — round 3
    /// will lift that into a multi-codec registry. The image must
    /// export `DriverProc`.
    pub fn install_codec(&mut self, image: &Image) -> Result<(), crate::Error> {
        let dp = image.export("DriverProc").ok_or_else(|| {
            crate::Error::Win32(crate::win32::Win32Error::InvalidArgument {
                stub: "install_codec",
                reason: format!("DriverProc not exported by {:?}", image.name),
            })
        })?;
        self.host.default_driver_proc = dp;
        Ok(())
    }

    /// Open the installed codec (`DRV_OPEN`).
    pub fn ic_open(
        &mut self,
        fcc_type: u32,
        fcc_handler: u32,
        mode: u32,
    ) -> Result<u32, crate::Error> {
        vfw32::ic_open(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            fcc_type,
            fcc_handler,
            mode,
        )
    }

    /// Close a codec instance (`DRV_CLOSE`).
    pub fn ic_close(&mut self, hic: u32) -> Result<u32, crate::Error> {
        vfw32::ic_close(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
        )
    }

    /// Read the codec's `ICINFO` block.
    pub fn ic_get_info(&mut self, hic: u32, cb: u32) -> Result<Vec<u8>, crate::Error> {
        vfw32::ic_get_info(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            cb,
        )
    }

    /// `ICDecompressQuery` — does the codec accept this format?
    pub fn ic_decompress_query(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
        output: Option<&vfw32::Bih>,
    ) -> Result<u32, crate::Error> {
        vfw32::ic_decompress_query(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
            output,
        )
    }

    /// `ICDecompressGetFormat` — ask the codec for the output BIH
    /// matching `input`. Round 30 uses this to probe stream
    /// dimensions when `CodecParameters` lacks them.
    pub fn ic_decompress_get_format(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
    ) -> Result<(u32, vfw32::Bih), crate::Error> {
        vfw32::ic_decompress_get_format(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
        )
    }

    /// `ICDecompressBegin` — set up the decoder pipeline.
    pub fn ic_decompress_begin(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
        output: &vfw32::Bih,
    ) -> Result<u32, crate::Error> {
        vfw32::ic_decompress_begin(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
            output,
        )
    }

    /// `ICDecompressEnd` — tear down the decoder pipeline.
    pub fn ic_decompress_end(&mut self, hic: u32) -> Result<u32, crate::Error> {
        vfw32::ic_decompress_end(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
        )
    }

    // ---- Trace-mode programmatic API (gated on the `trace`
    // ---- Cargo feature). Documented in
    // ---- `docs/winmf/winmf-emulator.md` §"Trace mode".

    /// Install a memory watchpoint covering `[addr, addr+size)`.
    /// Any guest access whose address range intersects the
    /// watchpoint emits a `kind=mem_write` (or `mem_read`) JSONL
    /// event to the configured sink. Multiple watchpoints may
    /// overlap; each fires independently.
    #[cfg(feature = "trace")]
    pub fn watch(&mut self, addr: u32, size: u32, mode: crate::trace::WatchMode) {
        self.mmu.trace.watch(addr, size, mode);
    }

    /// Remove watchpoints whose `(addr, size)` exactly matches.
    /// Mode is ignored for the match.
    #[cfg(feature = "trace")]
    pub fn unwatch(&mut self, addr: u32, size: u32) {
        self.mmu.trace.unwatch(addr, size);
    }

    /// Toggle per-instruction execution trace at runtime. Has no
    /// effect unless the crate was built with the `trace-exec`
    /// sub-feature.
    #[cfg(feature = "trace")]
    pub fn set_exec_trace(&mut self, on: bool) {
        self.mmu.trace.exec_on = on;
    }

    /// Override the trace JSONL sink at runtime. Defaults to
    /// honouring `OXIDEAV_VFW_TRACE_FILE`.
    #[cfg(feature = "trace")]
    pub fn set_trace_sink(&mut self, sink: Box<dyn std::io::Write + Send>) {
        self.mmu.trace.set_sink(sink);
    }

    // ---- COM / DirectShow surface (round 25) ------------------------

    /// Drive `DllGetClassObject(rclsid, riid, ppv)` on `image`,
    /// staging the GUID arguments + the `ppv` out-slot in a
    /// freshly-allocated heap region inside the sandbox.  On
    /// success returns the guest pointer the codec wrote into
    /// `*ppv` — typically a guest-side `IClassFactory`.
    ///
    /// When `riid == IID_IClassFactory`, the returned pointer is
    /// also registered with [`crate::com::ComObjectTable::register_class_factory`]
    /// keyed under `clsid`, so subsequent
    /// [`Self::co_create_instance`] calls can resolve `clsid`
    /// without re-driving `DllGetClassObject`.
    ///
    /// MSDN: `HRESULT DllGetClassObject(REFCLSID rclsid, REFIID
    /// riid, LPVOID *ppv)` — every COM in-process server
    /// exports it; DirectShow filter binaries (`.ax`) export it
    /// instead of `DriverProc`.
    pub fn dll_get_class_object(
        &mut self,
        image: &crate::pe::Image,
        clsid: crate::com::Guid,
        riid: crate::com::Guid,
    ) -> Result<u32, crate::Error> {
        let target = image.export("DllGetClassObject").ok_or_else(|| {
            crate::Error::Win32(crate::win32::Win32Error::InvalidArgument {
                stub: "dll_get_class_object",
                reason: format!("DllGetClassObject not exported by {:?}", image.name),
            })
        })?;
        // Stage the two GUIDs + the out-pointer slot in
        // contiguous arena memory: 16 + 16 + 4 = 36 bytes.
        let scratch = self.host.arena_alloc(36).map_err(crate::Error::Win32)?;
        clsid
            .stage(&mut self.mmu, scratch)
            .map_err(crate::Error::Trap)?;
        riid.stage(&mut self.mmu, scratch + 16)
            .map_err(crate::Error::Trap)?;
        // Zero the ppv slot.
        self.mmu
            .write_initializer(scratch + 32, &0u32.to_le_bytes())
            .map_err(crate::Error::Trap)?;
        let hr = call_guest(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            target,
            &[scratch, scratch + 16, scratch + 32],
        )?;
        if hr != crate::com::S_OK {
            return Err(crate::Error::Win32(
                crate::win32::Win32Error::InvalidArgument {
                    stub: "dll_get_class_object",
                    reason: format!("DllGetClassObject returned HRESULT {hr:#010x}"),
                },
            ));
        }
        let out_ptr = self.mmu.load32(scratch + 32).map_err(crate::Error::Trap)?;
        if out_ptr == 0 {
            return Err(crate::Error::Win32(
                crate::win32::Win32Error::InvalidArgument {
                    stub: "dll_get_class_object",
                    reason: "DllGetClassObject succeeded but *ppv is NULL".into(),
                },
            ));
        }
        // Bookkeep the new object.  If it is a class factory,
        // also register it under `clsid` so `CoCreateInstance`
        // can pick it up.
        self.host.com.intern(out_ptr, Some(riid));
        if riid == crate::com::IID_ICLASSFACTORY {
            self.host.com.register_class_factory(clsid, out_ptr);
        }
        Ok(out_ptr)
    }

    /// Drive `CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER,
    /// riid, ppv)` against the in-process class-factory cache.
    /// The CLSID must already be registered (typically by a
    /// prior [`Self::dll_get_class_object`] call); otherwise
    /// surfaces `CLASS_E_CLASSNOTAVAILABLE` as an error.
    pub fn co_create_instance(
        &mut self,
        clsid: crate::com::Guid,
        riid: crate::com::Guid,
    ) -> Result<u32, crate::Error> {
        let factory = self.host.com.lookup_class_factory(&clsid).ok_or_else(|| {
            crate::Error::Win32(crate::win32::Win32Error::InvalidArgument {
                stub: "co_create_instance",
                reason: format!(
                    "CLSID {clsid} not registered; \
                     call dll_get_class_object first"
                ),
            })
        })?;
        // Stage IID + out slot.
        let scratch = self.host.arena_alloc(20).map_err(crate::Error::Win32)?;
        riid.stage(&mut self.mmu, scratch)
            .map_err(crate::Error::Trap)?;
        self.mmu
            .write_initializer(scratch + 16, &0u32.to_le_bytes())
            .map_err(crate::Error::Trap)?;
        let r = crate::com::call::call_method(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            factory,
            crate::com::SLOT_CLASS_FACTORY_CREATE_INSTANCE,
            &[0, scratch, scratch + 16],
        )?;
        if r != crate::com::S_OK {
            return Err(crate::Error::Win32(
                crate::win32::Win32Error::InvalidArgument {
                    stub: "co_create_instance",
                    reason: format!("CreateInstance returned HRESULT {r:#010x}"),
                },
            ));
        }
        let out = self.mmu.load32(scratch + 16).map_err(crate::Error::Trap)?;
        if out != 0 {
            self.host.com.intern(out, Some(riid));
        }
        Ok(out)
    }

    /// Drive `obj->QueryInterface(riid, ppv)` on a guest COM
    /// object, staging the IID + out-slot in arena memory.
    /// Returns the new interface pointer on success, or surfaces
    /// the HRESULT in an error message.
    pub fn query_interface(
        &mut self,
        obj: u32,
        riid: crate::com::Guid,
    ) -> Result<u32, crate::Error> {
        let scratch = self.host.arena_alloc(20).map_err(crate::Error::Win32)?;
        riid.stage(&mut self.mmu, scratch)
            .map_err(crate::Error::Trap)?;
        self.mmu
            .write_initializer(scratch + 16, &0u32.to_le_bytes())
            .map_err(crate::Error::Trap)?;
        let r = crate::com::call::query_interface(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            obj,
            scratch,
            scratch + 16,
        )?;
        if r != crate::com::S_OK {
            return Err(crate::Error::Win32(
                crate::win32::Win32Error::InvalidArgument {
                    stub: "query_interface",
                    reason: format!("QueryInterface returned HRESULT {r:#010x}"),
                },
            ));
        }
        let out = self.mmu.load32(scratch + 16).map_err(crate::Error::Trap)?;
        if out != 0 {
            self.host.com.intern(out, Some(riid));
        }
        Ok(out)
    }

    /// Round 27 — mint a host-side `IFilterGraph` stub so the
    /// codec's `IBaseFilter::JoinFilterGraph(pGraph, pName)` call
    /// has a non-NULL parent graph to record.  The returned guest
    /// pointer's vtable function-pointer slots are synthetic
    /// thunk addresses that route into the host stubs registered
    /// by [`crate::com::host_iface::register`].
    ///
    /// `QueryInterface(IID_IUnknown | IID_IFilterGraph)` →
    /// `S_OK + *ppv = obj`; every other IID returns
    /// `E_NOINTERFACE`.  All eight `IFilterGraph` methods return
    /// `E_NOTIMPL` — none are exercised on the
    /// `JoinFilterGraph → ReceiveConnection` path the round-27
    /// probe takes.
    pub fn mint_host_filter_graph(&mut self) -> Result<u32, crate::Error> {
        crate::com::mint_host_filter_graph(&mut self.host, &mut self.mmu, &mut self.registry)
    }

    /// Round 27 — mint a host-side `IPin` stub that pretends to
    /// be an OUTPUT pin advertising `amt_addr` (a pointer to a
    /// staged `AM_MEDIA_TYPE`).  Suitable as the `pConnector`
    /// argument of `IPin::ReceiveConnection`.
    ///
    /// `QueryDirection` reports `PIN_OUTPUT`; `QueryAccept`
    /// returns `S_OK`; `ConnectionMediaType` copies the staged
    /// AMT; `EnumMediaTypes` vends an enumerator yielding the
    /// staged AMT once.
    pub fn mint_host_output_pin(&mut self, amt_addr: u32) -> Result<u32, crate::Error> {
        crate::com::host_iface::mint_host_output_pin(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
            amt_addr,
        )
    }

    /// Round 37 — same as [`Self::mint_host_output_pin`] but also
    /// stamps the codec's input-pin pointer (`connected_pin`) into
    /// the new pin object so `IPin::ConnectedTo` can return it,
    /// and synthesizes a parent `HostIBaseFilter` so
    /// `IPin::QueryPinInfo` can fill in `PIN_INFO::pFilter`.
    ///
    /// `connected_pin == 0` falls back to the round-30 behaviour
    /// where the pin reports `VFW_E_NOT_CONNECTED` from
    /// `ConnectedTo`.
    pub fn mint_host_output_pin_with_connection(
        &mut self,
        amt_addr: u32,
        connected_pin: u32,
    ) -> Result<u32, crate::Error> {
        crate::com::host_iface::mint_host_output_pin_with_connection(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
            amt_addr,
            connected_pin,
        )
    }

    /// Round 37 — number of `IPin::QueryPinInfo` calls the codec
    /// has driven against any host pin during this sandbox's
    /// lifetime.
    pub fn query_pin_info_call_count(&self) -> usize {
        crate::com::host_iface::query_pin_info_call_count(&self.host)
    }

    /// Round 37 — number of `IBaseFilter::QueryFilterInfo` calls
    /// the codec has driven against any host filter during this
    /// sandbox's lifetime.
    pub fn query_filter_info_call_count(&self) -> usize {
        crate::com::host_iface::query_filter_info_call_count(&self.host)
    }

    /// Round 37 — `this` pointers of every `IPin::QueryPinInfo`
    /// call observed.
    pub fn query_pin_info_calls(&self) -> Vec<u32> {
        crate::com::host_iface::query_pin_info_calls(&self.host)
    }

    /// Round 37 — `this` pointers of every
    /// `IBaseFilter::QueryFilterInfo` call observed.
    pub fn query_filter_info_calls(&self) -> Vec<u32> {
        crate::com::host_iface::query_filter_info_calls(&self.host)
    }

    /// Round 37 — drop every captured introspection call from this
    /// sandbox's per-state log.
    pub fn clear_query_info_log(&self) {
        crate::com::host_iface::clear_query_info_log(&self.host)
    }

    /// Round 30 — mint a host-side `IMemAllocator` backed by a
    /// pool of `pool_size` IMediaSample slots, each carrying a
    /// fresh `sample_capacity`-byte data region. The returned
    /// guest pointer is suitable as the `pAllocator` argument of
    /// `IMemInputPin::NotifyAllocator`.
    ///
    /// `media_type_ptr` is returned by every minted sample's
    /// `IMediaSample::GetMediaType` — pass `0` if no AMT should
    /// surface there (codecs then fall back to the upstream pin's
    /// connection media type).
    pub fn mint_host_mem_allocator(
        &mut self,
        pool_size: u32,
        sample_capacity: u32,
        media_type_ptr: u32,
    ) -> Result<u32, crate::Error> {
        crate::com::mint_host_mem_allocator(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
            pool_size,
            sample_capacity,
            media_type_ptr,
        )
    }

    /// Round 35 — mint a host-side `IClassFactory` whose
    /// `CreateInstance` mints fresh `HostIMemAllocator` instances.
    ///
    /// Pre-registered in [`Sandbox::new`] under
    /// [`crate::com::CLSID_MEMORY_ALLOCATOR`]; this method exists
    /// for tests that want a raw factory pointer to drive
    /// `IClassFactory::CreateInstance` directly without going
    /// through the `ole32!CoCreateInstance` cascade.
    pub fn mint_host_mem_allocator_class_factory(&mut self) -> Result<u32, crate::Error> {
        crate::com::mint_host_mem_allocator_class_factory(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
        )
    }

    /// Round 30 — mint a single host-side `IMediaSample` wrapping
    /// a fresh `data_capacity`-byte data region. Useful for
    /// stand-alone tests; production paths typically mint samples
    /// implicitly via [`Self::mint_host_mem_allocator`].
    pub fn mint_host_media_sample(
        &mut self,
        data_capacity: u32,
        media_type_ptr: u32,
    ) -> Result<u32, crate::Error> {
        crate::com::mint_host_media_sample(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
            data_capacity,
            media_type_ptr,
        )
    }

    /// Round 30 — copy a payload into a previously-minted sample
    /// + flag whether it is a sync (key) frame.
    ///
    /// Wraps [`crate::com::media_sample_set_payload`].
    pub fn media_sample_set_payload(
        &mut self,
        sample: u32,
        payload: &[u8],
        sync_point: bool,
    ) -> Result<(), crate::Error> {
        crate::com::media_sample_set_payload(&mut self.mmu, sample, payload, sync_point)
    }

    /// Round 31 — mint a paired downstream `(HostIPin, HostIMemInputPin)`
    /// for receiving samples the codec pushes from its output pin.
    pub fn host_iface_r31_mint_input_pin_pair(&mut self) -> Result<(u32, u32), crate::Error> {
        crate::com::host_iface_r31::mint_host_input_pin_pair(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
        )
    }

    /// Round 31 — mint a minimal HostIBaseFilter exposing
    /// `input_pin`.
    pub fn host_iface_r31_mint_base_filter(&mut self, input_pin: u32) -> Result<u32, crate::Error> {
        crate::com::host_iface_r31::mint_host_base_filter(
            &mut self.host,
            &mut self.mmu,
            &mut self.registry,
            input_pin,
        )
    }

    /// Round 31 — pop the oldest sample captured by the
    /// downstream `HostIMemInputPin::Receive` callback.
    pub fn pop_received_sample(&self) -> Option<crate::com::host_iface_r31::ReceivedSample> {
        crate::com::host_iface_r31::pop_sample(&self.host)
    }

    /// Round 31 — number of samples currently waiting in the
    /// host-side queue.
    pub fn received_samples_len(&self) -> usize {
        crate::com::host_iface_r31::queue_len(&self.host)
    }

    /// Round 33 — return the most recent
    /// `IMemAllocator::SetProperties` capture observed on this
    /// sandbox, or `None` if no codec has called `SetProperties`
    /// yet.  See [`crate::com::AllocatorPropertiesCapture`] for
    /// the captured field shape.
    pub fn last_set_properties(&self) -> Option<crate::com::AllocatorPropertiesCapture> {
        crate::com::last_set_properties(&self.host)
    }

    /// Round 33 — return every `SetProperties` capture observed on
    /// this sandbox, in arrival order.
    pub fn all_set_properties(&self) -> Vec<crate::com::AllocatorPropertiesCapture> {
        crate::com::all_set_properties(&self.host)
    }

    /// Round 33 — drop every captured `SetProperties` for this
    /// sandbox.  Useful for resetting per-test state.
    pub fn clear_set_properties_log(&self) {
        crate::com::clear_set_properties_log(&self.host)
    }

    /// Drive `obj->AddRef()`.  Returns the codec-reported new
    /// refcount; the host's bookkeeping is updated automatically.
    pub fn com_add_ref(&mut self, obj: u32) -> Result<u32, crate::Error> {
        crate::com::call::add_ref(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            obj,
        )
    }

    /// Drive `obj->Release()`.  Returns the codec-reported new
    /// refcount.  The host's bookkeeping is updated automatically.
    pub fn com_release(&mut self, obj: u32) -> Result<u32, crate::Error> {
        crate::com::call::release(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            obj,
        )
    }

    /// `ICDecompress` — decode one frame.
    #[allow(clippy::too_many_arguments)]
    pub fn ic_decompress(
        &mut self,
        hic: u32,
        flags: u32,
        input_bih: &vfw32::Bih,
        input_bytes: &[u8],
        output_bih: &vfw32::Bih,
        output_capacity: u32,
    ) -> Result<(u32, Vec<u8>), crate::Error> {
        vfw32::ic_decompress(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            flags,
            input_bih,
            input_bytes,
            output_bih,
            output_capacity,
        )
    }

    // ---- Round 51: encode (compress) wrappers --------------------------

    /// `ICCompressQuery` — does the codec accept this input/output
    /// format pair? `output` may be `None` to defer the choice.
    pub fn ic_compress_query(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
        output: Option<&vfw32::Bih>,
    ) -> Result<u32, crate::Error> {
        vfw32::ic_compress_query(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
            output,
        )
    }

    /// `ICCompressGetFormat` — ask the codec for the output BIH
    /// describing what its compressed format looks like for the
    /// supplied input.
    pub fn ic_compress_get_format(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
    ) -> Result<(u32, vfw32::Bih), crate::Error> {
        vfw32::ic_compress_get_format(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
        )
    }

    /// `ICCompressGetSize` — max encoded-frame byte count for the
    /// supplied input/output BIH pair.
    pub fn ic_compress_get_size(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
        output: &vfw32::Bih,
    ) -> Result<u32, crate::Error> {
        vfw32::ic_compress_get_size(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
            output,
        )
    }

    /// `ICCompressBegin` — set up the encoder pipeline.
    pub fn ic_compress_begin(
        &mut self,
        hic: u32,
        input: &vfw32::Bih,
        output: &vfw32::Bih,
    ) -> Result<u32, crate::Error> {
        vfw32::ic_compress_begin(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            input,
            output,
        )
    }

    /// `ICCompressEnd` — tear down the encoder pipeline.
    pub fn ic_compress_end(&mut self, hic: u32) -> Result<u32, crate::Error> {
        vfw32::ic_compress_end(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
        )
    }

    /// `ICCompress` — encode one frame. Returns the full encode
    /// outcome: codec LRESULT, encoded bytes, the post-call output
    /// BIH (whose `biSizeImage` holds the actual encoded byte
    /// count), the codec-written `*lpdwFlags` (e.g. whether the
    /// codec marked the emitted frame as a keyframe), and the
    /// codec-written `*lpckid`.
    ///
    /// `prev_bih_opt` / `prev_bytes_opt` are the previous
    /// reconstructed frame (P-frame encoding). Pass `None` for
    /// keyframes.
    #[allow(clippy::too_many_arguments)]
    pub fn ic_compress(
        &mut self,
        hic: u32,
        flags: u32,
        input_bih: &vfw32::Bih,
        input_bytes: &[u8],
        output_bih: &vfw32::Bih,
        output_capacity: u32,
        ckid: u32,
        frame_num: i32,
        frame_size_limit: u32,
        quality: u32,
        prev_bih_opt: Option<&vfw32::Bih>,
        prev_bytes_opt: Option<&[u8]>,
    ) -> Result<vfw32::CompressOutcome, crate::Error> {
        vfw32::ic_compress(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            flags,
            input_bih,
            input_bytes,
            output_bih,
            output_capacity,
            ckid,
            frame_num,
            frame_size_limit,
            quality,
            prev_bih_opt,
            prev_bytes_opt,
        )
    }

    /// `ICGetState` — ask the codec to serialise its private
    /// per-instance state into `dst_buf`.  Returns the byte count
    /// the codec actually wrote.
    ///
    /// Round 70 — wraps `ICM_GETSTATE` (`0x5009`) per MSDN; required
    /// by oxideav-tracevfw to drive the encoder's per-quality knob
    /// round-trip alongside [`Self::ic_set_state`].  See MSDN
    /// `ICGetState` topic page for the public contract.
    pub fn ic_get_state(&mut self, hic: u32, dst_buf: &mut [u8]) -> Result<u32, crate::Error> {
        vfw32::ic_get_state(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            dst_buf,
        )
    }

    /// `ICSetState` — ask the codec to deserialise `src_buf` into
    /// its private per-instance state.  Returns `Ok(())` on
    /// `ICERR_OK`, or [`crate::Error`] wrapping the codec's raw
    /// `LRESULT` otherwise.
    ///
    /// Round 70 — wraps `ICM_SETSTATE` (`0x500A`) per MSDN.  See
    /// MSDN `ICSetState` topic page for the public contract.
    pub fn ic_set_state(&mut self, hic: u32, src_buf: &[u8]) -> Result<(), crate::Error> {
        vfw32::ic_set_state(
            &mut self.cpu,
            &mut self.mmu,
            &mut self.registry,
            &mut self.host,
            hic,
            src_buf,
        )
    }

    /// Round 63 — patch `msadds32.ax`'s `helper_addref` thunk (at
    /// RVA `0x5cea`) to unconditionally return `value` (32-bit
    /// integer).
    ///
    /// **Why.** Round-62 forensics
    /// (`docs/codec/msadds32-receive-null-0x20.md`) traced the
    /// `IMemInputPin::Receive` NULL-deref trap at RVA `0x256a` to
    /// a buffer-pool init that's handed a size of zero.  The size
    /// is `(h * 10) / size_calc(...)` where `h` is what
    /// `helper_addref` returns.  On a fresh codec instance the
    /// helper-object field at `helper_90 + 0x3c` (the "initialised"
    /// flag the addref checks) is zero, so `helper_addref` returns
    /// `0`, the quotient is `0`, `operator new(0)` returns NULL,
    /// `buffer_pool_init` fails, and the Receive cleanup branch
    /// trips a NULL+0x20 deref.
    ///
    /// In a real DirectShow host the flag is set during
    /// `IFilterGraph::JoinFilterGraph` / `Pause` (the codec stamps
    /// the field as part of its run-state machine).  Until we
    /// drive that path, the surgical workaround is to short-circuit
    /// `helper_addref` to return a fixed non-zero value — which
    /// empirically lifts the trap and lets Receive run to
    /// completion (with HRESULT `0x8000ffff` from the decode body,
    /// which is the next round's investigation surface).
    ///
    /// **Encoding.** The original function (RVA `0x5cea`, 10 bytes)
    /// is:
    ///
    /// ```text
    /// 0x5cea: 83 79 20 00  cmp [ecx+0x20], 0
    /// 0x5cee: 74 04        jz  +4
    /// 0x5cf0: 8b 41 28     mov eax, [ecx+0x28]
    /// 0x5cf3: c3           ret
    /// 0x5cf4: 33 c0        xor eax, eax
    /// 0x5cf6: c3           ret
    /// ```
    ///
    /// We overwrite the first 6 bytes with:
    ///
    /// ```text
    /// b8 XX XX XX XX  mov eax, imm32
    /// c3              ret
    /// ```
    ///
    /// The remaining bytes at `0x5cf0..0x5cf6` are unreachable
    /// after the patch (no caller enters there directly), so the
    /// dead-code is harmless.
    ///
    /// `image_base` is the address the codec was loaded at; pass
    /// the value returned by [`Self::load`] on `msadds32.ax`.
    ///
    /// # Reference material (clean-room only)
    ///
    /// * Intel SDM Vol. 2A — `MOV imm32` (`B8+rd`), `RET` (`C3`).
    /// * Raw bytes of `msadds32.ax` from
    ///   `docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/`.
    ///
    /// No Wine / ReactOS / MinGW / Microsoft DShow source consulted.
    pub fn msadds32_patch_helper_addref(
        &mut self,
        image_base: u32,
        value: u32,
    ) -> Result<(), crate::Error> {
        const RVA_HELPER_ADDREF: u32 = 0x5cea;
        let va = image_base.wrapping_add(RVA_HELPER_ADDREF);
        let mut patch = [0u8; 6];
        patch[0] = 0xb8; // mov eax, imm32
        patch[1..5].copy_from_slice(&value.to_le_bytes());
        patch[5] = 0xc3; // ret
        self.mmu
            .write_initializer(va, &patch)
            .map_err(crate::Error::Trap)
    }
}

/// Recursively load `bytes`'s static imports from the VFS. Mirrors
/// [`Sandbox::preload_deps`] but free-function shape so it can run
/// from a stub (which doesn't own a Sandbox).
fn preload_deps_free(
    cpu: &mut crate::emulator::Cpu,
    mmu: &mut crate::emulator::Mmu,
    registry: &mut crate::win32::Registry,
    state: &mut crate::win32::HostState,
    bytes: &[u8],
    loading: &mut std::collections::BTreeSet<String>,
) {
    use crate::pe;
    let parsed = match pe::header::parse(bytes) {
        Ok(p) => p,
        Err(_) => return,
    };
    let imported = pe::imports::list_imported_dlls(&parsed, bytes).unwrap_or_default();
    for dll in imported {
        let dll_lc = dll.to_ascii_lowercase();
        if loading.contains(&dll_lc) {
            continue;
        }
        if crate::win32::is_host_stub_dll(&dll_lc) {
            continue;
        }
        if state.modules.contains_key(&dll_lc) {
            continue;
        }
        let bytes_dep = {
            let Some(vfs) = state.context.vfs.as_ref() else {
                continue;
            };
            let mut found: Option<Vec<u8>> = None;
            for prefix in crate::win32::dll_vfs_search_paths() {
                let p = format!("{prefix}{dll_lc}");
                if let Some(b) = vfs.read(&p) {
                    found = Some(b.to_vec());
                    break;
                }
            }
            match found {
                Some(b) => b,
                None => continue,
            }
        };
        loading.insert(dll_lc.clone());
        preload_deps_free(cpu, mmu, registry, state, &bytes_dep, loading);
        let Ok(parsed_dep) = pe::header::parse(&bytes_dep) else {
            loading.remove(&dll_lc);
            continue;
        };
        let preferred = parsed_dep.optional.image_base;
        let image_size = parsed_dep.optional.size_of_image;
        let aligned = (image_size + 0xFFFF) & !0xFFFF;
        let base = if mmu.region_is_unmapped(preferred, image_size) {
            preferred
        } else {
            let b = state.next_dll_image_base;
            state.next_dll_image_base = b.saturating_add(aligned);
            b
        };
        let mut options = pe::LoadOptions {
            imports: pe::imports::ResolveMode::FailSoft,
            fail_soft_log: Some(Vec::new()),
            target_image_base: Some(base),
        };
        let mut loader = pe::Loader::new(mmu, registry, state);
        let img = match loader.load_with_options(&dll_lc, &bytes_dep, &mut options) {
            Ok(i) => i,
            Err(e) => {
                state
                    .debug_log
                    .push(format!("dynamic-load {dll_lc}: load failed: {e}"));
                loading.remove(&dll_lc);
                continue;
            }
        };
        for (export_name, rva) in &img.exports {
            registry.register_guest_export(&dll_lc, export_name, img.image_base.wrapping_add(*rva));
        }
        state
            .loaded_dll_exports
            .insert(img.image_base, img.exports.clone());
        state.modules.insert(dll_lc.clone(), img.image_base);
        let msg = format!("dynamic-load {dll_lc}: loaded at {base:#010x}");
        eprintln!("  {msg}");
        state.debug_log.push(msg);
        let has_dll_main = img.exports.contains_key("DllMain");
        let has_entry = parsed_dep.optional.address_of_entry_point != 0;
        let target = if has_entry {
            img.image_base
                .wrapping_add(parsed_dep.optional.address_of_entry_point)
        } else if has_dll_main {
            img.image_base
                .wrapping_add(*img.exports.get("DllMain").unwrap())
        } else {
            0
        };
        if target != 0 {
            if std::env::var("UD_TRACE_WILD_JUMP").is_ok() {
                eprintln!("  dynamic-load {dll_lc}: calling DllMain at {target:#010x}");
            }
            if let Err(e) = crate::win32::call_guest(
                cpu,
                mmu,
                registry,
                state,
                target,
                &[img.image_base, DLL_PROCESS_ATTACH, 0],
            ) {
                let msg = format!("dynamic-load {dll_lc}: DllMain trapped: {e}");
                eprintln!("  {msg}");
                state.debug_log.push(msg);
            }
        }
        loading.remove(&dll_lc);
    }
}

/// Dynamic `LoadLibraryA`: find a DLL by name in the attached
/// VFS, load it (with its dependencies) at a fresh image base,
/// register its exports against the stub registry, and invoke
/// its `DllMain(PROCESS_ATTACH)`. Returns the new module's
/// image base on success, 0 if the DLL can't be found or fails
/// to load.
///
/// This lets `kernel32!LoadLibraryA` work for any DLL the
/// VFS contains — qtcf.dll's delay-load resolver hits
/// `LoadLibraryA("CoreFoundation.dll")` from inside qts's
/// CRT init chain, and we now load it on demand rather than
/// pre-staging everything.
pub fn load_dll_dynamic(
    cpu: &mut crate::emulator::Cpu,
    mmu: &mut crate::emulator::Mmu,
    registry: &mut crate::win32::Registry,
    state: &mut crate::win32::HostState,
    name: &str,
) -> u32 {
    use crate::pe;
    let name_lc = name.to_ascii_lowercase();
    let basename = name_lc
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&name_lc)
        .to_string();
    if let Some(b) = state.modules.get(&basename) {
        return *b;
    }
    if let Some(b) = state.modules.get(&name_lc) {
        return *b;
    }
    if crate::win32::is_host_stub_dll(&basename) {
        return 0;
    }
    let bytes = {
        let Some(vfs) = state.context.vfs.as_ref() else {
            return 0;
        };
        let mut found: Option<Vec<u8>> = None;
        for prefix in crate::win32::dll_vfs_search_paths() {
            let p = format!("{prefix}{basename}");
            if let Some(b) = vfs.read(&p) {
                found = Some(b.to_vec());
                break;
            }
        }
        match found {
            Some(b) => b,
            None => return 0,
        }
    };
    let mut loading: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    loading.insert(basename.clone());
    preload_deps_free(cpu, mmu, registry, state, &bytes, &mut loading);
    loading.remove(&basename);
    let Ok(parsed) = pe::header::parse(&bytes) else {
        return 0;
    };
    let preferred = parsed.optional.image_base;
    let image_size = parsed.optional.size_of_image;
    let aligned = (image_size + 0xFFFF) & !0xFFFF;
    let base = if mmu.region_is_unmapped(preferred, image_size) {
        preferred
    } else {
        let b = state.next_dll_image_base;
        state.next_dll_image_base = b.saturating_add(aligned);
        b
    };
    let mut options = pe::LoadOptions {
        imports: pe::imports::ResolveMode::FailSoft,
        fail_soft_log: Some(Vec::new()),
        target_image_base: Some(base),
    };
    let mut loader = pe::Loader::new(mmu, registry, state);
    let img = match loader.load_with_options(&basename, &bytes, &mut options) {
        Ok(i) => i,
        Err(_) => return 0,
    };
    for (export_name, rva) in &img.exports {
        registry.register_guest_export(&basename, export_name, img.image_base.wrapping_add(*rva));
    }
    state
        .loaded_dll_exports
        .insert(img.image_base, img.exports.clone());
    state.modules.insert(basename.clone(), img.image_base);
    let msg = format!(
        "dynamic-load {basename}: loaded at {:#010x}",
        img.image_base
    );
    eprintln!("  {msg}");
    state.debug_log.push(msg);
    let has_dll_main = img.exports.contains_key("DllMain");
    let has_entry = parsed.optional.address_of_entry_point != 0;
    let target = if has_entry {
        img.image_base
            .wrapping_add(parsed.optional.address_of_entry_point)
    } else if has_dll_main {
        img.image_base
            .wrapping_add(*img.exports.get("DllMain").unwrap())
    } else {
        0
    };
    if target != 0 {
        if let Err(e) = crate::win32::call_guest(
            cpu,
            mmu,
            registry,
            state,
            target,
            &[img.image_base, DLL_PROCESS_ATTACH, 0],
        ) {
            let msg = format!("dynamic-load {basename}: DllMain trapped: {e}");
            eprintln!("  {msg}");
            state.debug_log.push(msg);
        }
    }
    img.image_base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::isa_int::RET_SENTINEL;
    use crate::emulator::regs::Reg32;
    use crate::pe::test_image::build_minimal_dll;

    #[test]
    fn load_synth_dll_and_run_dll_main_returns_to_sentinel() {
        let bytes = build_minimal_dll();
        let mut sb = Sandbox::new();
        let img = sb.load("synth.dll", &bytes).unwrap();
        // Pre-set eax = 1 so we can confirm the synth DllMain
        // returned without modifying it (it's just `ret 12`).
        sb.cpu.regs.set32(Reg32::Eax, 1);
        let ret = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).unwrap();
        assert_eq!(ret, 1);
        assert_eq!(sb.cpu.regs.eip, RET_SENTINEL);
    }

    #[test]
    fn calling_through_iat_thunk_invokes_kernel32_stub() {
        // Emulator-only test: fabricate a code block that calls
        // a kernel32!GetProcessHeap thunk and rets. Verifies the
        // run loop's "is_thunk → dispatch" path.
        let mut sb = Sandbox::new();
        let thunk = sb
            .registry
            .resolve("kernel32.dll", "GetProcessHeap")
            .unwrap();
        // Map a code page at 0x1000.
        sb.mmu.map(0x1000, 0x1000, Perm::R | Perm::X);
        // call dword [thunk_slot]; ret 0
        // Easier: set eip directly to the thunk after pushing
        // the synthetic ret-sentinel.
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = thunk;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 0xDEAD_BEEF);
    }

    /// Phase 3c of the scheduler refactor: `WaitForSingleObject`
    /// on an unsignalled auto-reset Event parks the calling
    /// thread; `SetEvent` from a peer wakes exactly one waiter.
    /// We exercise this directly through state mutation rather
    /// than spawning guest threads (the kernel32 thunk path is
    /// covered by the spawn test below).
    #[test]
    fn wait_for_single_object_blocks_until_set_event() {
        let mut sb = Sandbox::new();
        // Mint an auto-reset Event, initially unsignalled.
        let h = sb
            .host
            .scheduler
            .insert_object(crate::sched::WaitObject::Event {
                signaled: false,
                manual_reset: false,
            });
        // Inject a second thread parked on a wait for the event.
        let mut t2 = crate::win32::ThreadState::new(2, 1);
        t2.parked_cpu = Some(crate::emulator::Cpu::new());
        t2.status = crate::sched::ThreadStatus::Waiting;
        t2.wait = Some(crate::sched::WaitCondition::Object {
            handle: h,
            timeout_after: None,
        });
        sb.host.threads.insert(2, t2);

        // Bootstrap drives SetEvent via the kernel32 thunk.
        let set_event = sb.registry.resolve("kernel32.dll", "SetEvent").unwrap();
        sb.cpu.push32(&mut sb.mmu, h).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = set_event;
        sb.run_until_sentinel().unwrap();

        // Thread 2 should be back to Ready with no wait.
        let t = sb.host.threads.get(&2).unwrap();
        assert!(
            matches!(t.status, crate::sched::ThreadStatus::Ready),
            "expected thread 2 Ready, got {:?}",
            t.status
        );
        assert!(t.wait.is_none(), "wait condition must be cleared");
        // Auto-reset: the signal is consumed by the wake.
        match sb.host.scheduler.objects.get(&h).unwrap() {
            crate::sched::WaitObject::Event { signaled, .. } => assert!(!*signaled),
            _ => panic!(),
        }
    }

    /// Mutex round-trip: contention parks the second caller,
    /// `ReleaseMutex` from the holder wakes them and transfers
    /// ownership.
    #[test]
    fn mutex_transfers_ownership_on_release() {
        let mut sb = Sandbox::new();
        // Mint a Mutex owned by tid 1 (the bootstrap).
        let h = sb
            .host
            .scheduler
            .insert_object(crate::sched::WaitObject::Mutex {
                owner: Some(1),
                recursion: 1,
            });
        // Inject thread 2 waiting on the mutex.
        let mut t2 = crate::win32::ThreadState::new(2, 1);
        t2.parked_cpu = Some(crate::emulator::Cpu::new());
        t2.status = crate::sched::ThreadStatus::Waiting;
        t2.wait = Some(crate::sched::WaitCondition::Object {
            handle: h,
            timeout_after: None,
        });
        sb.host.threads.insert(2, t2);

        // Bootstrap calls ReleaseMutex.
        let release = sb.registry.resolve("kernel32.dll", "ReleaseMutex").unwrap();
        sb.cpu.push32(&mut sb.mmu, h).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = release;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1, "release succeeds");

        // Ownership transferred to thread 2; thread 2 Ready.
        match sb.host.scheduler.objects.get(&h).unwrap() {
            crate::sched::WaitObject::Mutex { owner, recursion } => {
                assert_eq!(*owner, Some(2));
                assert_eq!(*recursion, 1);
            }
            _ => panic!(),
        }
        let t = sb.host.threads.get(&2).unwrap();
        assert!(matches!(t.status, crate::sched::ThreadStatus::Ready));
    }

    /// Semaphore round-trip: `ReleaseSemaphore(N)` wakes up to
    /// N waiters and bumps the count.
    #[test]
    fn semaphore_release_wakes_waiters_and_bumps_count() {
        let mut sb = Sandbox::new();
        let h = sb
            .host
            .scheduler
            .insert_object(crate::sched::WaitObject::Semaphore { count: 0, max: 10 });
        // Two waiters.
        for tid in [2u32, 3u32] {
            let mut t = crate::win32::ThreadState::new(tid, 1);
            t.parked_cpu = Some(crate::emulator::Cpu::new());
            t.status = crate::sched::ThreadStatus::Waiting;
            t.wait = Some(crate::sched::WaitCondition::Object {
                handle: h,
                timeout_after: None,
            });
            sb.host.threads.insert(tid, t);
        }
        // Bootstrap releases 2.
        let release = sb
            .registry
            .resolve("kernel32.dll", "ReleaseSemaphore")
            .unwrap();
        sb.mmu.map(0x500_0000, 0x1000, Perm::R | Perm::W);
        let p_prev = 0x500_0000u32;
        sb.cpu.push32(&mut sb.mmu, p_prev).unwrap();
        sb.cpu.push32(&mut sb.mmu, 2u32).unwrap();
        sb.cpu.push32(&mut sb.mmu, h).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = release;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1);
        // Previous count was 0.
        assert_eq!(sb.mmu.load32(p_prev).unwrap(), 0);
        // Both waiters woke; each consumed one count → net count = 0.
        match sb.host.scheduler.objects.get(&h).unwrap() {
            crate::sched::WaitObject::Semaphore { count, .. } => {
                assert_eq!(*count, 0, "both waiters consumed their signals");
            }
            _ => panic!(),
        }
        for tid in [2u32, 3u32] {
            let t = sb.host.threads.get(&tid).unwrap();
            assert!(matches!(t.status, crate::sched::ThreadStatus::Ready));
        }
    }

    /// Phase 5c: when the target EXE is staged in the
    /// VirtualFs, `CreateProcessA` actually loads it at a
    /// fresh image base and mints a Ready primary thread the
    /// scheduler can run alongside the parent. The PE used
    /// here is the synthetic-DLL fixture — it has a real PE
    /// header and the only import (`kernel32!ExitProcess`) is
    /// satisfied by our stub registry.
    #[test]
    fn create_process_a_loads_real_child_pe_from_vfs() {
        use crate::pe::test_image::build_minimal_dll;
        let mut sb = Sandbox::default();
        // Stage a child binary in the VFS.
        let dll_bytes = build_minimal_dll();
        let child_path = "c:\\setup\\helper.exe";
        let mut vfs = crate::context::VirtualFs::new();
        vfs.insert(child_path, dll_bytes);
        sb.host.context.vfs = Some(vfs);

        // Stage a PROCESS_INFORMATION scratch region.
        sb.mmu.map(0x500_0000, 0x1000, Perm::R | Perm::W);
        let pi = 0x500_0000u32;
        // Stage the lpApplicationName string.
        sb.mmu.map(0x500_1000, 0x1000, Perm::R | Perm::W);
        let app_ptr = 0x500_1000u32;
        sb.mmu
            .write_initializer(app_ptr, child_path.as_bytes())
            .unwrap();
        sb.mmu.store8(app_ptr + child_path.len() as u32, 0).unwrap();

        let create_proc = sb
            .registry
            .resolve("kernel32.dll", "CreateProcessA")
            .unwrap();
        for &a in [app_ptr, 0u32, 0, 0, 0, 0, 0, 0, 0, pi].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = create_proc;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1, "CreateProcessA TRUE");

        // The new process should be in the table, distinct PID,
        // and its primary thread Ready (not Terminated like the
        // fake-child fallback).
        let child_pid = sb.mmu.load32(pi + 8).unwrap();
        let child_tid = sb.mmu.load32(pi + 12).unwrap();
        let p = sb
            .host
            .processes
            .get(&child_pid)
            .expect("child process present");
        assert_ne!(
            p.image_base, 0,
            "child PE was rebased into a fresh image slot"
        );
        assert_eq!(p.parent_pid, 1);
        let t = sb
            .host
            .threads
            .get(&child_tid)
            .expect("child primary thread present");
        assert!(matches!(
            t.status,
            crate::sched::ThreadStatus::Ready | crate::sched::ThreadStatus::Running
        ));
        // The minimal-DLL entry just rets, so a subsequent
        // run_until_sentinel will Halt it cleanly.
    }

    /// Phase 3d: `EnterCriticalSection` takes ownership of an
    /// implicit Mutex keyed by `LPCRITICAL_SECTION`'s guest
    /// address; recursion increments on re-entry by the same
    /// thread; `LeaveCriticalSection` decrements and clears
    /// ownership when the count reaches zero. Exercised through
    /// IPC: `CreatePipe` mints a read/write handle pair;
    /// `WriteFile` on the write end stages bytes that
    /// `ReadFile` on the read end picks up. The two handles
    /// share an in-memory buffer through the scheduler's
    /// pipe table; closing the write end drains EOF on the
    /// reader.
    #[test]
    fn create_pipe_write_read_round_trip() {
        let mut sb = Sandbox::new();
        // Scratch region for handle outputs + data buffers.
        sb.mmu.map(0x500_0000, 0x1000, Perm::R | Perm::W);
        let p_read_h = 0x500_0000u32;
        let p_write_h = 0x500_0004u32;
        let p_written = 0x500_0010u32;
        let p_data_in = 0x500_0020u32; // bytes to write
        let p_data_out = 0x500_0040u32; // bytes to read into
        let p_n_read = 0x500_0080u32;

        // CreatePipe(read, write, NULL, 0).
        let create_pipe = sb.registry.resolve("kernel32.dll", "CreatePipe").unwrap();
        for &a in [p_read_h, p_write_h, 0u32, 0u32].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = create_pipe;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1, "CreatePipe TRUE");
        let h_read = sb.mmu.load32(p_read_h).unwrap();
        let h_write = sb.mmu.load32(p_write_h).unwrap();
        assert!(h_read >= crate::sched::WAIT_OBJECT_HANDLE_BASE);
        assert_ne!(h_read, h_write, "distinct ends");

        // Stage data in MMU + WriteFile(write_handle, data, 5, &written, NULL).
        sb.mmu.write_initializer(p_data_in, b"HELLO").unwrap();
        let write_file = sb.registry.resolve("kernel32.dll", "WriteFile").unwrap();
        for &a in [h_write, p_data_in, 5u32, p_written, 0u32].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = write_file;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1);
        assert_eq!(sb.mmu.load32(p_written).unwrap(), 5);

        // ReadFile(read_handle, out_buf, 5, &n_read, NULL).
        let read_file = sb.registry.resolve("kernel32.dll", "ReadFile").unwrap();
        for &a in [h_read, p_data_out, 5u32, p_n_read, 0u32].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = read_file;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1);
        assert_eq!(sb.mmu.load32(p_n_read).unwrap(), 5);
        // Verify the bytes round-tripped.
        let mut got = [0u8; 5];
        for i in 0..5 {
            got[i] = sb.mmu.load8(p_data_out + i as u32).unwrap();
        }
        assert_eq!(&got, b"HELLO");
    }

    /// Named-pipe handshake: a `CreateNamedPipeA(\\.\pipe\X)`
    /// server end + a `CreateFileA(\\.\pipe\X)` client end
    /// reach each other through the named-object registry
    /// and share a buffer for `WriteFile` / `ReadFile`.
    #[test]
    fn named_pipe_server_and_client_share_buffer() {
        let mut sb = Sandbox::new();
        sb.mmu.map(0x501_0000, 0x1000, Perm::R | Perm::W);
        let p_name = 0x501_0000u32;
        let pipe_path = b"\\\\.\\pipe\\test\0";
        sb.mmu.write_initializer(p_name, pipe_path).unwrap();
        let p_data_in = 0x501_0100u32;
        let p_data_out = 0x501_0200u32;
        let p_written = 0x501_0300u32;
        let p_n_read = 0x501_0310u32;

        // CreateNamedPipeA(name, PIPE_ACCESS_OUTBOUND, ...). With
        // OUTBOUND, the server holds the write end.
        let cnp = sb
            .registry
            .resolve("kernel32.dll", "CreateNamedPipeA")
            .unwrap();
        for &a in [p_name, 2u32, 0u32, 1u32, 4096u32, 4096u32, 0u32, 0u32]
            .iter()
            .rev()
        {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = cnp;
        sb.run_until_sentinel().unwrap();
        let h_server = sb.cpu.regs.get32(Reg32::Eax);
        assert!(h_server >= crate::sched::WAIT_OBJECT_HANDLE_BASE);

        // Client: CreateFileA(\\.\pipe\test, GENERIC_READ, ...).
        let cfa = sb.registry.resolve("kernel32.dll", "CreateFileA").unwrap();
        for &a in [p_name, 0x8000_0000u32, 0u32, 0u32, 3u32, 0u32, 0u32]
            .iter()
            .rev()
        {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = cfa;
        sb.run_until_sentinel().unwrap();
        let h_client = sb.cpu.regs.get32(Reg32::Eax);
        assert_ne!(h_client, 0xFFFF_FFFF, "client open should succeed");
        assert_ne!(h_client, h_server, "distinct handles");

        // Server WriteFile.
        sb.mmu.write_initializer(p_data_in, b"PING!").unwrap();
        let wfile = sb.registry.resolve("kernel32.dll", "WriteFile").unwrap();
        for &a in [h_server, p_data_in, 5u32, p_written, 0u32].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = wfile;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1);
        assert_eq!(sb.mmu.load32(p_written).unwrap(), 5);

        // Client ReadFile.
        let rfile = sb.registry.resolve("kernel32.dll", "ReadFile").unwrap();
        for &a in [h_client, p_data_out, 5u32, p_n_read, 0u32].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = rfile;
        sb.run_until_sentinel().unwrap();
        assert_eq!(sb.cpu.regs.get32(Reg32::Eax), 1);
        assert_eq!(sb.mmu.load32(p_n_read).unwrap(), 5);
        let mut got = [0u8; 5];
        for i in 0..5 {
            got[i] = sb.mmu.load8(p_data_out + i as u32).unwrap();
        }
        assert_eq!(&got, b"PING!");
    }

    /// the kernel32 thunk dispatch.
    #[test]
    fn enter_leave_critical_section_round_trip() {
        let mut sb = Sandbox::new();
        // Map a CRITICAL_SECTION scratch region.
        sb.mmu.map(0x400_0000, 0x1000, Perm::R | Perm::W);
        let cs = 0x400_0000u32;
        let enter = sb
            .registry
            .resolve("kernel32.dll", "EnterCriticalSection")
            .unwrap();
        let leave = sb
            .registry
            .resolve("kernel32.dll", "LeaveCriticalSection")
            .unwrap();
        // First enter: take ownership, recursion=1.
        sb.cpu.push32(&mut sb.mmu, cs).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = enter;
        sb.run_until_sentinel().unwrap();
        let h = sb.host.scheduler.critical_sections[&cs];
        match sb.host.scheduler.objects.get(&h).unwrap() {
            crate::sched::WaitObject::CriticalSection {
                owner, recursion, ..
            } => {
                assert_eq!(*owner, Some(1));
                assert_eq!(*recursion, 1);
            }
            _ => panic!(),
        }
        // Re-entry by same thread: recursion=2.
        sb.cpu.push32(&mut sb.mmu, cs).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = enter;
        sb.run_until_sentinel().unwrap();
        match sb.host.scheduler.objects.get(&h).unwrap() {
            crate::sched::WaitObject::CriticalSection { recursion, .. } => {
                assert_eq!(*recursion, 2);
            }
            _ => panic!(),
        }
        // First leave: recursion→1.
        sb.cpu.push32(&mut sb.mmu, cs).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = leave;
        sb.run_until_sentinel().unwrap();
        // Second leave: recursion→0, owner cleared.
        sb.cpu.push32(&mut sb.mmu, cs).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = leave;
        sb.run_until_sentinel().unwrap();
        match sb.host.scheduler.objects.get(&h).unwrap() {
            crate::sched::WaitObject::CriticalSection {
                owner, recursion, ..
            } => {
                assert_eq!(*owner, None);
                assert_eq!(*recursion, 0);
            }
            _ => panic!(),
        }
    }

    /// Phase 3b of the scheduler refactor: `CreateThread` mints
    /// a Ready thread, the scheduler context-switches into it
    /// the first time the bootstrap thread yields, and the new
    /// thread runs to its own RET_SENTINEL where it
    /// terminates. Verifies both halves of the round trip.
    #[test]
    fn create_thread_spawns_a_real_runnable_thread() {
        let mut sb = Sandbox::new();
        // Map a code page for the synthetic thread proc.
        sb.mmu.map(0x1000, 0x1000, Perm::R | Perm::X);
        // Thread proc: `mov eax, 0x42; ret 4` (stdcall, one arg
        // consumed; eax = exit code).
        let proc_va = 0x1010u32;
        let proc_code: [u8; 8] = [
            0xb8, 0x42, 0x00, 0x00, 0x00, // mov eax, 0x42
            0xc2, 0x04, 0x00, // ret 4
        ];
        sb.mmu.write_initializer(proc_va, &proc_code).unwrap();
        // Drive CreateThread via the kernel32 thunk so we exercise
        // the same code path a real codec would.
        let create_thread = sb.registry.resolve("kernel32.dll", "CreateThread").unwrap();
        // Push args right-to-left: (attrs, stack, start, param,
        // flags, p_tid) = (0, 0, proc_va, 0xCAFE, 0, 0).
        for &a in [0u32, 0, proc_va, 0xCAFE, 0, 0].iter().rev() {
            sb.cpu.push32(&mut sb.mmu, a).unwrap();
        }
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = create_thread;
        sb.run_until_sentinel().unwrap();
        let thread_handle = sb.cpu.regs.get32(Reg32::Eax);
        assert!(thread_handle >= crate::sched::WAIT_OBJECT_HANDLE_BASE);
        // The new thread is in the table, Ready, with its CPU
        // parked. TID 2 (bootstrap is 1).
        let t = sb.host.threads.get(&2).expect("new thread present");
        assert!(matches!(t.status, crate::sched::ThreadStatus::Ready));
        assert!(t.parked_cpu.is_some());
        assert_ne!(
            t.parked_cpu.as_ref().unwrap().regs.esp(),
            0,
            "stack was carved from the pool"
        );

        // Bootstrap now Sleeps — the scheduler must context
        // switch into the new thread, run it to its
        // RET_SENTINEL, mark it Terminated, and then come
        // back to the bootstrap (which wakes after the sleep
        // clock advances).
        let sleep_thunk = sb.registry.resolve("kernel32.dll", "Sleep").unwrap();
        // Sleep(1ms)
        sb.cpu.push32(&mut sb.mmu, 1u32).unwrap();
        sb.cpu.push32(&mut sb.mmu, RET_SENTINEL).unwrap();
        sb.cpu.regs.eip = sleep_thunk;
        sb.run_until_sentinel().unwrap();
        // After the run, the new thread should have ran to
        // completion (status Terminated, eax = 0x42 on its
        // parked CPU if any).
        let t = sb.host.threads.get(&2).expect("new thread still present");
        assert!(
            matches!(t.status, crate::sched::ThreadStatus::Terminated),
            "expected thread 2 Terminated, got {:?}",
            t.status
        );
    }
}

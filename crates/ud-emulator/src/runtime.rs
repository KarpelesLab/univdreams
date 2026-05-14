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
const HEAP_ARENA_START: u32 = 0x6000_0000;
const HEAP_ARENA_END: u32 = 0x7000_0000;

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

/// One sandbox instance per loaded codec DLL.
pub struct Sandbox {
    pub mmu: Mmu,
    pub cpu: Cpu,
    pub registry: Registry,
    pub host: HostState,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox {
    /// Create a fresh sandbox with the heap arena and stack
    /// pre-mapped, the kernel32 stub set registered, and the
    /// CPU's `esp` pointing at a freshly-allocated stack.
    pub fn new() -> Self {
        let mut mmu = Mmu::new();
        // Heap arena (R+W)
        mmu.map(
            HEAP_ARENA_START,
            HEAP_ARENA_END - HEAP_ARENA_START,
            Perm::R | Perm::W,
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
        // TEB / FS-segment data (R+W). Initialise FS:[0] = -1
        // (no SEH handler installed) and FS:[0x18] = TEB self
        // pointer per the Windows TEB ABI used by Win32 CRTs.
        mmu.map(TEB_BASE, TEB_SIZE, Perm::R | Perm::W);
        mmu.write_initializer(TEB_BASE, &SEH_END_OF_CHAIN.to_le_bytes())
            .expect("seed TEB FS:[0]");
        mmu.write_initializer(TEB_BASE + 0x18, &TEB_BASE.to_le_bytes())
            .expect("seed TEB FS:[0x18] (self pointer)");
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
            .with_const_arena(CONST_ARENA_START, CONST_ARENA_END);

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
            crate::com::mint_host_mem_allocator_class_factory(&mut host, &mut mmu, &registry)
        {
            host.com
                .register_class_factory(crate::com::CLSID_MEMORY_ALLOCATOR, factory);
        }

        Sandbox {
            mmu,
            cpu,
            registry,
            host,
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

    /// Load a PE32 DLL from `bytes`, mapping it into the
    /// sandbox's MMU. The returned [`Image`] holds the entry
    /// point + export table.
    pub fn load(&mut self, name: &str, bytes: &[u8]) -> Result<Image, crate::Error> {
        let mut loader = Loader::new(&mut self.mmu, &mut self.registry, &mut self.host);
        let img = loader.load(name, bytes)?;
        // Record primary module base so `GetModuleHandleA(NULL)`
        // returns the right value.
        self.host.primary_module_base = img.image_base;
        Ok(img)
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
        let target = image.export("DllMain").unwrap_or(image.entry_point);
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
            &self.registry,
            &mut self.host,
            target,
            &[h_module, reason, lpv_reserved],
        )
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
            &self.registry,
            &mut self.host,
            target,
            args,
        )
    }

    /// Drive the CPU until `eip == RET_SENTINEL`, dispatching to
    /// Win32 stubs whenever `eip` lands on a registered thunk
    /// address. Thin wrapper over [`crate::win32::run_until_sentinel`]
    /// kept for API stability.
    pub fn run_until_sentinel(&mut self) -> Result<(), crate::Error> {
        run_until_sentinel_free(&mut self.cpu, &mut self.mmu, &self.registry, &mut self.host)
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
            &self.registry,
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
            &self.registry,
            &mut self.host,
            hic,
        )
    }

    /// Read the codec's `ICINFO` block.
    pub fn ic_get_info(&mut self, hic: u32, cb: u32) -> Result<Vec<u8>, crate::Error> {
        vfw32::ic_get_info(
            &mut self.cpu,
            &mut self.mmu,
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
        crate::com::mint_host_filter_graph(&mut self.host, &mut self.mmu, &self.registry)
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
        )
    }

    /// Round 31 — mint a minimal HostIBaseFilter exposing
    /// `input_pin`.
    pub fn host_iface_r31_mint_base_filter(&mut self, input_pin: u32) -> Result<u32, crate::Error> {
        crate::com::host_iface_r31::mint_host_base_filter(
            &mut self.host,
            &mut self.mmu,
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
            &self.registry,
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
}

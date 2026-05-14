//! Win32 stub registry + per-DLL host implementations of the
//! functions the loaded codec DLLs import.
//!
//! Each stub is a Rust function pointer with the signature
//! [`StubFn`]. The PE loader, when populating the IAT, looks up
//! `(dll_name_lowercased, function_name)` in [`Registry`] and
//! writes the synthetic [`StubAddr`] (a guest address that lives
//! in the unmapped "thunk space" near `0xFFFE_0000`) into the
//! IAT slot.
//!
//! At call time, the integer ISA executor sees `eip` jump to a
//! thunk address. It detects this via [`Registry::is_thunk`]
//! and dispatches to the stub directly, popping the right number
//! of bytes off the guest stack for the calling convention.
//!
//! All stubs are stdcall (callee-cleanup) for round 1; the
//! `arg_dwords` field carries the count. Round-2 will add cdecl
//! (caller-cleanup) once vfw32 needs it.
//!
//! Reference for each function: the corresponding MSDN page
//! (linked in source comments next to each stub).

use std::collections::BTreeMap;

use crate::emulator::{Cpu, Mmu};

pub mod advapi32;
pub mod gdi32;
pub mod kernel32;
pub mod msvcrt;
pub mod ole32;
pub mod user32;
pub mod vfw32;
pub mod winmm;

/// First synthetic thunk address. Chosen well above any plausible
/// `ImageBase + section.VirtualAddress` so it cannot be mistaken
/// for a real DLL byte. Each registered stub gets the next
/// 16-byte slot.
pub const THUNK_BASE: u32 = 0xFFFE_0000;
const THUNK_STRIDE: u32 = 16;

/// Signature every Win32 stub uses.
///
/// Returns the dword to put in `eax` on return. The stub
/// internally reads its arguments off the guest stack via the
/// [`Cpu`] / [`Mmu`] handles. The runtime takes care of popping
/// `arg_dwords * 4` bytes from the guest stack after the stub
/// returns (stdcall callee-cleanup).
///
/// `&Registry` is passed so a stub can re-enter the run-loop to
/// call back into the guest (used by the round-2 `vfw32` stub
/// surface, which has to dispatch the codec DLL's `DriverProc`
/// before returning to the IAT caller).
pub type StubFn = fn(&mut Cpu, &mut Mmu, &mut HostState, &Registry) -> Result<u32, Win32Error>;

/// Information stored alongside each stub.
#[derive(Clone)]
pub struct StubEntry {
    pub dll: String,
    pub name: String,
    pub func: StubFn,
    /// Number of dword arguments to pop off the stack (stdcall
    /// callee-cleanup). cdecl callers will be added in round 2
    /// with a separate flag.
    pub arg_dwords: u32,
    /// The synthetic guest address that, when called, invokes
    /// this stub.
    pub thunk_addr: u32,
}

/// Errors a stub can raise. Wrapped in `crate::Error::Win32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Win32Error {
    /// No stub registered for the requested `(dll, name)` pair.
    /// PE-load-time error; surfaces from
    /// [`crate::pe::Loader::resolve_imports`].
    UnknownImport { dll: String, name: String },
    /// Stub-side argument validation failed.
    InvalidArgument { stub: &'static str, reason: String },
    /// Heap call referenced an unknown allocation.
    InvalidHeapBlock { stub: &'static str, addr: u32 },
}

impl core::fmt::Display for Win32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Win32Error::UnknownImport { dll, name } => {
                write!(f, "no Round-1 stub for import {dll}!{name}")
            }
            Win32Error::InvalidArgument { stub, reason } => {
                write!(f, "{stub}: {reason}")
            }
            Win32Error::InvalidHeapBlock { stub, addr } => {
                write!(f, "{stub}: unknown heap allocation {addr:#010x}")
            }
        }
    }
}

/// One entry in the open-codec table — a "Handle to Installable
/// Compressor" in MSDN's vfw32 vocabulary.
#[derive(Debug, Clone)]
pub struct HicEntry {
    /// 4-byte fcc type ('VIDC' for video).
    pub fcc_type: u32,
    /// 4-byte fcc handler ('cvid' for Cinepak, 'IV50' for Indeo 5).
    pub fcc_handler: u32,
    /// Open mode (vfw.h: 1 = ICMODE_COMPRESS, 2 = ICMODE_DECOMPRESS, …).
    pub mode: u32,
    /// VA of the codec DLL's `DriverProc` export (the entry point
    /// that every IC* call dispatches into).
    pub driver_proc_va: u32,
    /// `dwDriverId` to pass back to `DriverProc` on every call —
    /// the value `DriverProc(_, _, DRV_OPEN, _, _)` returned.
    pub driver_id: u32,
}

/// The host-side state every stub may read or mutate.
///
/// This is the "operating system" of the sandbox — the heap, the
/// LastError TLS, the pseudo-tick counter, the loaded-module
/// registry, etc. One per emulator instance.
#[derive(Default)]
pub struct HostState {
    /// Heap allocations keyed by guest address.
    pub heap: BTreeMap<u32, Vec<u8>>,
    /// Cursor for the next heap allocation. Walks through a
    /// dedicated guest-virtual region (configured by [`HostState::new`]).
    pub heap_cursor: u32,
    pub heap_arena_end: u32,
    /// Default process heap handle returned by `GetProcessHeap`.
    pub process_heap_handle: u32,
    /// Last error code (`SetLastError` / `GetLastError`).
    pub last_error: u32,
    /// Pseudo-tick counter incremented on every `GetTickCount`.
    pub tick: u32,
    /// Loaded-module registry: name → ImageBase.
    pub modules: BTreeMap<String, u32>,
    /// Most-recently-loaded codec module's image base — returned
    /// by `GetModuleHandleA(NULL)`. Set to 0 if no DLL has been
    /// loaded yet.
    pub primary_module_base: u32,
    /// Lines that the codec wrote to `OutputDebugString*`. Tests
    /// can introspect to confirm a known string was emitted.
    pub debug_log: Vec<String>,
    /// Lines that the codec wrote to `MessageBoxA` (also mirrored
    /// to `eprintln!`). Distinct from `debug_log` so a test can
    /// distinguish OutputDebugStringA traffic from real popups.
    pub message_box_log: Vec<String>,
    /// Open codec handles. Synthesised inside the host (no codec
    /// guest memory is consumed); each handle is a small integer
    /// the codec sees as an `HIC`.
    pub hics: BTreeMap<u32, HicEntry>,
    /// Counter for the next synthetic HIC. Starts at 1; 0 means
    /// "open failed".
    pub next_hic: u32,
    /// Default `DriverProc` VA used when a host caller invokes an
    /// `IC*` stub but has not staged a real codec image (i.e. for
    /// the no-fixture unit tests). Set to 0 when no codec is
    /// loaded — `ICOpen` then refuses to mint a HIC.
    pub default_driver_proc: u32,
    /// Set by `kernel32!ExitProcess` to break out of the
    /// emulator loop in lieu of unwinding to `RET_SENTINEL`.
    /// `Some(code)` means "the codec asked to terminate"; the
    /// run-loop converts this into a clean return so the calling
    /// host code can introspect what happened.
    pub exit_requested: Option<u32>,
    /// Read-only constant-data arena. Used by stubs like
    /// `GetCommandLineA` / `GetEnvironmentStrings` that need to
    /// hand out stable guest pointers to canned strings. The
    /// slab grows by `arena_const_alloc` and lives at
    /// `[const_arena_start, const_arena_end)`. Configured by
    /// [`HostState::new`] like the heap arena.
    pub const_arena_cursor: u32,
    pub const_arena_end: u32,
    /// Cached pointer to the canned `"oxideav-vfw\0"` command
    /// line. Lazily populated by `GetCommandLineA`.
    pub command_line_ptr: u32,
    /// Cached pointer to the canned empty environment block.
    pub environment_strings_ptr: u32,
    /// Currently-live `HDC` values handed out by
    /// `gdi32!CreateCompatibleDC` / `user32!GetDC`. `None` until
    /// the first DC is allocated, then a populated set.
    pub gdi_hdcs: Option<std::collections::BTreeSet<u32>>,
    /// Round 26 — synthetic `HWND` registry. `CreateWindowExA`
    /// hands out `HWND_BASE + n` values; `IsWindow` consults this
    /// set; `DestroyWindow` removes from it. None of these HWNDs
    /// back a real window — DirectShow / VfW codecs only need the
    /// `HWND` value to feel non-NULL so they fall through to
    /// their headless code path.
    pub hwnd_registry: std::collections::BTreeSet<u32>,
    /// Counter for the next synthetic HWND allocation. Starts at
    /// 0; first HWND handed out is `HWND_BASE + 0`.
    pub next_hwnd_index: u32,
    /// When `true`, [`dispatch_stub`] appends one line per Win32
    /// call to [`stub_trace`]. Off by default; round-8 tests flip
    /// it on while triaging which stub returns a bad value.
    pub trace_stubs: bool,
    /// Per-call trace lines populated when [`trace_stubs`] is on.
    pub stub_trace: Vec<String>,
    /// Set of `DriverProc` VAs that have already received the
    /// one-time `DRV_LOAD` + `DRV_ENABLE` initialisation pair.
    /// Round 11 — without this, `IR50_32.DLL`'s `DRV_LOAD` handler
    /// (which allocates the codec's huffman / inverse-DCT tables
    /// at `[0x1009c770]`) never runs, and `ICDecompress` later
    /// reads `[0x1009c770] == NULL` and bails with
    /// `ICERR_BADIMAGE`. We track per-VA so multi-codec sandboxes
    /// (round 12+) don't double-load the same driver.
    pub loaded_drivers: std::collections::BTreeSet<u32>,
    /// Per-loaded-module resource directory location:
    /// `image_base → resource_dir_va`. Empty if the module has no
    /// `.rsrc` (PE Data Directory entry 2). Round 12 needs this so
    /// that `kernel32!FindResourceA` on `IR50_32.DLL` can locate
    /// the RT_BITMAP/112 entry that holds the codec's huffman /
    /// inverse-DCT tables. Without it the codec's `DRV_LOAD`
    /// chain bails at `0x10034d31 (jz 0x10034f61)` and
    /// `[0x1009c770]` stays NULL.
    pub module_resource_dirs: BTreeMap<u32, u32>,
    /// Round 25 — host-side bookkeeping for COM objects the
    /// guest has handed back to the test harness (live class
    /// factories + IBaseFilter pointers etc).  See
    /// [`crate::com::ComObjectTable`] for the data layout.  Each
    /// `ole32!CoCreateInstance` and every test-side
    /// `query_interface` / `add_ref` / `release` updates this
    /// table so a missing `Release` surfaces as a non-zero
    /// `total_refcount()` at end-of-test.
    pub com: crate::com::ComObjectTable,
    /// Round 55 — PRNG state for `msvcrt!rand` calls from
    /// sandboxed codec code.  Default `1` matches MSVC's
    /// documented "no `srand` called yet" initial state.
    /// Updated by both `msvcrt!srand(seed)` (from guest code)
    /// and by `Sandbox::set_rand_seed` / `with_rand_seed` (from
    /// host code) — they share the same field so the host can
    /// observe what the codec did to the state, and the codec
    /// can override the host-staged seed via its own `srand`.
    /// LCG step (Knuth-style, mod 2^32, output bits 30..16
    /// masked to 15 bits per MSVC's documented contract):
    ///
    /// ```text
    /// state = state * 214013 + 2531011  (mod 2^32)
    /// rand  = (state >> 16) & 0x7FFF
    /// ```
    pub rand_state: u32,
}

impl HostState {
    /// Construct a HostState with the heap arena at `[heap_start,
    /// heap_end)` (caller is responsible for mapping that region
    /// in the MMU as R+W).
    ///
    /// The const-arena (used for canned strings handed back from
    /// `GetCommandLineA` / `GetEnvironmentStrings` / etc.) is
    /// **not** allocated here — call [`Self::with_const_arena`]
    /// to set it up if those stubs are exercised. Tests that
    /// don't use them can leave it at zero.
    pub fn new(heap_start: u32, heap_end: u32) -> Self {
        HostState {
            heap_cursor: heap_start,
            heap_arena_end: heap_end,
            process_heap_handle: 0xDEAD_BEEF,
            last_error: 0,
            tick: 0,
            heap: BTreeMap::new(),
            modules: BTreeMap::new(),
            primary_module_base: 0,
            debug_log: Vec::new(),
            message_box_log: Vec::new(),
            hics: BTreeMap::new(),
            next_hic: 1,
            default_driver_proc: 0,
            exit_requested: None,
            const_arena_cursor: 0,
            const_arena_end: 0,
            command_line_ptr: 0,
            environment_strings_ptr: 0,
            gdi_hdcs: None,
            hwnd_registry: std::collections::BTreeSet::new(),
            next_hwnd_index: 0,
            trace_stubs: false,
            stub_trace: Vec::new(),
            loaded_drivers: std::collections::BTreeSet::new(),
            module_resource_dirs: BTreeMap::new(),
            com: crate::com::ComObjectTable::new(),
            // MSVC documents the C standard's "no `srand` called yet"
            // initial state as `state = 1`.  See round 55 + the
            // `rand_state` field doc comment for the LCG contract.
            rand_state: 1,
        }
    }

    /// Configure the const-arena (region for canned read-only
    /// strings handed back to the codec). `[start, end)` is a
    /// guest-virtual range the caller has already mapped R+W
    /// (the arena bytes are written via `write_initializer`,
    /// so any page perms suffice as long as the page is mapped).
    pub fn with_const_arena(mut self, start: u32, end: u32) -> Self {
        self.const_arena_cursor = start;
        self.const_arena_end = end;
        self
    }

    /// Bump-allocate `n` bytes in the const arena. Returns the
    /// guest address of the new slab. The caller is responsible
    /// for [`Mmu::write_initializer`]'ing the contents.
    pub fn arena_const_alloc(&mut self, n: u32) -> Result<u32, Win32Error> {
        let aligned = n
            .checked_add(15)
            .map(|v| v & !15u32)
            .ok_or(Win32Error::InvalidArgument {
                stub: "arena_const_alloc",
                reason: "size overflow".into(),
            })?;
        let addr = self.const_arena_cursor;
        let next = addr
            .checked_add(aligned)
            .ok_or(Win32Error::InvalidArgument {
                stub: "arena_const_alloc",
                reason: "const arena address-space overflow".into(),
            })?;
        if next > self.const_arena_end {
            return Err(Win32Error::InvalidArgument {
                stub: "arena_const_alloc",
                reason: format!(
                    "const arena exhausted (need {n}, have {})",
                    self.const_arena_end - addr
                ),
            });
        }
        self.const_arena_cursor = next;
        Ok(addr)
    }

    /// Allocate a fresh slab in the heap arena and return its
    /// guest address. Used by the round-2 marshalling helpers to
    /// stage `ICDECOMPRESS` / `BITMAPINFOHEADER` / raw-frame
    /// buffers in guest memory before calling `DriverProc`.
    pub fn arena_alloc(&mut self, n: u32) -> Result<u32, Win32Error> {
        let aligned = n
            .checked_add(15)
            .map(|v| v & !15u32)
            .ok_or(Win32Error::InvalidArgument {
                stub: "arena_alloc",
                reason: "size overflow".into(),
            })?;
        let addr = self.heap_cursor;
        let next = addr
            .checked_add(aligned)
            .ok_or(Win32Error::InvalidArgument {
                stub: "arena_alloc",
                reason: "heap address-space overflow".into(),
            })?;
        if next > self.heap_arena_end {
            return Err(Win32Error::InvalidArgument {
                stub: "arena_alloc",
                reason: format!(
                    "arena exhausted (need {n}, have {})",
                    self.heap_arena_end - addr
                ),
            });
        }
        self.heap_cursor = next;
        self.heap.insert(addr, vec![0u8; n as usize]);
        Ok(addr)
    }
}

/// Stub registry. Created once per emulator instance.
#[derive(Default)]
pub struct Registry {
    by_thunk: BTreeMap<u32, StubEntry>,
    by_name: BTreeMap<(String, String), u32>,
    next_slot: u32,
    /// Per-(dll, name) **data imports**. Some CRT symbols are
    /// imported by name but are read as data (e.g.
    /// `msvcrt!_adjust_fdiv`, an `int` flag the FDIV-erratum
    /// fix-up code consults). The PE loader treats their IAT
    /// slots as `mov ecx, [iat]; mov edx, [ecx]` — the IAT
    /// slot is the address OF a 4-byte int, not a function
    /// pointer. We pre-allocate a small read/write region for
    /// these and patch the IAT slot to its address. The
    /// `(value)` is whatever the symbol is documented to hold;
    /// 0 is the safe default.
    data_imports: BTreeMap<(String, String), DataImport>,
    /// Bump cursor in the data-import slot region (assigned
    /// addresses live in `[DATA_IMPORT_BASE, DATA_IMPORT_BASE +
    /// DATA_IMPORT_SIZE)`).
    next_data_slot: u32,
}

/// One data-import slot, addressed via [`Registry::resolve`].
#[derive(Clone, Copy, Debug)]
pub struct DataImport {
    /// Guest address of the 4-byte slot. The PE loader patches
    /// the IAT entry with this value.
    pub addr: u32,
    /// Initial value to seed into `[addr]` at first slot
    /// allocation. Subsequent registrations of the same name
    /// keep the prior value.
    pub initial: u32,
}

/// Region reserved for data-import slots — see [`DataImport`].
/// 4 KiB is plenty: the entire CRT data-import set is fewer
/// than 16 dwords across all codecs we expect to load.
pub const DATA_IMPORT_BASE: u32 = 0x7010_0000;
const DATA_IMPORT_SIZE: u32 = 0x0000_1000;
const DATA_IMPORT_END: u32 = DATA_IMPORT_BASE + DATA_IMPORT_SIZE;

impl Registry {
    pub fn new() -> Self {
        Registry {
            by_thunk: BTreeMap::new(),
            by_name: BTreeMap::new(),
            next_slot: 0,
            data_imports: BTreeMap::new(),
            next_data_slot: DATA_IMPORT_BASE,
        }
    }

    /// Register a data import — a 4-byte symbol the codec
    /// reads via `mov reg, [iat]; mov reg, [reg]`. Returns
    /// the guest address that the IAT slot should point at.
    /// Subsequent calls with the same `(dll, name)` return the
    /// previously assigned slot.
    pub fn register_data(&mut self, dll: &str, name: &str, initial: u32) -> u32 {
        let key = (dll.to_ascii_lowercase(), name.to_string());
        if let Some(d) = self.data_imports.get(&key) {
            return d.addr;
        }
        let addr = self.next_data_slot;
        let next = addr.saturating_add(4);
        if next > DATA_IMPORT_END {
            // Caller asked to register more data imports than
            // we reserved space for. Return 0 — the loader
            // handles "unresolved" by falling back to a thunk
            // that will trap loudly.
            return 0;
        }
        self.next_data_slot = next;
        self.data_imports.insert(key, DataImport { addr, initial });
        // Also expose it through the by-name resolver so the
        // PE loader's ordinary lookup picks it up. The
        // returned address is in the data region (not a thunk
        // — `is_thunk(addr)` will correctly return false).
        self.by_name
            .insert((dll.to_ascii_lowercase(), name.to_string()), addr);
        addr
    }

    /// Iterate the registered data imports. The PE loader uses
    /// this to seed each slot's `initial` value into MMU memory
    /// after the data-import region has been mapped.
    pub fn data_imports(&self) -> impl Iterator<Item = (&String, &String, &DataImport)> {
        self.data_imports
            .iter()
            .map(|((dll, name), d)| (dll, name, d))
    }

    /// Register a stub. Returns the synthetic thunk address that
    /// the IAT slot should be populated with.
    pub fn register(&mut self, dll: &str, name: &str, func: StubFn, arg_dwords: u32) -> u32 {
        let key = (dll.to_ascii_lowercase(), name.to_string());
        if let Some(addr) = self.by_name.get(&key) {
            return *addr;
        }
        let thunk_addr = THUNK_BASE.wrapping_add(self.next_slot.wrapping_mul(THUNK_STRIDE));
        self.next_slot += 1;
        self.by_name.insert(key.clone(), thunk_addr);
        self.by_thunk.insert(
            thunk_addr,
            StubEntry {
                dll: key.0,
                name: key.1,
                func,
                arg_dwords,
                thunk_addr,
            },
        );
        thunk_addr
    }

    /// Resolve an import. The PE loader uses this when populating
    /// IAT slots. `dll_name` is matched case-insensitively.
    pub fn resolve(&self, dll: &str, name: &str) -> Option<u32> {
        let key = (dll.to_ascii_lowercase(), name.to_string());
        self.by_name.get(&key).copied()
    }

    /// True iff `addr` is a registered thunk address.
    pub fn is_thunk(&self, addr: u32) -> bool {
        self.by_thunk.contains_key(&addr)
    }

    /// Look up the stub entry by its thunk address. Used by the
    /// runtime when it sees `eip == thunk_addr`.
    pub fn entry(&self, addr: u32) -> Option<&StubEntry> {
        self.by_thunk.get(&addr)
    }

    /// Convenience: register every kernel32 stub. Returns the
    /// number of stubs registered.
    pub fn register_kernel32(&mut self) -> usize {
        let before = self.by_name.len();
        kernel32::register(self);
        self.by_name.len() - before
    }

    /// Register every gdi32 stub. Returns the number registered.
    pub fn register_gdi32(&mut self) -> usize {
        let before = self.by_name.len();
        gdi32::register(self);
        self.by_name.len() - before
    }

    /// Register every user32 stub. Returns the number registered.
    pub fn register_user32(&mut self) -> usize {
        let before = self.by_name.len();
        user32::register(self);
        self.by_name.len() - before
    }

    /// Register every winmm stub. Returns the number registered.
    pub fn register_winmm(&mut self) -> usize {
        let before = self.by_name.len();
        winmm::register(self);
        self.by_name.len() - before
    }

    /// Register every advapi32 stub. Returns the number registered.
    pub fn register_advapi32(&mut self) -> usize {
        let before = self.by_name.len();
        advapi32::register(self);
        self.by_name.len() - before
    }

    /// Register every ole32 stub. Returns the number registered.
    pub fn register_ole32(&mut self) -> usize {
        let before = self.by_name.len();
        ole32::register(self);
        self.by_name.len() - before
    }

    /// Register every msvcrt stub. Returns the number registered.
    pub fn register_msvcrt(&mut self) -> usize {
        let before = self.by_name.len();
        msvcrt::register(self);
        self.by_name.len() - before
    }

    /// Register every Round-1+4+8+20 stub family in one call:
    /// kernel32, gdi32, user32, winmm, advapi32, ole32, msvcrt,
    /// plus the round-27 host-COM thunk family used by
    /// [`crate::com::mint_host_filter_graph`].  Returns the total
    /// number registered.
    pub fn register_all(&mut self) -> usize {
        let host_before = self.by_name.len();
        crate::com::host_iface::register(self);
        crate::com::host_iface_r31::register(self);
        let host_count = self.by_name.len() - host_before;
        self.register_kernel32()
            + self.register_gdi32()
            + self.register_user32()
            + self.register_winmm()
            + self.register_advapi32()
            + self.register_ole32()
            + self.register_msvcrt()
            + host_count
    }
}

/// Read the `n`-th stdcall dword argument off the guest stack.
///
/// At entry, `esp` points to the saved return address (pushed by
/// the caller's CALL); the first argument is at `esp+4`, the
/// second at `esp+8`, etc.
pub fn arg_dword(cpu: &Cpu, mmu: &Mmu, n: u32) -> Result<u32, crate::emulator::Trap> {
    let addr = cpu.regs.esp().wrapping_add(4u32 * (n + 1));
    mmu.load32(addr)
}

/// Cdecl arg-count override table for trace-event extraction.
///
/// Stdcall stubs already declare their argument count in
/// [`StubEntry::arg_dwords`] (the value the dispatch site uses
/// to pop the stack on return). Cdecl stubs declare `0` because
/// the *caller* cleans the stack — but the args are still on the
/// stack at call entry. For known-shape cdecl entries we return
/// the per-call dword count so the trace probe can read those
/// dwords back into `args[]` on `kind=win32_call` events.
///
/// Returns `None` if the `(dll, name)` pair has no override; in
/// that case the trace site falls back to the registered
/// `arg_dwords` (0 for any cdecl stub, leaving `args:[]` as
/// before — so this is purely additive).
///
/// Reference: `docs/video/msmpeg4/audit/06-sandbox-O3-quant-init.md`
/// §5.2.3 — Auditor needs allocation sizes surfaced at call
/// time so the codec-context allocation can be located by size
/// match rather than by return-address differencing.
pub fn cdecl_trace_arg_count(dll: &str, name: &str) -> Option<u32> {
    match (dll, name) {
        // Heap surface — single-arg shapes.
        //   void* malloc(size_t)                              — 1
        //   void  free(void*)                                 — 1
        //   void* operator new(unsigned int)  ??2@YAPAXI@Z    — 1
        //   void  operator delete(void*)      ??3@YAXPAX@Z    — 1
        ("msvcrt.dll", "malloc")
        | ("msvcrt.dll", "free")
        | ("msvcrt.dll", "??2@YAPAXI@Z")
        | ("msvcrt.dll", "??3@YAXPAX@Z") => Some(1),
        // Two-arg shapes — not registered today but cheap to
        // pre-declare so a future `register("msvcrt.dll",
        // "calloc"/"realloc", ...)` automatically gets traced
        // args without revisiting this table.
        //   void* calloc(size_t count, size_t size)           — 2
        //   void* realloc(void*, size_t)                      — 2
        ("msvcrt.dll", "calloc") | ("msvcrt.dll", "realloc") => Some(2),
        _ => None,
    }
}

/// Convert an MMU/CPU [`crate::emulator::Trap`] into a [`Win32Error`]
/// so a stub's argument-fetch failure surfaces as
/// `Win32Error::InvalidArgument`. Used by the gdi32 / user32 /
/// winmm modules.
pub fn trap_to_win32_local(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}

/// Read a NUL-terminated 8-bit string from guest memory at `addr`,
/// stopping at NUL or after `max` bytes. Used by user32/winmm
/// stubs that take an `LPCSTR`.
pub fn read_cstr_local(mmu: &Mmu, mut addr: u32, max: u32) -> Result<String, Win32Error> {
    let mut bytes = Vec::new();
    for _ in 0..max {
        let b = mmu
            .load8(addr)
            .map_err(|t| trap_to_win32_local("read_cstr", t))?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        addr = addr.wrapping_add(1);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Dispatch a stub call. The runtime wires this into the executor
/// so that whenever `eip` lands on a thunk address, control
/// transfers here instead of fetching instruction bytes.
///
/// On entry: the guest CALL has already pushed the return
/// address; `eip` is the thunk address. On exit: `eax` holds the
/// stub's return value, `eip` is the popped return address, and
/// `arg_dwords*4` bytes have been removed from the stack
/// (stdcall callee-cleanup).
pub fn dispatch_stub(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
) -> Result<(), crate::Error> {
    let addr = cpu.regs.eip;
    let entry = registry
        .entry(addr)
        .ok_or_else(|| Win32Error::UnknownImport {
            dll: "<thunk>".into(),
            name: format!("@{:#010x}", addr),
        })?
        .clone();
    // Trace probe (gated): capture the call-site EIP (= the
    // saved return address pushed by the guest CALL — the
    // instruction right after the CALL, not the thunk address)
    // and the first few args off the guest stack BEFORE running
    // the stub, since the stub mutates the stack.
    //
    // Argument count: `entry.arg_dwords` carries the stdcall
    // count (the value used to pop the stack on return).
    // For cdecl stubs this is 0 — but for known cdecl shapes
    // (msvcrt heap entries) [`cdecl_trace_arg_count`] supplies a
    // per-call override so trace events surface the size /
    // pointer args rather than `args:[]`. See
    // `docs/video/msmpeg4/audit/06-sandbox-O3-quant-init.md`
    // §5.2.3 for the auditor requirement.
    #[cfg(feature = "trace")]
    let trace_args: Option<(u32, Vec<u32>)> = if mmu.trace.has_sink() {
        let call_site_eip = mmu.load32(cpu.regs.esp()).unwrap_or(0);
        let n_args = cdecl_trace_arg_count(&entry.dll, &entry.name).unwrap_or(entry.arg_dwords);
        let mut args = Vec::with_capacity(n_args as usize);
        for i in 0..n_args {
            let a = arg_dword(cpu, mmu, i).unwrap_or(0);
            args.push(a);
        }
        Some((call_site_eip, args))
    } else {
        None
    };
    // Run the host-side stub.
    let ret = (entry.func)(cpu, mmu, state, registry)?;
    if state.trace_stubs {
        state
            .stub_trace
            .push(format!("{}!{} → {:#010x}", entry.dll, entry.name, ret));
    }
    // Emit the trace event with the captured args + the actual
    // return value. Done before stack unwind so the EIP we log
    // is the call site, not the post-return PC.
    #[cfg(feature = "trace")]
    if let Some((call_site_eip, args)) = trace_args {
        mmu.trace
            .ev_win32_call(&entry.dll, &entry.name, &args, ret, call_site_eip);
    }
    // stdcall: pop return address, advance esp by arg_dwords*4,
    // set eax to the return value.
    let ret_addr = cpu.pop32(mmu)?;
    cpu.regs.set32(crate::emulator::regs::Reg32::Eax, ret);
    let new_esp = cpu
        .regs
        .esp()
        .wrapping_add(entry.arg_dwords.wrapping_mul(4));
    cpu.regs.set_esp(new_esp);
    cpu.regs.eip = ret_addr;
    Ok(())
}

/// Run the emulator until `eip == RET_SENTINEL`, dispatching to
/// any Win32 stub thunk addresses encountered along the way.
///
/// This is the shared run-loop body used both by [`crate::Sandbox`]
/// and by re-entrant host stubs (notably the `vfw32` surface,
/// which dispatches the codec's `DriverProc` synchronously
/// inside an outer `IC*` call).
pub fn run_until_sentinel(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
) -> Result<(), crate::Error> {
    use crate::emulator::isa_int::{StepOk, RET_SENTINEL};
    loop {
        if state.exit_requested.is_some() {
            // `kernel32!ExitProcess` was called. Force eip to
            // the sentinel so the outer caller's stack-frame
            // cleanup is consistent and exit cleanly.
            cpu.regs.eip = RET_SENTINEL;
            return Ok(());
        }
        if cpu.regs.eip == RET_SENTINEL {
            return Ok(());
        }
        if registry.is_thunk(cpu.regs.eip) {
            match dispatch_stub(cpu, mmu, registry, state) {
                Ok(()) => continue,
                Err(e) => {
                    #[cfg(feature = "trace")]
                    emit_trap_event(cpu, mmu, &e);
                    return Err(e);
                }
            }
        }
        match cpu.step(mmu) {
            Ok(StepOk::Continued) => continue,
            Ok(StepOk::Halted) => return Ok(()),
            Err(t) => {
                let e: crate::Error = t.into();
                #[cfg(feature = "trace")]
                emit_trap_event(cpu, mmu, &e);
                return Err(e);
            }
        }
    }
}

/// Trace-feature-gated: format the trap variant + register
/// snapshot and push one `kind=trap` JSONL event.
#[cfg(feature = "trace")]
fn emit_trap_event(cpu: &Cpu, mmu: &Mmu, err: &crate::Error) {
    use crate::emulator::regs::Reg32;
    let (label, eip, opcode) = match err {
        crate::Error::Trap(t) => match t {
            crate::emulator::Trap::MemoryFault { addr } => ("MemoryFault", *addr, None::<u32>),
            crate::emulator::Trap::ReadProtectFault { addr } => ("ReadProtectFault", *addr, None),
            crate::emulator::Trap::WriteProtectFault { addr } => ("WriteProtectFault", *addr, None),
            crate::emulator::Trap::ExecuteProtectFault { addr } => {
                ("ExecuteProtectFault", *addr, None)
            }
            crate::emulator::Trap::UndefinedOpcode { eip, opcode } => {
                ("UndefinedOpcode", *eip, Some(*opcode))
            }
            crate::emulator::Trap::PrivilegedOpcode { eip, .. } => ("PrivilegedOpcode", *eip, None),
            crate::emulator::Trap::DivideByZero { eip } => ("DivideByZero", *eip, None),
            crate::emulator::Trap::UnresolvedImport { .. } => {
                ("UnresolvedImport", cpu.regs.eip, None)
            }
            crate::emulator::Trap::InstructionLimitExceeded { eip, .. } => {
                ("InstructionLimitExceeded", *eip, None)
            }
            crate::emulator::Trap::UnimplementedMmx { eip, opcode, .. } => {
                ("UnimplementedMmx", *eip, Some(*opcode))
            }
        },
        crate::Error::PeLoader(_) => ("PeLoader", cpu.regs.eip, None),
        crate::Error::Win32(_) => ("Win32", cpu.regs.eip, None),
        crate::Error::NotImplemented => ("NotImplemented", cpu.regs.eip, None),
    };
    let regs = [
        ("eax", cpu.regs.get32(Reg32::Eax)),
        ("ecx", cpu.regs.get32(Reg32::Ecx)),
        ("edx", cpu.regs.get32(Reg32::Edx)),
        ("ebx", cpu.regs.get32(Reg32::Ebx)),
        ("esp", cpu.regs.esp()),
        ("ebp", cpu.regs.get32(Reg32::Ebp)),
        ("esi", cpu.regs.get32(Reg32::Esi)),
        ("edi", cpu.regs.get32(Reg32::Edi)),
    ];
    mmu.trace.ev_trap(label, eip, opcode, &regs);
}

/// Push args right-to-left, push the synthetic `RET_SENTINEL`,
/// jump to `target_va`, run the emulator until it returns,
/// and report the final `eax` value.
///
/// This is the building block both `Sandbox::call_dll_main`
/// and the round-2 `vfw32` stub surface use to invoke an
/// exported guest function with stdcall calling convention.
/// On entry, `cpu.regs.eip` may be anything; on exit it is
/// the popped return address (= `RET_SENTINEL`). Caller-saved
/// registers are not preserved beyond what the guest callee
/// preserves itself.
pub fn call_guest(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    target_va: u32,
    args: &[u32],
) -> Result<u32, crate::Error> {
    use crate::emulator::isa_int::RET_SENTINEL;
    use crate::emulator::regs::Reg32;
    // Push args right-to-left.
    for a in args.iter().rev() {
        cpu.push32(mmu, *a)?;
    }
    cpu.push32(mmu, RET_SENTINEL)?;
    cpu.regs.eip = target_va;
    run_until_sentinel(cpu, mmu, registry, state)?;
    Ok(cpu.regs.get32(Reg32::Eax))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::{mmu::Perm, Mmu};

    fn dummy_stub(
        _cpu: &mut Cpu,
        _mmu: &mut Mmu,
        _h: &mut HostState,
        _r: &Registry,
    ) -> Result<u32, Win32Error> {
        Ok(0xCAFE)
    }

    #[test]
    fn registry_assigns_stable_thunk_addresses() {
        let mut r = Registry::new();
        let a = r.register("kernel32.dll", "Foo", dummy_stub, 1);
        let b = r.register("kernel32.dll", "Bar", dummy_stub, 0);
        let a2 = r.register("kernel32.dll", "Foo", dummy_stub, 1);
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(r.is_thunk(a));
    }

    #[test]
    fn registry_resolve_is_case_insensitive_on_dll_name() {
        let mut r = Registry::new();
        let addr = r.register("KERNEL32.DLL", "GetProcessHeap", dummy_stub, 0);
        assert_eq!(r.resolve("kernel32.dll", "GetProcessHeap"), Some(addr));
        assert_eq!(r.resolve("Kernel32.Dll", "GetProcessHeap"), Some(addr));
    }

    #[test]
    fn cdecl_trace_arg_count_covers_msvcrt_heap_surface() {
        // Single-arg msvcrt cdecl entries.
        assert_eq!(cdecl_trace_arg_count("msvcrt.dll", "malloc"), Some(1));
        assert_eq!(cdecl_trace_arg_count("msvcrt.dll", "free"), Some(1));
        assert_eq!(
            cdecl_trace_arg_count("msvcrt.dll", "??2@YAPAXI@Z"),
            Some(1),
            "operator new",
        );
        assert_eq!(
            cdecl_trace_arg_count("msvcrt.dll", "??3@YAXPAX@Z"),
            Some(1),
            "operator delete",
        );
        // Two-arg msvcrt cdecl entries (pre-declared for future
        // calloc / realloc registrations).
        assert_eq!(cdecl_trace_arg_count("msvcrt.dll", "calloc"), Some(2));
        assert_eq!(cdecl_trace_arg_count("msvcrt.dll", "realloc"), Some(2));
    }

    #[test]
    fn cdecl_trace_arg_count_returns_none_for_unknown_calls() {
        assert_eq!(
            cdecl_trace_arg_count("kernel32.dll", "GetProcessHeap"),
            None
        );
        assert_eq!(cdecl_trace_arg_count("msvcrt.dll", "memcpy"), None);
        assert_eq!(
            cdecl_trace_arg_count("MSVCRT.DLL", "malloc"),
            None,
            "match is exact-case on dll string per registry contract"
        );
    }

    #[cfg(feature = "trace")]
    #[test]
    fn dispatch_emits_size_arg_for_msvcrt_malloc() {
        use std::sync::{Arc, Mutex};

        // Capture sink shared between TraceState (owns Box<dyn Write>)
        // and the test (reads back the JSONL line).
        struct CapSink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for CapSink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Arc::new(Mutex::new(Vec::new()));

        // Bring up an MMU + CPU + registry exactly as a real
        // dispatch would see them.
        let mut mmu = Mmu::new();
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        mmu.trace.set_sink(Box::new(CapSink(Arc::clone(&buf))));

        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x7000);

        let mut registry = Registry::new();
        // Register a dummy malloc-shaped stub at the msvcrt slot.
        // The stub returns a known pointer (the value the trace
        // event records as `ret`); the SIZE arg comes from the
        // stack at [esp+4] and must surface as `args:[2928]`.
        fn dummy_malloc_stub(
            _cpu: &mut Cpu,
            _mmu: &mut Mmu,
            _h: &mut HostState,
            _r: &Registry,
        ) -> Result<u32, Win32Error> {
            Ok(0x6000_0000)
        }
        let addr = registry.register("msvcrt.dll", "malloc", dummy_malloc_stub, 0);

        // Cdecl call frame: ret addr at [esp], size at [esp+4].
        // 2928 == 0xb70 — matches the auditor reference value.
        cpu.push32(&mut mmu, 2928).unwrap(); // arg0 (size)
        cpu.push32(&mut mmu, 0x1c218058).unwrap(); // saved ret addr (call-site EIP)

        cpu.regs.eip = addr;
        let mut state = HostState::new(0, 0);
        dispatch_stub(&mut cpu, &mut mmu, &registry, &mut state).unwrap();

        // The captured JSONL line should carry args:[2928] (decimal,
        // matching the existing ev_win32_call format), the dummy
        // pointer in `ret`, and the call-site EIP (NOT the thunk).
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"win32_call""#), "line: {s}");
        assert!(s.contains(r#""dll":"msvcrt.dll""#), "line: {s}");
        assert!(s.contains(r#""name":"malloc""#), "line: {s}");
        assert!(
            s.contains(r#""args":[2928]"#),
            "expected args:[2928] (== 0xb70), got: {s}",
        );
        assert!(s.contains(r#""ret":"0x60000000""#), "line: {s}");
        assert!(s.contains(r#""eip":"0x1c218058""#), "line: {s}");
    }

    #[cfg(feature = "trace")]
    #[test]
    fn dispatch_emits_pointer_arg_for_msvcrt_operator_delete() {
        use std::sync::{Arc, Mutex};
        struct CapSink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for CapSink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Arc::new(Mutex::new(Vec::new()));
        let mut mmu = Mmu::new();
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        mmu.trace.set_sink(Box::new(CapSink(Arc::clone(&buf))));
        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x7000);
        let mut registry = Registry::new();
        fn dummy_delete_stub(
            _cpu: &mut Cpu,
            _mmu: &mut Mmu,
            _h: &mut HostState,
            _r: &Registry,
        ) -> Result<u32, Win32Error> {
            Ok(0)
        }
        let addr = registry.register("msvcrt.dll", "??3@YAXPAX@Z", dummy_delete_stub, 0);
        cpu.push32(&mut mmu, 0x6000_02c0).unwrap(); // ptr arg
        cpu.push32(&mut mmu, 0x1c237e58).unwrap(); // saved ret
        cpu.regs.eip = addr;
        let mut state = HostState::new(0, 0);
        dispatch_stub(&mut cpu, &mut mmu, &registry, &mut state).unwrap();
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            s.contains(r#""args":[1610613440]"#),
            "expected args:[1610613440] (== 0x600002c0), got: {s}",
        );
        assert!(s.contains(r#""name":"??3@YAXPAX@Z""#), "line: {s}");
    }

    #[test]
    fn dispatch_pops_return_addr_and_args() {
        let mut mmu = Mmu::new();
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x7000);

        let mut registry = Registry::new();
        let addr = registry.register("kernel32.dll", "Sample", dummy_stub, 2);

        // Lay out a fake call frame: ret addr, arg1, arg2.
        cpu.push32(&mut mmu, 0x4444).unwrap(); // arg2
        cpu.push32(&mut mmu, 0x3333).unwrap(); // arg1
        cpu.push32(&mut mmu, 0x2222).unwrap(); // saved ret addr
        let esp_before = cpu.regs.esp();

        cpu.regs.eip = addr;
        let mut state = HostState::new(0, 0);
        dispatch_stub(&mut cpu, &mut mmu, &registry, &mut state).unwrap();

        // After: eax=0xCAFE, eip = ret addr, esp pops 12 bytes
        // total (1 ret + 2 args).
        assert_eq!(cpu.regs.get32(crate::emulator::regs::Reg32::Eax), 0xCAFE);
        assert_eq!(cpu.regs.eip, 0x2222);
        assert_eq!(cpu.regs.esp(), esp_before + 12);
    }
}

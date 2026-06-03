//! Win32 stub registry + per-DLL host implementations of the
//! functions the loaded codec DLLs import.
//!
//! Each stub is a Rust function pointer with the signature
//! [`StubFn`]. The PE loader, when populating the IAT, looks up
//! `(dll_name_lowercased, function_name)` in [`Registry`] and
//! writes the synthetic `StubAddr` (a guest address that lives
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
pub mod comctl32;
pub mod gdi32;
pub mod kernel32;
pub mod mfplat;
pub mod msi;
pub mod msiexec;
pub mod msvcrt;
pub mod ole32;
pub mod shell32;
pub mod shlwapi;
pub mod user32;
pub mod version;
pub mod vfw32;
pub mod winmm;
pub mod winsock;

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
pub type StubFn = fn(&mut Cpu, &mut Mmu, &mut HostState, &mut Registry) -> Result<u32, Win32Error>;

/// One stub call recorded for analysis. Populated whenever
/// [`HostState::trace_stubs`] is set; the [`HostState::stub_calls`]
/// vector accumulates these in call order.
#[derive(Clone, Debug)]
pub struct StubCall {
    /// The DLL the call targeted (`"kernel32.dll"`, …).
    pub dll: String,
    /// The function name (`"CreateFileA"`, …).
    pub name: String,
    /// Dword arguments captured off the guest stack at call
    /// entry, before the stub ran. Length is the stdcall
    /// `arg_dwords` count, or a per-call override for known
    /// cdecl shapes.
    pub args: Vec<u32>,
    /// Whatever `eax` value the stub returned.
    pub ret: u32,
    /// Call-site EIP — the saved return address on the guest
    /// stack at call entry, i.e. the instruction the codec
    /// will resume at when the stub returns.
    pub call_site_eip: u32,
}

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
    /// For Win16 FAR PASCAL stubs: the number of argument bytes the
    /// callee must clean on return (`RETF n`). 0 for Win32 stdcall
    /// stubs, where `arg_dwords * 4` is used instead. The dispatcher
    /// picks the convention by the CPU's 16-bit mode.
    pub far_pascal_arg_bytes: u16,
}

/// Errors a stub can raise. Wrapped in `crate::Error::Win32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Win32Error {
    /// No stub registered for the requested `(dll, name)` pair.
    /// PE-load-time error; surfaces from
    /// `crate::pe::Loader::resolve_imports`.
    UnknownImport { dll: String, name: String },
    /// Stub-side argument validation failed.
    InvalidArgument { stub: &'static str, reason: String },
    /// Heap call referenced an unknown allocation.
    InvalidHeapBlock { stub: &'static str, addr: u32 },
    /// The per-run instruction budget set on
    /// [`HostState::instruction_budget`] was exhausted before
    /// the guest reached `RET_SENTINEL`. Analysis front-ends
    /// use this to cap adversarial samples that loop. The
    /// state captured up to the budget point — coverage
    /// map, stub trace, register snapshot — is still valid.
    BudgetExhausted { executed: u64 },
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
            Win32Error::BudgetExhausted { executed } => {
                write!(
                    f,
                    "instruction budget exhausted after {executed} steps without reaching RET_SENTINEL"
                )
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

/// Per-process emulator state. Phase 1 of the scheduler refactor
/// (see `magical-popping-oasis` plan): every field that is
/// conceptually scoped to a single Win32 *process* lives here.
/// Today there is exactly one [`ProcessState`] per [`HostState`];
/// Phase 5 will switch this to a `BTreeMap<pid, ProcessState>`
/// indexed by an `active_pid` cursor, which keeps stub bodies
/// unchanged (they reach state through [`HostState`]'s
/// auto-deref).
///
/// The conceptual boundary: anything a child process spawned via
/// `CreateProcessA` should NOT share with its parent goes here.
/// Anything truly shared (virtual filesystem, virtual registry,
/// host-side trace buffers, the clock, the instruction budget)
/// stays on [`HostState`].
#[derive(Default)]
pub struct ProcessState {
    /// Synthetic process identifier. `1` for the bootstrap
    /// process; `CreateProcessA` mints monotonically
    /// increasing values.
    pub pid: u32,
    /// PID of the process that called `CreateProcessA` to spawn
    /// this one. `0` for the bootstrap (no parent).
    pub parent_pid: u32,
    /// Image base where the process's primary PE is mapped.
    /// Each process gets a unique base so child PEs don't
    /// collide with the parent — `0x00400000` for the bootstrap,
    /// `0x10000000` / `0x20000000` / … for spawned children.
    pub image_base: u32,
    /// Exit code reported by `ExitProcess` / `TerminateProcess`
    /// on this process; `None` while the process is still
    /// running. Wakes any `WaitForSingleObject` on the process
    /// handle when set.
    pub exit_code: Option<u32>,
    /// Heap allocations keyed by guest address.
    pub heap: BTreeMap<u32, Vec<u8>>,
    /// Cursor for the next heap allocation. Walks through a
    /// dedicated guest-virtual region (configured by [`HostState::new`]).
    pub heap_cursor: u32,
    pub heap_arena_end: u32,
    /// Default process heap handle returned by `GetProcessHeap`.
    pub process_heap_handle: u32,
    /// Loaded-module registry: name → ImageBase.
    pub modules: BTreeMap<String, u32>,
    /// Most-recently-loaded codec module's image base — returned
    /// by `GetModuleHandleA(NULL)`. Set to 0 if no DLL has been
    /// loaded yet.
    pub primary_module_base: u32,
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
    /// Set by `kernel32!ExitProcess` (and `TerminateProcess` on
    /// the current process) to break out of the emulator loop in
    /// lieu of unwinding to `RET_SENTINEL`. `Some(code)` means
    /// "this process asked to terminate"; the run-loop converts
    /// this into a clean return so the calling host code can
    /// introspect what happened.
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
    /// Cached pointer to the synthesised ANSI environment block.
    pub environment_strings_ptr: u32,
    /// Cached pointer to the synthesised UTF-16 environment
    /// block. Kept distinct from the ANSI cache so each
    /// encoding holds its own bytes.
    pub environment_strings_w_ptr: u32,
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
    /// Cursor for the next `TlsAlloc` slot. Slot indices are
    /// process-scoped (each `TlsAlloc` mints a fresh integer)
    /// but the *values* stored at those indices live in
    /// per-thread [`ThreadState::tls_slots`]. Phase 2 of the
    /// scheduler refactor.
    pub next_tls_slot: u32,
    /// Bottom of the thread-stack pool. `CreateThread` carves
    /// stacks from `[bottom, top)` walking down from
    /// `next_thread_stack_top`. Both are `0` when no pool has
    /// been configured — `CreateThread` reports an
    /// `InvalidArgument` error in that case.
    pub thread_stack_pool_bottom: u32,
    /// Next available stack-top for the next `CreateThread`.
    /// Decrements by [`THREAD_STACK_SIZE`] per spawned thread.
    pub next_thread_stack_top: u32,
    /// Bottom of the per-thread TIB (Thread Information Block)
    /// pool. `CreateThread` carves a 4 KiB TIB region per
    /// spawned thread. Phase 6 of the scheduler refactor.
    pub tib_pool_bottom: u32,
    /// Next available TIB base. Increments by
    /// [`THREAD_TIB_SIZE`] per spawned thread.
    pub next_tib_addr: u32,
    /// Live find-file enumerators minted by `FindFirstFileA/W`.
    /// Each handle owns a cursor + a frozen list of VFS paths
    /// the find pattern matched so the enumeration stays
    /// stable even if the VFS mutates mid-enum.
    pub find_handles: BTreeMap<u32, FindHandle>,
    /// Cursor for the next `FindFirstFileA` to mint a handle.
    pub next_find_handle: u32,
}

/// One live `FindFirstFileA` enumeration. The matching set
/// is captured at `FindFirstFile` time so a sibling thread
/// writing into the VFS mid-enum doesn't perturb the
/// caller's sequence.
#[derive(Debug, Clone)]
pub struct FindHandle {
    /// Resolved matching paths, in deterministic order.
    pub matches: Vec<String>,
    /// Next index to return from `FindNextFile`. The cursor
    /// is bumped after the slot is emitted (so cursor == 0
    /// before the first `FindNextFile` means there's a
    /// pending entry from the `FindFirstFile` call).
    pub cursor: usize,
}

/// First synthetic find-file handle the per-process table
/// hands out. Chosen well above every other handle base
/// (VFS, registry, wait objects) so `CloseHandle` can
/// disambiguate by numeric value.
pub const FIND_HANDLE_BASE: u32 = 0x6C00_0000;

/// Per-thread TIB size, in bytes. Real Windows uses a much
/// larger TEB (~4 KiB minimum); we only need enough room for
/// the handful of fields installer / codec CRTs actually
/// touch (SEH chain head at 0x00, self pointer at 0x18,
/// LastError at 0x34, …).
pub const THREAD_TIB_SIZE: u32 = 0x0000_1000;

/// Stride between consecutive child PE image bases. 256 MiB
/// per child gives plenty of room for sections + heap + stack
/// + TIB without colliding with adjacent processes.
pub const CHILD_IMAGE_STRIDE: u32 = 0x1000_0000;

/// Per-child-process heap arena size. Each spawned child
/// carves this much from the host's child-heap pool.
pub const CHILD_HEAP_SIZE: u32 = 0x0100_0000; // 16 MiB

/// Default per-thread stack size, in bytes. 64 KiB matches the
/// typical Win32 reserve size; many codec / installer threads
/// use only a few hundred bytes.
pub const THREAD_STACK_SIZE: u32 = 0x0001_0000;

impl ProcessState {
    /// Construct a fresh process with the heap arena at
    /// `[heap_start, heap_end)` (caller is responsible for
    /// mapping that region in the MMU as R+W).
    #[must_use]
    pub fn new(heap_start: u32, heap_end: u32) -> Self {
        ProcessState {
            pid: 1,
            heap_cursor: heap_start,
            heap_arena_end: heap_end,
            process_heap_handle: 0xDEAD_BEEF,
            next_hic: 1,
            rand_state: 1,
            ..ProcessState::default()
        }
    }
}

/// Per-thread emulator state. Phase 2 of the scheduler refactor:
/// the live `Cpu` in [`crate::Sandbox`] continues to drive
/// execution, but every thread-local Win32 surface (TLS slots,
/// priority, parked CPU register file from past quanta) lives
/// here. Phase 3 will swap the live `Cpu` value with
/// `ThreadState::parked_cpu` on context switch.
///
/// The `parked_cpu` field is `None` for the currently-running
/// thread (its register file lives on `Sandbox::cpu`) and
/// `Some(cpu)` for any thread that has been suspended,
/// preempted, or is waiting on a synchronization object.
pub struct ThreadState {
    /// Synthetic thread identifier. The first thread is `1`;
    /// `CreateThread` mints monotonically increasing values.
    pub tid: u32,
    /// Owning process. For Phase 2 every thread maps to
    /// process `1`.
    pub pid: u32,
    /// Windows thread priority axis. Default is
    /// `THREAD_PRIORITY_NORMAL = 0`. Range `-15..15` for the
    /// realtime / idle extremes.
    pub priority: i32,
    /// Map of TLS slot → value, set by `TlsSetValue` and read
    /// by `TlsGetValue`. Slot indices come from
    /// [`ProcessState::next_tls_slot`].
    pub tls_slots: BTreeMap<u32, u32>,
    /// Parked register file. Phase 3 will populate this when
    /// the scheduler swaps out the live `Cpu`.
    pub parked_cpu: Option<Cpu>,
    /// Quantum remaining for the scheduler's current slice.
    /// Phase 4 will tick this down; for now it's a placeholder
    /// initialised to the default quantum.
    pub quantum_remaining: u32,
    /// Lifecycle state — driven by the scheduler.
    pub status: crate::sched::ThreadStatus,
    /// Active wait, if `status == Waiting`. Cleared on wake.
    pub wait: Option<crate::sched::WaitCondition>,
    /// Per-thread TIB (Thread Information Block) base — guest
    /// VA the thread's CPU references via FS:[0]. `0` for the
    /// bootstrap thread (which uses the runtime's shared
    /// `TEB_BASE`); `CreateThread` carves a fresh page out of
    /// the per-process TIB pool for each new thread.
    pub tib_addr: u32,
    /// Debug aid: previous EIP, used by the wild-jump tracer
    /// under `UD_TRACE_WILD_JUMP`.
    pub last_eip_before_wild: u32,
}

impl Default for ThreadState {
    fn default() -> Self {
        ThreadState {
            tid: 0,
            pid: 0,
            priority: 0,
            tls_slots: BTreeMap::new(),
            parked_cpu: None,
            quantum_remaining: DEFAULT_QUANTUM,
            status: crate::sched::ThreadStatus::Ready,
            wait: None,
            tib_addr: 0,
            last_eip_before_wild: 0,
        }
    }
}

impl ThreadState {
    /// Construct a fresh thread bound to the given process.
    #[must_use]
    pub fn new(tid: u32, pid: u32) -> Self {
        ThreadState {
            tid,
            pid,
            ..ThreadState::default()
        }
    }
}

/// Default scheduler quantum, in guest instructions. Phase 4
/// will start consulting this; until then the value is purely
/// informational so `ThreadState::quantum_remaining` has a
/// sensible initial value.
pub const DEFAULT_QUANTUM: u32 = 10_000;

/// The host-side state every stub may read or mutate.
///
/// This is the "operating system" of the sandbox — the heap, the
/// LastError TLS, the pseudo-tick counter, the loaded-module
/// registry, etc. One per emulator instance.
///
/// `HostState` is the union of (a) **truly shared** state
/// (virtual filesystem, virtual registry, trace buffers, clock,
/// instruction budget) and (b) the **current process**'s
/// [`ProcessState`], exposed through [`std::ops::Deref`] so that
/// existing stub bodies that read `state.heap` / `state.modules`
/// / etc. continue to compile unchanged. The split prepares
/// Phase 5 of the scheduler refactor (`CreateProcessA` spawning
/// a real child PE) without churning every Win32 stub today.
pub struct HostState {
    /// Process table keyed by PID. The bootstrap process has
    /// `pid = 1`; `CreateProcessA` mints children with
    /// monotonically increasing PIDs. The
    /// [`std::ops::Deref`] / [`std::ops::DerefMut`] impls on
    /// `HostState` resolve `state.heap` / `state.modules` /
    /// etc. through the *active* process, so stub bodies
    /// continue to compile unchanged.
    pub processes: BTreeMap<u32, ProcessState>,
    /// PID of the currently-running process — points into
    /// [`Self::processes`]. The scheduler updates this when
    /// switching threads across process boundaries.
    pub active_pid: u32,
    /// Cursor for the next `CreateProcessA` to mint a PID.
    pub next_pid: u32,
    /// Image base for the next child PE loaded via
    /// `CreateProcessA`. `0` until a child-image arena is
    /// configured (via [`Self::with_child_image_arena`]); the
    /// runtime walks the cursor forward by [`CHILD_IMAGE_STRIDE`]
    /// per spawn.
    pub next_child_image_base: u32,
    /// Heap-arena pool the next child process carves its
    /// per-process heap from. `[next_child_heap_base,
    /// child_heap_arena_end)`. Each spawn takes
    /// [`CHILD_HEAP_SIZE`] bytes.
    pub next_child_heap_base: u32,
    pub child_heap_arena_end: u32,
    /// Thread table keyed by TID. Phase 2 of the scheduler
    /// refactor: there is always at least one thread, with
    /// `tid = 1`, owning the live `Cpu` on `Sandbox`. Phase 3
    /// will populate more entries when `CreateThread` mints a
    /// real thread, and the scheduler will move the live `Cpu`
    /// in/out of `parked_cpu` here on context switch.
    pub threads: BTreeMap<u32, ThreadState>,
    /// TID of the currently-executing thread — points into
    /// [`Self::threads`]. Phase 3 will mutate this on context
    /// switch.
    pub active_tid: u32,
    /// Cursor for the next `CreateThread` to mint a TID. Stays
    /// monotonic across the lifetime of the sandbox.
    pub next_tid: u32,
    /// Last error code (`SetLastError` / `GetLastError`). Phase
    /// 6 will mirror this through the per-thread TIB at
    /// FS:[0x34] so guest code reading it directly sees the
    /// per-thread value. For now (single thread) the field on
    /// HostState is the source of truth.
    pub last_error: u32,
    /// Lazily-allocated guest address of the C-CRT `errno` cell.
    /// `None` until the first call to `msvcrt::_errno`, then
    /// stable for the lifetime of the sandbox so repeated calls
    /// return the same pointer (the contract `int * _errno(void)`
    /// requires).
    pub errno_cell: Option<u32>,
    /// Pseudo-tick counter incremented on every `GetTickCount`.
    pub tick: u32,
    /// Lines that the codec wrote to `OutputDebugString*`. Tests
    /// can introspect to confirm a known string was emitted.
    pub debug_log: Vec<String>,
    /// Lines that the codec wrote to `MessageBoxA` (also mirrored
    /// to `eprintln!`). Distinct from `debug_log` so a test can
    /// distinguish OutputDebugStringA traffic from real popups.
    pub message_box_log: Vec<String>,
    /// Headless Win16 GUI model — windows, dialogs, controls, and a
    /// transcript of GUI actions, recorded by the USER stubs and
    /// serialised to JSON for expect-style automation.
    pub gui: crate::win16::gui::GuiState,
    /// Win16 global heap — `GlobalAlloc`/`GlobalLock` backing store.
    pub win16_heap: crate::win16::Win16Heap,
    /// `RT_STRING` resources parsed from a loaded NE module, keyed by
    /// string id, for `LoadString`.
    pub string_resources: std::collections::BTreeMap<u16, String>,
    /// Global atom table (`GlobalAddAtom`/`GlobalFindAtom`/…): interned
    /// strings; the atom for index `i` is `0xC000 + i`.
    pub atoms: Vec<String>,
    /// Resources parsed from a loaded NE module, for `FindResource` /
    /// `LoadResource`. The `HRSRC` handed out is the 1-based index.
    pub resources: Vec<crate::win16::LoadedResource>,
    /// Optional per-run instruction budget. Decremented at each
    /// top-of-loop iteration in [`run_until_sentinel`] (both
    /// instruction steps and stub dispatches count). When it
    /// hits zero the run loop bails with
    /// [`Win32Error::BudgetExhausted`] so adversarial guests
    /// can't loop the host. `None` (the default) keeps the
    /// historical unbounded behaviour.
    pub instruction_budget: Option<u64>,
    /// Counts how many instructions actually ran in the last
    /// (or current) run-loop session. Useful for the analysis
    /// front-ends to report "ran for N instructions, budget
    /// was M". Reset to zero on each top-level run entry.
    pub instructions_executed: u64,
    /// Optional emulation-context layer (virtual filesystem,
    /// virtual registry, future surfaces). When `None`, the
    /// Win32 stubs that would consult it fall through to
    /// their fail-soft default. See [`crate::context::Context`]
    /// for the contract.
    pub context: crate::context::Context,
    /// When `true`, [`dispatch_stub`] appends one line per Win32
    /// call to [`HostState::stub_trace`]. Off by default; round-8 tests flip
    /// it on while triaging which stub returns a bad value.
    pub trace_stubs: bool,
    /// Per-call trace lines populated when [`HostState::trace_stubs`] is on.
    /// Format: `dll!name(arg0, arg1, …) → 0xRET`. The args are
    /// the first `arg_dwords` (or, for known cdecl shapes, the
    /// override from [`cdecl_trace_arg_count`]) dwords off the
    /// guest stack, captured BEFORE the stub mutates them.
    pub stub_trace: Vec<String>,
    /// Structured per-call log, populated when [`HostState::trace_stubs`]
    /// is on. Parallel to [`HostState::stub_trace`]; analysis front-ends
    /// (the `ud analyze` JSON output) consume this directly so
    /// they don't have to re-parse the formatted string.
    pub stub_calls: Vec<StubCall>,
    /// Scheduler-owned wait-object table + global instruction
    /// clock. Phase 3 of the scheduler refactor.
    pub scheduler: crate::sched::Scheduler,
    /// When `true`, `DeleteFileA` / `RemoveDirectoryA` log
    /// the attempt and return success without actually
    /// mutating the VFS. Set by install-monitor harnesses
    /// so post-msiexec rollback doesn't drop the extracted
    /// MSI bundle.
    pub preserve_deletes: bool,
    /// Image-base cursor for guest-loaded dependent DLLs (the
    /// VFS-DLL-fallback resolution path). Each VFS load takes
    /// `align_up(size_of_image, 64 KiB)` from this cursor.
    /// Distinct from `next_child_image_base`, which carves out
    /// 256 MiB per *process* spawned via `CreateProcessA`.
    pub next_dll_image_base: u32,
    /// Per-image export tables for guest-loaded DLLs. The key is
    /// the image base; the value is the same `name → RVA` map
    /// the PE loader's `parse_exports` returns. Kept so a
    /// subsequent VFS-DLL load can still find a previously
    /// loaded sibling's exports for IAT patching.
    pub loaded_dll_exports: BTreeMap<u32, BTreeMap<String, u32>>,
    /// Active MSI session — `Some` while a DLL CustomAction is
    /// running and the msi.dll stub set needs to answer
    /// `MsiGetProperty` / `MsiSetProperty` / etc. against an
    /// in-process property map. `None` outside CA execution
    /// (the msi.dll stubs return error codes in that case).
    /// The session is set up by the msiexec walker before
    /// invoking the DLL CA's entry point and torn down after.
    pub msi_session: Option<MsiSession>,
    /// Pending DLL/EXE/script CustomActions handed off from
    /// `msiexec::dispatch_msiexec_install` for the outer
    /// Sandbox-side driver to execute after
    /// `CreateProcessA(msiexec.exe)` returns. The walker can
    /// only do the table walks + property/directory CA work
    /// (no Cpu/Registry access); guest-code CA dispatch
    /// happens in `Sandbox::pump_pending_msi_install` once
    /// the parent process resumes.
    pub pending_msi_install: Option<crate::win32::msiexec::PendingMsiInstall>,
    /// When `Some`, the most recently dispatched stub asked the
    /// run loop to switch threads. The run loop drains the
    /// field after every stub return: a `Wait(...)` moves the
    /// current thread to `Waiting`; `Yield` re-queues it at the
    /// end of the Ready queue; `Exit { code }` terminates it.
    pub yield_requested: Option<crate::sched::YieldRequest>,
}

impl Default for HostState {
    fn default() -> Self {
        let mut threads = BTreeMap::new();
        threads.insert(1, ThreadState::new(1, 1));
        let mut processes = BTreeMap::new();
        let mut p = ProcessState::default();
        p.pid = 1;
        processes.insert(1, p);
        HostState {
            processes,
            gui: crate::win16::gui::GuiState::default(),
            win16_heap: crate::win16::Win16Heap::default(),
            string_resources: BTreeMap::new(),
            atoms: Vec::new(),
            resources: Vec::new(),
            active_pid: 1,
            next_pid: 2,
            next_child_image_base: 0,
            next_child_heap_base: 0,
            child_heap_arena_end: 0,
            threads,
            active_tid: 1,
            next_tid: 2,
            last_error: 0,
            errno_cell: None,
            tick: 0,
            debug_log: Vec::new(),
            message_box_log: Vec::new(),
            instruction_budget: None,
            instructions_executed: 0,
            context: crate::context::Context::default(),
            trace_stubs: false,
            stub_trace: Vec::new(),
            stub_calls: Vec::new(),
            scheduler: crate::sched::Scheduler::new(),
            yield_requested: None,
            preserve_deletes: false,
            next_dll_image_base: 0x4000_0000,
            loaded_dll_exports: BTreeMap::new(),
            msi_session: None,
            pending_msi_install: None,
        }
    }
}

impl std::ops::Deref for HostState {
    type Target = ProcessState;
    fn deref(&self) -> &ProcessState {
        self.processes
            .get(&self.active_pid)
            .expect("active_pid must always point to a live process")
    }
}

impl std::ops::DerefMut for HostState {
    fn deref_mut(&mut self) -> &mut ProcessState {
        self.processes
            .get_mut(&self.active_pid)
            .expect("active_pid must always point to a live process")
    }
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
        let mut s = HostState::default();
        s.processes
            .insert(1, ProcessState::new(heap_start, heap_end));
        s
    }

    /// Borrow the active process. Resolved through
    /// [`Self::active_pid`].
    #[must_use]
    pub fn cur_process(&self) -> &ProcessState {
        self.processes
            .get(&self.active_pid)
            .expect("active_pid must always point to a live process")
    }

    /// Mutable borrow of the active process. Pair to
    /// [`Self::cur_process`]; same invariant.
    pub fn cur_process_mut(&mut self) -> &mut ProcessState {
        self.processes
            .get_mut(&self.active_pid)
            .expect("active_pid must always point to a live process")
    }

    /// Borrow a process by PID, if it exists.
    #[must_use]
    pub fn process(&self, pid: u32) -> Option<&ProcessState> {
        self.processes.get(&pid)
    }

    /// Mutable borrow of a process by PID.
    pub fn process_mut(&mut self, pid: u32) -> Option<&mut ProcessState> {
        self.processes.get_mut(&pid)
    }

    /// Borrow the currently-running thread. Falls back to the
    /// bootstrap thread (`tid = 1`) on the freshly-constructed
    /// state.
    #[must_use]
    pub fn cur_thread(&self) -> &ThreadState {
        self.threads
            .get(&self.active_tid)
            .expect("active_tid must always point to a live thread (Default initialises tid 1)")
    }

    /// Mutable borrow of the currently-running thread. Pair to
    /// [`Self::cur_thread`]; same invariant.
    pub fn cur_thread_mut(&mut self) -> &mut ThreadState {
        self.threads
            .get_mut(&self.active_tid)
            .expect("active_tid must always point to a live thread (Default initialises tid 1)")
    }

    /// Configure the const-arena (region for canned read-only
    /// strings handed back to the codec). `[start, end)` is a
    /// guest-virtual range the caller has already mapped R+W
    /// (the arena bytes are written via `write_initializer`,
    /// so any page perms suffice as long as the page is mapped).
    pub fn with_const_arena(mut self, start: u32, end: u32) -> Self {
        let p = self.cur_process_mut();
        p.const_arena_cursor = start;
        p.const_arena_end = end;
        self
    }

    /// Configure the thread-stack pool. `CreateThread` carves
    /// per-thread stacks from the top of this region walking
    /// downward. `[bottom, top)` must already be mapped R+W in
    /// the MMU.
    pub fn with_thread_stack_pool(mut self, bottom: u32, top: u32) -> Self {
        let p = self.cur_process_mut();
        p.thread_stack_pool_bottom = bottom;
        p.next_thread_stack_top = top;
        self
    }

    /// Configure the per-thread TIB pool. `CreateThread` carves
    /// 4 KiB TIB regions out of `[bottom, top)` walking upward.
    /// Both ends must already be mapped R+W in the MMU. The
    /// bootstrap thread continues to use the runtime's shared
    /// `TEB_BASE`; only spawned threads consume this pool.
    pub fn with_tib_pool(mut self, bottom: u32, top: u32) -> Self {
        let p = self.cur_process_mut();
        p.tib_pool_bottom = bottom;
        p.next_tib_addr = bottom;
        let _ = top; // explicit upper bound is informational
        self
    }

    /// Configure the child-process pools: image-base cursor
    /// + heap arena. `CreateProcessA` carves a child PE into
    /// `[image_base, image_base + CHILD_IMAGE_STRIDE)` and a
    /// 16 MiB heap out of `[heap_start, heap_end)`.
    pub fn with_child_arena(
        mut self,
        image_base_cursor: u32,
        heap_start: u32,
        heap_end: u32,
    ) -> Self {
        self.next_child_image_base = image_base_cursor;
        self.next_child_heap_base = heap_start;
        self.child_heap_arena_end = heap_end;
        self
    }

    /// Bump-allocate `n` bytes in the const arena. Returns the
    /// guest address of the new slab. The caller is responsible
    /// for [`Mmu::write_initializer`]'ing the contents.
    pub fn arena_const_alloc(&mut self, n: u32) -> Result<u32, Win32Error> {
        let aligned =
            n.checked_add(15)
                .map(|v| v & !15u32)
                .ok_or_else(|| Win32Error::InvalidArgument {
                    stub: "arena_const_alloc",
                    reason: format!("size overflow: requested {n} (≈ {n:#x})"),
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
        let aligned =
            n.checked_add(15)
                .map(|v| v & !15u32)
                .ok_or_else(|| Win32Error::InvalidArgument {
                    stub: "arena_alloc",
                    reason: format!("size overflow: requested {n} (≈ {n:#x})"),
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

/// In-process MSI install session — set on [`HostState`] while
/// a DLL CustomAction is running so the msi.dll stub set can
/// answer `MsiGetProperty` / `MsiSetProperty` / etc. against
/// the walker's property map. The walker sets `handle` to a
/// caller-supplied non-zero token (we use 1 since there's
/// only ever one active install in our sandbox); the msi.dll
/// stubs verify the caller's hInstall matches before serving
/// the request.
#[derive(Debug, Default, Clone)]
pub struct MsiSession {
    /// Token the DLL CA was invoked with. msi.dll stubs check
    /// the caller's `hInstall` argument against this; mismatch
    /// returns ERROR_INVALID_HANDLE.
    pub handle: u32,
    /// Property namespace, mutable across the CA's lifetime.
    /// `MsiGetProperty(handle, name, ...)` reads from here;
    /// `MsiSetProperty(handle, name, value)` writes back.
    pub properties: BTreeMap<String, String>,
    /// Resolved directory paths injected into the property
    /// namespace by the walker. Kept separately so
    /// `MsiGetTargetPath` (which is supposed to consult the
    /// directory table specifically) can serve from here
    /// without lookups falling through to non-directory props.
    pub target_paths: BTreeMap<String, String>,
}

/// Returns true iff the given DLL name (lowercase, with `.dll`
/// suffix) is one the host has a stub registry for. The
/// VFS-DLL-fallback path in [`crate::Sandbox::load_with_deps`]
/// skips lookups for these — they're always satisfied via
/// host code regardless of whether a same-named DLL exists in
/// the VFS.
#[must_use]
pub fn is_host_stub_dll(dll_lc: &str) -> bool {
    matches!(
        dll_lc,
        "kernel32.dll"
            | "user32.dll"
            | "gdi32.dll"
            | "msvcrt.dll"
            | "msvcr80.dll"
            | "msvcr90.dll"
            | "msvcr100.dll"
            | "msvcr110.dll"
            | "msvcr120.dll"
            | "ole32.dll"
            | "oleaut32.dll"
            | "advapi32.dll"
            | "comctl32.dll"
            | "shell32.dll"
            | "shlwapi.dll"
            | "winmm.dll"
            | "version.dll"
            | "vfw32.dll"
            | "msi.dll"
            | "mfplat.dll"
            | "ws2_32.dll"
            | "wsock32.dll"
            | "ntdll.dll"
            | "imm32.dll"
            | "rpcrt4.dll"
            | "secur32.dll"
            | "crypt32.dll"
            | "iphlpapi.dll"
            | "wininet.dll"
            | "urlmon.dll"
            | "psapi.dll"
            | "userenv.dll"
            | "comdlg32.dll"
    )
}

/// Sandbox VFS path prefixes searched (in order) when the
/// [`crate::Sandbox::load_with_deps`] resolver tries to find a
/// dependent DLL the host stub registry doesn't satisfy. Paths
/// are lowercase, forward-slash, no leading slash — the
/// `format!("{prefix}{dll}")` concatenation produces a key
/// directly usable with [`crate::context::VirtualFs::read`].
#[must_use]
pub fn dll_vfs_search_paths() -> &'static [&'static str] {
    &[
        "c:/program files/quicktime/qtsystem/",
        "c:/program files/quicktime/",
        "c:/program files/common files/apple/apple application support/",
        "c:/common files/apple/apple application support/",
        "c:/windows/system32/",
        "c:/windows/",
        "",
    ]
}

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
                far_pascal_arg_bytes: 0,
            },
        );
        thunk_addr
    }

    /// Register a Win16 FAR PASCAL stub keyed by `(module, "@ordinal")`
    /// — e.g. `("kernel", "@91")` for `InitTask`. `arg_bytes` is the
    /// number of argument bytes the callee cleans on its far return.
    /// Returns the thunk address far pointers should target.
    pub fn register_far_pascal(
        &mut self,
        module: &str,
        ordinal: &str,
        func: StubFn,
        arg_bytes: u16,
    ) -> u32 {
        let key = (module.to_ascii_lowercase(), ordinal.to_string());
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
                arg_dwords: 0,
                thunk_addr,
                far_pascal_arg_bytes: arg_bytes,
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

    /// Register a *guest-loaded* DLL's export — the IAT slot
    /// will be patched with `addr` (an absolute guest VA into
    /// the loaded DLL's `.text`) and the guest jumps straight
    /// there with no host-side thunk in between. Used by the
    /// VFS-DLL-fallback path in the PE loader so codecs whose
    /// import surface includes another guest-loadable DLL
    /// (e.g. QuickTime's `.qtx` files importing CoreVideo /
    /// CoreAudioToolbox from `AppleApplicationSupport.msi`)
    /// can find the real Apple-DLL function rather than a
    /// fail-soft trap thunk. Idempotent: re-registering the
    /// same `(dll, name)` leaves the prior address in place.
    pub fn register_guest_export(&mut self, dll: &str, name: &str, addr: u32) {
        let key = (dll.to_ascii_lowercase(), name.to_string());
        self.by_name.entry(key).or_insert(addr);
    }

    /// Register a fail-soft fallback thunk for an import we
    /// don't have a stub for. The thunk's stub function looks
    /// itself up in the registry and raises
    /// [`crate::emulator::Trap::UnresolvedImport`] carrying
    /// the (dll, name) pair on first call.
    ///
    /// The PE loader's fail-soft mode installs one of these
    /// for every unresolved IAT entry so loading succeeds and
    /// execution proceeds until the first unknown API actually
    /// gets called. That's a much better signal than failing
    /// at load time: the trap names the specific function to
    /// implement next, and reveals which import paths are
    /// reachable from the entry point.
    pub fn register_unknown_fallback(&mut self, dll: &str, name: &str) -> u32 {
        let key = (dll.to_ascii_lowercase(), name.to_string());
        if let Some(addr) = self.by_name.get(&key) {
            return *addr;
        }
        let thunk_addr = THUNK_BASE.wrapping_add(self.next_slot.wrapping_mul(THUNK_STRIDE));
        self.next_slot += 1;
        self.by_name.insert(key.clone(), thunk_addr);
        // arg_dwords=0 is wrong for most stdcall APIs but
        // doesn't matter — the stub traps before returning so
        // dispatch_stub never reaches the stack-cleanup path.
        self.by_thunk.insert(
            thunk_addr,
            StubEntry {
                dll: key.0,
                name: key.1,
                func: stub_unresolved_fallback,
                arg_dwords: 0,
                thunk_addr,
                far_pascal_arg_bytes: 0,
            },
        );
        thunk_addr
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

    /// Register the msvcrt stub set under `msvcr71.dll`. Used by
    /// codecs from the wmfdist11 era (mp43decd, mp4sdecd,
    /// wmvdecod, …) that link MSVC 7.1's runtime by its
    /// per-version name. Returns the number registered.
    pub fn register_msvcr71(&mut self) -> usize {
        let before = self.by_name.len();
        msvcrt::register_alias(self, "msvcr71.dll");
        self.by_name.len() - before
    }

    /// Register the msvcrt stub set under `pncrt.dll`. Used by
    /// RealNetworks codecs that ship their own CRT fork.
    /// Returns the number registered.
    pub fn register_pncrt(&mut self) -> usize {
        let before = self.by_name.len();
        msvcrt::register_alias(self, "pncrt.dll");
        self.by_name.len() - before
    }

    /// Register the msvcrt stub set under `msvcr80.dll` (Visual
    /// Studio 2005 CRT). Used by `camstudio-1.4-camcodec.dll`.
    pub fn register_msvcr80(&mut self) -> usize {
        let before = self.by_name.len();
        msvcrt::register_alias(self, "msvcr80.dll");
        self.by_name.len() - before
    }

    /// Register the msvcrt stub set under `msvcr90.dll` (Visual
    /// Studio 2008 CRT). Used by `camstudio-1.5-camcodec.dll`.
    pub fn register_msvcr90(&mut self) -> usize {
        let before = self.by_name.len();
        msvcrt::register_alias(self, "msvcr90.dll");
        self.by_name.len() - before
    }

    /// Register every mfplat (Media Foundation platform) stub.
    /// Returns the number registered.
    pub fn register_mfplat(&mut self) -> usize {
        let before = self.by_name.len();
        mfplat::register(self);
        self.by_name.len() - before
    }

    /// Register every msi.dll stub — Windows Installer surface
    /// touched by application installers (QuickTime, …).
    /// Returns the number registered.
    pub fn register_msi(&mut self) -> usize {
        let before = self.by_name.len();
        msi::register(self);
        self.by_name.len() - before
    }

    /// Register the version.dll / comctl32.dll / shell32.dll /
    /// shlwapi.dll stub families — the config-dialog and
    /// settings-file surface VfW codecs pull in alongside their
    /// decode core. Returns the number registered.
    pub fn register_shell_support(&mut self) -> usize {
        let before = self.by_name.len();
        version::register(self);
        comctl32::register(self);
        shell32::register(self);
        shlwapi::register(self);
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
        crate::win32::winsock::register(self);
        let host_count = self.by_name.len() - host_before;
        self.register_kernel32()
            + self.register_gdi32()
            + self.register_user32()
            + self.register_winmm()
            + self.register_advapi32()
            + self.register_ole32()
            + self.register_msvcrt()
            + self.register_msvcr71()
            + self.register_pncrt()
            + self.register_msvcr80()
            + self.register_msvcr90()
            + self.register_mfplat()
            + self.register_msi()
            + self.register_shell_support()
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

/// Read a NUL-terminated UTF-16 string from guest memory at
/// `addr`, stopping at NUL or after `max_chars` 16-bit code
/// units. Used by every `*W` Win32 stub that takes an
/// `LPCWSTR`.
pub fn read_wide_cstr_local(mmu: &Mmu, mut addr: u32, max_chars: u32) -> String {
    let mut units = Vec::new();
    for _ in 0..max_chars {
        match mmu.load16(addr) {
            Ok(0) => break,
            Ok(u) => units.push(u),
            Err(_) => break,
        }
        addr = addr.wrapping_add(2);
    }
    String::from_utf16_lossy(&units)
}

/// Stub function used by [`Registry::register_unknown_fallback`].
/// Looks up its own (dll, name) by reverse-resolving the entry
/// EIP against the registry and raises a
/// [`Win32Error::UnknownImport`] that the runtime surfaces as
/// `Trap::UnresolvedImport`. Execution halts on first call —
/// the operator sees the precise import to implement next.
///
/// When `UD_LENIENT_UNRESOLVED=1` is set, the stub returns 0
/// instead of trapping (logged once per import via debug_log).
/// This is for chasing through deeply-stacked DLL chains —
/// e.g. qtcf.dll → corefoundation.dll → many CRT helpers —
/// where most failing imports are throwaway init/cleanup
/// hooks and returning 0 lets the chain proceed. Trapping
/// remains the default since it reveals what stubs to add.
fn stub_unresolved_fallback(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let addr = cpu.regs.eip;
    let (dll, name) = registry
        .entry(addr)
        .map(|e| (e.dll.clone(), e.name.clone()))
        .unwrap_or_else(|| ("<unknown>".to_string(), format!("@{addr:#010x}")));
    // Win16 debugging aid: print where the unimplemented ordinal was
    // called from (caller CS:IP sit above the far return) so the call
    // site can be disassembled to read its argument count.
    if cpu.is_code16() && std::env::var("UD_NE_DEBUG").is_ok() {
        let ip = cpu.stack_word(mmu, 0).unwrap_or(0);
        let cs = cpu.stack_word(mmu, 2).unwrap_or(0);
        eprintln!("WIN16 unresolved {dll}!{name} called from {cs:#06x}:{ip:#06x}");
    }
    if std::env::var("UD_LENIENT_UNRESOLVED").is_ok() {
        // One-line summary per unique (dll, name) the operator
        // sees; the stub then returns 0 so the calling code
        // proceeds as if a null/zero stub function did nothing.
        state
            .debug_log
            .push(format!("lenient: returning 0 for {dll}!{name}"));
        return Ok(0);
    }
    Err(Win32Error::UnknownImport { dll, name })
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
    registry: &mut Registry,
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
    // Snapshot the call-site EIP (= the saved return address
    // pushed by the guest CALL — the instruction right after
    // the CALL, not the thunk address) and the first few args
    // off the guest stack BEFORE running the stub, since the
    // stub mutates the stack.
    //
    // Argument count: `entry.arg_dwords` carries the stdcall
    // count (the value used to pop the stack on return). For
    // cdecl stubs this is 0 — but for known cdecl shapes
    // (msvcrt heap entries) [`cdecl_trace_arg_count`] supplies a
    // per-call override so the trace surfaces the size / pointer
    // args rather than `args:[]`.
    //
    // The snapshot is always-on when `state.trace_stubs` is set
    // (the structured `stub_calls` vector consumes it) and is
    // additionally emitted as a JSONL event under the `trace`
    // feature flag.
    let capture_args = state.trace_stubs;
    #[cfg(feature = "trace")]
    let capture_args = capture_args || mmu.trace.has_sink();
    let snapshot: Option<(u32, Vec<u32>)> = if capture_args {
        if cpu.is_code16() {
            // Win16 FAR PASCAL: the 4-byte far return address sits at
            // SP+0..3; arguments are 16-bit words above it. Capture the
            // return IP as the call site and each declared word arg.
            let call_site_eip = u32::from(cpu.stack_word(mmu, 0).unwrap_or(0));
            let n_words = u32::from(entry.far_pascal_arg_bytes / 2);
            let mut args = Vec::with_capacity(n_words as usize);
            for i in 0..n_words {
                args.push(u32::from(cpu.stack_word(mmu, 4 + i * 2).unwrap_or(0)));
            }
            Some((call_site_eip, args))
        } else {
            let call_site_eip = mmu.load32(cpu.regs.esp()).unwrap_or(0);
            let n_args = cdecl_trace_arg_count(&entry.dll, &entry.name).unwrap_or(entry.arg_dwords);
            let mut args = Vec::with_capacity(n_args as usize);
            for i in 0..n_args {
                let a = arg_dword(cpu, mmu, i).unwrap_or(0);
                args.push(a);
            }
            Some((call_site_eip, args))
        }
    } else {
        None
    };
    // Run the host-side stub.
    let ret = (entry.func)(cpu, mmu, state, registry)?;
    if state.trace_stubs {
        let (call_site_eip, args) = snapshot.clone().unwrap_or((0, Vec::new()));
        let args_str = args
            .iter()
            .map(|a| format!("{a:#010x}"))
            .collect::<Vec<_>>()
            .join(", ");
        state.stub_trace.push(format!(
            "{}!{}({args_str}) → {:#010x}",
            entry.dll, entry.name, ret
        ));
        state.stub_calls.push(StubCall {
            dll: entry.dll.clone(),
            name: entry.name.clone(),
            args,
            ret,
            call_site_eip,
        });
    }
    // Emit the trace event with the captured args + the actual
    // return value. Done before stack unwind so the EIP we log
    // is the call site, not the post-return PC.
    #[cfg(feature = "trace")]
    if let Some((call_site_eip, args)) = snapshot {
        mmu.trace
            .ev_win32_call(&entry.dll, &entry.name, &args, ret, call_site_eip);
    }
    if cpu.is_code16() {
        // Win16 FAR PASCAL: return value in DX:AX, far return, callee
        // cleans `far_pascal_arg_bytes` of arguments.
        cpu.regs.set16(crate::emulator::regs::Reg16::Ax, ret as u16);
        cpu.regs
            .set16(crate::emulator::regs::Reg16::Dx, (ret >> 16) as u16);
        cpu.far_return_and_clean(mmu, entry.far_pascal_arg_bytes)?;
    } else {
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
    }
    Ok(())
}

/// Run the emulator until `eip == RET_SENTINEL`, dispatching to
/// any Win32 stub thunk addresses encountered along the way.
///
/// This is the shared run-loop body used both by [`crate::Sandbox`]
/// and by re-entrant host stubs (notably the `vfw32` surface,
/// which dispatches the codec's `DriverProc` synchronously
/// inside an outer `IC*` call).
/// Process a yield request from a freshly-returned stub. The
/// active thread transitions to the requested scheduler state,
/// then the run loop picks the next `Ready` thread via
/// [`schedule_next_thread`]. The live `Cpu` is parked into the
/// previous active thread's `parked_cpu` slot and the new
/// thread's parked Cpu replaces it.
fn handle_yield(cpu: &mut Cpu, state: &mut HostState, req: crate::sched::YieldRequest) {
    use crate::sched::{ThreadStatus, YieldRequest};
    match req {
        YieldRequest::Wait(cond) => {
            let t = state.cur_thread_mut();
            t.status = ThreadStatus::Waiting;
            t.wait = Some(cond);
        }
        YieldRequest::Yield => {
            let t = state.cur_thread_mut();
            t.status = ThreadStatus::Ready;
        }
        YieldRequest::Exit { code } => {
            let tid = state.active_tid;
            let t = state.cur_thread_mut();
            t.status = ThreadStatus::Terminated;
            t.wait = None;
            on_thread_terminated(state, tid);
            // Signal any pending `WaitForSingleObject` against
            // this thread's Thread WaitObject. (Phase 3c will
            // implement the wake side; here we just mark the
            // state machine so Phase 3c's wake-up sees a
            // terminated thread).
            let _ = code;
        }
    }
    schedule_next_thread(cpu, state);
}

/// Park the live `Cpu` into the current thread and resume the
/// next `Ready` thread (if one exists). When no other Ready
/// thread is available, restores the current thread's CPU
/// unchanged — the run loop continues with the same thread
/// (which is fine for single-thread Sleep behaviour: the clock
/// fast-forward at the top of the loop wakes the same thread).
fn schedule_next_thread(cpu: &mut Cpu, state: &mut HostState) {
    use crate::sched::ThreadStatus;
    // Pick the next runnable thread other than the current
    // one — round-robin by TID order. Phase 4 will add
    // priority-aware picking.
    let cur_tid = state.active_tid;
    let next_tid = {
        let mut candidates: Vec<(i32, u32)> = state
            .threads
            .iter()
            .filter(|(tid, t)| **tid != cur_tid && matches!(t.status, ThreadStatus::Ready))
            .map(|(tid, t)| (t.priority, *tid))
            .collect();
        // Sort by descending priority then ascending TID for
        // deterministic round-robin within the same priority.
        candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        candidates.into_iter().next().map(|(_, tid)| tid)
    };
    let cur_is_runnable = matches!(
        state
            .threads
            .get(&cur_tid)
            .map(|t| t.status)
            .unwrap_or(ThreadStatus::Terminated),
        ThreadStatus::Ready | ThreadStatus::Running
    );
    let Some(next_tid) = next_tid else {
        // No other Ready thread. If the current is still
        // runnable, just keep going. Otherwise the run loop's
        // sleep-clock fast-forward will wake it; if that
        // doesn't apply we'd deadlock — but Phase 3b only
        // exposes Sleep, so this path is fine.
        if cur_is_runnable {
            state.cur_thread_mut().status = ThreadStatus::Running;
        }
        return;
    };
    // Park the live CPU into the current thread.
    let parked = std::mem::take(cpu);
    if let Some(t) = state.threads.get_mut(&cur_tid) {
        t.parked_cpu = Some(parked);
    }
    // Restore the next thread's parked CPU into the live one.
    let mut new_pid = None;
    if let Some(t) = state.threads.get_mut(&next_tid) {
        if let Some(c) = t.parked_cpu.take() {
            *cpu = c;
        }
        t.status = ThreadStatus::Running;
        new_pid = Some(t.pid);
    }
    state.active_tid = next_tid;
    // When the new thread lives in a different process, update
    // `active_pid` so the Deref-resolved per-process state
    // (heap arena, modules, hwnd registry, …) points at the
    // new process. Phase 5c.
    if let Some(pid) = new_pid {
        if state.processes.contains_key(&pid) {
            state.active_pid = pid;
        }
    }
}

/// After a thread terminates, check whether its owning
/// process has any live threads left. If not, record the
/// process's exit code (defaulting to 0 if not already set)
/// and wake every thread blocked on a `WaitObject::Process`
/// targeting that PID. Phase 5c — chains the natural Win32
/// "last thread out marks the process exited" contract.
fn on_thread_terminated(state: &mut HostState, tid: u32) {
    let pid = match state.threads.get(&tid) {
        Some(t) => t.pid,
        None => return,
    };
    let alive = state
        .threads
        .values()
        .any(|t| t.pid == pid && !matches!(t.status, crate::sched::ThreadStatus::Terminated));
    if alive {
        return;
    }
    if let Some(p) = state.processes.get_mut(&pid) {
        if p.exit_code.is_none() {
            p.exit_code = Some(0);
        }
    }
    // Wake every Process-handle waiter on this PID.
    let handles: Vec<u32> = state
        .scheduler
        .objects
        .iter()
        .filter_map(|(h, obj)| match obj {
            crate::sched::WaitObject::Process { pid: p } if *p == pid => Some(*h),
            _ => None,
        })
        .collect();
    for h in handles {
        for waiter_tid in crate::sched::waiters_on(&state.threads, h) {
            if let Some(t) = state.threads.get_mut(&waiter_tid) {
                t.status = crate::sched::ThreadStatus::Ready;
                t.wait = None;
            }
        }
    }
    // Same for any pending Thread-handle waits on this TID.
    let thread_handles: Vec<u32> = state
        .scheduler
        .objects
        .iter()
        .filter_map(|(h, obj)| match obj {
            crate::sched::WaitObject::Thread { tid: t } if *t == tid => Some(*h),
            _ => None,
        })
        .collect();
    for h in thread_handles {
        for waiter_tid in crate::sched::waiters_on(&state.threads, h) {
            if let Some(t) = state.threads.get_mut(&waiter_tid) {
                t.status = crate::sched::ThreadStatus::Ready;
                t.wait = None;
            }
        }
    }
}

/// Earliest `resume_after_instructions` across every
/// Sleep-waiting thread, or `None` if no thread is sleeping.
fn earliest_sleep_resume(state: &HostState) -> Option<u64> {
    state
        .threads
        .values()
        .filter_map(|t| {
            if matches!(t.status, crate::sched::ThreadStatus::Waiting) {
                if let Some(crate::sched::WaitCondition::Sleep {
                    resume_after_instructions,
                }) = t.wait
                {
                    return Some(resume_after_instructions);
                }
            }
            None
        })
        .min()
}

/// Move every `Waiting`-on-Sleep thread whose resume target is
/// in the past back to `Ready`. Called from
/// [`run_until_sentinel`] after the global clock advances.
fn wake_sleep_if_due(state: &mut HostState) {
    let now = state.scheduler.instructions_global;
    for t in state.threads.values_mut() {
        if matches!(t.status, crate::sched::ThreadStatus::Waiting) {
            if let Some(crate::sched::WaitCondition::Sleep {
                resume_after_instructions,
            }) = t.wait
            {
                if now >= resume_after_instructions {
                    t.status = crate::sched::ThreadStatus::Ready;
                    t.wait = None;
                }
            }
        }
    }
}

pub fn run_until_sentinel(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &mut Registry,
    state: &mut HostState,
) -> Result<(), crate::Error> {
    use crate::emulator::isa_int::{StepOk, RET_SENTINEL};
    // Reset the per-run instruction counter so analysis
    // front-ends can ask "how many did this top-level call
    // burn?" without subtracting from a stale snapshot.
    state.instructions_executed = 0;
    loop {
        // Honour any yield request the most recently dispatched
        // stub left behind. Phase 3 of the scheduler refactor:
        // a `Wait`/`Yield`/`Exit` request handed up from a stub
        // suspends the active thread and resumes the next
        // `Ready` one. Until Phase 3d ships, only `Sleep` and
        // `Yield` (single-thread) are observable here — both
        // resolve as "spin until wake-up" without an actual
        // context switch.
        if let Some(req) = state.yield_requested.take() {
            handle_yield(cpu, state, req);
        }
        // Scheduler nudge: when the active thread isn't
        // runnable (Terminated / Waiting because no other
        // Ready thread could be picked at yield time), look
        // for any thread sleeping on a Sleep wait. The
        // earliest wake target fast-forwards the global
        // clock; `wake_sleep_if_due` then moves matching
        // threads back to Ready, and `schedule_next_thread`
        // switches into one of them.
        let active_runnable = matches!(
            state.cur_thread().status,
            crate::sched::ThreadStatus::Ready | crate::sched::ThreadStatus::Running
        );
        if !active_runnable {
            if let Some(earliest) = earliest_sleep_resume(state) {
                state.scheduler.instructions_global =
                    state.scheduler.instructions_global.max(earliest);
                wake_sleep_if_due(state);
                schedule_next_thread(cpu, state);
            }
            // Active thread still not runnable AND no Ready
            // peer was found — the run is done. Return so the
            // outer host caller observes a clean exit rather
            // than a busy spin.
            if !matches!(
                state.cur_thread().status,
                crate::sched::ThreadStatus::Ready | crate::sched::ThreadStatus::Running
            ) {
                cpu.regs.eip = RET_SENTINEL;
                return Ok(());
            }
            state.cur_thread_mut().status = crate::sched::ThreadStatus::Running;
        }
        if state.exit_requested.is_some() {
            // `kernel32!ExitProcess` was called. Force eip to
            // the sentinel so the outer caller's stack-frame
            // cleanup is consistent and exit cleanly.
            cpu.regs.eip = RET_SENTINEL;
            return Ok(());
        }
        if cpu.regs.eip == RET_SENTINEL {
            // The active thread has run off the end of its
            // top-level callable. If it's the bootstrap thread
            // (TID 1), the entire run is done. Otherwise, mark
            // the thread Terminated and switch to the next
            // Ready one.
            if state.active_tid == 1 {
                return Ok(());
            }
            let dead_tid = state.active_tid;
            state.cur_thread_mut().status = crate::sched::ThreadStatus::Terminated;
            on_thread_terminated(state, dead_tid);
            schedule_next_thread(cpu, state);
            // After the switch the live CPU points at the next
            // thread; if no other was Ready, we're back on the
            // bootstrap thread and `schedule_next_thread`
            // left the live CPU untouched — so we'll re-enter
            // this branch and return.
            if state.active_tid == 1
                && matches!(
                    state.cur_thread().status,
                    crate::sched::ThreadStatus::Ready | crate::sched::ThreadStatus::Running
                )
                && cpu.regs.eip == RET_SENTINEL
            {
                return Ok(());
            }
            continue;
        }
        // Optional instruction budget — both instruction steps
        // and stub dispatches are counted as one "step" each,
        // since either is a unit of progress the host attributed
        // to the guest. When the budget hits zero, bail with a
        // clean `BudgetExhausted` so adversarial samples can't
        // loop the analyser host.
        if let Some(remaining) = state.instruction_budget.as_mut() {
            if *remaining == 0 {
                return Err(crate::Error::Win32(Win32Error::BudgetExhausted {
                    executed: state.instructions_executed,
                }));
            }
            *remaining -= 1;
        }
        state.instructions_executed = state.instructions_executed.saturating_add(1);
        state.scheduler.instructions_global = state.scheduler.instructions_global.saturating_add(1);
        // Quantum-based preemption (Phase 4). Each executed
        // instruction or stub dispatch counts against the
        // current thread's quantum. When it hits zero, ask the
        // scheduler to switch — but only when there is another
        // Ready thread to switch to, otherwise the current
        // thread just keeps the floor with a fresh quantum.
        {
            let quantum_default = state.scheduler.quantum_default;
            let cur_tid = state.active_tid;
            let t = state.cur_thread_mut();
            if t.quantum_remaining > 0 {
                t.quantum_remaining -= 1;
            }
            let exhausted = t.quantum_remaining == 0;
            if exhausted {
                t.quantum_remaining = quantum_default;
            }
            if exhausted {
                let has_peer = state.threads.iter().any(|(tid, ts)| {
                    *tid != cur_tid && matches!(ts.status, crate::sched::ThreadStatus::Ready)
                });
                if has_peer {
                    state.yield_requested = Some(crate::sched::YieldRequest::Yield);
                }
            }
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
        // Snapshot eip BEFORE the step so a successful step
        // updates `last_eip_before_wild` to the actual last-
        // executed instruction, and a trapping step leaves it
        // holding the EIP of the instruction whose target was
        // the bad one (the call/jmp that pointed at a bad slot).
        let pre_step_eip = cpu.regs.eip;
        // Per-instruction trace for a configured EIP range
        // (UD_TRACE_RANGE=lo,hi). Useful when you've narrowed
        // a trap to a specific small function and want to see
        // the exact instruction that mis-jumps.
        if let Ok(range) = std::env::var("UD_TRACE_RANGE") {
            if let Some((lo_s, hi_s)) = range.split_once(',') {
                let lo = u32::from_str_radix(lo_s.trim_start_matches("0x"), 16).unwrap_or(0);
                let hi = u32::from_str_radix(hi_s.trim_start_matches("0x"), 16).unwrap_or(0);
                if pre_step_eip >= lo && pre_step_eip <= hi {
                    let esp = cpu.regs.get32(crate::emulator::regs::Reg32::Esp);
                    let opc: Vec<u8> = (0..6)
                        .map(|i| mmu.load8(pre_step_eip.wrapping_add(i)).unwrap_or(0))
                        .collect();
                    eprintln!(
                        "TRACE eip={pre_step_eip:#010x} esp={esp:#010x} bytes={:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                        opc[0], opc[1], opc[2], opc[3], opc[4], opc[5]
                    );
                }
            }
        }
        match cpu.step(mmu) {
            Ok(StepOk::Continued) => {
                if std::env::var("UD_TRACE_WILD_JUMP").is_ok() {
                    state.cur_thread_mut().last_eip_before_wild = pre_step_eip;
                }
                continue;
            }
            Ok(StepOk::Halted) => {
                // The active thread executed a `ret` whose
                // popped address was `RET_SENTINEL`. For the
                // bootstrap thread that's the run's exit; for
                // any other thread it means the thread proc
                // returned, so we mark it Terminated and let
                // the scheduler pick the next runnable peer.
                if state.active_tid == 1 {
                    return Ok(());
                }
                cpu.regs.eip = RET_SENTINEL;
                let dead_tid = state.active_tid;
                state.cur_thread_mut().status = crate::sched::ThreadStatus::Terminated;
                on_thread_terminated(state, dead_tid);
                schedule_next_thread(cpu, state);
                continue;
            }
            Err(t) => {
                // Win16 software interrupts (DOS INT 21h, …) are
                // serviced in place and the run resumes.
                if let crate::emulator::Trap::SoftwareInterrupt { num, .. } = t {
                    if crate::win16::service_interrupt(num, cpu, mmu, state) {
                        continue;
                    }
                }
                if cpu.is_code16() && std::env::var("UD_NE_DEBUG").is_ok() {
                    eprintln!("TRAP {t} | {}", cpu.seg_state());
                }
                if std::env::var("UD_TRACE_WILD_JUMP").is_ok() {
                    let last = state.cur_thread().last_eip_before_wild;
                    let esp = cpu.regs.get32(crate::emulator::regs::Reg32::Esp);
                    eprintln!(
                        "WILD-TRAP at_step_eip={pre_step_eip:#010x} prev_eip={last:#010x} esp={esp:#010x} trap={t}"
                    );
                }
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
            crate::emulator::Trap::SoftwareInterrupt { eip, .. } => {
                ("SoftwareInterrupt", *eip, None)
            }
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
        crate::Error::NeLoader(_) => ("NeLoader", cpu.regs.eip, None),
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
    registry: &mut Registry,
    state: &mut HostState,
    target_va: u32,
    args: &[u32],
) -> Result<u32, crate::Error> {
    use crate::emulator::isa_int::RET_SENTINEL;
    use crate::emulator::regs::Reg32;
    // Top-level host re-entries: the bootstrap thread always has a
    // ready quantum and a cleared exit/wait state. Without this,
    // a prior call_guest that ended with the guest in a `Waiting`
    // status (e.g. a `WaitForSingleObject` inside the codec's
    // DllMain) leaves `cur_thread().status` non-runnable —
    // `run_until_sentinel` would then short-circuit and the new
    // call would never execute a single instruction (returning
    // whatever EAX already held). Snap the bootstrap thread back
    // to Ready and clear its pending wait condition so each
    // top-level call_guest starts from a clean scheduler state.
    if state.active_tid == 1 {
        let quantum = state.scheduler.quantum_default;
        let t = state.cur_thread_mut();
        t.status = crate::sched::ThreadStatus::Ready;
        t.wait = None;
        t.quantum_remaining = quantum;
    }
    state.exit_requested = None;
    // Push args right-to-left.
    for a in args.iter().rev() {
        cpu.push32(mmu, *a)?;
    }
    cpu.push32(mmu, RET_SENTINEL)?;
    cpu.regs.eip = target_va;
    if std::env::var("UD_TRACE_WILD_JUMP").is_ok() {
        eprintln!(
            "  call_guest: eip set to {:#010x} (esp={:#010x})",
            cpu.regs.eip,
            cpu.regs.esp()
        );
    }
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
        _r: &mut Registry,
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
            _r: &mut Registry,
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
        dispatch_stub(&mut cpu, &mut mmu, &mut registry, &mut state).unwrap();

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
            _r: &mut Registry,
        ) -> Result<u32, Win32Error> {
            Ok(0)
        }
        let addr = registry.register("msvcrt.dll", "??3@YAXPAX@Z", dummy_delete_stub, 0);
        cpu.push32(&mut mmu, 0x6000_02c0).unwrap(); // ptr arg
        cpu.push32(&mut mmu, 0x1c237e58).unwrap(); // saved ret
        cpu.regs.eip = addr;
        let mut state = HostState::new(0, 0);
        dispatch_stub(&mut cpu, &mut mmu, &mut registry, &mut state).unwrap();
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
        dispatch_stub(&mut cpu, &mut mmu, &mut registry, &mut state).unwrap();

        // After: eax=0xCAFE, eip = ret addr, esp pops 12 bytes
        // total (1 ret + 2 args).
        assert_eq!(cpu.regs.get32(crate::emulator::regs::Reg32::Eax), 0xCAFE);
        assert_eq!(cpu.regs.eip, 0x2222);
        assert_eq!(cpu.regs.esp(), esp_before + 12);
    }
}

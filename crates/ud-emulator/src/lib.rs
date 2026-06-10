//! Pure-Rust 32-bit x86 emulator + PE loader + Video for Windows
//! host. Lets oxideav delegate decoding (and eventually encoding)
//! to legitimately-licensed Windows codec DLLs on any platform.
//!
//! **Round 1 — "Load + DllMain + clean exit".** The crate ships:
//!
//! * [`emulator::mmu`] — flat 4 GiB virtual address space, sparse
//!   4 KiB pages with R/W/X permission bits.
//! * [`emulator::regs`], [`emulator::decode`], [`emulator::isa_int`]
//!   — i386 register file, instruction decoder, executor for the
//!   integer base ISA.
//! * [`pe`] — PE32-only loader: DOS + PE header parse, section
//!   mapping into the MMU, base relocation, IAT resolution against
//!   the Win32 stub registry, export-by-name lookup.
//! * [`win32::kernel32`] — minimum stub set to satisfy a
//!   Cinepak-class DLL: `GetProcessHeap` / `HeapAlloc` /
//!   `HeapFree` / `HeapReAlloc` / `LocalAlloc` / `LocalFree` /
//!   `OutputDebugStringA` / `GetTickCount` /
//!   `InterlockedIncrement` / `InterlockedDecrement` /
//!   `LoadLibraryA` / `GetProcAddress`.
//!
//! **Round 2 — "Decode one Cinepak frame".** Adds:
//!
//! * [`Sandbox::call_export`] — generic stdcall guest-call helper.
//! * [`win32::vfw32`] — `BITMAPINFOHEADER` marshalling, `ICDECOMPRESS`
//!   layout, and the `IC*` host surface (`ICOpen`, `ICClose`,
//!   `ICGetInfo`, `ICDecompressBegin`, `ICDecompressQuery`,
//!   `ICDecompress`, `ICDecompressEnd`) that drives the codec
//!   DLL's `DriverProc` end-to-end.
//! * [`Sandbox::install_codec`] / [`Sandbox::ic_open`] etc — the
//!   ergonomic Rust-side wrappers the integration test uses.
//!
//! **Round 3 — "Real-codec smoke against IR32_32.DLL".** Adds:
//!
//! * `tests/common/mod.rs` — fixture-discovery helper:
//!   `OXIDEAV_VFW_FIXTURE_DIR` env var → Wine prefix → Windows
//!   system32 → on-disk cache → HTTPS fetch from
//!   `samples.oxideav.org`. CI=true bypasses the cache.
//! * Round-3 m1 test asserted the exact set of 49 Win32 imports
//!   (gdi32 / user32 / winmm + 24 extra kernel32) the
//!   round-1+2 stub registry did not satisfy — round 4's
//!   concrete dispatch budget. Round 4 closed every gap; the
//!   m1 test now asserts zero unresolved imports.
//! * `tests/m2_indeo3_driverproc.rs` retained the
//!   synthetic-codec walkthrough; a forward-compatible Indeo 3
//!   `DllMain → ICOpen → ICGetInfo → ICClose` walkthrough that
//!   activated once round 4 closed the import gaps.
//!
//! **Round 4 — "Close the 49 round-3 import gaps".** Adds the
//! 49 stubs round 3 surfaced:
//!
//! * [`win32::gdi32`] — 8 fail-soft stubs for `BitBlt` /
//!   `CreateCompatibleDC` / `DeleteDC` / `GetDeviceCaps` /
//!   `GetNearestColor` / `GetObjectA` /
//!   `GetSystemPaletteEntries` / `SelectObject`.
//! * [`win32::kernel32`] — 24 round-4 stubs covering the CRT
//!   init surface (`ExitProcess`, `GetACP` / `GetOEMCP` /
//!   `GetCPInfo`, `GetCommandLineA` / `GetEnvironmentStrings` /
//!   `GetFileType`, `GetLastError` / `SetLastError`,
//!   `GetModuleFileNameA` / `GetModuleHandleA`,
//!   `GetStartupInfoA` / `GetStdHandle` / `GetSystemInfo` /
//!   `GetVersion`, `GlobalAlloc` / `GlobalFree` / `GlobalLock`
//!   / `GlobalUnlock`, `MultiByteToWideChar` /
//!   `WideCharToMultiByte`, `RtlUnwind`, `VirtualAlloc` /
//!   `VirtualFree`, `WriteFile`).
//! * [`win32::user32`] — 16 fail-soft stubs covering the
//!   dialog / paint surface; `MessageBoxA` logs to stderr +
//!   `host.message_box_log`; `wsprintfA` is a real cdecl
//!   variadic implementation.
//! * [`win32::winmm`] — `DefDriverProc` (returns 0 / DRVCNF_OK).
//! * [`emulator::mmu::Mmu::unmap`] +
//!   [`emulator::mmu::Mmu::find_free_range`] for the
//!   `VirtualAlloc` / `VirtualFree` family.
//!
//! With round 4 in place, `IR32_32.DLL` loads cleanly and
//! `DllMain` runs until it hits the first ISA opcode our integer
//! interpreter does not yet decode: `ADD AL, imm8` (opcode
//! `0x04`) at `eip = 0x1000_612A`. That was round-4's hand-off
//! to round 5.
//!
//! **Round 5 — "DllMain + ICOpen + ICGetInfo + ICClose against
//! Intel IR32_32.DLL".** Adds:
//!
//! * The 8-bit primary ALU opcodes (`0x00..=0x05` ADD,
//!   `0x08..=0x0D` OR, `0x10..=0x15` ADC, …, `0x38..=0x3D` CMP)
//!   plus `r/m8 imm8` group-1 (`0x80`), `r/m8` group-3 (`0xF6`),
//!   `r/m8` group-4 (`0xFE`).
//! * Group-2 `r/m8` shifts (`0xC0/0xD0/0xD2`) plus the
//!   `r/m32` 1/cl variants (`0xD1/0xD3`).
//! * `IMUL r32, r/m32, imm32`/`imm8` (`0x69/0x6B`),
//!   `XCHG r/m, r` (`0x86/0x87`), `SAHF/LAHF` (`0x9E/0x9F`),
//!   `CMC` (`0xF5`), `PUSHAD/POPAD` (`0x60/0x61`), `ENTER`
//!   (`0xC8`), the full `MOVS/CMPS/STOS/LODS/SCAS` family with
//!   REP / REPE / REPNE prefixes.
//! * `0F 40..4F CMOVcc`, `0F A3 BT`, `0F AB BTS`, `0F A4..A5
//!   SHLD`, `0F AC..AD SHRD`, `0F BA` group-8 (BT/BTS/BTR/BTC
//!   imm8), `0F B1 CMPXCHG`, `0F C1 XADD`, `0F C8..CF BSWAP`.
//! * Per-instruction segment-override prefix routing through
//!   [`emulator::Cpu::set_fs_base`] / `set_gs_base`. The
//!   runtime maps a 4 KiB TEB at `0x7FFD_E000`, primes
//!   `FS:[0]` (SEH chain end-of-list = `-1`) and `FS:[0x18]`
//!   (TEB self-pointer), and points FS at it.
//! * Corrected `vfw32::ICM_*` numeric values
//!   (`ICM_GETINFO = 0x5002`, `ICM_DECOMPRESS = 0x400D`, etc).
//! * [`win32::vfw32::ic_open`] now stages a real 36-byte
//!   `ICOPEN` so the codec's `DRV_OPEN` allocates per-instance
//!   state (round 4 passed NULL).
//! * [`win32::vfw32::ic_get_info`] falls back to an
//!   fcc-derived `szName` when the codec leaves it NUL
//!   (real `vfw32!ICGetInfo` fills it from the registry).
//! * Bug-fix: round-4's `0xC6` (MOV r/m8, imm8) handler
//!   fetched the immediate BEFORE resolving the displacement.
//!
//! **Round 6 — "Drive the full IC* decode pipeline end-to-end
//! against Intel IR32_32.DLL".** No new emulator code needed:
//! round-5's ISA + segment-prefix coverage is sufficient for the
//! `ICDecompressQuery → ICDecompressBegin → ICDecompress →
//! ICDecompressEnd` sequence to walk cleanly. The
//! `tests/m2_indeo3_driverproc.rs::indeo3_decompress_one_keyframe`
//! integration test exercises the whole sequence against a
//! synthetic IV31 keyframe (64×48). The codec accepts the input
//! / output formats, sets up internal state, rejects the
//! synthetic NULL-data-size sync frame at the bitstream-header
//! validation step (returns `ICERR_BADIMAGE = -100`), and tears
//! down cleanly. SPECGAP: the `IV5PLAY` fixture bundle ships
//! only DLLs, no `.avi` payloads, so round-6 cannot exercise a
//! real keyframe end-to-end. Round 7+ swaps the synthetic input
//! for a real keyframe once one becomes available.
//!
//! **Round 7 — "Real IV31 keyframe decode through `cubes.mov`,
//! plus MMX scaffolding".** Twin deliverables:
//!
//! * **Part A — Real keyframe decode.** Adds a test-side
//!   QuickTime / ISO BMFF chunk walker
//!   (`tests/common/mov_extractor.rs`, ~270 LOC, authored from
//!   ISO/IEC 14496-12 alone) that locates sample 0 in
//!   `cubes.mov` (160×120 yuv410p, 121 KB) from
//!   `samples.oxideav.org/ffmpeg/V-codecs/IV32/`. The new
//!   `tests/round7_cubes_mov.rs::cubes_mov_first_keyframe_decodes_through_ir32_32_dll`
//!   feeds the real 3079-byte IV31 keyframe through the IC*
//!   sequence; `ICDecompress` returns `ICERR_OK` and ~30 K of
//!   the 57.6 KB RGB24 output is non-zero — the first real
//!   pixel decode through `IR32_32.DLL`. The bug fix that
//!   unblocks this:
//!   `ICM_DECOMPRESS_BEGIN` was at `ICM_USER + 16 = 0x4010`
//!   (round-5 typo) — an unmapped slot in `IR32_32.DLL`'s
//!   dispatch table. The canonical vfw.h value is
//!   `ICM_USER + 12 = 0x400C`. Without the BEGIN handler running,
//!   `ICDecompress` bailed early at a `[state2_ptr] != 0`
//!   sentinel check. While here,
//!   `ICM_DECOMPRESS_GET_FORMAT` corrected from
//!   `0x4008` → `0x400A`.
//! * **Part B — MMX scaffolding** for round 8.
//!   [`emulator::Cpu`] grows an `mmx: [u64; 8]` register file
//!   (`mm0..mm7`, per Intel SDM Vol. 1 §9.2.1). A new
//!   [`emulator::Trap::UnimplementedMmx`] variant carries the
//!   2-byte opcode + EIP + an SDM-derived mnemonic hint
//!   (`"PADDB MMX"`, `"PXOR MMX"`, `"EMMS"`, …). The
//!   `0x0F 0x60..0x6F`, `0x0F 0x70..0x7F`, and
//!   `0x0F 0xD0..0xFF` opcode blocks (per SDM Vol. 2
//!   Appendix A Table A-3) now route through
//!   `emulator::isa_int::dispatch_mmx` to the structured trap
//!   instead of the generic `UndefinedOpcode`. Round 8 reads
//!   the trap log to land MMX semantics opcode-by-opcode.
//!
//! **Round 18 — `trace` Cargo feature.** Resolves the planned
//! "trace mode" milestone documented in
//! `docs/winmf/winmf-emulator.md` §"Trace mode". A new feature
//! gate `trace` (off by default) adds `#[cfg]`'d probe sites at
//! the four natural choke points: every `dispatch_stub` call
//! (`kind=win32_call`), every guest memory access overlapping
//! a registered watchpoint (`kind=mem_write` / `kind=mem_read`),
//! every trap that bubbles out of the run loop (`kind=trap`),
//! and — under the `trace-exec` sub-feature plus
//! `Sandbox::set_exec_trace(true)` — every executed
//! instruction (`kind=exec`). Output is JSONL on a sink
//! configured via `OXIDEAV_VFW_TRACE_FILE=<path|2>` or
//! [`Sandbox::set_trace_sink`]. With the feature off, every
//! probe compiles away; release builds are bit-identical to
//! the round-17 baseline. Companion CLI is
//! `oxideav-tracevfw`.
//!
//! Modern codecs (H.264 / HEVC / AV1 / Opus / AAC / …) are decoded
//! natively elsewhere in the workspace; this crate exists for
//! **rare/legacy** codecs the project would otherwise permanently
//! shelve. Codec DLLs never execute on the host CPU; they run
//! through the bounded-MMU interpreter.
//!
//! See `OxideAV/docs/winmf/winmf-emulator.md` (659 lines, 13
//! sections) for the full design contract.

// `unsafe` is denied crate-wide — the pure-software interpreter, loaders, and
// Win32/Linux shims contain none. The single exception is the opt-in `kvm`
// backend (`linux::kvm`), which must mmap guest memory and issue `/dev/kvm`
// ioctls; that module carries a scoped `#![allow(unsafe_code)]` and every
// block has a `// SAFETY:` note. Hence `deny` (locally overridable there)
// rather than `forbid` (which is not).
#![deny(unsafe_code)]
// Mirror-from-oxideav-vfw allowances. Proper `Debug` impls and
// clippy-pedantic cleanup land in follow-up commits once the
// crate has been integrated with the decompile pipeline; the
// initial mirror keeps the source verbatim modulo crate-name
// shims for ease of diffing against the upstream.
#![allow(missing_debug_implementations)]
#![allow(clippy::pedantic)]
#![allow(clippy::all)]

pub mod com;
pub mod context;
pub mod coverage;
pub mod emulator;
pub mod ffi;
pub mod fsmount;
pub mod linux;
pub mod ne;
pub mod pe;
pub mod runtime;
pub mod sched;
#[cfg(feature = "trace")]
pub mod trace;
pub mod win16;
pub mod win32;

pub use context::{
    Context, FileAccess, FileHandle, OpenKey, RegistryKey, RegistryValue, VirtualFs,
    VirtualRegistry, HKCR, HKCU, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, HKLM, HKU,
};
pub use coverage::CoverageMap;
pub use ffi::{CallArgs, Dword, FromRet, Guest};

pub use com::{
    Guid, GuidParseError, CLSID_MEMORY_ALLOCATOR, IID_IBASEFILTER, IID_ICLASSFACTORY,
    IID_IENUMPINS, IID_IFILTERGRAPH, IID_IMEDIAFILTER, IID_IMEDIASAMPLE, IID_IMEMALLOCATOR,
    IID_IMEMINPUTPIN, IID_IPERSIST, IID_IPIN, IID_IUNKNOWN, MSADDS_AUDIO_DECODER_CLSID,
    MSADDS_AUDIO_PROPERTY_PAGE_CLSID,
};
pub use runtime::{Sandbox, DLL_PROCESS_ATTACH};
#[cfg(feature = "trace")]
pub use trace::{TraceState, WatchMode, Watchpoint};
pub use win32::vfw32::Bih;

/// Crate-local error type. Each layer (MMU / decoder / executor /
/// PE loader / Win32 stub) has its own variant; sublayers nest
/// their detail enums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Reserved placeholder. Removed in a later round once every
    /// caller has migrated to a more specific variant.
    NotImplemented,
    /// Guest tripped a CPU trap (memory fault, illegal opcode,
    /// privileged instruction, division by zero, …).
    Trap(emulator::Trap),
    /// PE loader rejected the input bytes — bad signature,
    /// unsupported PE32+ / .NET / packed binary, malformed
    /// directory entries, missing import, etc.
    PeLoader(pe::PeError),
    /// A Win32 stub was called with an argument the round-1 stub
    /// surface cannot satisfy (unknown DLL, unknown ordinal,
    /// invalid heap handle, etc.).
    Win32(win32::Win32Error),
    /// NE (16-bit Windows) loader rejected the input — bad signature,
    /// truncated segment, or a failed segment map. Carries the
    /// formatted detail (the loader error is not `Eq`).
    NeLoader(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotImplemented => f.write_str(
                "oxideav-vfw: round-1 does not yet implement this code path; \
                 see crates/oxideav-vfw/README.md for the milestone schedule.",
            ),
            Error::Trap(t) => write!(f, "oxideav-vfw emulator trap: {t}"),
            Error::PeLoader(e) => write!(f, "oxideav-vfw PE loader: {e}"),
            Error::Win32(e) => write!(f, "oxideav-vfw Win32 stub: {e}"),
            Error::NeLoader(e) => write!(f, "oxideav-vfw NE loader: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<emulator::Trap> for Error {
    fn from(t: emulator::Trap) -> Self {
        Error::Trap(t)
    }
}

impl From<pe::PeError> for Error {
    fn from(e: pe::PeError) -> Self {
        Error::PeLoader(e)
    }
}

impl From<win32::Win32Error> for Error {
    fn from(e: win32::Win32Error) -> Self {
        Error::Win32(e)
    }
}

/// Crate-local Result alias.
pub type Result<T> = core::result::Result<T, Error>;

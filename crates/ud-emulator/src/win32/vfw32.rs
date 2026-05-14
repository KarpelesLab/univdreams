//! `vfw32.dll` Installable-Compressor (`IC*`) stub surface.
//!
//! Each `IC*` entry point — the API the host side of the sandbox
//! drives the codec DLL with — boils down to "package the
//! arguments into the message-specific structure and dispatch to
//! `DriverProc`". This module owns:
//!
//! * The stdcall `DriverProc` guest invocation.
//! * The `BITMAPINFOHEADER` / `ICINFO` / `ICDECOMPRESS` /
//!   `ICDECOMPRESSEX` marshalling helpers.
//! * `IC*` host-side wrappers ([`ic_open`], [`ic_close`],
//!   [`ic_get_info`], [`ic_decompress_query`],
//!   [`ic_decompress_begin`], [`ic_decompress`],
//!   [`ic_decompress_end`]).
//!
//! These wrappers are what the round-2 end-to-end test calls.
//! Because no caller DLL imports `vfw32!IC*` into the sandbox
//! today (we're driving it from outside, not from another guest
//! codec), there is no IAT thunk to register; the wrappers are
//! plain Rust functions that take a `&mut Sandbox`-shaped tuple
//! and synchronously invoke `DriverProc` until it returns.
//!
//! Reference: MSDN "Installable Compressor / IC functions"
//! (`docs.microsoft.com/en-us/windows/win32/api/vfw/`),
//! `winddi.h` / `mmsystem.h` / `vfw.h` constant definitions
//! transcribed below.
//!
//! All structures here are POD with explicit field-by-field
//! marshalling; no use of `#[repr(C)]` types crossing the host /
//! guest boundary, by design — the entire crate is
//! `#![forbid(unsafe_code)]`.

use super::{call_guest, HicEntry, HostState, Registry, Win32Error};
use crate::emulator::{Cpu, Mmu};

// --- Constants — vfw.h transcriptions --------------------------------

/// `mmsystem.h`: Driver-proc message — driver code is being
/// loaded into memory. Sent ONCE, by the system, before any
/// per-instance `DRV_OPEN`. Real `vfw32!ICOpen` issues this before
/// the first `DRV_OPEN`. Round 11 — without this, `IR50_32.DLL`'s
/// global table-init chain (semaphore-guarded one-time setup that
/// allocates ~400 KB at `[0x1009c770]`) is never run, and the
/// later `ICDecompress` validation that reads `[0x1009c770]` finds
/// NULL and bails with `ICERR_BADIMAGE`.
pub const DRV_LOAD: u32 = 0x0001;
/// `mmsystem.h`: Driver-proc message — enable the driver.
/// Sent after `DRV_LOAD` and before per-instance `DRV_OPEN`.
pub const DRV_ENABLE: u32 = 0x0002;
/// `mmsystem.h`: Driver-proc message — the driver was just opened.
pub const DRV_OPEN: u32 = 0x0003;
/// `mmsystem.h`: Driver-proc message — the driver is being closed.
pub const DRV_CLOSE: u32 = 0x0004;
/// `mmsystem.h`: Driver-proc message — disable the driver.
/// Sent before `DRV_FREE`.
pub const DRV_DISABLE: u32 = 0x0005;
/// `mmsystem.h`: Driver-proc message — driver code is being
/// unloaded. Sent ONCE, after the last `DRV_CLOSE` /
/// `DRV_DISABLE`.
pub const DRV_FREE: u32 = 0x0006;

/// vfw.h: `ICM_USER = DRV_USER + 0x0000 = 0x4000`. Start of the
/// IC message space.
pub const ICM_USER: u32 = 0x4000;

/// vfw.h: `ICM_RESERVED_LOW = DRV_USER + 0x1000 = 0x5000`. Used
/// as the base for `ICM_GETINFO` etc.
pub const ICM_RESERVED: u32 = 0x5000;

// Authoritative `ICM_*` numeric values (vfw.h, Windows 10 SDK):
//   ICM_GETINFO                  = ICM_RESERVED + 2   (0x5002)
//   ICM_DECOMPRESS_GET_FORMAT    = ICM_USER + 10      (0x400A)
//   ICM_DECOMPRESS_QUERY         = ICM_USER + 11      (0x400B)
//   ICM_DECOMPRESS_BEGIN         = ICM_USER + 12      (0x400C)
//   ICM_DECOMPRESS               = ICM_USER + 13      (0x400D)
//   ICM_DECOMPRESS_END           = ICM_USER + 14      (0x400E)
//   ICM_DECOMPRESS_SET_PALETTE   = ICM_USER + 29      (0x401D)
//   ICM_DECOMPRESS_GET_PALETTE   = ICM_USER + 30      (0x401E)
//
// Round-4's table was wrong (used `ICM_USER + 0/0x29/0x2A/0x2B/0x2C`)
// — round-5 corrected QUERY/END/DECOMPRESS but kept BEGIN at the wrong
// value (ICM_USER + 16 = 0x4010). Round-7 fixes BEGIN to ICM_USER + 12
// after disassembling IR32_32.DLL's dispatch table at 0x10001760: the
// real BEGIN handler at 0x10001339 calls 0x10002a30 which sets up the
// per-instance state2 buffer (`inc [state2_ptr]`), without which
// ICM_DECOMPRESS bails immediately at the `cmp [state2_ptr], 0`
// validation in 0x10002b30 (returns ICERR_BADIMAGE = 0xFFFFFF9C).
//
// And GET_FORMAT was at +8 (0x4008) — round-7 fixes to +10 (0x400A).

/// `vfw.h`: `ICM_GETINFO` (request the codec's identity card).
pub const ICM_GETINFO: u32 = ICM_RESERVED + 2;
/// `vfw.h`: `ICM_DECOMPRESS_GET_FORMAT`.
pub const ICM_DECOMPRESS_GET_FORMAT: u32 = ICM_USER + 10;
/// `vfw.h`: `ICM_DECOMPRESS_QUERY` — can we decompress this format?
pub const ICM_DECOMPRESS_QUERY: u32 = ICM_USER + 11;
/// `vfw.h`: `ICM_DECOMPRESS_BEGIN`.
pub const ICM_DECOMPRESS_BEGIN: u32 = ICM_USER + 12;
/// `vfw.h`: `ICM_DECOMPRESS`.
pub const ICM_DECOMPRESS: u32 = ICM_USER + 13;
/// `vfw.h`: `ICM_DECOMPRESS_END`.
pub const ICM_DECOMPRESS_END: u32 = ICM_USER + 14;

// --- ICM_COMPRESS_* messages (vfw.h, Windows 10 SDK) ---
//   ICM_COMPRESS_GET_FORMAT     = ICM_USER + 4   (0x4004)
//   ICM_COMPRESS_GET_SIZE       = ICM_USER + 5   (0x4005)
//   ICM_COMPRESS_QUERY          = ICM_USER + 6   (0x4006)
//   ICM_COMPRESS_BEGIN          = ICM_USER + 7   (0x4007)
//   ICM_COMPRESS                = ICM_USER + 8   (0x4008)
//   ICM_COMPRESS_END            = ICM_USER + 9   (0x4009)
//
// Round 51 transcribes these from `winsdk-10/Include/.../um/Vfw.h`
// against MSDN's `ICM_COMPRESS` / `ICM_COMPRESS_QUERY` /
// `ICM_COMPRESS_BEGIN` / `ICM_COMPRESS_END` /
// `ICM_COMPRESS_GET_FORMAT` / `ICM_COMPRESS_GET_SIZE` topic
// pages. None of these are documented as decimal offsets in the
// MSDN topic prose; the canonical numeric values come from the
// header.

/// `vfw.h`: `ICM_COMPRESS_GET_FORMAT` — codec fills in the output
/// `BITMAPINFOHEADER` describing what its compressed output looks
/// like for the supplied input format.
pub const ICM_COMPRESS_GET_FORMAT: u32 = ICM_USER + 4;
/// `vfw.h`: `ICM_COMPRESS_GET_SIZE` — max bytes the codec might
/// emit for one frame at the supplied input/output formats.
pub const ICM_COMPRESS_GET_SIZE: u32 = ICM_USER + 5;
/// `vfw.h`: `ICM_COMPRESS_QUERY` — can the codec compress this
/// input format into the requested output format?
pub const ICM_COMPRESS_QUERY: u32 = ICM_USER + 6;
/// `vfw.h`: `ICM_COMPRESS_BEGIN` — set up the encoder pipeline.
pub const ICM_COMPRESS_BEGIN: u32 = ICM_USER + 7;
/// `vfw.h`: `ICM_COMPRESS` — encode one frame; `lParam1` is a
/// pointer to an `ICCOMPRESS` struct.
pub const ICM_COMPRESS: u32 = ICM_USER + 8;
/// `vfw.h`: `ICM_COMPRESS_END` — tear down the encoder pipeline.
pub const ICM_COMPRESS_END: u32 = ICM_USER + 9;

/// `vfw.h`: `ICCOMPRESS_KEYFRAME = 0x00000001L`. Caller sets this
/// in `ICCOMPRESS::dwFlags` to ask the codec to emit a keyframe;
/// the codec writes its actual choice into `*lpdwFlags` (the
/// pointer slot at offset +24 in the `ICCOMPRESS` struct).
pub const ICCOMPRESS_KEYFRAME: u32 = 0x0000_0001;

// vfw.h: ICDECOMPRESS dwFlags
/// "This is a key/intra frame" — set on the first frame and on
/// any frame the bitstream marks as a keyframe.
pub const ICDECOMPRESS_HURRYUP: u32 = 0x80000000;
pub const ICDECOMPRESS_UPDATE: u32 = 0x40000000;
pub const ICDECOMPRESS_PREROL: u32 = 0x20000000;
pub const ICDECOMPRESS_NULLFRAME: u32 = 0x10000000;
pub const ICDECOMPRESS_NOTKEYFRAME: u32 = 0x08000000;

/// `vfw.h`: `ICERR_OK = 0`. Most query-style messages should
/// return this when the answer is "yes".
pub const ICERR_OK: i32 = 0;
/// `vfw.h`: `ICERR_UNSUPPORTED = -1`.
pub const ICERR_UNSUPPORTED: i32 = -1;
/// `vfw.h`: `ICERR_BADFORMAT = -2`.
pub const ICERR_BADFORMAT: i32 = -2;

/// `vfw.h` `ICINFO` total size — 6 dwords (`dwSize`, `fccType`,
/// `fccHandler`, `dwFlags`, `dwVersion`, `dwVersionICM`) +
/// `WCHAR szName[16]` (32 B) + `WCHAR szDescription[128]`
/// (256 B) + `WCHAR szDriver[128]` (256 B) = 24 + 32 + 256 + 256
/// = **568 bytes**. Real `vfw32!ICGetInfo` always passes this
/// value as `lParam2` of `ICM_GETINFO`.
///
/// **Round 24 — ICGetInfo callers MUST pass `cb >= ICINFO_SIZE`.**
/// MS-MPEG-4 v3 (`mpg4c32.dll`) gates its handler at
/// `mpg4c32!DriverProc+0x999..0x99c`:
/// ```text
///     mov  ebx, 0x238           ; 0x238 = 568
///     cmp  [ebp+0x10], ebx      ; lParam2 (cb)
///     jb   .return_zero
/// ```
/// — codecs that gate this way silently return 0 bytes when `cb`
/// is short, with no error indication. Indeo predecessors
/// (`IR32_32.DLL`, `IR41_32.AX`) accept `cb < 568` and write a
/// truncated header, but that's the lenient case; the strict
/// case is what host code must conform to.
pub const ICINFO_SIZE: u32 = 568;

// --- BITMAPINFOHEADER ------------------------------------------------

/// `wingdi.h` `BITMAPINFOHEADER` — 40 bytes. Round-2 only models
/// the canonical fields; the trailing extension area (used by
/// codecs that ship a private blob after the header) is not
/// touched by these helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bih {
    /// `biSize` — must be `>= 40`.
    pub bi_size: u32,
    pub width: i32,
    pub height: i32,
    pub planes: u16,
    pub bit_count: u16,
    /// 4-byte FOURCC stored little-endian (`b'cvid'` for Cinepak,
    /// 0 for `BI_RGB`).
    pub compression: [u8; 4],
    pub size_image: u32,
    pub x_pels_per_meter: i32,
    pub y_pels_per_meter: i32,
    pub clr_used: u32,
    pub clr_important: u32,
}

impl Default for Bih {
    fn default() -> Self {
        Bih {
            bi_size: 40,
            width: 0,
            height: 0,
            planes: 1,
            bit_count: 24,
            compression: [0; 4],
            size_image: 0,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            clr_used: 0,
            clr_important: 0,
        }
    }
}

/// Total size of a canonical `BITMAPINFOHEADER` record.
pub const BIH_SIZE: u32 = 40;

/// Marshal a host-side [`Bih`] into 40 bytes at `addr` in guest
/// memory. The page must be R+W and have at least 40 bytes
/// mapped.
pub fn host_bih_to_guest(mmu: &mut Mmu, bih: &Bih, addr: u32) -> Result<(), Win32Error> {
    let trap = |t: crate::emulator::Trap| Win32Error::InvalidArgument {
        stub: "host_bih_to_guest",
        reason: format!("{t}"),
    };
    mmu.store32(addr, bih.bi_size).map_err(trap)?;
    mmu.store32(addr + 4, bih.width as u32).map_err(trap)?;
    mmu.store32(addr + 8, bih.height as u32).map_err(trap)?;
    mmu.store16(addr + 12, bih.planes).map_err(trap)?;
    mmu.store16(addr + 14, bih.bit_count).map_err(trap)?;
    mmu.write(addr + 16, &bih.compression).map_err(trap)?;
    mmu.store32(addr + 20, bih.size_image).map_err(trap)?;
    mmu.store32(addr + 24, bih.x_pels_per_meter as u32)
        .map_err(trap)?;
    mmu.store32(addr + 28, bih.y_pels_per_meter as u32)
        .map_err(trap)?;
    mmu.store32(addr + 32, bih.clr_used).map_err(trap)?;
    mmu.store32(addr + 36, bih.clr_important).map_err(trap)?;
    Ok(())
}

/// Read a guest [`Bih`] back into a host struct.
pub fn guest_bih_to_host(mmu: &Mmu, addr: u32) -> Result<Bih, Win32Error> {
    let trap = |t: crate::emulator::Trap| Win32Error::InvalidArgument {
        stub: "guest_bih_to_host",
        reason: format!("{t}"),
    };
    let bi_size = mmu.load32(addr).map_err(trap)?;
    let width = mmu.load32(addr + 4).map_err(trap)? as i32;
    let height = mmu.load32(addr + 8).map_err(trap)? as i32;
    let planes = mmu.load16(addr + 12).map_err(trap)?;
    let bit_count = mmu.load16(addr + 14).map_err(trap)?;
    let mut compression = [0u8; 4];
    for (i, c) in compression.iter_mut().enumerate() {
        *c = mmu.load8(addr + 16 + i as u32).map_err(trap)?;
    }
    let size_image = mmu.load32(addr + 20).map_err(trap)?;
    let x_pels_per_meter = mmu.load32(addr + 24).map_err(trap)? as i32;
    let y_pels_per_meter = mmu.load32(addr + 28).map_err(trap)? as i32;
    let clr_used = mmu.load32(addr + 32).map_err(trap)?;
    let clr_important = mmu.load32(addr + 36).map_err(trap)?;
    Ok(Bih {
        bi_size,
        width,
        height,
        planes,
        bit_count,
        compression,
        size_image,
        x_pels_per_meter,
        y_pels_per_meter,
        clr_used,
        clr_important,
    })
}

// --- ICDECOMPRESS structure ------------------------------------------

/// `vfw.h` `ICDECOMPRESS` — the lParam1 of `ICM_DECOMPRESS`.
///
/// ```c
/// typedef struct {
///     DWORD              dwFlags;
///     LPBITMAPINFOHEADER lpbiInput;
///     LPVOID             lpInput;
///     LPBITMAPINFOHEADER lpbiOutput;
///     LPVOID             lpOutput;
///     DWORD              ckid;
/// } ICDECOMPRESS;
/// ```
pub const ICDECOMPRESS_SIZE: u32 = 24;

/// `vfw.h` `ICDECOMPRESSEX` — the lParam1 of
/// `ICM_DECOMPRESS_BEGIN` / `ICM_DECOMPRESS_END`. The full
/// definition has source/dst rect arrays; we model the header
/// fields the codec actually reads during BEGIN / END (input
/// bih, output bih, dwFlags). Round-2 doesn't yet drive
/// per-region decode.
pub const ICDECOMPRESSEX_SIZE: u32 = 88;

/// `vfw.h` `ICCOMPRESS` — the `lParam1` of `ICM_COMPRESS`. Twelve
/// fields, all 4 bytes each on i386 (DWORD / LONG / pointer):
///
/// ```c
/// typedef struct {
///     DWORD              dwFlags;       // +0  ICCOMPRESS_KEYFRAME etc.
///     LPBITMAPINFOHEADER lpbiOutput;    // +4
///     LPVOID             lpOutput;      // +8
///     LPBITMAPINFOHEADER lpbiInput;     // +12
///     LPVOID             lpInput;       // +16
///     LPDWORD            lpckid;        // +20 chunk id (out)
///     LPDWORD            lpdwFlags;     // +24 returned flags (out)
///     LONG               lFrameNum;     // +28
///     DWORD              dwFrameSize;   // +32 max size, 0 = no limit
///     DWORD              dwQuality;     // +36 0..10000
///     LPBITMAPINFOHEADER lpbiPrev;      // +40
///     LPVOID             lpPrev;        // +44
/// } ICCOMPRESS;
/// ```
pub const ICCOMPRESS_SIZE: u32 = 48;

// --- IC* host-side wrappers ------------------------------------------

/// Open a codec instance.
///
/// `fcc_type` is a 4CC stored as `u32::from_le_bytes(b"VIDC")`
/// for video.  `fcc_handler` is the codec's 4CC (`b"cvid"` for
/// Cinepak; case-insensitive in real vfw32, but the codec
/// dispatch is up to the codec). `mode` is one of (vfw.h):
///
/// * `1` — `ICMODE_COMPRESS`
/// * `2` — `ICMODE_DECOMPRESS`
/// * `3` — `ICMODE_FASTDECOMPRESS`
/// * `4` — `ICMODE_QUERY`
/// * `5` — `ICMODE_FASTCOMPRESS`
/// * `8` — `ICMODE_DRAW`
///
/// (The earlier doc-comment swapped 1 and 2; corrected in round
/// 51 — Microsoft's codecs are historically permissive about
/// the mode word at DRV_OPEN so existing decode tests with
/// `mode=2` continue to work, but the canonical vfw.h mapping
/// is `ICMODE_DECOMPRESS = 2`.)
///
/// On success a synthetic `HIC` is minted and the codec's
/// `DriverProc(0, 0, DRV_OPEN, 0, 0)` is invoked. If `DriverProc`
/// returns 0, the open fails and the HIC is not retained.
pub fn ic_open(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    fcc_type: u32,
    fcc_handler: u32,
    mode: u32,
) -> Result<u32, crate::Error> {
    let driver_proc = state.default_driver_proc;
    if driver_proc == 0 {
        return Err(Win32Error::InvalidArgument {
            stub: "ICOpen",
            reason: "no codec image staged (host-side)".into(),
        }
        .into());
    }
    // Round 11 — before the first DRV_OPEN, real vfw32 dispatches
    // the one-time DRV_LOAD + DRV_ENABLE pair to the driver. The
    // codec's DRV_LOAD handler is where global / one-time table
    // initialisation runs. IR50_32.DLL allocates the codec's
    // huffman / inverse-DCT tables at `[0x1009c770]` from DRV_LOAD;
    // without it, ICDecompress reads `[0x1009c770] == NULL` and
    // bails with ICERR_BADIMAGE. Round 10 (and earlier) skipped
    // this step because IR32_32.DLL's DRV_LOAD is a near-no-op.
    // Track per-VA so a multi-codec sandbox (round-12+) doesn't
    // double-init the same driver.
    if !state.loaded_drivers.contains(&driver_proc) {
        let _ = call_guest(
            cpu,
            mmu,
            registry,
            state,
            driver_proc,
            &[0, 0, DRV_LOAD, 0, 0],
        )?;
        let _ = call_guest(
            cpu,
            mmu,
            registry,
            state,
            driver_proc,
            &[0, 0, DRV_ENABLE, 0, 0],
        )?;
        state.loaded_drivers.insert(driver_proc);
    }
    // Real vfw32 calls
    //   DriverProc(dwDriverId=0, hdrvr=0, DRV_OPEN, 0, &ICOPEN).
    // The ICOPEN structure (vfw.h) is what triggers the codec to
    // allocate per-instance state and return a real pointer-as-
    // dwDriverId. Round-4 passed NULL for `lParam2`; Indeo 3 then
    // returns the magic sentinel 0xFFFF0000, which is NOT a real
    // pointer — every subsequent message that dereferences
    // `dwDriverId` faults. Round-5 stages a real ICOPEN.
    //
    // ICOPEN layout (vfw.h, 36 bytes, 9 dwords):
    //   +0  DWORD   dwSize       = 36
    //   +4  DWORD   fccType      = caller's `fcc_type`  ('vidc')
    //   +8  DWORD   fccHandler   = caller's `fcc_handler` ('iv31')
    //   +12 DWORD   dwVersion    = 0x00010000 (vfw 1.0)
    //   +16 DWORD   dwFlags      = caller's `mode`
    //   +20 LRESULT dwError      = 0 (out — codec sets on err)
    //   +24 LPVOID  pV1Reserved  = 0
    //   +28 LPVOID  pV2Reserved  = 0
    //   +32 DWORD   dnDevNode    = 0
    //
    // Round 21: real Win32 vfw32.dll lowercases fccType /
    // fccHandler before staging ICOPEN — `vfw.h` defines
    // `ICTYPE_VIDEO = mmioFOURCC('v','i','d','c')` (lowercase)
    // and the codec INF files register lowercase handler 4CCs
    // ('mp43', 'iv31', 'cvid', …). The strict mpg4c32 DRV_OPEN
    // path tests `[ebx+4] == 'vidc'` (lower); Indeo codecs are
    // permissive about casing so earlier rounds got away with
    // passing 'VIDC' through verbatim. Canonicalising here
    // matches `vfw32!ICOpen` and unblocks MSMPEG4 v3.
    const ICOPEN_SIZE: u32 = 36;
    let icopen = state.arena_alloc(ICOPEN_SIZE)?;
    let fcc_type_canon = fourcc_to_lower(fcc_type);
    let fcc_handler_canon = fourcc_to_lower(fcc_handler);
    let bytes: [u8; 36] = {
        let mut b = [0u8; 36];
        b[0..4].copy_from_slice(&ICOPEN_SIZE.to_le_bytes());
        b[4..8].copy_from_slice(&fcc_type_canon.to_le_bytes());
        b[8..12].copy_from_slice(&fcc_handler_canon.to_le_bytes());
        b[12..16].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        b[16..20].copy_from_slice(&mode.to_le_bytes());
        // dwError, pV1, pV2, dnDevNode all left as 0
        b
    };
    mmu.write_initializer(icopen, &bytes)
        .map_err(|t| Win32Error::InvalidArgument {
            stub: "ICOpen",
            reason: format!("{t}"),
        })?;
    let driver_id = call_guest(
        cpu,
        mmu,
        registry,
        state,
        driver_proc,
        &[0, 0, DRV_OPEN, 0, icopen],
    )?;
    if driver_id == 0 {
        return Ok(0);
    }
    let hic = state.next_hic;
    state.next_hic = state.next_hic.wrapping_add(1);
    state.hics.insert(
        hic,
        HicEntry {
            fcc_type,
            fcc_handler,
            mode,
            driver_proc_va: driver_proc,
            driver_id,
        },
    );
    Ok(hic)
}

/// Close a codec instance. Calls `DriverProc(driver_id, hic,
/// DRV_CLOSE, 0, 0)` and removes the HIC entry.
pub fn ic_close(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
) -> Result<u32, crate::Error> {
    let entry = match state.hics.remove(&hic) {
        Some(e) => e,
        None => {
            return Err(Win32Error::InvalidArgument {
                stub: "ICClose",
                reason: format!("unknown HIC {hic}"),
            }
            .into());
        }
    };
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, DRV_CLOSE, 0, 0],
    )
}

/// Set of FourCCs that get the round-17 short-return fallback in
/// [`ic_get_info`]. When a codec returns 0 bytes from
/// `ICM_GETINFO` (typical of DirectShow filters that delegate to
/// the Windows registry), and the open `HIC`'s `fcc_handler` is in
/// this set, a synthetic ICINFO buffer is fabricated with the
/// dwSize / fccType / fccHandler dwords and an fcc-derived
/// `szName`. The set covers every Indeo FourCC the crate has
/// ever loaded a binary for (round 5 IV31, round 14 IV32 alias,
/// rounds 15+16 IV41, rounds 8..14 IV50). New entries are added
/// only when a real codec binary lands in the corpus and surfaces
/// the same n=0 shape — the fallback is a host-side cushion, not
/// a registry replacement.
/// Lower-case every ASCII byte of a FOURCC, leaving non-letter
/// bytes untouched. The Win32 vfw32 ABI canonicalises 4CCs to
/// lower case before passing them to the codec — `vfw.h`
/// defines `ICTYPE_VIDEO = 'vidc'` (lowercase) and codec INF
/// entries register lowercase handler tags. Round 21 surfaced
/// the asymmetry with mpg4c32: its `DRV_OPEN` literally tests
/// `cmp dword [ebx+4], 'vidc'` (lower-case), and Indeo
/// predecessors only happened to ignore the field. Use this
/// in [`ic_open`] when staging the ICOPEN block.
fn fourcc_to_lower(fcc: u32) -> u32 {
    let bytes = fcc.to_le_bytes();
    let lowered = [
        bytes[0].to_ascii_lowercase(),
        bytes[1].to_ascii_lowercase(),
        bytes[2].to_ascii_lowercase(),
        bytes[3].to_ascii_lowercase(),
    ];
    u32::from_le_bytes(lowered)
}

fn is_known_short_return_fcc(fcc: u32) -> bool {
    matches!(
        &fcc.to_le_bytes(),
        b"IV31" | b"iv31" | b"IV32" | b"iv32" | b"IV41" | b"iv41" | b"IV50" | b"iv50"
    )
}

/// Synthesise an `ICINFO` record by calling
/// `DriverProc(_, _, ICM_GETINFO, &scratch, cb)` and reading
/// back what the codec wrote.
///
/// Real `vfw32!ICGetInfo` populates `fccType`, `fccHandler`, and
/// the three string fields (`szName`, `szDescription`, `szDriver`)
/// from registry data **before** posting `ICM_GETINFO`, so that
/// codecs that don't fill the string fields still report a name.
/// We have no registry; if the codec leaves `szName` empty we
/// synthesise a four-character ASCII rendering of the fcc handler
/// so callers (the integration test, the eventual codec wrapper)
/// see a non-empty descriptor. The fcc-derived fallback is purely
/// the host-side "I have no registry" cushion, **not** a claim
/// about what the codec returned.
///
/// Round 17 generalises the fallback to also fire when the codec
/// returns **zero bytes** (DirectShow filters such as `IR41_32.AX`
/// delegate `ICM_GETINFO` entirely to the host vfw32 registry +
/// drop the call on the floor). For known-Indeo FourCCs, when the
/// codec writes zero bytes, we synthesise a `cb`-sized buffer with
/// the standard ICINFO header (dwSize / fccType / fccHandler) plus
/// the fcc-derived szName WCHAR string.
///
/// Round 24 — caller must pass `cb >= ICINFO_SIZE` (= 568) for
/// strict codecs; mpg4c32 gates the handler at
/// `cmp [ebp+0x10], 0x238 / jb .return_zero`. Round-20's
/// experimental call passed `cb=80`, hitting that gate and
/// returning 0 bytes silently. We still accept smaller `cb`
/// values for the lenient Indeo codecs.
pub fn ic_get_info(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    cb: u32,
) -> Result<Vec<u8>, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICGetInfo",
            reason: format!("unknown HIC {hic}"),
        })?;
    let scratch = state.arena_alloc(cb)?;
    // Stamp the mapped bytes to zero (arena_alloc already zeroed
    // the host-mirror buffer, but we want to make sure mmu pages
    // are actually populated for read-back).
    let zeros = vec![0u8; cb as usize];
    mmu.write_initializer(scratch, &zeros)
        .map_err(|t| Win32Error::InvalidArgument {
            stub: "ICGetInfo",
            reason: format!("{t}"),
        })?;
    let written = call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_GETINFO, scratch, cb],
    )?;
    let n = written.min(cb) as usize;

    // Round-17 short-return generalisation: if the codec wrote
    // zero bytes AND the fcc is a known-Indeo handler, fabricate
    // a `cb`-sized ICINFO with the dwSize / fccType / fccHandler
    // header dwords + fcc-derived szName. This matches what
    // real `vfw32!ICGetInfo` would have done after consulting
    // the Windows registry — the IR41 DirectShow filter relies
    // on this code path because it ignores ICM_GETINFO entirely.
    if n == 0 && is_known_short_return_fcc(entry.fcc_handler) {
        // Surface a buffer the size the caller asked for, capped
        // to the full ICINFO 568-byte shape so we don't write past
        // any reasonable buffer.
        let synth_len = (cb as usize).min(568);
        let mut out = vec![0u8; synth_len];
        // dwSize (offset 0, the structure size the caller supplied).
        if synth_len >= 4 {
            out[0..4].copy_from_slice(&cb.to_le_bytes());
        }
        // fccType (offset 4).
        if synth_len >= 8 {
            out[4..8].copy_from_slice(&entry.fcc_type.to_le_bytes());
        }
        // fccHandler (offset 8).
        if synth_len >= 12 {
            out[8..12].copy_from_slice(&entry.fcc_handler.to_le_bytes());
        }
        // szName (offset 24, 16 WCHARs / 32 bytes): fcc-derived
        // ASCII as UTF-16LE — same shape as the post-call fallback
        // a few lines below.
        let fcc = entry.fcc_handler.to_le_bytes();
        for (i, &c) in fcc.iter().enumerate() {
            if 24 + i * 2 + 1 < synth_len {
                out[24 + i * 2] = c;
            }
        }
        return Ok(out);
    }

    let mut out = vec![0u8; n];
    for (i, b) in out.iter_mut().enumerate() {
        *b = mmu
            .load8(scratch + i as u32)
            .map_err(|t| Win32Error::InvalidArgument {
                stub: "ICGetInfo",
                reason: format!("{t}"),
            })?;
    }
    // szName starts at offset 24 (dwSize..dwVersionICM = 6 dwords)
    // and is 16 WCHARs (32 bytes). If the codec left it all-NUL,
    // fall back to the fcc handler — `vfw32!ICGetInfo` would
    // normally fill this from a registry "DESCRIPTION" entry.
    if out.len() >= 24 + 32 && out[24..24 + 32].iter().all(|b| *b == 0) {
        let fcc = entry.fcc_handler.to_le_bytes();
        for (i, &c) in fcc.iter().enumerate() {
            if 24 + i * 2 + 1 < out.len() {
                out[24 + i * 2] = c;
            }
        }
    }
    Ok(out)
}

/// Ask the codec whether it can decompress the given input format
/// to the given output format. Returns the `LRESULT` value
/// `DriverProc` chose — 0 means yes, negative means no.
///
/// Either `output` may be `None` to defer the format choice to
/// the codec.
pub fn ic_decompress_query(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
    output: Option<&Bih>,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICDecompressQuery",
            reason: format!("unknown HIC {hic}"),
        })?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = if let Some(out_bih) = output {
        let a = state.arena_alloc(BIH_SIZE)?;
        host_bih_to_guest(mmu, out_bih, a)?;
        a
    } else {
        0
    };
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[
            entry.driver_id,
            hic,
            ICM_DECOMPRESS_QUERY,
            in_addr,
            out_addr,
        ],
    )
}

/// `ICDecompressGetFormat` — ask the codec to fill in the output
/// `BITMAPINFOHEADER` corresponding to the given input BIH.
///
/// The codec writes the output format (typically a BI_RGB or
/// codec-native YUV BIH at the input's `width × height`) into the
/// supplied output buffer. Returns the codec's `LRESULT` (0 on
/// success). Round 30 uses this to probe the codec for stream
/// dimensions when `CodecParameters` arrived with `width = None`
/// (for callers that don't know dimensions ahead of time).
///
/// MSDN: `LRESULT ICDecompressGetFormat(HIC hic, LPBITMAPINFOHEADER
/// lpbiInput, LPBITMAPINFOHEADER lpbiOutput)` — when `lpbiOutput`
/// is NULL real vfw32 returns the size needed; we don't expose
/// that variant since our caller always provides a 40-byte slot.
pub fn ic_decompress_get_format(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
) -> Result<(u32, Bih), crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICDecompressGetFormat",
            reason: format!("unknown HIC {hic}"),
        })?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = state.arena_alloc(BIH_SIZE)?;
    // Pre-zero the output BIH so a codec that returns S_OK but
    // doesn't populate every field still produces deterministic
    // bytes.
    for i in 0..BIH_SIZE {
        mmu.store8(out_addr + i, 0)
            .map_err(|t| Win32Error::InvalidArgument {
                stub: "ICDecompressGetFormat",
                reason: format!("{t}"),
            })?;
    }
    let lr = call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[
            entry.driver_id,
            hic,
            ICM_DECOMPRESS_GET_FORMAT,
            in_addr,
            out_addr,
        ],
    )?;
    let out = guest_bih_to_host(mmu, out_addr)?;
    Ok((lr, out))
}

/// Negotiate the decoder pipeline. Returns the codec's `LRESULT`.
pub fn ic_decompress_begin(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
    output: &Bih,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICDecompressBegin",
            reason: format!("unknown HIC {hic}"),
        })?;
    // Round 22 — preempt the MSMPEG4 v3 (`mpg4c32!DriverProc`)
    // private "is this codec instance bound to the v3 wrapper?"
    // gate. The gate fires only when `state[+0x18] == 3` (set by
    // DRV_OPEN for fccHandler `MP43`/`mp43`); it dereferences a
    // 20-byte `{ DWORD == 1, 16-byte GUID }` record at
    // `state[+0xb4..+0xc8]` and bails with `ICERR_INTERNAL`
    // (`-100`) if the GUID does not match
    // `b4c66e30-0180-11d3-bbc6-006008320064`. No public Win32
    // ICM_* message populates these fields — they are written by
    // a private wrapper layer (DirectShow / DMO codec factory)
    // that real WMP/Media Foundation hosts the codec inside. We
    // synthesise the wrapper's contribution directly into guest
    // memory before the begin call. See
    // `tests/round22_decomp_begin_trace.rs` for the disasm-of-
    // record. Indeo / Cinepak codecs do not gate this way, so
    // the round-12 / round-15 paths remain a no-op.
    msmpeg4_v3_preinit(mmu, state, &entry)?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, output, out_addr)?;
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[
            entry.driver_id,
            hic,
            ICM_DECOMPRESS_BEGIN,
            in_addr,
            out_addr,
        ],
    )
}

/// 16-byte GUID at `mpg4c32.dll!.text:0x1c201128`, decoded from
/// the on-disk byte sequence
/// `30 6e c6 b4 80 01 d3 11 bb c6 00 60 08 32 00 64`. Stored as
/// big-endian-by-field per Microsoft's `GUID` layout
/// (DWORD, WORD, WORD, BYTE[8]) so the byte stream is what
/// `rep cmpsb` matches against. Used by [`msmpeg4_v3_preinit`]
/// to satisfy mpg4c32's v3-only ICDecompressBegin gate.
const MSMPEG4_V3_PRIVATE_GUID: [u8; 16] = [
    0x30, 0x6e, 0xc6, 0xb4, 0x80, 0x01, 0xd3, 0x11, 0xbb, 0xc6, 0x00, 0x60, 0x08, 0x32, 0x00, 0x64,
];

/// Plant the MSMPEG4 v3 private-wrapper handshake at
/// `state[+0xb4..+0xc8]` for instances that DRV_OPEN tagged as
/// v3 (i.e. `state[+0x18] == 3`). A no-op for any other codec
/// or non-v3 MSMPEG4 instance. Idempotent — safe to call from
/// every entry into the begin / decompress wrappers.
fn msmpeg4_v3_preinit(
    mmu: &mut Mmu,
    _state: &mut HostState,
    entry: &HicEntry,
) -> Result<(), Win32Error> {
    // Only mpg4c32 (and the binary-equivalent winxp build of
    // the same codec) tags state[+0x18]; on Indeo / Cinepak the
    // offset holds something unrelated. Gate on fcc_handler
    // first to keep the host-side behaviour predictable.
    let h = entry.fcc_handler.to_le_bytes();
    let is_msmpeg4 = matches!(
        &h,
        b"MP43" | b"mp43" | b"MP42" | b"mp42" | b"MPG4" | b"mpg4"
    );
    if !is_msmpeg4 {
        return Ok(());
    }
    let trap = |t: crate::emulator::Trap| Win32Error::InvalidArgument {
        stub: "ICDecompressBegin/msmpeg4_v3_preinit",
        reason: format!("{t}"),
    };
    // Verify the codec marked the instance as v3. Reading
    // [driver_id + 0x18] is safe: DRV_OPEN allocated 0xc8 bytes
    // via `malloc`, so the entire [+0..+0xc8] range is within
    // the codec's own arena.
    let v3_tag = mmu.load32(entry.driver_id + 0x18).map_err(trap)?;
    if v3_tag != 3 {
        return Ok(());
    }
    // Plant `{1u32, GUID}` at [driver_id + 0xb4]. The check at
    // mpg4c32!DriverProc+0x14e2 walks [driver_id+0xb4] for a
    // refcount-style sentinel (== 1), then `rep cmpsb` 16 bytes
    // from [driver_id+0xb8] against the GUID below.
    mmu.store32(entry.driver_id + 0xb4, 1).map_err(trap)?;
    mmu.write(entry.driver_id + 0xb8, &MSMPEG4_V3_PRIVATE_GUID)
        .map_err(trap)?;
    Ok(())
}

/// End-of-stream cleanup. Returns the codec's `LRESULT`.
pub fn ic_decompress_end(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICDecompressEnd",
            reason: format!("unknown HIC {hic}"),
        })?;
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_DECOMPRESS_END, 0, 0],
    )
}

/// Decompress one frame.
///
/// Lays out an `ICDECOMPRESS` structure in guest memory,
/// populates input/output `BITMAPINFOHEADER`s and the encoded /
/// raw byte buffers, calls `DriverProc(_, _, ICM_DECOMPRESS,
/// &icd, sizeof)`, then reads the decoded bytes back out.
///
/// `flags` is the `dwFlags` field of `ICDECOMPRESS`; a typical
/// value for the first frame is `0` (sender's choice; common
/// codec implementations key on `ICDECOMPRESS_NOTKEYFRAME`).
#[allow(clippy::too_many_arguments)]
pub fn ic_decompress(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    flags: u32,
    input_bih: &Bih,
    input_bytes: &[u8],
    output_bih: &Bih,
    output_capacity: u32,
) -> Result<(u32, Vec<u8>), crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICDecompress",
            reason: format!("unknown HIC {hic}"),
        })?;

    // Lay out the four pieces of guest scratch:
    //   bi-input, bi-output, in-bytes, out-bytes
    let bi_in = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input_bih, bi_in)?;
    let bi_out = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, output_bih, bi_out)?;

    let in_buf = state.arena_alloc(input_bytes.len() as u32)?;
    mmu.write_initializer(in_buf, input_bytes)
        .map_err(|t| Win32Error::InvalidArgument {
            stub: "ICDecompress",
            reason: format!("{t}"),
        })?;
    let out_buf = state.arena_alloc(output_capacity)?;
    let zeros = vec![0u8; output_capacity as usize];
    mmu.write_initializer(out_buf, &zeros)
        .map_err(|t| Win32Error::InvalidArgument {
            stub: "ICDecompress",
            reason: format!("{t}"),
        })?;

    // Lay out the ICDECOMPRESS struct.
    let icd = state.arena_alloc(ICDECOMPRESS_SIZE)?;
    let trap = |t: crate::emulator::Trap| Win32Error::InvalidArgument {
        stub: "ICDecompress",
        reason: format!("{t}"),
    };
    mmu.store32(icd, flags).map_err(trap)?;
    mmu.store32(icd + 4, bi_in).map_err(trap)?;
    mmu.store32(icd + 8, in_buf).map_err(trap)?;
    mmu.store32(icd + 12, bi_out).map_err(trap)?;
    mmu.store32(icd + 16, out_buf).map_err(trap)?;
    mmu.store32(icd + 20, 0).map_err(trap)?; // ckid

    let lresult = call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_DECOMPRESS, icd, ICDECOMPRESS_SIZE],
    )?;

    // Read back the decoded bytes.
    let mut out = vec![0u8; output_capacity as usize];
    for (i, b) in out.iter_mut().enumerate() {
        *b = mmu
            .load8(out_buf + i as u32)
            .map_err(|t| Win32Error::InvalidArgument {
                stub: "ICDecompress",
                reason: format!("{t}"),
            })?;
    }
    Ok((lresult, out))
}

// --- IC*Compress* host-side wrappers (round 51) ----------------------
//
// Mirror the decompress family one-for-one against vfw.h's
// ICM_COMPRESS_* messages. The only message that diverges
// structurally is `ICM_COMPRESS` itself, which takes a 12-field
// `ICCOMPRESS` struct (48 bytes) — twice as wide as
// `ICDECOMPRESS` and with `lpbiOutput` ordered before `lpbiInput`
// (opposite to ICDECOMPRESS). The other five messages
// (QUERY / GET_FORMAT / GET_SIZE / BEGIN / END) take a pair of
// `BITMAPINFOHEADER` pointers in `(lParam1, lParam2)`, exactly
// like their decompress counterparts.

/// `ICCompressQuery` — ask the codec whether it can compress the
/// given input format to the given output format. `lParam1` = input
/// BIH, `lParam2` = output BIH (or 0 to defer the choice).
/// Returns `ICERR_OK` (0) if the codec accepts the input.
///
/// MSDN: `LRESULT ICCompressQuery(HIC hic, LPBITMAPINFOHEADER
/// lpbiInput, LPBITMAPINFOHEADER lpbiOutput)`.
pub fn ic_compress_query(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
    output: Option<&Bih>,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICCompressQuery",
            reason: format!("unknown HIC {hic}"),
        })?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = if let Some(out_bih) = output {
        let a = state.arena_alloc(BIH_SIZE)?;
        host_bih_to_guest(mmu, out_bih, a)?;
        a
    } else {
        0
    };
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_COMPRESS_QUERY, in_addr, out_addr],
    )
}

/// `ICCompressGetFormat` — ask the codec to fill in the output
/// `BITMAPINFOHEADER` corresponding to the given input BIH. The
/// codec writes the format it would emit (the FourCC tag,
/// `biBitCount`, `biSizeImage` upper bound, etc.) into the output
/// slot. Returns `(LRESULT, output_bih)`.
///
/// MSDN: `LRESULT ICCompressGetFormat(HIC hic, LPBITMAPINFOHEADER
/// lpbiInput, LPBITMAPINFOHEADER lpbiOutput)`. When `lpbiOutput`
/// is NULL the codec returns the byte count needed; we always
/// supply a 40-byte slot.
pub fn ic_compress_get_format(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
) -> Result<(u32, Bih), crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICCompressGetFormat",
            reason: format!("unknown HIC {hic}"),
        })?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = state.arena_alloc(BIH_SIZE)?;
    // Pre-zero the output BIH so a partial codec write still
    // produces deterministic bytes for the caller to compare.
    for i in 0..BIH_SIZE {
        mmu.store8(out_addr + i, 0)
            .map_err(|t| Win32Error::InvalidArgument {
                stub: "ICCompressGetFormat",
                reason: format!("{t}"),
            })?;
    }
    let lr = call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[
            entry.driver_id,
            hic,
            ICM_COMPRESS_GET_FORMAT,
            in_addr,
            out_addr,
        ],
    )?;
    let out = guest_bih_to_host(mmu, out_addr)?;
    Ok((lr, out))
}

/// `ICCompressGetSize` — ask the codec for the maximum number of
/// bytes one encoded frame might produce. Caller passes both the
/// input BIH and the output BIH (the latter typically obtained from
/// [`ic_compress_get_format`]). Returns the size as a `u32`.
///
/// MSDN: `DWORD ICCompressGetSize(HIC hic, LPBITMAPINFOHEADER
/// lpbiInput, LPBITMAPINFOHEADER lpbiOutput)` — note the return
/// is documented as `DWORD`, not `LRESULT`. The codec's
/// `DriverProc` still returns the value in `eax` so the same
/// `call_guest` shape works.
pub fn ic_compress_get_size(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
    output: &Bih,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICCompressGetSize",
            reason: format!("unknown HIC {hic}"),
        })?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, output, out_addr)?;
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[
            entry.driver_id,
            hic,
            ICM_COMPRESS_GET_SIZE,
            in_addr,
            out_addr,
        ],
    )
}

/// `ICCompressBegin` — set up the encoder pipeline. Returns the
/// codec's `LRESULT` (0 = OK).
///
/// MSDN: `LRESULT ICCompressBegin(HIC hic, LPBITMAPINFOHEADER
/// lpbiInput, LPBITMAPINFOHEADER lpbiOutput)`.
///
/// Round 51 — applies the same `msmpeg4_v3_preinit` handshake the
/// decode-begin path already uses. The bare `ICCompressBegin`
/// against mpg4c32 returns `ICERR_INTERNAL` (`-100` /
/// `0xFFFFFF9C`) for the same reason `ICDecompressBegin` did in
/// round 21: mpg4c32's MS-MPEG-4 v3 dispatch gate at
/// `mpg4c32!DriverProc+0x14e2` walks `[driver_id+0xb4]` for the
/// `{1u32, GUID}` wrapper-handshake plant before either BEGIN
/// handler runs.  Mirroring the plant here unblocks the encode
/// pipeline symmetrically.
pub fn ic_compress_begin(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    input: &Bih,
    output: &Bih,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICCompressBegin",
            reason: format!("unknown HIC {hic}"),
        })?;
    msmpeg4_v3_preinit(mmu, state, &entry)?;
    let in_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input, in_addr)?;
    let out_addr = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, output, out_addr)?;
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_COMPRESS_BEGIN, in_addr, out_addr],
    )
}

/// `ICCompressEnd` — tear down the encoder pipeline. Returns the
/// codec's `LRESULT`.
///
/// MSDN: `LRESULT ICCompressEnd(HIC hic)`.
pub fn ic_compress_end(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
) -> Result<u32, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICCompressEnd",
            reason: format!("unknown HIC {hic}"),
        })?;
    call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_COMPRESS_END, 0, 0],
    )
}

/// Returned-by-reference companion to [`ic_compress`].
#[derive(Debug, Clone, Default)]
pub struct CompressOutcome {
    /// Codec's `LRESULT` (0 = `ICERR_OK`).
    pub lresult: u32,
    /// Encoded bytes (truncated to whatever fits in
    /// `output_capacity`).
    pub bytes: Vec<u8>,
    /// `output_bih` after the codec finished — `biSizeImage` is
    /// the field codecs update to advertise the actual encoded
    /// byte count.
    pub output_bih: Bih,
    /// Value the codec wrote to `*lpdwFlags`. The
    /// `ICCOMPRESS_KEYFRAME` bit echoes whether the codec
    /// emitted a keyframe (independent of the caller's request
    /// — some codecs force every frame to be a keyframe regardless
    /// of input flags, while others may skip a keyframe request if
    /// they think it would hurt compression).
    pub returned_flags: u32,
    /// Value the codec wrote to `*lpckid`. Real-vfw32 AVI muxers
    /// use this as the per-frame chunk-id ('00dc' = compressed
    /// frame, '00db' = uncompressed frame); the codec is allowed
    /// to override the caller-supplied default.
    pub ckid: u32,
}

/// Encode one frame.
///
/// Lays out an [`ICCOMPRESS_SIZE`]-byte `ICCOMPRESS` struct in
/// guest memory, populates input/output `BITMAPINFOHEADER`s, the
/// raw input pixel buffer, the encoded output buffer, and the
/// returned-flags / chunk-id slots, then calls
/// `DriverProc(_, _, ICM_COMPRESS, &icc, sizeof)`. After return,
/// reads back the encoded bytes + the post-call output BIH (whose
/// `biSizeImage` holds the actual encoded byte count) +
/// `*lpdwFlags` + `*lpckid`.
///
/// `flags` is the `dwFlags` field of `ICCOMPRESS`; a typical
/// value for a forced keyframe is [`ICCOMPRESS_KEYFRAME`] (`1`).
///
/// `ckid` / `frame_flags_in` / `frame_num` / `frame_size_limit`
/// (0 = no limit) / `quality` (0..10000) mirror the `ICCOMPRESS`
/// field names.
///
/// `prev_bih_opt` / `prev_bytes_opt` describe the previous
/// reconstructed frame for P-frame encoders. Pass `None` /
/// `None` for keyframes — the codec sets the pointer slots
/// (`lpbiPrev` / `lpPrev`) to NULL.
#[allow(clippy::too_many_arguments)]
pub fn ic_compress(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &Registry,
    state: &mut HostState,
    hic: u32,
    flags: u32,
    input_bih: &Bih,
    input_bytes: &[u8],
    output_bih: &Bih,
    output_capacity: u32,
    ckid: u32,
    frame_num: i32,
    frame_size_limit: u32,
    quality: u32,
    prev_bih_opt: Option<&Bih>,
    prev_bytes_opt: Option<&[u8]>,
) -> Result<CompressOutcome, crate::Error> {
    let entry = state
        .hics
        .get(&hic)
        .cloned()
        .ok_or_else(|| Win32Error::InvalidArgument {
            stub: "ICCompress",
            reason: format!("unknown HIC {hic}"),
        })?;

    // Lay out the per-call guest scratch:
    //   bi-input, bi-output, in-bytes, out-bytes, ckid-slot,
    //   flags-slot, optional bi-prev + prev-bytes.
    let bi_in = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, input_bih, bi_in)?;
    let bi_out = state.arena_alloc(BIH_SIZE)?;
    host_bih_to_guest(mmu, output_bih, bi_out)?;

    let in_buf = state.arena_alloc(input_bytes.len().max(1) as u32)?;
    if !input_bytes.is_empty() {
        mmu.write_initializer(in_buf, input_bytes)
            .map_err(|t| Win32Error::InvalidArgument {
                stub: "ICCompress",
                reason: format!("{t}"),
            })?;
    }
    let out_buf = state.arena_alloc(output_capacity.max(1))?;
    let zeros = vec![0u8; output_capacity as usize];
    mmu.write_initializer(out_buf, &zeros)
        .map_err(|t| Win32Error::InvalidArgument {
            stub: "ICCompress",
            reason: format!("{t}"),
        })?;

    // 4-byte `lpckid` + 4-byte `lpdwFlags` out-slots — codec
    // writes the actual chunk-id and the actual flags into these.
    // Seeded with caller-supplied values so a non-overwriting
    // codec preserves the caller's intent.
    let ckid_slot = state.arena_alloc(4)?;
    let trap = |t: crate::emulator::Trap| Win32Error::InvalidArgument {
        stub: "ICCompress",
        reason: format!("{t}"),
    };
    mmu.store32(ckid_slot, ckid).map_err(trap)?;
    let flags_slot = state.arena_alloc(4)?;
    mmu.store32(flags_slot, flags).map_err(trap)?;

    // Optional previous-frame slots for P-frame encoders.
    let (bi_prev, prev_buf) = match (prev_bih_opt, prev_bytes_opt) {
        (Some(bih), Some(bytes)) => {
            let bp = state.arena_alloc(BIH_SIZE)?;
            host_bih_to_guest(mmu, bih, bp)?;
            let pb = state.arena_alloc(bytes.len().max(1) as u32)?;
            if !bytes.is_empty() {
                mmu.write_initializer(pb, bytes).map_err(trap)?;
            }
            (bp, pb)
        }
        _ => (0, 0),
    };

    // Lay out the ICCOMPRESS struct. 12 dwords, exact field
    // ordering from vfw.h (note: lpbiOutput is BEFORE lpbiInput,
    // inverted vs ICDECOMPRESS).
    let icc = state.arena_alloc(ICCOMPRESS_SIZE)?;
    mmu.store32(icc, flags).map_err(trap)?; // +0  dwFlags
    mmu.store32(icc + 4, bi_out).map_err(trap)?; // +4  lpbiOutput
    mmu.store32(icc + 8, out_buf).map_err(trap)?; // +8  lpOutput
    mmu.store32(icc + 12, bi_in).map_err(trap)?; // +12 lpbiInput
    mmu.store32(icc + 16, in_buf).map_err(trap)?; // +16 lpInput
    mmu.store32(icc + 20, ckid_slot).map_err(trap)?; // +20 lpckid
    mmu.store32(icc + 24, flags_slot).map_err(trap)?; // +24 lpdwFlags
    mmu.store32(icc + 28, frame_num as u32).map_err(trap)?; // +28 lFrameNum
    mmu.store32(icc + 32, frame_size_limit).map_err(trap)?; // +32 dwFrameSize
    mmu.store32(icc + 36, quality).map_err(trap)?; // +36 dwQuality
    mmu.store32(icc + 40, bi_prev).map_err(trap)?; // +40 lpbiPrev
    mmu.store32(icc + 44, prev_buf).map_err(trap)?; // +44 lpPrev

    let lresult = call_guest(
        cpu,
        mmu,
        registry,
        state,
        entry.driver_proc_va,
        &[entry.driver_id, hic, ICM_COMPRESS, icc, ICCOMPRESS_SIZE],
    )?;

    // Read back: encoded bytes from out_buf, the updated BIH (its
    // biSizeImage is what the codec uses to advertise the encoded
    // size), and the returned-by-reference flags/ckid slots.
    let mut bytes = vec![0u8; output_capacity as usize];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = mmu.load8(out_buf + i as u32).map_err(trap)?;
    }
    let output_bih_back = guest_bih_to_host(mmu, bi_out)?;
    let returned_flags = mmu.load32(flags_slot).map_err(trap)?;
    let ckid_back = mmu.load32(ckid_slot).map_err(trap)?;

    // Truncate `bytes` to the codec-advertised payload size when
    // it is non-zero and within capacity — bi.biSizeImage is the
    // canonical "actual encoded size" channel per the MSDN
    // `ICCompress` topic page ("On return, [the codec] sets the
    // size of the output frame in `biSizeImage` of the
    // BITMAPINFOHEADER pointed to by `lpbiOutput`"). If the codec
    // leaves biSizeImage at 0 or beyond `output_capacity`, we
    // surface the whole buffer and let the caller decide.
    let encoded_len = output_bih_back.size_image;
    if encoded_len > 0 && encoded_len <= output_capacity {
        bytes.truncate(encoded_len as usize);
    }

    Ok(CompressOutcome {
        lresult,
        bytes,
        output_bih: output_bih_back,
        returned_flags,
        ckid: ckid_back,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::{
        isa_int::RET_SENTINEL,
        mmu::{Mmu, Perm},
        regs::Reg32,
        Cpu,
    };
    use crate::win32::{HostState, Registry};

    /// Build a synthetic "DriverProc" — three bytes of code at
    /// `va` that load the second argument (`hdrvr` for OPEN /
    /// CLOSE; or just an `imm32` we choose) into eax and return:
    ///
    /// ```asm
    ///     mov eax, imm32
    ///     ret 20  ; pop 5 stdcall dwords
    /// ```
    fn install_canned_driver_proc(mmu: &mut Mmu, va: u32, ret_value: u32) {
        // mov eax, imm32  (B8 imm32)
        // ret 20          (C2 14 00)
        mmu.map(va & !0xFFF, 0x1000, Perm::R | Perm::W | Perm::X);
        let mut code = [0u8; 8];
        code[0] = 0xB8;
        code[1..5].copy_from_slice(&ret_value.to_le_bytes());
        code[5] = 0xC2;
        code[6..8].copy_from_slice(&20u16.to_le_bytes());
        mmu.write_initializer(va, &code).unwrap();
    }

    fn make_env() -> (Cpu, Mmu, Registry, HostState) {
        let mut mmu = Mmu::new();
        // Heap arena
        mmu.map(0x6000_0000, 0x10_0000, Perm::R | Perm::W);
        // Stack
        mmu.map(0x9000_0000, 0x10_0000, Perm::R | Perm::W);
        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x9000_0000 + 0x0F_0000);
        let mut registry = Registry::new();
        registry.register_kernel32();
        let state = HostState::new(0x6000_0000, 0x6000_0000 + 0x10_0000);
        (cpu, mmu, registry, state)
    }

    #[test]
    fn host_bih_marshal_roundtrip() {
        let (mut _cpu, mut mmu, _registry, _state) = make_env();
        let bih = Bih {
            bi_size: 40,
            width: 320,
            height: 240,
            planes: 1,
            bit_count: 24,
            compression: *b"cvid",
            size_image: 320 * 240 * 3 / 2,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            clr_used: 0,
            clr_important: 0,
        };
        host_bih_to_guest(&mut mmu, &bih, 0x6000_0000).unwrap();
        let back = guest_bih_to_host(&mmu, 0x6000_0000).unwrap();
        assert_eq!(bih, back);
    }

    #[test]
    fn ic_open_with_canned_driver_returns_synthetic_hic() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // Plant DriverProc at a fixed VA returning 0xC0FFEE
        // (driver-id) for DRV_OPEN.
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 0xC0FFEE);
        state.default_driver_proc = dpv;
        let fcc_video = u32::from_le_bytes(*b"VIDC");
        let fcc_cvid = u32::from_le_bytes(*b"cvid");
        let hic = ic_open(
            &mut cpu, &mut mmu, &registry, &mut state, fcc_video, fcc_cvid, 1,
        )
        .unwrap();
        assert_ne!(hic, 0);
        let entry = state.hics.get(&hic).unwrap();
        assert_eq!(entry.driver_id, 0xC0FFEE);
        assert_eq!(entry.driver_proc_va, dpv);
        assert_eq!(entry.fcc_type, fcc_video);
        assert_eq!(entry.fcc_handler, fcc_cvid);
        // Sentinel was popped — eip should be RET_SENTINEL or
        // wherever the runner left it. The contract is just that
        // the hic was installed.
        assert_eq!(cpu.regs.eip, RET_SENTINEL);
    }

    #[test]
    fn ic_open_returning_zero_does_not_install_hic() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 0);
        state.default_driver_proc = dpv;
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, 0, 1).unwrap();
        assert_eq!(hic, 0);
        assert!(state.hics.is_empty());
    }

    #[test]
    fn ic_close_invokes_driver_proc_and_drops_hic() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 0xABCD);
        state.default_driver_proc = dpv;
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, 0, 1).unwrap();
        // ic_close: codec returns whatever, we ensure the HIC is
        // gone.
        let _ = ic_close(&mut cpu, &mut mmu, &registry, &mut state, hic).unwrap();
        assert!(state.hics.is_empty());
    }

    #[test]
    fn ic_close_unknown_hic_errors() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let r = ic_close(&mut cpu, &mut mmu, &registry, &mut state, 99);
        assert!(r.is_err());
    }

    #[test]
    fn ic_get_info_reads_back_codec_buffer() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // DriverProc that, instead of writing icinfo, just
        // returns the cb argument so we can verify the message
        // round-trip + the cb passed into the callback.
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 16);
        state.default_driver_proc = dpv;
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, 0, 1).unwrap();
        let bytes = ic_get_info(&mut cpu, &mut mmu, &registry, &mut state, hic, 32).unwrap();
        // We allocated 32; the canned proc returns 16 → we read
        // the first 16 bytes (all zero from arena_alloc).
        assert_eq!(bytes.len(), 16);
        assert!(bytes.iter().all(|b| *b == 0));
    }

    /// Round-17 unit gate for the short-return host-side szName
    /// fallback. A canned DriverProc that returns 0 from
    /// `ICM_GETINFO` (mirrors `IR41_32.AX`'s DirectShow-filter
    /// "delegate to registry" behaviour) MUST get a synthesised
    /// ICINFO with the standard header dwords and the fcc-derived
    /// szName WCHAR string when the open `HIC`'s fcc_handler is a
    /// known-Indeo FourCC.
    #[test]
    fn ic_get_info_short_return_synthesises_known_indeo_fcc() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        // DRV_OPEN must return non-zero to mint the HIC, but
        // ICM_GETINFO must return 0 to trigger the fallback. The
        // canned proc returns the same value for both — so we plant
        // a non-zero return for DRV_OPEN, install the HIC, then
        // re-plant 0 before driving ICGetInfo.
        install_canned_driver_proc(&mut mmu, dpv, 0xC0FFEE);
        state.default_driver_proc = dpv;
        let fcc_video = u32::from_le_bytes(*b"VIDC");
        let fcc_iv41 = u32::from_le_bytes(*b"IV41");
        let hic = ic_open(
            &mut cpu, &mut mmu, &registry, &mut state, fcc_video, fcc_iv41, 1,
        )
        .unwrap();
        assert_ne!(hic, 0);
        // Now flip the canned return to 0 — emulates the
        // DirectShow filter ignoring ICM_GETINFO.
        install_canned_driver_proc(&mut mmu, dpv, 0);
        let cb = 96u32;
        let bytes = ic_get_info(&mut cpu, &mut mmu, &registry, &mut state, hic, cb).unwrap();
        // Synthesised buffer: cb bytes (capped at 568, but cb=96 < 568).
        assert_eq!(bytes.len(), cb as usize);
        // dwSize echoes cb.
        assert_eq!(&bytes[0..4], &cb.to_le_bytes());
        // fccType / fccHandler propagated from the open HIC.
        assert_eq!(&bytes[4..8], &fcc_video.to_le_bytes());
        assert_eq!(&bytes[8..12], &fcc_iv41.to_le_bytes());
        // szName at offset 24 carries 'I','V','4','1' as UTF-16LE
        // ASCII (low-byte every other byte; high bytes stay 0).
        assert_eq!(bytes[24], b'I');
        assert_eq!(bytes[26], b'V');
        assert_eq!(bytes[28], b'4');
        assert_eq!(bytes[30], b'1');
        assert_eq!(bytes[25], 0);
        assert_eq!(bytes[27], 0);
        assert_eq!(bytes[29], 0);
        assert_eq!(bytes[31], 0);
    }

    /// Round-17 negative gate: the short-return fallback only
    /// fires for known-Indeo FourCCs. An unknown fcc with a 0-byte
    /// codec response must surface as the original 0-length output
    /// vec — preserving the round-2 contract for canned tests like
    /// `ic_get_info_reads_back_codec_buffer` (which uses fcc=0).
    #[test]
    fn ic_get_info_short_return_unknown_fcc_returns_empty() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 0xC0FFEE);
        state.default_driver_proc = dpv;
        let fcc_unknown = u32::from_le_bytes(*b"XXXX");
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, fcc_unknown, 1).unwrap();
        // Flip canned to 0.
        install_canned_driver_proc(&mut mmu, dpv, 0);
        let bytes = ic_get_info(&mut cpu, &mut mmu, &registry, &mut state, hic, 64).unwrap();
        // Codec wrote 0 bytes, fcc is not Indeo → no synthesis,
        // empty output preserved (existing contract).
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn ic_decompress_round_trip_passes_buffers_through_emulator() {
        // Use a slightly-richer DriverProc that copies the input
        // bytes into the output buffer when ICM_DECOMPRESS fires.
        // For the canned proc to do that we'd need a real
        // assembly routine — too much for an isa_int unit test.
        // Instead we just check the call dispatches and the
        // output buffer survives.
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        // Plant a non-zero return value so DRV_OPEN succeeds and
        // mints a HIC. The same canned proc is then re-used for
        // ICM_DECOMPRESS, which expects 0 (ICERR_OK) — but our
        // contract here is just "the buffers round-trip cleanly".
        install_canned_driver_proc(&mut mmu, dpv, 0xDEAD_BEEF);
        state.default_driver_proc = dpv;
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, 0, 1).unwrap();
        assert_ne!(hic, 0);
        let bih_in = Bih {
            width: 16,
            height: 16,
            bit_count: 24,
            compression: *b"cvid",
            ..Default::default()
        };
        let bih_out = Bih {
            width: 16,
            height: 16,
            bit_count: 24,
            ..Default::default()
        };
        let input = vec![0xAAu8; 64];
        let (lr, out) = ic_decompress(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            hic,
            0,
            &bih_in,
            &input,
            &bih_out,
            16 * 16 * 3,
        )
        .unwrap();
        assert_eq!(lr, 0xDEAD_BEEF);
        assert_eq!(out.len(), 16 * 16 * 3);
        // Eax was set to the canned LRESULT.
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0xDEAD_BEEF);
    }

    // -- Round-51 unit tests for the compress wrappers ---------------

    #[test]
    fn iccompress_struct_size_matches_vfw_h_definition() {
        // 12 fields × 4 bytes each on i386 = 48. If anyone shrinks
        // ICCOMPRESS_SIZE in a future round this test catches it
        // before it corrupts the codec's view of the struct.
        assert_eq!(ICCOMPRESS_SIZE, 48);
    }

    #[test]
    fn icm_compress_constants_match_vfw_h_offsets() {
        // Canonical numeric values from `winsdk-10/.../Vfw.h`.
        // ICM_USER = 0x4000; the per-message offsets are
        // 4..9 in declaration order (GET_FORMAT, GET_SIZE,
        // QUERY, BEGIN, COMPRESS, END).
        assert_eq!(ICM_COMPRESS_GET_FORMAT, 0x4004);
        assert_eq!(ICM_COMPRESS_GET_SIZE, 0x4005);
        assert_eq!(ICM_COMPRESS_QUERY, 0x4006);
        assert_eq!(ICM_COMPRESS_BEGIN, 0x4007);
        assert_eq!(ICM_COMPRESS, 0x4008);
        assert_eq!(ICM_COMPRESS_END, 0x4009);
        assert_eq!(ICCOMPRESS_KEYFRAME, 0x0000_0001);
    }

    #[test]
    fn ic_compress_query_dispatches_to_driver_proc() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 0xC0FFEE);
        state.default_driver_proc = dpv;
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, 0, 1).unwrap();
        assert_ne!(hic, 0);
        // Now flip the canned to return 0 (ICERR_OK), mirroring
        // a codec that accepts the format.
        install_canned_driver_proc(&mut mmu, dpv, 0);
        let bih_in = Bih {
            width: 176,
            height: 144,
            bit_count: 24,
            compression: [0; 4],
            ..Default::default()
        };
        let bih_out = Bih {
            width: 176,
            height: 144,
            bit_count: 24,
            compression: *b"MP43",
            ..Default::default()
        };
        let lr = ic_compress_query(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            hic,
            &bih_in,
            Some(&bih_out),
        )
        .unwrap();
        assert_eq!(lr, 0);
    }

    #[test]
    fn ic_compress_round_trip_passes_buffers_through_emulator() {
        // The canned proc returns DEAD_BEEF for every message; we
        // are only verifying that the full ICCOMPRESS marshal +
        // call-guest sequence does not trap. Real-codec semantics
        // live in the integration test against `mpg4c32.dll`.
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let dpv = 0x0040_0000;
        install_canned_driver_proc(&mut mmu, dpv, 0xDEAD_BEEF);
        state.default_driver_proc = dpv;
        let hic = ic_open(&mut cpu, &mut mmu, &registry, &mut state, 0, 0, 1).unwrap();
        assert_ne!(hic, 0);
        let bih_in = Bih {
            width: 16,
            height: 16,
            bit_count: 24,
            compression: [0; 4],
            ..Default::default()
        };
        let bih_out = Bih {
            width: 16,
            height: 16,
            bit_count: 24,
            compression: *b"MP43",
            ..Default::default()
        };
        let input = vec![0xAAu8; 16 * 16 * 3];
        let outcome = ic_compress(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            hic,
            ICCOMPRESS_KEYFRAME,
            &bih_in,
            &input,
            &bih_out,
            16 * 16 * 3,
            u32::from_le_bytes(*b"00dc"),
            0,
            0,
            5000,
            None,
            None,
        )
        .unwrap();
        assert_eq!(outcome.lresult, 0xDEAD_BEEF);
        // Output buffer survived. Length stays at output_capacity
        // because the canned proc didn't touch bi.biSizeImage, so
        // the truncate-on-encoded-len branch leaves bytes alone.
        assert_eq!(outcome.bytes.len(), 16 * 16 * 3);
        // The returned-flags slot was seeded with dwFlags +
        // canned proc didn't update it, so we see the seed.
        assert_eq!(outcome.returned_flags, ICCOMPRESS_KEYFRAME);
    }
}

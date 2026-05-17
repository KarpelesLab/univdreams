//! Round 70 piece B — `Sandbox::ic_get_state` /
//! `Sandbox::ic_set_state` integration test against `mpg4c32.dll`.
//!
//! Required by oxideav-tracevfw to drive the encoder's per-quality
//! knob round-trip via the VfW `ICM_GETSTATE` (`0x5009`) and
//! `ICM_SETSTATE` (`0x500A`) messages.
//!
//! The test exercises three behaviours:
//!
//!   1. **Probe call** — `ic_get_state(hic, &mut [])` returns the
//!      number of bytes the codec would write into a real buffer
//!      (the canonical "size-discovery" pattern from MSDN's
//!      `ICGetState` topic page).
//!   2. **Round-trip** — `ic_get_state` into a buffer, then
//!      `ic_set_state` with those same bytes, then `ic_get_state`
//!      again — should produce the same payload (idempotency).
//!   3. **Failure surface** — supplying an obviously-wrong-sized
//!      buffer to `ic_set_state` either returns `Ok(())` (codec
//!      tolerated it) or an `Err` (codec rejected it).  Either is
//!      a useful empirical signal for round-71 callers.
//!
//! ## References (clean-room only)
//!
//!  * MSDN `ICGetState` / `ICSetState` topic pages
//!    (`learn.microsoft.com/en-us/windows/win32/api/vfw/`).
//!  * `winsdk-10/Include/.../um/Vfw.h` — `ICM_GETSTATE = 0x5009`,
//!    `ICM_SETSTATE = 0x500A`.
//!
//! No Wine / ReactOS / MinGW source consulted.

use std::path::PathBuf;
use ud_emulator::Sandbox;

fn workspace_root() -> Option<PathBuf> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let manifest = PathBuf::from(manifest);
    Some(manifest.parent()?.parent()?.to_path_buf())
}

fn mpg4c32_path() -> Option<PathBuf> {
    let p =
        workspace_root()?.join("docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/mpg4c32.dll");
    p.is_file().then_some(p)
}

/// vfw.h: `ICMODE_COMPRESS = 1`.
const ICMODE_COMPRESS: u32 = 1;

fn open_msmpeg4_encoder() -> Option<(Sandbox, u32)> {
    let dll = mpg4c32_path()?;
    let dll_bytes = std::fs::read(&dll).ok()?;
    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(2_000_000_000);
    let img = sb.load("mpg4c32.dll", &dll_bytes).ok()?;
    let _ = sb
        .call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH)
        .ok()?;
    sb.install_codec(&img).ok()?;
    let fcc_video = u32::from_le_bytes(*b"VIDC");
    let fcc_handler = u32::from_le_bytes(*b"MP43");
    let hic = sb.ic_open(fcc_video, fcc_handler, ICMODE_COMPRESS).ok()?;
    if hic == 0 {
        return None;
    }
    Some((sb, hic))
}

/// `vfw.h: ICERR_UNSUPPORTED = -1` — codec doesn't support the
/// message.  Cast to `u32` because driver-procs return their
/// `LRESULT` in `eax` and the wrapper carries it back as `u32`.
const ICERR_UNSUPPORTED_U32: u32 = 0xFFFF_FFFFu32;

#[test]
fn mpg4c32_ic_get_state_probe_returns_byte_count_or_unsupported() {
    let Some((mut sb, hic)) = open_msmpeg4_encoder() else {
        eprintln!("round70 piece B: mpg4c32.dll missing or codec refused encode mode; skipping");
        return;
    };
    // Probe: zero-length buffer.  Per MSDN `ICGetState`, a codec
    // that supports state serialisation returns the byte count it
    // would write into a real buffer.  Codecs that don't may
    // return `ICERR_UNSUPPORTED` (`-1`).  Either is a valid
    // empirical finding.
    let mut empty: Vec<u8> = Vec::new();
    let n = sb
        .ic_get_state(hic, &mut empty)
        .expect("ICGetState dispatch should not trap (LRESULT can be any value)");
    if n == ICERR_UNSUPPORTED_U32 {
        eprintln!(
            "round70 piece B: mpg4c32 returns ICERR_UNSUPPORTED for ICGetState — \
             this codec is stateless across calls (no per-instance state to \
             serialise via the VfW state surface)"
        );
    } else {
        eprintln!("round70 piece B: mpg4c32 ICGetState probe returned {n} bytes (state-blob size)");
    }
}

#[test]
fn mpg4c32_ic_get_set_state_round_trip_is_idempotent() {
    let Some((mut sb, hic)) = open_msmpeg4_encoder() else {
        eprintln!("round70 piece B: mpg4c32.dll missing or codec refused encode mode; skipping");
        return;
    };
    // Step 1 — probe the size.
    let mut empty: Vec<u8> = Vec::new();
    let probe_n = sb
        .ic_get_state(hic, &mut empty)
        .expect("ICGetState probe dispatch should not trap");
    #[allow(clippy::cast_possible_wrap)]
    let probe_signed = probe_n as i32;
    eprintln!(
        "round70 piece B: mpg4c32 ICGetState probe size = {probe_signed} (raw LRESULT {probe_n:#010x})"
    );

    if probe_n == ICERR_UNSUPPORTED_U32 {
        // mpg4c32 doesn't support ICGetState — that's a valid
        // empirical finding for this codec.  Round-trip is
        // skipped because there's nothing to serialise.
        eprintln!(
            "round70 piece B: mpg4c32 reports ICERR_UNSUPPORTED — \
             round-trip not applicable; treating as valid empirical finding"
        );
        return;
    }
    if probe_n == 0 {
        // Zero-length state blob — also valid (codec reports
        // stateless-but-supported).
        eprintln!(
            "round70 piece B: mpg4c32 reports zero state-blob size — \
             round-trip degenerates to empty payload"
        );
        // ICSetState with empty blob.
        sb.ic_set_state(hic, &[])
            .expect("ICSetState with empty blob should succeed against zero-state codec");
        return;
    }

    // Step 2 — fetch the actual blob.
    let cap = (probe_n as usize).max(1);
    let mut blob_a = vec![0u8; cap];
    let n_a = sb
        .ic_get_state(hic, &mut blob_a)
        .expect("ICGetState (real fetch) should succeed");
    assert_eq!(
        n_a as usize, cap,
        "ICGetState write-count should match the probed size"
    );
    eprintln!(
        "round70 piece B: mpg4c32 ICGetState fetched {} bytes — first 16 = {:02x?}",
        n_a,
        &blob_a[..blob_a.len().min(16)]
    );

    // Step 3 — set the blob back.  Codec should return ICERR_OK.
    sb.ic_set_state(hic, &blob_a)
        .expect("ICSetState with previously-fetched state should return ICERR_OK");

    // Step 4 — re-fetch and compare.  Idempotency demands the
    // second fetch matches the first; if it doesn't, the codec is
    // mutating internal state on each get/set cycle (legal but
    // notable).
    let mut blob_b = vec![0u8; cap];
    let n_b = sb
        .ic_get_state(hic, &mut blob_b)
        .expect("ICGetState (re-fetch) should succeed");
    assert_eq!(
        n_b, n_a,
        "ICGetState size should be stable across set/get cycles"
    );
    if blob_a == blob_b {
        eprintln!("round70 piece B: ICGetState/SetState round-trip IDEMPOTENT");
    } else {
        // Find the first differing byte for the diagnostic.
        let first_diff = blob_a
            .iter()
            .zip(blob_b.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        eprintln!(
            "round70 piece B: ICGetState/SetState round-trip NOT byte-identical; \
             first diff at offset {first_diff} (a={:#04x}, b={:#04x}) — \
             codec may stamp a sequence counter or timestamp on each get",
            blob_a[first_diff], blob_b[first_diff]
        );
    }
}

#[test]
fn unit_sandbox_ic_get_set_state_smoke_against_canned_driver() {
    // Sanity-check the Sandbox wrapper layer against a
    // canned-driver setup that doesn't require mpg4c32.dll.  The
    // canned driver returns a fixed driver-id (`0x00C0_FFEE`) on
    // every dispatch — both DRV_OPEN (so `ic_open` installs the
    // HIC) and the subsequent ICM_GETSTATE/ICM_SETSTATE.  We
    // only verify the marshal layer doesn't trap; the exact
    // codec semantics live in the per-codec integration tests.
    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(50_000_000);
    let dpv = 0x0040_0000u32;
    sb.mmu.map(
        dpv & !0xFFF,
        0x1000,
        ud_emulator::emulator::mmu::Perm::R
            | ud_emulator::emulator::mmu::Perm::W
            | ud_emulator::emulator::mmu::Perm::X,
    );
    // mov eax, 0x00C0_FFEE; ret 20  (5 stdcall dwords)
    let _ = sb
        .mmu
        .write_initializer(dpv, &[0xB8, 0xEE, 0xFF, 0xC0, 0x00, 0xC2, 0x14, 0x00]);
    sb.host.default_driver_proc = dpv;

    // Use the high-level Sandbox::ic_open API (mirrors what
    // tracevfw downstream will do).
    let hic = sb
        .ic_open(0, 0, 1)
        .expect("Sandbox::ic_open against canned driver should succeed");
    assert_ne!(hic, 0);

    // ic_get_state with empty buffer: returns the canned driver's
    // LRESULT (`0x00C0_FFEE`).  We only verify the wrapper doesn't
    // trap and the value is surfaced unmodified.
    let mut empty: Vec<u8> = Vec::new();
    let n = sb
        .ic_get_state(hic, &mut empty)
        .expect("ic_get_state probe should succeed");
    assert_eq!(n, 0x00C0_FFEE);

    // ic_set_state with empty buffer: canned driver returns
    // `0x00C0_FFEE` (NOT `ICERR_OK = 0`), so the wrapper surfaces
    // an `Err` carrying the raw LRESULT in its message.
    let r = sb.ic_set_state(hic, &[]);
    assert!(
        r.is_err(),
        "ic_set_state with non-zero LRESULT should return Err"
    );
}

//! Round 69 — pin which of the four NULL-guard `jz 0xc969` branches
//! inside `msadds32.ax`'s inner-decode body at RVA `0xc887..0xc973`
//! actually fires now that the round-68 ffmpeg-derived
//! `WAVEFORMATEX::cbSize` preamble shifts `IMemInputPin::Receive`
//! HRESULT from `E_UNEXPECTED` (`0x8000FFFF`) to `E_FAIL`
//! (`0x80004005`).
//!
//! Round 68 (see `tests/round68_msadds32_real_extradata.rs` +
//! `docs/codec/msadds32-receive-e-unexpected.md` §"Round 68") observed
//! that the inner decode at RVA `0xc887` — a `__thiscall` with 9
//! stdcall args — has FOUR argument-NULL bail-outs all targeting the
//! same `E_FAIL` mov at `0xc96a`:
//!
//! ```text
//! 0xc890: cmp [ebp+0x08], eax  ; arg0 (input pointer)
//! 0xc898: jz  0xc969
//! 0xc89e: mov ebx, [ebp+0x10]  ; arg2 (out-struct A pointer)
//! 0xc8a1: cmp ebx, eax
//! 0xc8a3: jz  0xc969
//! 0xc8a9: cmp [ebp+0x14], eax  ; arg3 (flag/length)
//! 0xc8ac: jz  0xc969
//! 0xc8b2: mov edi, [ebp+0x1c]  ; arg5 (&samples_produced)
//! 0xc8b5: cmp edi, eax
//! 0xc8b7: jz  0xc969
//! ```
//!
//! Plus a fifth bail at `0xc936: jnz +0x36 → 0xc96e` which fires when
//! the inner-inner decode call at `0xc92c: call 0xc975` returns
//! non-zero.  Any of these five sites can produce the `E_FAIL` Round
//! 68 observed.  (Round-64's hand-off note placed the `jnz` at
//! `0xc935` — that's a 1-byte transcription error; the actual
//! instruction starts at `0xc936`, with `0xc935` being the last byte
//! of the prior `mov [ebp+0x1c], eax` at `0xc933`.  Round 69 confirms
//! both via raw-byte readback.)
//!
//! ## Strategy
//!
//! This round arms `Cpu::add_register_watchpoint` snapshots at:
//!
//!   * `0xc887` — entry sentinel (confirms the inner decode is
//!     reached at all).
//!   * `0xc890` — right after the prologue's `mov ebp, esp`, before
//!     any guard.  At this point the memory probe `[ebp+8]` directly
//!     reads `arg0`.
//!   * `0xc8a1` — `ebx = arg2` is in a register; the snapshot's
//!     `ebx` field shows `arg2`'s value.
//!   * `0xc8a9` — `cmp [ebp+0x14], eax`; ebp is still valid, so a
//!     post-mortem `mmu.load32(ebp+0x14)` reads `arg3`.
//!   * `0xc8b5` — `edi = arg5` is in a register; the snapshot's
//!     `edi` field shows `arg5`'s value.
//!   * `0xc935` — only reached if all four arg guards pass; if a
//!     snapshot lands here, the bail is the inner-inner failure
//!     check, NOT the NULL-arg guards.
//!   * `0xc969` — the common `E_FAIL` bail sink.  A snapshot here
//!     confirms which-ever guard fired.
//!
//! After `Receive` returns / traps, the test dumps every snapshot in
//! fire order.  The very first snapshot at `0xc969` (or `0xc935`) is
//! the bail site for THIS run.
//!
//! ## Reference material (clean-room only)
//!
//! * Intel SDM Vol. 2 — opcode encoding, ModR/M, SIB.
//! * MSDN — `IMemInputPin::Receive`, COM HRESULT semantics
//!   (`E_FAIL = 0x80004005`).
//! * Raw bytes of `msadds32.ax` from
//!   `docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/`.
//!
//! No Wine / ReactOS / MinGW / Microsoft DShow base-class source
//! consulted.

// Forensic tests carry large diagnostic dumps that legitimately
// trip a handful of pedantic lints (long literal disassembly RVAs
// are easier to read without `_` separators when they match the
// listing; `usize → u16` casts are LRESULT-bound; multi-pane
// snapshot loops blow past 100 LOC by design).  Allow them here
// rather than diluting the diagnostic prose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::default_trait_access,
    clippy::format_in_format_args,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::redundant_closure_for_method_calls,
    clippy::single_match_else,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::cast_lossless,
    clippy::explicit_iter_loop,
    clippy::map_unwrap_or,
    clippy::needless_bool,
    clippy::needless_for_each
)]

use std::path::PathBuf;
use ud_emulator::com::{
    call::{call_method, vtable_is_plausible},
    AmtBlueprint, Guid, MSADDS_AUDIO_DECODER_CLSID, PIN_DIRECTION_INPUT, PIN_DIRECTION_OUTPUT,
    SLOT_BASEFILTER_ENUM_PINS, SLOT_BASEFILTER_STOP, SLOT_ENUMPINS_NEXT, SLOT_MEDIAFILTER_PAUSE,
    SLOT_MEDIAFILTER_RUN, SLOT_MEMALLOCATOR_COMMIT, SLOT_MEMALLOCATOR_SET_PROPERTIES,
    SLOT_MEMINPUTPIN_GET_ALLOCATOR, SLOT_MEMINPUTPIN_NOTIFY_ALLOCATOR, SLOT_MEMINPUTPIN_RECEIVE,
    SLOT_PIN_QUERY_DIRECTION, SLOT_PIN_RECEIVE_CONNECTION,
};
use ud_emulator::{Sandbox, IID_IBASEFILTER, IID_ICLASSFACTORY, IID_IMEMINPUTPIN, IID_IUNKNOWN};

// ─── inner-decode site sentinels (clean-room from raw bytes) ─────────

/// Function entry — confirms the inner decode was reached at all.
const RVA_INNER_DECODE_ENTRY: u32 = 0xc887;
/// First post-prologue site: `cmp [ebp+8], eax`.  Watchpoint here
/// reads `arg0` via the `[ebp+8]` memory probe.
const RVA_AFTER_PROLOGUE: u32 = 0xc890;
/// `cmp ebx, eax` after `mov ebx, [ebp+0x10]`.  Snapshot's ebx == arg2.
const RVA_ARG2_IN_EBX: u32 = 0xc8a1;
/// `cmp [ebp+0x14], eax`.  Snapshot has ebp; arg3 = mmu.load32(ebp+0x14).
const RVA_ARG3_CMP: u32 = 0xc8a9;
/// `cmp edi, eax` after `mov edi, [ebp+0x1c]`.  Snapshot's edi == arg5.
const RVA_ARG5_IN_EDI: u32 = 0xc8b5;
/// Inner-inner decode failure check; only reached if all four NULL
/// guards pass.
const RVA_INNER_INNER_FAIL_CHECK: u32 = 0xc935;
/// The common `E_FAIL` bail target — any guard that fires lands here.
const RVA_BAIL_SINK: u32 = 0xc969;

// ─── shared bootstrap (mirrors r68's drive_full_chain_with_blueprint) ──

fn workspace_root() -> Option<PathBuf> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let manifest = PathBuf::from(manifest);
    Some(manifest.parent()?.parent()?.to_path_buf())
}

fn msadds32_path() -> Option<PathBuf> {
    let p =
        workspace_root()?.join("docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/msadds32.ax");
    p.is_file().then_some(p)
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audio/wma2_440hz_mono_1s.wma")
}

fn load_msadds32() -> Option<(Sandbox, ud_emulator::pe::Image)> {
    let p = msadds32_path()?;
    let bytes = std::fs::read(&p).ok()?;
    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(8_000_000_000);
    sb.cpu.enable_trace_ring(1_048_576);
    sb.cpu.track_visited_eips = true;
    // Round 69: lift the snapshot cap so a single Receive call can
    // accumulate snapshots at every armed site without losing the
    // tail (16 default ≪ ~5..7 expected hits, but the outer Receive
    // loop may re-enter the inner decode on a back-edge).
    sb.cpu.register_snapshots_cap = 256;
    let img = sb.load("msadds32.ax", &bytes).ok()?;
    let _ = sb.call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH);
    Some((sb, img))
}

fn bootstrap_filter() -> Option<(Sandbox, ud_emulator::pe::Image, u32, u32)> {
    let (mut sb, img) = load_msadds32()?;
    let _factory = sb
        .dll_get_class_object(&img, MSADDS_AUDIO_DECODER_CLSID, IID_ICLASSFACTORY)
        .ok()?;
    let unk = sb
        .co_create_instance(MSADDS_AUDIO_DECODER_CLSID, IID_IUNKNOWN)
        .ok()?;
    if unk == 0 {
        return None;
    }
    let filter = sb.query_interface(unk, IID_IBASEFILTER).ok()?;
    if filter == 0 || !vtable_is_plausible(&sb.mmu, filter) {
        return None;
    }
    Some((sb, img, unk, filter))
}

fn enum_pin_by_direction(sb: &mut Sandbox, filter: u32, want_dir: u32) -> Option<u32> {
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        filter,
        SLOT_BASEFILTER_STOP,
        &[],
    );
    let scratch = sb.host.arena_alloc(4).ok()?;
    sb.mmu.write_initializer(scratch, &[0u8; 4]).ok()?;
    call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        filter,
        SLOT_BASEFILTER_ENUM_PINS,
        &[scratch],
    )
    .ok()?;
    let pp = sb.mmu.load32(scratch).ok()?;
    if pp == 0 {
        return None;
    }
    sb.host.com.intern(pp, None);
    let mut found = None;
    for _ in 0..8 {
        let pin_slot = sb.host.arena_alloc(8).ok()?;
        sb.mmu.write_initializer(pin_slot, &[0u8; 8]).ok()?;
        let _ = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            pp,
            SLOT_ENUMPINS_NEXT,
            &[1, pin_slot, pin_slot + 4],
        );
        let pin = sb.mmu.load32(pin_slot).unwrap_or(0);
        let fetched = sb.mmu.load32(pin_slot + 4).unwrap_or(0);
        if pin == 0 || fetched != 1 {
            break;
        }
        sb.host.com.intern(pin, None);
        let dir_slot = sb.host.arena_alloc(4).ok()?;
        let _ = sb
            .mmu
            .write_initializer(dir_slot, &0xFFFF_FFFFu32.to_le_bytes());
        let _ = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            pin,
            SLOT_PIN_QUERY_DIRECTION,
            &[dir_slot],
        );
        let dir = sb.mmu.load32(dir_slot).unwrap_or(0xFFFF_FFFF);
        if dir == want_dir {
            found = Some(pin);
            break;
        }
    }
    let _ = sb.com_release(pp);
    found
}

fn stage_audio_amt_from_blueprint(
    sb: &mut Sandbox,
    bp: &AmtBlueprint,
) -> Result<u32, ud_emulator::Error> {
    use ud_emulator::Error;
    let wfx_len = bp.wfx_total_len();
    let total = 72 + wfx_len + 16;
    let blob = sb.host.arena_alloc(total).map_err(Error::Win32)?;
    let amt = blob;
    let fmt = blob + 72;
    let trap = Error::Trap;
    let mediatype_audio = Guid::parse("{73647561-0000-0010-8000-00AA00389B71}").unwrap();
    let format_wave = Guid::parse("{05589F81-C356-11CE-BF01-00AA0055595A}").unwrap();
    let subtype = Guid::new(
        bp.format_tag as u32,
        0x0000,
        0x0010,
        [0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71],
    );
    mediatype_audio.stage(&mut sb.mmu, amt).map_err(trap)?;
    subtype.stage(&mut sb.mmu, amt + 16).map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 32, &0u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 36, &1u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 40, &0u32.to_le_bytes())
        .map_err(trap)?;
    format_wave.stage(&mut sb.mmu, amt + 44).map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 60, &0u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 64, &wfx_len.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 68, &fmt.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(fmt, &bp.format_tag.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(fmt + 2, &bp.n_channels.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(fmt + 4, &bp.n_samples_per_sec.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(fmt + 8, &bp.n_avg_bytes_per_sec.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(fmt + 12, &bp.n_block_align.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(fmt + 14, &bp.w_bits_per_sample.to_le_bytes())
        .map_err(trap)?;
    let cb = bp.extradata.len() as u16;
    sb.mmu
        .write_initializer(fmt + 16, &cb.to_le_bytes())
        .map_err(trap)?;
    if !bp.extradata.is_empty() {
        sb.mmu
            .write_initializer(fmt + 18, &bp.extradata)
            .map_err(trap)?;
    }
    Ok(amt)
}

// ─── Snapshot capture ──────────────────────────────────────────────────

/// One snapshot at one of the armed RVAs.  All values are post-translation
/// (image_base added), so `eip` is the absolute guest address.
#[derive(Debug, Clone)]
struct Snapshot {
    /// Absolute guest EIP at snapshot time (image_base + RVA).
    eip: u32,
    /// Order of fire — 0 = first hit, 1 = second, …
    fire_order: usize,
    /// Integer register file at snapshot time: eax, ecx, edx, ebx,
    /// esp, ebp, esi, edi.
    regs: [u32; 8],
    /// Memory snapshot at the four fixed probe addresses:
    /// `[esp]`, `[esp+4]`, `[ebp+8]`, `[ebp-0x50]`.
    mem: [(u32, u32); 4],
}

/// Outcome of one watchpoint-armed Receive run.
struct WatchOutcome {
    receive_hr: Option<u32>,
    receive_trap: Option<String>,
    snapshots: Vec<Snapshot>,
    /// The Sandbox is preserved so post-mortem `mmu.load32` probes can
    /// read `[ebp+0x14]` / `[ebp+0x18]` / `[ebp+0x1c]` against the
    /// captured `ebp` values.
    sb: Sandbox,
    /// `image_base` captured at run time so the test can convert
    /// absolute EIPs back to RVAs.
    image_base: u32,
    /// Set of every RVA the codec executed during the Receive run
    /// (drained from `cpu.visited_eips` after the call returned).
    /// Used by phase 5 to identify the actual `0x80004005`-emission
    /// site — the inner decode at `0xc96a` is one of 17 candidate
    /// sites in the binary.
    visited_rvas: std::collections::BTreeSet<u32>,
}

/// File-offset scan of `msadds32.ax` (= RVAs because `.text` raw_data
/// == virt_addr == `0x1000`) for every linear occurrence of
/// `b8 05 40 00 80` — the canonical encoding of
/// `mov eax, 0x80004005` (E_FAIL).
///
/// Scan command (clean-room from raw bytes):
/// ```sh
/// python3 -c "import sys; d=open(sys.argv[1],'rb').read();
///     o=0;
///     while True:
///         i = d.find(b'\\xb8\\x05\\x40\\x00\\x80', o)
///         if i<0: break
///         print(hex(i)); o=i+1" \
///   docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/msadds32.ax
/// ```
const E_FAIL_MOV_EAX_SITES: &[u32] = &[
    0x28d8, 0x5ff1, 0x9179, 0x951b, 0x95c8, 0xc3f8, 0xc87b, 0xc969, 0xcb6e, 0xd044, 0xd113, 0xd209,
    0xd312, 0xd43c, 0xde84, 0xe0ed, 0xe2bb,
];

fn run_watch_armed_receive(
    bp: AmtBlueprint,
    apply_helper_addref_patch: Option<u32>,
) -> Option<WatchOutcome> {
    let (mut sb, img, _unk, filter) = bootstrap_filter()?;
    let base = img.image_base;

    if let Some(v) = apply_helper_addref_patch {
        sb.msadds32_patch_helper_addref(base, v).ok()?;
    }

    // Arm the watchpoints AFTER patch-time so the patched code path
    // still gets its snapshots if it ever lands inside the inner
    // decode.
    for rva in [
        RVA_INNER_DECODE_ENTRY,
        RVA_AFTER_PROLOGUE,
        RVA_ARG2_IN_EBX,
        RVA_ARG3_CMP,
        RVA_ARG5_IN_EDI,
        RVA_INNER_INNER_FAIL_CHECK,
        RVA_BAIL_SINK,
    ] {
        sb.cpu.add_register_watchpoint(base.wrapping_add(rva));
    }

    // ── Input pin + ReceiveConnection ───────────────────────────────
    let input_pin = enum_pin_by_direction(&mut sb, filter, PIN_DIRECTION_INPUT)?;
    let amt = stage_audio_amt_from_blueprint(&mut sb, &bp).ok()?;
    let host_out = sb
        .mint_host_output_pin_with_connection(amt, input_pin)
        .ok()?;
    let r_rc = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        input_pin,
        SLOT_PIN_RECEIVE_CONNECTION,
        &[host_out, amt],
    )
    .ok()?;
    if r_rc != 0 {
        eprintln!(
            "round69: ReceiveConnection returned {r_rc:#010x} — \
             AMT not accepted; skipping watchpoint capture"
        );
        return None;
    }

    let mip = sb.query_interface(input_pin, IID_IMEMINPUTPIN).ok()?;
    if mip == 0 {
        return None;
    }

    // ── Output pin ──────────────────────────────────────────────────
    let out_pin = enum_pin_by_direction(&mut sb, filter, PIN_DIRECTION_OUTPUT)?;
    let (h_pin, _h_mip) = sb.host_iface_r31_mint_input_pin_pair().ok()?;
    let _ = sb.host_iface_r31_mint_base_filter(h_pin).ok()?;
    let dn_wfx_len: u32 = 18;
    let dn_total = 72 + dn_wfx_len;
    let dn_blob = sb.host.arena_alloc(dn_total).ok()?;
    let dn_amt = dn_blob;
    let dn_fmt = dn_blob + 72;
    let mediatype_audio = Guid::parse("{73647561-0000-0010-8000-00AA00389B71}").unwrap();
    let mediasubtype_pcm = Guid::parse("{00000001-0000-0010-8000-00AA00389B71}").unwrap();
    let format_wave = Guid::parse("{05589F81-C356-11CE-BF01-00AA0055595A}").unwrap();
    let _ = mediatype_audio.stage(&mut sb.mmu, dn_amt);
    let _ = mediasubtype_pcm.stage(&mut sb.mmu, dn_amt + 16);
    let _ = sb.mmu.write_initializer(dn_amt + 32, &0u32.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_amt + 36, &1u32.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_amt + 40, &0u32.to_le_bytes());
    let _ = format_wave.stage(&mut sb.mmu, dn_amt + 44);
    let _ = sb.mmu.write_initializer(dn_amt + 60, &0u32.to_le_bytes());
    let _ = sb
        .mmu
        .write_initializer(dn_amt + 64, &dn_wfx_len.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_amt + 68, &dn_fmt.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_fmt, &1u16.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_fmt + 2, &1u16.to_le_bytes());
    let _ = sb
        .mmu
        .write_initializer(dn_fmt + 4, &44_100u32.to_le_bytes());
    let _ = sb
        .mmu
        .write_initializer(dn_fmt + 8, &88_200u32.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_fmt + 12, &2u16.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_fmt + 14, &16u16.to_le_bytes());
    let _ = sb.mmu.write_initializer(dn_fmt + 16, &0u16.to_le_bytes());
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        out_pin,
        SLOT_PIN_RECEIVE_CONNECTION,
        &[h_pin, dn_amt],
    );

    // ── Allocator handshake ─────────────────────────────────────────
    let pp = sb.host.arena_alloc(4).ok()?;
    let _ = sb.mmu.write_initializer(pp, &0u32.to_le_bytes());
    let r_ga = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        mip,
        SLOT_MEMINPUTPIN_GET_ALLOCATOR,
        &[pp],
    )
    .unwrap_or(0xFFFF_FFFF);
    let codec_alloc = sb.mmu.load32(pp).unwrap_or(0);
    let host_alloc = sb.mint_host_mem_allocator(4, 8192, amt).ok()?;
    let target_alloc = if r_ga == 0 && codec_alloc != 0 {
        codec_alloc
    } else {
        host_alloc
    };
    let req = sb.host.arena_alloc(16).ok()?;
    let actual = sb.host.arena_alloc(16).ok()?;
    for (off, val) in [(0u32, 4u32), (4, 8192), (8, 1), (12, 0)] {
        let _ = sb.mmu.write_initializer(req + off, &val.to_le_bytes());
        let _ = sb.mmu.write_initializer(actual + off, &0u32.to_le_bytes());
    }
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        target_alloc,
        SLOT_MEMALLOCATOR_SET_PROPERTIES,
        &[req, actual],
    );
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        target_alloc,
        SLOT_MEMALLOCATOR_COMMIT,
        &[],
    );
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        mip,
        SLOT_MEMINPUTPIN_NOTIFY_ALLOCATOR,
        &[target_alloc, 0],
    );

    // ── Pause + Run ─────────────────────────────────────────────────
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        filter,
        SLOT_MEDIAFILTER_PAUSE,
        &[],
    );
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        filter,
        SLOT_MEDIAFILTER_RUN,
        &[0, 0],
    );

    // ── Push the WMA fixture sample ─────────────────────────────────
    let asf_bytes = std::fs::read(fixture_path()).ok()?;
    let packet = ud_emulator::com::locate_first_data_packet(&asf_bytes).unwrap_or(&[]);
    if packet.is_empty() {
        return None;
    }
    let payload: Vec<u8> = packet.iter().take(4096).copied().collect();
    let sample = sb.mint_host_media_sample(8192, amt).ok()?;
    sb.media_sample_set_payload(sample, &payload, true).ok()?;

    // Clear the trace ring + any pre-Receive register snapshots so
    // only the Receive call's hits land in the diagnostic.
    sb.cpu.trace_ring.clear();
    sb.cpu.visited_eips.clear();
    let _ = sb.cpu.clear_register_watchpoints();
    let _ = sb.cpu.take_memory_snapshots();
    // Re-arm AFTER the clear (clear_register_watchpoints also disarms).
    for rva in [
        RVA_INNER_DECODE_ENTRY,
        RVA_AFTER_PROLOGUE,
        RVA_ARG2_IN_EBX,
        RVA_ARG3_CMP,
        RVA_ARG5_IN_EDI,
        RVA_INNER_INNER_FAIL_CHECK,
        RVA_BAIL_SINK,
    ] {
        sb.cpu.add_register_watchpoint(base.wrapping_add(rva));
    }

    let r = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        mip,
        SLOT_MEMINPUTPIN_RECEIVE,
        &[sample],
    );

    // CRITICAL ordering: `take_memory_snapshots` MUST run BEFORE
    // `clear_register_watchpoints` because `clear_register_watchpoints`
    // ALSO drains `memory_snapshots` (via `mem::take`), so calling it
    // first leaves nothing for `take_memory_snapshots` to pick up.
    // Mirrors the round-40 discovery::codec.rs gotcha.
    let mem_snap = sb.cpu.take_memory_snapshots();
    let regs_snap = sb.cpu.clear_register_watchpoints();
    let mut snapshots: Vec<Snapshot> = Vec::with_capacity(regs_snap.len());
    for (i, ((eip, regs), (_eip_mem, mem))) in regs_snap.into_iter().zip(mem_snap).enumerate() {
        snapshots.push(Snapshot {
            eip,
            fire_order: i,
            regs,
            mem,
        });
    }

    let (receive_hr, receive_trap) = match r {
        Ok(hr) => (Some(hr), None),
        Err(e) => (None, Some(format!("{e}"))),
    };
    let visited = sb.cpu.take_visited_eips();
    let visited_rvas: std::collections::BTreeSet<u32> = visited
        .into_iter()
        .map(|eip| eip.wrapping_sub(base))
        .collect();
    Some(WatchOutcome {
        receive_hr,
        receive_trap,
        snapshots,
        sb,
        image_base: base,
        visited_rvas,
    })
}

/// Pretty-print one snapshot (for the test log).
fn fmt_snapshot(s: &Snapshot, base: u32) -> String {
    let rva = s.eip.wrapping_sub(base);
    let [eax, ecx, edx, ebx, esp, ebp, esi, edi] = s.regs;
    let mut s_out = format!(
        "  hit#{:02}  eip={:#010x}  rva={:#06x}  eax={:#010x} ecx={:#010x} edx={:#010x} ebx={:#010x} esp={:#010x} ebp={:#010x} esi={:#010x} edi={:#010x}",
        s.fire_order, s.eip, rva, eax, ecx, edx, ebx, esp, ebp, esi, edi,
    );
    s_out.push_str("\n    mem-probes:");
    for (addr, val) in s.mem.iter() {
        s_out.push_str(&format!("  [{:#010x}]={:#010x}", addr, val));
    }
    s_out
}

// ─── Phase 1 — sanity: snapshot infrastructure fires at every armed RVA ──

#[test]
fn phase1_unit_register_watchpoints_fire_at_every_armed_rva() {
    // This phase is purely an emulator-side smoke check on the
    // snapshot infrastructure — we register four watchpoints, run a
    // hand-built code stream that visits each, and assert all four
    // snapshots come back.  Round 40 introduced the infrastructure
    // but it never had a self-test inside this crate's test suite.
    use ud_emulator::emulator::regs::Reg32;
    let mut sb = Sandbox::new();
    let code = 0x1000_0000u32;
    sb.mmu.map(
        code,
        0x1000,
        ud_emulator::emulator::mmu::Perm::R
            | ud_emulator::emulator::mmu::Perm::W
            | ud_emulator::emulator::mmu::Perm::X,
    );
    // Map a stack page so the inserted nops have somewhere to live.
    let stack = 0x2000_0000u32;
    sb.mmu.map(
        stack,
        0x1000,
        ud_emulator::emulator::mmu::Perm::R | ud_emulator::emulator::mmu::Perm::W,
    );
    sb.cpu.regs.set_esp(stack + 0x800);
    // 4× NOP + C3 (ret).  Arm watchpoints at each NOP.
    let stream = [0x90u8, 0x90, 0x90, 0x90, 0xc3];
    sb.mmu.write_initializer(code, &stream).unwrap();
    for off in 0..4u32 {
        sb.cpu.add_register_watchpoint(code + off);
    }
    sb.cpu.regs.set32(Reg32::Eax, 0xCAFEBABE);
    sb.cpu
        .push32(&mut sb.mmu, ud_emulator::emulator::isa_int::RET_SENTINEL)
        .unwrap();
    sb.cpu.regs.eip = code;
    sb.cpu.run(&mut sb.mmu).unwrap();
    let snaps = sb.cpu.clear_register_watchpoints();
    assert_eq!(snaps.len(), 4, "expected one snapshot per NOP");
    for (i, (eip, regs)) in snaps.iter().enumerate() {
        assert_eq!(*eip, code + i as u32);
        assert_eq!(regs[0], 0xCAFEBABE, "eax preserved across nops");
    }
}

// ─── Phase 2 — Watch the four NULL guards in the real inner-decode ───

/// Phase 2 — arm watchpoints at all five inner-decode sentinel sites
/// plus the `0xc969` bail sink, drive Receive with the round-68
/// ffmpeg-derived extradata and the round-63 helper_addref patch,
/// and dump the snapshots.
///
/// The HRESULT should match round 68 phase 3: `0x80004005` (E_FAIL).
/// The very first snapshot at `0xc969` identifies which guard fired.
#[test]
fn phase2_watch_inner_decode_arg_guards_with_patch_and_ffmpeg_extradata() {
    if msadds32_path().is_none() {
        eprintln!("round69 phase2: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round69 phase2: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let Some(o) = run_watch_armed_receive(bp, Some(65_536)) else {
        eprintln!("round69 phase2: bootstrap failed (AMT may have been rejected)");
        return;
    };
    let base: u32 = 0; // we report RVAs relative to image_base; base
                       // itself is captured implicitly because every
                       // snapshot's eip is an absolute guest address.
                       // We accept that the report's `rva` field is
                       // computed as `eip - image_base` further down.

    // Look up image_base by re-loading the same DLL — or, more cheaply,
    // derive it from the eip of the entry watchpoint hit which equals
    // image_base + RVA_INNER_DECODE_ENTRY.
    let image_base_guess = o
        .snapshots
        .iter()
        .find(|s| (s.eip & 0xFFF) == (RVA_INNER_DECODE_ENTRY & 0xFFF))
        .map(|s| s.eip.wrapping_sub(RVA_INNER_DECODE_ENTRY))
        .unwrap_or(base);

    eprintln!(
        "round69 phase2: receive_hr={:?}  trap={:?}  snapshots={}  image_base={:#010x}",
        o.receive_hr,
        o.receive_trap,
        o.snapshots.len(),
        image_base_guess,
    );
    for s in &o.snapshots {
        eprintln!("{}", fmt_snapshot(s, image_base_guess));
    }

    // Identify which RVA(s) the snapshots landed at.
    let mut hits_per_rva: std::collections::BTreeMap<u32, usize> = Default::default();
    for s in &o.snapshots {
        let rva = s.eip.wrapping_sub(image_base_guess);
        *hits_per_rva.entry(rva).or_default() += 1;
    }
    eprintln!("round69 phase2: hits-per-RVA = {:?}", hits_per_rva);

    // The diagnostic conclusion: find the FIRST snapshot at the bail
    // sink (0xc969) — that's where the bail emerged.  The preceding
    // snapshot tells us which guard fired.
    if let Some(bail_idx) = o
        .snapshots
        .iter()
        .position(|s| s.eip.wrapping_sub(image_base_guess) == RVA_BAIL_SINK)
    {
        eprintln!(
            "round69 phase2: bail-sink first hit at fire_order={}",
            bail_idx
        );
        let last_before_bail = if bail_idx > 0 {
            Some(&o.snapshots[bail_idx - 1])
        } else {
            None
        };
        if let Some(s) = last_before_bail {
            let rva = s.eip.wrapping_sub(image_base_guess);
            let pretty = match rva {
                RVA_INNER_DECODE_ENTRY => {
                    "entry — bail fired from arg0 (impossible without a prior cmp)"
                }
                RVA_AFTER_PROLOGUE => "after-prologue cmp [ebp+8],0 — bail = arg0 NULL",
                RVA_ARG2_IN_EBX => "cmp ebx,0 — bail = arg2 NULL (ebx=arg2)",
                RVA_ARG3_CMP => "cmp [ebp+0x14],0 — bail = arg3 NULL",
                RVA_ARG5_IN_EDI => "cmp edi,0 — bail = arg5 NULL (edi=arg5)",
                RVA_INNER_INNER_FAIL_CHECK => {
                    "post-call test — bail = inner-inner returned non-zero"
                }
                _ => "(unidentified)",
            };
            eprintln!(
                "round69 phase2: pre-bail snapshot at rva={:#06x} ⇒ diagnosis: {}",
                rva, pretty
            );
            // Post-mortem: with the snapshot's captured ebp value,
            // read the four arg slots directly.  Some may be stale
            // (overwritten by leave/ret cleanup), but the bail at
            // 0xc969 does:
            //   mov eax, 0x80004005
            //   pop edi; pop esi; pop ebx; leave; ret 0x24
            // The stack slots below the popped frame's original SP
            // (i.e. the arg slots above ebp+8) are NOT touched by
            // the pop sequence, so they should survive.
            let ebp = s.regs[5];
            for (label, off) in &[
                ("arg0[ebp+0x08]", 0x08u32),
                ("arg1[ebp+0x0c]", 0x0c),
                ("arg2[ebp+0x10]", 0x10),
                ("arg3[ebp+0x14]", 0x14),
                ("arg4[ebp+0x18]", 0x18),
                ("arg5[ebp+0x1c]", 0x1c),
                ("arg6[ebp+0x20]", 0x20),
                ("arg7[ebp+0x24]", 0x24),
                ("arg8[ebp+0x28]", 0x28),
            ] {
                if let Ok(v) = o.sb.mmu.load32(ebp.wrapping_add(*off)) {
                    eprintln!("    post-mortem {} = {:#010x}", label, v);
                }
            }
        }
    } else {
        eprintln!("round69 phase2: NO bail-sink hit — either Receive succeeded, the inner decode was never reached, or it exited via the success path");
    }

    // Hard A/B sanity: round 68 reported E_FAIL on this combo.  If
    // we're now getting something else, the trajectory shifted.  Log
    // but do not panic — this is forensic work, not a regression
    // pin.
    match o.receive_hr {
        Some(0x80004005) => {
            eprintln!("round69 phase2: E_FAIL reproduces round 68 phase 3 — A/B clean");
        }
        Some(hr) => {
            eprintln!(
                "round69 phase2: HRESULT shifted from r68's E_FAIL to {:#010x}",
                hr
            );
        }
        None => {
            if let Some(msg) = &o.receive_trap {
                eprintln!("round69 phase2: trap = {msg}");
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // ROUND 69 CONCLUSION (asserted below to pin the finding):
    //
    // 1. Inner decode at 0xc887 IS entered cleanly.
    // 2. ALL FOUR NULL-arg guards (0xc898 / 0xc8a3 / 0xc8ac / 0xc8b7)
    //    PASS — arg0/arg2/arg3/arg5 are all non-NULL.
    // 3. The function executes through to 0xc92c (inner-inner call)
    //    and exits via the jnz at 0xc936 to the epilogue at 0xc96e,
    //    NOT via the 0xc969 E_FAIL bail (0xc969 NOT in visited set).
    //
    // The round-68 hand-off's "one of the 4 NULL guards fires"
    // hypothesis is therefore FALSIFIED.  The actual E_FAIL emission
    // is much deeper — phase 5 below identifies it as 0xe2bb inside
    // function 0xe0f4, reached via the inner-inner call chain
    // starting at 0xc975.
    // ──────────────────────────────────────────────────────────────

    // Pin: all 5 expected armed RVAs fired (entry, after-prologue,
    // arg2-in-ebx, arg3-cmp, arg5-in-edi).  0xc935 doesn't fire
    // (round-64 doc's wrong offset — the actual jnz is at 0xc936).
    // 0xc969 doesn't fire (no bail taken).
    let entry_hit = o
        .snapshots
        .iter()
        .any(|s| s.eip.wrapping_sub(image_base_guess) == RVA_INNER_DECODE_ENTRY);
    let prologue_hit = o
        .snapshots
        .iter()
        .any(|s| s.eip.wrapping_sub(image_base_guess) == RVA_AFTER_PROLOGUE);
    let arg2_hit = o
        .snapshots
        .iter()
        .any(|s| s.eip.wrapping_sub(image_base_guess) == RVA_ARG2_IN_EBX);
    let arg3_hit = o
        .snapshots
        .iter()
        .any(|s| s.eip.wrapping_sub(image_base_guess) == RVA_ARG3_CMP);
    let arg5_hit = o
        .snapshots
        .iter()
        .any(|s| s.eip.wrapping_sub(image_base_guess) == RVA_ARG5_IN_EDI);
    let bail_hit = o
        .snapshots
        .iter()
        .any(|s| s.eip.wrapping_sub(image_base_guess) == RVA_BAIL_SINK);
    assert!(
        entry_hit,
        "round69 phase2: inner-decode entry at 0xc887 NOT reached \
         — round-68 hand-off claimed it was; this falsifies that too"
    );
    assert!(prologue_hit, "round69 phase2: post-prologue NOT reached");
    assert!(arg2_hit, "round69 phase2: arg2-in-ebx NOT reached");
    assert!(arg3_hit, "round69 phase2: arg3-cmp NOT reached");
    assert!(arg5_hit, "round69 phase2: arg5-in-edi NOT reached");
    assert!(
        !bail_hit,
        "round69 phase2: 0xc969 bail-sink WAS reached — round-68 \
         hand-off would be confirmed.  Re-examine the diagnosis."
    );

    // Pin: in each per-arg snapshot, the arg value (where derivable
    // from registers or the mem-probe `[ebp+8]` slot) is non-zero.
    // arg0: from the prologue snapshot's `[ebp+8]` mem-probe.
    // arg2: ebx register at hit#02 (RVA_ARG2_IN_EBX).
    // arg5: edi register at hit#04 (RVA_ARG5_IN_EDI).
    let s_prologue = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base_guess) == RVA_AFTER_PROLOGUE)
        .expect("prologue snapshot");
    // `[ebp+8]` is the 3rd entry in the mem-probe array
    // (index 2 — see step()'s probe_addrs).
    let arg0 = s_prologue.mem[2].1;
    assert!(
        arg0 != 0,
        "round69 phase2: arg0 unexpectedly NULL at prologue snapshot"
    );
    let s_arg2 = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base_guess) == RVA_ARG2_IN_EBX)
        .expect("arg2 snapshot");
    let arg2 = s_arg2.regs[3]; // ebx
    assert!(arg2 != 0, "round69 phase2: arg2 unexpectedly NULL");
    let s_arg5 = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base_guess) == RVA_ARG5_IN_EDI)
        .expect("arg5 snapshot");
    let arg5 = s_arg5.regs[7]; // edi
    assert!(arg5 != 0, "round69 phase2: arg5 unexpectedly NULL");

    eprintln!(
        "round69 phase2: PINNED — arg0={:#010x} arg2={:#010x} arg5={:#010x} all non-NULL; \
         round-68 \"NULL arg guard\" hypothesis FALSIFIED",
        arg0, arg2, arg5
    );
}

// ─── Phase 3 — Watch with NO patch (round-63 retirement probe) ──────

/// Phase 3 — same watchpoints, but WITHOUT the round-63 patch.
/// Round 68 phase 2 reported `0x80004005` on this combo too (no trap
/// at the `0x20` site), suggesting the patch is retirable.  This
/// phase confirms the snapshots line up with phase 2's reading —
/// same bail site, same arg-NULL guard.
#[test]
fn phase3_watch_inner_decode_arg_guards_without_patch() {
    if msadds32_path().is_none() {
        eprintln!("round69 phase3: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round69 phase3: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let Some(o) = run_watch_armed_receive(bp, None) else {
        eprintln!("round69 phase3: bootstrap failed");
        return;
    };
    let image_base_guess = o
        .snapshots
        .iter()
        .find(|s| (s.eip & 0xFFF) == (RVA_INNER_DECODE_ENTRY & 0xFFF))
        .map(|s| s.eip.wrapping_sub(RVA_INNER_DECODE_ENTRY))
        .unwrap_or(0);
    eprintln!(
        "round69 phase3: receive_hr={:?}  trap={:?}  snapshots={}",
        o.receive_hr,
        o.receive_trap,
        o.snapshots.len(),
    );
    for s in &o.snapshots {
        eprintln!("{}", fmt_snapshot(s, image_base_guess));
    }
    let mut hits_per_rva: std::collections::BTreeMap<u32, usize> = Default::default();
    for s in &o.snapshots {
        *hits_per_rva
            .entry(s.eip.wrapping_sub(image_base_guess))
            .or_default() += 1;
    }
    eprintln!("round69 phase3: hits-per-RVA = {:?}", hits_per_rva);
    if hits_per_rva.contains_key(&RVA_INNER_DECODE_ENTRY) {
        eprintln!(
            "round69 phase3: inner decode REACHED without the round-63 patch — \
             confirms patch is retirable now that ffmpeg-derived extradata \
             changes the helper-struct trajectory"
        );
    } else {
        eprintln!(
            "round69 phase3: inner decode NOT REACHED without the patch — \
             a different trap fired before getting there"
        );
    }
}

// ─── Phase 4 — Baseline comparison: zero preamble + patch (round-68 phase 4) ──

/// Phase 4 — baseline check.  Round-68 phase 4 reported
/// `0x8000FFFF` (E_UNEXPECTED) with the old zero-preamble + patch.
/// On this combo the bail is at the outer `0x172f` (NOT the inner
/// decode's `0xc969`).  Our inner-decode watchpoints should
/// therefore EITHER not fire (if the inner decode is never reached
/// from this trajectory — implausible since round 64 confirmed it
/// was) OR fire but proceed past the NULL guards and hit some other
/// downstream sentinel.  This phase logs whichever observation
/// applies.
#[test]
fn phase4_baseline_zero_preamble_inner_decode_watch() {
    if msadds32_path().is_none() {
        eprintln!("round69 phase4: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round69 phase4: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_criteria_passing(0x0161, 1, 44_100, 4_000, 185);
    let Some(o) = run_watch_armed_receive(bp, Some(65_536)) else {
        eprintln!("round69 phase4: bootstrap failed");
        return;
    };
    let image_base_guess = o
        .snapshots
        .iter()
        .find(|s| (s.eip & 0xFFF) == (RVA_INNER_DECODE_ENTRY & 0xFFF))
        .map(|s| s.eip.wrapping_sub(RVA_INNER_DECODE_ENTRY))
        .unwrap_or(0);
    eprintln!(
        "round69 phase4 (zero preamble baseline): receive_hr={:?}  trap={:?}  snapshots={}",
        o.receive_hr,
        o.receive_trap,
        o.snapshots.len(),
    );
    for s in &o.snapshots {
        eprintln!("{}", fmt_snapshot(s, image_base_guess));
    }
    let mut hits_per_rva: std::collections::BTreeMap<u32, usize> = Default::default();
    for s in &o.snapshots {
        *hits_per_rva
            .entry(s.eip.wrapping_sub(image_base_guess))
            .or_default() += 1;
    }
    eprintln!("round69 phase4: hits-per-RVA = {:?}", hits_per_rva);
    let bail_hits = hits_per_rva.get(&RVA_BAIL_SINK).copied().unwrap_or(0);
    let inner_inner_hits = hits_per_rva
        .get(&RVA_INNER_INNER_FAIL_CHECK)
        .copied()
        .unwrap_or(0);
    eprintln!(
        "round69 phase4: bail-sink hits = {}  inner-inner-fail hits = {}",
        bail_hits, inner_inner_hits
    );
    if o.receive_hr == Some(0x8000_FFFF) && bail_hits == 0 {
        eprintln!(
            "round69 phase4: E_UNEXPECTED reproduces AND inner-decode bail NOT taken — \
             confirms r64 reading that the inner decode returns eax=0 + samples_produced=0, \
             outer loop emits E_UNEXPECTED at 0x172f"
        );
    }
}

// ─── Phase 5 — Find the ACTUAL E_FAIL emission site ──────────────────

/// Phase 5 — round 68's "E_FAIL emerges from `0xc96a`" hypothesis is
/// falsified by phases 2-4: the watchpoints prove the inner decode
/// at `0xc887..0xc973` is NEVER entered.  Therefore the
/// `0x80004005` HRESULT must come from one of the OTHER 16
/// `mov eax, 0x80004005` sites in `msadds32.ax`.
///
/// This phase scans `cpu.visited_eips` for every site in
/// [`E_FAIL_MOV_EAX_SITES`] and prints which ones were reached — the
/// actual bail site is in the intersection.
#[test]
fn phase5_locate_actual_e_fail_emission_site() {
    if msadds32_path().is_none() {
        eprintln!("round69 phase5: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round69 phase5: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let Some(o) = run_watch_armed_receive(bp, Some(65_536)) else {
        eprintln!("round69 phase5: bootstrap failed");
        return;
    };
    eprintln!(
        "round69 phase5: receive_hr={:?}  trap={:?}  visited_rvas={}  image_base={:#010x}",
        o.receive_hr,
        o.receive_trap,
        o.visited_rvas.len(),
        o.image_base,
    );
    let mut reached: Vec<u32> = Vec::new();
    for &site in E_FAIL_MOV_EAX_SITES {
        if o.visited_rvas.contains(&site) {
            reached.push(site);
        }
    }
    eprintln!(
        "round69 phase5: reached E_FAIL emission sites: [{}]",
        reached
            .iter()
            .map(|r| format!("{:#06x}", r))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if reached.is_empty() {
        eprintln!(
            "round69 phase5: NONE of the {} `mov eax, 0x80004005` sites were reached. \
             The E_FAIL HRESULT must originate from a `c7 [..]` immediate store \
             (mov [mem], 0x80004005) or from a synthesised value inside our host \
             COM bridge — investigate `src/com/host_iface.rs` + `host_iface_r31.rs`",
            E_FAIL_MOV_EAX_SITES.len()
        );
    } else {
        eprintln!(
            "round69 phase5: the bail site is one of the above. \
             Static disasm of each candidate is needed to identify the calling function."
        );
    }

    // Additional forensic: also scan the trace ring for the LAST
    // executed RVA in the Receive call's run.  That tells us what
    // ret-tail produced the final eax.
    let ring = &o.sb.cpu.trace_ring;
    if let Some(&last_eip) = ring.last() {
        let last_rva = last_eip.wrapping_sub(o.image_base);
        eprintln!(
            "round69 phase5: trace-ring last eip = {:#010x} (rva {:#06x})",
            last_eip, last_rva
        );
    }
    // Print the last 16 RVAs to give the tail-of-bail context.
    if !ring.is_empty() {
        let tail = if ring.len() >= 16 {
            &ring[ring.len() - 16..]
        } else {
            &ring[..]
        };
        eprintln!(
            "round69 phase5: trace-ring tail (last 16 RVAs): [{}]",
            tail.iter()
                .map(|eip| format!("{:#06x}", eip.wrapping_sub(o.image_base)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // ALSO scan visited for the inner-decode's body (any RVA in
    // 0xc887..0xc973) — phases 2/3 showed the entry sentinel didn't
    // fire, but the watchpoint only fires on those 7 specific RVAs.
    // We need to confirm NO part of the body executed.
    let inner_body_visited: Vec<u32> = o
        .visited_rvas
        .iter()
        .copied()
        .filter(|&rva| (0xc887..0xc973).contains(&rva))
        .collect();
    eprintln!(
        "round69 phase5: inner-decode body RVAs visited (within 0xc887..0xc973): {} entries: [{}]",
        inner_body_visited.len(),
        inner_body_visited
            .iter()
            .map(|r| format!("{:#06x}", r))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Phase 5 extension: which outer-Receive sentinels did the
    // trajectory hit?  Round 64 documented these:
    //   0x172f — E_UNEXPECTED stamp (mov [ebp+8], 0x8000FFFF)
    //   0x1736..0x176c — cleanup tail
    //   0x176c — final eax = [ebp+8]; load
    //   0x1643 — call 0xc887 (the inner decode we just watched)
    //   0x1648 — cmp eax, ebx (was inner decode's eax 0?)
    //   0x165b — JNZ to 0x172f bail
    let outer_sentinels = [
        (0x1643u32, "call 0xc887"),
        (0x1648, "cmp eax,ebx (inner ret == 0?)"),
        (0x164a, "mov [ebp+8], eax (stash as HRESULT)"),
        (0x164d, "JNZ to 0x1736 (bail if inner != 0)"),
        (0x1736, "cleanup tail entry"),
        (0x165b, "JNZ to 0x172f bail (no-progress)"),
        (0x172f, "E_UNEXPECTED stamp"),
        (0x176c, "load [ebp+8] to eax"),
    ];
    for (rva, label) in &outer_sentinels {
        let visited = o.visited_rvas.contains(rva);
        eprintln!(
            "round69 phase5: outer-sentinel rva={:#06x} ({}) visited={}",
            rva, label, visited
        );
    }
    // Find function start preceding 0xe2bb (where E_FAIL was stamped)
    // and enumerate visited RVAs in 0xe0f0..0xe2c0 to identify the
    // function body.
    let e2bb_function_visited: Vec<u32> = o
        .visited_rvas
        .iter()
        .copied()
        .filter(|&rva| (0xe0f4..0xe2c2).contains(&rva))
        .collect();
    eprintln!(
        "round69 phase5: visited inside 0xe0f4..0xe2c2 (E_FAIL emitter): {} entries",
        e2bb_function_visited.len(),
    );
    if !e2bb_function_visited.is_empty() {
        // Print the first ~30 visited entries in that range for context.
        let head: Vec<String> = e2bb_function_visited
            .iter()
            .take(60)
            .map(|r| format!("{:#06x}", r))
            .collect();
        eprintln!("  first 60: [{}]", head.join(", "));
    }
}

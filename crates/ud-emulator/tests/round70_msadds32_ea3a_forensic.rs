//! Round 70 — trace into `0xea3a` (the call from `0xe13c` inside
//! `0xe0f4`) and characterise WHY it returns non-zero, which steers
//! `0xe0f4` toward the `0x80004005` E_FAIL stamp at `0xe2bb`.
//!
//! Round 69 (`tests/round69_msadds32_inner_decode_watch.rs` +
//! `docs/codec/msadds32-receive-e-unexpected.md` §"Round 69") proved
//! the four NULL-arg guards at `0xc887..0xc8b7` ALL pass and the
//! E_FAIL bail at `0xc969` is NEVER reached.  The actual emission is
//! at RVA `0xe2bb` inside function `0xe0f4`, reached via:
//!
//! ```text
//!   Receive (0x1501)
//!     → call 0xc887 (inner decode)
//!       → call 0xc975 (inner-inner)
//!         → ...
//!           → call 0xe0f4
//!             → call 0xea3a  (RVA 0xe13c, bail-emitter for this round)
//! ```
//!
//! Round 70's job is to arm `add_register_watchpoint` snapshots
//! around `0xea3a` + the post-call test at `0xe141..0xe148` inside
//! `0xe0f4`, characterise WHY the post-call check at `0xe141: cmp
//! [ebx+0x468], 0` (where `ebx = outer_this`) is non-zero, and
//! capture concrete register state at the conditional branches.
//!
//! ## Disassembly of `0xea3a` (clean-room from raw `msadds32.ax` bytes)
//!
//! ```text
//! 0xea3a: 55                    push ebp
//! 0xea3b: 8b ec                 mov ebp, esp
//! 0xea3d: 51                    push ecx              ; alloc 1 dword local
//! 0xea3e: 56                    push esi
//! 0xea3f: 57                    push edi
//! 0xea40: 8b f1                 mov esi, ecx          ; __fastcall: ECX = this
//! 0xea42: 33 ff                 xor edi, edi          ; edi = 0
//! 0xea44: 39 7e 08              cmp [esi+8], edi      ; this->field_8 == 0 ?
//! 0xea47: 75 04                 jnz +4 → 0xea4d       ; non-zero: continue
//! 0xea49: 33 c0                 xor eax, eax          ; zero: return 0
//! 0xea4b: eb 65                 jmp +0x65 → 0xeab2    ; epilogue
//! 0xea4d: 53                    push ebx              ; save ebx
//! 0xea4e: 8b 5e 14               mov ebx, [esi+0x14]   ; ebx = this->field_14
//! 0xea51: 8b 46 18               mov eax, [esi+0x18]   ; eax = this->field_18
//! 0xea54: 8b 4d 08               mov ecx, [ebp+8]      ; ecx = arg1 (= outer_this+0x458)
//! 0xea57: ff 34 07              push [edi+eax]        ; edi=0, push [eax]
//! 0xea5a: e8 c9 fe ff ff        call 0xe928           ; helper A
//! 0xea5f: 83 7c c3 04 00         cmp [ebx+eax*8+4], 0 ; check sub-table entry
//! 0xea64: 8d 0c c3               lea ecx, [ebx+eax*8] ; ecx = entry pointer
//! 0xea67: 89 4d fc               mov [ebp-4], ecx     ; stash
//! 0xea6a: 75 2c                  jnz +0x2c → 0xea98   ; cached path
//! 0xea6c: 8b 46 18               mov eax, [esi+0x18]
//! 0xea6f: 8b 4d 08               mov ecx, [ebp+8]
//! 0xea72: ff 34 07               push [edi+eax]
//! 0xea75: e8 2f ff ff ff         call 0xe9a9          ; helper B (slow path)
//! 0xea7a: 8b 46 18               mov eax, [esi+0x18]
//! 0xea7d: 8b 0c 07               mov ecx, [edi+eax]
//! 0xea80: 8b 45 0c               mov eax, [ebp+0xc]   ; arg2 (= outer's esi)
//! 0xea83: 01 08                  add [eax], ecx       ; *arg2 += [edi+arg1->field_18]
//! 0xea85: 8b 45 fc               mov eax, [ebp-4]
//! 0xea88: 8b 00                  mov eax, [eax]       ; eax = entry's field_0 = inner ret
//! 0xea8a: 8b f8                  mov edi, eax
//! 0xea8c: 8b 46 18               mov eax, [esi+0x18]
//! 0xea8f: c1 e7 03               shl edi, 3           ; edi *= 8
//! 0xea92: 8b 5c 07 04             mov ebx, [edi+eax+4] ; ebx = next entry
//! 0xea96: eb b9                   jmp -0x47 → 0xea51   ; loop back
//! 0xea98: ff 74 c3 04             push [ebx+eax*8+4]   ; cached entry's field_4
//! 0xea9c: 8b 4d 08                mov ecx, [ebp+8]
//! 0xea9f: 8d 1c c3                lea ebx, [ebx+eax*8] ; ebx = entry pointer
//! 0xeaa2: e8 02 ff ff ff          call 0xe9a9          ; helper B
//! 0xeaa7: 8b 45 0c                mov eax, [ebp+0xc]
//! 0xeaaa: 8b 4b 04                mov ecx, [ebx+4]     ; ecx = entry->field_4
//! 0xeaad: 01 08                   add [eax], ecx       ; *arg2 += entry->field_4
//! 0xeaaf: 8b 03                   mov eax, [ebx]       ; eax = entry->field_0 (return)
//! 0xeab1: 5b                     pop ebx
//! 0xeab2: 5f                     pop edi
//! 0xeab3: 5e                     pop esi
//! 0xeab4: c9                     leave
//! 0xeab5: c2 08 00               ret 8                ; (eax, esi) caller pop
//! ```
//!
//! Note `0xea3a` writes to `*arg2` (the outer esi value, which was
//! `[outer_this->ebp+0x14]` arg3) via `add [eax], ecx` at `0xea83` /
//! `0xeaad`.  Round-69 noted that the field `[outer_this+0x468]` is
//! tested at `0xe141` after the call returns.  The call itself
//! does NOT write to `[ebx+0x468]` directly — it writes to
//! `*arg2 = outer_esi` (a stack slot, NOT the helper-state field at
//! `outer_this+0x468`).  So `[outer_this+0x468]` is set by ONE OF:
//!
//!   * an earlier path inside `0xe0f4` itself (before the `0xe13c` call)
//!   * one of the helper calls (`0xe928` or `0xe9a9`) called transitively
//!     from `0xea3a`
//!   * an unrelated codec path (Pause / Run / ReceiveConnection)
//!
//! Round 70 captures the value of `[ebx+0x468]` at three checkpoints
//! to disambiguate:
//!
//!   * BEFORE the `0xe13c` call (snapshot at `0xe13c` itself; `ebx` is
//!     `outer_this` — the value of `[ebx+0x468]` here is the
//!     pre-call setting)
//!   * AFTER the `0xe13c` call (snapshot at `0xe141`; same ebx)
//!   * at the bail jnz `0xe148`
//!
//! The DELTA between the two snapshots tells us whether `0xea3a`
//! (or any of its callees) set the field, OR whether it was already
//! non-zero before the call (set by an upstream path).
//!
//! ## References (clean-room only)
//!
//!  * Intel SDM Vol. 2 — opcode encoding, ModR/M, SIB.
//!  * MSDN — `IMemInputPin::Receive`, COM HRESULT semantics
//!    (`E_FAIL = 0x80004005`).
//!  * Raw bytes of `msadds32.ax` from
//!    `docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/`.
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
    clippy::needless_for_each,
    clippy::nonminimal_bool,
    clippy::if_not_else
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

// ── Sentinel RVAs ──────────────────────────────────────────────────────

/// `0xea3a` — function entry; ECX = this, args on stack.
const RVA_EA3A_ENTRY: u32 = 0xea3a;
/// `0xea44` — `cmp [esi+8], edi` (esi = this; edi = 0).
const RVA_EA44_THIS8_CMP: u32 = 0xea44;
/// `0xea47` — `jnz +4 → 0xea4d`.
const RVA_EA47_THIS8_JNZ: u32 = 0xea47;
/// `0xea4b` — `jmp epilogue` (only reached if `this->field_8 == 0`).
const RVA_EA4B_EARLY_RET: u32 = 0xea4b;
/// `0xea4d` — past the early-return guard; `push ebx` — `ebx`
/// will then load `this->field_14`.
const RVA_EA4D_PAST_GUARD: u32 = 0xea4d;
/// `0xea5a` — `call 0xe928` (helper A).
const RVA_EA5A_CALL_HELPER_A: u32 = 0xea5a;
/// `0xea6a` — `jnz +0x2c → 0xea98` (cached-path branch).
const RVA_EA6A_CACHED_BRANCH: u32 = 0xea6a;
/// `0xea75` — `call 0xe9a9` (helper B, slow path).
const RVA_EA75_CALL_HELPER_B_SLOW: u32 = 0xea75;
/// `0xea96` — `jmp -0x47 → 0xea51` (loop back).
const RVA_EA96_LOOP_BACK: u32 = 0xea96;
/// `0xeaa2` — `call 0xe9a9` (helper B, cached path).
const RVA_EAA2_CALL_HELPER_B_CACHED: u32 = 0xeaa2;
/// `0xeaaf` — `mov eax, [ebx]` — eax loaded with the return
/// value (after the loop or cached-path success).
const RVA_EAAF_LOAD_RETURN: u32 = 0xeaaf;
/// `0xeab1` — `pop ebx` — start of the epilogue (eax == return).
const RVA_EAB1_EPILOGUE: u32 = 0xeab1;

// Caller-side sentinels inside `0xe0f4`.
/// `0xe13c` — `call 0xea3a` site (BEFORE the call: ebx = outer_this).
const RVA_E13C_CALL_EA3A: u32 = 0xe13c;
/// `0xe141` — `cmp [ebx+0x468], 0` (AFTER the call: same ebx).
const RVA_E141_POST_CALL_CMP: u32 = 0xe141;
/// `0xe148` — `jnz +0x16d → 0xe2bb` (one of NINE bail JNZs that
/// can reach the E_FAIL stamp).  Round 70 phase 4 enumerates the
/// other eight, identified by a clean-room linear scan of the
/// `.text` section for jumps targeting RVA `0xe2bb`.
const RVA_E148_BAIL_JNZ: u32 = 0xe148;
/// `0xe2bb` — the `mov eax, 0x80004005` E_FAIL stamp itself.
const RVA_E2BB_E_FAIL_STAMP: u32 = 0xe2bb;

/// Every JNE/JNZ/JL/JGE/JS/JNC site inside `0xe0f4`'s body that
/// targets the `0xe2bb` E_FAIL stamp.  Identified by a linear-byte
/// scan against the raw image of `msadds32.ax`:
///
/// ```sh
/// python3 -c "
/// import struct
/// data = open('msadds32.ax','rb').read()
/// target = 0xe2bb
/// for i in range(len(data) - 5):
///     b = data[i]
///     if b == 0x0f and i + 5 < len(data):
///         b2 = data[i+1]
///         if 0x80 <= b2 <= 0x8f:
///             rel = struct.unpack('<i', bytes(data[i+2:i+6]))[0]
///             if i + 6 + rel == target:
///                 print(hex(i), hex(b2-0x80))
///     if 0x70 <= b <= 0x7f or b == 0xeb:
///         rel = data[i+1]
///         if rel >= 0x80: rel -= 0x100
///         if i + 2 + rel == target:
///             print(hex(i), hex(b-0x70))
/// "
/// ```
///
/// The 9 sites observed (with the Jcc condition codes):
///
/// | RVA      | bytes         | mnemonic                                          |
/// |----------|---------------|---------------------------------------------------|
/// | `0xe148` | `0f 85 ...`   | `jne` (after `cmp [ebx+0x468], 0`)               |
/// | `0xe173` | `0f 85 ...`   | `jne` (after a subsequent test)                  |
/// | `0xe19e` | `0f 85 ...`   | `jne`                                             |
/// | `0xe1a6` | `0f 8c ...`   | `jl`                                              |
/// | `0xe1c5` | `0f 85 ...`   | `jne`                                             |
/// | `0xe205` | `0f 8d ...`   | `jge`  (`jge` was `0xd`)                          |
/// | `0xe22b` | `0f 8c ...`   | `jl`                                              |
/// | `0xe266` | `7x ...`      | rel8 jcc                                          |
/// | `0xe282` | `7x ...`      | rel8 jcc                                          |
const RVA_E0F4_BAIL_JCCS: &[u32] = &[
    0xe148, 0xe173, 0xe19e, 0xe1a6, 0xe1c5, 0xe205, 0xe22b, 0xe266, 0xe282,
];

// ── Bootstrap (mirrors r68/r69) ─────────────────────────────────────────

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
    // Round 70: ample snapshot cap — the conditional branches inside
    // `0xea3a` may fire several times if the loop at `0xea51..0xea96`
    // iterates, plus `0xea3a` itself may be invoked more than once
    // across the Receive chain.
    sb.cpu.register_snapshots_cap = 1024;
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

// ── Snapshot capture ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Snapshot {
    eip: u32,
    fire_order: usize,
    /// eax, ecx, edx, ebx, esp, ebp, esi, edi.
    regs: [u32; 8],
    /// `[esp]`, `[esp+4]`, `[ebp+8]`, `[ebp-0x50]` — fixed by the
    /// emulator's `step()`; for `0xea3a` `[esp]` is the return-IP
    /// (the post-call EIP at `0xe141`), `[esp+4]` is arg1
    /// (`outer_this+0x458`), `[esp+8]` is arg2 (`outer_esi`).
    mem: [(u32, u32); 4],
}

struct WatchOutcome {
    receive_hr: Option<u32>,
    receive_trap: Option<String>,
    snapshots: Vec<Snapshot>,
    sb: Sandbox,
    image_base: u32,
    visited_rvas: std::collections::BTreeSet<u32>,
}

fn run_watch_armed_receive(
    bp: AmtBlueprint,
    apply_helper_addref_patch: Option<u32>,
    arm_rvas: &[u32],
) -> Option<WatchOutcome> {
    let (mut sb, img, _unk, filter) = bootstrap_filter()?;
    let base = img.image_base;

    if let Some(v) = apply_helper_addref_patch {
        sb.msadds32_patch_helper_addref(base, v).ok()?;
    }

    // Arm the watchpoints AFTER patch-time.
    for &rva in arm_rvas {
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
            "round70: ReceiveConnection returned {r_rc:#010x} — \
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

    // Clear pre-Receive snapshots / visited so only the Receive run lands.
    sb.cpu.trace_ring.clear();
    sb.cpu.visited_eips.clear();
    let _ = sb.cpu.clear_register_watchpoints();
    let _ = sb.cpu.take_memory_snapshots();
    for &rva in arm_rvas {
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

    // CRITICAL ordering: take_memory_snapshots BEFORE
    // clear_register_watchpoints (round-69 + round-40 gotcha).
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

fn fmt_snapshot(s: &Snapshot, base: u32) -> String {
    let rva = s.eip.wrapping_sub(base);
    let [eax, ecx, edx, ebx, esp, ebp, esi, edi] = s.regs;
    let mut s_out = format!(
        "  hit#{:03}  eip={:#010x}  rva={:#06x}  eax={:#010x} ecx={:#010x} edx={:#010x} ebx={:#010x} esp={:#010x} ebp={:#010x} esi={:#010x} edi={:#010x}",
        s.fire_order, s.eip, rva, eax, ecx, edx, ebx, esp, ebp, esi, edi,
    );
    s_out.push_str("\n    mem-probes:");
    for (addr, val) in s.mem.iter() {
        s_out.push_str(&format!("  [{:#010x}]={:#010x}", addr, val));
    }
    s_out
}

// ── Phase 1 — confirm 0xea3a is reached + characterise its branches ───

/// Phase 1 — arm watchpoints at every conditional inside `0xea3a`
/// plus the caller's bail-predicate test.  The test runs WITHOUT the
/// round-63 helper_addref patch (round 69 confirmed the patch is
/// retirable on the ffmpeg-extradata path; this phase re-verifies
/// that finding by demonstrating `0xea3a` is still reached).
#[test]
fn phase1_walk_ea3a_branches_and_caller_bail_predicate() {
    if msadds32_path().is_none() {
        eprintln!("round70 phase1: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round70 phase1: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let arm = [
        RVA_EA3A_ENTRY,
        RVA_EA44_THIS8_CMP,
        RVA_EA47_THIS8_JNZ,
        RVA_EA4B_EARLY_RET,
        RVA_EA4D_PAST_GUARD,
        RVA_EA5A_CALL_HELPER_A,
        RVA_EA6A_CACHED_BRANCH,
        RVA_EA75_CALL_HELPER_B_SLOW,
        RVA_EA96_LOOP_BACK,
        RVA_EAA2_CALL_HELPER_B_CACHED,
        RVA_EAAF_LOAD_RETURN,
        RVA_EAB1_EPILOGUE,
        RVA_E13C_CALL_EA3A,
        RVA_E141_POST_CALL_CMP,
        RVA_E148_BAIL_JNZ,
        RVA_E2BB_E_FAIL_STAMP,
    ];
    // Round 70's headline retirement check: NO patch.  Round 69 phase
    // 3 already confirmed this path reaches the inner decode.
    let Some(o) = run_watch_armed_receive(bp, None, &arm) else {
        eprintln!("round70 phase1: bootstrap failed");
        return;
    };

    // Compute image_base from the entry sentinel hit (any sentinel
    // would do; we pick the one most likely to fire first).
    let image_base = o
        .snapshots
        .iter()
        .find(|s| (s.eip & 0xFFF) == (RVA_EA3A_ENTRY & 0xFFF))
        .map(|s| s.eip.wrapping_sub(RVA_EA3A_ENTRY))
        .or_else(|| {
            o.snapshots
                .iter()
                .find(|s| (s.eip & 0xFFF) == (RVA_E13C_CALL_EA3A & 0xFFF))
                .map(|s| s.eip.wrapping_sub(RVA_E13C_CALL_EA3A))
        })
        .unwrap_or(o.image_base);

    eprintln!(
        "round70 phase1: receive_hr={:?}  trap={:?}  snapshots={}  image_base={:#010x}",
        o.receive_hr,
        o.receive_trap,
        o.snapshots.len(),
        image_base,
    );

    // Per-RVA hit count.
    let mut hits_per_rva: std::collections::BTreeMap<u32, usize> = Default::default();
    for s in &o.snapshots {
        let rva = s.eip.wrapping_sub(image_base);
        *hits_per_rva.entry(rva).or_default() += 1;
    }
    eprintln!("round70 phase1: hits-per-RVA = {:?}", hits_per_rva);

    // Print the FIRST snapshot at every armed RVA — that's the
    // one we want to characterise.  For loop-back sites (0xea96)
    // we also report the last hit so we can see whether the
    // exit path was taken in the final iteration.
    for &rva in &arm {
        let first = o
            .snapshots
            .iter()
            .find(|s| s.eip.wrapping_sub(image_base) == rva);
        let last = o
            .snapshots
            .iter()
            .rev()
            .find(|s| s.eip.wrapping_sub(image_base) == rva);
        if let Some(s) = first {
            eprintln!(
                "round70 phase1: FIRST snapshot at rva={:#06x}\n{}",
                rva,
                fmt_snapshot(s, image_base)
            );
        }
        if let Some(s) = last {
            if first.map(|f| f.fire_order) != Some(s.fire_order) {
                eprintln!(
                    "round70 phase1: LAST  snapshot at rva={:#06x}\n{}",
                    rva,
                    fmt_snapshot(s, image_base)
                );
            }
        }
    }

    // ── Headline: characterise the `0xea44` conditional ─────────────
    //
    // The first hit at `0xea44` shows ESI = this.  Post-mortem read
    // `[esi+8]` to get the value being compared against EDI = 0.
    if let Some(s) = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base) == RVA_EA44_THIS8_CMP)
    {
        let esi = s.regs[6];
        let cmp_val = o.sb.mmu.load32(esi.wrapping_add(8)).unwrap_or(0xDEAD_BEEF);
        let jnz_taken = cmp_val != 0;
        eprintln!(
            "round70 phase1: HEADLINE — at rva=0xea44 (cmp [esi+8],edi)  esi={:#010x}  [esi+8]={:#010x}  jnz_taken={}",
            esi, cmp_val, jnz_taken
        );
        if !jnz_taken {
            eprintln!(
                "round70 phase1: → 0xea3a returns 0 IMMEDIATELY (early-return path); the post-call non-zero must be set elsewhere"
            );
        } else {
            eprintln!(
                "round70 phase1: → 0xea3a continues past the early-return guard into the helper-call body"
            );
        }
    }

    // ── Headline: characterise the post-call bail predicate ────────
    //
    // The snapshot at `0xe141` captures `ebx = outer_this`.  The
    // value `[ebx+0x468]` is what `0xe148` compares against zero to
    // bail to the E_FAIL stamp at `0xe2bb`.
    if let Some(s) = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base) == RVA_E141_POST_CALL_CMP)
    {
        let ebx = s.regs[3];
        let post_call_field =
            o.sb.mmu
                .load32(ebx.wrapping_add(0x468))
                .unwrap_or(0xDEAD_BEEF);
        eprintln!(
            "round70 phase1: HEADLINE — at rva=0xe141 (cmp [ebx+0x468],0)  ebx={:#010x}  [ebx+0x468]={:#010x}  bail_taken={}",
            ebx,
            post_call_field,
            post_call_field != 0
        );
    }

    // ── Headline: was 0xea3a even reached? ────────────────────────
    let ea3a_reached = o.visited_rvas.contains(&RVA_EA3A_ENTRY);
    let ea4b_reached = o.visited_rvas.contains(&RVA_EA4B_EARLY_RET);
    let eaaf_reached = o.visited_rvas.contains(&RVA_EAAF_LOAD_RETURN);
    let e141_reached = o.visited_rvas.contains(&RVA_E141_POST_CALL_CMP);
    let e2bb_reached = o.visited_rvas.contains(&RVA_E2BB_E_FAIL_STAMP);
    eprintln!(
        "round70 phase1: REACHED — 0xea3a={} 0xea4b(early-ret)={} 0xeaaf(load-ret)={} 0xe141(post-call-cmp)={} 0xe2bb(E_FAIL stamp)={}",
        ea3a_reached, ea4b_reached, eaaf_reached, e141_reached, e2bb_reached
    );

    // ── Round-69 retirement check verification ──────────────────────
    //
    // Round 69 phase 3 reported the inner decode at 0xc887 IS
    // reached without the round-63 patch.  Round 70 piece-A goal 3
    // re-verifies this finding still holds: assert 0xea3a is
    // reachable WITHOUT the patch.  If it isn't, the patch is NOT
    // retirable (some other init path needs work).
    if ea3a_reached {
        eprintln!(
            "round70 phase1: helper_addref_patch RETIREMENT CONFIRMED — \
             0xea3a IS reached on the no-patch trajectory."
        );
    } else {
        eprintln!(
            "round70 phase1: helper_addref_patch RETIREMENT REGRESSED — \
             0xea3a NOT reached without the patch.  A different init \
             path interferes; do NOT remove the patch from prior tests."
        );
    }

    // Pin: 0xea3a is reached at all.  This is the round's structural
    // reachability test — failure here means the trajectory diverged
    // before reaching the deeper bail site and the rest of the
    // analysis is moot.
    assert!(
        ea3a_reached,
        "round70 phase1: 0xea3a NOT reached — round 69's reachability \
         finding regressed.  Re-run round 69 phase 3 to triage."
    );

    // Pin: the post-call comparison site at 0xe141 IS reached, AND
    // the E_FAIL stamp at 0xe2bb IS reached — these are the two
    // structural anchors for the round 71 hand-off.
    assert!(
        e141_reached,
        "round70 phase1: 0xe141 (post-call cmp) NOT reached — \
         the trajectory diverged before reaching the bail predicate"
    );
    assert!(
        e2bb_reached,
        "round70 phase1: 0xe2bb (E_FAIL stamp) NOT reached — \
         the bail predicate at 0xe148 did not steer to E_FAIL on \
         this run.  Did the HRESULT shift?"
    );
}

// ── Phase 2 — A/B with patch vs without patch (retirement re-confirmation) ──

/// Phase 2 — re-verify that the round-63 `helper_addref_patch` is
/// retirable by running the same arm-set twice (with patch / without
/// patch) and comparing the per-RVA hit counts at the deeper-call
/// sites.  The expected outcome: identical reach-set (every armed
/// site present in BOTH runs).  If patching changes the reach-set,
/// the patch is NOT yet retirable on the ffmpeg-extradata path.
#[test]
fn phase2_helper_addref_patch_retirement_ab_check() {
    if msadds32_path().is_none() {
        eprintln!("round70 phase2: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round70 phase2: WMA2 fixture missing; skipping");
        return;
    }
    let bp = || AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let arm = [
        RVA_EA3A_ENTRY,
        RVA_EA4D_PAST_GUARD,
        RVA_EAAF_LOAD_RETURN,
        RVA_EAB1_EPILOGUE,
        RVA_E141_POST_CALL_CMP,
        RVA_E148_BAIL_JNZ,
        RVA_E2BB_E_FAIL_STAMP,
    ];
    let with_patch = run_watch_armed_receive(bp(), Some(65_536), &arm);
    let without_patch = run_watch_armed_receive(bp(), None, &arm);
    let (Some(wp), Some(np)) = (with_patch, without_patch) else {
        eprintln!("round70 phase2: one of the two runs failed to bootstrap");
        return;
    };

    let key = |o: &WatchOutcome| -> std::collections::BTreeSet<u32> {
        let base = o
            .snapshots
            .iter()
            .find(|s| (s.eip & 0xFFF) == (RVA_EA3A_ENTRY & 0xFFF))
            .map(|s| s.eip.wrapping_sub(RVA_EA3A_ENTRY))
            .unwrap_or(o.image_base);
        o.snapshots
            .iter()
            .map(|s| s.eip.wrapping_sub(base))
            .collect()
    };

    let wp_set = key(&wp);
    let np_set = key(&np);
    eprintln!(
        "round70 phase2: with_patch    hr={:?}  reach-set={:?}",
        wp.receive_hr, wp_set
    );
    eprintln!(
        "round70 phase2: without_patch hr={:?}  reach-set={:?}",
        np.receive_hr, np_set
    );

    if wp_set == np_set {
        eprintln!(
            "round70 phase2: REACH-SET IDENTICAL — \
             helper_addref_patch is RETIRABLE on the ffmpeg-extradata \
             path (re-confirms round 69 phase 3 finding)."
        );
    } else {
        let only_wp: std::collections::BTreeSet<_> = wp_set.difference(&np_set).copied().collect();
        let only_np: std::collections::BTreeSet<_> = np_set.difference(&wp_set).copied().collect();
        eprintln!(
            "round70 phase2: REACH-SET DIVERGES — patch-only sites: {:?}, \
             no-patch-only sites: {:?}",
            only_wp, only_np
        );
    }

    // Pin: both runs reach 0xea3a and 0xe141 — the structural
    // pre-conditions for round-70's analysis to hold.  If the
    // no-patch run misses either, the patch is NOT retirable and
    // round 71 should keep applying it.
    assert!(
        wp_set.contains(&RVA_EA3A_ENTRY) && np_set.contains(&RVA_EA3A_ENTRY),
        "round70 phase2: 0xea3a missing from one of the runs"
    );
    assert!(
        wp_set.contains(&RVA_E141_POST_CALL_CMP) && np_set.contains(&RVA_E141_POST_CALL_CMP),
        "round70 phase2: 0xe141 missing from one of the runs"
    );
}

// ── Phase 3 — pre-call vs post-call delta on `[outer_this+0x468]` ────

/// Phase 3 — characterise WHEN the `[outer_this+0x468]` flag
/// transitions to non-zero.  We arm two watchpoints:
///
///   * `0xe13c` — BEFORE the call to `0xea3a`.  Snapshot's `ebx` is
///     `outer_this`; reading `[ebx+0x468]` post-mortem gives the
///     pre-call value of the flag.
///   * `0xe141` — AFTER the call.  Same `ebx`; same post-mortem
///     read gives the post-call value.
///
/// If `pre == 0 && post != 0`, then `0xea3a` (or one of its callees)
/// SET the flag — round 71's investigation should focus on writes to
/// `[outer_this+0x468]` from inside `0xe928` / `0xe9a9` (the helpers
/// `0xea3a` calls).
///
/// If `pre != 0`, then the flag was set by an UPSTREAM path (likely
/// during ReceiveConnection or Pause/Run).  Round 71's investigation
/// should trace writes to `[ebx+0x468]` across the bring-up.
#[test]
fn phase3_outer_this_0x468_delta_around_ea3a() {
    if msadds32_path().is_none() {
        eprintln!("round70 phase3: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round70 phase3: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let arm = [
        RVA_E13C_CALL_EA3A,
        RVA_E141_POST_CALL_CMP,
        RVA_E148_BAIL_JNZ,
    ];
    let Some(o) = run_watch_armed_receive(bp, None, &arm) else {
        eprintln!("round70 phase3: bootstrap failed");
        return;
    };
    let image_base = o
        .snapshots
        .iter()
        .find(|s| (s.eip & 0xFFF) == (RVA_E13C_CALL_EA3A & 0xFFF))
        .map(|s| s.eip.wrapping_sub(RVA_E13C_CALL_EA3A))
        .or_else(|| {
            o.snapshots
                .iter()
                .find(|s| (s.eip & 0xFFF) == (RVA_E141_POST_CALL_CMP & 0xFFF))
                .map(|s| s.eip.wrapping_sub(RVA_E141_POST_CALL_CMP))
        })
        .unwrap_or(o.image_base);
    eprintln!(
        "round70 phase3: receive_hr={:?}  snapshots={}  image_base={:#010x}",
        o.receive_hr,
        o.snapshots.len(),
        image_base
    );

    let pre = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base) == RVA_E13C_CALL_EA3A);
    let post = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base) == RVA_E141_POST_CALL_CMP);
    let bail = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base) == RVA_E148_BAIL_JNZ);

    if let (Some(pre), Some(post)) = (pre, post) {
        let ebx_pre = pre.regs[3];
        let ebx_post = post.regs[3];
        let pre_val =
            o.sb.mmu
                .load32(ebx_pre.wrapping_add(0x468))
                .unwrap_or(0xDEAD_BEEF);
        let post_val =
            o.sb.mmu
                .load32(ebx_post.wrapping_add(0x468))
                .unwrap_or(0xDEAD_BEEF);
        eprintln!(
            "round70 phase3: HEADLINE — pre-call  ebx={:#010x}  [ebx+0x468]={:#010x}",
            ebx_pre, pre_val
        );
        eprintln!(
            "round70 phase3: HEADLINE — post-call ebx={:#010x}  [ebx+0x468]={:#010x}",
            ebx_post, post_val
        );
        if pre_val == post_val {
            eprintln!(
                "round70 phase3: → flag UNCHANGED across the call — \
                 set by an UPSTREAM path (round 71: trace writes during \
                 ReceiveConnection / Pause / Run)."
            );
        } else if pre_val == 0 && post_val != 0 {
            eprintln!(
                "round70 phase3: → flag SET BY 0xea3a (or a transitive \
                 callee) — round 71: trace writes inside 0xe928 / 0xe9a9 \
                 to `[outer_this+0x468]`."
            );
        } else {
            eprintln!(
                "round70 phase3: → flag CLEARED by the call (pre={:#x}, \
                 post={:#x}) — unexpected; investigate.",
                pre_val, post_val
            );
        }
    } else {
        eprintln!(
            "round70 phase3: pre/post snapshots missing — pre={}, post={}",
            pre.is_some(),
            post.is_some()
        );
    }
    if let Some(s) = bail {
        eprintln!(
            "round70 phase3: bail-jnz snapshot present (jnz to 0xe2bb) at fire_order={}",
            s.fire_order
        );
    }
}

// ── Phase 4 — identify WHICH of the 9 bail-JCCs reaches the E_FAIL stamp ──

/// Phase 4 — `0xe2bb` is reachable from NINE distinct conditional
/// jumps inside `0xe0f4`'s body, not just the `0xe148` jne following
/// the `[ebx+0x468]` test (clean-room enumeration in
/// [`RVA_E0F4_BAIL_JCCS`]).  Phase 1 confirmed `0xe2bb` IS reached
/// but phase 1's mem-probe at `[ebx+0x468]` showed zero on the
/// FIRST `0xe148` hit — meaning the `0xe148` JNZ was NOT taken on
/// the first iteration.  This phase identifies the OTHER bail
/// JCC(s) that fire and reach `0xe2bb`.
///
/// We arm a watchpoint at every bail JCC site + at `0xe2bb` itself,
/// then drive Receive once.  The reach-set tells us which JCC(s)
/// actually steer to E_FAIL.
#[test]
fn phase4_identify_bail_jcc_that_reaches_e_fail_stamp() {
    if msadds32_path().is_none() {
        eprintln!("round70 phase4: msadds32.ax missing; skipping");
        return;
    }
    if !fixture_path().is_file() {
        eprintln!("round70 phase4: WMA2 fixture missing; skipping");
        return;
    }
    let bp = AmtBlueprint::wma_with_ffmpeg_extradata_prefix(0x0161, 1, 44_100, 4_000, 185);
    let mut arm: Vec<u32> = RVA_E0F4_BAIL_JCCS.to_vec();
    arm.push(RVA_E2BB_E_FAIL_STAMP);
    let Some(o) = run_watch_armed_receive(bp, None, &arm) else {
        eprintln!("round70 phase4: bootstrap failed");
        return;
    };
    let image_base = o.image_base;
    eprintln!(
        "round70 phase4: receive_hr={:?}  trap={:?}  snapshots={}",
        o.receive_hr,
        o.receive_trap,
        o.snapshots.len(),
    );
    let mut hits_per_rva: std::collections::BTreeMap<u32, usize> = Default::default();
    for s in &o.snapshots {
        let rva = s.eip.wrapping_sub(image_base);
        *hits_per_rva.entry(rva).or_default() += 1;
    }
    eprintln!("round70 phase4: hits-per-RVA = {:?}", hits_per_rva);

    // Locate the FIRST `0xe2bb` snapshot — the bail JCC that fires
    // immediately before is the actual bail site for this run.
    let e2bb_first = o
        .snapshots
        .iter()
        .find(|s| s.eip.wrapping_sub(image_base) == RVA_E2BB_E_FAIL_STAMP);
    if let Some(s_e2bb) = e2bb_first {
        eprintln!(
            "round70 phase4: 0xe2bb FIRST hit at fire_order={}\n{}",
            s_e2bb.fire_order,
            fmt_snapshot(s_e2bb, image_base)
        );
        // Walk backwards from the e2bb snapshot to find the
        // immediately-prior bail-JCC snapshot.
        let bail_set: std::collections::BTreeSet<u32> =
            RVA_E0F4_BAIL_JCCS.iter().copied().collect();
        let prior = o
            .snapshots
            .iter()
            .take(s_e2bb.fire_order)
            .rev()
            .find(|s| bail_set.contains(&s.eip.wrapping_sub(image_base)));
        if let Some(s_prior) = prior {
            let prior_rva = s_prior.eip.wrapping_sub(image_base);
            eprintln!(
                "round70 phase4: HEADLINE — actual bail JCC is at rva={:#06x} (fire_order={})\n{}",
                prior_rva,
                s_prior.fire_order,
                fmt_snapshot(s_prior, image_base)
            );

            // For the 0xe148 case specifically, post-mortem read
            // `[ebx+0x468]` — the captured ebx is the value at the
            // JCC fire moment.  This is the closest we can get
            // without a memory watchpoint; if mid-run writes have
            // cleared the field by the end of Receive, the
            // post-mortem read will show 0.
            if prior_rva == 0xe148 {
                let ebx = s_prior.regs[3];
                let final_val =
                    o.sb.mmu
                        .load32(ebx.wrapping_add(0x468))
                        .unwrap_or(0xDEAD_BEEF);
                eprintln!(
                    "round70 phase4: bail-via-0xe148 — ebx={:#010x}  [ebx+0x468] (post-Receive)={:#010x} \
                     (note: this is the END-of-run value; intermediate writes may have cleared it)",
                    ebx, final_val
                );
            } else if prior_rva == 0xe282 {
                // 0xe282 is the `jge +0x37` after `cmp edi, [ebp+0x10]`
                // at 0xe27d.  The bail fires when `edi >= [ebp+0x10]`.
                // edi at this snapshot is the loop counter; [ebp+0x10]
                // is the second arg to 0xe0f4 (a length / item count).
                let ebp = s_prior.regs[5];
                let edi = s_prior.regs[7];
                let length_bound =
                    o.sb.mmu
                        .load32(ebp.wrapping_add(0x10))
                        .unwrap_or(0xDEAD_BEEF);
                let arg0 = o.sb.mmu.load32(ebp.wrapping_add(8)).unwrap_or(0xDEAD_BEEF);
                let arg1 =
                    o.sb.mmu
                        .load32(ebp.wrapping_add(0xc))
                        .unwrap_or(0xDEAD_BEEF);
                eprintln!(
                    "round70 phase4: bail-via-0xe282 — edi (loop counter)={:#010x} \
                     [ebp+0x10] (loop-bound, jge target)={:#010x}  [ebp+0x08]={:#010x}  \
                     [ebp+0x0c]={:#010x}",
                    edi, length_bound, arg0, arg1
                );
                eprintln!(
                    "round70 phase4: → bail fires because edi >= length_bound — \
                     interpretation: the 0xe0f4 outer loop walked past the codec's \
                     declared output-buffer length.  Round 71 should trace the \
                     length_bound's source (it is `arg2` of 0xe0f4, set by the \
                     outer caller at one of `0xc975`'s downstream call sites)."
                );
            }
        } else {
            eprintln!(
                "round70 phase4: NO prior bail-JCC snapshot before 0xe2bb hit — \
                 the entry path may be a fall-through from a non-armed site \
                 or a different control flow than expected"
            );
        }
    } else {
        eprintln!(
            "round70 phase4: 0xe2bb NEVER hit on this run — \
             the trajectory diverged or the HRESULT shifted"
        );
    }

    // Pin: at least one bail JCC fires AND 0xe2bb is reached.
    let any_bail_reached = RVA_E0F4_BAIL_JCCS
        .iter()
        .any(|rva| o.visited_rvas.contains(rva));
    let e2bb_reached = o.visited_rvas.contains(&RVA_E2BB_E_FAIL_STAMP);
    assert!(
        any_bail_reached,
        "round70 phase4: NO bail JCC reached — trajectory diverged"
    );
    assert!(
        e2bb_reached,
        "round70 phase4: 0xe2bb NOT reached — HRESULT may have shifted"
    );
}

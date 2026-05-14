//! Wire each [`super::DiscoveryEntry`] into the framework codec
//! registry as a [`oxideav_core::CodecInfo`].
//!
//! Because [`oxideav_core::DecoderFactory`] is a bare `fn`
//! pointer, the per-codec context (DLL path / FourCC / kind /
//! CLSID) cannot be captured. Instead we maintain a process-wide
//! lookup keyed by `codec_id`, and a single shared factory function
//! looks up the [`DiscoveryRecord`] there at construction time.
//!
//! Codec id format: `vfw_<fourcc-lowercase>_<dll-basename-stem>`,
//! e.g. `"vfw_mp43_mpg4ds32"`. Avoids collisions when multiple
//! DLLs claim the same FourCC.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use oxideav_core::{
    CodecCapabilities, CodecId, CodecInfo, CodecParameters, CodecTag, Decoder, Error, Frame,
    Packet, PixelFormat, Result, RuntimeContext, VideoFrame, VideoPlane,
};

use crate::win32::vfw32::{Bih, ICDECOMPRESS_NOTKEYFRAME};

use super::probe::{fourcc_to_bytes, Kind};

/// Backing-store record for one discovered codec. Stashed in the
/// per-process [`record_table`] so the bare `fn`
/// [`oxideav_core::DecoderFactory`] can reach it at
/// `make_decoder` time.
#[derive(Debug, Clone)]
pub struct DiscoveryRecord {
    pub dll_path: PathBuf,
    pub fourcc: String,
    pub kind: Kind,
    pub clsid: Option<String>,
}

/// Process-wide lookup of `codec_id` → [`DiscoveryRecord`].
///
/// Populated by [`register_factory_for_id`] before `register()`
/// returns. Read by the `make_decoder` factory below.
///
/// `OnceLock<Mutex<…>>` keeps initialisation lazy — most consumers
/// won't ever use the auto-discovery path and we don't want to
/// pay for the table.
fn record_table() -> &'static Mutex<HashMap<String, DiscoveryRecord>> {
    static TABLE: OnceLock<Mutex<HashMap<String, DiscoveryRecord>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Insert `record` under `codec_id`. Overwrites any prior entry
/// — `register()` may legitimately be called multiple times in a
/// single process (CLI's `--list` then a real run, tests, …).
pub fn register_factory_for_id(codec_id: &str, record: DiscoveryRecord) {
    if let Ok(mut t) = record_table().lock() {
        t.insert(codec_id.to_string(), record);
    }
}

/// Look up the discovery record stashed for `codec_id`. Returns
/// `None` for any codec id that wasn't registered through
/// [`register_factory_for_id`].
pub fn lookup_record(codec_id: &str) -> Option<DiscoveryRecord> {
    let t = record_table().lock().ok()?;
    t.get(codec_id).cloned()
}

/// Round 34 — outcome of `SandboxedDshowDecoder::ensure_open`'s
/// codec-allocator negotiation handshake.  Captured globally
/// (keyed on `codec_id`) so tests can introspect what
/// `IMemInputPin::GetAllocator + SetProperties + Commit` did
/// against the codec's own allocator without having to construct
/// a parallel sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecAllocatorNegotiation {
    /// `IMemInputPin::GetAllocator` HRESULT.
    pub get_allocator_hr: u32,
    /// Allocator interface pointer the codec wrote into `*pp`,
    /// or `0` if NULL / GetAllocator failed.
    pub codec_allocator: u32,
    /// `IMemAllocator::SetProperties` HRESULT against the codec's
    /// allocator, or `0xFFFF_FFFF` if not attempted.
    pub set_properties_hr: u32,
    /// `IMemAllocator::Commit` HRESULT against the codec's
    /// allocator, or `0xFFFF_FFFF` if not attempted.
    pub commit_hr: u32,
    /// True iff the production path elected to drive `Receive`'s
    /// `GetBuffer` against the codec's allocator (vs the host
    /// allocator fallback).
    pub using_codec_allocator: bool,
}

fn negotiation_table() -> &'static std::sync::Mutex<HashMap<String, CodecAllocatorNegotiation>> {
    static T: std::sync::OnceLock<std::sync::Mutex<HashMap<String, CodecAllocatorNegotiation>>> =
        std::sync::OnceLock::new();
    T.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn record_codec_allocator_negotiation(codec_id: &str, neg: CodecAllocatorNegotiation) {
    if let Ok(mut t) = negotiation_table().lock() {
        t.insert(codec_id.to_string(), neg);
    }
}

/// Round 34 — return the most recent codec-allocator negotiation
/// outcome captured for `codec_id`, or `None` if the decoder for
/// that id has not yet been driven through `send_packet`.
pub fn last_codec_allocator_negotiation(codec_id: &str) -> Option<CodecAllocatorNegotiation> {
    negotiation_table().lock().ok()?.get(codec_id).copied()
}

/// Build the canonical codec id string for a given DLL + FourCC.
///
/// Format: `vfw_<lowercase-fourcc>_<dll-basename-stem-lowercase>`.
/// Sanitisation: any byte outside `[a-z0-9]` is replaced by `_`
/// so the id stays JSON / CLI / shell-safe.
pub fn codec_id_for(dll_path: &Path, fourcc: &str) -> String {
    let stem = dll_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let mut id = String::with_capacity(8 + 4 + 1 + stem.len());
    id.push_str("vfw_");
    push_sanitised(&mut id, fourcc);
    id.push('_');
    push_sanitised(&mut id, stem);
    id
}

fn push_sanitised(out: &mut String, s: &str) {
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
}

/// Register one [`CodecInfo`] for a discovered DLL+FourCC pair.
///
/// Priority is fixed at 200 — VfW is a last-resort path that
/// resolves only when a native crate doesn't already claim the
/// tag. The shared `make_decoder` factory below pulls the
/// matching [`DiscoveryRecord`] out of [`record_table`] at
/// construction time.
pub fn register_codec_info(ctx: &mut RuntimeContext, codec_id: &str, fourcc: &str) {
    let id = CodecId::new(codec_id.to_string());
    let caps = CodecCapabilities::video("vfw_sandboxed")
        .with_decode()
        .with_lossy(true)
        .with_priority(200);

    let mut info = CodecInfo::new(id).capabilities(caps).decoder(make_decoder);
    if let Some(bytes) = fourcc_to_bytes(fourcc) {
        info = info.tag(CodecTag::fourcc(&bytes));
    }
    ctx.codecs.register(info);
}

/// Shared `make_decoder` factory — looks up the per-codec record
/// stashed by [`register_factory_for_id`] at register-time.
///
/// VfW codecs return a real [`SandboxedVfwDecoder`]. DirectShow
/// codecs return `Err(Unsupported)` for round 28 — the full
/// `IPin::Receive → IMemAllocator → IMediaSample` host wiring
/// arrives in round 29.
pub fn make_decoder(params: &CodecParameters) -> Result<Box<dyn Decoder>> {
    let id_str = params.codec_id.as_str();
    let record = lookup_record(id_str).ok_or_else(|| {
        Error::other(format!(
            "vfw discovery: codec id {id_str:?} not registered (call \
             oxideav_vfw::register first, or ensure OXIDEAV_VFW_CODEC_PATH \
             points at a codec directory)"
        ))
    })?;

    match record.kind {
        Kind::Vfw => Ok(Box::new(SandboxedVfwDecoder::new(record, params.clone())?)),
        Kind::DirectShow => Ok(Box::new(SandboxedDshowDecoder::new(
            record,
            params.clone(),
        )?)),
        Kind::Unsupported => Err(Error::unsupported(
            "vfw discovery: this codec was probed but found unsupported",
        )),
    }
}

// ────────────────────────────────────────────────────────────────
// SandboxedVfwDecoder — Decoder impl that holds the Sandbox + the
// codec instance handle (HIC) across packets and dispatches
// `send_packet` → `ic_decompress` → `Frame::Video`.
//
// Round 29 wires the full ICDecompressQuery → ICDecompressBegin →
// ICDecompress → ICDecompressEnd handshake:
//
// * `ensure_open` (lazy on first `send_packet`) loads the DLL,
//   drives DllMain, opens the codec handle, runs the
//   query+begin handshake against a synthesised input
//   `BITMAPINFOHEADER` (FOURCC = record.fourcc, 24bpp coded
//   from the codec parameters) and a fixed BI_RGB 24bpp output
//   `BITMAPINFOHEADER`.
// * `receive_frame` consumes the pending packet, calls
//   `ic_decompress` with `ICDECOMPRESS_NOTKEYFRAME` set unless
//   `packet.flags.keyframe`, then materialises the codec's
//   bottom-up BGR24 output as a top-down `Frame::Video` with
//   `PixelFormat::Bgr24`.
// * `Drop` calls `ic_decompress_end` then `ic_close`.
//
// DirectShow codecs (`Kind::DirectShow`) still return
// `Error::Unsupported` — that path needs `IMemAllocator` +
// `IMediaSample` host stubs (round 30+).
// ────────────────────────────────────────────────────────────────

struct SandboxedVfwDecoder {
    codec_id: CodecId,
    record: DiscoveryRecord,
    /// Sandbox is constructed lazily on the first `send_packet`
    /// — `make_decoder` runs synchronously on every codec lookup
    /// and consumers may discard the result without ever calling
    /// `send_packet`, so we don't pay for the DLL load until it
    /// matters.
    sandbox: Option<crate::Sandbox>,
    /// Loaded image — kept alive alongside the sandbox.
    image: Option<crate::pe::Image>,
    /// Currently-open ICOpen handle. `0` means "not opened yet".
    hic: u32,
    /// True once `ICDecompressBegin` has run successfully on
    /// `hic`. `Drop` calls `ICDecompressEnd` only when set.
    begin_done: bool,
    /// Stream width / height. Resolved lazily from
    /// [`CodecParameters`] when present, or — if absent — probed
    /// from the codec via `ICM_DECOMPRESS_GET_FORMAT` after
    /// `ICDecompressQuery` accepts the input format. Round 30
    /// added the probe path; round 29 hard-required the caller
    /// to populate dims, which made the trait surface awkward
    /// for callers that don't know dims ahead of time.
    width: u32,
    height: u32,
    /// Whether `width`/`height` were known at construction time
    /// (false means we need to run the GET_FORMAT probe on first
    /// `ensure_open` after a successful `ICDecompressQuery`).
    dims_from_params: bool,
    /// Source BIH FOURCC, derived from `record.fourcc`.
    fourcc_bytes: [u8; 4],
    /// Pending packet awaiting `receive_frame`. Cleared on each
    /// frame surfaced.
    pending: Option<Packet>,
    eof: bool,
}

impl SandboxedVfwDecoder {
    fn new(record: DiscoveryRecord, params: CodecParameters) -> Result<Self> {
        let dims_from_params = params.width.is_some() && params.height.is_some();
        // Use placeholder dims when missing; the GET_FORMAT probe
        // populates them in `ensure_open` after `ICDecompressQuery`.
        let width = params.width.unwrap_or(0);
        let height = params.height.unwrap_or(0);
        let fourcc_bytes = fourcc_to_bytes(&record.fourcc).ok_or_else(|| {
            Error::other(format!(
                "vfw discovery: bad fourcc {:?} in record",
                record.fourcc
            ))
        })?;
        Ok(SandboxedVfwDecoder {
            codec_id: params.codec_id.clone(),
            record,
            sandbox: None,
            image: None,
            hic: 0,
            begin_done: false,
            width,
            height,
            dims_from_params,
            fourcc_bytes,
            pending: None,
            eof: false,
        })
    }

    /// Build the input BIH used for query/begin — `size_image` is
    /// stubbed to 0 here; per-packet `ic_decompress` overrides the
    /// field with the actual encoded byte count.
    fn build_input_bih(&self, size_image: u32) -> Bih {
        Bih {
            bi_size: 40,
            width: self.width as i32,
            height: self.height as i32,
            planes: 1,
            bit_count: 24,
            compression: self.fourcc_bytes,
            size_image,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            clr_used: 0,
            clr_important: 0,
        }
    }

    /// Build the output BIH — fixed BI_RGB 24bpp (BGR byte order
    /// on disk; bottom-up since `height` is positive). round-24
    /// confirmed mpg4c32 honours BI_RGB but rejects 32bpp; Indeo
    /// (IR32_32 / IR50_32 round 7+) likewise.
    fn build_output_bih(&self) -> Bih {
        Bih {
            bi_size: 40,
            width: self.width as i32,
            height: self.height as i32,
            planes: 1,
            bit_count: 24,
            compression: [0; 4], // BI_RGB
            size_image: self.output_capacity(),
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            clr_used: 0,
            clr_important: 0,
        }
    }

    fn output_capacity(&self) -> u32 {
        // Saturating so an as-yet-unprobed (0×0) decoder produces a
        // sensible 0 here rather than wrapping; the
        // `ICDecompressBegin` path validates dims afterwards.
        self.width.saturating_mul(self.height).saturating_mul(3)
    }

    /// Lazy: load DLL, install codec, ICOpen, run ICDecompressQuery
    /// + ICDecompressBegin so the codec is primed for per-packet
    ///   `ic_decompress` calls.
    fn ensure_open(&mut self) -> Result<()> {
        if self.begin_done {
            return Ok(());
        }
        if self.sandbox.is_none() {
            let bytes = std::fs::read(&self.record.dll_path)
                .map_err(|e| Error::other(format!("vfw discovery: read DLL failed: {e}")))?;
            let mut sb = crate::Sandbox::new();
            // VfW codecs (esp. mpg4c32) need a generous instruction
            // budget to walk the larger fixtures' P-frames; the
            // round-24 manual path uses 8 G instructions for the
            // 5-6-frame 352×288 fixtures.
            sb.cpu.set_instr_limit(8_000_000_000);
            let img = sb
                .load("codec.dll", &bytes)
                .map_err(|e| Error::other(format!("vfw discovery: Sandbox::load failed: {e}")))?;
            sb.install_codec(&img)
                .map_err(|e| Error::other(format!("vfw discovery: install_codec failed: {e}")))?;
            // Drive DllMain so any per-DLL CRT init runs.
            let _ = sb.call_dll_main(&img, crate::DLL_PROCESS_ATTACH);

            let fcc_handler = u32::from_le_bytes(self.fourcc_bytes);
            let fcc_type = u32::from_le_bytes(*b"VIDC");
            // Mode 2 = ICMODE_DECOMPRESS in vfw.h.  The round-24
            // manual path uses 2 here for MP43 because that IS the
            // decode-mode value; the round-29 byte-equality
            // requirement just demands the trait + manual paths
            // exercise the identical DRV_OPEN sequence, including
            // the mode word.  See
            // `tests/round24_mp43_multiframe_and_wmv.rs`.
            // (Original comment had ICMODE_COMPRESS / ICMODE_DECOMPRESS
            //  inverted; corrected in round 51 alongside the encode
            //  surface landing.  Microsoft's codecs are historically
            //  permissive about the mode word at DRV_OPEN, so even
            //  a wrong mode here would still mint a HIC.)
            let hic = sb
                .ic_open(fcc_type, fcc_handler, 2)
                .map_err(|e| Error::other(format!("vfw discovery: ic_open failed: {e}")))?;
            if hic == 0 {
                return Err(Error::other(
                    "vfw discovery: ICOpen returned NULL (codec rejected handler FourCC)",
                ));
            }
            self.sandbox = Some(sb);
            self.image = Some(img);
            self.hic = hic;
        }

        // ICDecompressQuery + ICDecompressBegin against the input/
        // output BIH templates. We run these here (not in `new`)
        // because the sandbox is constructed lazily and the
        // pre-handshake DllMain call may have already mutated the
        // codec's internal state — running query/begin before the
        // first packet keeps the trait path's lifecycle predictable.
        //
        // If the caller didn't supply dims on `CodecParameters`,
        // synthesise a placeholder input BIH and probe the codec
        // via `ICM_DECOMPRESS_GET_FORMAT` first. The codec writes
        // the output BIH (carrying the codec-known dims for the
        // bound stream); we then re-build the input/output BIHs
        // with the probed dims for the real query+begin.
        if !self.dims_from_params {
            // GET_FORMAT needs *some* input BIH. Use 0×0 — codecs
            // that key on dims will simply mirror the dims back
            // into the output BIH at decode time. For codecs that
            // refuse 0×0 here, dims_from_params stays the
            // hard-error path (callers can still pass them).
            let probe_in = self.build_input_bih(0);
            let hic = self.hic;
            let sb = self
                .sandbox
                .as_mut()
                .expect("sandbox just constructed above");
            match sb.ic_decompress_get_format(hic, &probe_in) {
                Ok((rc, out)) if rc == 0 && out.width > 0 && out.height > 0 => {
                    self.width = out.width.unsigned_abs();
                    self.height = out.height.unsigned_abs();
                }
                Ok((rc, out)) => {
                    return Err(Error::invalid(format!(
                        "vfw discovery: ICM_DECOMPRESS_GET_FORMAT \
                         could not establish dims (rc={rc:#010x}, \
                         out_width={}, out_height={}); pass \
                         CodecParameters.{{width,height}} explicitly",
                        out.width, out.height
                    )));
                }
                Err(e) => {
                    return Err(Error::invalid(format!(
                        "vfw discovery: ICM_DECOMPRESS_GET_FORMAT failed: {e}; \
                         pass CodecParameters.{{width,height}} explicitly"
                    )));
                }
            }
        }
        let bih_in = self.build_input_bih(0);
        let bih_out = self.build_output_bih();
        let hic = self.hic;
        let sb = self
            .sandbox
            .as_mut()
            .expect("sandbox just constructed above");
        let q = sb
            .ic_decompress_query(hic, &bih_in, Some(&bih_out))
            .map_err(|e| Error::other(format!("vfw discovery: ic_decompress_query failed: {e}")))?;
        if q != 0 {
            return Err(Error::other(format!(
                "vfw discovery: ic_decompress_query returned {q:#010x} \
                 (want 0 = ICERR_OK; codec rejected the input/output format)"
            )));
        }
        let b = sb
            .ic_decompress_begin(hic, &bih_in, &bih_out)
            .map_err(|e| Error::other(format!("vfw discovery: ic_decompress_begin failed: {e}")))?;
        if b != 0 {
            return Err(Error::other(format!(
                "vfw discovery: ic_decompress_begin returned {b:#010x} \
                 (want 0 = ICERR_OK)"
            )));
        }
        self.begin_done = true;
        Ok(())
    }
}

impl Decoder for SandboxedVfwDecoder {
    fn codec_id(&self) -> &CodecId {
        &self.codec_id
    }

    fn send_packet(&mut self, packet: &Packet) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::other(
                "vfw discovery: receive_frame must be called before sending another packet",
            ));
        }
        self.ensure_open()?;
        self.pending = Some(packet.clone());
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<Frame> {
        let packet = match self.pending.take() {
            Some(p) => p,
            None => {
                return if self.eof {
                    Err(Error::Eof)
                } else {
                    Err(Error::NeedMore)
                };
            }
        };

        let hic = self.hic;
        let bih_in = self.build_input_bih(packet.data.len() as u32);
        let bih_out = self.build_output_bih();
        let cap = self.output_capacity();
        let flags = if packet.flags.keyframe {
            0
        } else {
            ICDECOMPRESS_NOTKEYFRAME
        };
        let sb = self.sandbox.as_mut().ok_or_else(|| {
            Error::other("vfw discovery: receive_frame called without prior send_packet")
        })?;
        let (lr, raw) = sb
            .ic_decompress(hic, flags, &bih_in, &packet.data, &bih_out, cap)
            .map_err(|e| Error::other(format!("vfw discovery: ic_decompress trapped: {e}")))?;
        if lr != 0 {
            return Err(Error::other(format!(
                "vfw discovery: ic_decompress returned {lr:#010x} (want 0 = ICERR_OK)"
            )));
        }

        // Codec wrote BGR24 bottom-up because `bih_out.height >= 0`.
        // Convert to top-down so consumers can treat the buffer as
        // a row-major frame without container-aware flipping.
        let width = self.width as usize;
        let height = self.height as usize;
        let stride = width * 3;
        let mut data = vec![0u8; stride * height];
        if raw.len() < stride * height {
            return Err(Error::other(format!(
                "vfw discovery: ic_decompress returned {} bytes, expected {} (stride*height)",
                raw.len(),
                stride * height,
            )));
        }
        for row in 0..height {
            let src_off = (height - 1 - row) * stride;
            let dst_off = row * stride;
            data[dst_off..dst_off + stride].copy_from_slice(&raw[src_off..src_off + stride]);
        }

        Ok(Frame::Video(VideoFrame {
            pts: packet.pts,
            planes: vec![VideoPlane { stride, data }],
        }))
    }

    fn flush(&mut self) -> Result<()> {
        self.eof = true;
        Ok(())
    }
}

impl Drop for SandboxedVfwDecoder {
    fn drop(&mut self) {
        if let Some(sb) = self.sandbox.as_mut() {
            if self.hic != 0 {
                if self.begin_done {
                    let _ = sb.ic_decompress_end(self.hic);
                }
                let _ = sb.ic_close(self.hic);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────
// SandboxedDshowDecoder — round 30.
//
// Wires a `oxideav_core::Decoder` against a DirectShow filter
// `.ax`. On `send_packet`:
//
// * `ensure_open` (lazy on first packet): load DLL, drive
//   DllMain, drive `DllGetClassObject(CLSID, IID_IClassFactory)`
//   then `IClassFactory::CreateInstance(NULL, IID_IBaseFilter,
//   &filter)`. Walk `IBaseFilter::EnumPins → IEnumPins::Next`
//   for the first input pin. Mint a host IFilterGraph, call
//   `IBaseFilter::JoinFilterGraph(host_graph, NULL)`. Stage an
//   AM_MEDIA_TYPE for the discovery FourCC + 320×240 (or
//   user-supplied dims), mint a host output pin advertising
//   the AMT, call `IPin::ReceiveConnection(host_out_pin, &amt)`.
// * Then QI the input pin for `IID_IMemInputPin`, mint a
//   HostIMemAllocator (4-sample pool, sample capacity =
//   `max(packet.data.len(), 64 KiB)`), call
//   `IMemInputPin::NotifyAllocator(host_alloc, FALSE)`. Stage
//   the packet bytes into the first sample, call
//   `IMemInputPin::Receive(sample)`.
//
// The codec's *output* path needs a downstream HostIPin::Receive
// callback wired into the codec's output pin — that's the r31
// gap the GOAL doc calls out. For r30 we observe via
// `Cpu::trace_ring` what the codec did during `Receive` and
// surface `Error::Unsupported` carrying the captured ring head/tail
// so the next round can mine it.
// ────────────────────────────────────────────────────────────────

struct SandboxedDshowDecoder {
    codec_id: CodecId,
    record: DiscoveryRecord,
    sandbox: Option<crate::Sandbox>,
    image: Option<crate::pe::Image>,
    /// IBaseFilter pointer (after CreateInstance).
    filter: u32,
    /// First input pin (after EnumPins → Next).
    input_pin: u32,
    /// Cached IMemInputPin (after QI).
    mem_input_pin: u32,
    /// Host IFilterGraph (after JoinFilterGraph).
    host_graph: u32,
    /// Host IMemAllocator (after NotifyAllocator).
    host_allocator: u32,
    /// Round 34 — codec's own allocator obtained via
    /// `IMemInputPin::GetAllocator`.  `0` if the codec did not
    /// expose its own allocator (returned NULL or any HRESULT
    /// other than S_OK).  When non-zero, `receive_frame` uses
    /// THIS allocator's `GetBuffer` rather than the host's, so
    /// the sample bytes live in codec-managed guest memory the
    /// codec actually walks.  Per DShow:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-imeminputpin-getallocator>
    /// the input pin returns its preferred allocator interface
    /// pointer; the upstream filter may use it directly without
    /// allocating its own.
    codec_allocator: u32,
    /// Round 34 — true when the codec's `GetAllocator` returned
    /// a usable allocator AND we successfully drove
    /// `SetProperties + Commit` on it.  Drives the
    /// `receive_frame` allocator selection.
    using_codec_allocator: bool,
    /// Whether ReceiveConnection has succeeded — only after that
    /// can we safely proceed to NotifyAllocator + Receive.
    connection_done: bool,
    width: u32,
    height: u32,
    fourcc_bytes: [u8; 4],
    pending: Option<Packet>,
    eof: bool,
    /// Round 33 — `IMediaFilter::GetState` HRESULT observed
    /// immediately after `Run(0)`.  `S_OK` (0) means the
    /// transition completed; `VFW_S_STATE_INTERMEDIATE`
    /// (0x00040003) means the filter is still transitioning.
    last_get_state_hr: u32,
    /// Round 33 — `FILTER_STATE` value the codec wrote into
    /// `*pState` from the same `GetState` call.  Per MSDN:
    /// `State_Stopped=0`, `State_Paused=1`, `State_Running=2`.
    last_get_state_value: u32,
    /// Round 34 — `IMemInputPin::GetAllocator` HRESULT.
    /// `0xFFFF_FFFF` until `ensure_open` runs the call.
    last_get_allocator_hr: u32,
    /// Round 34 — `IMemAllocator::SetProperties` HRESULT against
    /// the codec's own allocator.  `0xFFFF_FFFF` when GetAllocator
    /// did not surface a usable allocator.
    last_codec_alloc_set_properties_hr: u32,
    /// Round 34 — `IMemAllocator::Commit` HRESULT against the
    /// codec's own allocator.  `0xFFFF_FFFF` when GetAllocator did
    /// not surface a usable allocator.
    last_codec_alloc_commit_hr: u32,
}

impl SandboxedDshowDecoder {
    fn new(record: DiscoveryRecord, params: CodecParameters) -> Result<Self> {
        let fourcc_bytes = fourcc_to_bytes(&record.fourcc).ok_or_else(|| {
            Error::other(format!(
                "vfw discovery: bad fourcc {:?} in record",
                record.fourcc
            ))
        })?;
        Ok(SandboxedDshowDecoder {
            codec_id: params.codec_id.clone(),
            record,
            sandbox: None,
            image: None,
            filter: 0,
            input_pin: 0,
            mem_input_pin: 0,
            host_graph: 0,
            host_allocator: 0,
            codec_allocator: 0,
            using_codec_allocator: false,
            connection_done: false,
            // DShow path is more permissive than VfW; default to
            // 320×240 if dims missing — the negotiation may
            // override during ReceiveConnection.
            width: params.width.unwrap_or(320),
            height: params.height.unwrap_or(240),
            fourcc_bytes,
            pending: None,
            eof: false,
            last_get_state_hr: 0xFFFF_FFFF,
            last_get_state_value: 0xFFFF_FFFF,
            last_get_allocator_hr: 0xFFFF_FFFF,
            last_codec_alloc_set_properties_hr: 0xFFFF_FFFF,
            last_codec_alloc_commit_hr: 0xFFFF_FFFF,
        })
    }

    /// Round 33 — `IMediaFilter::GetState` HRESULT observed
    /// immediately after `Run(0)` (or `0xFFFF_FFFF` if the codec
    /// has not yet been driven through `Run`).
    #[allow(dead_code)]
    fn last_get_state_hr(&self) -> u32 {
        self.last_get_state_hr
    }

    /// Round 33 — `FILTER_STATE` value the codec wrote into
    /// `*pState` from the same `GetState` call.  `0xFFFF_FFFF`
    /// when not-yet-probed.
    #[allow(dead_code)]
    fn last_get_state_value(&self) -> u32 {
        self.last_get_state_value
    }

    /// Round 34 — codec's own allocator obtained via
    /// `IMemInputPin::GetAllocator`, or `0` if the codec did not
    /// expose a usable allocator (NULL / E_NOTIMPL / SetProperties
    /// rejection / Commit rejection).
    #[allow(dead_code)]
    fn codec_allocator(&self) -> u32 {
        self.codec_allocator
    }

    /// Round 34 — true when `receive_frame` will use the codec's
    /// own allocator (via `GetBuffer` against `codec_allocator`),
    /// false when it falls back to the host allocator.
    #[allow(dead_code)]
    fn using_codec_allocator(&self) -> bool {
        self.using_codec_allocator
    }

    /// Round 34 — `IMemInputPin::GetAllocator` HRESULT observed
    /// during `ensure_open`.  `0xFFFF_FFFF` if not yet probed.
    #[allow(dead_code)]
    fn last_get_allocator_hr(&self) -> u32 {
        self.last_get_allocator_hr
    }

    /// Round 34 — `IMemAllocator::SetProperties` HRESULT observed
    /// when running it on the codec's allocator.  `0xFFFF_FFFF`
    /// if the codec's allocator could not be obtained.
    #[allow(dead_code)]
    fn last_codec_alloc_set_properties_hr(&self) -> u32 {
        self.last_codec_alloc_set_properties_hr
    }

    /// Round 34 — `IMemAllocator::Commit` HRESULT observed when
    /// running it on the codec's allocator.  `0xFFFF_FFFF` if the
    /// codec's allocator could not be obtained.
    #[allow(dead_code)]
    fn last_codec_alloc_commit_hr(&self) -> u32 {
        self.last_codec_alloc_commit_hr
    }

    fn ensure_open(&mut self) -> Result<()> {
        if self.connection_done {
            return Ok(());
        }
        if self.sandbox.is_none() {
            let bytes = std::fs::read(&self.record.dll_path).map_err(|e| {
                Error::other(format!("vfw discovery (DShow): read DLL failed: {e}"))
            })?;
            let mut sb = crate::Sandbox::new();
            sb.cpu.set_instr_limit(8_000_000_000);
            let img = sb.load("codec.ax", &bytes).map_err(|e| {
                Error::other(format!("vfw discovery (DShow): Sandbox::load failed: {e}"))
            })?;
            let _ = sb.call_dll_main(&img, crate::DLL_PROCESS_ATTACH);

            // Resolve the CLSID from the discovery record.
            let clsid_str = self.record.clsid.as_deref().ok_or_else(|| {
                Error::unsupported(
                    "vfw discovery (DShow): record carries no CLSID — \
                     can't drive DllGetClassObject",
                )
            })?;
            let clsid = crate::com::Guid::parse(clsid_str).map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): bad CLSID {clsid_str:?}: {e}"
                ))
            })?;
            let _factory = sb
                .dll_get_class_object(&img, clsid, crate::IID_ICLASSFACTORY)
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): DllGetClassObject failed: {e}"
                    ))
                })?;
            let filter = sb
                .co_create_instance(clsid, crate::IID_IBASEFILTER)
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): co_create_instance failed: {e}"
                    ))
                })?;
            if filter == 0 {
                return Err(Error::other(
                    "vfw discovery (DShow): CreateInstance returned NULL filter",
                ));
            }
            self.sandbox = Some(sb);
            self.image = Some(img);
            self.filter = filter;
        }

        let sb = self.sandbox.as_mut().expect("sandbox just constructed");

        // Walk EnumPins → Next for the first input pin.
        if self.input_pin == 0 {
            let pin = first_input_pin(sb, self.filter).ok_or_else(|| {
                Error::other("vfw discovery (DShow): could not enumerate input pin")
            })?;
            self.input_pin = pin;
        }

        // Mint host IFilterGraph + JoinFilterGraph.
        if self.host_graph == 0 {
            let host_graph = sb.mint_host_filter_graph().map_err(|e| {
                Error::other(format!("vfw discovery (DShow): mint host graph: {e}"))
            })?;
            let _ = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                self.filter,
                crate::com::SLOT_BASEFILTER_JOIN_FILTER_GRAPH,
                &[host_graph, 0],
            );
            self.host_graph = host_graph;
        }

        // Round 31 A — walk the codec's input pin AMT enumeration
        // first.  If it surfaces any AMTs, prefer them over the
        // fabricated VIH+BIH the round-30 path forced.
        let captured = crate::com::host_iface_r31::walk_codec_input_pin_amts(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            self.input_pin,
            8,
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): walk_codec_input_pin_amts: {e}"
            ))
        })?;
        if !captured.is_empty() {
            log::debug!(
                "vfw discovery (DShow): captured {} codec-native AMT(s); first subtype={}",
                captured.len(),
                captured[0].subtype
            );
        }

        let synth_amt =
            stage_am_media_type_dshow(sb, self.fourcc_bytes, self.width as i32, self.height as i32)
                .map_err(|e| Error::other(format!("vfw discovery (DShow): stage AMT: {e}")))?;

        let mut accepted_amt = 0u32;
        let mut last_hr = 0u32;
        for (i, cap) in captured.iter().enumerate() {
            // Round 37 — pass codec's input pin so the host output
            // pin's QueryPinInfo / ConnectedTo answer the codec's
            // upstream introspection (the round-36 trap was the
            // codec walking a NULL upstream-pin field).
            let host_out_pin = sb
                .mint_host_output_pin_with_connection(cap.amt_addr, self.input_pin)
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): mint host output pin (codec amt {i}): {e}"
                    ))
                })?;
            let r = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                self.input_pin,
                4, // SLOT_PIN_RECEIVE_CONNECTION
                &[host_out_pin, cap.amt_addr],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): IPin::ReceiveConnection (codec amt {i}) trapped: {e}"
                ))
            })?;
            last_hr = r;
            if r == 0 {
                accepted_amt = cap.amt_addr;
                break;
            }
        }
        if accepted_amt == 0 {
            // Fall back to synthetic AMT.  Round 37 — same
            // connection-aware mint as the codec-AMT branch above.
            let host_out_pin = sb
                .mint_host_output_pin_with_connection(synth_amt, self.input_pin)
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): mint host output pin (synth): {e}"
                    ))
                })?;
            let r = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                self.input_pin,
                4, // SLOT_PIN_RECEIVE_CONNECTION
                &[host_out_pin, synth_amt],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): IPin::ReceiveConnection (synth) trapped: {e}"
                ))
            })?;
            if r != 0 {
                return Err(Error::unsupported(format!(
                    "vfw discovery (DShow): IPin::ReceiveConnection rejected every \
                     candidate AMT (codec-native count={}, last codec-native HRESULT \
                     {last_hr:#010x}, synth HRESULT {r:#010x})",
                    captured.len()
                )));
            }
            accepted_amt = synth_amt;
        }
        let amt = accepted_amt;
        self.connection_done = true;

        // QI for IMemInputPin.
        let mip = sb
            .query_interface(self.input_pin, crate::IID_IMEMINPUTPIN)
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): QI IMemInputPin failed: {e}"
                ))
            })?;
        self.mem_input_pin = mip;

        // Round 34 — try the codec's *own* allocator first via
        // `IMemInputPin::GetAllocator(IMemAllocator** ppAllocator)`.
        // Per MSDN, an input pin returns its preferred allocator
        // there; the upstream filter then runs `SetProperties +
        // Commit` on it and finally `NotifyAllocator(this, FALSE)`
        // so both ends agree on which allocator to use.  Most
        // DShow filters create their own allocator and walk it from
        // inside `Receive` regardless of what was handed to
        // `NotifyAllocator` — round 33's `VFW_E_NOT_COMMITTED` came
        // from `mpg4ds32` walking *its own* uncommitted allocator
        // (we'd Commit'd the host one, but not the codec's).
        //
        // The codec-allocator path is best-effort: if `GetAllocator`
        // returns NULL, `E_NOTIMPL`, or `VFW_E_NO_ALLOCATOR`, we fall
        // back to the existing host-allocator path which is then the
        // sole allocator the codec sees.
        let codec_alloc_pp = sb.host.arena_alloc(4).map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): codec_alloc out-slot arena: {e}"
            ))
        })?;
        sb.mmu
            .write_initializer(codec_alloc_pp, &0u32.to_le_bytes())
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec_alloc out-slot init: {e}"
                ))
            })?;
        let r_ga = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            mip,
            crate::com::SLOT_MEMINPUTPIN_GET_ALLOCATOR,
            &[codec_alloc_pp],
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): IMemInputPin::GetAllocator trapped: {e}"
            ))
        })?;
        let codec_alloc = sb.mmu.load32(codec_alloc_pp).unwrap_or(0);
        self.last_get_allocator_hr = r_ga;
        log::debug!(
            "vfw discovery (DShow): IMemInputPin::GetAllocator → \
             hr={r_ga:#010x}, allocator={codec_alloc:#010x}"
        );
        record_codec_allocator_negotiation(
            self.codec_id.as_str(),
            CodecAllocatorNegotiation {
                get_allocator_hr: r_ga,
                codec_allocator: codec_alloc,
                set_properties_hr: 0xFFFF_FFFF,
                commit_hr: 0xFFFF_FFFF,
                using_codec_allocator: false,
            },
        );

        // Mint host IMemAllocator + drive NotifyAllocator(alloc, FALSE).
        // Sample capacity is 256 KiB by default — large enough for
        // 320×240 keyframes from the discovery FourCCs we drive
        // here. Pool size 4 leaves room for codec-side queueing
        // without exhausting the arena.
        let cap = 256 * 1024;
        let alloc = sb.mint_host_mem_allocator(4, cap, amt).map_err(|e| {
            Error::other(format!("vfw discovery (DShow): mint host allocator: {e}"))
        })?;
        self.host_allocator = alloc;

        // Round 34 — when GetAllocator returned a usable allocator,
        // drive `SetProperties + Commit` on IT (not just the host
        // one) so the codec's internal pool transitions out of the
        // "decommitted" state that produces VFW_E_NOT_COMMITTED on
        // its first `GetBuffer` from inside `Receive`.
        //
        // ALLOCATOR_PROPERTIES values mirror the round-30 host
        // shape — pool size 4, cbBuffer big enough for the largest
        // keyframe we'd push (we use 384*288*3 = 331_776, capped at
        // 256 KiB minimum), cbAlign = 1, cbPrefix = 0.
        if r_ga == crate::com::S_OK && codec_alloc != 0 {
            let props = sb.host.arena_alloc(16).map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec_alloc props arena: {e}"
                ))
            })?;
            let actual = sb.host.arena_alloc(16).map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec_alloc actual arena: {e}"
                ))
            })?;
            // cbBuffer = max(coded-frame upper bound, 256 KiB) so
            // small fixtures still fit comfortably.
            let cb_buffer = self
                .width
                .saturating_mul(self.height)
                .saturating_mul(3)
                .max(256 * 1024);
            for (off, val) in [(0u32, 4u32), (4, cb_buffer), (8, 1), (12, 0)] {
                sb.mmu
                    .write_initializer(props + off, &val.to_le_bytes())
                    .map_err(|e| {
                        Error::other(format!(
                            "vfw discovery (DShow): codec_alloc props write: {e}"
                        ))
                    })?;
                sb.mmu
                    .write_initializer(actual + off, &0u32.to_le_bytes())
                    .map_err(|e| {
                        Error::other(format!(
                            "vfw discovery (DShow): codec_alloc actual write: {e}"
                        ))
                    })?;
            }
            let r_sp = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                codec_alloc,
                crate::com::SLOT_MEMALLOCATOR_SET_PROPERTIES,
                &[props, actual],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec_alloc SetProperties trapped: {e}"
                ))
            })?;
            self.last_codec_alloc_set_properties_hr = r_sp;
            log::debug!(
                "vfw discovery (DShow): codec_alloc SetProperties → \
                 hr={r_sp:#010x} (cBuffers=4 cbBuffer={cb_buffer} \
                 cbAlign=1 cbPrefix=0)"
            );
            let mut commit_ok = false;
            // Treat any "success" HRESULT (high bit clear) as
            // permissive — some codecs return VFW_S_NOT_NEEDED or
            // other VFW_S_* informational codes from SetProperties
            // when their internal pool already matches the request.
            if (r_sp & 0x8000_0000) == 0 {
                let r_co = crate::com::call::call_method(
                    &mut sb.cpu,
                    &mut sb.mmu,
                    &sb.registry,
                    &mut sb.host,
                    codec_alloc,
                    crate::com::SLOT_MEMALLOCATOR_COMMIT,
                    &[],
                )
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): codec_alloc Commit trapped: {e}"
                    ))
                })?;
                self.last_codec_alloc_commit_hr = r_co;
                log::debug!("vfw discovery (DShow): codec_alloc Commit → hr={r_co:#010x}");
                commit_ok = (r_co & 0x8000_0000) == 0;
            }
            if commit_ok {
                self.codec_allocator = codec_alloc;
                self.using_codec_allocator = true;
            }
            // Update the per-codec capture stash with the resolved
            // negotiation outcome.
            record_codec_allocator_negotiation(
                self.codec_id.as_str(),
                CodecAllocatorNegotiation {
                    get_allocator_hr: r_ga,
                    codec_allocator: codec_alloc,
                    set_properties_hr: self.last_codec_alloc_set_properties_hr,
                    commit_hr: self.last_codec_alloc_commit_hr,
                    using_codec_allocator: self.using_codec_allocator,
                },
            );
        }

        // Pick the allocator we'll advertise in NotifyAllocator —
        // codec's own when usable, host's otherwise.  Per MSDN
        // semantics either choice is legal: NotifyAllocator just
        // confirms which allocator the upstream filter committed to
        // use.
        let advertised_alloc = if self.using_codec_allocator {
            self.codec_allocator
        } else {
            alloc
        };
        let r_na = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            mip,
            4, // SLOT_MEMINPUTPIN_NOTIFY_ALLOCATOR
            &[advertised_alloc, 0],
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): NotifyAllocator trapped: {e}"
            ))
        })?;
        // We accept any HRESULT here — some codecs return E_NOTIMPL
        // for NotifyAllocator and rely entirely on GetAllocator;
        // the host-allocator path is best-effort.
        log::debug!(
            "vfw discovery (DShow): NotifyAllocator → {r_na:#010x}; \
             alloc = {advertised_alloc:#010x} (codec={})",
            self.using_codec_allocator
        );

        // Round 31 B — wire a downstream HostIPin / HostIMemInputPin
        // pair into the codec's output pin so that when the codec
        // emits a decoded sample, our `Receive` callback captures
        // the bytes into the per-state queue.  The output pin's
        // ReceiveConnection is best-effort — some codecs don't
        // expose a separate output pin (transform-in-place); for
        // those we still pre-mint the host pair so that QI from the
        // input side can find it.
        let (h_pin, h_mip) = sb.host_iface_r31_mint_input_pin_pair().map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): mint host input pin pair: {e}"
            ))
        })?;
        let _h_filter = sb.host_iface_r31_mint_base_filter(h_pin).map_err(|e| {
            Error::other(format!("vfw discovery (DShow): mint host base filter: {e}"))
        })?;
        if let Some(out_pin) = first_output_pin_dshow(sb, self.filter, self.input_pin) {
            // Stage a downstream RGB24 AMT.
            let dn_amt = stage_am_media_type_rgb24_dshow(sb, self.width as i32, self.height as i32)
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): stage downstream RGB24 AMT: {e}"
                    ))
                })?;
            let r_dn = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                out_pin,
                4, // SLOT_PIN_RECEIVE_CONNECTION
                &[h_pin, dn_amt],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): output ReceiveConnection trapped: {e}"
                ))
            })?;
            log::debug!(
                "vfw discovery (DShow): downstream Connect → {r_dn:#010x} (out_pin={out_pin:#010x})"
            );
        }
        let _ = h_mip; // retained on the sandbox via QI on h_pin.

        // Round 32 B — Commit the host allocator so subsequent
        // GetBuffer calls succeed (the allocator starts decommitted
        // per real IMemAllocator semantics).
        let r_commit = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            alloc,
            crate::com::SLOT_MEMALLOCATOR_COMMIT,
            &[],
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): host allocator Commit trapped: {e}"
            ))
        })?;
        log::debug!("vfw discovery (DShow): host alloc Commit → {r_commit:#010x}");

        // Round 32 A — drive the codec from State_Stopped into
        // State_Running through `IMediaFilter::Pause()` →
        // `IMediaFilter::Run(0)`.  Per the DShow filter-state
        // machine (MSDN: "Filter States"), `Receive()` is only
        // legal in Paused or Running; codecs that QI for
        // IMediaFilter and check the state will return
        // VFW_E_NOT_COMMITTED to upstream Receive() while still
        // Stopped.  Both methods are safe even when the codec
        // ignores them — S_OK / S_FALSE are both acceptable.
        //
        // `IBaseFilter` extends `IMediaFilter` so the same vtable
        // slots (5 = Pause, 6 = Run) are reachable directly via
        // the IBaseFilter pointer; no explicit QI(IID_IMediaFilter)
        // is required.
        let r_pause = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            self.filter,
            crate::com::SLOT_MEDIAFILTER_PAUSE,
            &[],
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): IMediaFilter::Pause trapped: {e}"
            ))
        })?;
        log::debug!("vfw discovery (DShow): IMediaFilter::Pause → {r_pause:#010x}");

        // `IMediaFilter::Run(REFERENCE_TIME tStart)` — `tStart` is
        // a 64-bit integer marshalled as two adjacent dwords on the
        // stdcall stack (low dword first, high dword next).  We
        // start the stream at t=0.
        let r_run = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            self.filter,
            crate::com::SLOT_MEDIAFILTER_RUN,
            &[0, 0],
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): IMediaFilter::Run trapped: {e}"
            ))
        })?;
        log::debug!("vfw discovery (DShow): IMediaFilter::Run(0) → {r_run:#010x}");

        // Round 33 B — drive `IMediaFilter::GetState(1000ms,
        // FILTER_STATE*)` to confirm the codec actually
        // transitioned into `State_Running (2)`.  Per MSDN
        // <https://learn.microsoft.com/en-us/windows/win32/api/strmif/nf-strmif-imediafilter-getstate>,
        // GetState blocks for up to `dwMilliSecsTimeout` waiting
        // for any pending state transition to complete.  HRESULT
        // is `S_OK (0)` on completion or
        // `VFW_S_STATE_INTERMEDIATE (0x00040003)` if the
        // transition is still in flight.  Many codecs simply
        // return E_NOTIMPL because they do not maintain explicit
        // state — that's fine, we just record what we see.
        let state_slot = sb.host.arena_alloc(4).map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): IMediaFilter::GetState arena: {e}"
            ))
        })?;
        sb.mmu
            .write_initializer(state_slot, &0xFFFF_FFFFu32.to_le_bytes())
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): IMediaFilter::GetState seed: {e}"
                ))
            })?;
        let r_state = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            self.filter,
            crate::com::SLOT_MEDIAFILTER_GET_STATE,
            &[1000, state_slot],
        )
        .map_err(|e| {
            Error::other(format!(
                "vfw discovery (DShow): IMediaFilter::GetState trapped: {e}"
            ))
        })?;
        let state_value = sb.mmu.load32(state_slot).unwrap_or(0xFFFF_FFFF);
        self.last_get_state_hr = r_state;
        self.last_get_state_value = state_value;
        log::debug!(
            "vfw discovery (DShow): IMediaFilter::GetState(1000ms) \
             → hr={r_state:#010x}, state={state_value:#010x} \
             (Stopped=0, Paused=1, Running=2)"
        );

        Ok(())
    }
}

/// Round 31 — find a PIN_OUTPUT pin on the codec filter (skipping
/// `skip` which is already-bound input).  Returns `None` if the
/// filter has no output pin.  Round 32 unifies on
/// [`pin_with_direction`].
fn first_output_pin_dshow(sb: &mut crate::Sandbox, filter: u32, skip: u32) -> Option<u32> {
    pin_with_direction(sb, filter, crate::com::PIN_DIRECTION_OUTPUT, Some(skip))
}

/// Stage a downstream RGB24 AM_MEDIA_TYPE.  Used by round 31 B.
fn stage_am_media_type_rgb24_dshow(
    sb: &mut crate::Sandbox,
    width: i32,
    height: i32,
) -> Result<u32> {
    let to_oxide =
        |e: crate::Error| Error::other(format!("vfw discovery (DShow): stage RGB24 AMT: {e}"));
    let blob = sb
        .host
        .arena_alloc(72 + 88 + 16)
        .map_err(|e| to_oxide(crate::Error::Win32(e)))?;
    let amt = blob;
    let fmt = blob + 72;
    let mediatype_video =
        crate::com::Guid::parse("{73646976-0000-0010-8000-00AA00389B71}").unwrap();
    let format_videoinfo =
        crate::com::Guid::parse("{05589F80-C356-11CE-BF01-00AA0055595A}").unwrap();
    let mediasubtype_rgb24 =
        crate::com::Guid::parse("{E436EB7D-524F-11CE-9F53-0020AF0BA770}").unwrap();
    let trap = |e: crate::emulator::Trap| to_oxide(crate::Error::Trap(e));
    mediatype_video.stage(&mut sb.mmu, amt).map_err(trap)?;
    mediasubtype_rgb24
        .stage(&mut sb.mmu, amt + 16)
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 32, &1u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 36, &0u32.to_le_bytes())
        .map_err(trap)?;
    let stride = (width.unsigned_abs() * 3 + 3) & !3;
    let img = stride * height.unsigned_abs();
    sb.mmu
        .write_initializer(amt + 40, &img.to_le_bytes())
        .map_err(trap)?;
    format_videoinfo
        .stage(&mut sb.mmu, amt + 44)
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 60, &0u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 64, &88u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 68, &fmt.to_le_bytes())
        .map_err(trap)?;
    for i in 0..48u32 {
        sb.mmu.store8(fmt + i, 0).map_err(trap)?;
    }
    let bih = fmt + 48;
    sb.mmu
        .write_initializer(bih, &40u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 4, &(width as u32).to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 8, &(height as u32).to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 12, &1u16.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 14, &24u16.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 16, &0u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 20, &img.to_le_bytes())
        .map_err(trap)?;
    for off in [24u32, 28, 32, 36] {
        sb.mmu
            .write_initializer(bih + off, &0u32.to_le_bytes())
            .map_err(trap)?;
    }
    Ok(amt)
}

/// Stage an AM_MEDIA_TYPE (72 B) + VIDEOINFOHEADER (88 B) in arena
/// memory describing a video stream of (`fourcc`, `width × height`,
/// 24 bpp). Returns the AMT's guest VA. Thin equivalent of the
/// round-27 test helper, lifted into the production module so
/// `SandboxedDshowDecoder` can reuse it.
fn stage_am_media_type_dshow(
    sb: &mut crate::Sandbox,
    fourcc: [u8; 4],
    width: i32,
    height: i32,
) -> Result<u32> {
    let to_oxide = |e: crate::Error| Error::other(format!("vfw discovery (DShow): stage AMT: {e}"));
    let blob = sb
        .host
        .arena_alloc(72 + 88 + 16)
        .map_err(|e| to_oxide(crate::Error::Win32(e)))?;
    let amt = blob;
    let fmt = blob + 72;

    // AM_MEDIA_TYPE @ amt.
    let mediatype_video =
        crate::com::Guid::parse("{73646976-0000-0010-8000-00AA00389B71}").unwrap();
    let format_videoinfo =
        crate::com::Guid::parse("{05589F80-C356-11CE-BF01-00AA0055595A}").unwrap();
    let d1 = u32::from_le_bytes(fourcc);
    let subtype = crate::com::Guid::new(
        d1,
        0x0000,
        0x0010,
        [0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71],
    );

    let trap = |e: crate::emulator::Trap| to_oxide(crate::Error::Trap(e));
    mediatype_video.stage(&mut sb.mmu, amt).map_err(trap)?;
    subtype.stage(&mut sb.mmu, amt + 16).map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 32, &1u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 36, &1u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 40, &0u32.to_le_bytes())
        .map_err(trap)?;
    format_videoinfo
        .stage(&mut sb.mmu, amt + 44)
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 60, &0u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 64, &88u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(amt + 68, &fmt.to_le_bytes())
        .map_err(trap)?;

    // VIH @ fmt — first 48 bytes (rcSource + rcTarget + dwBitRate +
    // dwBitErrorRate + AvgTimePerFrame) zeroed; BIH at fmt+48.
    for i in 0..48u32 {
        sb.mmu.store8(fmt + i, 0).map_err(trap)?;
    }
    let bih = fmt + 48;
    sb.mmu
        .write_initializer(bih, &40u32.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 4, &(width as u32).to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 8, &(height as u32).to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 12, &1u16.to_le_bytes())
        .map_err(trap)?;
    sb.mmu
        .write_initializer(bih + 14, &24u16.to_le_bytes())
        .map_err(trap)?;
    sb.mmu.write_initializer(bih + 16, &fourcc).map_err(trap)?;
    let size_image = (width.unsigned_abs() * height.unsigned_abs() * 3) / 2;
    sb.mmu
        .write_initializer(bih + 20, &size_image.to_le_bytes())
        .map_err(trap)?;
    for off in [24u32, 28, 32, 36] {
        sb.mmu
            .write_initializer(bih + off, &0u32.to_le_bytes())
            .map_err(trap)?;
    }
    Ok(amt)
}

/// Round 32 — walk every pin the codec exposes via
/// `IBaseFilter::EnumPins → IEnumPins::Next`, query each for its
/// direction (`IPin::QueryDirection(PIN_DIRECTION*)` — slot 9),
/// and return the *first* pin that reports `PIN_INPUT (0)`.
///
/// Round 30 (and r31) returned the *first enumerated* pin and
/// trusted DirectShow's "input pins enumerate first" convention.
/// Some codecs (e.g. `mpg4ds32`) violate this — their first pin
/// is non-input, which causes downstream `EnumMediaTypes` to
/// return `E_NOTIMPL` and `ReceiveConnection` to reject every
/// AMT.  Walking + filtering by `QueryDirection` is the canonical
/// MSDN recipe.
///
/// Reference: MSDN — "IPin::QueryDirection" + `PIN_DIRECTION`
/// enum (`PINDIR_INPUT = 0`, `PINDIR_OUTPUT = 1`).  Source:
/// `strmif.h` from the Windows SDK.
fn first_input_pin(sb: &mut crate::Sandbox, filter: u32) -> Option<u32> {
    pin_with_direction(sb, filter, crate::com::PIN_DIRECTION_INPUT, None)
}

/// Walk every pin on `filter` via EnumPins/Next; for each pin
/// that reports `direction`, return it (skipping `skip` if any).
/// Released enumerator + non-matching pin objects on the way.
fn pin_with_direction(
    sb: &mut crate::Sandbox,
    filter: u32,
    direction: u32,
    skip: Option<u32>,
) -> Option<u32> {
    use crate::com::call::call_method;
    // Stop the filter so ReceiveConnection is legal in the caller's
    // subsequent flow (matches the round-30 behaviour for the input
    // pin path; harmless on output-pin probing — codec is already
    // stopped at construction time).
    let _ = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        filter,
        crate::com::SLOT_BASEFILTER_STOP,
        &[],
    );
    let scratch = sb.host.arena_alloc(4).ok()?;
    sb.mmu.write_initializer(scratch, &[0u8; 4]).ok()?;
    let r = call_method(
        &mut sb.cpu,
        &mut sb.mmu,
        &sb.registry,
        &mut sb.host,
        filter,
        crate::com::SLOT_BASEFILTER_ENUM_PINS,
        &[scratch],
    );
    let pp = sb.mmu.load32(scratch).unwrap_or(0);
    if !matches!(r, Ok(0)) || pp == 0 {
        return None;
    }
    sb.host.com.intern(pp, None);

    // Walk Next() up to 16 times, capturing every pin pointer.
    let mut pins: Vec<u32> = Vec::new();
    for _ in 0..16 {
        let pin_slot = sb.host.arena_alloc(8).ok()?;
        sb.mmu.write_initializer(pin_slot, &[0u8; 8]).ok()?;
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            pp,
            crate::com::SLOT_ENUMPINS_NEXT,
            &[1, pin_slot, pin_slot + 4],
        );
        let pin = sb.mmu.load32(pin_slot).unwrap_or(0);
        let fetched = sb.mmu.load32(pin_slot + 4).unwrap_or(0);
        match r {
            Ok(0) if pin != 0 && fetched == 1 => {
                sb.host.com.intern(pin, None);
                pins.push(pin);
            }
            Ok(1) => {
                // S_FALSE — possibly with one last pin populated.
                if pin != 0 && fetched == 1 {
                    sb.host.com.intern(pin, None);
                    pins.push(pin);
                }
                break;
            }
            _ => break,
        }
    }
    let _ = sb.com_release(pp);

    // Pick the first pin matching `direction` (skipping `skip`).
    let mut chosen: Option<u32> = None;
    for &pin in &pins {
        if let Some(s) = skip {
            if pin == s {
                continue;
            }
        }
        let dir_slot = sb.host.arena_alloc(4).ok()?;
        let _ = sb.mmu.write_initializer(dir_slot, &0xFFu32.to_le_bytes());
        let r = call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            pin,
            crate::com::SLOT_PIN_QUERY_DIRECTION,
            &[dir_slot],
        );
        if !matches!(r, Ok(0)) {
            continue;
        }
        let dir = sb.mmu.load32(dir_slot).unwrap_or(u32::MAX);
        if dir == direction {
            chosen = Some(pin);
            break;
        }
    }
    // Release every pin we won't return (the chosen one stays
    // owned by the caller).
    for pin in pins {
        if Some(pin) == chosen {
            continue;
        }
        let _ = sb.com_release(pin);
    }
    chosen
}

impl Decoder for SandboxedDshowDecoder {
    fn codec_id(&self) -> &CodecId {
        &self.codec_id
    }

    fn send_packet(&mut self, packet: &Packet) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::other(
                "vfw discovery (DShow): receive_frame must be called before sending another packet",
            ));
        }
        self.ensure_open()?;
        self.pending = Some(packet.clone());
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<Frame> {
        let packet = match self.pending.take() {
            Some(p) => p,
            None => {
                return if self.eof {
                    Err(Error::Eof)
                } else {
                    Err(Error::NeedMore)
                };
            }
        };
        let mip = self.mem_input_pin;
        if mip == 0 {
            return Err(Error::other(
                "vfw discovery (DShow): IMemInputPin not bound; ensure_open did not complete",
            ));
        }
        // Round 34 — pick the allocator we negotiated in
        // `ensure_open`: the codec's own when GetAllocator+SetProps+
        // Commit succeeded, otherwise the host fallback.
        let allocator = if self.using_codec_allocator {
            self.codec_allocator
        } else {
            self.host_allocator
        };
        let from_codec = self.using_codec_allocator;
        let sb = self
            .sandbox
            .as_mut()
            .ok_or_else(|| Error::other("vfw discovery (DShow): no sandbox"))?;

        // Acquire a sample from the chosen allocator: emulate the
        // codec calling `IMemAllocator::GetBuffer(&sample, 0, 0, 0)`
        // by driving the vtable directly.  The codec allocator path
        // is a real guest call (mpg4ds32 returns a sample backed by
        // codec-managed guest memory it walks from inside `Receive`);
        // the host-allocator path executes the host Rust stub.
        let pp = sb
            .host
            .arena_alloc(4)
            .map_err(|e| Error::other(format!("vfw discovery (DShow): arena: {e}")))?;
        sb.mmu
            .write_initializer(pp, &0u32.to_le_bytes())
            .map_err(|e| Error::other(format!("vfw discovery (DShow): mmu init: {e}")))?;
        let r_gb = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            allocator,
            crate::com::SLOT_MEMALLOCATOR_GET_BUFFER,
            &[pp, 0, 0, 0],
        )
        .map_err(|e| Error::other(format!("vfw discovery (DShow): GetBuffer trapped: {e}")))?;
        if r_gb != 0 {
            return Err(Error::other(format!(
                "vfw discovery (DShow): {} allocator GetBuffer returned \
                 {r_gb:#010x} (pool exhausted?)",
                if from_codec { "codec" } else { "host" }
            )));
        }
        let sample = sb
            .mmu
            .load32(pp)
            .map_err(|e| Error::other(format!("vfw discovery (DShow): load sample slot: {e}")))?;
        if sample == 0 {
            return Err(Error::other(format!(
                "vfw discovery (DShow): {} GetBuffer succeeded but sample = 0",
                if from_codec { "codec" } else { "host" }
            )));
        }

        // Stage the packet bytes + sync flag into the sample.  The
        // host-allocator path uses `media_sample_set_payload` (which
        // pokes our known sample layout directly); the codec-
        // allocator path goes through the standard IMediaSample
        // vtable methods (`GetPointer` + `SetActualDataLength` +
        // `SetSyncPoint`) because the codec's sample uses an
        // internal layout we cannot assume.
        if from_codec {
            // GetPointer(BYTE** ppBuffer) → byte address of payload.
            let pp_buf = sb.host.arena_alloc(4).map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec sample GetPointer arena: {e}"
                ))
            })?;
            sb.mmu
                .write_initializer(pp_buf, &0u32.to_le_bytes())
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): codec sample GetPointer init: {e}"
                    ))
                })?;
            let r_gp = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                sample,
                crate::com::SLOT_MEDIASAMPLE_GET_POINTER,
                &[pp_buf],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec sample GetPointer trapped: {e}"
                ))
            })?;
            if r_gp != crate::com::S_OK {
                return Err(Error::other(format!(
                    "vfw discovery (DShow): codec sample GetPointer returned \
                     {r_gp:#010x}"
                )));
            }
            let buf = sb.mmu.load32(pp_buf).unwrap_or(0);
            if buf == 0 {
                return Err(Error::other(
                    "vfw discovery (DShow): codec sample GetPointer wrote NULL buffer",
                ));
            }
            // Write the payload byte-by-byte (page-safe).
            for (i, &b) in packet.data.iter().enumerate() {
                sb.mmu.store8(buf + i as u32, b).map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): codec sample payload write: {e}"
                    ))
                })?;
            }
            // SetActualDataLength(packet.data.len()).
            let _ = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                sample,
                crate::com::SLOT_MEDIASAMPLE_SET_ACTUAL_DATA_LENGTH,
                &[packet.data.len() as u32],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec sample SetActualDataLength: {e}"
                ))
            })?;
            // SetSyncPoint(packet.flags.keyframe).
            let _ = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                sample,
                crate::com::SLOT_MEDIASAMPLE_SET_SYNC_POINT,
                &[u32::from(packet.flags.keyframe)],
            )
            .map_err(|e| {
                Error::other(format!(
                    "vfw discovery (DShow): codec sample SetSyncPoint: {e}"
                ))
            })?;
        } else {
            sb.media_sample_set_payload(sample, &packet.data, packet.flags.keyframe)
                .map_err(|e| {
                    Error::other(format!(
                        "vfw discovery (DShow): media_sample_set_payload: {e}"
                    ))
                })?;
        }

        // Snapshot trace ring before Receive so we can document
        // what the codec did.  Round 36 — bumped to 4096 entries
        // so on trap we can see the chain of function calls leading
        // up to the failure (the prior 64-entry ring barely covered
        // the failing function's prolog).
        sb.cpu.enable_trace_ring(4096);

        // Round 40+41 — diagnostic register-snapshot watchpoints
        // around Transform.  Round 40's snapshots localised a
        // 4-byte stack imbalance to `pop ebx` at RVA `0x4065c4`;
        // by walking the per-call ESP delta we determined the
        // imbalance was introduced by the FIRST call site,
        // `0x4064d4: call [ecx+0x1c]` — `IMemAllocator::GetBuffer`,
        // a 5-arg stdcall whose host stub was registered with
        // `arg_dwords=4`.  The dispatcher's callee-cleanup popped
        // 16 bytes instead of 20, leaving esp 4 bytes too low and
        // causing Transform's matched `pop ebx` to read junk.
        // Round 41 fixed the registration (now `arg_dwords=5`);
        // the watchpoints below remain so any future regression
        // re-traps with the bisect data immediately to hand.
        let r40_module_base = sb.host.primary_module_base;
        for off in [
            0x002626u32,
            0x002634,
            0x00263b,
            0x0025a2,
            0x0025a4,
            0x0025a8,
            0x0025ab,
            0x0025ae,
            0x002620,
            0x002621,
            0x006479,
            0x0064a3,
            0x0064f3,
            0x006545,
            0x00655e,
            0x0065c0,
            0x0065c4,
        ] {
            sb.cpu
                .add_register_watchpoint(r40_module_base.wrapping_add(off));
        }
        sb.cpu.register_snapshots_cap = 64;

        // Round 36 — dump `[mip+0..0x100]` so the diagnostic carries
        // the per-field state of the codec's own IMemInputPin
        // object before the Receive call.  Helps identify which
        // field at +0x8c (the trap site) the codec expected us to
        // populate.
        let mut mip_state: Vec<String> = Vec::new();
        for off in (0..=0xa0u32).step_by(4) {
            if let Ok(v) = sb.mmu.load32(mip + off) {
                mip_state.push(format!("[+{off:#04x}]={v:#010x}"));
            }
        }
        log::debug!(
            "vfw discovery (DShow): pre-Receive mip={mip:#010x} state: {:?}",
            mip_state
        );

        // Round 38 — also stamp `mip` into the diagnostic body so
        // r39 can confirm `mip == filter_base` (or not) without
        // recomputing.
        let r38_mip = mip;

        // Round 38 — pre-Receive sanity check.  Round 37 wired
        // `IPin::QueryPinInfo` + `ConnectedTo` + `IBaseFilter::
        // QueryFilterInfo`, but the trap at MPG4DS32 RVA `0x7184`
        // (= `repe cmpsd` inside the `IsEqualGUID(this+0x1c, &kIID)`
        // helper at `0x7176`) persisted because `[ebx+0x8c]` was
        // still NULL when reached via the Receive → Transform call
        // chain.
        //
        // Static disassembly of MPG4DS32.AX RVA `0x7176`/`0x2da7`/
        // `0x6473`/`0x6560`/`0x2626`/`0x25a2`/`0x69ab`/`0x5e34`
        // (function-table walk via `objdump -d -M intel`) identifies:
        //
        //  * `0x69ab` = `CTransformInputPin::Receive(IMediaSample*)`
        //    — calls a worker `0x5e34` then delegates to filter
        //    vtable slot 21 (`[+0x54]`) = `0x25a2`.
        //  * `0x25a2` = `CTransformFilter::Receive(IMediaSample*)`
        //    — calls preprocess helper `0x6fee` (which calls
        //    `sample->GetTime` at vtable slot 5).  Our
        //    `sample_get_time` returns `VFW_S_NO_STOP_TIME`
        //    (`0x00040007`, not `S_OK`), which the codec treats
        //    as failure: `xor eax, eax; jmp 0x70f1` returning 0.
        //    `0x25a2` then takes the `0x261a` failure branch and
        //    calls `0x6473` (`Transform`) anyway.
        //  * `0x6473` = `CTransformFilter::Transform(in, out**)` —
        //    reads `[filter+0x8c]` (input pin pointer) and
        //    dereferences `pin+0xa8` for the connection media-type
        //    sub-struct.  Returns S_OK from its 0x6560 cleanup
        //    branch even when `inSample->GetMediaTime` returns the
        //    `VFW_E_MEDIA_TIME_NOT_SET` we hand back.
        //  * After `0x6473` returns to `0x25a2` at `0x402626`, the
        //    next instruction at `0x402634-0x40263b` does
        //    `mov eax, [ebx]; lea ecx, [ebp+8]; push ecx; push ebx;
        //    call [eax+0x34]`.  `ebx` is the SAMPLE pointer
        //    (function arg 1, never overwritten on this branch);
        //    `[eax+0x34]` is slot 13 of its vtable.  The trap shows
        //    execution lands at codec RVA `0x2da7`, and the only
        //    vtable in the binary with `0x2da7` at slot 13 is
        //    `0x1c4269f4` — the codec's PRIMARY C++ class vtable
        //    for `CTransformFilter`/its derived class.
        //
        // The implication is that the SAMPLE we're handing to
        // `Receive` has its first dword == `0x1c4269f4` — i.e. the
        // codec's `IMemAllocator::GetBuffer` returned an object
        // whose vtable IS the filter's primary vtable, NOT a
        // `CMediaSample` vtable.  This can only happen if the
        // codec re-purposed the filter pointer as a "sample" stub
        // (some allocator implementations stamp a sentinel vtable
        // for diagnostics), or our `[mip+0x40]` / `[mip+0x48]`
        // back-references (both `0x60000110` per round-37 mip
        // dump) are being mistaken for samples.
        //
        // For r38 the goal is observation, not speculation.  Dump
        // the SAMPLE's first 0x40 bytes + the codec's filter
        // primary-vtable view at `[filter]` so r39 can see whether
        // the sample REALLY has the filter vtable, or whether the
        // call chain actually walks through some other intermediate
        // object.  Also dump `[filter+0x8c]` (the C++ `m_pInput`
        // field whose NULL we keep crashing on).
        let mut sample_state: Vec<String> = Vec::new();
        for off in (0..=0xa0u32).step_by(4) {
            if let Ok(v) = sb.mmu.load32(sample + off) {
                sample_state.push(format!("[+{off:#04x}]={v:#010x}"));
            }
        }
        let sample_vtbl = sb.mmu.load32(sample).unwrap_or(0);
        let sample_slot13 = if sample_vtbl != 0 {
            sb.mmu.load32(sample_vtbl + 0x34).unwrap_or(0)
        } else {
            0
        };
        // The IBaseFilter pointer we hold is the IBaseFilter
        // SUB-INTERFACE of the C++ class, which the constructor at
        // RVA `0x24ca` stamps at `[filter_base + 0xc] = 0x1c4269b8`.
        // The C++ class's primary vtable is at `[filter_base + 0]
        // = 0x1c4269f4`, and its `m_pInput` (the field referenced
        // as `[ebx+0x8c]` in the trap function `0x2da7`) is at
        // `[filter_base + 0x8c]`.  Hence: `filter_base =
        // self.filter - 0xc`, and `[filter_base + 0x8c] =
        // [self.filter + 0x80]`.
        let filter_base = self.filter.wrapping_sub(0xc);
        let filter_primary_vtbl = sb.mmu.load32(filter_base).unwrap_or(0);
        let filter_pin_in = sb.mmu.load32(filter_base.wrapping_add(0x8c)).unwrap_or(0);
        let filter_pin_out = sb.mmu.load32(filter_base.wrapping_add(0x90)).unwrap_or(0);
        log::debug!(
            "vfw discovery (DShow): r38 pre-Receive sanity: \
             sample={sample:#010x} sample[+0]={sample_vtbl:#010x} \
             sample_vtbl[+0x34]={sample_slot13:#010x} \
             self.filter={:#010x} filter_base={filter_base:#010x} \
             [filter_base+0]={filter_primary_vtbl:#010x} \
             [filter_base+0x8c]={filter_pin_in:#010x} \
             [filter_base+0x90]={filter_pin_out:#010x}",
            self.filter,
        );

        // Round 38 — if `[filter_base+0x8c]` is NULL, force the
        // codec to lazy-allocate its input pin via slot 7 of its
        // primary C++ class vtable (per static disasm:
        // `[0x269f4 + 0x1c] = 0x33fd`, the per-CLSID GetPin helper
        // that runs `new(0xe8); ctor(0, this, &hr_local,
        // vtable=0x429264); [filter_base+0x8c] = pin`).
        //
        // Round 27's `EnumPins → Next` walked a DIFFERENT vtable
        // (the IBaseFilter COM sub-vtable at `0x269b8`, slot 7 of
        // which is `0x4ace = EnumPins`, NOT GetPin), so the
        // PRIMARY-vtable `m_pInput` field never got lazy-
        // initialized through that path.  IEnumPins::Next does
        // call back into the filter via `[edx+0x1c]` (slot 7 of
        // FILTER's primary vtable — see `0x404f25`), but that
        // call-target is the FILTER's primary vtable, not the
        // IBaseFilter sub-vtable, so the lazy-init only happens
        // when the codec's IEnumPins enumerator is walked.  We DO
        // walk that, but it appears to construct an enumerator
        // bound to a DIFFERENT this-pointer than the one we hold
        // via `self.filter`.
        let r38_force_target = filter_base; // C++ class base
        if filter_pin_in == 0 {
            log::debug!(
                "vfw discovery (DShow): r38 [filter_base+0x8c]=NULL — \
                 calling filter_base->primary_slot7 to force input-pin \
                 allocation"
            );
            // Slot 7 of the filter's primary C++ vtable. We need
            // to pass `this = filter_base` (NOT `self.filter`),
            // since the C++ class methods use offset-0 vtable.
            let _ = crate::com::call::call_method(
                &mut sb.cpu,
                &mut sb.mmu,
                &sb.registry,
                &mut sb.host,
                r38_force_target,
                7,
                &[0],
            );
            let now = sb.mmu.load32(filter_base.wrapping_add(0x8c)).unwrap_or(0);
            log::debug!("vfw discovery (DShow): r38 post-force [filter_base+0x8c]={now:#010x}");
        }

        // Round 39 — capture the OUTPUT pin's allocator pointer
        // (`[output_pin+0x98]`) + its vtable head, so we know
        // whether the codec's `m_pOutput->m_pAllocator` is wired
        // through to one of our host allocators (vtable in the
        // `0xfffe...` thunk band).
        let output_alloc = if filter_pin_out != 0 {
            sb.mmu.load32(filter_pin_out + 0x98).unwrap_or(0)
        } else {
            0
        };
        let output_alloc_vtbl0 = if output_alloc != 0 {
            sb.mmu.load32(output_alloc).unwrap_or(0)
        } else {
            0
        };
        let output_alloc_qi_thunk = if output_alloc_vtbl0 != 0 {
            sb.mmu.load32(output_alloc_vtbl0).unwrap_or(0)
        } else {
            0
        };
        // Round 43 — dump the OUTPUT allocator's first 0x40 bytes
        // pre-Receive so a future trap can be cross-referenced
        // against round 42's `cur+36 = 0xffff0223` failure.  Slots
        // of interest:
        //   `output_alloc+0`  vtbl_ptr
        //   `output_alloc+4`  refcount
        //   `output_alloc+8`  sample_pool_head (the walk start)
        //   `output_alloc+12` committed flag (0=decommitted, 1=committed)
        let mut r43_oalloc_state: Vec<String> = Vec::new();
        if output_alloc != 0 {
            for off in (0..=0x3cu32).step_by(4) {
                if let Ok(v) = sb.mmu.load32(output_alloc + off) {
                    r43_oalloc_state.push(format!("[+{off:#04x}]={v:#010x}"));
                }
            }
        }
        // Round 43 — also walk the OUTPUT pool's first 4 entries
        // (head + next-links) to confirm the linked list is intact
        // before the codec's GetBuffer call.  Each pool entry's
        // `+32` field links to the next.  A NULL or non-arena
        // value identifies the pool tail / corruption.
        let mut r43_oalloc_pool: Vec<String> = Vec::new();
        if output_alloc != 0 {
            let mut cur = sb.mmu.load32(output_alloc + 8).unwrap_or(0);
            for i in 0..6u32 {
                if cur == 0 {
                    r43_oalloc_pool.push(format!("[{i}]=NULL"));
                    break;
                }
                let in_use = sb.mmu.load32(cur + 36).unwrap_or(0xDEAD_BEEF);
                let next = sb.mmu.load32(cur + 32).unwrap_or(0xDEAD_BEEF);
                r43_oalloc_pool.push(format!(
                    "[{i}]={cur:#010x} in_use={in_use:#x} next={next:#010x}"
                ));
                cur = next;
            }
        }

        let r38_pre_receive = format!(
            "sample={sample:#010x} sample_vtbl={sample_vtbl:#010x} \
             sample_vtbl[+0x34]={sample_slot13:#010x} \
             mip={r38_mip:#010x} self.filter={:#010x} \
             filter_base={filter_base:#010x} \
             [filter_base+0]={filter_primary_vtbl:#010x} \
             [filter_base+0x8c]={filter_pin_in:#010x} \
             [filter_base+0x90]={filter_pin_out:#010x} \
             output_alloc={output_alloc:#010x} \
             output_alloc_vtbl0={output_alloc_vtbl0:#010x} \
             output_alloc_qi_thunk={output_alloc_qi_thunk:#010x} \
             r43_oalloc_state={r43_oalloc_state:?} \
             r43_oalloc_pool={r43_oalloc_pool:?} \
             sample_state={sample_state:?}",
            self.filter,
        );

        // Drive IMemInputPin::Receive(sample).  On trap, snapshot
        // the CPU register file + the last 8 entries of the trace
        // ring so the round-36+ diagnostic doesn't require a
        // separate trace-feature build.  The last trace ring entry
        // is the entry-EIP of the failing instruction (set in
        // `Cpu::step` BEFORE the opcode dispatch); regs reflect
        // state at the point of the trap.
        let r_recv = match crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            mip,
            crate::com::SLOT_MEMINPUTPIN_RECEIVE,
            &[sample],
        ) {
            Ok(v) => v,
            Err(e) => {
                use crate::emulator::regs::Reg32;
                let ring = sb.cpu.trace_ring.clone();
                let trap_eip = ring.last().copied().unwrap_or(sb.cpu.regs.eip);
                let module_base = sb.host.primary_module_base;
                let rva = trap_eip.wrapping_sub(module_base);
                // Snapshot the trap-time integer register file
                // into locals so we can later take a mutable
                // borrow of `sb.cpu` (Round 40 watchpoint drain)
                // without a use-after-mut conflict.
                let trap_eax = sb.cpu.regs.get32(Reg32::Eax);
                let trap_ecx = sb.cpu.regs.get32(Reg32::Ecx);
                let trap_edx = sb.cpu.regs.get32(Reg32::Edx);
                let trap_ebx = sb.cpu.regs.get32(Reg32::Ebx);
                let trap_ebp = sb.cpu.regs.get32(Reg32::Ebp);
                let trap_esi = sb.cpu.regs.get32(Reg32::Esi);
                let trap_edi = sb.cpu.regs.get32(Reg32::Edi);
                let ring_tail: Vec<String> = ring
                    .iter()
                    .rev()
                    .take(8)
                    .map(|e| format!("{e:#010x}"))
                    .collect();
                // Round 36 — capture the unique sequence of RVAs
                // visited (call-site chain).  Compress the ring by
                // emitting one entry per "function entry" — i.e.
                // any RVA that's the target of a CALL or any new
                // RVA region.  We do this naively by detecting
                // backward jumps: when eip[i] < eip[i-1] - 0x100
                // or eip[i] > eip[i-1] + 0x40 we've crossed a
                // function boundary.
                let mut call_chain: Vec<u32> = Vec::new();
                let mut prev: u32 = 0;
                for &eip in ring.iter() {
                    let rva_e = eip.wrapping_sub(module_base);
                    if prev == 0 || (eip >= prev + 0x40) || (eip + 0x100 < prev) {
                        call_chain.push(rva_e);
                    }
                    prev = eip;
                }
                // Last 24 entries of the chain.
                let chain_tail: Vec<String> = call_chain
                    .iter()
                    .rev()
                    .take(24)
                    .rev()
                    .map(|e| format!("{e:#010x}"))
                    .collect();
                // Round 39 — also expose the LAST 64 raw RVAs from
                // the trace ring, so we can see the per-instruction
                // path that the heuristic chain compresses.
                // Round 39 — also expose the LAST 32 raw RVAs from
                // the trace ring so the heuristic-compressed
                // `call_chain` can be cross-checked.
                let raw_tail: Vec<String> = ring
                    .iter()
                    .rev()
                    .take(32)
                    .rev()
                    .map(|e| format!("{:#010x}", e.wrapping_sub(module_base)))
                    .collect();
                // Round 39 — re-read the input + output pool head
                // samples' vtable slot 13 RIGHT NOW (post-trap) so
                // we can see whether the codec mutated them.  We
                // expect both to remain `0xfffe03a0` (host thunk);
                // a different value means the codec's transform
                // wrote through pSample's vtable.
                let recheck_sample_vtbl = sb.mmu.load32(sample).unwrap_or(0);
                let recheck_sample_slot13 = if recheck_sample_vtbl != 0 {
                    sb.mmu
                        .load32(recheck_sample_vtbl.wrapping_add(0x34))
                        .unwrap_or(0)
                } else {
                    0
                };
                // Round 40 — drain the register-snapshot
                // watchpoints armed before the call.  Each entry
                // is `(eip, [eax, ecx, edx, ebx, esp, ebp, esi,
                // edi])`.  The watchpoints fire BEFORE their
                // instruction executes, so the snapshot at
                // `0x002626` reflects the registers exactly as
                // Transform left them; the snapshot at `0x00263b`
                // is what the codec hands to the slot-13 call.
                // Drain BOTH the register snapshots AND the
                // memory probes captured at the same hits.
                // `take_memory_snapshots` MUST run before
                // `clear_register_watchpoints` (which clears
                // the memory snapshots too).
                let r40_mem_raw = sb.cpu.take_memory_snapshots();
                let r40_snaps_raw = sb.cpu.clear_register_watchpoints();
                let r40_snaps: Vec<String> = r40_snaps_raw
                    .iter()
                    .map(|(eip, regs)| {
                        let r_rva = eip.wrapping_sub(module_base);
                        format!(
                            "rva={r_rva:#06x} eax={:#010x} ecx={:#010x} \
                             edx={:#010x} ebx={:#010x} esp={:#010x} \
                             ebp={:#010x} esi={:#010x} edi={:#010x}",
                            regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]
                        )
                    })
                    .collect();
                // Round 40 — when the watchpoints captured ebp at
                // `0x002626`, also dump `[ebp+8]` (= the function
                // arg-1 slot, which Receive's prolog uses to bind
                // its `ebx`).  If `[ebp+8]` here disagrees with
                // ebx at the same site, hypothesis (b) is
                // confirmed: something clobbered ebx between
                // prolog (where `ebx = [ebp+8]`) and the
                // return-from-Transform IP.  If the two agree but
                // are 0x60000110 (filter_base), then `[ebp+8]`
                // itself was overwritten — look for a recent
                // SetProperties write at that address.
                // Use the MEMORY SNAPSHOTS captured at watchpoint
                // time (NOT trap time).  The probe order is fixed
                // in `Cpu::step`'s watchpoint handler:
                //   probe[0] = [esp]
                //   probe[1] = [esp+4]
                //   probe[2] = [ebp+8]
                //   probe[3] = [ebp-0x50]   (saved-ebx slot in
                //                            standard MSVC frame)
                let mut r40_arg1: Vec<String> = Vec::new();
                for (eip, mem) in &r40_mem_raw {
                    let r_rva = eip.wrapping_sub(module_base);
                    let p_esp = mem[0].1;
                    let p_esp4 = mem[1].1;
                    let p_ebp_p8 = mem[2].1;
                    let p_ebp_m50 = mem[3].1;
                    let a_ebp_p8 = mem[2].0;
                    let a_ebp_m50 = mem[3].0;
                    r40_arg1.push(format!(
                        "rva={r_rva:#06x} [ebp+8]@{a_ebp_p8:#010x}={p_ebp_p8:#010x} \
                         [esp]={p_esp:#010x} [esp+4]={p_esp4:#010x} \
                         [ebp-0x50]@{a_ebp_m50:#010x}={p_ebp_m50:#010x}"
                    ));
                }
                // Round 40 — also expose the input pin's pInSample
                // we passed in (via the outer Receive call).  The
                // sandbox's `sample` local is the IMediaSample we
                // handed to IMemInputPin::Receive; if ebx at
                // `0x002626` doesn't equal `sample`, something
                // mid-Receive substituted a different pointer.
                let r40_expected_pin_sample = sample;
                let r40_expected_filter_base = self.filter.wrapping_sub(0xc);
                // Walk the stack frame: dump esp..esp+32 dwords as
                // potential return addresses + saved registers, so
                // a follow-up disasm pass can identify the caller.
                let esp = sb.cpu.regs.esp();
                let mut stack_frame: Vec<String> = Vec::new();
                // Round 39 — widened from 16 → 32 dwords so we can
                // walk both the inner `0x7176` frame and the
                // outer `0x25a2` frame's locals (`[ebp-0x4]` =
                // pSampleOut, `[ebp+0x8]` = pInSample).  The first
                // outer-frame slot of interest sits at ~`esp+0x4c`
                // (return EIP) and the args at `esp+0x50/0x54`.
                for i in 0..32u32 {
                    if let Ok(v) = sb.mmu.load32(esp + i * 4) {
                        let v_rva = v.wrapping_sub(module_base);
                        // Filter to values that look like they
                        // could be code RVAs in the codec (< 0x1_0000_0000
                        // and > 0).
                        stack_frame.push(format!(
                            "[esp+{:02x}]={:#010x} (rva={:#010x})",
                            i * 4,
                            v,
                            v_rva
                        ));
                    }
                }
                return Err(Error::other(format!(
                    "vfw discovery (DShow): Receive trapped: {e} \
                     [trap_eip={trap_eip:#010x} rva={rva:#010x} \
                     eax={trap_eax:#010x} ecx={trap_ecx:#010x} \
                     edx={trap_edx:#010x} ebx={trap_ebx:#010x} \
                     esp={esp:#010x} ebp={trap_ebp:#010x} \
                     esi={trap_esi:#010x} edi={trap_edi:#010x} \
                     recheck_sample_vtbl={recheck_sample_vtbl:#010x} \
                     recheck_sample_slot13={recheck_sample_slot13:#010x} \
                     r40_expected_pin_sample={r40_expected_pin_sample:#010x} \
                     r40_expected_filter_base={r40_expected_filter_base:#010x} \
                     r40_snaps={r40_snaps:?} r40_arg1={r40_arg1:?} \
                     trace_tail={ring_tail:?} call_chain={chain_tail:?} \
                     raw_tail={raw_tail:?} stack={stack_frame:?} \
                     mip_state={mip_state:?} r38_pre={r38_pre_receive}]"
                )));
            }
        };

        // Round 41 — drain the diagnostic watchpoints on the
        // success path too, so they don't accumulate across
        // back-to-back Receive calls.  (On the trap branch above
        // they're drained as part of the diagnostic blob.)
        let _ = sb.cpu.take_memory_snapshots();
        let _ = sb.cpu.clear_register_watchpoints();

        // Round 43 — release the INPUT sample back to its allocator
        // so the next `send_packet` can draw a fresh slot.  Without
        // this, frame N+1's `GetBuffer` ladders past the (still
        // marked `in_use=1`) earlier samples until the pool is
        // exhausted (round 42 hit `0x80040211 = VFW_E_NOT_COMMITTED`
        // on frame 4 of `gop-30-352x288` for exactly this reason).
        // We call `IMemAllocator::ReleaseBuffer` on whichever
        // allocator we drew the sample from — codec's own when
        // `using_codec_allocator`, else the host fallback.  Errors
        // are swallowed (best-effort cleanup; the codec may have
        // already released or refused the sample).
        let _ = crate::com::call::call_method(
            &mut sb.cpu,
            &mut sb.mmu,
            &sb.registry,
            &mut sb.host,
            allocator,
            crate::com::SLOT_MEMALLOCATOR_RELEASE_BUFFER,
            &[sample],
        );

        // Round 31 — drain the host-side queue populated by the
        // downstream `HostIMemInputPin::Receive` callback.
        if let Some(rs) = sb.pop_received_sample() {
            return surface_received_dshow_frame(rs, packet.pts, self.width, self.height);
        }

        // Capture trace ring head / tail for diagnostics.
        let ring = sb.cpu.trace_ring.clone();
        let ring_summary = if ring.is_empty() {
            String::from("empty")
        } else {
            let head: Vec<String> = ring.iter().take(4).map(|e| format!("{e:#010x}")).collect();
            let tail: Vec<String> = ring
                .iter()
                .rev()
                .take(4)
                .map(|e| format!("{e:#010x}"))
                .collect();
            format!("len={} head={:?} tail={:?}", ring.len(), head, tail)
        };

        // Per round-31 goal: prefer Eof when codec accepted input
        // but emitted nothing (vs round 30's Unsupported path).
        if r_recv == 0 {
            log::debug!(
                "vfw discovery (DShow): Receive ok but no output sample queued \
                 (trace_ring {ring_summary})"
            );
            Err(Error::Eof)
        } else {
            Err(Error::unsupported(format!(
                "vfw discovery (DShow): IMemInputPin::Receive → {r_recv:#010x}; \
                 no decoded sample emitted (trace_ring {ring_summary})"
            )))
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.eof = true;
        Ok(())
    }
}

impl Drop for SandboxedDshowDecoder {
    fn drop(&mut self) {
        if let Some(sb) = self.sandbox.as_mut() {
            if self.mem_input_pin != 0 {
                let _ = sb.com_release(self.mem_input_pin);
            }
            if self.input_pin != 0 {
                let _ = sb.com_release(self.input_pin);
            }
            if self.filter != 0 {
                let _ = sb.com_release(self.filter);
            }
            crate::com::host_iface_r31::clear_queue(&sb.host);
        }
    }
}

/// Round 31 — turn a host-captured `ReceivedSample` into a
/// `Frame::Video`.  Assumes the codec emitted RGB24 in the
/// negotiated dimensions; pads / truncates to `stride * height`.
/// Bottom-up storage is flipped to top-down to match the VfW
/// path's surface convention.
fn surface_received_dshow_frame(
    rs: crate::com::host_iface_r31::ReceivedSample,
    pts: Option<i64>,
    width: u32,
    height: u32,
) -> Result<Frame> {
    let w = width as usize;
    let h = height as usize;
    let stride = w * 3;
    let expected = stride * h;
    let raw = if rs.data.len() >= expected {
        rs.data[..expected].to_vec()
    } else {
        let mut padded = vec![0u8; expected];
        padded[..rs.data.len()].copy_from_slice(&rs.data);
        padded
    };
    let mut data = vec![0u8; expected];
    if h > 0 && stride > 0 {
        for row in 0..h {
            let src_off = (h - 1 - row) * stride;
            let dst_off = row * stride;
            data[dst_off..dst_off + stride].copy_from_slice(&raw[src_off..src_off + stride]);
        }
    }
    Ok(Frame::Video(VideoFrame {
        pts,
        planes: vec![VideoPlane { stride, data }],
    }))
}

/// Stream-level pixel format for [`Frame::Video`]s emitted by
/// [`SandboxedVfwDecoder`]. The decoder always renders to
/// [`PixelFormat::Bgr24`] — VfW codecs reliably honour BI_RGB
/// 24bpp output (round-24 confirmed mpg4c32 rejects 32bpp + most
/// YUV outputs); the bottom-up storage is flipped to top-down
/// before the frame leaves the decoder, so consumers always
/// receive a row-major BGR24 buffer.
pub fn output_pixel_format() -> PixelFormat {
    PixelFormat::Bgr24
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn codec_id_format_matches_spec() {
        assert_eq!(
            codec_id_for(&PathBuf::from("/tmp/MPG4DS32.AX"), "MP43"),
            "vfw_mp43_mpg4ds32"
        );
        assert_eq!(
            codec_id_for(&PathBuf::from("foo/IR32_32.DLL"), "IV31"),
            "vfw_iv31_ir32_32"
        );
    }

    #[test]
    fn codec_id_sanitises_dashes_and_dots() {
        // dashes / dots / spaces collapse to underscores.
        assert_eq!(
            codec_id_for(&PathBuf::from("/p/some-name.with.dot.dll"), "ABCD"),
            "vfw_abcd_some_name_with_dot"
        );
    }

    #[test]
    fn record_table_round_trip() {
        let id = "vfw_test_record_round_trip_unique";
        register_factory_for_id(
            id,
            DiscoveryRecord {
                dll_path: PathBuf::from("/x/y.dll"),
                fourcc: "MP43".to_string(),
                kind: Kind::Vfw,
                clsid: None,
            },
        );
        let r = lookup_record(id).expect("present");
        assert_eq!(r.fourcc, "MP43");
        assert_eq!(r.kind, Kind::Vfw);
    }

    #[test]
    fn make_decoder_unknown_id_errors_cleanly() {
        let params = CodecParameters::video(CodecId::new(
            "vfw_unknown_codec_id_should_not_match_anything",
        ));
        let r = make_decoder(&params);
        assert!(r.is_err());
    }

    #[test]
    fn make_decoder_dshow_constructs_decoder_without_dll() {
        // Round 30 — DShow path now constructs a `SandboxedDshowDecoder`
        // at make_decoder time; the actual DLL load + handshake happen
        // lazily on the first `send_packet`. Constructor only validates
        // the FourCC. (Round 29 used to return Err(Unsupported) here.)
        let id = "vfw_dshow_make_decoder_test_round30";
        register_factory_for_id(
            id,
            DiscoveryRecord {
                dll_path: PathBuf::from("/dev/null"),
                fourcc: "WMV3".to_string(),
                kind: Kind::DirectShow,
                clsid: Some("{82CCD3E0-F71A-11D0-9FE5-00609778EA66}".into()),
            },
        );
        let params = CodecParameters::video(CodecId::new(id));
        let decoder = make_decoder(&params).expect("DShow make_decoder constructs lazily");
        assert_eq!(decoder.codec_id().as_str(), id);
    }
}

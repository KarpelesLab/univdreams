//! Per-DLL probe.
//!
//! Round 28 keeps this conservative: we run each candidate
//! through a fresh [`crate::Sandbox`], try the VfW path first
//! (`Sandbox::load → DriverProc DRV_LOAD → ICOpen → ICGetInfo`),
//! and fall back to a small static CLSID list driven through
//! `DllGetClassObject` for DirectShow filters. Anything that
//! doesn't load or doesn't respond to either path is recorded as
//! [`Kind::Unsupported`].
//!
//! All work runs inside the bounded MMU emulator, so a malformed
//! DLL CAN'T panic the host — it just trips a CPU trap that
//! bubbles back as `Sandbox::load` / `Sandbox::call_*` `Err(_)`.
//!
//! The FourCC sweep list mirrors the existing `wmpcdcs8-2001`
//! fixture corpus; we don't brute-force every possible 4-byte
//! permutation — false positives on synthetic VIDC handlers
//! would just inflate the on-disk cache.

use crate::Sandbox;

/// Static list of FourCCs we sweep through `ICOpen` for every
/// candidate DLL. Mirrors the codecs we already have working
/// fixtures for in the round-3..27 test suite.
const VFW_FOURCC_CANDIDATES: &[&[u8; 4]] = &[
    b"MP43", b"MP42", b"MPG4", b"DIV3", b"IV31", b"IV41", b"IV50", b"CVID", b"MJPG",
];

/// `mmioFOURCC('V','I','D','C')` — VfW video-codec driver type.
const FCC_TYPE_VIDC: u32 = u32::from_le_bytes(*b"VIDC");

/// Static list of CLSIDs we try with `DllGetClassObject` when the
/// VfW probe fails. Round-28 seeded this with wmpcdcs8-2001's
/// `MPG4DS32.AX`; round 57 adds `msadds32.ax`'s audio decoder
/// CLSID alongside.  WMVDS32 constructs its CLSID dynamically
/// inside `DllRegisterServer`; static lookup will miss it, and
/// that's OK (we record those as [`Kind::Unsupported`] so we
/// don't re-probe). Round 29+ reverses the dynamic
/// `DllRegisterServer` path to recover the missing CLSIDs.
const DSHOW_CLSID_CANDIDATES: &[(&str, [u8; 16])] = &[
    (
        // MPG4DS32.AX — Microsoft MPEG-4 v3 decoder filter.
        "{82CCD3E0-F71A-11D0-9FE5-00609778EA66}",
        [
            0xE0, 0xD3, 0xCC, 0x82, 0x1A, 0xF7, 0xD0, 0x11, 0x9F, 0xE5, 0x00, 0x60, 0x97, 0x78,
            0xEA, 0x66,
        ],
    ),
    (
        // MSADDS32.AX — Windows Media Audio Decoder filter
        // (round 57).  Reverse-engineered from the splitter's
        // `DllGetClassObject` CLSID table (RVA 0x11000, entry 0).
        "{22E24591-49D0-11D2-BB50-006008320064}",
        [
            0x91, 0x45, 0xE2, 0x22, 0xD0, 0x49, 0xD2, 0x11, 0xBB, 0x50, 0x00, 0x60, 0x08, 0x32,
            0x00, 0x64,
        ],
    ),
];

/// Discovery classification for one probed DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Exports `DriverProc`; `ICOpen` returned a non-NULL HIC for
    /// at least one of the [`VFW_FOURCC_CANDIDATES`].
    Vfw,
    /// Exports `DllGetClassObject`; at least one of the static
    /// [`DSHOW_CLSID_CANDIDATES`] returned an `IClassFactory`.
    DirectShow,
    /// Neither path succeeded. Recorded so we don't re-probe.
    Unsupported,
}

/// Result bundle emitted by [`probe_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub kind: Kind,
    pub fourccs: Vec<String>,
    pub clsid: Option<String>,
}

/// Probe a candidate DLL given its raw bytes. Always returns a
/// `ProbeResult` — failures fall through to [`Kind::Unsupported`]
/// rather than surfacing an error.
pub fn probe_bytes(bytes: &[u8]) -> ProbeResult {
    // ── 1. VfW path ─────────────────────────────────────────────
    if let Some(r) = try_probe_vfw(bytes) {
        return r;
    }
    // ── 2. DirectShow path ──────────────────────────────────────
    if let Some(r) = try_probe_dshow(bytes) {
        return r;
    }
    ProbeResult {
        kind: Kind::Unsupported,
        fourccs: Vec::new(),
        clsid: None,
    }
}

/// Try VfW probe path. Returns `None` if the DLL doesn't even
/// load as a PE32, or if `DriverProc` isn't exported, or if
/// every `ICOpen` candidate misses.
fn try_probe_vfw(bytes: &[u8]) -> Option<ProbeResult> {
    let mut sb = Sandbox::new();
    let img = sb.load("probe.dll", bytes).ok()?;
    img.export("DriverProc")?;
    if sb.install_codec(&img).is_err() {
        return None;
    }
    // Drive DllMain so any CRT init runs before ICOpen.
    let _ = sb.call_dll_main(&img, crate::DLL_PROCESS_ATTACH);

    let mut found: Vec<String> = Vec::new();
    for fcc_bytes in VFW_FOURCC_CANDIDATES {
        let fcc = u32::from_le_bytes(**fcc_bytes);
        match sb.ic_open(FCC_TYPE_VIDC, fcc, 0) {
            Ok(hic) if hic != 0 => {
                // Optional sanity ping — we don't require ICGetInfo
                // to succeed; some codecs leave it as ICERR_UNSUPPORTED
                // until ICDecompressBegin runs.
                //
                // Round 67 — `cb` MUST be `>= ICINFO_SIZE` (= 568).
                // mpg4c32.dll gates the ICM_GETINFO handler at
                // `mpg4c32!DriverProc+0x999..0x99c`
                // (`cmp [ebp+0x10], 0x238 / jb .return_zero`), so
                // the pre-r67 `cb = 112` value silently dropped
                // mpg4c32's identity card on the floor.  Real
                // `vfw32!ICGetInfo` always passes `sizeof(ICINFO)`;
                // mirror that here so the discovery probe sees
                // what real Windows would see.
                let _ = sb.ic_get_info(hic, crate::win32::vfw32::ICINFO_SIZE);
                let _ = sb.ic_close(hic);
                found.push(fourcc_to_string(fcc_bytes));
            }
            _ => {}
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(ProbeResult {
        kind: Kind::Vfw,
        fourccs: found,
        clsid: None,
    })
}

/// Try DirectShow probe. Returns `None` if `DllGetClassObject`
/// isn't exported or every CLSID candidate misses.
///
/// Per the spec, FourCC extraction via `IPin::EnumMediaTypes` is
/// deferred to round 29 — recording the matching CLSID is
/// sufficient for `register()` to know there's a DShow filter
/// here, and the consumer can inspect `clsid` to decide whether
/// to drive it.
fn try_probe_dshow(bytes: &[u8]) -> Option<ProbeResult> {
    let mut sb = Sandbox::new();
    let img = sb.load("probe.dll", bytes).ok()?;
    img.export("DllGetClassObject")?;
    let _ = sb.call_dll_main(&img, crate::DLL_PROCESS_ATTACH);

    for (clsid_str, clsid_bytes) in DSHOW_CLSID_CANDIDATES {
        let guid = guid_from_le_bytes(clsid_bytes);
        match sb.dll_get_class_object(&img, guid, crate::IID_ICLASSFACTORY) {
            Ok(ptr) if ptr != 0 => {
                return Some(ProbeResult {
                    kind: Kind::DirectShow,
                    fourccs: Vec::new(),
                    clsid: Some((*clsid_str).to_string()),
                });
            }
            _ => {}
        }
    }
    None
}

/// Format a FourCC byte slice for serialisation. Non-ASCII bytes
/// are escaped to `0xNN` so the cache JSON remains valid UTF-8.
fn fourcc_to_string(fcc: &[u8; 4]) -> String {
    let mut out = String::with_capacity(4);
    for &b in fcc {
        if b.is_ascii_alphanumeric() || b == b' ' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{:02X}", b));
        }
    }
    out
}

/// Parse a FourCC string back to bytes. Round-trips
/// [`fourcc_to_string`]; rejects anything not exactly 4
/// characters of plain ASCII (we don't honour the `\xNN` escape
/// here — the static FourCC sweep list never produces one).
pub fn fourcc_to_bytes(s: &str) -> Option<[u8; 4]> {
    let bytes = s.as_bytes();
    if bytes.len() != 4 || !bytes.iter().all(|b| b.is_ascii()) {
        return None;
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Some(out)
}

/// Convert a 16-byte little-endian on-disk GUID literal to a
/// [`crate::com::Guid`]. The wire form is
/// `data1[le], data2[le], data3[le], data4[8]`.
fn guid_from_le_bytes(bytes: &[u8; 16]) -> crate::com::Guid {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(&bytes[8..16]);
    crate::com::Guid::new(data1, data2, data3, data4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::test_image::build_minimal_dll;

    #[test]
    fn probe_garbage_classified_unsupported() {
        let r = probe_bytes(b"this is not a PE32 file");
        assert_eq!(r.kind, Kind::Unsupported);
        assert!(r.fourccs.is_empty());
        assert!(r.clsid.is_none());
    }

    #[test]
    fn probe_minimal_synthetic_dll_unsupported() {
        // The `build_minimal_dll` helper produces a real PE32 with
        // a single `DllMain` export (no `DriverProc`, no
        // `DllGetClassObject`). Both probe paths should miss and
        // we land on Unsupported.
        let dll = build_minimal_dll();
        let r = probe_bytes(&dll);
        assert_eq!(r.kind, Kind::Unsupported);
        assert!(r.fourccs.is_empty());
        assert!(r.clsid.is_none());
    }

    #[test]
    fn fourcc_round_trip() {
        let s = fourcc_to_string(b"MP43");
        assert_eq!(s, "MP43");
        let bytes = fourcc_to_bytes(&s).unwrap();
        assert_eq!(&bytes, b"MP43");
    }

    #[test]
    fn fourcc_to_bytes_rejects_non_ascii() {
        assert!(fourcc_to_bytes("MP\\x43").is_none());
        assert!(fourcc_to_bytes("MP4").is_none());
    }

    #[test]
    fn guid_from_le_bytes_matches_known_clsid() {
        // {82CCD3E0-F71A-11D0-9FE5-00609778EA66}
        let bytes = DSHOW_CLSID_CANDIDATES[0].1;
        let g = guid_from_le_bytes(&bytes);
        assert_eq!(g.data1, 0x82CC_D3E0);
        assert_eq!(g.data2, 0xF71A);
        assert_eq!(g.data3, 0x11D0);
        assert_eq!(g.data4, [0x9F, 0xE5, 0x00, 0x60, 0x97, 0x78, 0xEA, 0x66]);
    }

    #[test]
    fn guid_from_le_bytes_matches_msadds_audio_clsid() {
        // Round 57 — {22E24591-49D0-11D2-BB50-006008320064}.
        let bytes = DSHOW_CLSID_CANDIDATES[1].1;
        let g = guid_from_le_bytes(&bytes);
        assert_eq!(g.data1, 0x22E2_4591);
        assert_eq!(g.data2, 0x49D0);
        assert_eq!(g.data3, 0x11D2);
        assert_eq!(g.data4, [0xBB, 0x50, 0x00, 0x60, 0x08, 0x32, 0x00, 0x64]);
        assert_eq!(g, crate::com::MSADDS_AUDIO_DECODER_CLSID);
    }
}

//! Encode / decode coverage harness for the 13 ICOpen-confirmed
//! video codecs.
//!
//! Drives the VfW IC* pipeline end-to-end on each codec with a
//! 32×32 RGB24 synthetic input frame:
//!
//! ```text
//!   ICOpen(VIDC, fcc, ICMODE_COMPRESS)
//!   → ICCompressGetFormat
//!   → ICCompressQuery
//!   → ICCompressGetSize
//!   → ICCompressBegin
//!   → ICCompress  (keyframe)
//!   → ICCompressEnd
//!   → ICClose
//! ```
//!
//! Then, if the encode succeeded with a non-empty payload, feeds
//! the payload back through `ICDecompress` to confirm the codec
//! can also decode its own output.
//!
//! Marked `#[ignore]` — fetches DLLs from the corpus cache and
//! runs ~13 emulator instances. Opt-in via:
//!
//! ```text
//! cargo test --release -p ud-emulator encode_decode_corpus -- \
//!     --ignored --nocapture
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

mod common;

use ud_emulator::{Bih, Sandbox, DLL_PROCESS_ATTACH};

const ICMODE_COMPRESS: u32 = 1;
const ICMODE_DECOMPRESS: u32 = 2;
const ICCOMPRESS_KEYFRAME: u32 = 1;
const WIDTH: u32 = 32;
const HEIGHT: u32 = 32;
const RGB24_SIZE: u32 = WIDTH * HEIGHT * 3;

/// One row of the table. `base_url` and `name` are passed to
/// `common::fetch_or_load`; `fcc` is the FourCC the codec
/// accepts at `ICOpen`.
struct Entry {
    label: &'static str,
    name: &'static str,
    base_url: &'static str,
    fcc: &'static str,
    /// `true` for codecs we expect to round-trip pixel-exactly
    /// (HuffYUV, Lagarith, MagicYUV, CamStudio). Lossy codecs
    /// just need to encode + decode without trapping.
    lossless: bool,
    /// `true` for codecs that ship without an encoder by design
    /// — e.g. Intel's `IR32_32.DLL` shipped as a decoder-only
    /// build; the encoder lived in a separate `ENCODE.DLL` that
    /// isn't in the corpus. `ICOpen(ICMODE_COMPRESS)` legitimately
    /// returns 0 here; the harness records this as "decode-only
    /// by design" rather than a failure.
    decode_only: bool,
}

const CODECS: &[Entry] = &[
    Entry {
        label: "DivX 3.11",
        name: "DivXc32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/divx-3.11",
        fcc: "DIV3",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "DivX 3.11 fast",
        name: "DivXc32f.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/divx-3.11",
        fcc: "DIV4",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "Cinepak",
        name: "iccvid-win32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/cinepak",
        fcc: "cvid",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "Indeo 3",
        name: "IR32_32.DLL",
        base_url: "https://samples.oxideav.org/codecs/windows/indeo3",
        fcc: "IV31",
        lossless: false,
        decode_only: true,
    },
    Entry {
        label: "Indeo 4",
        name: "IR41_32.AX",
        base_url: "https://samples.oxideav.org/codecs/windows/indeo4",
        fcc: "IV41",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "Indeo 5",
        name: "IR50_32.DLL",
        base_url: "https://samples.oxideav.org/codecs/windows/indeo5",
        fcc: "IV50",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "MS-MPEG-4 v3 (wmpcdcs8)",
        name: "wmpcdcs8-mpg4c32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/msmpeg4v3",
        fcc: "MP43",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "MS-MPEG-4 v3 (winxp)",
        name: "winxp-mpg4c32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/msmpeg4v3",
        fcc: "MP43",
        lossless: false,
        decode_only: false,
    },
    Entry {
        label: "HuffYUV",
        name: "huffyuv-i386.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/huffyuv",
        fcc: "HFYU",
        lossless: true,
        decode_only: false,
    },
    Entry {
        label: "CamStudio 1.4",
        name: "camstudio-1.4-camcodec.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/camstudio",
        fcc: "CSCD",
        lossless: true,
        decode_only: false,
    },
    Entry {
        label: "CamStudio 1.5",
        name: "camstudio-1.5-camcodec.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/camstudio",
        fcc: "CSCD",
        lossless: true,
        decode_only: false,
    },
    Entry {
        label: "Lagarith",
        name: "lagarith-i386.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/lagarith",
        fcc: "LAGS",
        lossless: true,
        decode_only: false,
    },
    Entry {
        label: "MagicYUV",
        name: "magicyuv-i386.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/magicyuv",
        fcc: "M8RG",
        lossless: true,
        decode_only: false,
    },
];

/// Result of one codec's encode + decode pass.
#[derive(Debug, Default)]
struct Outcome {
    /// `ICOpen(ICMODE_COMPRESS)` returned a non-zero HIC.
    compress_open_ok: bool,
    /// `ICCompress` returned (no trap) and produced > 0 bytes.
    compress_ok: bool,
    /// Encoded payload size in bytes.
    encoded_size: usize,
    /// `ICOpen(ICMODE_DECOMPRESS)` returned a non-zero HIC.
    decompress_open_ok: bool,
    /// `ICDecompress` returned (no trap) and produced > 0 bytes.
    decompress_ok: bool,
    /// Decoded payload size.
    decoded_size: usize,
    /// `true` for lossless codecs whose decode output equals the
    /// original RGB24 input byte-for-byte.
    round_trip_pixel_exact: bool,
    /// First failure description, if any.
    error: Option<String>,
}

fn fourcc(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

fn make_input_rgb24() -> Vec<u8> {
    // Gradient pattern — every pixel gets a deterministic colour
    // so a lossless round-trip can compare bytes directly.
    let mut frame = Vec::with_capacity(RGB24_SIZE as usize);
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            frame.push((x * 8) as u8); // B
            frame.push((y * 8) as u8); // G
            frame.push(((x + y) * 4) as u8); // R
        }
    }
    frame
}

/// Candidate input formats tried in order; the first that
/// passes `ICCompressQuery` is the one the encode path uses.
/// Most codecs accept RGB24 — only HuffYUV / MagicYUV need
/// the alternatives.
fn candidate_input_formats() -> Vec<(&'static str, Bih, Vec<u8>)> {
    let rgb32_payload = {
        let mut v = Vec::with_capacity((WIDTH * HEIGHT * 4) as usize);
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                v.push((x * 8) as u8); // B
                v.push((y * 8) as u8); // G
                v.push(((x + y) * 4) as u8); // R
                v.push(0xFF); // A / reserved
            }
        }
        v
    };
    vec![
        (
            "RGB24",
            Bih {
                bi_size: 40,
                width: WIDTH as i32,
                height: HEIGHT as i32,
                planes: 1,
                bit_count: 24,
                compression: [0; 4],
                size_image: RGB24_SIZE,
                ..Bih::default()
            },
            make_input_rgb24(),
        ),
        (
            "RGB32",
            Bih {
                bi_size: 40,
                width: WIDTH as i32,
                height: HEIGHT as i32,
                planes: 1,
                bit_count: 32,
                compression: [0; 4],
                size_image: WIDTH * HEIGHT * 4,
                ..Bih::default()
            },
            rgb32_payload,
        ),
        (
            "YUY2",
            Bih {
                bi_size: 40,
                width: WIDTH as i32,
                height: HEIGHT as i32,
                planes: 1,
                bit_count: 16,
                compression: *b"YUY2",
                size_image: WIDTH * HEIGHT * 2,
                ..Bih::default()
            },
            vec![0x80; (WIDTH * HEIGHT * 2) as usize],
        ),
    ]
}

fn run_one(entry: &Entry) -> Outcome {
    let mut out = Outcome::default();
    let bytes = match common::fetch_or_load(entry.base_url, entry.name) {
        Ok(b) => b,
        Err(e) => {
            out.error = Some(format!("fetch: {e}"));
            return out;
        }
    };

    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(100_000_000);
    sb.host.trace_stubs = true;
    sb.cpu.trace_ring_cap = 8;

    let img = match sb.load(entry.name, &bytes) {
        Ok(i) => i,
        Err(e) => {
            out.error = Some(format!("load: {e}"));
            return out;
        }
    };
    if let Err(e) = sb.call_dll_main(&img, DLL_PROCESS_ATTACH) {
        out.error = Some(format!("DllMain: {e}"));
        return out;
    }
    if let Err(e) = sb.install_codec(&img) {
        out.error = Some(format!("install_codec: {e}"));
        return out;
    }

    let fcc_type = fourcc("VIDC");
    let fcc_handler_u32 = fourcc(entry.fcc);

    if entry.decode_only {
        // Decode-only by design — record the marker and skip the
        // encode + same-bitstream-round-trip path entirely.
        // Independent decode would need an external bitstream
        // fixture; not in this harness yet.
        out.error = Some("decode-only by design (no encoder in DLL)".into());
        return out;
    }

    // ---- encode path ----------------------------------------
    let enc_hic = match sb.ic_open(fcc_type, fcc_handler_u32, ICMODE_COMPRESS) {
        Ok(0) => {
            let last_stubs: Vec<String> = sb
                .host
                .stub_calls
                .iter()
                .rev()
                .take(8)
                .rev()
                .map(|c| format!("{}!{}", c.dll, c.name))
                .collect();
            out.error = Some(format!(
                "ICOpen(COMPRESS) returned 0; last stubs=[{}]",
                last_stubs.join(",")
            ));
            return out;
        }
        Ok(h) => h,
        Err(e) => {
            out.error = Some(format!("ICOpen(COMPRESS): {e}"));
            return out;
        }
    };
    out.compress_open_ok = true;

    // Try each candidate input format; pick the first whose
    // (in_bih, codec-chosen out_bih) pair passes ICCompressQuery.
    // Most codecs accept RGB24, but HuffYUV / MagicYUV need
    // one of the alternatives.
    let mut chosen: Option<(Bih, Bih, Vec<u8>)> = None;
    let mut last_reject = String::new();
    for (label, in_bih, payload) in candidate_input_formats() {
        let out_bih = match sb.ic_compress_get_format(enc_hic, &in_bih) {
            Ok((_, o)) => o,
            Err(e) => {
                last_reject = format!("ICCompressGetFormat({label}): {e}");
                continue;
            }
        };
        // Try with the codec-chosen out_bih first; if it rejects,
        // try with `None` ("any output") — some codecs (HuffYUV)
        // accept the latter even when they reject their own
        // chosen output BIH echoed back.
        let q_pair = sb.ic_compress_query(enc_hic, &in_bih, Some(&out_bih));
        let q_any = if matches!(q_pair, Ok(0)) {
            Ok(0xFFFF_FFFF) // unused — pair already passed
        } else {
            sb.ic_compress_query(enc_hic, &in_bih, None)
        };
        match (q_pair, q_any) {
            (Ok(0), _) | (_, Ok(0)) => {
                chosen = Some((in_bih, out_bih, payload));
                break;
            }
            (Ok(rc), _) => {
                last_reject = format!(
                    "ICCompressQuery({label}) rejected pair (LRESULT {rc:#x}); \
                     out_bih bit_count={} compression={:?}",
                    out_bih.bit_count, out_bih.compression,
                );
            }
            (Err(e), _) => {
                last_reject = format!("ICCompressQuery({label}): {e}");
            }
        }
    }
    let Some((in_bih, out_bih, input)) = chosen else {
        out.error = Some(last_reject);
        return out;
    };
    let cap = match sb.ic_compress_get_size(enc_hic, &in_bih, &out_bih) {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(format!("ICCompressGetSize: {e}"));
            return out;
        }
    };
    let _ = sb.ic_compress_begin(enc_hic, &in_bih, &out_bih);
    let encoded = match sb.ic_compress(
        enc_hic,
        ICCOMPRESS_KEYFRAME,
        &in_bih,
        &input,
        &out_bih,
        cap,
        u32::from_le_bytes(*b"00dc"), // ckid — standard video chunk id
        0,                            // frame_num — first frame
        cap,                          // frame_size_limit
        75,                           // quality, 0..100
        None,                         // prev_bih_opt — keyframe, no prev
        None,
    ) {
        Ok(outcome) => outcome.bytes,
        Err(e) => {
            let last_eips: Vec<String> = sb
                .cpu
                .trace_ring
                .iter()
                .map(|e| format!("{e:#x}"))
                .collect();
            let last_stubs: Vec<String> = sb
                .host
                .stub_calls
                .iter()
                .rev()
                .take(8)
                .rev()
                .map(|c| format!("{}!{}", c.dll, c.name))
                .collect();
            out.error = Some(format!(
                "ICCompress: {e}; last_eips=[{}]; last_stubs=[{}]",
                last_eips.join(","),
                last_stubs.join(","),
            ));
            return out;
        }
    };
    let _ = sb.ic_compress_end(enc_hic);
    let _ = sb.ic_close(enc_hic);
    out.encoded_size = encoded.len();
    out.compress_ok = !encoded.is_empty();
    if !out.compress_ok {
        out.error = Some("ICCompress produced 0 bytes".into());
        return out;
    }

    // ---- decode path ----------------------------------------
    // Re-open the same codec in DECOMPRESS mode and feed the
    // bytes we just produced. The codec's own bitstream is the
    // best test fixture we have.
    let dec_hic = match sb.ic_open(fcc_type, fcc_handler_u32, ICMODE_DECOMPRESS) {
        Ok(0) => {
            out.error = Some("ICOpen(DECOMPRESS) returned 0".into());
            return out;
        }
        Ok(h) => h,
        Err(e) => {
            out.error = Some(format!("ICOpen(DECOMPRESS): {e}"));
            return out;
        }
    };
    out.decompress_open_ok = true;

    // BIH for the encoded input — use the codec's chosen format.
    let dec_in_bih = Bih {
        size_image: encoded.len() as u32,
        ..out_bih.clone()
    };
    let dec_out_bih = in_bih.clone();
    let _ = sb.ic_decompress_query(dec_hic, &dec_in_bih, Some(&dec_out_bih));
    let _ = sb.ic_decompress_begin(dec_hic, &dec_in_bih, &dec_out_bih);
    let decoded =
        match sb.ic_decompress(dec_hic, 0, &dec_in_bih, &encoded, &dec_out_bih, RGB24_SIZE) {
            Ok((_lresult, buf)) => buf,
            Err(e) => {
                out.error = Some(format!("ICDecompress: {e}"));
                return out;
            }
        };
    let _ = sb.ic_decompress_end(dec_hic);
    let _ = sb.ic_close(dec_hic);
    out.decoded_size = decoded.len();
    out.decompress_ok = !decoded.is_empty();

    if out.decompress_ok && entry.lossless && decoded.len() == input.len() {
        out.round_trip_pixel_exact = decoded == input;
    }
    out
}

#[test]
#[ignore = "fetches 13 codec DLLs from samples.oxideav.org; run on demand"]
fn encode_decode_corpus() {
    let mut totals = (0usize, 0usize, 0usize); // (encode_ok, decode_ok, round_trip)
    let testable = CODECS.iter().filter(|c| !c.decode_only).count();
    let lossless_testable = CODECS
        .iter()
        .filter(|c| c.lossless && !c.decode_only)
        .count();
    for entry in CODECS {
        let r = run_one(entry);
        if r.compress_ok {
            totals.0 += 1;
        }
        if r.decompress_ok {
            totals.1 += 1;
        }
        if r.round_trip_pixel_exact {
            totals.2 += 1;
        }
        let (enc, dec, rt);
        if entry.decode_only {
            enc = "enc=N/A".into();
            dec = "dec=N/A".into();
            rt = "";
        } else {
            enc = if r.compress_ok {
                format!("enc=ok({} B)", r.encoded_size)
            } else {
                "enc=FAIL".into()
            };
            dec = if r.decompress_ok {
                format!("dec=ok({} B)", r.decoded_size)
            } else if r.compress_ok {
                "dec=FAIL".into()
            } else {
                "dec=skip".into()
            };
            rt = if entry.lossless {
                if r.round_trip_pixel_exact {
                    " rt=EXACT"
                } else if r.decompress_ok {
                    " rt=lossy"
                } else {
                    ""
                }
            } else {
                ""
            };
        }
        let err = r
            .error
            .as_deref()
            .map(|e| format!("  -- {e}"))
            .unwrap_or_default();
        println!("  {:<28}  {enc:<14}  {dec:<14}{rt}{err}", entry.label);
    }
    println!();
    println!("Totals (excluding decode-only by design):");
    println!("  encode ok:     {} / {}", totals.0, testable);
    println!("  decode ok:     {} / {}", totals.1, testable);
    println!(
        "  lossless round-trip exact: {} / {}",
        totals.2, lossless_testable,
    );
}

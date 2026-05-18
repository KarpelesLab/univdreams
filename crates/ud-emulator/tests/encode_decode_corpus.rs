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
}

const CODECS: &[Entry] = &[
    Entry {
        label: "DivX 3.11",
        name: "DivXc32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/divx-3.11",
        fcc: "DIV3",
        lossless: false,
    },
    Entry {
        label: "DivX 3.11 fast",
        name: "DivXc32f.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/divx-3.11",
        fcc: "DIV4",
        lossless: false,
    },
    Entry {
        label: "Cinepak",
        name: "iccvid-win32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/cinepak",
        fcc: "cvid",
        lossless: false,
    },
    Entry {
        label: "Indeo 3",
        name: "IR32_32.DLL",
        base_url: "https://samples.oxideav.org/codecs/windows/indeo3",
        fcc: "IV31",
        lossless: false,
    },
    Entry {
        label: "Indeo 4",
        name: "IR41_32.AX",
        base_url: "https://samples.oxideav.org/codecs/windows/indeo4",
        fcc: "IV41",
        lossless: false,
    },
    Entry {
        label: "Indeo 5",
        name: "IR50_32.DLL",
        base_url: "https://samples.oxideav.org/codecs/windows/indeo5",
        fcc: "IV50",
        lossless: false,
    },
    Entry {
        label: "MS-MPEG-4 v3 (wmpcdcs8)",
        name: "wmpcdcs8-mpg4c32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/msmpeg4v3",
        fcc: "MP43",
        lossless: false,
    },
    Entry {
        label: "MS-MPEG-4 v3 (winxp)",
        name: "winxp-mpg4c32.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/msmpeg4v3",
        fcc: "MP43",
        lossless: false,
    },
    Entry {
        label: "HuffYUV",
        name: "huffyuv-i386.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/huffyuv",
        fcc: "HFYU",
        lossless: true,
    },
    Entry {
        label: "CamStudio 1.4",
        name: "camstudio-1.4-camcodec.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/camstudio",
        fcc: "CSCD",
        lossless: true,
    },
    Entry {
        label: "CamStudio 1.5",
        name: "camstudio-1.5-camcodec.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/camstudio",
        fcc: "CSCD",
        lossless: true,
    },
    Entry {
        label: "Lagarith",
        name: "lagarith-i386.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/lagarith",
        fcc: "LAGS",
        lossless: true,
    },
    Entry {
        label: "MagicYUV",
        name: "magicyuv-i386.dll",
        base_url: "https://samples.oxideav.org/codecs/windows/magicyuv",
        fcc: "M8RG",
        lossless: true,
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

fn input_bih(_fcc_handler_u32: u32) -> Bih {
    Bih {
        bi_size: 40,
        width: WIDTH as i32,
        height: HEIGHT as i32,
        planes: 1,
        bit_count: 24,
        compression: [0; 4], // BI_RGB
        size_image: RGB24_SIZE,
        ..Bih::default()
    }
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
    let input = make_input_rgb24();
    let in_bih = input_bih(fcc_handler_u32);

    // ---- encode path ----------------------------------------
    let enc_hic = match sb.ic_open(fcc_type, fcc_handler_u32, ICMODE_COMPRESS) {
        Ok(0) => {
            out.error = Some("ICOpen(COMPRESS) returned 0".into());
            return out;
        }
        Ok(h) => h,
        Err(e) => {
            out.error = Some(format!("ICOpen(COMPRESS): {e}"));
            return out;
        }
    };
    out.compress_open_ok = true;

    let (_, out_bih) = match sb.ic_compress_get_format(enc_hic, &in_bih) {
        Ok(p) => p,
        Err(e) => {
            out.error = Some(format!("ICCompressGetFormat: {e}"));
            return out;
        }
    };
    let q = match sb.ic_compress_query(enc_hic, &in_bih, Some(&out_bih)) {
        Ok(rc) => rc,
        Err(e) => {
            out.error = Some(format!("ICCompressQuery: {e}"));
            return out;
        }
    };
    if (q as i32) != 0 {
        out.error = Some(format!("ICCompressQuery rejected pair (LRESULT {q:#x})"));
        return out;
    }
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
            out.error = Some(format!("ICCompress: {e}"));
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
    let total = CODECS.len();
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
        let enc = if r.compress_ok {
            format!("enc=ok({} B)", r.encoded_size)
        } else {
            "enc=FAIL".into()
        };
        let dec = if r.decompress_ok {
            format!("dec=ok({} B)", r.decoded_size)
        } else if r.compress_ok {
            "dec=FAIL".into()
        } else {
            "dec=skip".into()
        };
        let rt = if entry.lossless {
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
        let err = r
            .error
            .as_deref()
            .map(|e| format!("  -- {e}"))
            .unwrap_or_default();
        println!("  {:<28}  {enc:<14}  {dec:<14}{rt}{err}", entry.label);
    }
    println!();
    println!("Totals:");
    println!("  encode ok:     {} / {}", totals.0, total);
    println!("  decode ok:     {} / {}", totals.1, total);
    println!(
        "  lossless round-trip exact: {} / {} (of lossless codecs)",
        totals.2,
        CODECS.iter().filter(|c| c.lossless).count(),
    );
}

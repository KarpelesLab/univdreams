//! msmpeg4 cleanroom round 30 (Extractor/Validator, sandbox side) —
//! multi-frame `mpg4c32.dll` **encode** harness.
//!
//! Drives `ICOpen(VIDC/<fcc>, ICMODE_COMPRESS) → ICCompressGetFormat →
//! ICCompressQuery → ICCompressBegin → ICCompress × N → ICCompressEnd`
//! on a sequence of raw BGR24 frames. Frame 0 is requested as a keyframe,
//! later frames are requested as non-key frames with the previous *input*
//! frame passed as `lpbiPrev`/`lpPrev` (VfW ABI). Each encoded frame is
//! written to `<out>.f<k>.bin`, and one JSON line per frame
//! (size, lresult, returned dwFlags) is printed to stdout.
//!
//! Only VfW ABI facts are used; no third-party codec source consulted.
//!
//! ```text
//! cargo run --release -p ud-emulator --features trace --example msmpeg4_r30_encode_seq -- \
//!     --dll mpg4c32.dll --width 64 --height 48 --quality 5000 \
//!     --frame f0.bgr --frame f1.bgr --out enc \
//!     [--watch 0x1c23a788:0xa8 --trace enc.trace.jsonl]   # read-watch (hex addr:len)
//! ```
// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::uninlined_format_args
)]

use ud_emulator::{Bih, Sandbox, WatchMode, DLL_PROCESS_ATTACH};

const ICMODE_COMPRESS: u32 = 0;
const ICCOMPRESS_KEYFRAME: u32 = 1;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (mut dll, mut w, mut h, mut q, mut fcc, mut out) = (
        String::new(),
        0u32,
        0u32,
        5000u32,
        "MP43".to_string(),
        String::from("enc"),
    );
    let mut frames = Vec::new();
    let mut all_key = false;
    let mut watches: Vec<(u32, u32)> = Vec::new();
    let mut trace: Option<String> = None;
    let mut i = 0;
    while i < argv.len() {
        let v = argv.get(i + 1).cloned().unwrap_or_default();
        match argv[i].as_str() {
            "--dll" => dll = v,
            "--width" => w = v.parse().unwrap(),
            "--height" => h = v.parse().unwrap(),
            "--quality" => q = v.parse().unwrap(),
            "--fcc" => fcc = v,
            "--frame" => frames.push(v),
            "--out" => out = v,
            "--trace" => trace = Some(v),
            "--watch" => {
                let p: Vec<&str> = v.split(':').collect();
                let h = |t: &str| u32::from_str_radix(t.trim_start_matches("0x"), 16).unwrap();
                watches.push((h(p[0]), h(p[1])));
            }
            "--all-key" => {
                all_key = true;
                i += 1;
                continue;
            }
            o => panic!("unknown arg {o}"),
        }
        i += 2;
    }
    let bytes = std::fs::read(&dll).expect("dll");
    let name = std::path::Path::new(&dll)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(40_000_000_000);
    sb.cpu.set_instr_limit(40_000_000_000);
    if let Some(t) = &trace {
        let f = std::fs::File::create(t).expect("trace");
        sb.set_trace_sink(Box::new(std::io::BufWriter::with_capacity(1 << 20, f)));
    }
    for (a, n) in &watches {
        sb.watch(*a, *n, WatchMode::Read);
    }
    let img = sb.load(&name, &bytes).expect("load");
    let _ = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install");
    let fb = fcc.as_bytes();
    let hic = sb
        .ic_open(
            u32::from_le_bytes(*b"VIDC"),
            u32::from_le_bytes([fb[0], fb[1], fb[2], fb[3]]),
            ICMODE_COMPRESS,
        )
        .expect("open");
    assert!(hic != 0);
    let in_bih = Bih {
        bi_size: 40,
        width: w as i32,
        height: h as i32,
        planes: 1,
        bit_count: 24,
        compression: [0; 4],
        size_image: w * h * 3,
        ..Bih::default()
    };
    let (_, out_bih) = sb.ic_compress_get_format(hic, &in_bih).expect("fmt");
    let qr = sb
        .ic_compress_query(hic, &in_bih, Some(&out_bih))
        .expect("query");
    assert_eq!(qr as i32, 0, "query");
    let cap = sb
        .ic_compress_get_size(hic, &in_bih, &out_bih)
        .expect("size");
    let _ = sb.ic_compress_begin(hic, &in_bih, &out_bih);
    let mut prev: Option<Vec<u8>> = None;
    for (k, p) in frames.iter().enumerate() {
        let f = std::fs::read(p).expect("frame");
        let key = k == 0 || all_key;
        let r = sb
            .ic_compress(
                hic,
                if key { ICCOMPRESS_KEYFRAME } else { 0 },
                &in_bih,
                &f[..(w * h * 3) as usize],
                &out_bih,
                cap,
                0,
                k as i32,
                0,
                q,
                if key { None } else { Some(&in_bih) },
                if key { None } else { prev.as_deref() },
            )
            .expect("compress");
        std::fs::write(format!("{out}.f{k}.bin"), &r.bytes).unwrap();
        println!(
            "{{\"frame\":{},\"lresult\":{},\"bytes\":{},\"flags\":{}}}",
            k,
            r.lresult as i32,
            r.bytes.len(),
            r.returned_flags
        );
        prev = Some(f);
    }
    let _ = sb.ic_compress_end(hic);
    let _ = sb.ic_close(hic);
}

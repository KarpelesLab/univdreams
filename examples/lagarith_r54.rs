//! Lagarith Validator round 54 (2026-09-12) — sandbox harness.
//!
//! Drives `syswow64/lagarith.dll` (i386, SHA-256 `bac1ea74…f20bcc`)
//! through the VfW compress / decompress surface inside the
//! `ud-emulator` sandbox and, on request, arms `Cpu::add_register_watchpoint`
//! snapshots at the round-53 sites so that the static claims of
//! `provenance/53` can be ratified behaviourally.
//!
//! Sub-commands (all take the DLL path first):
//!
//! ```text
//! lagarith_r54 <dll> encode <fmt> <W> <H> <in.raw> <out.lags>
//! lagarith_r54 <dll> decode <fmt> <W> <H> <in.lags> <out.raw> [repeat]
//! lagarith_r54 <dll> state
//! lagarith_r54 <dll> watch <set> <fmt> <W> <H> <in.lags> <out.jsonl> [repeat]
//! ```
//!
//! `<fmt>` ∈ `rgb24 | rgb32 | yuy2 | yv12` names the *uncompressed*
//! side (input BIH for encode, output BIH for decode).  `<set>` ∈
//! `stepb | yuy2 | ff | all` selects which watchpoint PCs are armed;
//! every snapshot is written as one JSON line with the eight GP
//! registers plus a fixed list of memory probes (see `probe_list`).
//! `repeat` decodes the same frame N times in one sandbox (Lagarith's
//! i386 YUY2 predictor entry alternates between two implementations
//! for its first ten calls, so `repeat 2` exercises both).
//!
//! No Wine, no native execution, no third-party decoder source.

// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use univdreams::emulator::{Bih, DLL_PROCESS_ATTACH, Sandbox};

/// Mirrors `ud vfw` (crates/ud-cli): the CLI opens the decoder with
/// mode 1 and the encoder with mode 2 and Lagarith accepts both, so
/// the same values are used here for a like-for-like reproduction.
const MODE_DECODE: u32 = 1;
const MODE_ENCODE: u32 = 2;
const ICCOMPRESS_KEYFRAME: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Rgb24,
    Rgb32,
    Rgba,
    Yuy2,
    Yv12,
}

impl Fmt {
    fn parse(s: &str) -> Fmt {
        match s {
            "rgb24" | "bgr24" => Fmt::Rgb24,
            "rgb32" | "bgr32" => Fmt::Rgb32,
            "rgba" | "bgra" => Fmt::Rgba,
            "yuy2" => Fmt::Yuy2,
            "yv12" => Fmt::Yv12,
            _ => panic!("unknown fmt {s}"),
        }
    }
    fn bit_count(self) -> u16 {
        match self {
            Fmt::Rgb24 => 24,
            Fmt::Rgb32 | Fmt::Rgba => 32,
            Fmt::Yuy2 => 16,
            Fmt::Yv12 => 12,
        }
    }
    fn compression(self) -> [u8; 4] {
        match self {
            Fmt::Rgb24 | Fmt::Rgb32 => [0; 4],
            // Lagarith's "RGBA mode": the input BIH carries biCompression
            // = 'RGBA' with biBitCount = 32 (compare at i386 0x1001e0ff).
            Fmt::Rgba => *b"RGBA",
            Fmt::Yuy2 => *b"YUY2",
            Fmt::Yv12 => *b"YV12",
        }
    }
    fn frame_bytes(self, w: u32, h: u32) -> u32 {
        match self {
            Fmt::Rgb24 => w * h * 3,
            Fmt::Rgb32 | Fmt::Rgba => w * h * 4,
            Fmt::Yuy2 => w * h * 2,
            Fmt::Yv12 => w * h + 2 * ((w / 2) * (h / 2)),
        }
    }
    fn bih(self, w: u32, h: u32) -> Bih {
        Bih {
            bi_size: 40,
            width: w as i32,
            height: h as i32,
            planes: 1,
            bit_count: self.bit_count(),
            compression: self.compression(),
            size_image: self.frame_bytes(w, h),
            ..Bih::default()
        }
    }
}

/// Compressed-side BIH.  Lagarith's `ICCompressGetFormat` stamps the
/// uncompressed bit depth (24 / 32 / 16 / 12) into the `LAGS` BIH and
/// `ICDecompressQuery` rejects (`ICERR_BADFORMAT`) a mismatch, so the
/// decoder side must carry the same depth.
fn lags_bih(fmt: Fmt, w: u32, h: u32, len: usize) -> Bih {
    Bih {
        bi_size: 40,
        width: w as i32,
        height: h as i32,
        planes: 1,
        bit_count: fmt.bit_count(),
        compression: *b"LAGS",
        size_image: len as u32,
        ..Bih::default()
    }
}

/// `LAG_REG="NullFrames=1;Multithread=0"` seeds `HKCU\Software\Lagarith`
/// REG_DWORD values before the codec is loaded (the codec reads its
/// settings from that key: strings at .rdata 0x1002de48 / 0x1002de5c /
/// 0x1002de74).
fn open(dll: &str) -> (Sandbox, u32) {
    let bytes = std::fs::read(dll).expect("read dll");
    let mut sb = Sandbox::new();
    if let Ok(spec) = std::env::var("LAG_REG") {
        let mut reg = univdreams::emulator::VirtualRegistry::new();
        for kv in spec.split(';').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').expect("LAG_REG entry k=v");
            let v: u32 = v.parse().expect("LAG_REG value");
            reg.set_value(
                "HKEY_CURRENT_USER\\Software\\Lagarith",
                k,
                univdreams::emulator::RegistryValue::Dword(v),
            );
            eprintln!("[reg] HKCU\\Software\\Lagarith\\{k} = {v}");
        }
        sb = sb.with_registry(reg);
    }
    sb.host.instruction_budget = Some(2_000_000_000);
    sb.cpu.set_instr_limit(2_000_000_000);
    let img = sb.load("lagarith.dll", &bytes).expect("load");
    let _ = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");
    (sb, img.image_base)
}

fn fcc(s: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*s)
}

fn do_encode(
    sb: &mut Sandbox,
    fmt: Fmt,
    w: u32,
    h: u32,
    raw: &[u8],
    repeat: usize,
) -> (u32, Vec<u8>, u32) {
    let hic = sb
        .ic_open(fcc(b"VIDC"), fcc(b"LAGS"), MODE_ENCODE)
        .expect("ICOpen");
    assert_ne!(hic, 0, "codec refused DRV_OPEN");
    let in_bih = fmt.bih(w, h);
    let (_, out_bih) = sb.ic_compress_get_format(hic, &in_bih).expect("GetFormat");
    let q = sb
        .ic_compress_query(hic, &in_bih, Some(&out_bih))
        .expect("CompressQuery");
    assert_eq!(q as i32, 0, "ICCompressQuery rejected {fmt:?} {w}x{h}");
    let cap = sb
        .ic_compress_get_size(hic, &in_bih, &out_bih)
        .expect("GetSize");
    let _ = sb.ic_compress_begin(hic, &in_bih, &out_bih);
    let n = fmt.frame_bytes(w, h) as usize;
    let mut last = (0u32, Vec::new(), 0u32);
    if repeat > 1 {
        // SAFETY: single-threaded example binary; no other thread reads the env.
        unsafe {
            std::env::set_var(
                "LAG_ENCODE_OUT",
                std::env::var_os("LAG_ENCODE_OUT").unwrap_or_default(),
            );
        }
    }
    for i in 0..repeat.max(1) {
        // Only the first frame is requested as a keyframe; later
        // frames of the same input probe the null-frame path.
        let flags = if i == 0 { ICCOMPRESS_KEYFRAME } else { 0 };
        let r = sb
            .ic_compress(
                hic,
                flags,
                &in_bih,
                &raw[..n],
                &out_bih,
                cap,
                0,
                i as i32,
                0,
                5000,
                None,
                None,
            )
            .expect("ICCompress");
        eprintln!(
            "[encode] frame {i}: rc={} bytes={} returned_flags={:#x} size_image={}",
            r.lresult as i32,
            r.bytes.len(),
            r.returned_flags,
            r.output_bih.size_image
        );
        let n_out = (r.output_bih.size_image as usize).min(r.bytes.len());
        let mut bytes = r.bytes;
        bytes.truncate(n_out);
        if i > 0 {
            if let Some(p) = std::env::var_os("LAG_ENCODE_OUT") {
                let path = format!("{}.{i}", p.to_string_lossy());
                std::fs::write(&path, &bytes).expect("write frame");
                eprintln!("[encode] frame {i} written to {path} ({n_out} bytes)");
            }
        }
        if i == 0 {
            last = (r.lresult, bytes, r.returned_flags);
        }
    }
    let _ = sb.ic_compress_end(hic);
    let _ = sb.ic_close(hic);
    last
}

fn do_decode(
    sb: &mut Sandbox,
    fmt: Fmt,
    w: u32,
    h: u32,
    frame: &[u8],
    repeat: usize,
) -> (u32, Vec<u8>) {
    let hic = sb
        .ic_open(fcc(b"VIDC"), fcc(b"LAGS"), MODE_DECODE)
        .expect("ICOpen");
    assert_ne!(hic, 0, "codec refused DRV_OPEN");
    let in_bih = lags_bih(fmt, w, h, frame.len());
    let out_bih = fmt.bih(w, h);
    let q = sb
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .expect("DecompressQuery");
    assert_eq!(q as i32, 0, "ICDecompressQuery rejected {fmt:?} {w}x{h}");
    let _ = sb.ic_decompress_begin(hic, &in_bih, &out_bih);
    let cap = fmt.frame_bytes(w, h);
    let mut last = (0u32, Vec::new());
    for _ in 0..repeat.max(1) {
        let (rc, out) = sb
            .ic_decompress(hic, 0, &in_bih, frame, &out_bih, cap)
            .expect("ICDecompress");
        last = (rc, out);
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    last
}

/// Watchpoint sites (i386 build, ImageBase 0x10000000).  Labels are
/// the round-53 / round-54 names used in provenance/54.
fn sites(set: &str) -> Vec<(u32, &'static str)> {
    let stepb: Vec<(u32, &'static str)> = vec![
        // header-0 plain loop (provenance/53 §1.6)
        (0x1001_5c94, "init: mov edx,[ecx+0x3fc] (cum[255] load)"),
        (0x1001_5d99, "A: imul eax,[ebp+0x5c] (cum[1]*q)"),
        (
            0x1001_5db7,
            "B0: cmp edi,eax  (eax=cum[255]*q, ebx=q, edi=low, esi=range)",
        ),
        (0x1001_5e50, "B0-ff: sub esi,eax (range-=)"),
        (0x1001_5e5d, "B0-ff: mov byte [eax],0xff (post-subtract)"),
        (0x1001_5e60, "B0: inc eax (join of A and ff paths)"),
        // RLE sub-paths — the other five Step-B sites
        (0x1001_5ee0, "B1: cmp edi,ecx"),
        (0x1001_5f88, "B1-ff: mov byte [ecx],0xff"),
        (0x1001_60d3, "B2: cmp edi,ecx"),
        (0x1001_6206, "B3: cmp edi,ecx"),
        (0x1001_62b0, "B3-ff: mov byte [ecx],0xff"),
        (0x1001_6360, "B4: cmp edi,ecx"),
        (0x1001_64bb, "B5: cmp edi,eax"),
        (0x1001_6575, "B5-ff: mov byte [eax],0xff"),
        (
            0x1001_657e,
            "B5-ff: inc [ebp+0x74] (escape-run variant, no byte write)",
        ),
    ];
    let yuy2: Vec<(u32, &'static str)> = vec![
        (0x1001_da10, "YUY2 predictor entry (timing dispatcher)"),
        (0x1001_9610, "YUY2 impl A entry"),
        (
            0x1001_9641,
            "A: mov [esi+2],dl  (dl = Yres[1] raw; edi=Yres)",
        ),
        (
            0x1001_9650,
            "A: cmp eax,1  (eax = W/2+2 prefix macropixels; [esp+0x38]=W)",
        ),
        (0x1001_96cb, "A: prefix done, cmp H,1 ([esp+0x3c]=H)"),
        (0x1001_9803, "A: paddb mm4,mm0 (L+T, byte lanes)"),
        (
            0x1001_9814,
            "A: psubb mm4,mm6 (-TL, byte lanes → gradient mod 256)",
        ),
        (0x1001_981d, "A: pminub/pmaxub clamp"),
        (0x1001_9966, "A: paddb mm4,mm0 (second MED block)"),
        (0x1001_9977, "A: psubb mm4,mm5 (second MED block)"),
        (0x1001_b840, "YUY2 impl B entry"),
        (
            0x1001_b87a,
            "B: mov [eax+2],dl (dl = Yres[1] raw; [ebp+0xc]=Yres)",
        ),
        (0x1001_b888, "B: cmp edi,esi (edi = W/2+2; [ebp+0x18]=W)"),
        (
            0x1001_b96e,
            "B: and edx,0xff (gradient L+T-TL byte-wrap, scalar pre-loop)",
        ),
        (0x1002_02ec, "YUY2 coord: cmp [frame+1],0xb"),
        (0x1002_02f2, "YUY2 coord: Y[1]=Y[0] patch taken"),
    ];
    let ff: Vec<(u32, &'static str)> = vec![
        (
            0x1002_3e4d,
            "disp: movzx eax,[esi] (header byte; ebx=count, ebp=plane)",
        ),
        (0x1002_3ec4, "disp: cmp eax,0xff"),
        (
            0x1002_3ecb,
            "disp-ff: push ebx (memset(plane,0,count) about to run)",
        ),
        (
            0x1002_3ed4,
            "disp-ff: mov cl,[esi+1] (after memset; [ebp]=0)",
        ),
        (0x1002_3edd, "disp-ff: pop esi (after plane[0]=byte1)"),
        (0x1002_3ee3, "disp: inc esi (header 4..7 path)"),
        (0x1002_3eed, "disp: call RLE-only expander (header 5..7)"),
        (0x1002_3efb, "disp: call memcpy (header 4)"),
        (
            0x1002_3e8f,
            "disp: call range coder (header 1..3 with len>=count → as 0)",
        ),
        (0x1002_3eb9, "disp: call range coder (header 1..3)"),
        (0x1002_3f28, "disp: call range coder (header 0)"),
        (0x1001_fe50, "per-plane dispatcher entry"),
        (0x1001_adb0, "RGB predictor A entry"),
        (0x1001_a4a0, "RGB predictor B (24-bit) entry"),
        (0x1001_a320, "RGB predictor C (32-bit) entry"),
        (0x1001_da10, "YUY2 predictor entry"),
        (
            0x1001_d8a0,
            "YV12 predictor entry (dispatcher; called from the YV12 coordinator 0x1002007a/0x100201f6)",
        ),
    ];
    match set {
        "stepb" => stepb,
        "yuy2" => yuy2,
        "ff" => ff,
        "all" => {
            let mut v = stepb;
            v.extend(yuy2);
            v.extend(ff);
            v
        }
        _ => panic!("unknown set {set}"),
    }
}

fn probe_list() -> Vec<(&'static str, u8, u32, u8)> {
    // (label, base register index in snapshot order, offset, width in bytes)
    // snapshot order: eax ecx edx ebx esp ebp esi edi
    vec![
        ("[ebp+0x50]", 5, 0x50, 4),
        ("[ebp+0x58]", 5, 0x58, 4),
        ("[ebp+0x5c]", 5, 0x5c, 4),
        ("[ebp+0x74]", 5, 0x74, 4),
        ("[ebp+0x4c]", 5, 0x4c, 4),
        ("[ebp+0xc]", 5, 0x0c, 4),
        ("[ebp+0x18]", 5, 0x18, 4),
        ("[ebp+0x1c]", 5, 0x1c, 4),
        ("[esp+0x38]", 4, 0x38, 4),
        ("[esp+0x3c]", 4, 0x3c, 4),
        ("[esp]", 4, 0x0, 4),
        ("b[eax]", 0, 0, 1),
        ("b[ecx]", 1, 0, 1),
        ("b[ebp]", 5, 0, 1),
        ("b[ebp+1]", 5, 1, 1),
        ("b[ebp+2]", 5, 2, 1),
        ("b[esi]", 6, 0, 1),
        ("b[esi+1]", 6, 1, 1),
        ("b[edi]", 7, 0, 1),
        ("b[edi+1]", 7, 1, 1),
        ("d[eax+1]", 0, 1, 4),
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: lagarith_r54 <dll> encode|decode|state|watch ...");
        std::process::exit(2);
    }
    let dll = &args[1];
    match args[2].as_str() {
        "encode" => {
            let fmt = Fmt::parse(&args[3]);
            let (w, h) = (args[4].parse().unwrap(), args[5].parse().unwrap());
            let raw = std::fs::read(&args[6]).expect("read input");
            let repeat = args.get(8).map_or(1, |s| s.parse().unwrap());
            // SAFETY: single-threaded example binary; no other thread reads the env.
            unsafe { std::env::set_var("LAG_ENCODE_OUT", &args[7]) };
            let (mut sb, _) = open(dll);
            let (rc, bytes, flags) = do_encode(&mut sb, fmt, w, h, &raw, repeat);
            std::fs::write(&args[7], &bytes).expect("write");
            eprintln!(
                "[encode] rc={} bytes={} flags={:#x} instr={}",
                rc as i32,
                bytes.len(),
                flags,
                sb.cpu.instr_count
            );
        }
        "decode" => {
            let fmt = Fmt::parse(&args[3]);
            let (w, h) = (args[4].parse().unwrap(), args[5].parse().unwrap());
            let frame = std::fs::read(&args[6]).expect("read frame");
            let repeat = args.get(8).map_or(1, |s| s.parse().unwrap());
            let (mut sb, _) = open(dll);
            let (rc, out) = do_decode(&mut sb, fmt, w, h, &frame, repeat);
            std::fs::write(&args[7], &out).expect("write");
            eprintln!(
                "[decode] rc={} bytes={} instr={}",
                rc as i32,
                out.len(),
                sb.cpu.instr_count
            );
        }
        "state" => {
            let (mut sb, _) = open(dll);
            for (label, mode) in [("compress", MODE_ENCODE), ("decompress", MODE_DECODE)] {
                let hic = sb
                    .ic_open(fcc(b"VIDC"), fcc(b"LAGS"), mode)
                    .expect("ICOpen");
                let mut empty: Vec<u8> = Vec::new();
                let n = sb.ic_get_state(hic, &mut empty).expect("ICGetState probe");
                println!(
                    "[state] mode={label} ICGetState(NULL,0) = {} ({:#010x})",
                    n as i32, n
                );
                if (n as i32) > 0 && n < 4096 {
                    let mut blob = vec![0u8; n as usize];
                    let m = sb.ic_get_state(hic, &mut blob).expect("ICGetState fetch");
                    println!("[state] mode={label} fetched {} bytes: {}", m, hex(&blob));
                    // Try to set each byte of the blob independently to
                    // learn which bytes the codec accepts as switches.
                    for i in 0..blob.len() {
                        let mut b2 = blob.clone();
                        b2[i] ^= 1;
                        let r = sb.ic_set_state(hic, &b2);
                        let mut b3 = vec![0u8; n as usize];
                        let _ = sb.ic_get_state(hic, &mut b3);
                        println!(
                            "[state] mode={label} set byte {i} ^=1 -> {:?}; readback {}",
                            r.map_err(|e| e.to_string()),
                            hex(&b3)
                        );
                        let _ = sb.ic_set_state(hic, &blob);
                    }
                    let r = sb.ic_set_state(hic, &blob[..blob.len() / 2]);
                    println!(
                        "[state] mode={label} set half-size blob -> {:?}",
                        r.map_err(|e| e.to_string())
                    );
                }
                let _ = sb.ic_close(hic);
            }
        }
        "watch" => {
            let set = args[3].as_str();
            let fmt = Fmt::parse(&args[4]);
            let (w, h) = (args[5].parse().unwrap(), args[6].parse().unwrap());
            let frame = std::fs::read(&args[7]).expect("read frame");
            let out_path = &args[8];
            let repeat = args.get(9).map_or(1, |s| s.parse().unwrap());
            let (mut sb, _) = open(dll);
            let sites = sites(set);
            let labels: BTreeMap<u32, &str> = sites.iter().map(|(a, l)| (*a, *l)).collect();
            sb.cpu.register_snapshots_cap = 4_000_000;
            for (a, _) in &sites {
                sb.cpu.add_register_watchpoint(*a);
            }
            sb.cpu.track_visited_eips = true;
            let probes = probe_list();
            sb.cpu.snapshot_probes = probes
                .iter()
                .map(|(_, r, off, w)| (*r, *off as i32, *w))
                .collect();
            // ecx = probability model at the cum[255] load: dump cum[0..=256] + shift (0x408 bytes).
            sb.cpu.snapshot_block_dump = Some((0x1001_5c94, 1, 0x408));
            let (rc, out) = do_decode(&mut sb, fmt, w, h, &frame, repeat);
            let snaps = sb.cpu.clear_register_watchpoints();
            let (probe_vals, block_dumps) = sb.cpu.take_snapshot_probes();
            let block_by_snap: BTreeMap<usize, &Vec<u8>> =
                block_dumps.iter().map(|(i, b)| (*i, b)).collect();
            let visited = sb.cpu.take_visited_eips();
            let mut f =
                std::io::BufWriter::new(std::fs::File::create(out_path).expect("create jsonl"));
            let mut hits: BTreeMap<u32, usize> = BTreeMap::new();
            for (i, (pc, regs)) in snaps.iter().enumerate() {
                *hits.entry(*pc).or_default() += 1;
                let mut line = String::new();
                let _ = write!(
                    line,
                    "{{\"i\":{i},\"pc\":\"{pc:#010x}\",\"label\":{:?},\"eax\":\"{:#010x}\",\"ecx\":\"{:#010x}\",\"edx\":\"{:#010x}\",\"ebx\":\"{:#010x}\",\"esp\":\"{:#010x}\",\"ebp\":\"{:#010x}\",\"esi\":\"{:#010x}\",\"edi\":\"{:#010x}\",\"probe\":{{",
                    labels.get(pc).copied().unwrap_or("?"),
                    regs[0],
                    regs[1],
                    regs[2],
                    regs[3],
                    regs[4],
                    regs[5],
                    regs[6],
                    regs[7]
                );
                let mut first = true;
                for (k, (label, _reg, _off, _width)) in probes.iter().enumerate() {
                    // Captured at snapshot time by the emulator (round-54
                    // `Cpu::snapshot_probes`), never post-mortem.
                    let v = probe_vals
                        .get(i)
                        .and_then(|pv| pv.get(k).copied().flatten());
                    if let Some(v) = v {
                        if !first {
                            line.push(',');
                        }
                        first = false;
                        let _ = write!(line, "{label:?}:\"{v:#x}\"");
                    }
                }
                line.push('}');
                if let Some(b) = block_by_snap.get(&i) {
                    // ecx = probability model at 0x10015c94: cum[0..=256] then shift at +0x404,
                    // captured at snapshot time (a later plane overwrites the same buffer).
                    let m: Vec<String> = b
                        .chunks(4)
                        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string())
                        .collect();
                    let _ = write!(line, ",\"model\":[{}]", m.join(","));
                }
                line.push_str("}\n");
                f.write_all(line.as_bytes()).expect("write");
            }
            f.flush().unwrap();
            eprintln!(
                "[watch] set={set} rc={} out={} bytes snapshots={} (cap {}) instr={}",
                rc as i32,
                out.len(),
                snaps.len(),
                sb.cpu.register_snapshots_cap,
                sb.cpu.instr_count
            );
            for (a, l) in &sites {
                eprintln!(
                    "  {a:#010x} hits={:<8} visited={} {l}",
                    hits.get(a).copied().unwrap_or(0),
                    visited.contains(a)
                );
            }
            // Function-entry coverage summary for the predictor / dispatcher entries.
            let entries: [(u32, &str); 13] = [
                (0x1001_d8a0, "YV12 predictor dispatcher"),
                (0x1002_3e40, "channel dispatcher"),
                (0x1001_5c30, "modern range decoder"),
                (0x1001_4b30, "RLE-only expander (hdr 5..7)"),
                (0x1000_5b90, "memcpy helper (hdr 4)"),
                (0x1001_fe50, "per-plane dispatcher"),
                (0x1002_0360, "RGB coordinator"),
                (0x1001_adb0, "RGB predictor A"),
                (0x1001_a4a0, "RGB predictor B"),
                (0x1001_a320, "RGB predictor C"),
                (0x1001_da10, "YUY2 predictor dispatcher"),
                (0x1001_9610, "YUY2 impl A"),
                (0x1001_b840, "YUY2 impl B"),
            ];
            for (a, l) in entries {
                eprintln!("  entry {a:#010x} visited={} {l}", visited.contains(&a));
            }
            let hi: Vec<String> = visited
                .iter()
                .filter(|e| **e >= 0x1000_1000 && **e < 0x1003_0000)
                .map(|e| format!("{e:#x}"))
                .collect();
            std::fs::write(format!("{out_path}.visited.txt"), hi.join("\n")).unwrap();
            std::io::stdout().write_all(&out).unwrap();
        }
        other => panic!("unknown command {other}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

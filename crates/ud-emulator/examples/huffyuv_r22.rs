//! huffyuv_r22 — HuffYUV (HFYU) sandbox harness for the oxideav docs
//! clean-room workspace `video/huffyuv/` (provenance 22 / 23, 2026-09-12).
//!
//! Drives the proprietary i386 `huffyuv.dll` through the VfW compress /
//! decompress surface inside the univdreams sandbox:
//!
//!   encode  <dll> --width W --height H --fmt yuy2|bgr24 --in RAW --out-prefix P [--ini key=val]...
//!           → P.bih   (the codec's output BIH, 40 bytes + extradata tail, verbatim)
//!           → P.frame (the encoded frame bytes)
//!   decode  <dll> --bih FILE --frame FILE --pix yuy2|rgb24 --out FILE [--ini key=val]...
//!           [--flag 0xNN]  patch BIH+0x2A (the interlace byte) before decoding
//!           [--height H]   override the BIH's biHeight (in + out) before decoding
//!           → OUT (decoded pixels)
//!
//! `--ini key=val` overrides `GetPrivateProfileIntA("general", key, default, "huffyuv.ini")`
//! (the codec's only configuration channel: `yuy2method`, `rgbmethod`,
//! `field_threshold`, `ignore_iflag`, `decomp_swap_fields`, ...). The
//! override is installed by registering a second stub and patching the
//! DLL's IAT slot for `GetPrivateProfileIntA` (i386 build: `0x1000701c`,
//! passed via `--iat`) after the image is loaded.
//!
//! Clean-room: only the raw bytes of the vendor DLL and caller-generated
//! synthetic pixel data are consumed. No third-party decoder source.
// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::uninlined_format_args
)]

use std::path::PathBuf;
use std::sync::Mutex;
use ud_emulator::emulator::{Cpu, Mmu};
use ud_emulator::win32::{HostState, Registry, Win32Error, arg_dword, read_cstr_local};
use ud_emulator::{Bih, DLL_PROCESS_ATTACH, Sandbox};

const ICMODE_COMPRESS: u32 = 1;
const ICMODE_DECOMPRESS: u32 = 2;
const ICCOMPRESS_KEYFRAME: u32 = 0x0000_0001;

static INI: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());

fn stub_ini_override(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let trap = |t: ud_emulator::emulator::Trap| Win32Error::InvalidArgument {
        stub: "GetPrivateProfileIntA(override)",
        reason: format!("{t}"),
    };
    let app = arg_dword(cpu, mmu, 0).map_err(trap)?;
    let key = arg_dword(cpu, mmu, 1).map_err(trap)?;
    let default = arg_dword(cpu, mmu, 2).map_err(trap)?;
    let app_s = read_cstr_local(mmu, app, 64).unwrap_or_default();
    let key_s = read_cstr_local(mmu, key, 64).unwrap_or_default();
    let table = INI.lock().expect("ini table");
    let hit = table.iter().find(|(k, _)| *k == key_s).map(|(_, v)| *v);
    let val = hit.unwrap_or(default);
    eprintln!(
        "[ini] GetPrivateProfileIntA(\"{app_s}\", \"{key_s}\", default={default}) -> {val}{}",
        if hit.is_some() { " (override)" } else { "" }
    );
    Ok(val)
}

fn parse_u32(s: &str) -> u32 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).expect("hex")
    } else {
        s.parse().expect("dec")
    }
}

fn fourcc(s: &str) -> u32 {
    let b = s.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn bih_to_bytes(b: &Bih) -> Vec<u8> {
    let mut v = Vec::with_capacity(40 + b.tail.len());
    v.extend_from_slice(&b.bi_size.to_le_bytes());
    v.extend_from_slice(&(b.width as u32).to_le_bytes());
    v.extend_from_slice(&(b.height as u32).to_le_bytes());
    v.extend_from_slice(&b.planes.to_le_bytes());
    v.extend_from_slice(&b.bit_count.to_le_bytes());
    v.extend_from_slice(&b.compression);
    v.extend_from_slice(&b.size_image.to_le_bytes());
    v.extend_from_slice(&(b.x_pels_per_meter as u32).to_le_bytes());
    v.extend_from_slice(&(b.y_pels_per_meter as u32).to_le_bytes());
    v.extend_from_slice(&b.clr_used.to_le_bytes());
    v.extend_from_slice(&b.clr_important.to_le_bytes());
    v.extend_from_slice(&b.tail);
    v
}

fn bih_from_bytes(d: &[u8]) -> Bih {
    let u32at = |o: usize| u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]);
    let u16at = |o: usize| u16::from_le_bytes([d[o], d[o + 1]]);
    let bi_size = u32at(0);
    Bih {
        bi_size,
        width: u32at(4) as i32,
        height: u32at(8) as i32,
        planes: u16at(12),
        bit_count: u16at(14),
        compression: [d[16], d[17], d[18], d[19]],
        size_image: u32at(20),
        x_pels_per_meter: u32at(24) as i32,
        y_pels_per_meter: u32at(28) as i32,
        clr_used: u32at(32),
        clr_important: u32at(36),
        tail: d[40..(bi_size as usize).min(d.len())].to_vec(),
    }
}

struct Common {
    dll: PathBuf,
    iat: Option<u32>,
    instr_limit: u64,
}

fn boot(c: &Common, mode: u32) -> (Sandbox, u32) {
    let dll_bytes = std::fs::read(&c.dll).expect("read dll");
    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(c.instr_limit);
    let img = sb.load("huffyuv.dll", &dll_bytes).expect("load");
    if let Some(iat) = c.iat {
        let thunk = sb.registry.register(
            "kernel32.dll",
            "GetPrivateProfileIntA#r22",
            stub_ini_override,
            4,
        );
        let before = sb.mmu.load32(iat).expect("iat read");
        let perm = sb.mmu.perm_at(iat).expect("iat page mapped");
        sb.mmu
            .set_perm(iat, perm.or(ud_emulator::emulator::Perm::W));
        sb.mmu.store32(iat, thunk).expect("iat write");
        sb.mmu.set_perm(iat, perm);
        eprintln!("[ini] IAT slot {iat:#010x}: {before:#010x} -> {thunk:#010x} (override stub)");
    }
    let _ = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");
    let hic = sb
        .ic_open(fourcc("vidc"), fourcc("HFYU"), mode)
        .expect("ICOpen");
    assert!(hic != 0, "codec refused DRV_OPEN");
    (sb, hic)
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.len() < 2 {
        eprintln!("usage: huffyuv_r22 encode|decode <dll> [options]");
        std::process::exit(2);
    }
    let cmd = argv[0].clone();
    let mut c = Common {
        dll: PathBuf::from(&argv[1]),
        iat: None,
        instr_limit: 50_000_000_000,
    };
    let (mut width, mut height) = (0u32, 0u32);
    let mut fmt = String::from("yuy2");
    let mut input = PathBuf::new();
    let mut out_prefix = PathBuf::new();
    let mut bih_path = PathBuf::new();
    let mut frame_path = PathBuf::new();
    let mut out = PathBuf::new();
    let mut flag: Option<u8> = None;
    let mut height_override: Option<u32> = None;
    let mut i = 2;
    while i < argv.len() {
        let k = argv[i].as_str();
        let mut val = || {
            i += 1;
            argv[i].clone()
        };
        match k {
            "--width" => width = parse_u32(&val()),
            "--height" => {
                let v = parse_u32(&val());
                height = v;
                height_override = Some(v);
            }
            "--fmt" | "--pix" => fmt = val(),
            "--in" => input = PathBuf::from(val()),
            "--out-prefix" => out_prefix = PathBuf::from(val()),
            "--bih" => bih_path = PathBuf::from(val()),
            "--frame" => frame_path = PathBuf::from(val()),
            "--out" => out = PathBuf::from(val()),
            "--flag" => flag = Some(parse_u32(&val()) as u8),
            "--iat" => c.iat = Some(parse_u32(&val())),
            "--instr-limit" => c.instr_limit = val().parse().expect("u64"),
            "--ini" => {
                let v = val();
                let (kk, vv) = v.split_once('=').expect("key=val");
                INI.lock().unwrap().push((kk.to_string(), parse_u32(vv)));
            }
            _ => panic!("unexpected arg {k}"),
        }
        i += 1;
    }

    match cmd.as_str() {
        "encode" => {
            let (bits, comp, bpp): (u16, [u8; 4], u32) = match fmt.as_str() {
                "yuy2" => (16, *b"YUY2", 2),
                "bgr24" => (24, [0; 4], 3),
                "bgr32" => (32, [0; 4], 4),
                _ => panic!("fmt"),
            };
            let pixels = std::fs::read(&input).expect("read input");
            let need = (width * height * bpp) as usize;
            assert!(
                pixels.len() >= need,
                "input too short: {} < {need}",
                pixels.len()
            );
            let in_bih = Bih {
                bi_size: 40,
                width: width as i32,
                height: height as i32,
                planes: 1,
                bit_count: bits,
                compression: comp,
                size_image: (width * height * bpp),
                ..Bih::default()
            };
            let (mut sb, hic) = boot(&c, ICMODE_COMPRESS);
            let (_, out_bih) = sb.ic_compress_get_format(hic, &in_bih).expect("GetFormat");
            eprintln!(
                "[encode] out BIH: biSize={} bits={} comp={:?} sizeImage={} tail={} bytes",
                out_bih.bi_size,
                out_bih.bit_count,
                std::str::from_utf8(&out_bih.compression).unwrap_or("?"),
                out_bih.size_image,
                out_bih.tail.len()
            );
            let q = sb
                .ic_compress_query(hic, &in_bih, Some(&out_bih))
                .expect("Query");
            assert_eq!(q, 0, "ICCompressQuery rejected");
            let cap = sb
                .ic_compress_get_size(hic, &in_bih, &out_bih)
                .expect("GetSize");
            let rb = sb.ic_compress_begin(hic, &in_bih, &out_bih).expect("Begin");
            eprintln!("[encode] ICCompressBegin = {} cap = {cap}", rb as i32);
            let r = sb
                .ic_compress(
                    hic,
                    ICCOMPRESS_KEYFRAME,
                    &in_bih,
                    &pixels[..need],
                    &out_bih,
                    cap,
                    0,
                    0,
                    0,
                    10000,
                    None,
                    None,
                )
                .expect("ICCompress");
            eprintln!(
                "[encode] ICCompress = {} bytes = {} (biSizeImage={})",
                r.lresult as i32,
                r.bytes.len(),
                r.output_bih.size_image
            );
            assert_eq!(r.lresult, 0);
            let n = r.output_bih.size_image as usize;
            let frame = &r.bytes[..n.min(r.bytes.len())];
            let mut bp = out_prefix.clone();
            bp.set_extension("bih");
            std::fs::write(&bp, bih_to_bytes(&out_bih)).expect("write bih");
            let mut fp = out_prefix.clone();
            fp.set_extension("frame");
            std::fs::write(&fp, frame).expect("write frame");
            eprintln!(
                "[encode] wrote {} ({} B) and {} ({} B)",
                bp.display(),
                40 + out_bih.tail.len(),
                fp.display(),
                frame.len()
            );
            let _ = sb.ic_compress_end(hic);
            let _ = sb.ic_close(hic);
        }
        "decode" => {
            let (bits, comp, bpp): (u16, [u8; 4], u32) = match fmt.as_str() {
                "yuy2" => (16, *b"YUY2", 2),
                "rgb24" => (24, [0; 4], 3),
                "rgb32" => (32, [0; 4], 4),
                _ => panic!("pix"),
            };
            let mut bih_bytes = std::fs::read(&bih_path).expect("read bih");
            if let Some(f) = flag {
                assert!(bih_bytes.len() > 0x2a);
                eprintln!(
                    "[decode] patch BIH+0x2A: {:#04x} -> {:#04x}",
                    bih_bytes[0x2a], f
                );
                bih_bytes[0x2a] = f;
            }
            let mut in_bih = bih_from_bytes(&bih_bytes);
            if let Some(h) = height_override {
                eprintln!("[decode] override biHeight {} -> {h}", in_bih.height);
                in_bih.height = h as i32;
            }
            let frame = std::fs::read(&frame_path).expect("read frame");
            in_bih.size_image = frame.len() as u32;
            let w = in_bih.width as u32;
            let h = in_bih.height as u32;
            let out_bih = Bih {
                bi_size: 40,
                width: w as i32,
                height: h as i32,
                planes: 1,
                bit_count: bits,
                compression: comp,
                size_image: w * h * bpp,
                ..Bih::default()
            };
            let (mut sb, hic) = boot(&c, ICMODE_DECOMPRESS);
            let q = sb
                .ic_decompress_query(hic, &in_bih, Some(&out_bih))
                .expect("Query");
            eprintln!("[decode] ICDecompressQuery = {}", q as i32);
            assert_eq!(q, 0, "ICDecompressQuery rejected");
            let rb = sb
                .ic_decompress_begin(hic, &in_bih, &out_bih)
                .expect("Begin");
            eprintln!("[decode] ICDecompressBegin = {}", rb as i32);
            let (rc, decoded) = sb
                .ic_decompress(hic, 0, &in_bih, &frame, &out_bih, w * h * bpp)
                .expect("ICDecompress");
            eprintln!(
                "[decode] ICDecompress = {} ({} bytes)",
                rc as i32,
                decoded.len()
            );
            std::fs::write(&out, &decoded).expect("write out");
            eprintln!("[decode] wrote {}", out.display());
            let _ = sb.ic_decompress_end(hic);
            let _ = sb.ic_close(hic);
        }
        _ => panic!("cmd"),
    }
}

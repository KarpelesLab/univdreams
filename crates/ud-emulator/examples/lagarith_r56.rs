//! Lagarith Validator round 56 (docs issue #437, 2026-09-25) — sandbox harness.
//!
//! Drives `syswow64/lagarith.dll` (i386, SHA-256 `bac1ea74…f20bcc`) inside
//! the `ud-emulator` sandbox. Differences from `lagarith_r54`:
//!
//! * `decodepad` hands the decoder a full Windows-DIB output buffer
//!   (`round_up_4(W*bpp/8) * H` bytes, `biSizeImage` set to that) plus a
//!   guard tail, pre-filled with a caller-chosen byte, and dumps the whole
//!   buffer — so pad bytes and any over-run are visible and "untouched"
//!   can be told apart from "written" by changing the fill byte.
//! * `encode` takes the input as a full DIB (padded rows) when `stride=dib`.
//! * `padwatch` (build with `--features trace`) logs every guest store that
//!   touches a pad byte or the guard tail, with the storing EIP.
//! * `encwatch` runs one encode with register watchpoints at caller-supplied
//!   PCs and prints the GP registers at each hit.
//! * `LAG_POKE="10034ce1=1"` stores bytes into the image after ICOpen and
//!   after IC*Begin (CPU-feature flags; see `poke`).
//!
//! ```text
//! lagarith_r56 <dll> encode    <fmt> <W> <H> <in.raw> <out.lags> [tight|dib]
//! lagarith_r56 <dll> decodepad <fmt> <W> <H> <in.lags> <out.raw> <fill-hex> <guard>
//! lagarith_r56 <dll> padwatch  <fmt> <W> <H> <in.lags> <fill-hex> <guard>
//! lagarith_r56 <dll> encwatch  <fmt> <W> <H> <in.raw> <out.lags> <pc,pc,...> [tight|dib]
//! ```
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

use ud_emulator::win32::vfw32::{self, Bih};
use ud_emulator::{DLL_PROCESS_ATTACH, Sandbox};

const MODE_DECODE: u32 = 1;
const MODE_ENCODE: u32 = 2;
const ICCOMPRESS_KEYFRAME: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Rgb24,
    Rgb32,
}

impl Fmt {
    fn parse(s: &str) -> Fmt {
        match s {
            "rgb24" | "bgr24" => Fmt::Rgb24,
            "rgb32" | "bgr32" | "rgba" | "bgra" => Fmt::Rgb32,
            _ => panic!("unsupported fmt {s} (this harness does RGB only)"),
        }
    }
    fn bpp(self) -> u32 {
        match self {
            Fmt::Rgb24 => 3,
            Fmt::Rgb32 => 4,
        }
    }
    fn tight(self, w: u32, h: u32) -> u32 {
        w * h * self.bpp()
    }
    fn stride(self, w: u32) -> u32 {
        (w * self.bpp() + 3) & !3
    }
    fn dib(self, w: u32, h: u32) -> u32 {
        self.stride(w) * h
    }
    fn bih(self, w: u32, h: u32, size_image: u32) -> Bih {
        Bih {
            bi_size: 40,
            width: w as i32,
            height: h as i32,
            planes: 1,
            bit_count: (self.bpp() * 8) as u16,
            compression: [0; 4],
            size_image,
            ..Bih::default()
        }
    }
}

fn lags_bih(fmt: Fmt, w: u32, h: u32, len: usize) -> Bih {
    Bih {
        bi_size: 40,
        width: w as i32,
        height: h as i32,
        planes: 1,
        bit_count: (fmt.bpp() * 8) as u16,
        compression: *b"LAGS",
        size_image: len as u32,
        ..Bih::default()
    }
}

fn open(dll: &str) -> Sandbox {
    let bytes = std::fs::read(dll).expect("read dll");
    let mut sb = Sandbox::new();
    if let Ok(spec) = std::env::var("LAG_REG") {
        let mut reg = ud_emulator::VirtualRegistry::new();
        for kv in spec.split(';').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').expect("LAG_REG entry k=v");
            let v: u32 = v.parse().expect("LAG_REG value");
            reg.set_value(
                "HKEY_CURRENT_USER\\Software\\Lagarith",
                k,
                ud_emulator::RegistryValue::Dword(v),
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
    sb
}

/// `LAG_POKE="10034ce1=1;..."` stores bytes into the image after ICOpen —
/// used to force the codec's CPU-feature flags (CPUID.EDX bit 25 → byte
/// 0x10034ce1, bit 26 → 0x10034ce2; set at 0x1001dfb3/0x1001dfb9) so the
/// SSE-flagged predictor branch can be exercised on the MMX-only sandbox CPU.
fn poke(sb: &mut Sandbox) {
    if let Ok(spec) = std::env::var("LAG_POKE") {
        for kv in spec.split(';').filter(|s| !s.is_empty()) {
            let (a, v) = kv.split_once('=').expect("addr=val");
            let a = u32::from_str_radix(a, 16).unwrap();
            let v = u8::from_str_radix(v, 16).unwrap();
            sb.mmu.store8(a, v).unwrap();
            eprintln!("[poke] {a:#x} = {v:#x}");
        }
    }
}

fn fcc(s: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*s)
}

fn do_encode(sb: &mut Sandbox, fmt: Fmt, w: u32, h: u32, raw: &[u8], dib: bool) -> (u32, Vec<u8>) {
    let hic = sb
        .ic_open(fcc(b"VIDC"), fcc(b"LAGS"), MODE_ENCODE)
        .expect("ICOpen");
    assert_ne!(hic, 0);
    poke(sb);
    let n = if dib { fmt.dib(w, h) } else { fmt.tight(w, h) };
    assert!(raw.len() >= n as usize, "input {} < {}", raw.len(), n);
    let in_bih = fmt.bih(w, h, n);
    let (_, out_bih) = sb.ic_compress_get_format(hic, &in_bih).expect("GetFormat");
    let q = sb
        .ic_compress_query(hic, &in_bih, Some(&out_bih))
        .expect("CompressQuery");
    assert_eq!(q as i32, 0, "ICCompressQuery rejected");
    let cap = sb
        .ic_compress_get_size(hic, &in_bih, &out_bih)
        .expect("GetSize");
    let _ = sb.ic_compress_begin(hic, &in_bih, &out_bih);
    poke(sb);
    let r = sb
        .ic_compress(
            hic,
            ICCOMPRESS_KEYFRAME,
            &in_bih,
            &raw[..n as usize],
            &out_bih,
            cap,
            0,
            0,
            0,
            5000,
            None,
            None,
        )
        .expect("ICCompress");
    let n_out = (r.output_bih.size_image as usize).min(r.bytes.len());
    let mut bytes = r.bytes;
    bytes.truncate(n_out);
    let _ = sb.ic_compress_end(hic);
    let _ = sb.ic_close(hic);
    (r.lresult, bytes)
}

/// `ICM_DECOMPRESS` with a caller-controlled output buffer: `dib + guard`
/// bytes, all pre-set to `fill`; returns (lresult, whole buffer, buffer VA).
fn decode_pad(
    sb: &mut Sandbox,
    fmt: Fmt,
    w: u32,
    h: u32,
    frame: &[u8],
    fill: u8,
    guard: u32,
    watch: bool,
) -> (u32, Vec<u8>, u32) {
    let hic = sb
        .ic_open(fcc(b"VIDC"), fcc(b"LAGS"), MODE_DECODE)
        .expect("ICOpen");
    assert_ne!(hic, 0);
    poke(sb);
    let in_bih = lags_bih(fmt, w, h, frame.len());
    let out_bih = fmt.bih(w, h, fmt.dib(w, h));
    let q = sb
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .expect("DecompressQuery");
    assert_eq!(q as i32, 0, "ICDecompressQuery rejected");
    let _ = sb.ic_decompress_begin(hic, &in_bih, &out_bih);
    poke(sb);

    let entry = sb.host.hics.get(&hic).cloned().expect("hic");
    let cap = fmt.dib(w, h) + guard;
    let bi_in = sb
        .host
        .arena_alloc(vfw32::BIH_SIZE + vfw32::BIH_TAIL_CAP)
        .unwrap();
    vfw32::host_bih_to_guest(&mut sb.mmu, &in_bih, bi_in).unwrap();
    let bi_out = sb
        .host
        .arena_alloc(vfw32::BIH_SIZE + vfw32::BIH_TAIL_CAP)
        .unwrap();
    vfw32::host_bih_to_guest(&mut sb.mmu, &out_bih, bi_out).unwrap();
    let in_buf = sb.host.arena_alloc(frame.len() as u32).unwrap();
    sb.mmu.write_initializer(in_buf, frame).unwrap();
    // 16 bytes of fill before the buffer too, to see under-runs.
    let pre = sb.host.arena_alloc(16).unwrap();
    let out_buf = sb.host.arena_alloc(cap).unwrap();
    assert!(out_buf >= pre + 16);
    sb.mmu
        .write_initializer(pre, &vec![fill; (out_buf - pre) as usize])
        .unwrap();
    sb.mmu
        .write_initializer(out_buf, &vec![fill; cap as usize])
        .unwrap();
    let icd = sb.host.arena_alloc(vfw32::ICDECOMPRESS_SIZE).unwrap();
    for (off, v) in [
        (0u32, 0u32),
        (4, bi_in),
        (8, in_buf),
        (12, bi_out),
        (16, out_buf),
        (20, 0),
    ] {
        sb.mmu.store32(icd + off, v).unwrap();
    }
    #[cfg(feature = "trace")]
    if watch {
        let stride = fmt.stride(w);
        let row = w * fmt.bpp();
        for y in 0..h {
            if stride > row {
                sb.watch(
                    out_buf + y * stride + row,
                    stride - row,
                    ud_emulator::WatchMode::Write,
                );
            }
        }
        if guard > 0 {
            sb.watch(
                out_buf + fmt.dib(w, h),
                guard,
                ud_emulator::WatchMode::Write,
            );
        }
        sb.watch(pre, out_buf - pre, ud_emulator::WatchMode::Write);
        sb.set_trace_sink(Box::new(std::io::stdout()));
    }
    #[cfg(not(feature = "trace"))]
    assert!(!watch, "padwatch needs --features trace");
    let lresult = ud_emulator::win32::call_guest(
        &mut sb.cpu,
        &mut sb.mmu,
        &mut sb.registry,
        &mut sb.host,
        entry.driver_proc_va,
        &[
            entry.driver_id,
            hic,
            vfw32::ICM_DECOMPRESS,
            icd,
            vfw32::ICDECOMPRESS_SIZE,
        ],
    )
    .expect("ICM_DECOMPRESS");
    let mut out = vec![0u8; cap as usize];
    for (i, b) in out.iter_mut().enumerate() {
        *b = sb.mmu.load8(out_buf + i as u32).unwrap();
    }
    let mut under = Vec::new();
    for a in pre..out_buf {
        under.push(sb.mmu.load8(a).unwrap());
    }
    if under.iter().any(|b| *b != fill) {
        eprintln!("[decodepad] UNDER-RUN: bytes before buffer changed: {under:02x?}");
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    (lresult, out, out_buf)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dll = &a[1];
    let fmt = Fmt::parse(&a[3]);
    let (w, h): (u32, u32) = (a[4].parse().unwrap(), a[5].parse().unwrap());
    match a[2].as_str() {
        "encode" => {
            let raw = std::fs::read(&a[6]).expect("read input");
            let dib = a.get(8).map_or(false, |s| s == "dib");
            let mut sb = open(dll);
            let (rc, bytes) = do_encode(&mut sb, fmt, w, h, &raw, dib);
            std::fs::write(&a[7], &bytes).expect("write");
            eprintln!(
                "[encode] rc={} bytes={} type={}",
                rc as i32,
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            );
        }
        "decodepad" | "padwatch" => {
            let frame = std::fs::read(&a[6]).expect("read frame");
            let watch = a[2] == "padwatch";
            let (fill_s, guard_s) = if watch {
                (&a[7], &a[8])
            } else {
                (&a[8], &a[9])
            };
            let fill = u8::from_str_radix(fill_s, 16).unwrap();
            let guard: u32 = guard_s.parse().unwrap();
            let mut sb = open(dll);
            let (rc, out, va) = decode_pad(&mut sb, fmt, w, h, &frame, fill, guard, watch);
            eprintln!(
                "[decodepad] rc={} buf_va={:#x} stride={} dib={} guard={} fill={:02x}",
                rc as i32,
                va,
                fmt.stride(w),
                fmt.dib(w, h),
                guard,
                fill
            );
            let dibn = fmt.dib(w, h) as usize;
            if out[dibn..].iter().any(|b| *b != fill) {
                eprintln!("[decodepad] OVER-RUN into guard: {:02x?}", &out[dibn..]);
            }
            if !watch {
                std::fs::write(&a[7], &out).expect("write");
            }
        }
        "encwatch" => {
            let raw = std::fs::read(&a[6]).expect("read input");
            let pcs: Vec<u32> = a[8]
                .split(',')
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .collect();
            let dib = a.get(9).map_or(false, |s| s == "dib");
            let mut sb = open(dll);
            sb.cpu.register_snapshots_cap = 1_000_000;
            for p in &pcs {
                sb.cpu.add_register_watchpoint(*p);
            }
            let (rc, bytes) = do_encode(&mut sb, fmt, w, h, &raw, dib);
            std::fs::write(&a[7], &bytes).expect("write");
            let snaps = sb.cpu.clear_register_watchpoints();
            for (pc, r) in &snaps {
                println!(
                    "{pc:#010x} eax={:08x} ecx={:08x} edx={:08x} ebx={:08x} esp={:08x} ebp={:08x} esi={:08x} edi={:08x}",
                    r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]
                );
            }
            eprintln!(
                "[encwatch] rc={} bytes={} type={} snaps={}",
                rc as i32,
                bytes.len(),
                bytes.first().copied().unwrap_or(0),
                snaps.len()
            );
        }
        o => panic!("unknown command {o}"),
    }
}

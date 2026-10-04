//! re2_indeo5_r18 — Extractor/Validator harness for the Indeo 5 clean-room
//! (docs workspace `video/indeo/indeo5`, provenance round 18, issue #438).
//!
//! Two modes, selected by `R18_MODE`:
//!
//! * `dec` (default): drive `IR50_32.DLL` through ICOpen → Query → Begin →
//!   Decompress × N on a list of IV50 frames (`R18_FRAMES`, comma-separated
//!   paths, decoded in order on one HIC). Output format `R18_PIX`:
//!   `yuy2` | `rgb24` | `yvu9` | `if09` | `yv12` | `i420` (the last four
//!   are raw BIH attempts; the query result is printed). Register
//!   watchpoints at `R18_REG_WP` (hex list); per-snapshot memory probes
//!   `R18_PROBES` = `reg:off:w,...` (reg 0..7 = eax ecx edx ebx esp ebp esi
//!   edi; w = 1 or 4); one block dump `R18_DUMP` = `eip:reg:len` (or
//!   `eip:reg:off:len`, offset applied to the register).
//! * `enc`: drive the vendor encoder on `R18_ENC_INPUT` (raw BGR24 frames,
//!   bottom-up, concatenated), `R18_ENC_N` frames, first frame a keyframe,
//!   the rest delta frames with the previous *input* frame as lpPrev,
//!   quality `R18_ENC_Q`; writes `enc-fNN.iv50` + `enc-frames.csv`.
//!
//! Everything is written under `R18_OUT`. Run with
//! `cargo test --release -p ud-emulator --test re2_indeo5_r18 -- --nocapture`.

// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::unreadable_literal
)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use ud_emulator::{Bih, DLL_PROCESS_ATTACH, Sandbox};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn hex(t: &str) -> u32 {
    u32::from_str_radix(t.trim().trim_start_matches("0x"), 16).unwrap()
}

fn new_sandbox() -> (Sandbox, u32) {
    let dll_path = env_or(
        "R18_DLL",
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/indeo/indeo5/reference/binaries/IR50_32.DLL",
    );
    let dll = fs::read(&dll_path).expect("read DLL");
    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(40_000_000_000);
    let img = sb.load("IR50_32.DLL", &dll).expect("load");
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");
    let mode = if env_or("R18_MODE", "dec") == "enc" {
        1
    } else {
        2
    };
    let hic = sb
        .ic_open(
            u32::from_le_bytes(*b"VIDC"),
            u32::from_le_bytes(*b"IV50"),
            mode,
        )
        .expect("ICOpen");
    assert_ne!(hic, 0, "codec refused DRV_OPEN");
    (sb, hic)
}

fn dump_ring(sb: &Sandbox, out_dir: &PathBuf, tag: &str) {
    let ring = &sb.cpu.trace_ring;
    let mut f = fs::File::create(out_dir.join(format!("ring-{tag}.txt"))).unwrap();
    for e in ring.iter() {
        writeln!(f, "{e:#010x}").unwrap();
    }
    println!(
        "[r18] trace ring ({} eips) -> ring-{tag}.txt; last = {:#010x?}",
        ring.len(),
        ring.last()
    );
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn re2_indeo5_r18() {
    let out_dir = PathBuf::from(env_or("R18_OUT", "/tmp/re2-indeo5-r18"));
    fs::create_dir_all(&out_dir).unwrap();
    if env_or("R18_MODE", "dec") == "enc" {
        run_enc(&out_dir);
    } else {
        run_dec(&out_dir);
    }
}

fn run_enc(out_dir: &PathBuf) {
    let width: u32 = env_or("R18_W", "160").parse().unwrap();
    let height: u32 = env_or("R18_H", "120").parse().unwrap();
    let n: usize = env_or("R18_ENC_N", "2").parse().unwrap();
    let quality: u32 = env_or("R18_ENC_Q", "8500").parse().unwrap();
    let key_every: usize = env_or("R18_ENC_KEY_EVERY", "0").parse().unwrap();
    let input = fs::read(env_or("R18_ENC_INPUT", "/tmp/in.bgr")).expect("read enc input");
    let fsz = (width * height * 3) as usize;
    assert!(input.len() >= fsz * n, "input too short");
    let (mut sb, hic) = new_sandbox();
    sb.cpu.enable_trace_ring(64);
    let in_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: [0; 4],
        size_image: fsz as u32,
        ..Bih::default()
    };
    let gf = sb.ic_compress_get_format(hic, &in_bih);
    let out_bih = match gf {
        Ok((lr, b)) => {
            println!(
                "[r18] GetFormat = {} -> {}x{} bc={} {:?} size={} bi_size={} tail={}",
                lr as i32,
                b.width,
                b.height,
                b.bit_count,
                String::from_utf8_lossy(&b.compression),
                b.size_image,
                b.bi_size,
                b.tail.len()
            );
            b
        }
        Err(e) => {
            dump_ring(&sb, out_dir, "getformat");
            panic!("GetFormat: {e}");
        }
    };
    let q = sb.ic_compress_query(hic, &in_bih, Some(&out_bih));
    println!("[r18] CompressQuery = {:?}", q.as_ref().map(|v| *v as i32));
    if q.is_err() {
        dump_ring(&sb, out_dir, "query");
    }
    let cap = sb
        .ic_compress_get_size(hic, &in_bih, &out_bih)
        .unwrap_or(fsz as u32 * 2)
        .max(fsz as u32);
    println!("[r18] GetSize = {cap}");
    let b = sb.ic_compress_begin(hic, &in_bih, &out_bih);
    println!("[r18] CompressBegin = {:?}", b.as_ref().map(|v| *v as i32));
    if b.is_err() {
        dump_ring(&sb, out_dir, "begin");
    }
    let mut csv = fs::File::create(out_dir.join("enc-frames.csv")).unwrap();
    writeln!(csv, "frame,requested_key,lresult,bytes,out_flags,ckid").unwrap();
    for i in 0..n {
        let cur = &input[i * fsz..(i + 1) * fsz];
        let key = i == 0 || (key_every > 0 && i % key_every == 0);
        let prev = if key {
            None
        } else {
            Some(&input[(i - 1) * fsz..i * fsz])
        };
        let r = sb.ic_compress(
            hic,
            u32::from(key),
            &in_bih,
            cur,
            &out_bih,
            cap,
            0,
            i as i32,
            0,
            quality,
            prev.map(|_| &in_bih),
            prev,
        );
        match r {
            Ok(o) => {
                let len = o.output_bih.size_image as usize;
                let bytes = &o.bytes[..len.min(o.bytes.len())];
                fs::write(out_dir.join(format!("enc-f{i:02}.iv50")), bytes).unwrap();
                println!(
                    "[r18] ICCompress f{i} key={key} = {} len={len} flags={:#x}",
                    o.lresult as i32, o.returned_flags
                );
                writeln!(
                    csv,
                    "{i},{},{},{len},{:#x},{:#x}",
                    u8::from(key),
                    o.lresult as i32,
                    o.returned_flags,
                    o.ckid
                )
                .unwrap();
            }
            Err(e) => {
                dump_ring(&sb, out_dir, &format!("compress-f{i}"));
                panic!("ICCompress f{i}: {e}");
            }
        }
    }
    let _ = sb.ic_compress_end(hic);
    let _ = sb.ic_close(hic);
}

fn run_dec(out_dir: &PathBuf) {
    let width: u32 = env_or("R18_W", "320").parse().unwrap();
    let height: u32 = env_or("R18_H", "240").parse().unwrap();
    let pix = env_or("R18_PIX", "yuy2");
    let frames: Vec<String> = env_or(
        "R18_FRAMES",
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/indeo/indeo5/fixtures/intra-320x240-indeo5/input.iv50",
    )
    .split(',')
    .map(str::to_string)
    .collect();
    let wps: Vec<u32> = std::env::var("R18_REG_WP")
        .ok()
        .map(|s| s.split(',').filter(|t| !t.is_empty()).map(hex).collect())
        .unwrap_or_default();
    let probes: Vec<(u8, i32, u8)> = std::env::var("R18_PROBES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter(|t| !t.is_empty())
                .map(|t| {
                    let p: Vec<&str> = t.split(':').collect();
                    let off = if let Some(x) = p[1].strip_prefix('-') {
                        -(hex(x) as i32)
                    } else {
                        hex(p[1]) as i32
                    };
                    (p[0].parse().unwrap(), off, p[2].parse().unwrap())
                })
                .collect()
        })
        .unwrap_or_default();
    let dump = std::env::var("R18_DUMP").ok().map(|s| {
        let p: Vec<&str> = s.split(':').collect();
        (hex(p[0]), p[1].parse::<u8>().unwrap(), hex(p[2]))
    });

    let (mut sb, hic) = new_sandbox();
    let (bit_count, compression, size): (u16, [u8; 4], u32) = match pix.as_str() {
        "yuy2" => (16, *b"YUY2", width * height * 2),
        "rgb24" => (24, [0; 4], width * height * 3),
        "yvu9" => (9, *b"YVU9", width * height * 9 / 8),
        "if09" => (9, *b"IF09", width * height * 9 / 8 + width * height / 16),
        "yv12" => (12, *b"YV12", width * height * 3 / 2),
        "i420" => (12, *b"I420", width * height * 3 / 2),
        "iyuv" => (12, *b"IYUV", width * height * 3 / 2),
        "uyvy" => (16, *b"UYVY", width * height * 2),
        other => panic!("unknown R18_PIX {other}"),
    };
    let first = fs::read(&frames[0]).expect("read frame");
    let mut in_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: *b"IV50",
        size_image: first.len() as u32,
        ..Bih::default()
    };
    let out_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count,
        compression,
        size_image: size,
        ..Bih::default()
    };
    let q = sb
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .expect("query");
    println!(
        "[r18] ICDecompressQuery({width}x{height} IV50 -> {pix}) = {}",
        q as i32
    );
    if q != 0 {
        return;
    }
    if let Ok(w) = std::env::var("R18_WATCH_BEGIN") {
        let p: Vec<&str> = w.split(':').collect();
        let sink = fs::File::create(out_dir.join("trace-watch-begin.jsonl")).unwrap();
        sb.set_trace_sink(Box::new(sink));
        sb.watch(hex(p[0]), hex(p[1]), ud_emulator::WatchMode::Write);
    }
    let b = sb
        .ic_decompress_begin(hic, &in_bih, &out_bih)
        .expect("begin");
    println!("[r18] ICDecompressBegin = {}", b as i32);

    sb.cpu.register_snapshots_cap = 8_000_000;
    sb.cpu.snapshot_probes = probes.clone();
    sb.cpu.snapshot_block_dump = dump;
    for wp in &wps {
        sb.cpu.add_register_watchpoint(*wp);
    }
    let mut hashes = fs::File::create(out_dir.join("frames.csv")).unwrap();
    writeln!(hashes, "frame,input,input_len,rc,out_len,snap_end").unwrap();
    let mut snap_start = 0usize;
    for (i, path) in frames.iter().enumerate() {
        let frame = fs::read(path).expect("read frame");
        in_bih.size_image = frame.len() as u32;
        let cur0 = sb.host.heap_cursor;
        if let Ok(w) = std::env::var("R18_WATCH") {
            // addr:len (write watch), armed only for the frame index R18_WATCH_FRAME (default last)
            let wf: usize = env_or("R18_WATCH_FRAME", &format!("{}", frames.len() - 1))
                .parse()
                .unwrap();
            if wf == i {
                let p: Vec<&str> = w.split(':').collect();
                let sink =
                    fs::File::create(out_dir.join(format!("trace-watch-f{i:02}.jsonl"))).unwrap();
                sb.set_trace_sink(Box::new(sink));
                sb.watch(hex(p[0]), hex(p[1]), ud_emulator::WatchMode::Write);
            }
        }
        let (rc, decoded) = sb
            .ic_decompress(hic, 0, &in_bih, &frame, &out_bih, size)
            .expect("ICDecompress");
        for (a, v) in sb.host.heap.range(cur0..) {
            if v.len() == size as usize {
                println!(
                    "[r18] f{i} candidate output buffer {a:#010x} len {}",
                    v.len()
                );
            }
        }
        fs::write(out_dir.join(format!("decoded-{pix}-f{i:02}.bin")), &decoded).unwrap();
        println!(
            "[r18] f{i} ICDecompress = {} ({} bytes)",
            rc as i32,
            decoded.len()
        );
        // Post-frame plane dump: every writer call at 0x100342d0 in this frame
        // (dst = edx, dst stride = ecx, rows = ebp, width = esi).
        if env_or("R18_PLANEDUMP", "0") == "1" {
            let snaps_now: Vec<(u32, [u32; 8])> = sb.cpu.register_snapshots[snap_start..].to_vec();
            let mut k = 0;
            for (eip, r) in snaps_now {
                if eip != 0x100342d0 {
                    continue;
                }
                let (dst, stride, rows, width) = (r[2], r[1], r[5], r[6]);
                let mut plane = Vec::with_capacity((width * rows) as usize);
                for y in 0..rows {
                    for x in 0..width {
                        plane.push(sb.mmu.load8(dst + y * stride + x).unwrap_or(0));
                    }
                }
                fs::write(
                    out_dir.join(format!("plane-f{i:02}-{k}-{width}x{rows}.bin")),
                    &plane,
                )
                .unwrap();
                k += 1;
            }
        }
        snap_start = sb.cpu.register_snapshots.len();
        writeln!(
            hashes,
            "{i},{path},{},{},{},{}",
            frame.len(),
            rc as i32,
            decoded.len(),
            sb.cpu.register_snapshots.len()
        )
        .unwrap();
    }
    let (pvals, dumps) = sb.cpu.take_snapshot_probes();
    let snaps = sb.cpu.clear_register_watchpoints();
    println!(
        "[r18] register snapshots: {}, block dumps: {}",
        snaps.len(),
        dumps.len()
    );
    let mut f = fs::File::create(out_dir.join("regsnaps.tsv")).unwrap();
    write!(f, "i\teip\teax\tecx\tedx\tebx\tesp\tebp\tesi\tedi").unwrap();
    for (r, o, w) in &probes {
        write!(f, "\tp{r}{o:+#x}w{w}").unwrap();
    }
    writeln!(f).unwrap();
    for (i, (eip, r)) in snaps.iter().enumerate() {
        write!(
            f,
            "{i}\t{eip:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}",
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]
        )
        .unwrap();
        if let Some(pv) = pvals.get(i) {
            for v in pv {
                match v {
                    Some(x) => write!(f, "\t{x:#x}").unwrap(),
                    None => write!(f, "\t-").unwrap(),
                }
            }
        }
        writeln!(f).unwrap();
    }
    if !dumps.is_empty() {
        let mut blob = Vec::new();
        let mut idx = fs::File::create(out_dir.join("dumps.csv")).unwrap();
        writeln!(idx, "dump,snap_index,offset,len").unwrap();
        for (k, (si, bytes)) in dumps.iter().enumerate() {
            writeln!(idx, "{k},{si},{},{}", blob.len(), bytes.len()).unwrap();
            blob.extend_from_slice(bytes);
        }
        fs::write(out_dir.join("dumps.bin"), &blob).unwrap();
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
}

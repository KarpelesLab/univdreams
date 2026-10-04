//! re2_indeo5_dequant — Validator/Extractor harness for the Indeo 5
//! clean-room (docs workspace `video/indeo/indeo5`, provenance round 16).
//!
//! Drives `IR50_32.DLL` through ICOpen → ICDecompressQuery → Begin →
//! Decompress on a staged IV50 fixture frame and records:
//!
//! 1. the `.sdata` quantiser-matrix bank `0x1007b000..0x1007f800` at four
//!    points (after load, after DllMain, after ICOpen, after Begin);
//! 2. the reconstruction-table pointer array `.bss 0x1009c770[0..256]`;
//! 3. every guest READ of the reconstruction-table heap (memory
//!    watchpoint, JSONL `mem_read` events with the reading EIP);
//! 4. register snapshots at the `band_glob_quant` consumer sites and at
//!    any extra EIPs given in `RE2_REG_WP` (comma-separated hex);
//! 5. the decoded frame (pix format from `RE2_PIX`: yuv|rgb24|rgb32).
//!
//! Everything is written under `RE2_OUT`. Run with
//! `cargo test --release -p ud-emulator --features trace --test re2_indeo5_dequant -- --nocapture`.

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

use ud_emulator::{Bih, DLL_PROCESS_ATTACH, Sandbox, WatchMode};

const SDATA_LO: u32 = 0x1007b000;
const SDATA_HI: u32 = 0x1007f800;
const PTRARRAY: u32 = 0x1009c770;
const SITE_BGQ_PTR: u32 = 0x1001f166; // eax = instance, esi = band_glob_quant
const SITE_MB_FETCH: u32 = 0x1001f6e5; // ebx = [esp+0xf4] (table base), edx = 0x80 + rel
const SITE_MB_STORE: u32 = 0x1001f6ef; // ebx = fetched 64-entry table pointer
const SITE_MB_STORE_UNCODED: u32 = 0x1001fb4a; // edx = fetched pointer (uncoded path)

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn dump_range(sb: &Sandbox, lo: u32, hi: u32) -> Vec<u8> {
    (lo..hi).map(|a| sb.mmu.load8(a).unwrap_or(0)).collect()
}

fn write(path: &PathBuf, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn re2_indeo5_dequant() {
    let dll_path = env_or(
        "RE2_IR50_DLL",
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/indeo/indeo5/reference/binaries/IR50_32.DLL",
    );
    let fixture = env_or(
        "RE2_IV50_INPUT",
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/indeo/indeo5/fixtures/intra-320x240-indeo5/input.iv50",
    );
    let width: u32 = env_or("RE2_W", "320").parse().unwrap();
    let height: u32 = env_or("RE2_H", "240").parse().unwrap();
    let pix = env_or("RE2_PIX", "yuv");
    let out_dir = PathBuf::from(env_or("RE2_OUT", "/tmp/re2-indeo5"));
    fs::create_dir_all(&out_dir).unwrap();
    let extra_wps: Vec<u32> = std::env::var("RE2_REG_WP")
        .ok()
        .map(|s| {
            s.split(',')
                .filter(|t| !t.is_empty())
                .map(|t| u32::from_str_radix(t.trim().trim_start_matches("0x"), 16).unwrap())
                .collect()
        })
        .unwrap_or_default();
    let watch_recon = env_or("RE2_WATCH_RECON", "1") == "1";

    let dll = fs::read(&dll_path).expect("read DLL");
    let frame = fs::read(&fixture).expect("read fixture frame");

    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(4_000_000_000);
    let img = sb.load("IR50_32.DLL", &dll).expect("load");
    write(
        &out_dir.join("sdata-0-after-load.bin"),
        &dump_range(&sb, SDATA_LO, SDATA_HI),
    );
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    write(
        &out_dir.join("sdata-1-after-dllmain.bin"),
        &dump_range(&sb, SDATA_LO, SDATA_HI),
    );
    sb.install_codec(&img).expect("install_codec");

    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler = u32::from_le_bytes(*b"IV50");
    let hic = sb.ic_open(fcc_type, fcc_handler, 1).expect("ICOpen");
    assert_ne!(hic, 0, "codec refused DRV_OPEN");
    write(
        &out_dir.join("sdata-2-after-icopen.bin"),
        &dump_range(&sb, SDATA_LO, SDATA_HI),
    );

    let (bit_count, compression, bpp_num, bpp_den): (u16, [u8; 4], u32, u32) = match pix.as_str() {
        "yuv" => (16, *b"YUY2", 2, 1),
        "rgb24" => (24, [0; 4], 3, 1),
        "rgb32" => (32, [0; 4], 4, 1),
        other => panic!("unknown RE2_PIX {other}"),
    };
    let in_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: *b"IV50",
        size_image: frame.len() as u32,
        ..Bih::default()
    };
    let out_size = width * height * bpp_num / bpp_den;
    let out_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count,
        compression,
        size_image: out_size,
        ..Bih::default()
    };
    let q = sb
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .expect("query");
    println!(
        "[re2] ICDecompressQuery({width}x{height} IV50 -> {pix}) = {}",
        q as i32
    );
    assert_eq!(q, 0, "codec rejected the BIH pair");
    let b = sb
        .ic_decompress_begin(hic, &in_bih, &out_bih)
        .expect("begin");
    println!("[re2] ICDecompressBegin = {}", b as i32);
    write(
        &out_dir.join("sdata-3-after-begin.bin"),
        &dump_range(&sb, SDATA_LO, SDATA_HI),
    );

    // Reconstruction-table pointer array.
    let ptrs: Vec<u32> = (0..256u32)
        .map(|i| sb.mmu.load32(PTRARRAY + 4 * i).unwrap_or(0))
        .collect();
    {
        let mut f = fs::File::create(out_dir.join("ptrarray-1009c770.csv")).unwrap();
        writeln!(f, "b,ptr_hex").unwrap();
        for (i, p) in ptrs.iter().enumerate() {
            writeln!(f, "{i},0x{p:08x}").unwrap();
        }
    }
    let heap_lo = ptrs[1];
    let heap_hi = ptrs[255].wrapping_add(8 * (8192 / 255) + 8);
    println!(
        "[re2] recon heap {heap_lo:#010x}..{heap_hi:#010x} ({} bytes)",
        heap_hi.wrapping_sub(heap_lo)
    );

    // Dump the whole reconstruction heap (post-begin, before decode).
    if heap_lo != 0 && heap_hi > heap_lo && heap_hi - heap_lo < 0x200000 {
        write(
            &out_dir.join("recon-heap.bin"),
            &dump_range(&sb, heap_lo, heap_hi),
        );
    }

    if watch_recon && heap_lo != 0 {
        let sink = fs::File::create(out_dir.join("trace-recon-reads.jsonl")).unwrap();
        sb.set_trace_sink(Box::new(sink));
        sb.watch(heap_lo, heap_hi.wrapping_sub(heap_lo), WatchMode::Read);
    }

    sb.cpu.register_snapshots_cap = 8_000_000;
    for wp in [
        SITE_BGQ_PTR,
        SITE_MB_FETCH,
        SITE_MB_STORE,
        SITE_MB_STORE_UNCODED,
    ] {
        sb.cpu.add_register_watchpoint(wp);
    }
    for wp in &extra_wps {
        sb.cpu.add_register_watchpoint(*wp);
    }

    let (rc, decoded) = sb
        .ic_decompress(hic, 0, &in_bih, &frame, &out_bih, out_size)
        .expect("ICDecompress");
    println!(
        "[re2] ICDecompress = {} (output {} bytes; instructions {})",
        rc as i32,
        decoded.len(),
        sb.host.instructions_executed
    );
    write(&out_dir.join(format!("decoded-{pix}.bin")), &decoded);

    let mem = sb.cpu.take_memory_snapshots();
    let snaps = sb.cpu.clear_register_watchpoints();
    println!("[re2] register snapshots: {}", snaps.len());
    {
        let mut f = fs::File::create(out_dir.join("regsnaps.tsv")).unwrap();
        writeln!(
            f,
            "i\teip\teax\tecx\tedx\tebx\tesp\tebp\tesi\tedi\t[esp]\t[esp+4]\t[ebp+8]\t[ebp-0x50]"
        )
        .unwrap();
        for (i, (eip, r)) in snaps.iter().enumerate() {
            let m = mem.get(i).map(|(_, m)| *m).unwrap_or([(0, 0); 4]);
            writeln!(
                f,
                "{i}\t{eip:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}",
                r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], m[0].1, m[1].1, m[2].1, m[3].1
            )
            .unwrap();
        }
    }

    // Post-mortem: instance pointer table at instance+0x33e8 and the 64-entry
    // per-(class,q) tables, mapped back to their step b via ptrarray.
    if let Some((_, r)) = snaps.iter().find(|(e, _)| *e == SITE_BGQ_PTR) {
        let instance = r[0];
        let bgq = r[6];
        println!("[re2] instance = {instance:#010x}, band_glob_quant (first hit) = {bgq}");
        let group = sb.mmu.load32(instance + 0x3e4).unwrap_or(0xffff_ffff);
        println!("[re2] instance+0x3e4 (matrix group) = {group:#x}");
        let mut f = fs::File::create(out_dir.join("live-postables.csv")).unwrap();
        writeln!(f, "class,quant,table_ptr_hex,pos,entry_ptr_hex,step_b").unwrap();
        for c in 0..2u32 {
            for qq in 0..24u32 {
                let tp = sb
                    .mmu
                    .load32(instance + 0x33e8 + 4 * (qq + 24 * c))
                    .unwrap_or(0);
                for pos in 0..64u32 {
                    let ep = sb.mmu.load32(tp + 4 * pos).unwrap_or(0);
                    let b = ptrs
                        .iter()
                        .position(|p| *p == ep)
                        .map_or(-1i32, |x| x as i32);
                    writeln!(f, "{c},{qq},{tp:#010x},{pos},{ep:#010x},{b}").unwrap();
                }
            }
        }
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    println!("[re2] done; outputs under {}", out_dir.display());
}

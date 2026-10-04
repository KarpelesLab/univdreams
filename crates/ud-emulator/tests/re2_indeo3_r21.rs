//! re2_indeo3_r21 — Validator harness for the Indeo 3 clean-room
//! (docs workspace `video/indeo/indeo3`, provenance round 21, issue #438).
//!
//! Drives `IR32_32.DLL` through ICOpen → ICDecompressQuery → Begin →
//! Decompress over all access units of a staged fixture (decode order, one
//! HIC) and records:
//!
//! 1. the codebook staging image (`[0x1004d25a]`, 0x18000 bytes) after Begin;
//! 2. register snapshots (+ stack-slot probes `[esp+0x2c]`, `[esp+0x48]`,
//!    `[esp+0x24]`, `[esp+0x28]`, `[esp+0x34]`, byte `[ebp]`, byte
//!    `[ebp+1]`) at the cell walker, unpacker, prologue, family-body, MC and
//!    VQ_NULL sites listed in `SITES` plus any `RE2_REG_WP` extras;
//! 3. optionally (`RE2_WATCH=lo,hi` hex) every guest WRITE into `[lo, hi)`
//!    as JSONL, together with a dump of `[lo, hi)` taken before each frame,
//!    so the buffer state at every store can be reconstructed offline;
//! 4. the decoded frames (RGB24).
//!
//! Run with
//! `cargo test --release -p ud-emulator --features trace --test re2_indeo3_r21 -- --nocapture`.

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

use ud_emulator::{Bih, Sandbox, WatchMode, DLL_PROCESS_ATTACH};

const STAGING_PTR: u32 = 0x1004d25a;
const SITES: [u32; 30] = [
    0x10006634, // strip plane-buffer pointer (edx)
    0x10006660, // cell positioned (edi = bank, ecx flags)
    0x100066cc, // MC-flag test (edi = cell dest, ecx flags after rol)
    0x100066dc, // MC path entry
    0x100067f9, // after MC copy: VQ leaf bits of an INTER cell
    0x10006805, // INTER: bit 1 -> unpacker
    0x10006823, // INTER: second bit consumed -> mark / pop
    0x10006829, // INTER: VQ_NULL keep (jmp pop)
    0x100069ca, // INTRA (MC clear): VQ leaf bits
    0x100069f4, // INTRA: copy-upper body
    0x10006a2f, // mark path
    0x10006a5b, // cell pop
    0x10006bac, // unpacker entry
    0x10006c14, // LUT rewrite
    0x10006c4a, // second-table dispatch
    0x10006c90, // prologue A/B arena
    0x10006c9c, // prologue A/B staging
    0x10006ca6, // after base add (A/B)
    0x100072bb, // prologue C/D arena
    0x100072c7, // prologue C/D staging
    0x10007710, // prologue D arena
    0x1000771c, // prologue D staging
    0x10007a9b, // prologue E/F staging
    0x10007aa5, // after base add (E/F)
    0x10007abb, // family E body
    0x1000818e, // family F body
    0x10007d94, // E literal, row pair 0
    0x100082e4, // F literal, row pair 0
    0x10006cb2, // family A body
    0x10006fe1, // family B body
];

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn dump_range(sb: &Sandbox, lo: u32, hi: u32) -> Vec<u8> {
    (lo..hi).map(|a| sb.mmu.load8(a).unwrap_or(0)).collect()
}

fn hex(s: &str) -> u32 {
    u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap()
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn re2_indeo3_r21() {
    let dll_path = env_or(
        "RE2_IR32_DLL",
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/indeo/indeo3/reference/binaries/IR32_32.DLL",
    );
    let frames_dir = PathBuf::from(env_or("RE2_IV32_FRAMES", "/tmp/re2-indeo3-frames"));
    let nframes: u32 = env_or("RE2_NFRAMES", "8").parse().unwrap();
    let width: u32 = env_or("RE2_W", "176").parse().unwrap();
    let height: u32 = env_or("RE2_H", "144").parse().unwrap();
    let out_dir = PathBuf::from(env_or("RE2_OUT", "/tmp/re2-indeo3-r21"));
    fs::create_dir_all(&out_dir).unwrap();
    let extra: Vec<u32> = std::env::var("RE2_REG_WP")
        .ok()
        .map(|s| s.split(',').filter(|t| !t.is_empty()).map(hex).collect())
        .unwrap_or_default();
    let watch: Option<(u32, u32)> = std::env::var("RE2_WATCH").ok().map(|s| {
        let v: Vec<u32> = s.split(',').map(hex).collect();
        (v[0], v[1])
    });

    let dll = fs::read(&dll_path).expect("read DLL");
    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(4_000_000_000);
    let img = sb.load("IR32_32.DLL", &dll).expect("load");
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");
    let hic = sb
        .ic_open(
            u32::from_le_bytes(*b"VIDC"),
            u32::from_le_bytes(*b"IV32"),
            1,
        )
        .expect("ICOpen");
    assert_ne!(hic, 0);

    let out_size = width * height * 3;
    let first = fs::read(frames_dir.join("f0.bin")).expect("f0.bin");
    let in_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: *b"IV32",
        size_image: first.len() as u32,
        ..Bih::default()
    };
    let out_bih = Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: [0; 4],
        size_image: out_size,
        ..Bih::default()
    };
    assert_eq!(
        sb.ic_decompress_query(hic, &in_bih, Some(&out_bih))
            .expect("query"),
        0
    );
    let b = sb
        .ic_decompress_begin(hic, &in_bih, &out_bih)
        .expect("begin");
    println!("[r21] ICDecompressBegin = {}", b as i32);
    let staging = sb.mmu.load32(STAGING_PTR).unwrap_or(0);
    println!("[r21] staging image base = {staging:#010x}");
    fs::write(
        out_dir.join("staging-image.bin"),
        dump_range(&sb, staging, staging + 0x18000),
    )
    .unwrap();
    fs::write(
        out_dir.join("staging-base.txt"),
        format!("{staging:#010x}\n"),
    )
    .unwrap();

    if let Some((lo, hi)) = watch {
        let sink = fs::File::create(out_dir.join("trace-writes.jsonl")).unwrap();
        sb.set_trace_sink(Box::new(sink));
        sb.watch(lo, hi - lo, WatchMode::Write);
    }

    // probes: [esp+0x2c], [esp+0x48], [esp+0x24], [esp+0x28], [esp+0x34], b[ebp], b[ebp+1]
    sb.cpu.snapshot_probes = vec![
        (4, 0x2c, 4),
        (4, 0x48, 4),
        (4, 0x24, 4),
        (4, 0x28, 4),
        (4, 0x34, 4),
        (5, 0, 1),
        (5, 1, 1),
    ];

    let mut all = fs::File::create(out_dir.join("regsnaps.tsv")).unwrap();
    writeln!(
        all,
        "frame\ti\teip\teax\tecx\tedx\tebx\tesp\tebp\tesi\tedi\tesp2c\tesp48\tesp24\tesp28\tesp34\tb_ebp\tb_ebp1"
    )
    .unwrap();
    let mut summary = fs::File::create(out_dir.join("frames.csv")).unwrap();
    writeln!(summary, "frame,in_bytes,rc,out_bytes,snapshots").unwrap();
    for fr in 0..nframes {
        let frame = fs::read(frames_dir.join(format!("f{fr}.bin"))).expect("frame");
        let in_bih_f = Bih {
            size_image: frame.len() as u32,
            ..in_bih.clone()
        };
        if let Some((lo, hi)) = watch {
            fs::write(
                out_dir.join(format!("pre-f{fr}.bin")),
                dump_range(&sb, lo, hi),
            )
            .unwrap();
        }
        sb.cpu.register_snapshots_cap = 8_000_000;
        for wp in SITES.iter().chain(extra.iter()) {
            sb.cpu.add_register_watchpoint(*wp);
        }
        let (rc, decoded) = sb
            .ic_decompress(hic, 0, &in_bih_f, &frame, &out_bih, out_size)
            .expect("ICDecompress");
        fs::write(out_dir.join(format!("f{fr}-rgb24.bin")), &decoded).unwrap();
        let (probes, _) = sb.cpu.take_snapshot_probes();
        let snaps = sb.cpu.clear_register_watchpoints();
        println!(
            "[r21] frame {fr}: rc={} snapshots={}",
            rc as i32,
            snaps.len()
        );
        writeln!(
            summary,
            "{fr},{},{},{},{}",
            frame.len(),
            rc as i32,
            decoded.len(),
            snaps.len()
        )
        .unwrap();
        for (i, (eip, r)) in snaps.iter().enumerate() {
            let p: Vec<String> = probes
                .get(i)
                .map(|v| {
                    v.iter()
                        .map(|x| x.map_or("-".to_string(), |y| format!("{y:#x}")))
                        .collect()
                })
                .unwrap_or_default();
            writeln!(
                all,
                "{fr}\t{i}\t{eip:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{}",
                r[0],
                r[1],
                r[2],
                r[3],
                r[4],
                r[5],
                r[6],
                r[7],
                p.join("\t")
            )
            .unwrap();
        }
        // also a post-frame dump of the watched range
        if let Some((lo, hi)) = watch {
            fs::write(
                out_dir.join(format!("post-f{fr}.bin")),
                dump_range(&sb, lo, hi),
            )
            .unwrap();
        }
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    println!("[r21] done; outputs under {}", out_dir.display());
}

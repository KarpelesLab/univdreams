//! re2_indeo3_cells — Validator/Extractor harness for the Indeo 3
//! clean-room (docs workspace `video/indeo/indeo3`, provenance round 19).
//!
//! Drives `IR32_32.DLL` through ICOpen → ICDecompressQuery → Begin →
//! Decompress over a whole staged fixture (all access units, in decode
//! order, on one HIC so inter frames see their reference) and records:
//!
//! 1. the four cell-geometry banks (0xb00 bytes each) as populated by
//!    `0x100038f0` during ICDecompressBegin (bank addresses taken from the
//!    `[esp+4]` probe of a register snapshot at the populator's entry);
//! 2. register snapshots at the tree walker's cell-positioning sites, the
//!    row-stream (unpacker) entry `0x10006bac`, the six unpacker family
//!    bodies and the LUT-rewrite handler, for every frame;
//! 3. the decoded frames (pix format from `RE2_PIX`: rgb24|if09|yvu9).
//!
//! Everything is written under `RE2_OUT`. Run with
//! `cargo test --release -p ud-emulator --features trace --test re2_indeo3_cells -- --nocapture`.

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

use univdreams::emulator::{Bih, DLL_PROCESS_ATTACH, Sandbox};

const SITE_POPULATOR: u32 = 0x100038f0; // [esp+4] = bank
const SITE_SLOT_PLANE: u32 = 0x1000662f; // eax = 16*strip_slot, edi = plane
const SITE_STRIP_BUF: u32 = 0x10006634; // edx = strip plane-buffer pointer
const SITE_CELL: u32 = 0x10006660; // edi = chosen bank, cl/ch = heap indices, ecx flags
const SITE_UNPACK: u32 = 0x10006bac; // ebp = mode-byte cursor, edi = dest, ecx flags, esi
const SITE_LUT: u32 = 0x10006c14;
const FAMILIES: [(u32, &str); 6] = [
    (0x10006cb2, "A"),
    (0x10006fe1, "B"),
    (0x100072e2, "C"),
    (0x10007737, "D"),
    (0x10007abb, "E"),
    (0x1000818e, "F"),
];
const SITE_MC_MV: u32 = 0x100065f4; // al = MV index byte (INTER bit path)
const SITE_FAULT: u32 = 0x1000854b;

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn dump_range(sb: &Sandbox, lo: u32, hi: u32) -> Vec<u8> {
    (lo..hi).map(|a| sb.mmu.load8(a).unwrap_or(0)).collect()
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn re2_indeo3_cells() {
    let dll_path = env_or(
        "RE2_IR32_DLL",
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/indeo/indeo3/reference/binaries/IR32_32.DLL",
    );
    let frames_dir = PathBuf::from(env_or(
        "RE2_IV32_FRAMES",
        "/private/tmp/claude-501/-Users-magicaltux-projects-oxideav-workspace-docs/2f1b8f4f-d7a0-46cf-8b62-89c461147282/scratchpad/work/re2/indeo3/iv32-176x144-4frame-intra-period",
    ));
    let nframes: u32 = env_or("RE2_NFRAMES", "8").parse().unwrap();
    let width: u32 = env_or("RE2_W", "176").parse().unwrap();
    let height: u32 = env_or("RE2_H", "144").parse().unwrap();
    let pix = env_or("RE2_PIX", "rgb24");
    let out_dir = PathBuf::from(env_or("RE2_OUT", "/tmp/re2-indeo3"));
    fs::create_dir_all(&out_dir).unwrap();
    let watch_cells = env_or("RE2_WATCH_CELLS", "1") == "1";

    let dll = fs::read(&dll_path).expect("read DLL");
    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(4_000_000_000);
    let img = sb.load("IR32_32.DLL", &dll).expect("load");
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");

    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler = u32::from_le_bytes(*b"IV32");
    let hic = sb.ic_open(fcc_type, fcc_handler, 1).expect("ICOpen");
    assert_ne!(hic, 0, "codec refused DRV_OPEN");

    let (bit_count, compression, out_size): (u16, [u8; 4], u32) = match pix.as_str() {
        "rgb24" => (24, [0; 4], width * height * 3),
        "rgb32" => (32, [0; 4], width * height * 4),
        "if09" => (9, *b"IF09", width * height * 9 / 8),
        "yvu9" => (9, *b"YVU9", width * height * 9 / 8),
        "yuy2" => (16, *b"YUY2", width * height * 2),
        other => panic!("unknown RE2_PIX {other}"),
    };
    let bit_count: u16 = std::env::var("RE2_BITCOUNT")
        .ok()
        .map_or(bit_count, |v| v.parse().unwrap());
    let out_size: u32 = std::env::var("RE2_SIZEIMAGE")
        .ok()
        .map_or(out_size, |v| v.parse().unwrap());
    let planes: u16 = std::env::var("RE2_PLANES")
        .ok()
        .map_or(1, |v| v.parse().unwrap());
    println!(
        "[re2] out BIH: bit_count={bit_count} planes={planes} size_image={out_size} compression={:?}",
        std::str::from_utf8(&compression).unwrap_or("?")
    );
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
        planes,
        bit_count,
        compression,
        size_image: out_size,
        ..Bih::default()
    };
    let q = sb
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .expect("query");
    println!(
        "[re2] ICDecompressQuery({width}x{height} IV32 -> {pix}) = {}",
        q as i32
    );
    if q != 0 {
        println!("[re2] codec rejected {pix}; stopping");
        return;
    }

    sb.cpu.register_snapshots_cap = 64;
    sb.cpu.add_register_watchpoint(SITE_POPULATOR);
    let b = sb
        .ic_decompress_begin(hic, &in_bih, &out_bih)
        .expect("begin");
    println!("[re2] ICDecompressBegin = {}", b as i32);
    let mem = sb.cpu.take_memory_snapshots();
    let snaps = sb.cpu.clear_register_watchpoints();
    let mut banks: Vec<u32> = Vec::new();
    for (i, (eip, _)) in snaps.iter().enumerate() {
        if *eip == SITE_POPULATOR {
            let bank = mem[i].1[1].1; // [esp+4]
            banks.push(bank);
        }
    }
    println!("[re2] populator calls: {} banks {:x?}", banks.len(), banks);
    for (i, bank) in banks.iter().enumerate() {
        fs::write(
            out_dir.join(format!("bank-{i}-{bank:08x}.bin")),
            dump_range(&sb, *bank, *bank + 0xb00),
        )
        .unwrap();
    }
    {
        let mut f = fs::File::create(out_dir.join("banks.csv")).unwrap();
        writeln!(f, "call_index,bank_addr_hex").unwrap();
        for (i, b) in banks.iter().enumerate() {
            writeln!(f, "{i},{b:#010x}").unwrap();
        }
    }

    let mut all = fs::File::create(out_dir.join(format!("regsnaps-{pix}.tsv"))).unwrap();
    writeln!(
        all,
        "frame\ti\teip\teax\tecx\tedx\tebx\tesp\tebp\tesi\tedi\t[esp]\t[esp+4]\tbyte_at_ebp"
    )
    .unwrap();
    let mut summary = fs::File::create(out_dir.join(format!("frames-{pix}.csv"))).unwrap();
    writeln!(
        summary,
        "frame,in_bytes,rc,out_bytes,instructions,snapshots"
    )
    .unwrap();

    for fr in 0..nframes {
        let frame = fs::read(frames_dir.join(format!("f{fr}.bin"))).expect("frame");
        let in_bih_f = Bih {
            size_image: frame.len() as u32,
            ..in_bih.clone()
        };
        if watch_cells {
            sb.cpu.register_snapshots_cap = 8_000_000;
            for wp in [
                SITE_SLOT_PLANE,
                SITE_STRIP_BUF,
                SITE_CELL,
                SITE_UNPACK,
                SITE_LUT,
                SITE_MC_MV,
                SITE_FAULT,
            ] {
                sb.cpu.add_register_watchpoint(wp);
            }
            for (wp, _) in FAMILIES {
                sb.cpu.add_register_watchpoint(wp);
            }
        }
        let before = sb.host.instructions_executed;
        let (rc, decoded) = sb
            .ic_decompress(hic, 0, &in_bih_f, &frame, &out_bih, out_size)
            .expect("ICDecompress");
        let instr = sb.host.instructions_executed - before;
        fs::write(out_dir.join(format!("f{fr}-{pix}.bin")), &decoded).unwrap();
        let mem = sb.cpu.take_memory_snapshots();
        let snaps = sb.cpu.clear_register_watchpoints();
        println!(
            "[re2] frame {fr}: {} in, rc={}, {} out, {} instr, {} snapshots",
            frame.len(),
            rc as i32,
            decoded.len(),
            instr,
            snaps.len()
        );
        writeln!(
            summary,
            "{fr},{},{},{},{instr},{}",
            frame.len(),
            rc as i32,
            decoded.len(),
            snaps.len()
        )
        .unwrap();
        for (i, (eip, r)) in snaps.iter().enumerate() {
            let m = mem.get(i).map(|(_, m)| *m).unwrap_or([(0, 0); 4]);
            let byte = if *eip == SITE_UNPACK || *eip == SITE_MC_MV {
                sb.mmu.load8(r[5]).unwrap_or(0)
            } else {
                0
            };
            writeln!(
                all,
                "{fr}\t{i}\t{eip:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{:#010x}\t{byte:#04x}",
                r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], m[0].1, m[1].1
            )
            .unwrap();
        }
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    println!("[re2] done; outputs under {}", out_dir.display());
}

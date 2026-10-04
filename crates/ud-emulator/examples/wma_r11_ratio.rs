//! wma_r11_ratio — audio/wma round 11 (Validator) sandbox harness.
//!
//! Decodes a WMA v2 stream through WMADMOD.DLL's flat entry points
//! (0x78b0 alloc, 0x79b0 open, 0x7df0 decode; provenance/03, provenance/10)
//! and snapshots the VLC-path noise-band normaliser `.text 0x5390`
//! (called from the VLC dequantiser at 0x5dec):
//!   * site 0x537053aa (after the three chan loads): eax = chan+4 exponent
//!     array, ecx = chan+8 band-flag bytes, edx = chan+0xc ratio array,
//!     esi = ctx, ebp = frame (args at +0x10..+0x20);
//!   * site 0x53705745 (G > 0 exit, after the 1.0 store at 0x5748): ecx = ratio array -> 32 f32 block dump;
//!   * site 0x53705739 (exit, every call): [ebp+0xc] low byte = G.
//! After the run the two band-edge arrays passed as args 2/3 are dumped
//! (41 x i32 each, distinct pointer values) to edges.csv.
//!
//! Env: WMA_DLL, WMA_IN (wfx.bin + packets.bin), WMA_OUT, WMA_PACKETS, WMA_CW.
// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(clippy::all, clippy::pedantic)]

use std::io::Write;
use std::path::PathBuf;
use ud_emulator::emulator::regs::Reg32;
use ud_emulator::win32::call_guest;
use ud_emulator::{DLL_PROCESS_ATTACH, Sandbox};

const IB: u32 = 0x5370_0000;
const NEXP: i32 = 40;
const NFLAG: i32 = 40;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}
fn r32(sb: &Sandbox, a: u32) -> u32 {
    sb.mmu
        .load32(a)
        .unwrap_or_else(|e| panic!("load32 {a:#x}: {e:?}"))
}
fn galloc(sb: &mut Sandbox, n: u32) -> u32 {
    let a = sb.host.arena_alloc(n).expect("arena_alloc");
    sb.mmu
        .write_initializer(a, &vec![0u8; n as usize])
        .expect("zero fill");
    a
}
fn call(sb: &mut Sandbox, va: u32, args: &[u32]) -> Result<u32, String> {
    let esp = sb.cpu.regs.get32(Reg32::Esp);
    let r = call_guest(
        &mut sb.cpu,
        &mut sb.mmu,
        &mut sb.registry,
        &mut sb.host,
        va,
        args,
    )
    .map_err(|e| format!("{e:?} (eip={:#010x})", sb.cpu.regs.eip));
    sb.cpu.regs.set32(Reg32::Esp, esp);
    r
}
fn le16(b: &[u8], o: usize) -> u32 {
    u16::from_le_bytes([b[o], b[o + 1]]) as u32
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn main() {
    let dll = env("WMA_DLL").unwrap_or_else(|| {
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/WMADMOD.DLL".into()
    });
    let indir = PathBuf::from(env("WMA_IN").expect("WMA_IN"));
    let out = PathBuf::from(env("WMA_OUT").expect("WMA_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let max_packets: usize = env("WMA_PACKETS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);
    let cw0: u16 =
        u16::from_str_radix(&env("WMA_CW").unwrap_or_else(|| "027f".into()), 16).unwrap();
    let bytes = std::fs::read(&dll).expect("read dll");
    let wfx = std::fs::read(indir.join("wfx.bin")).expect("wfx.bin");
    let packets = std::fs::read(indir.join("packets.bin")).expect("packets.bin");
    let tag = le16(&wfx, 0);
    let channels = le16(&wfx, 2);
    let sample_rate = le32(&wfx, 4);
    let avg_bps = le32(&wfx, 8);
    let block_align = le16(&wfx, 12);
    let cb = le16(&wfx, 16) as usize;
    let xd = &wfx[18..18 + cb];
    let version = if tag == 0x160 { 1 } else { 2 };
    let (spb, flags2) = if version == 1 {
        (le16(xd, 0), le16(xd, 2))
    } else {
        (le32(xd, 0), le16(xd, 4))
    };
    let n_packets = (packets.len() / block_align as usize).min(max_packets);

    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(u64::MAX / 2);
    sb.host.instruction_budget = Some(u64::MAX / 2);
    sb.cpu.register_snapshots_cap = 50_000_000;
    sb.cpu.fpu_cw = cw0;
    let (img, _unres) = sb.load_fail_soft("WMADMOD.DLL", &bytes).expect("load");
    assert_eq!(img.image_base, IB);
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    let state = call(&mut sb, IB + 0x78b0, &[]).expect("alloc_state");
    let rc = call(
        &mut sb,
        IB + 0x79b0,
        &[
            state,
            version,
            spb,
            sample_rate,
            channels,
            avg_bps,
            block_align,
            flags2,
            0,
            0,
            0,
        ],
    )
    .expect("open");
    assert!((rc as i32) >= 0, "open failed");
    let ctx = r32(&sb, state);
    let f = |o: u32| r32(&sb, ctx + o);
    let mut meta = std::fs::File::create(out.join("run.meta")).unwrap();
    writeln!(meta, "version={version}\nspb={spb}\nsample_rate={sample_rate}\nchannels={channels}\navg_bps={avg_bps}\nblock_align={block_align}\nflags2={flags2:#06x}\nframe_length={}\nnoise_enable={}\ncutoff_hz={}\nn_block_sizes={}\nclass={}\nbyte_offset_bits={}\npackets={n_packets}\ncw0={cw0:#06x}",
        f(0x364), f(0x7c), f32::from_bits(f(0x3fc)), f(0xc8), f(0x384), f(0x54)).unwrap();

    // probes: [0..NEXP) exps (eax,4i); [NEXP..NEXP+NFLAG) flags (ecx,i,1);
    // then ebp+0x10,+0x14,+0x18,+0x1c,+0x20, ebp+0xc (byte), ctx fields.
    let mut probes: Vec<(u8, i32, u8)> = Vec::new();
    for i in 0..NEXP {
        probes.push((0, 4 * i, 4));
    }
    for i in 0..NFLAG {
        probes.push((1, i, 1));
    }
    for o in [0x10, 0x14, 0x18, 0x1c, 0x20] {
        probes.push((5, o, 4));
    }
    probes.push((5, 0xc, 1));
    for o in [
        0x400, 0x404, 0x370, 0x378, 0xa4, 0x364, 0x90, 0x9c, 0xbc, 0xb4, 0x36c,
    ] {
        probes.push((6, o, 4));
    }
    sb.cpu.snapshot_probes = probes;
    let sites: &[(u32, &str)] = &[
        (IB + 0x53aa, "n5390.entry"),
        (IB + 0x5739, "n5390.exit"),
        (IB + 0x5750, "n5390.ratios"),
    ];
    for (va, _) in sites {
        sb.cpu.add_register_watchpoint(*va);
    }
    sb.cpu.snapshot_block_dump = Some((IB + 0x5750, 1, 128));

    let in_buf = galloc(&mut sb, block_align + 64);
    let out_len: u32 = 1 << 18;
    let out_buf = galloc(&mut sb, out_len);
    let scratch = galloc(&mut sb, 64);
    let mut pcm = std::fs::File::create(out.join("pcm.raw")).unwrap();
    let mut log = std::fs::File::create(out.join("packets.log")).unwrap();
    writeln!(log, "packet,rc,consumed,written,extra,snapshots_so_far").unwrap();
    for p in 0..n_packets {
        let pk = &packets[p * block_align as usize..(p + 1) * block_align as usize];
        sb.mmu.write_initializer(in_buf, pk).unwrap();
        for k in 0..4 {
            sb.mmu.store32(scratch + 4 * k, 0).unwrap();
        }
        let res = call(
            &mut sb,
            IB + 0x7df0,
            &[
                state,
                in_buf,
                block_align,
                scratch,
                out_buf,
                out_len,
                scratch + 4,
                0,
                0,
                0,
                scratch + 8,
            ],
        );
        let written = r32(&sb, scratch + 4);
        let rc = match &res {
            Ok(v) => *v as i64,
            Err(e) => {
                eprintln!("packet {p}: trap {e}");
                -1
            }
        };
        writeln!(
            log,
            "{p},{rc:#x},{},{written},{},{}",
            r32(&sb, scratch),
            r32(&sb, scratch + 8),
            sb.cpu.register_snapshots.len()
        )
        .unwrap();
        if res.is_err() {
            break;
        }
        let mut buf = vec![0u8; written as usize];
        for i in 0..written {
            buf[i as usize] = sb.mmu.load8(out_buf + i).unwrap();
        }
        pcm.write_all(&buf).unwrap();
    }
    writeln!(meta, "cw_after={:#06x}", sb.cpu.fpu_cw).unwrap();
    let regs = std::mem::take(&mut sb.cpu.register_snapshots);
    let (pv, dumps) = sb.cpu.take_snapshot_probes();
    let mut dump_by = std::collections::BTreeMap::new();
    for (i, b) in dumps {
        dump_by.insert(i, b);
    }
    let mut fo = std::io::BufWriter::new(std::fs::File::create(out.join("snaps.jsonl")).unwrap());
    let mut edge_ptrs = std::collections::BTreeSet::new();
    for (i, (eip, r)) in regs.iter().enumerate() {
        let site = sites
            .iter()
            .find(|s| s.0 == *eip)
            .map(|s| s.1)
            .unwrap_or("?");
        let pr: Vec<String> = pv
            .get(i)
            .map(|v| {
                v.iter()
                    .map(|x| x.map(|y| y.to_string()).unwrap_or("null".into()))
                    .collect()
            })
            .unwrap_or_default();
        if site == "n5390.entry" {
            if let Some(v) = pv.get(i) {
                for k in [NEXP + NFLAG, NEXP + NFLAG + 1] {
                    if let Some(p) = v[k as usize] {
                        edge_ptrs.insert(p as u32);
                    }
                }
            }
        }
        let dump = dump_by
            .get(&i)
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
            .unwrap_or_default();
        writeln!(
            fo,
            "{{\"i\":{i},\"site\":\"{site}\",\"regs\":[{}],\"probes\":[{}],\"dump\":\"{dump}\"}}",
            r.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
            pr.join(",")
        )
        .unwrap();
    }
    drop(fo);
    let mut fe = std::fs::File::create(out.join("edges.csv")).unwrap();
    for p in edge_ptrs {
        let v: Vec<String> = (0..41)
            .map(|k| (sb.mmu.load32(p + 4 * k).unwrap_or(0) as i32).to_string())
            .collect();
        writeln!(fe, "{p:#x},{}", v.join(",")).unwrap();
    }
    eprintln!("{n_packets} packets; {} snapshots", regs.len());
}

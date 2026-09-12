//! wma_r10_lsp — Validator round 10 sandbox harness for `WMADMOD.DLL`
//! (Windows Media Audio Standard v1/v2 DMO decoder, PE32 i386, image base
//! 0x53700000, SHA-256 3626a856…36f214).
//!
//! Drives the module's *flat* internal decoder entry points (read
//! statically in audio/wma provenance/03 — no COM / IMediaObject needed):
//!
//!   0x537078b0  state = alloc_state()                                  cdecl, no args
//!   0x537079b0  open(state, version, samples_per_block, sample_rate,
//!                    channels, avg_bytes_per_sec, block_align, flags2,
//!                    0, 0, 0)                                          stdcall (ret 0x2c)
//!   0x53707df0  decode(state, in, in_len, &consumed, out, out_len,
//!                      &written, 0, 0, 0, &extra)                     stdcall (ret 0x2c)
//!
//! with the real WAVEFORMATEX of `cand_mono8k_8kbps_v8.wma` and its real
//! 640-byte codec packets (reassembled from the ASF Data Object by the
//! spec-derived `asf_extract.py`).  It captures:
//!
//!   * register snapshots + memory probes at the LSP envelope path
//!     (`0x4e30` parser → `0x6d80` builder → `0x6e40` evaluator): the ten
//!     wire indices, the ten `-a_n` inputs, N / grid flag / frame_length,
//!     and the running maximum at the success exit;
//!   * memory watchpoints (JSONL) on the channel's envelope buffer
//!     (`[chan+0x6c]`) and its maximum (`chan+0x70`), so every f32 the
//!     evaluator's epilogue stores is on tape with the storing EIP;
//!   * in `deq` mode additionally the LSP-path dequantiser's inputs and
//!     outputs (coefficients `[chan+0]`, output `[chan+0x64]`, the noise
//!     generator state `ctx+0x43c/0x440`, the band flags / ratios / gains);
//!   * the PCM the decoder writes, per packet;
//!   * the x87 control word before and after the whole run (the emulator
//!     computes every x87 op in binary64 regardless of the CW's precision
//!     field — see the report — so this only shows whether the module
//!     ever *writes* the CW).
//!
//! Env: WMA_DLL, WMA_IN (dir with wfx.bin + packets.bin), WMA_OUT,
//!      WMA_PACKETS (max packets, default all), WMA_MODE (lsp | deq),
//!      WMA_CW (initial x87 CW, hex, default 027f).
#![allow(clippy::all, clippy::pedantic)]

use std::io::Write;
use std::path::PathBuf;
use ud_emulator::emulator::regs::Reg32;
use ud_emulator::win32::call_guest;
use ud_emulator::{Sandbox, WatchMode, DLL_PROCESS_ATTACH};

const IB: u32 = 0x5370_0000;
const VA_ALLOC_STATE: u32 = IB + 0x78b0;
const VA_OPEN: u32 = IB + 0x79b0;
const VA_DECODE: u32 = IB + 0x7df0;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}
fn r32(sb: &Sandbox, a: u32) -> u32 {
    sb.mmu.load32(a).unwrap_or_else(|e| panic!("load32 {a:#x}: {e:?}"))
}
fn galloc(sb: &mut Sandbox, n: u32) -> u32 {
    let a = sb.host.arena_alloc(n).expect("arena_alloc");
    sb.mmu.write_initializer(a, &vec![0u8; n as usize]).expect("zero fill");
    a
}
fn call(sb: &mut Sandbox, va: u32, args: &[u32]) -> Result<u32, String> {
    let esp = sb.cpu.regs.get32(Reg32::Esp);
    let r = call_guest(&mut sb.cpu, &mut sb.mmu, &mut sb.registry, &mut sb.host, va, args)
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
    let out = PathBuf::from(env("WMA_OUT").unwrap_or_else(|| "wma_r10_out".into()));
    std::fs::create_dir_all(&out).unwrap();
    let max_packets: usize = env("WMA_PACKETS").and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);
    let mode = env("WMA_MODE").unwrap_or_else(|| "lsp".into());
    let cw0: u16 = u16::from_str_radix(&env("WMA_CW").unwrap_or_else(|| "027f".into()), 16).unwrap();

    let bytes = std::fs::read(&dll).expect("read dll");
    let wfx = std::fs::read(indir.join("wfx.bin")).expect("wfx.bin");
    let packets = std::fs::read(indir.join("packets.bin")).expect("packets.bin");

    // WAVEFORMATEX (mmreg.h): wFormatTag, nChannels, nSamplesPerSec,
    // nAvgBytesPerSec, nBlockAlign, wBitsPerSample, cbSize, then cbSize
    // bytes of codec-specific data.  The module's media-type parser
    // (.text 0x1c24) takes: version = 1 iff the WMAUDIO1 subtype (tag
    // 0x160) else 2; samples_per_block = extradata dword 0 (v2) / word 0
    // (v1); flags2 = extradata word at +4 (v2) / +2 (v1).
    let tag = le16(&wfx, 0);
    let channels = le16(&wfx, 2);
    let sample_rate = le32(&wfx, 4);
    let avg_bps = le32(&wfx, 8);
    let block_align = le16(&wfx, 12);
    let cb = le16(&wfx, 16) as usize;
    let xd = &wfx[18..18 + cb];
    let version = if tag == 0x160 { 1 } else { 2 };
    let (spb, flags2) = if version == 1 { (le16(xd, 0), le16(xd, 2)) } else { (le32(xd, 0), le16(xd, 4)) };
    eprintln!(
        "wfx: tag={tag:#x} ch={channels} sr={sample_rate} avgBps={avg_bps} blockAlign={block_align} cbSize={cb} extradata={:02x?} -> version={version} spb={spb} flags2={flags2:#06x}",
        xd
    );
    assert_eq!(packets.len() % block_align as usize, 0);
    let n_packets = (packets.len() / block_align as usize).min(max_packets);

    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(u64::MAX / 2);
    sb.host.instruction_budget = Some(u64::MAX / 2);
    sb.cpu.register_snapshots_cap = 50_000_000;
    sb.cpu.fpu_cw = cw0;
    let (img, unresolved) = sb.load_fail_soft("WMADMOD.DLL", &bytes).expect("load");
    eprintln!("loaded at {:#x}; {} fail-soft imports: {:?}", img.image_base, unresolved.len(), unresolved);
    assert_eq!(img.image_base, IB, "image must load at its preferred base");
    let r = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    eprintln!("DllMain -> {r:#x}; fpu_cw after DllMain = {:#06x}", sb.cpu.fpu_cw);

    // --- open ------------------------------------------------------------
    let state = call(&mut sb, VA_ALLOC_STATE, &[]).expect("alloc_state");
    assert!(state != 0);
    let rc = call(&mut sb, VA_OPEN, &[state, version, spb, sample_rate, channels, avg_bps, block_align, flags2, 0, 0, 0]).expect("open");
    eprintln!("open -> {rc:#x}");
    assert!((rc as i32) >= 0, "open failed");
    let ctx = r32(&sb, state);
    let f = |o: u32| r32(&sb, ctx + o);
    eprintln!(
        "ctx={ctx:#x}: frame_length={} N(0xa4)={} grid_flag(0xb0)={} sr={} ch={} class={} noise_enable(0x7c)={} n_block_sizes(0xc8)={} byte_offset_bits(0x54)={} dither(0x388)={} dispatch(0x42c)={:#x} coef_start(0x36c)={} coef_end(0x370)={} cutoff(0x404)={} start_band(0x400)={} version(0x90)={}",
        f(0x364), f(0xa4), f(0xb0), f(0x9c), f(0xa0) & 0xffff, f(0x384), f(0x7c), f(0xc8), f(0x54),
        f32::from_bits(f(0x388)), f(0x42c), f(0x36c), f(0x370), f(0x404), f(0x400), f(0x90)
    );
    let chan0 = r32(&sb, ctx + 0x3e0);
    let env_buf = r32(&sb, chan0 + 0x6c);
    let frame_length = f(0x364);
    eprintln!(
        "chan0={chan0:#x}: env(0x6c)={env_buf:#x} deq_in(0x2c)={:#x} q(0x0)={:#x} out(0x64)={:#x} flags(0x8)={:#x} ratios(0xc)={:#x} gains(0x10)={:#x}",
        r32(&sb, chan0 + 0x2c), r32(&sb, chan0), r32(&sb, chan0 + 0x64), r32(&sb, chan0 + 0x8), r32(&sb, chan0 + 0xc), r32(&sb, chan0 + 0x10)
    );
    assert_eq!(r32(&sb, chan0 + 0x2c), env_buf, "chan+0x2c must alias chan+0x6c (provenance/09 s5)");
    let mut meta = std::fs::File::create(out.join("run.meta")).unwrap();
    writeln!(meta, "dll={dll}\nversion={version}\nspb={spb}\nsample_rate={sample_rate}\nchannels={channels}\navg_bps={avg_bps}\nblock_align={block_align}\nflags2={flags2:#06x}\nstate={state:#x}\nctx={ctx:#x}\nchan0={chan0:#x}\nenv_buf={env_buf:#x}\nframe_length={frame_length}\nmode={mode}\ncw0={cw0:#06x}").unwrap();
    for (name, off) in [("q", 0u32), ("flags", 8), ("ratios", 0xc), ("gains", 0x10), ("deq_in", 0x2c), ("out", 0x64), ("env", 0x6c)] {
        writeln!(meta, "chan0.{name}={:#x}", r32(&sb, chan0 + off)).unwrap();
    }
    for off in [0x36c, 0x370, 0x388, 0x38c, 0x39c, 0x3a0, 0x400, 0x404, 0x43c, 0x440, 0x7c, 0xa4, 0xb0, 0x364, 0x424] {
        writeln!(meta, "ctx+{off:#x}={:#x}", f(off)).unwrap();
    }

    // --- trace sink + memory watchpoints ---------------------------------
    let sink = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(out.join("trace.jsonl")).unwrap());
    sb.set_trace_sink(Box::new(sink));
    sb.watch(env_buf, frame_length * 4, if mode == "deq" { WatchMode::Both } else { WatchMode::Write });
    sb.watch(chan0 + 0x70, 4, WatchMode::Both);
    let mut armed: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    // Watches whose targets live behind pointers the decoder allocates at
    // its first decode call (chan+0 coefficients, chan+8 band flags,
    // chan+0xc ratios, chan+0x10 gains, chan+0x64 output): (re)armed after
    // open and after every packet, once per distinct pointer value.
    fn arm_ptr_watches(sb: &mut Sandbox, chan0: u32, frame_length: u32, armed: &mut std::collections::BTreeSet<u32>, meta: &mut std::fs::File, when: &str) {
        for (name, off, bytes, mode) in [
            ("q", 0u32, frame_length * 2, WatchMode::Read),
            ("flags", 8, 64, WatchMode::Both),
            ("ratios", 0xc, 64 * 4, WatchMode::Both),
            ("gains", 0x10, 64 * 4, WatchMode::Both),
            ("out", 0x64, frame_length * 4, WatchMode::Write),
        ] {
            let p = r32(sb, chan0 + off);
            if p != 0 && armed.insert(p) {
                sb.watch(p, bytes, mode);
                writeln!(meta, "watch.{name}@{when}={p:#x}").unwrap();
                eprintln!("armed watch {name} at {p:#x} ({when})");
            }
        }
    }
    if mode == "deq" || mode == "noise" {
        sb.watch(ctx + 0x43c, 8, WatchMode::Both); // LCG state (r_prev, s)
        sb.watch(ctx + 0x388, 8, WatchMode::Read); // dither scale, total gain
        sb.watch(ctx + 0x36c, 8, WatchMode::Read); // coef_start / coef_end
        sb.watch(ctx + 0x400, 8, WatchMode::Both); // start band / cutoff bin
        sb.watch(ctx + 0x7c, 4, WatchMode::Read);  // noise enable
        sb.watch(ctx + 0x39c, 4, WatchMode::Read); // band edge table pointer
        arm_ptr_watches(&mut sb, chan0, frame_length, &mut armed, &mut meta, "open");
    }
    if mode == "noise" {
        sb.watch(ctx + 0xa4, 4, WatchMode::Both);            // block length
        let exps = r32(&sb, chan0 + 4);
        writeln!(meta, "chan0.exps={exps:#x}").unwrap();
        // Extra watches from WMA_WATCH="base+off:size:mode,..." with base in
        // {ctx, chan0, exps, abs}, mode in {r, w, b}.  Used to bisect an
        // emulator-side interaction between watch ranges (see report).
        if let Some(spec) = env("WMA_WATCH") {
            for item in spec.split(',') {
                let parts: Vec<&str> = item.split(':').collect();
                if parts.len() != 3 { continue; }
                let (base, off) = match parts[0].split_once('+') { Some((b, o)) => (b, o), None => ("abs", parts[0]) };
                let off = u32::from_str_radix(off.trim_start_matches("0x"), 16).unwrap();
                let addr = match base { "ctx" => ctx + off, "chan0" => chan0 + off, "exps" => exps + off, "ib" => IB + off, _ => off };
                let size = u32::from_str_radix(parts[1].trim_start_matches("0x"), 16).unwrap();
                let m = match parts[2] { "r" => WatchMode::Read, "w" => WatchMode::Write, _ => WatchMode::Both };
                sb.watch(addr, size, m);
                writeln!(meta, "watch.extra={addr:#x}:{size:#x}:{}", parts[2]).unwrap();
                eprintln!("extra watch {item} -> {addr:#x} size {size:#x}");
            }
        }
    }

    // --- register snapshots ---------------------------------------------
    // probes: index -> (reg, off): 0 (eax,0xa4) 1 (eax,0xb0) 2 (eax,0x364)
    //   3 (ebp,0xc) 4 (ebp,0x10) 5..14 (edx, 4*i) 15 (ebp,0x8) 16 (esp,0) 17 (esp,4) 18 (esp,8)
    let mut probes: Vec<(u8, i32, u8)> = vec![(0, 0xa4, 4), (0, 0xb0, 4), (0, 0x364, 4), (5, 0xc, 4), (5, 0x10, 4)];
    for i in 0..10 { probes.push((2, 4 * i, 4)); }
    probes.push((5, 8, 4));
    probes.push((4, 0, 4));
    probes.push((4, 4, 4));
    probes.push((4, 8, 4));
    sb.cpu.snapshot_probes = probes;
    let sites: &[(u32, &str)] = &[
        (IB + 0x4f02, "lsp.call_builder"),   // eax = &idx[10] (bytes), edx = &neg_a, ebx = ctx
        (IB + 0x4f2f, "lsp.uncoded_fill"),   // uncoded channel: env := 1.0, max := 1.0
        (IB + 0x4f56, "lsp.reuse_resample"), // B2 = 0 on a different block size: 0x5c20
        (IB + 0x6e50, "eval.entry"),         // eax = ctx, [ebp+0xc] = neg_a, [ebp+0x10] = chan
        (IB + 0x6e8d, "eval.inputs"),        // edx = neg_a ptr (ten f32)
        (IB + 0x778b, "eval.ok"),            // [ebp+0xc] = max (f32), [ebp+0x10] = chan
        (IB + 0x777d, "eval.fail"),
        (IB + 0x6570, "deq.entry"),          // [esp+4] = ctx, [esp+8] = chan, [esp+0xc] = W
        (IB + 0x698b, "deq.ret"),
        (IB + 0x4fa2, "noise.parser_entry"),  // ebx = state, esi = ctx
        (IB + 0x4fd5, "noise.channel_coded"), // ecx = chan (+edx), esi = ctx
        (IB + 0x5cd8, "vlcdeq.entry"),
    ];
    let mut labels = std::collections::BTreeMap::new();
    for (va, l) in sites { sb.cpu.add_register_watchpoint(*va); labels.insert(*va, *l); }
    sb.cpu.snapshot_block_dump = Some((IB + 0x4f02, 0, 10)); // eax -> ten index bytes

    // --- decode ------------------------------------------------------------
    let in_buf = galloc(&mut sb, block_align + 64);
    let out_len: u32 = 1 << 18;
    let out_buf = galloc(&mut sb, out_len);
    let scratch = galloc(&mut sb, 64);
    let mut pcm = std::fs::File::create(out.join("pcm.raw")).unwrap();
    let mut log = std::fs::File::create(out.join("packets.log")).unwrap();
    writeln!(log, "packet,rc,consumed,written,extra,instr").unwrap();
    let cw_before = sb.cpu.fpu_cw;
    let t0 = std::time::Instant::now();
    let mut total_written = 0u64;
    for p in 0..n_packets {
        let pk = &packets[p * block_align as usize..(p + 1) * block_align as usize];
        sb.mmu.write_initializer(in_buf, pk).unwrap();
        for k in 0..4 { sb.mmu.store32(scratch + 4 * k, 0).unwrap(); }
        let i0 = sb.cpu.instr_count;
        let res = call(&mut sb, VA_DECODE, &[state, in_buf, block_align, scratch, out_buf, out_len, scratch + 4, 0, 0, 0, scratch + 8]);
        let di = sb.cpu.instr_count - i0;
        let consumed = r32(&sb, scratch);
        let written = r32(&sb, scratch + 4);
        let extra = r32(&sb, scratch + 8);
        let rc = match &res { Ok(v) => *v as i64, Err(e) => { eprintln!("packet {p}: decode trapped: {e}"); -1 } };
        writeln!(log, "{p},{rc:#x},{consumed},{written},{extra},{di}").unwrap();
        if p < 5 || p % 50 == 0 { eprintln!("packet {p}: rc={rc:#x} consumed={consumed} written={written} extra={extra} instr={di} t={:.1}s", t0.elapsed().as_secs_f64()); }
        if res.is_err() { break; }
        if mode == "deq" || mode == "noise" { arm_ptr_watches(&mut sb, chan0, frame_length, &mut armed, &mut meta, &format!("pkt{p}")); }
        if written > 0 {
            let mut buf = vec![0u8; written as usize];
            for i in 0..written { buf[i as usize] = sb.mmu.load8(out_buf + i).unwrap(); }
            pcm.write_all(&buf).unwrap();
            total_written += written as u64;
        }
    }
    let cw_after = sb.cpu.fpu_cw;
    eprintln!("decoded {n_packets} packets, {total_written} PCM bytes, {} instructions, {:.1}s; fpu_cw before={cw_before:#06x} after={cw_after:#06x}", sb.cpu.instr_count, t0.elapsed().as_secs_f64());
    writeln!(meta, "packets_decoded={n_packets}\npcm_bytes={total_written}\ninstructions={}\ncw_before={cw_before:#06x}\ncw_after={cw_after:#06x}", sb.cpu.instr_count).unwrap();
    // drop the sink so the JSONL is flushed
    sb.set_trace_sink(Box::new(std::io::sink()));

    // --- snapshots -----------------------------------------------------------
    let regs = std::mem::take(&mut sb.cpu.register_snapshots);
    let (pv, dumps) = sb.cpu.take_snapshot_probes();
    let mut dump_by_snap = std::collections::BTreeMap::new();
    for (i, b) in dumps { dump_by_snap.insert(i, b); }
    let mut f = std::io::BufWriter::new(std::fs::File::create(out.join("snaps.jsonl")).unwrap());
    for (i, (eip, r)) in regs.iter().enumerate() {
        let lab = labels.get(eip).copied().unwrap_or("?");
        let probes: Vec<String> = pv.get(i).map(|v| v.iter().map(|x| match x { Some(v) => format!("{v}"), None => "null".into() }).collect()).unwrap_or_default();
        let dump = dump_by_snap.get(&i).map(|b| format!("{:02x?}", b).replace(' ', "")).unwrap_or_else(|| "null".into());
        writeln!(f, "{{\"i\":{i},\"eip\":\"{eip:#010x}\",\"site\":\"{lab}\",\"eax\":{},\"ecx\":{},\"edx\":{},\"ebx\":{},\"esp\":{},\"ebp\":{},\"esi\":{},\"edi\":{},\"probes\":[{}],\"dump\":\"{}\"}}",
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], probes.join(","), dump).unwrap();
    }
    eprintln!("{} snapshots written", regs.len());
}

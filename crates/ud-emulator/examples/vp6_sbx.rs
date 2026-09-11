//! vp6_sbx — VP6 sandbox harness (oxideav docs, video/vp6 provenance 05).
//!
//! Drives On2 `vp6vfw.dll` through the VfW decompress surface for a
//! *sequence* of raw VP6 frames inside one ICOpen session (so P-frames
//! reference the previously decoded frame), with:
//!   * register-snapshot watchpoints (`--reg-wp 0xEIP`, repeatable),
//!   * one "context discovery" watchpoint (`--ctx-wp 0xEIP:REG`) whose
//!     snapshot register is taken as the decoder-context base,
//!   * memory watchpoints relative to that base (`--mem-wp OFF:SIZE:MODE`,
//!     MODE = r|w|rw; requires the `trace` cargo feature),
//!   * absolute memory probes printed after each stage (`--probe 0xADDR`),
//!   * optional 32-bit stores before the first decode (`--poke 0xADDR=0xVAL`).
//!
//! Snapshots are appended, one line per hit, to `<out>/snap-frameN.tsv`
//! (eip eax ecx edx ebx esp ebp esi edi | four probe pairs). Decoded
//! output goes to `<out>/frameN.<pix>`.
//!
//! Clean-room: only the raw bytes of the vendor DLL and the staged
//! fixture bitstreams are consumed. No third-party decoder source.
#![allow(clippy::too_many_lines, clippy::cast_possible_truncation, clippy::cast_possible_wrap,
         clippy::cast_sign_loss, clippy::uninlined_format_args, clippy::unreadable_literal)]

use std::io::Write as _;
use std::path::PathBuf;
use ud_emulator::{Bih, Sandbox, DLL_PROCESS_ATTACH};

const ICMODE_DECOMPRESS: u32 = 2;

fn parse_u32(s: &str) -> u32 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).expect("hex")
    } else {
        s.parse().expect("dec")
    }
}

struct Args {
    dll: PathBuf,
    fcc: String,
    width: u32,
    height: u32,
    pix: String,
    frames: Vec<PathBuf>,
    out: PathBuf,
    reg_wps: Vec<u32>,
    ctx_wp: Option<(u32, usize)>,
    mem_wps: Vec<(u32, u32, String)>,
    probes: Vec<u32>,
    pokes: Vec<(u32, u32)>,
    snap_cap: usize,
    instr_limit: u64,
    trace: Option<PathBuf>,
    exec_trace: bool,
    regs: Vec<(String, String, String)>,
    ctx_probes: Vec<u32>,
    ctx_dumps: Vec<(u32, u32)>,
    ctx_preset: Option<u32>,
    abs_wps: Vec<(u32, u32, String)>,
    exec_frame: Option<usize>,
    frame_cap: Option<u64>,
    in_dims: Option<(u32, u32)>,
    visited: bool,
    abs_dumps: Vec<(u32, u32)>,
}

fn parse_args() -> Args {
    let mut a = Args {
        dll: PathBuf::new(), fcc: "VP62".into(), width: 0, height: 0, pix: "yv12".into(),
        frames: vec![], out: PathBuf::from("."), reg_wps: vec![], ctx_wp: None, mem_wps: vec![],
        probes: vec![], pokes: vec![], snap_cap: 2_000_000, instr_limit: 20_000_000_000, trace: None,
        exec_trace: false, regs: vec![], ctx_probes: vec![], ctx_dumps: vec![], ctx_preset: None, abs_wps: vec![], exec_frame: None, frame_cap: None, in_dims: None, visited: false, abs_dumps: vec![],
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let regname = |r: &str| -> usize {
        match r { "eax" => 0, "ecx" => 1, "edx" => 2, "ebx" => 3, "esp" => 4, "ebp" => 5, "esi" => 6, "edi" => 7, _ => panic!("reg") }
    };
    while i < argv.len() {
        let k = argv[i].as_str();
        let mut val = || { i += 1; argv[i].clone() };
        match k {
            "--fcc" => a.fcc = val(),
            "--width" => a.width = parse_u32(&val()),
            "--height" => a.height = parse_u32(&val()),
            "--pix" => a.pix = val(),
            "--frame" => a.frames.push(PathBuf::from(val())),
            "--out" => a.out = PathBuf::from(val()),
            "--reg-wp" => a.reg_wps.push(parse_u32(&val())),
            "--ctx-wp" => { let v = val(); let (e, r) = v.split_once(':').expect("EIP:REG"); a.ctx_wp = Some((parse_u32(e), regname(r))); }
            "--mem-wp" => { let v = val(); let p: Vec<&str> = v.split(':').collect(); a.mem_wps.push((parse_u32(p[0]), parse_u32(p[1]), p.get(2).unwrap_or(&"rw").to_string())); }
            "--probe" => a.probes.push(parse_u32(&val())),
            "--ctx-probe" => a.ctx_probes.push(parse_u32(&val())),
            "--ctx" => a.ctx_preset = Some(parse_u32(&val())),
            "--in-dims" => { let v = val(); let (w, h) = v.split_once('x').expect("WxH"); a.in_dims = Some((parse_u32(w), parse_u32(h))); }
            "--abs-wp" => { let v = val(); let p: Vec<&str> = v.split(':').collect(); a.abs_wps.push((parse_u32(p[0]), parse_u32(p[1]), p.get(2).unwrap_or(&"rw").to_string())); }
            "--exec-trace-frame" => a.exec_frame = Some(parse_u32(&val()) as usize),
            "--frame-instr-cap" => a.frame_cap = Some(val().parse().expect("u64")),
            "--ctx-dump" => { let v = val(); let (o, l) = v.split_once(':').expect("OFF:LEN"); a.ctx_dumps.push((parse_u32(o), parse_u32(l))); }
            "--poke" => { let v = val(); let (x, y) = v.split_once('=').expect("ADDR=VAL"); a.pokes.push((parse_u32(x), parse_u32(y))); }
            "--snap-cap" => a.snap_cap = parse_u32(&val()) as usize,
            "--instr-limit" => a.instr_limit = val().parse().expect("u64"),
            "--trace" => a.trace = Some(PathBuf::from(val())),
            "--exec-trace" => a.exec_trace = true,
            "--visited" => a.visited = true,
            "--dump" => { let v = val(); let (o, l) = v.split_once(':').expect("ADDR:LEN"); a.abs_dumps.push((parse_u32(o), parse_u32(l))); }
            "--reg" => { let v = val(); let (kp, nv) = v.rsplit_once('|').expect("KEY|NAME=VALUE"); let (n, vv) = nv.split_once('=').expect("NAME=VALUE"); a.regs.push((kp.to_string(), n.to_string(), vv.to_string())); }
            _ => { if a.dll.as_os_str().is_empty() { a.dll = PathBuf::from(k); } else { panic!("unexpected arg {k}"); } }
        }
        i += 1;
    }
    a
}

fn pix_bih(pix: &str, w: u32, h: u32) -> (Bih, u32) {
    let (bits, comp, size): (u16, [u8; 4], u32) = match pix {
        "rgb24" => (24, [0; 4], w * h * 3),
        "rgb32" => (32, [0; 4], w * h * 4),
        "yuy2" => (16, *b"YUY2", w * h * 2),
        "yv12" => (12, *b"YV12", w * h * 3 / 2),
        "i420" => (12, *b"I420", w * h * 3 / 2),
        "iyuv" => (12, *b"IYUV", w * h * 3 / 2),
        _ => panic!("pix"),
    };
    (Bih { bi_size: 40, width: w as i32, height: h as i32, planes: 1, bit_count: bits, compression: comp, size_image: size, ..Bih::default() }, size)
}

fn probe(sb: &Sandbox, tag: &str, addrs: &[u32]) {
    for &p in addrs {
        let v = sb.mmu.load32(p).map(|v| format!("0x{v:08x}")).unwrap_or_else(|_| "<unmapped>".into());
        eprintln!("[probe:{tag}] [0x{p:08x}] = {v}");
    }
}

fn drain(sb: &mut Sandbox, path: &PathBuf) -> (usize, Vec<(u32, [u32; 8])>) {
    let regs = sb.cpu.clear_register_watchpoints();
    let mems = sb.cpu.take_memory_snapshots();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).expect("snap file");
    for (i, (eip, r)) in regs.iter().enumerate() {
        let m = mems.get(i).map(|(_, m)| *m).unwrap_or([(0, 0); 4]);
        writeln!(f, "{eip:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}={:08x}\t{:08x}={:08x}\t{:08x}={:08x}\t{:08x}={:08x}",
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], m[0].0, m[0].1, m[1].0, m[1].1, m[2].0, m[2].1, m[3].0, m[3].1).unwrap();
    }
    (regs.len(), regs)
}

#[allow(unused_variables)]
fn arm_mem(sb: &mut Sandbox, a: &Args, c: u32) {
    #[cfg(feature = "trace")]
    for (off, size, mode) in &a.mem_wps {
        let m = match mode.as_str() { "r" => ud_emulator::WatchMode::Read, "w" => ud_emulator::WatchMode::Write, _ => ud_emulator::WatchMode::Both };
        sb.watch(c.wrapping_add(*off), *size, m);
        eprintln!("[sbx] mem-wp ctx+0x{off:x} (0x{:08x}) size {size} {mode}", c.wrapping_add(*off));
    }
}

fn main() {
    let a = parse_args();
    std::fs::create_dir_all(&a.out).unwrap();
    let dll_bytes = std::fs::read(&a.dll).expect("dll");
    let dll_name = a.dll.file_name().unwrap().to_string_lossy().into_owned();

    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(a.instr_limit);
    sb.host.instruction_budget = Some(a.instr_limit);
    sb.cpu.register_snapshots_cap = a.snap_cap;
    let mut marker: Option<std::fs::File> = None;
    #[cfg(feature = "trace")]
    if let Some(t) = &a.trace {
        let f = std::fs::File::create(t).expect("trace file");
        marker = Some(f.try_clone().expect("clone"));
        sb.set_trace_sink(Box::new(f));
        sb.set_exec_trace(a.exec_trace);
    }
    let mut mark = |stage: &str, n: usize| {
        if let Some(m) = marker.as_mut() { let _ = writeln!(m, "{{\"kind\":\"marker\",\"stage\":\"{stage}\",\"frame\":{n}}}"); }
    };

    if !a.regs.is_empty() {
        let reg = sb.host.context.registry.get_or_insert_with(ud_emulator::context::VirtualRegistry::new);
        for (k, n, v) in &a.regs {
            reg.set_value(k, n, ud_emulator::context::RegistryValue::Sz(v.clone()));
            eprintln!("[sbx] registry {k} \\ {n} = REG_SZ {v:?}");
        }
    }
    let img = sb.load(&dll_name, &dll_bytes).expect("load");
    eprintln!("[sbx] loaded {dll_name} image_base=0x{:08x}", img.image_base);
    // Arm watchpoints before DllMain so CRT static initialisers and
    // DRV_LOAD-time code are covered too.
    for &e in &a.reg_wps { sb.cpu.add_register_watchpoint(e); }
    if let Some((e, _)) = a.ctx_wp { sb.cpu.add_register_watchpoint(e); }
    let r = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    eprintln!("[sbx] DllMain = {r}");
    sb.install_codec(&img).expect("install_codec");

    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fccb: [u8; 4] = a.fcc.as_bytes().try_into().expect("fcc 4 chars");
    let fcc_u32 = u32::from_le_bytes(fccb);
    let hic = sb.ic_open(fcc_type, fcc_u32, ICMODE_DECOMPRESS).expect("ICOpen");
    eprintln!("[sbx] ICOpen({}) hic={hic}", a.fcc);
    probe(&sb, "after-open", &a.probes);

    let (iw, ih) = a.in_dims.unwrap_or((a.width, a.height));
    let in_bih = Bih { bi_size: 40, width: iw as i32, height: ih as i32, planes: 1, bit_count: 24, compression: fccb, size_image: 0, ..Bih::default() };
    let (out_bih, out_cap) = pix_bih(&a.pix, a.width, a.height);
    let q = sb.ic_decompress_query(hic, &in_bih, Some(&out_bih)).expect("query");
    eprintln!("[sbx] ICDecompressQuery({}x{} {} -> {}) = {}", a.width, a.height, a.fcc, a.pix, q as i32);
    if q as i32 != 0 { std::process::exit(2); }
    let b = sb.ic_decompress_begin(hic, &in_bih, &out_bih).expect("begin");
    eprintln!("[sbx] ICDecompressBegin = {}", b as i32);
    probe(&sb, "after-begin", &a.probes);

    // Context discovery.
    let snap0 = a.out.join("snap-setup.tsv");
    let (n0, regs0) = drain(&mut sb, &snap0);
    eprintln!("[sbx] setup snapshots: {n0}");
    let mut ctx: Option<u32> = a.ctx_preset;
    if let Some(c) = a.ctx_preset { eprintln!("[sbx] ctx preset 0x{c:08x}"); }
    if let Some((e, ri)) = a.ctx_wp {
        for (eip, r) in &regs0 { if *eip == e { ctx = Some(r[ri]); } }
        eprintln!("[sbx] ctx-wp 0x{e:08x} -> ctx = {:?}", ctx.map(|c| format!("0x{c:08x}")));
    }
    for &e in &a.reg_wps { sb.cpu.add_register_watchpoint(e); }
    if let Some((e, _)) = a.ctx_wp { sb.cpu.add_register_watchpoint(e); }
    if let Some(c) = ctx { arm_mem(&mut sb, &a, c); }
    #[cfg(feature = "trace")]
    for (addr, size, mode) in &a.abs_wps {
        let m = match mode.as_str() { "r" => ud_emulator::WatchMode::Read, "w" => ud_emulator::WatchMode::Write, _ => ud_emulator::WatchMode::Both };
        sb.watch(*addr, *size, m);
        eprintln!("[sbx] abs-wp 0x{addr:08x} size {size} {mode}");
    }
    for &(addr, val) in &a.pokes {
        sb.mmu.store32(addr, val).expect("poke");
        eprintln!("[sbx] poke [0x{addr:08x}] = 0x{val:08x}");
    }

    for (n, fp) in a.frames.iter().enumerate() {
        let frame = std::fs::read(fp).expect("frame");
        let mut ib = in_bih.clone();
        ib.size_image = frame.len() as u32;
        let flags = if n == 0 { 0 } else { ud_emulator::win32::vfw32::ICDECOMPRESS_NOTKEYFRAME };
        let before = sb.cpu.instr_count;
        if a.visited { sb.cpu.enable_visited_eip_tracking(); let _ = sb.cpu.take_visited_eips(); }
        #[cfg(feature = "trace")]
        if a.exec_frame == Some(n) { sb.set_exec_trace(true); eprintln!("[sbx] exec trace ON for frame {n}"); }
        if let Some(cap) = a.frame_cap { sb.cpu.set_instr_limit(before + cap); sb.host.instruction_budget = Some(before + cap); }
        mark("begin", n);
        let res = sb.ic_decompress(hic, flags, &ib, &frame, &out_bih, out_cap);
        mark("end", n);
        #[cfg(feature = "trace")]
        if a.exec_frame == Some(n) { sb.set_exec_trace(false); }
        let after = sb.cpu.instr_count;
        match res {
            Ok((rc, out)) => {
                let op = a.out.join(format!("frame{n}.{}", a.pix));
                std::fs::write(&op, &out).unwrap();
                eprintln!("[sbx] frame {n}: ICDecompress = {} ({} bytes -> {}), {} instructions", rc as i32, out.len(), op.display(), after - before);
            }
            Err(e) => {
                eprintln!("[sbx] frame {n}: ICDecompress ERROR {e:?} after {} instructions", after - before);
                let snap = a.out.join(format!("snap-frame{n}.tsv"));
                let (k, _) = drain(&mut sb, &snap);
                eprintln!("[sbx] frame {n}: {k} snapshots (partial) -> {}", snap.display());
                probe(&sb, &format!("frame{n}-err"), &a.probes);
                std::process::exit(3);
            }
        }
        probe(&sb, &format!("frame{n}"), &a.probes);
        for &(addr, len) in &a.abs_dumps {
            if let Ok(bytes) = sb.mmu.read(addr, len as usize) {
                let dp = a.out.join(format!("dump-frame{n}-{addr:08x}.bin"));
                std::fs::write(&dp, &bytes).unwrap();
                eprintln!("[dump:frame{n}] 0x{addr:08x} len {len} -> {}", dp.display());
            } else { eprintln!("[dump:frame{n}] 0x{addr:08x} len {len} UNMAPPED"); }
        }
        if a.visited {
            let v = sb.cpu.take_visited_eips();
            let vp = a.out.join(format!("visited-frame{n}.txt"));
            let mut f = std::fs::File::create(&vp).unwrap();
            for e in &v { writeln!(f, "{e:08x}").unwrap(); }
            eprintln!("[sbx] frame {n}: {} distinct EIPs -> {}", v.len(), vp.display());
        }
        let snap = a.out.join(format!("snap-frame{n}.tsv"));
        let (k, regs) = drain(&mut sb, &snap);
        eprintln!("[sbx] frame {n}: {k} snapshots -> {}", snap.display());
        if ctx.is_none() {
            if let Some((e, ri)) = a.ctx_wp {
                for (eip, r) in &regs { if *eip == e { ctx = Some(r[ri]); } }
                if let Some(c) = ctx { eprintln!("[sbx] ctx discovered in frame {n}: 0x{c:08x}"); arm_mem(&mut sb, &a, c); }
            }
        }
        if let Some(c) = ctx {
            for &off in &a.ctx_probes {
                let v = sb.mmu.load32(c.wrapping_add(off)).map(|v| format!("0x{v:08x}")).unwrap_or_else(|_| "<unmapped>".into());
                eprintln!("[ctx-probe:frame{n}] [ctx+0x{off:x}] = {v}");
            }
            for &(off, len) in &a.ctx_dumps {
                if let Ok(bytes) = sb.mmu.read(c.wrapping_add(off), len as usize) {
                    let dp = a.out.join(format!("ctxdump-frame{n}-{off:x}.bin"));
                    std::fs::write(&dp, &bytes).unwrap();
                    eprintln!("[ctx-dump:frame{n}] ctx+0x{off:x} len {len} -> {}", dp.display());
                }
            }
        }
        for &e in &a.reg_wps { sb.cpu.add_register_watchpoint(e); }
        if let Some((e, _)) = a.ctx_wp { sb.cpu.add_register_watchpoint(e); }
    }
    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    eprintln!("[sbx] done; total instructions {}", sb.cpu.instr_count);
}

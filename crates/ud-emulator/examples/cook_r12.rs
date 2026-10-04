//! cook_r12 — Validator round 12 sandbox harness for RealNetworks `cook.dll`
//! (RealAudio Cook decoder, PE32 i386, SHA-256 0a8c69d3…47dd2).
//!
//! Drives the RA codec SPI (`RAOpenCodec → RAInitDecoder → RADecode×N`)
//! inside the univdreams sandbox with the real extradata cookie and the real
//! 465-byte container packets of `fixtures/FUN_RM_32.rm`, and captures
//! behavioural evidence only (black-box; no third-party decoder source).
//!
//! Modes (argv[1]):
//!   pcm <flags-hex>     decode all 144 packets with the given RADecode
//!                       `flags`; write `pcm-flags<hex>.raw` + per-call log;
//!                       register-snapshot the driver's per-sub-packet gate
//!                       (RVA 0x12ba) and the flags shift (RVA 0x12ce) on the
//!                       first two calls.
//!   trace <p>           warm up with packets 0..p (flags=1, as round 9 did),
//!                       then decode packet p (flags=1) with store watchpoints
//!                       on the frame context's reader state, the packed word
//!                       buffer, the refinement-count slot and the whole guest
//!                       stack; JSONL to `trace-pkt<p>.jsonl`, plus a `.meta`
//!                       with the live context addresses and tree pointers.
//!   tables              init only; dump the runtime-built VLC tables (spectral
//!                       BSS, envelope BSS, coupling arrays in the context) and
//!                       the init-built DSP tables (window/twiddles/FFT tables)
//!                       to `runtime-*.csv` for a byte-for-byte diff against
//!                       `tables/`.
//!
//! Env: COOK_WS (workspace dir, default the cook cleanroom path),
//!      COOK_OUT (output dir, default ./cook_r12_out).
// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(clippy::all, clippy::pedantic)]

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use ud_emulator::{DLL_PROCESS_ATTACH, Sandbox, WatchMode};

const IB: u32 = 0x60bd_0000;
const STACK_BOTTOM: u32 = 0x9000_0000;
const STACK_SIZE: u32 = 0x0010_0000;

fn ws() -> PathBuf {
    std::env::var_os("COOK_WS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("/Users/magicaltux/projects/oxideav-workspace/docs/audio/cook")
        })
}
fn outdir() -> PathBuf {
    let p = std::env::var_os("COOK_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cook_r12_out"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes(b[o..o + 2].try_into().unwrap())
}

/// Walk the RealMedia top-level chunks and return the stream-0 DATA payloads
/// (validation/04 §2 layout, parsed from bytes).
fn rm_packets(b: &[u8]) -> Vec<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos + 10 <= b.len() {
        let four = &b[pos..pos + 4];
        let size = be32(b, pos + 4) as usize;
        if four == b"DATA" {
            let n = be32(b, pos + 10) as usize;
            let mut p = pos + 18;
            for _ in 0..n {
                let len = be16(b, p + 2) as usize;
                let st = be16(b, p + 4);
                if st == 0 {
                    out.push(b[p + 12..p + len].to_vec());
                }
                p += len;
            }
            return out;
        }
        if size == 0 {
            break;
        }
        pos += size;
    }
    out
}

fn fnv1a(b: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &x in b {
        h ^= x as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

struct Cook {
    sb: Sandbox,
    img: ud_emulator::pe::Image,
    ra: u32,
    backend: u32,
    ctx: u32,
    inbuf: u32,
    outbuf: u32,
    outlen: u32,
}

fn galloc(sb: &mut Sandbox, bytes: &[u8]) -> u32 {
    let p = sb.host.arena_alloc(bytes.len().max(1) as u32).unwrap();
    sb.mmu.write(p, bytes).unwrap();
    p
}

fn setup(dll: &[u8], cookie: &[u8]) -> Cook {
    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(1 << 42);
    let img = sb.load("cook.dll", dll).expect("load cook.dll");
    assert_eq!(img.image_base, IB, "image relocated");
    let r = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    assert_eq!(r, 1);
    let cookie_va = galloc(&mut sb, cookie);
    let mut desc = [0u8; 0x20];
    desc[6..8].copy_from_slice(&2u16.to_le_bytes()); // +0x06 = 2 (spf divisor -> N=1024)
    desc[0xa..0xe].copy_from_slice(&93u32.to_le_bytes()); // +0x0a = sub_packet_size
    desc[0x12..0x16].copy_from_slice(&(cookie.len() as u32).to_le_bytes());
    desc[0x16..0x1a].copy_from_slice(&cookie_va.to_le_bytes());
    let desc_va = galloc(&mut sb, &desc);
    let slot = galloc(&mut sb, &[0u8; 4]);
    let hr = sb
        .call_export(&img, "RAOpenCodec", &[slot])
        .expect("RAOpenCodec");
    let ra = sb.mmu.load32(slot).unwrap();
    println!("RAOpenCodec -> {hr:#x}, ctx={ra:#x}");
    let hr = sb
        .call_export(&img, "RAInitDecoder", &[ra, desc_va])
        .expect("RAInitDecoder");
    println!("RAInitDecoder -> {hr:#x}");
    assert_eq!(hr, 0);
    let backend = sb.mmu.load32(ra).unwrap();
    if std::env::var_os("COOK_PROBE").is_some() {
        for (name, base) in [("ra", ra), ("[ra]", backend)] {
            let v = read_u32s(&sb, base, 24);
            let s: Vec<String> = v.iter().map(|x| format!("{x:08x}")).collect();
            println!("{name} @{base:#x}: {}", s.join(" "));
        }
        std::process::exit(0);
    }
    // [ra] is the decode interface sub-object (vtable 0x8bc4): +4 = frame
    // bits, +8 = samples/frame x channels, +0xc = pointer to the frame
    // context (observed == [ra] + 0x10, the "0x10 lower" of provenance/11).
    let ctx = sb.mmu.load32(backend + 0xc).unwrap();
    println!(
        "frame bits = {} ([ra]+4); spf*ch = {} ([ra]+8); ctx - [ra] = {:#x}",
        sb.mmu.load32(backend + 4).unwrap(),
        sb.mmu.load32(backend + 8).unwrap(),
        ctx.wrapping_sub(backend)
    );
    assert_eq!(sb.mmu.load32(ctx + 4).unwrap(), 1024, "ctx+4 must be N");
    let n = sb.mmu.load32(ctx + 0x47bc).unwrap();
    let sbands = sb.mmu.load32(ctx + 0xc).unwrap();
    let nb = sb.mmu.load32(ctx + 0x20).unwrap();
    let cs = sb.mmu.load32(ctx + 0x18).unwrap();
    let w = sb.mmu.load32(ctx + 0x1c).unwrap();
    let ch = sb.mmu.load32(ctx + 0x8).unwrap();
    println!(
        "backend={backend:#x} frame-ctx={ctx:#x}: N={n} sb={sbands} Nb={nb} cs={cs} w={w} ch={ch}"
    );
    let inbuf = galloc(&mut sb, &[0u8; 512]);
    let outbuf = galloc(&mut sb, &[0u8; 0x10000]);
    let outlen = galloc(&mut sb, &[0u8; 4]);
    Cook {
        sb,
        img,
        ra,
        backend,
        ctx,
        inbuf,
        outbuf,
        outlen,
    }
}

impl Cook {
    fn decode(&mut self, pkt: &[u8], flags: u32) -> (Result<u32, String>, Vec<u8>) {
        self.sb.mmu.write(self.inbuf, pkt).unwrap();
        self.sb.mmu.write(self.outlen, &0u32.to_le_bytes()).unwrap();
        let r = self.sb.call_export(
            &self.img,
            "RADecode",
            &[
                self.ra,
                self.inbuf,
                pkt.len() as u32,
                self.outbuf,
                self.outlen,
                flags,
            ],
        );
        let n = self.sb.mmu.load32(self.outlen).unwrap() as usize;
        let pcm = self.sb.mmu.read(self.outbuf, n.min(0x10000)).unwrap();
        (r.map_err(|e| format!("{e}")), pcm)
    }
}

fn load_inputs() -> (Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
    let w = ws();
    let dll = std::fs::read(w.join("reference/binaries/cook.dll")).unwrap();
    let rm = std::fs::read(w.join("fixtures/FUN_RM_32.rm")).unwrap();
    let cookie = rm[0xe0..0xf0].to_vec();
    assert_eq!(&cookie[..4], &[1, 0, 0, 3]);
    let pk = rm_packets(&rm);
    assert_eq!(pk.len(), 144);
    assert!(pk.iter().all(|p| p.len() == 465));
    (dll, cookie, pk)
}

fn mode_pcm(flags: u32) {
    let (dll, cookie, pk) = load_inputs();
    let mut c = setup(&dll, &cookie);
    let out = outdir();
    let mut log =
        BufWriter::new(File::create(out.join(format!("pcm-flags{flags:x}.log"))).unwrap());
    let mut pcm_all = Vec::new();
    // register snapshots on the driver's gate push (0x12ba: edx = (~flags)&1,
    // ebx = sub-packet index) and the flags shift store (0x12ce: eax = flags>>1)
    c.sb.cpu.register_snapshots_cap = 24;
    c.sb.cpu.add_register_watchpoint(IB + 0x12ba);
    c.sb.cpu.add_register_watchpoint(IB + 0x12ce);
    let mut ok = 0;
    for (i, p) in pk.iter().enumerate() {
        let (r, pcm) = c.decode(p, flags);
        match &r {
            Ok(hr) => {
                if *hr == 0 {
                    ok += 1;
                }
                writeln!(log, "call {i}: hr={hr:#x} out_len={}", pcm.len()).unwrap();
            }
            Err(e) => {
                writeln!(log, "call {i}: TRAP {e}").unwrap();
                println!("call {i}: TRAP {e}");
                break;
            }
        }
        pcm_all.extend_from_slice(&pcm);
        if i == 1 {
            let snaps = c.sb.cpu.clear_register_watchpoints();
            for (eip, regs) in &snaps {
                let rva = eip - IB;
                if rva == 0x12ba {
                    writeln!(
                        log,
                        "  gate-push @0x12ba: subpacket ebx={} gate edx={}",
                        regs[3], regs[2]
                    )
                    .unwrap();
                } else {
                    writeln!(log, "  flags-shift @0x12ce: new flags eax={:#x}", regs[0]).unwrap();
                }
            }
        }
    }
    let path = out.join(format!("pcm-flags{flags:x}.raw"));
    std::fs::write(&path, &pcm_all).unwrap();
    let msg = format!(
        "flags={flags:#x}: {ok}/{} S_OK, {} PCM bytes, FNV-1a {:#010x} -> {}",
        pk.len(),
        pcm_all.len(),
        fnv1a(&pcm_all),
        path.display()
    );
    writeln!(log, "{msg}").unwrap();
    println!("{msg}");
}

fn mode_trace(p: usize) {
    let (dll, cookie, pk) = load_inputs();
    let mut c = setup(&dll, &cookie);
    let out = outdir();
    for i in 0..p {
        let (r, _) = c.decode(&pk[i], 1);
        assert_eq!(r.unwrap(), 0, "warm-up call {i}");
    }
    let ctx = c.ctx;
    let wordbuf = c.sb.mmu.load32(ctx + 0x4798).unwrap();
    // meta: live addresses + tree pointer arrays (for attributing VLC walks)
    let mut meta = BufWriter::new(File::create(out.join(format!("trace-pkt{p}.meta"))).unwrap());
    writeln!(meta, "image_base=0x{IB:08x}").unwrap();
    writeln!(meta, "ra_ctx=0x{:08x}", c.ra).unwrap();
    writeln!(meta, "backend=0x{:08x}", c.backend).unwrap();
    writeln!(meta, "frame_ctx=0x{ctx:08x}").unwrap();
    writeln!(meta, "wordbuf=0x{wordbuf:08x}").unwrap();
    writeln!(meta, "stack=0x{STACK_BOTTOM:08x}+0x{STACK_SIZE:x}").unwrap();
    writeln!(meta, "inbuf=0x{:08x}", c.inbuf).unwrap();
    for k in 0..31u32 {
        let t = c.sb.mmu.load32(ctx + 0x44b8 + 4 * k).unwrap();
        writeln!(meta, "envtree[{k}]=0x{t:08x}").unwrap();
    }
    for k in 0..7u32 {
        let t = c.sb.mmu.load32(ctx + 0x4580 + 4 * k).unwrap();
        writeln!(meta, "spectree[{k}]=0x{t:08x}").unwrap();
    }
    writeln!(
        meta,
        "cpltree=0x{:08x}",
        c.sb.mmu.load32(ctx + 0x459c).unwrap()
    )
    .unwrap();
    // watches
    let jsonl = out.join(format!("trace-pkt{p}.jsonl"));
    c.sb.set_trace_sink(Box::new(BufWriter::new(File::create(&jsonl).unwrap())));
    c.sb.watch(ctx + 0x479c, 0x10, WatchMode::Write); // word ptr / bit pos / cursor / limit
    c.sb.watch(wordbuf, 0x60, WatchMode::Write); // packed sub-packet words (24)
    c.sb.watch(ctx + 0x35c, 4, WatchMode::Write); // refinement count
    c.sb.watch(STACK_BOTTOM, STACK_SIZE, WatchMode::Write); // whole guest stack
    let (r, pcm) = c.decode(&pk[p], 1);
    c.sb.set_trace_sink(Box::new(std::io::sink()));
    c.sb.unwatch(STACK_BOTTOM, STACK_SIZE);
    c.sb.unwatch(ctx + 0x479c, 0x10);
    c.sb.unwatch(wordbuf, 0x60);
    c.sb.unwatch(ctx + 0x35c, 4);
    let words = c.sb.mmu.read(wordbuf, 0x60).unwrap();
    let ws: Vec<String> = words
        .chunks(4)
        .map(|w| format!("{:08x}", u32::from_le_bytes(w.try_into().unwrap())))
        .collect();
    writeln!(meta, "words_after={}", ws.join(",")).unwrap();
    writeln!(
        meta,
        "bit_cursor_after={}",
        c.sb.mmu.load32(ctx + 0x47a4).unwrap()
    )
    .unwrap();
    writeln!(meta, "bit_limit={}", c.sb.mmu.load32(ctx + 0x47a8).unwrap()).unwrap();
    writeln!(
        meta,
        "refine_count={}",
        c.sb.mmu.load32(ctx + 0x35c).unwrap()
    )
    .unwrap();
    writeln!(meta, "decode_result={:?} pcm_bytes={}", r, pcm.len()).unwrap();
    println!(
        "trace pkt {p}: RADecode={:?} pcm={} bytes, cursor={} / {} -> {}",
        r,
        pcm.len(),
        c.sb.mmu.load32(ctx + 0x47a4).unwrap(),
        c.sb.mmu.load32(ctx + 0x47a8).unwrap(),
        jsonl.display()
    );
}

/// Target 4: watch the heap spectrum/output buffers the stereo body and the
/// transform work on ([ctx+0xeae8], [ctx+0xeaf0], [ctx+0xeaf4]) plus the
/// stack, and register-snapshot the transform driver's call sites and the
/// gain-control entry so the FFT input/output can be reconstructed.
fn mode_xform(p: usize) {
    let (dll, cookie, pk) = load_inputs();
    let mut c = setup(&dll, &cookie);
    let out = outdir();
    for i in 0..p {
        let (r, _) = c.decode(&pk[i], 1);
        assert_eq!(r.unwrap(), 0, "warm-up call {i}");
    }
    let ctx = c.ctx;
    // [ctx+0xeae8/0xeaf0/0xeaf4]: heap spectrum buffers handed to the stereo
    // body; ctx+0x14afc: the transform work buffer (pre-twiddle output, FFT
    // in place, fold/window output, then gain control at 0x2d6d).
    let mut bufs: Vec<u32> = [0xeae8u32, 0xeaf0, 0xeaf4]
        .iter()
        .map(|o| c.sb.mmu.load32(ctx + o).unwrap())
        .collect();
    bufs.push(ctx + 0x14afc);
    let mut meta = BufWriter::new(File::create(out.join(format!("xform-pkt{p}.meta"))).unwrap());
    writeln!(meta, "frame_ctx=0x{ctx:08x}").unwrap();
    writeln!(meta, "buf_eae8=0x{:08x}", bufs[0]).unwrap();
    writeln!(meta, "buf_eaf0=0x{:08x}", bufs[1]).unwrap();
    writeln!(meta, "buf_eaf4=0x{:08x}", bufs[2]).unwrap();
    writeln!(meta, "buf_work=0x{:08x}", bufs[3]).unwrap();
    writeln!(
        meta,
        "blocklen_47c0={}",
        c.sb.mmu.load32(ctx + 0x47c0).unwrap()
    )
    .unwrap();
    writeln!(
        meta,
        "fft_n_47ac={}",
        c.sb.mmu.load32(ctx + 0x47ac).unwrap()
    )
    .unwrap();
    // snapshot before: contents of the three buffers
    for (i, b) in bufs.iter().enumerate() {
        std::fs::write(
            out.join(format!("xform-pkt{p}-buf{i}-before.bin")),
            c.sb.mmu.read(*b, 0x1000).unwrap(),
        )
        .unwrap();
    }
    c.sb.cpu.register_snapshots_cap = 256;
    for rva in [
        0x37d0u32, 0x37ee, 0x37f6, 0x37fb, 0x3803, 0x3810, 0x3815, 0x3130, 0x3154, 0x2fe0, 0x2c28,
        0x2c39,
    ] {
        c.sb.cpu.add_register_watchpoint(IB + rva);
    }
    let jsonl = out.join(format!("xform-pkt{p}.jsonl"));
    c.sb.set_trace_sink(Box::new(BufWriter::new(File::create(&jsonl).unwrap())));
    for b in &bufs {
        c.sb.watch(*b, 0x1000, WatchMode::Write);
    }
    c.sb.watch(STACK_BOTTOM, STACK_SIZE, WatchMode::Write);
    let (r, pcm) = c.decode(&pk[p], 1);
    c.sb.set_trace_sink(Box::new(std::io::sink()));
    c.sb.unwatch(STACK_BOTTOM, STACK_SIZE);
    for b in &bufs {
        c.sb.unwatch(*b, 0x1000);
    }
    let snaps = c.sb.cpu.clear_register_watchpoints();
    for (eip, regs) in &snaps {
        writeln!(
            meta,
            "snap rva=0x{:04x} eax=0x{:08x} ecx=0x{:08x} edx=0x{:08x} ebx=0x{:08x} esp=0x{:08x} ebp=0x{:08x} esi=0x{:08x} edi=0x{:08x}",
            eip - IB, regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]
        )
        .unwrap();
    }
    for (i, b) in bufs.iter().enumerate() {
        std::fs::write(
            out.join(format!("xform-pkt{p}-buf{i}-after.bin")),
            c.sb.mmu.read(*b, 0x1000).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(out.join(format!("xform-pkt{p}-pcm.raw")), &pcm).unwrap();
    writeln!(meta, "decode_result={:?} pcm_bytes={}", r, pcm.len()).unwrap();
    println!(
        "xform pkt {p}: RADecode={:?} snaps={} -> {}",
        r,
        snaps.len(),
        jsonl.display()
    );
}

fn dump_u32_rows(path: PathBuf, rows: &[Vec<u32>]) {
    let mut f = BufWriter::new(File::create(path).unwrap());
    for r in rows {
        let s: Vec<String> = r.iter().map(|v| v.to_string()).collect();
        writeln!(f, "{}", s.join(",")).unwrap();
    }
}
fn dump_f32(path: PathBuf, vals: &[u32], per_row: usize) {
    let mut f = BufWriter::new(File::create(path).unwrap());
    for r in vals.chunks(per_row) {
        let s: Vec<String> = r.iter().map(|v| format!("0x{v:08x}")).collect();
        writeln!(f, "{}", s.join(",")).unwrap();
    }
}

fn read_u32s(sb: &Sandbox, addr: u32, n: usize) -> Vec<u32> {
    let b = sb.mmu.read(addr, n * 4).unwrap();
    b.chunks(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect()
}

fn mode_tables() {
    let (dll, cookie, _pk) = load_inputs();
    let c = setup(&dll, &cookie);
    let out = outdir();
    let sb = &c.sb;
    let ctx = c.ctx;
    // spectral: relocated pointer arrays 0x91a8 (lengths) / 0x91c4 (codes), counts 0x91e0
    let counts = read_u32s(sb, IB + 0x91e0, 7);
    let lp = read_u32s(sb, IB + 0x91a8, 7);
    let cp = read_u32s(sb, IB + 0x91c4, 7);
    let mut lens = Vec::new();
    let mut codes = Vec::new();
    for i in 0..7 {
        lens.push(read_u32s(sb, lp[i], counts[i] as usize));
        codes.push(read_u32s(sb, cp[i], counts[i] as usize));
    }
    println!("spectral counts={counts:?} len-ptrs={lp:x?} code-ptrs={cp:x?}");
    dump_u32_rows(
        out.join("runtime-spectral-codebook-code-lengths.csv"),
        &lens,
    );
    dump_u32_rows(out.join("runtime-spectral-codebook-codes.csv"), &codes);
    // envelope family: 50 books x 24; lengths BSS 0xc670 + 0x60k, codes BSS 0xf8f0 + 0x60k
    let mut el = Vec::new();
    let mut ec = Vec::new();
    for k in 0..50u32 {
        el.push(read_u32s(sb, IB + 0xc670 + 0x60 * k, 24));
        ec.push(read_u32s(sb, IB + 0xf8f0 + 0x60 * k, 24));
    }
    dump_u32_rows(out.join("runtime-envelope-codebook-code-lengths.csv"), &el);
    dump_u32_rows(out.join("runtime-envelope-codebook-codes.csv"), &ec);
    // coupling book (w = ctx+0x1c): lengths ctx+0x45a0, codes ctx+0x469c, 2^w-1 symbols
    let w = sb.mmu.load32(ctx + 0x1c).unwrap();
    let n = (1usize << w) - 1;
    dump_u32_rows(
        out.join("runtime-coupling-codebook-code-lengths.csv"),
        &[read_u32s(sb, ctx + 0x45a0, n)],
    );
    dump_u32_rows(
        out.join("runtime-coupling-codebook-codes.csv"),
        &[read_u32s(sb, ctx + 0x469c, n)],
    );
    println!("coupling w={w} n={n}");
    // DSP tables built at init (provenance/06 offsets, relative to the frame ctx)
    let nn = sb.mmu.load32(ctx + 0x47bc).unwrap() as usize;
    let p_sine = sb.mmu.load32(ctx + 0x16afc).unwrap();
    let p_cos = sb.mmu.load32(ctx + 0x16b00).unwrap();
    let p_sin = sb.mmu.load32(ctx + 0x16b04).unwrap();
    let p_win = sb.mmu.load32(ctx + 0x16b08).unwrap();
    let fw = sb.mmu.load32(ctx + 0x47ac).unwrap() as usize;
    let p_tw = sb.mmu.load32(ctx + 0x47b4).unwrap();
    let p_perm = sb.mmu.load32(ctx + 0x47b8).unwrap();
    println!(
        "N={nn} sine@{p_sine:#x} cos@{p_cos:#x} sin@{p_sin:#x} win@{p_win:#x} fft n={fw} tw@{p_tw:#x} perm@{p_perm:#x}"
    );
    dump_f32(
        out.join("runtime-mdct-sine-1024.csv"),
        &read_u32s(sb, p_sine, nn),
        1,
    );
    dump_f32(
        out.join("runtime-mdct-twiddle-cos-1024.csv"),
        &read_u32s(sb, p_cos, nn / 2),
        1,
    );
    dump_f32(
        out.join("runtime-mdct-twiddle-sin-1024.csv"),
        &read_u32s(sb, p_sin, nn / 2),
        1,
    );
    dump_f32(
        out.join("runtime-mdct-window-1024.csv"),
        &read_u32s(sb, p_win, nn / 2 + 1),
        1,
    );
    dump_f32(
        out.join("runtime-coupling-rotation-coeffs.csv"),
        &read_u32s(sb, p_tw, fw),
        2,
    );
    dump_u32_rows(
        out.join("runtime-coupling-index-permutation.csv"),
        &read_u32s(sb, p_perm, fw)
            .iter()
            .map(|v| vec![*v])
            .collect::<Vec<_>>(),
    );
    // tree pointer arrays, for the record
    let mut f = BufWriter::new(File::create(out.join("runtime-tables.meta")).unwrap());
    writeln!(f, "frame_ctx=0x{ctx:08x} N={nn} w={w} fft_n={fw}").unwrap();
    writeln!(f, "spectral_counts={counts:?}").unwrap();
    writeln!(f, "spectral_len_ptrs={lp:x?}").unwrap();
    writeln!(f, "spectral_code_ptrs={cp:x?}").unwrap();
    writeln!(f, "dsp_ptrs sine={p_sine:#x} cos={p_cos:#x} sin={p_sin:#x} win={p_win:#x} tw={p_tw:#x} perm={p_perm:#x}").unwrap();
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("pcm") => {
            let f = u32::from_str_radix(a.get(2).map(String::as_str).unwrap_or("1f"), 16).unwrap();
            mode_pcm(f)
        }
        Some("trace") => mode_trace(a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2)),
        Some("tables") => mode_tables(),
        Some("xform") => mode_xform(a.get(2).and_then(|s| s.parse().ok()).unwrap_or(2)),
        _ => {
            eprintln!("usage: cook_r12 pcm <flags-hex> | trace <packet> | tables | xform <packet>")
        }
    }
}

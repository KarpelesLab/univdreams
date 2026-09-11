//! Round 27 (msmpeg4 cleanroom, Validator/Extractor sandbox side) —
//! generic `mpg4c32.dll` decode harness.
//!
//! Drives `ICOpen(VIDC/MP43, ICMODE_DECOMPRESS) → ICDecompressQuery →
//! ICDecompressBegin → ICDecompress × N → ICDecompressEnd → ICClose`
//! on one or more raw MP43 frames inside the `ud-emulator` sandbox and
//! records, for the cleanroom's per-round analysis scripts:
//!
//! * register-file snapshots at every PC named with `--snap-pc`
//!   (`Cpu::add_register_watchpoint`), drained after **each** frame and
//!   written as JSONL to `--snaps` with the four fixed memory probes
//!   (`[esp]`, `[esp+4]`, `[ebp+8]`, `[ebp-0x50]`);
//! * memory watchpoints named with `--watch addr:size:{r|w|rw}`
//!   (`Sandbox::watch`), whose `mem_read` / `mem_write` JSONL events go
//!   to `--trace`;
//! * post-mortem memory dumps for every `--post-read addr:len`, taken
//!   after the last frame and before `ICDecompressEnd`, appended to the
//!   snaps file as `{"kind":"mem","addr":..,"hex":".."}`;
//! * the decoded output buffer of every frame (`<out>.f<k>.bin`).
//!
//! Everything the harness knows about the codec is a VfW ABI fact; the
//! PCs / addresses come from the caller. No third-party decoder source
//! was consulted for this file.
//!
//! Build/run (trace feature required for `Sandbox::watch`):
//!
//! ```text
//! cargo run --release -p ud-emulator --features trace \
//!     --example round27_msmpeg4_watch -- --dll mpg4c32.dll \
//!     --width 64 --height 48 --frame f0.bin [--frame f1.bin] \
//!     --snap-pc 0x1c215ac6 --watch 0x1c298478:8:r \
//!     --snaps snaps.jsonl --trace trace.jsonl --out dec
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unreadable_literal
)]

use std::io::Write;

use ud_emulator::{Bih, Sandbox, WatchMode, DLL_PROCESS_ATTACH};

const ICMODE_DECOMPRESS: u32 = 1;

fn parse_u32(s: &str) -> u32 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).expect("hex")
    } else {
        s.parse::<u32>().expect("dec")
    }
}

struct Args {
    dll: String,
    width: u32,
    height: u32,
    fcc: String,
    frames: Vec<String>,
    snap_pcs: Vec<u32>,
    watches: Vec<(u32, u32, WatchMode)>,
    post_reads: Vec<(u32, u32)>,
    snaps: Option<String>,
    trace: Option<String>,
    out: Option<String>,
    snap_cap: usize,
    exec_trace: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        dll: String::new(),
        width: 0,
        height: 0,
        fcc: "MP43".into(),
        frames: vec![],
        snap_pcs: vec![],
        watches: vec![],
        post_reads: vec![],
        snaps: None,
        trace: None,
        out: None,
        snap_cap: 4_000_000,
        exec_trace: false,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let k = argv[i].as_str();
        let mut val = || {
            i += 1;
            argv.get(i).cloned().unwrap_or_else(|| panic!("missing value for {k}"))
        };
        match k {
            "--dll" => a.dll = val(),
            "--width" => a.width = parse_u32(&val()),
            "--height" => a.height = parse_u32(&val()),
            "--fcc" => a.fcc = val(),
            "--frame" => a.frames.push(val()),
            "--snap-pc" => a.snap_pcs.push(parse_u32(&val())),
            "--watch" => {
                let v = val();
                let parts: Vec<&str> = v.split(':').collect();
                let mode = match parts.get(2).copied().unwrap_or("rw") {
                    "r" => WatchMode::Read,
                    "w" => WatchMode::Write,
                    _ => WatchMode::Both,
                };
                a.watches.push((parse_u32(parts[0]), parse_u32(parts[1]), mode));
            }
            "--post-read" => {
                let v = val();
                let parts: Vec<&str> = v.split(':').collect();
                a.post_reads.push((parse_u32(parts[0]), parse_u32(parts[1])));
            }
            "--snaps" => a.snaps = Some(val()),
            "--trace" => a.trace = Some(val()),
            "--out" => a.out = Some(val()),
            "--snap-cap" => a.snap_cap = parse_u32(&val()) as usize,
            "--exec-trace" => a.exec_trace = true,
            other => panic!("unknown arg {other}"),
        }
        i += 1;
    }
    assert!(!a.dll.is_empty() && a.width > 0 && a.height > 0 && !a.frames.is_empty());
    a
}

fn fourcc(s: &str) -> u32 {
    let b = s.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn main() {
    let args = parse_args();
    let dll_bytes = std::fs::read(&args.dll).expect("read dll");
    let dll_name = std::path::Path::new(&args.dll)
        .file_name()
        .map_or_else(|| "codec.dll".into(), |n| n.to_string_lossy().into_owned());

    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(4_000_000_000);
    sb.cpu.set_instr_limit(4_000_000_000);
    sb.cpu.register_snapshots_cap = args.snap_cap;
    for pc in &args.snap_pcs {
        sb.cpu.add_register_watchpoint(*pc);
    }
    if let Some(p) = &args.trace {
        let f = std::fs::File::create(p).expect("trace file");
        sb.set_trace_sink(Box::new(std::io::BufWriter::with_capacity(1 << 20, f)));
    }
    for (addr, size, mode) in &args.watches {
        sb.watch(*addr, *size, *mode);
    }
    if args.exec_trace {
        sb.set_exec_trace(true);
    }

    let mut snaps_out: Box<dyn Write> = match &args.snaps {
        Some(p) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(p).expect("snaps file"),
        )),
        None => Box::new(std::io::sink()),
    };

    let img = sb.load(&dll_name, &dll_bytes).expect("load");
    let _ = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");

    let fcc_type = fourcc("VIDC");
    let fcc_h = fourcc(&args.fcc);
    let out_bih = Bih {
        bi_size: 40,
        width: args.width as i32,
        height: args.height as i32,
        planes: 1,
        bit_count: 24,
        compression: [0; 4],
        size_image: args.width * args.height * 3,
        ..Bih::default()
    };
    let mk_in = |len: usize| Bih {
        bi_size: 40,
        width: args.width as i32,
        height: args.height as i32,
        planes: 1,
        bit_count: 24,
        compression: fcc_h.to_le_bytes(),
        size_image: len as u32,
        ..Bih::default()
    };

    let hic = sb.ic_open(fcc_type, fcc_h, ICMODE_DECOMPRESS).expect("ICOpen");
    assert!(hic != 0, "DRV_OPEN refused");
    let first = std::fs::read(&args.frames[0]).expect("frame 0");
    let q = sb
        .ic_decompress_query(hic, &mk_in(first.len()), Some(&out_bih))
        .expect("query");
    eprintln!("[r27] ICDecompressQuery = {}", q as i32);
    assert!(q as i32 == 0, "codec rejected BIH pair");
    let b = sb
        .ic_decompress_begin(hic, &mk_in(first.len()), &out_bih)
        .expect("begin");
    eprintln!("[r27] ICDecompressBegin = {}", b as i32);

    // Drain snapshots produced during open/begin (constructor-time
    // sites such as the IDCT binder fire here, before any frame).
    let mut dump_snaps = |sb: &mut Sandbox, phase: &str, snaps_out: &mut Box<dyn Write>| {
        let regs = std::mem::take(&mut sb.cpu.register_snapshots);
        let mems = sb.cpu.take_memory_snapshots();
        for (i, ((eip, r), m)) in regs.iter().zip(mems.iter()).enumerate() {
            debug_assert_eq!(*eip, m.0);
            let probes: Vec<String> = m
                .1
                .iter()
                .map(|(a, v)| format!("[{},{}]", a, v))
                .collect();
            writeln!(
                snaps_out,
                "{{\"kind\":\"snap\",\"phase\":\"{}\",\"seq\":{},\"eip\":{},\"eax\":{},\"ecx\":{},\"edx\":{},\"ebx\":{},\"esp\":{},\"ebp\":{},\"esi\":{},\"edi\":{},\"probe\":[{}]}}",
                phase, i, eip, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], probes.join(",")
            )
            .unwrap();
        }
        eprintln!("[r27] phase {phase}: {} snapshots", regs.len());
    };
    dump_snaps(&mut sb, "open", &mut snaps_out);

    for (k, path) in args.frames.iter().enumerate() {
        let frame = std::fs::read(path).expect("frame");
        let in_bih = mk_in(frame.len());
        let cap = args.width * args.height * 3;
        let (rc, decoded) = sb
            .ic_decompress(hic, 0, &in_bih, &frame, &out_bih, cap)
            .expect("ICDecompress");
        eprintln!(
            "[r27] frame {k} ({} bytes): ICDecompress = {} ; instr_count={} cpuid_count={}",
            frame.len(),
            rc as i32,
            sb.cpu.instr_count,
            sb.cpu.cpuid_dispatch_count
        );
        writeln!(
            snaps_out,
            "{{\"kind\":\"frame\",\"index\":{},\"bytes\":{},\"rc\":{}}}",
            k,
            frame.len(),
            rc as i32
        )
        .unwrap();
        if let Some(o) = &args.out {
            std::fs::write(format!("{o}.f{k}.bin"), &decoded).expect("write out");
        }
        dump_snaps(&mut sb, &format!("frame{k}"), &mut snaps_out);
    }

    // Post-mortem memory reads (state as left by the last frame).
    let mut reads = args.post_reads.clone();
    // Always record the two IDCT binding slots (globals in .data).
    reads.push((0x1c298478, 8));
    for (addr, len) in reads {
        match sb.mmu.read(addr, len as usize) {
            Ok(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(
                    snaps_out,
                    "{{\"kind\":\"mem\",\"addr\":{},\"len\":{},\"hex\":\"{}\"}}",
                    addr, len, hex
                )
                .unwrap();
            }
            Err(e) => {
                writeln!(
                    snaps_out,
                    "{{\"kind\":\"mem\",\"addr\":{},\"len\":{},\"error\":\"{:?}\"}}",
                    addr, len, e
                )
                .unwrap();
            }
        }
    }
    snaps_out.flush().unwrap();

    let _ = sb.ic_decompress_end(hic);
    let _ = sb.ic_close(hic);
    eprintln!("[r27] done");
}

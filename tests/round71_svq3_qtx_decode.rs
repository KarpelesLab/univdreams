//! Round 71 — SVQ3 clean-room sandbox harness (video/svq3 provenance/07).
//!
//! Drives the SVQ3 *decompressor* core class inside
//! `QuickTimeEssentials.qtx` (SHA-256 0fd4e7eb…3732c, PE32 i386, image
//! base 0x67d00000) WITHOUT the QuickTime Component Manager: the qtx
//! imports only kernel32/advapi32/version/user32/shell32, and the
//! decoder core is a plain C++ object reachable through the component
//! glue's own call sequence (read statically, see provenance/07):
//!
//!   core = alloc(0x12d6); ctor(core)                     0x67d11620 / 0x67d15d30
//!   core->vt[0x3c](seqh_payload, len)                   SEQH parse   (0x67d14760)
//!   pool = alloc(0x7c); pool_init(pool)                  0x67d11650
//!   core->vt[0x00](w, h, &params)                        pool-parameter filler (0x67d120c0)
//!   pool_alloc(pool, &params)                            0x67d11bc0
//!   core->vt[0x30](w, h, &o1, &o2)                       set size / allocate (0x67d15e00)
//!   pool_reset(pool)                                     0x67d11a30
//!   per access unit: core->vt[0x34](data, size, pool, &opts)   frame driver (0x67d14ea0)
//!   pool_planes(pool, &y, &u, &v, &stride, &cstride)     0x67d118f0
//!
//! Register-snapshot watchpoints are armed on the universal-code reader
//! (0x67d11f90: entry, the post-load site 0x67d11f9c where eax = bit
//! position, and its three `ret`s), the fixed-width reader (0x67d11ed0 /
//! 0x67d11ed7), the three residual decoders (entries, bit-position
//! sites, rets), the quantiser-delta reader, the three macroblock loops
//! and the P-loop jump-table arms.  Snapshots are dumped as JSONL under
//! `$SVQ3_OUT/<fixture>/frameN.snap.jsonl`; the decoded (cropped) planes
//! as `frameN.{y,u,v}.raw`.
//!
//! Env: SVQ3_QTX (path), SVQ3_FIXTURE (fixture dir with samples.bin +
//! samples-index.csv + extradata.bin), SVQ3_OUT (output dir), SVQ3_FRAMES
//! (how many access units, default all), SVQ3_VTABLE (override the core
//! vtable VA, default = base-class table left by the ctor).

// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::uninlined_format_args,
    clippy::manual_let_else,
    clippy::needless_range_loop,
    clippy::cast_lossless,
    clippy::similar_names
)]

use std::io::Write;
use std::path::PathBuf;
use univdreams::emulator::emulator::regs::Reg32;
use univdreams::emulator::win32::call_guest;
use univdreams::emulator::{DLL_PROCESS_ATTACH, Sandbox};

const VA_ALLOC: u32 = 0x67d1_1620; // cdecl(size) -> zero-filled block (CRT malloc + memset)
const VA_CORE_CTOR: u32 = 0x67d1_5d30; // thiscall
const VA_POOL_INIT: u32 = 0x67d1_1650; // thiscall
const VA_POOL_ALLOC: u32 = 0x67d1_1bc0; // thiscall(params*) ret 4
const VA_POOL_RESET: u32 = 0x67d1_1a30; // thiscall
const VA_POOL_PLANES: u32 = 0x67d1_18f0; // thiscall(&y,&u,&v,&s,&cs) ret 0x14
const CORE_SIZE: u32 = 0x12d6;
const POOL_SIZE: u32 = 0x7c;

/// (VA, label) — every site that gets a register snapshot.
const SNAP_SITES: &[(u32, &str)] = &[
    (0x67d11f90, "uvlc.entry"),
    (0x67d11f9c, "uvlc.pos"), // eax = bit position, edx = data ptr, esi = reader
    (0x67d11fe2, "uvlc.ret1"),
    (0x67d11ff9, "uvlc.ret2"),
    (0x67d120a6, "uvlc.retn"),
    (0x67d11ed0, "bits.entry"), // [esp+4]=reader [esp+8]=n
    (0x67d11ed7, "bits.pos"),   // eax = bit position, edx = reader
    (0x67d11f3e, "bits.ret1"),
    (0x67d11f74, "bits.ret2"),
    (0x67d121d0, "resid_n.entry"),
    (0x67d12201, "resid_n.pos"), // eax = bit position
    (0x67d12238, "resid_n.ret1"),
    (0x67d12437, "resid_n.ret2"),
    (0x67d1244c, "resid_n.ret3"),
    (0x67d24750, "resid_a.entry"),
    (0x67d247a1, "resid_a.pos"), // eax = bit position
    (0x67d24715, "resid_a.ret1"),
    (0x67d24724, "resid_a.ret2"),
    (0x67d12500, "chdc.entry"),
    (0x67d1258e, "chdc.ret"),
    (0x67d124a0, "chac.entry"),
    (0x67d124f7, "chac.ret"),
    (0x67d235b0, "qpdelta.entry"),
    (0x67d235e4, "qpdelta.ret"),
    (0x67d26cf0, "loop_i.entry"),
    (0x67d23800, "loop_p.entry"),
    (0x67d193e0, "loop_b.entry"),
    (0x67d26edb, "loop_i.type"),
    (0x67d23a62, "loop_p.type"),
    (0x67d23c0f, "loop_p.arm0"),
    (0x67d23c34, "loop_p.arm1"),
    (0x67d23d0b, "loop_p.arm2"),
    (0x67d23c93, "loop_p.arm3"),
    (0x67d23d82, "loop_p.arm4"),
    (0x67d23e63, "loop_p.arm5"),
    (0x67d24020, "loop_p.arm6"),
    (0x67d241f5, "loop_p.arm7"),
    (0x67d245b6, "loop_p.arm8"),
    (0x67d195f4, "loop_b.type"),
    (0x67d1972c, "loop_b.arm0"),
    (0x67d1974c, "loop_b.arm1"),
    (0x67d1977c, "loop_b.arm2"),
    (0x67d197ac, "loop_b.arm3"),
    (0x67d197fc, "loop_b.arm4"),
    (0x67d14d50, "slice_hdr.entry"),
    (0x67d13d30, "envelope.entry"),
    (0x67d14ea0, "driver.entry"),
    (0x67d14760, "seqh.entry"),
    (0x67d24e4a, "i4.mode"), // eax = 4x4 pred mode, esi = dest sample address
    (0x67d255e3, "i16.mode"), // edi = 16x16 pred mode
    (0x67d230b5, "mvpred.x"), // edi = horizontal predictor (clamped), edx = out ptr
    (0x67d230d0, "mvpred.y_neg"), // eax = vertical predictor (negative-clamp path)
    (0x67d230f1, "mvpred.y"), // eax = vertical predictor
    (0x67d1307c, "mvstore16"), // esi = mv x (1/6), edi = mv y (1/6), ecx = slot
    (0x67d13136, "mvstore.other"),
    (0x67d1313b, "mvstore16x8"),
    (0x67d131a8, "mvstore8"),
    (0x67d132ab, "mvstore4"),
    (0x67d21e10, "mc.third"),
    (0x67d22350, "mc.half"),
    (0x67d22610, "mc.full"),
    (0x67d22a30, "mc.skipcopy"),
    (0x67d23440, "mv.third.entry"),
    (0x67d232d0, "mv.half.entry"),
    (0x67d23150, "mv.full.entry"),
];

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn r32(sb: &Sandbox, a: u32) -> u32 {
    sb.mmu
        .load32(a)
        .unwrap_or_else(|e| panic!("load32 {a:#x}: {e}"))
}
fn w32(sb: &mut Sandbox, a: u32, v: u32) {
    sb.mmu
        .store32(a, v)
        .unwrap_or_else(|e| panic!("store32 {a:#x}: {e}"));
}
fn read_bytes(sb: &Sandbox, a: u32, n: u32) -> Vec<u8> {
    (0..n).map(|i| sb.mmu.load8(a + i).unwrap_or(0)).collect()
}
fn galloc(sb: &mut Sandbox, n: u32) -> u32 {
    let a = sb.host.arena_alloc(n).expect("arena_alloc");
    let zero = vec![0u8; n as usize];
    sb.mmu.write_initializer(a, &zero).expect("zero fill");
    a
}

fn thiscall(sb: &mut Sandbox, va: u32, this: u32, args: &[u32]) -> Result<u32, String> {
    let esp = sb.cpu.regs.get32(Reg32::Esp);
    sb.cpu.regs.set32(Reg32::Ecx, this);
    let r = call_guest(
        &mut sb.cpu,
        &mut sb.mmu,
        &mut sb.registry,
        &mut sb.host,
        va,
        args,
    )
    .map_err(|e| format!("{e} (eip={:#010x})", sb.cpu.regs.eip));
    sb.cpu.regs.set32(Reg32::Esp, esp);
    r
}
fn cdecl(sb: &mut Sandbox, va: u32, args: &[u32]) -> Result<u32, String> {
    thiscall(sb, va, 0, args)
}

fn dump_snaps(
    sb: &mut Sandbox,
    path: &PathBuf,
    labels: &std::collections::BTreeMap<u32, &str>,
) -> usize {
    let regs = std::mem::take(&mut sb.cpu.register_snapshots);
    let mems = std::mem::take(&mut sb.cpu.memory_snapshots);
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).expect("create snap file"));
    for (i, (eip, r)) in regs.iter().enumerate() {
        let lab = labels.get(eip).copied().unwrap_or("?");
        let m = mems.get(i).map(|(_, p)| *p).unwrap_or([(0, 0); 4]);
        writeln!(
            f,
            "{{\"i\":{i},\"eip\":\"{eip:#010x}\",\"site\":\"{lab}\",\"eax\":{},\"ecx\":{},\"edx\":{},\"ebx\":{},\"esp\":{},\"ebp\":{},\"esi\":{},\"edi\":{},\"probe\":[[{},{}],[{},{}],[{},{}],[{},{}]]}}",
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
            m[0].0, m[0].1, m[1].0, m[1].1, m[2].0, m[2].1, m[3].0, m[3].1
        )
        .unwrap();
    }
    regs.len()
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn svq3_qtx_decode_fixture() {
    let qtx = env("SVQ3_QTX").unwrap_or_else(|| {
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/svq3/reference/binaries/QuickTimeEssentials.qtx".into()
    });
    let fixture = match env("SVQ3_FIXTURE") {
        Some(f) => PathBuf::from(f),
        None => {
            eprintln!("SVQ3_FIXTURE not set; skipping");
            return;
        }
    };
    let out = PathBuf::from(env("SVQ3_OUT").unwrap_or_else(|| "/tmp/svq3-out".into()));
    std::fs::create_dir_all(&out).unwrap();
    let max_frames: usize = env("SVQ3_FRAMES")
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);
    let only: Option<usize> = env("SVQ3_ONLY").and_then(|s| s.parse().ok());
    let vt_override: Option<u32> =
        env("SVQ3_VTABLE").and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok());

    let bytes = std::fs::read(&qtx).expect("read qtx");
    let samples = std::fs::read(fixture.join("samples.bin")).expect("samples.bin");
    let index = std::fs::read_to_string(fixture.join("samples-index.csv")).expect("index");
    let extradata = std::fs::read(fixture.join("extradata.bin")).expect("extradata");

    // Locate the SEQH atom inside the SMI wrapper: 'SEQH' fourcc, then
    // u32 big-endian payload length, then payload (matches the glue at
    // 0x67d10ccc..0x67d10d0a: payload = atom+8, len = bswap(atom+4)).
    let p = extradata
        .windows(4)
        .position(|w| w == b"SEQH")
        .expect("SEQH");
    let seqh_len = u32::from_be_bytes([
        extradata[p + 4],
        extradata[p + 5],
        extradata[p + 6],
        extradata[p + 7],
    ]);
    let seqh = &extradata[p + 8..p + 8 + seqh_len as usize];
    eprintln!("SEQH payload: {:02x?}", seqh);

    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(50_000_000_000);
    sb.host.instruction_budget = Some(50_000_000_000);
    sb.cpu.register_snapshots_cap = 20_000_000;
    let (img, unresolved) = sb
        .load_fail_soft("QuickTimeEssentials.qtx", &bytes)
        .expect("load");
    eprintln!(
        "loaded at {:#x}; {} fail-soft imports: {:?}",
        img.image_base,
        unresolved.len(),
        unresolved
    );
    assert_eq!(
        img.image_base, 0x67d0_0000,
        "image must load at its preferred base (VAs are absolute)"
    );
    let r = sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    eprintln!("DllMain -> {r:#x}");

    // --- core object -------------------------------------------------
    let core = cdecl(&mut sb, VA_ALLOC, &[CORE_SIZE]).expect("alloc core");
    assert!(core != 0);
    thiscall(&mut sb, VA_CORE_CTOR, core, &[]).expect("core ctor");
    if let Some(vt) = vt_override {
        w32(&mut sb, core, vt);
    }
    let vt = r32(&sb, core);
    eprintln!("core={core:#x} vtable={vt:#x}");
    let slot = |sb: &Sandbox, off: u32| r32(sb, vt + off);

    // --- SEQH --------------------------------------------------------
    let seqh_buf = galloc(&mut sb, 64);
    sb.mmu.write_initializer(seqh_buf, seqh).unwrap();
    let f = slot(&sb, 0x3c);
    let rc = thiscall(&mut sb, f, core, &[seqh_buf, seqh_len]).expect("seqh parse");
    let w = r32(&sb, core + 0x2c);
    let h = r32(&sb, core + 0x30);
    eprintln!(
        "SEQH parse rc={rc} width={w} height={h} halfpel={} thirdpel={} [0x4c]={} [0x70]={} [0x12ce]={} [0x34]={} [0x68]={}",
        r32(&sb, core + 0x40),
        r32(&sb, core + 0x44),
        r32(&sb, core + 0x4c),
        r32(&sb, core + 0x70),
        r32(&sb, core + 0x12ce),
        r32(&sb, core + 0x34),
        r32(&sb, core + 0x68)
    );
    assert_eq!(rc, 0, "SEQH parse failed");

    // --- pool --------------------------------------------------------
    let pool = cdecl(&mut sb, VA_ALLOC, &[POOL_SIZE]).expect("alloc pool");
    thiscall(&mut sb, VA_POOL_INIT, pool, &[]).expect("pool init");
    let params = galloc(&mut sb, 0x40);
    let f = slot(&sb, 0x00);
    let rc = thiscall(&mut sb, f, core, &[w, h, params]).expect("params");
    let pb: Vec<u32> = (0..13).map(|i| r32(&sb, params + 4 * i)).collect();
    eprintln!("params rc={rc}: {pb:?}");
    let rc = thiscall(&mut sb, VA_POOL_ALLOC, pool, &[params]).expect("pool alloc");
    eprintln!(
        "pool alloc rc={rc} count={} stride={} cstride={}",
        r32(&sb, pool + 0x10),
        r32(&sb, pool + 0x14),
        r32(&sb, pool + 0x18)
    );
    assert_eq!(rc, 0);
    let o1 = galloc(&mut sb, 8);
    let f = slot(&sb, 0x30);
    let rc = thiscall(&mut sb, f, core, &[w, h, o1, o1 + 4]).expect("set size");
    eprintln!(
        "set-size rc={rc} o1={} o2={} mbw*16={} mbh*16={}",
        r32(&sb, o1),
        r32(&sb, o1 + 4),
        r32(&sb, core + 0x1198),
        r32(&sb, core + 0x119c)
    );
    assert_eq!(rc, 0);
    thiscall(&mut sb, VA_POOL_RESET, pool, &[]).expect("pool reset");

    // --- watchpoints ---------------------------------------------------
    let mut labels = std::collections::BTreeMap::new();
    for (va, l) in SNAP_SITES {
        sb.cpu.add_register_watchpoint(*va);
        labels.insert(*va, *l);
    }

    // --- decode --------------------------------------------------------
    let opts = galloc(&mut sb, 0x40);
    w32(&mut sb, opts + 0x14, 1);
    let outs = galloc(&mut sb, 0x20);
    let mut summary = std::fs::File::create(out.join("summary.txt")).unwrap();
    let mut n = 0usize;
    for line in index.lines().skip(1) {
        if n >= max_frames {
            break;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 4 {
            continue;
        }
        let frame: usize = cols[0].parse().unwrap();
        if let Some(o) = only {
            if frame != o {
                continue;
            }
        }
        let off: usize = cols[1].parse().unwrap();
        let size: usize = cols[2].parse().unwrap();
        let au = &samples[off..off + size];
        let buf = galloc(&mut sb, (size + 64) as u32);
        sb.mmu.write_initializer(buf, au).unwrap();
        let t0 = std::time::Instant::now();
        let f = slot(&sb, 0x34);
        let res = thiscall(&mut sb, f, core, &[buf, size as u32, pool, opts]);
        let dt = t0.elapsed();
        let reader = r32(&sb, core + 4);
        let bitpos = r32(&sb, reader + 4);
        let bitlim = r32(&sb, reader);
        let rerr = r32(&sb, reader + 0x18);
        let nsnap = dump_snaps(
            &mut sb,
            &out.join(format!("frame{frame}.snap.jsonl")),
            &labels,
        );
        let line = format!(
            "frame {frame}: size={size} rc={:?} slice_type={} qp={} pic_id={} reader_pos={bitpos} reader_limit={bitlim} reader_err={rerr} snaps={nsnap} time={:.1}s pool_cur={} pool_ref={}",
            res,
            r32(&sb, core + 0x1c),
            r32(&sb, core + 0x10),
            r32(&sb, core + 0xc),
            dt.as_secs_f64(),
            r32(&sb, pool),
            r32(&sb, pool + 4)
        );
        eprintln!("{line}");
        writeln!(summary, "{line}").unwrap();
        if res.is_err() {
            break;
        }
        // planes of the current display picture
        thiscall(
            &mut sb,
            VA_POOL_PLANES,
            pool,
            &[outs, outs + 4, outs + 8, outs + 12, outs + 16],
        )
        .expect("planes");
        let (py, pu, pv, st, cst) = (
            r32(&sb, outs),
            r32(&sb, outs + 4),
            r32(&sb, outs + 8),
            r32(&sb, outs + 12),
            r32(&sb, outs + 16),
        );
        eprintln!("  planes y={py:#x} u={pu:#x} v={pv:#x} stride={st} cstride={cst}");
        let mut y = Vec::with_capacity((w * h) as usize);
        for row in 0..h {
            y.extend(read_bytes(&sb, py + row * st, w));
        }
        let (cw, ch) = (w / 2, h / 2);
        let mut u = Vec::new();
        let mut v = Vec::new();
        for row in 0..ch {
            u.extend(read_bytes(&sb, pu + row * cst, cw));
            v.extend(read_bytes(&sb, pv + row * cst, cw));
        }
        std::fs::write(out.join(format!("frame{frame}.y.raw")), &y).unwrap();
        std::fs::write(out.join(format!("frame{frame}.u.raw")), &u).unwrap();
        std::fs::write(out.join(format!("frame{frame}.v.raw")), &v).unwrap();
        // every pool record: [pool+0xc] -> count x 5 dwords (Y,U,V,aux0,aux1)
        let count = r32(&sb, pool + 0x10);
        let recs = r32(&sb, pool + 0xc);
        let pline = format!(
            "  pool: cur={} ref={} [8]={} [0x44]={} [0x48]={} [0x5c]={} [0x60]={} [0x64]={} count={count}",
            r32(&sb, pool),
            r32(&sb, pool + 4),
            r32(&sb, pool + 8),
            r32(&sb, pool + 0x44),
            r32(&sb, pool + 0x48),
            r32(&sb, pool + 0x5c),
            r32(&sb, pool + 0x60),
            r32(&sb, pool + 0x64)
        );
        eprintln!("{pline}");
        writeln!(summary, "{pline}").unwrap();
        for k in 0..count {
            let rec = recs + k * 0x14;
            let (by, bu, bv) = (r32(&sb, rec), r32(&sb, rec + 4), r32(&sb, rec + 8));
            let mut yy = Vec::new();
            for row in 0..h {
                yy.extend(read_bytes(&sb, by + row * st, w));
            }
            for row in 0..ch {
                yy.extend(read_bytes(&sb, bu + row * cst, cw));
            }
            for row in 0..ch {
                yy.extend(read_bytes(&sb, bv + row * cst, cw));
            }
            std::fs::write(out.join(format!("frame{frame}.buf{k}.yuv")), &yy).unwrap();
        }
        n += 1;
    }
}

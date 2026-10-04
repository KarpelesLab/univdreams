//! Round 10 (svq3 provenance/10, sandbox-03) — intra 16x16 plane predictor,
//! chroma DC predictor, and the three motion-compensation routines (full-,
//! half-, third-pel) of the SVQ3 decompressor inside `QuickTimeEssentials.qtx`
//! (SHA-256 0fd4e7eb…3732c, image base 0x67d00000), measured two ways:
//!
//! * `svq3_r10_direct` — the decoder core is constructed exactly as in the
//!   round-71 / round-8 harnesses (ctor, SEQH, pool, set-size), then the
//!   leaf routines are called directly on synthetic sample planes the
//!   harness owns (the core's plane-pointer / stride fields +0x11b0,
//!   +0x11b4, +0x11bc, +0x11c0, +0x11c4 are pointed at harness buffers):
//!     0x67d255a0 thiscall(x, y, mode)            intra 16x16 predictor
//!     0x67d25a20 thiscall(plane, x, y)            chroma DC predictor
//!     0x67d22610 thiscall(16 args)                full-pel motion comp
//!     0x67d22350 thiscall(14 args)                half-pel motion comp
//!     0x67d21e10 thiscall(14 args)                third-pel motion comp
//!   Every output is compared with an explicit arithmetic model; mismatch
//!   counts and a sample of cases go to `$SVQ3_OUT/direct.txt`.
//!
//! * `svq3_r10_fixture` — full fixture decode (as round 8) with register
//!   snapshots + snapshot-time memory probes at the plane arm entry
//!   (0x67d25768, esi = destination, neighbours read through probes) and
//!   its return (0x67d25a03, ebp = destination + 16 rows), and at the
//!   chroma DC predictor after its availability test (0x67d25a5b, esi =
//!   destination) and its three exits (0x67d25b53 / 0x67d25dd9 /
//!   0x67d25ff7, esi = destination + 7 rows). Output: `frameN.pred.jsonl`.
//!
//! Env: SVQ3_QTX, SVQ3_FIXTURE, SVQ3_OUT, SVQ3_TRIALS (direct, default 2000).

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
    clippy::similar_names,
    clippy::too_many_arguments
)]

use std::io::Write;
use std::path::PathBuf;
use ud_emulator::emulator::regs::Reg32;
use ud_emulator::win32::call_guest;
use ud_emulator::{DLL_PROCESS_ATTACH, Sandbox};

const VA_ALLOC: u32 = 0x67d1_1620;
const VA_CORE_CTOR: u32 = 0x67d1_5d30;
const VA_POOL_INIT: u32 = 0x67d1_1650;
const VA_POOL_ALLOC: u32 = 0x67d1_1bc0;
const VA_POOL_RESET: u32 = 0x67d1_1a30;
const CORE_SIZE: u32 = 0x12d6;
const POOL_SIZE: u32 = 0x7c;

const VA_I16: u32 = 0x67d2_55a0;
const VA_CDC: u32 = 0x67d2_5a20;
const VA_MC_FULL: u32 = 0x67d2_2610;
const VA_MC_HALF: u32 = 0x67d2_2350;
const VA_MC_THIRD: u32 = 0x67d2_1e10;

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

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as u32
    }
    fn range(&mut self, lo: i32, hi: i32) -> i32 {
        lo + (self.next() % ((hi - lo + 1) as u32)) as i32
    }
}

/// Load the component and build a decoder core the same way as the
/// round-8 harness; returns (sandbox, core, pool, width, height).
fn setup(fixture: &PathBuf) -> (Sandbox, u32, u32, u32, u32) {
    let qtx = env("SVQ3_QTX").unwrap_or_else(|| {
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/svq3/reference/binaries/QuickTimeEssentials.qtx".into()
    });
    let bytes = std::fs::read(&qtx).expect("read qtx");
    let extradata = std::fs::read(fixture.join("extradata.bin")).expect("extradata");
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
    let seqh = extradata[p + 8..p + 8 + seqh_len as usize].to_vec();

    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(50_000_000_000);
    sb.host.instruction_budget = Some(50_000_000_000);
    sb.cpu.register_snapshots_cap = 20_000_000;
    let (img, _unres) = sb
        .load_fail_soft("QuickTimeEssentials.qtx", &bytes)
        .expect("load");
    assert_eq!(img.image_base, 0x67d0_0000);
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    let core = cdecl(&mut sb, VA_ALLOC, &[CORE_SIZE]).expect("alloc core");
    thiscall(&mut sb, VA_CORE_CTOR, core, &[]).expect("ctor");
    let vt = r32(&sb, core);
    let seqh_buf = galloc(&mut sb, 64);
    sb.mmu.write_initializer(seqh_buf, &seqh).unwrap();
    let f = r32(&sb, vt + 0x3c);
    let rc = thiscall(&mut sb, f, core, &[seqh_buf, seqh.len() as u32]).expect("seqh");
    assert_eq!(rc, 0);
    let w = r32(&sb, core + 0x2c);
    let h = r32(&sb, core + 0x30);
    let pool = cdecl(&mut sb, VA_ALLOC, &[POOL_SIZE]).expect("alloc pool");
    thiscall(&mut sb, VA_POOL_INIT, pool, &[]).expect("pool init");
    let params = galloc(&mut sb, 0x40);
    let f = r32(&sb, vt);
    thiscall(&mut sb, f, core, &[w, h, params]).expect("params");
    let rc = thiscall(&mut sb, VA_POOL_ALLOC, pool, &[params]).expect("pool alloc");
    assert_eq!(rc, 0);
    let o1 = galloc(&mut sb, 8);
    let f = r32(&sb, vt + 0x30);
    let rc = thiscall(&mut sb, f, core, &[w, h, o1, o1 + 4]).expect("set size");
    assert_eq!(rc, 0);
    thiscall(&mut sb, VA_POOL_RESET, pool, &[]).expect("pool reset");
    (sb, core, pool, w, h)
}

fn tdiv(a: i32, b: i32) -> i32 {
    a / b // Rust integer division truncates toward zero
}

/// Model of the plane arm (spec/01 Gap 4 as rewritten in round 10).
/// `t[k]` = top row sample k-1 (t[0] = corner), `l[k]` = left column sample k-1 (l[0] = corner).
fn plane_model(t: &[i32; 17], l: &[i32; 17]) -> [[u8; 16]; 16] {
    let top = |i: i32| t[(i + 1) as usize];
    let left = |i: i32| l[(i + 1) as usize];
    let mut hh = 0;
    let mut vv = 0;
    for i in 1..=8 {
        hh += i * (top(7 + i) - top(7 - i));
        vv += i * (left(7 + i) - left(7 - i));
    }
    let b = tdiv(5 * tdiv(hh, 4), 16); // from the top row, applied down the rows
    let c = tdiv(5 * tdiv(vv, 4), 16); // from the left column, applied along a row
    let a = 16 * (left(15) + top(15));
    let mut o = [[0u8; 16]; 16];
    for r in 0..16 {
        for col in 0..16 {
            let v = a - 7 * (b + c) + 16 + b * r as i32 + c * col as i32;
            o[r][col] = tdiv(v, 32) as u8; // low 8 bits, no clamp
        }
    }
    o
}

/// The two readings the fixture-pinned Implementer model left open, plus the old spec/01 text.
fn plane_alt(t: &[i32; 17], l: &[i32; 17], variant: u32) -> [[u8; 16]; 16] {
    let top = |i: i32| t[(i + 1) as usize];
    let left = |i: i32| l[(i + 1) as usize];
    let (mut hh, mut vv) = (0, 0);
    let n = if variant == 0 { 7 } else { 8 };
    for i in 1..=n {
        hh += i * (top(7 + i) - top(7 - i));
        vv += i * (left(7 + i) - left(7 - i));
    }
    let (b, c) = match variant {
        0 => ((5 * hh + 32) >> 6, (5 * vv + 32) >> 6), // old spec/01 text
        1 => ((hh + 16) >> 5, (vv + 16) >> 5),
        _ => ((5 * hh + 48) >> 7, (5 * vv + 48) >> 7),
    };
    let a = 16 * (left(15) + top(15));
    let mut o = [[0u8; 16]; 16];
    for r in 0..16 {
        for col in 0..16 {
            let v = (a + b * (r as i32 - 7) + c * (col as i32 - 7) + 16) >> 5;
            o[r][col] = v.clamp(0, 255) as u8;
        }
    }
    o
}

fn cdc_model(top: Option<[i32; 8]>, left: Option<[i32; 8]>) -> [[u8; 2]; 2] {
    // quadrant [row][col]
    let s = |v: &[i32; 8], k: usize| v[4 * k..4 * k + 4].iter().sum::<i32>();
    let mut q = [[128u8; 2]; 2];
    match (top, left) {
        (None, None) => {}
        (Some(t), None) => {
            for r in 0..2 {
                for c in 0..2 {
                    q[r][c] = ((s(&t, c) + 2) >> 2) as u8;
                }
            }
        }
        (None, Some(l)) => {
            for r in 0..2 {
                for c in 0..2 {
                    q[r][c] = ((s(&l, r) + 2) >> 2) as u8;
                }
            }
        }
        (Some(t), Some(l)) => {
            q[0][0] = ((s(&t, 0) + s(&l, 0) + 4) >> 3) as u8;
            q[0][1] = ((s(&t, 1) + 2) >> 2) as u8;
            q[1][0] = ((s(&l, 1) + 2) >> 2) as u8;
            q[1][1] = ((s(&t, 1) + s(&l, 1) + 4) >> 3) as u8;
        }
    }
    q
}

/// Kernel model: `phase` = (px, py) in units of 1/`den` sample (den 1, 2 or 3).
fn kern(src: &dyn Fn(i32, i32) -> i32, x: i32, y: i32, px: i32, py: i32, den: i32) -> u8 {
    let a = src(x, y);
    let b = src(x + 1, y);
    let c = src(x, y + 1);
    let d = src(x + 1, y + 1);
    let v = match (den, px, py) {
        (_, 0, 0) => a,
        (2, 1, 0) => (a + b + 1) >> 1,
        (2, 0, 1) => (a + c + 1) >> 1,
        (2, 1, 1) => (a + b + c + d + 2) >> 2,
        (3, 1, 0) => (4 * a + 2 * b + 3) / 6,
        (3, 2, 0) => (2 * a + 4 * b + 3) / 6,
        (3, 0, 1) => (4 * a + 2 * c + 3) / 6,
        (3, 0, 2) => (2 * a + 4 * c + 3) / 6,
        (3, 1, 1) => (4 * a + 3 * b + 3 * c + 2 * d + 6) / 12,
        (3, 2, 1) => (3 * a + 4 * b + 2 * c + 3 * d + 6) / 12,
        (3, 1, 2) => (3 * a + 2 * b + 4 * c + 3 * d + 6) / 12,
        (3, 2, 2) => (2 * a + 3 * b + 3 * c + 4 * d + 6) / 12,
        _ => panic!("bad phase"),
    };
    v as u8
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn svq3_r10_direct() {
    let fixture = match env("SVQ3_FIXTURE") {
        Some(f) => PathBuf::from(f),
        None => {
            eprintln!("SVQ3_FIXTURE not set; skipping");
            return;
        }
    };
    let out = PathBuf::from(env("SVQ3_OUT").unwrap_or_else(|| "/tmp/svq3-r10".into()));
    std::fs::create_dir_all(&out).unwrap();
    let trials: u32 = env("SVQ3_TRIALS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let (mut sb, core, _pool, w, h) = setup(&fixture);
    let mut rep = std::fs::File::create(out.join("direct.txt")).unwrap();
    let interp = r32(&sb, core + 0x7c);
    if let Some(v) =
        env("SVQ3_IVT").and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    {
        let o = r32(&sb, interp);
        w32(&mut sb, interp, v);
        eprintln!("interp vtable override {o:#x} -> {v:#x}");
    }
    let ivt = if interp != 0 { r32(&sb, interp) } else { 0 };
    writeln!(
        rep,
        "fixture {} {}x{} core={core:#x} [+0x7c]={interp:#x} interp-vtable={ivt:#x}",
        fixture.display(),
        w,
        h
    )
    .unwrap();
    writeln!(
        rep,
        "interp vtable slots +0x08..+0x34: {:x?}",
        (2..14).map(|k| r32(&sb, ivt + 4 * k)).collect::<Vec<_>>()
    )
    .unwrap();

    // harness-owned planes: luma stride 128 x 96 rows, chroma stride 64 x 48 rows
    const S: u32 = 128;
    const SC: u32 = 64;
    let ybuf = galloc(&mut sb, S * 96);
    let ubuf = galloc(&mut sb, SC * 48);
    let vbuf = galloc(&mut sb, SC * 48);
    let refy = galloc(&mut sb, S * 96);
    let refu = galloc(&mut sb, SC * 48);
    let refv = galloc(&mut sb, SC * 48);
    let old = [0x11b0u32, 0x11b4, 0x11bc, 0x11c0, 0x11c4].map(|o| r32(&sb, core + o));
    w32(&mut sb, core + 0x11b0, S);
    w32(&mut sb, core + 0x11b4, SC);
    w32(&mut sb, core + 0x11bc, ybuf);
    w32(&mut sb, core + 0x11c0, ubuf);
    w32(&mut sb, core + 0x11c4, vbuf);
    writeln!(
        rep,
        "core plane fields before override (+0x11b0,+0x11b4,+0x11bc,+0x11c0,+0x11c4): {:x?}",
        old
    )
    .unwrap();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);

    // ---------------- 1. intra 16x16 plane (mode 3) ----------------
    let (x0, y0) = (32u32, 32u32);
    let mut mism = [0u32; 4]; // model, old text, (G+16)>>5, (5G+48)>>7
    let mut wraps = 0u32;
    let mut shown = 0;
    for trial in 0..trials {
        // neighbours: mixture of smooth ramps (realistic) and raw noise (stress)
        let kind = trial % 3;
        let base = rng.range(0, 255);
        let gx = rng.range(-12, 12);
        let gy = rng.range(-12, 12);
        let mut t = [0i32; 17];
        let mut l = [0i32; 17];
        for k in 0..17 {
            let i = k as i32 - 1;
            let noise = if kind == 0 { 0 } else { rng.range(-3, 3) };
            t[k] = if kind == 2 {
                rng.range(0, 255)
            } else {
                (base + gx * i + noise).clamp(0, 255)
            };
            let noise = if kind == 0 { 0 } else { rng.range(-3, 3) };
            l[k] = if kind == 2 {
                rng.range(0, 255)
            } else {
                (base + gy * i + noise).clamp(0, 255)
            };
        }
        l[0] = t[0];
        // write neighbours
        for k in 0..17u32 {
            sb.mmu
                .write_initializer(ybuf + (y0 - 1) * S + x0 + k - 1, &[t[k as usize] as u8])
                .unwrap();
            sb.mmu
                .write_initializer(ybuf + (y0 + k - 1) * S + x0 - 1, &[l[k as usize] as u8])
                .unwrap();
        }
        thiscall(&mut sb, VA_I16, core, &[x0, y0, 3]).expect("i16 plane");
        let mut got = [[0u8; 16]; 16];
        for r in 0..16 {
            let row = read_bytes(&sb, ybuf + (y0 + r) * S + x0, 16);
            got[r as usize].copy_from_slice(&row);
        }
        let m = plane_model(&t, &l);
        if m != got {
            mism[0] += 1;
        }
        for v in 0..3 {
            if plane_alt(&t, &l, v) != got {
                mism[v as usize + 1] += 1;
            }
        }
        // did the model need the no-clamp wrap?
        {
            let top = |i: i32| t[(i + 1) as usize];
            let left = |i: i32| l[(i + 1) as usize];
            let (mut hh, mut vv) = (0, 0);
            for i in 1..=8 {
                hh += i * (top(7 + i) - top(7 - i));
                vv += i * (left(7 + i) - left(7 - i));
            }
            let b = tdiv(5 * tdiv(hh, 4), 16);
            let c = tdiv(5 * tdiv(vv, 4), 16);
            let a = 16 * (left(15) + top(15));
            let mut wr = false;
            for r in 0..16 {
                for col in 0..16 {
                    let q = tdiv(a - 7 * (b + c) + 16 + b * r + c * col, 32);
                    if !(0..=255).contains(&q) {
                        wr = true;
                    }
                }
            }
            if wr {
                wraps += 1;
            }
        }
        if shown < 3 && kind == 1 {
            shown += 1;
            writeln!(
                rep,
                "plane sample: top(-1..15)={:?} left(-1..15)={:?}",
                t, l
            )
            .unwrap();
            writeln!(rep, "  component row0={:?} row15={:?}", got[0], got[15]).unwrap();
            writeln!(rep, "  model     row0={:?} row15={:?}", m[0], m[15]).unwrap();
        }
    }
    writeln!(rep, "PLANE trials={trials}: mismatches model={} old-spec01(7tap,(5G+32)>>6)={} (G+16)>>5={} (5G+48)>>7={}; trials whose model value leaves 0..255 (wrap exercised)={wraps}",
        mism[0], mism[1], mism[2], mism[3]).unwrap();

    // ---------------- 2. chroma DC ----------------
    let mut cm = [0u32; 4];
    let mut sym_m = 0u32; // symmetric-average reading for all quadrants
    for trial in 0..trials {
        let case = trial % 4; // 0 none (x=0,y=0), 1 left only (y=0), 2 top only (x=0), 3 both
        let (cx, cy) = match case {
            0 => (0u32, 0u32),
            1 => (8, 0),
            2 => (0, 8),
            _ => (8, 8),
        };
        let mut t = [0i32; 8];
        let mut l = [0i32; 8];
        for k in 0..8 {
            t[k] = rng.range(0, 255);
            l[k] = rng.range(0, 255);
        }
        // plane base for this call = ubuf + 16*SC + 16 so that (x-1),(y-1) exist
        let pbase = ubuf + 16 * SC + 16;
        for k in 0..8u32 {
            if cy > 0 {
                sb.mmu
                    .write_initializer(pbase + (cy - 1) * SC + cx + k, &[t[k as usize] as u8])
                    .unwrap();
            }
            if cx > 0 {
                sb.mmu
                    .write_initializer(pbase + (cy + k) * SC + cx - 1, &[l[k as usize] as u8])
                    .unwrap();
            }
        }
        thiscall(&mut sb, VA_CDC, core, &[pbase, cx, cy]).expect("cdc");
        let mut got = [[0u8; 8]; 8];
        for r in 0..8 {
            got[r as usize].copy_from_slice(&read_bytes(&sb, pbase + (cy + r) * SC + cx, 8));
        }
        let q = cdc_model(
            if cy > 0 { Some(t) } else { None },
            if cx > 0 { Some(l) } else { None },
        );
        let mut ok = true;
        let mut sym_ok = true;
        for r in 0..8 {
            for c in 0..8 {
                if got[r][c] != q[r / 4][c / 4] {
                    ok = false;
                }
            }
        }
        if case == 3 {
            let s = |v: &[i32; 8], k: usize| v[4 * k..4 * k + 4].iter().sum::<i32>();
            for r in 0..2 {
                for c in 0..2 {
                    let sym = ((s(&t, c) + s(&l, r) + 4) >> 3) as u8;
                    if got[r * 4][c * 4] != sym {
                        sym_ok = false;
                    }
                }
            }
            if !sym_ok {
                sym_m += 1;
            }
        }
        if !ok {
            cm[case as usize] += 1;
        }
        if trial < 4 {
            writeln!(rep, "cdc case {case}: top={:?} left={:?} got quadrants TL={} TR={} BL={} BR={} model={:?}", t, l, got[0][0], got[0][4], got[4][0], got[4][4], q).unwrap();
        }
    }
    writeln!(rep, "CHROMA-DC trials={trials}: mismatches none={} left-only={} top-only={} both={}; symmetric-average reading mismatches (both)={sym_m}/{}",
        cm[0], cm[1], cm[2], cm[3], trials / 4).unwrap();

    // ---------------- 3. motion compensation ----------------
    // random reference planes
    let ry: Vec<u8> = (0..S * 96).map(|_| rng.next() as u8).collect();
    let ru: Vec<u8> = (0..SC * 48).map(|_| rng.next() as u8).collect();
    let rv: Vec<u8> = (0..SC * 48).map(|_| rng.next() as u8).collect();
    sb.mmu.write_initializer(refy, &ry).unwrap();
    sb.mmu.write_initializer(refu, &ru).unwrap();
    sb.mmu.write_initializer(refv, &rv).unwrap();
    for (name, va, den) in [
        ("full", VA_MC_FULL, 1i32),
        ("half", VA_MC_HALF, 2),
        ("third", VA_MC_THIRD, 3),
    ] {
        let mut mis_y = 0u32;
        let mut mis_c = 0u32;
        let mut mis_c_alt2 = 0u32;
        let mut mis_c_alt = 0u32; // alternative: chroma at true mv/2 rounded to the same grid (see report)
        let mut n = 0u32;
        let mut phase_hist = std::collections::BTreeMap::new();
        for trial in 0..trials {
            let (pw, ph) = [(16u32, 16u32), (16, 8), (8, 16), (8, 8), (4, 4)][(trial % 5) as usize];
            let x = 32 + (rng.next() % 4) * 4;
            let y = 32 + (rng.next() % 4) * 4;
            let lim = 12 * den;
            let mvx = rng.range(-lim, lim);
            let mvy = rng.range(-lim, lim);
            let dsty = ybuf + y * S + x;
            let dstu = ubuf + (y / 2) * SC + x / 2;
            let dstv = vbuf + (y / 2) * SC + x / 2;
            let mut args = vec![
                x, y, mvx as u32, mvy as u32, pw, ph, refy, refu, refv, dsty, dstu, dstv, S, SC,
            ];
            if den == 1 {
                args.push(0);
                args.push(0xffff_ffff);
            }
            thiscall(&mut sb, va, core, &args).unwrap_or_else(|e| panic!("mc {name}: {e}"));
            n += 1;
            let fl = |v: i32| v.div_euclid(den);
            let fr = |v: i32| v.rem_euclid(den);
            let (fx, fy, px, py) = (fl(mvx), fl(mvy), fr(mvx), fr(mvy));
            *phase_hist.entry((px, py)).or_insert(0u32) += 1;
            // luma
            let sy = |xx: i32, yy: i32| ry[(yy as u32 * S + xx as u32) as usize] as i32;
            let mut bad = false;
            for r in 0..ph as i32 {
                let row = read_bytes(&sb, dsty + r as u32 * S, pw);
                for c in 0..pw as i32 {
                    let m = kern(&sy, x as i32 + fx + c, y as i32 + fy + r, px, py, den);
                    if row[c as usize] != m {
                        bad = true;
                    }
                }
            }
            if bad {
                mis_y += 1;
            }
            // chroma: integer part trunc(F/2) (F = luma full-sample part), phase = luma phase
            let (cxw, chh) = (pw / 2, ph / 2);
            let cxi = (x / 2) as i32 + tdiv(fx, 2);
            let cyi = (y / 2) as i32 + tdiv(fy, 2);
            let su = |xx: i32, yy: i32| ru[(yy as u32 * SC + xx as u32) as usize] as i32;
            let sv = |xx: i32, yy: i32| rv[(yy as u32 * SC + xx as u32) as usize] as i32;
            let mut badc = false;
            let mut badalt = false;
            let mut badalt2 = false;
            for r in 0..chh as i32 {
                let urow = read_bytes(&sb, dstu + r as u32 * SC, cxw);
                let vrow = read_bytes(&sb, dstv + r as u32 * SC, cxw);
                for c in 0..cxw as i32 {
                    if urow[c as usize] != kern(&su, cxi + c, cyi + r, px, py, den)
                        || vrow[c as usize] != kern(&sv, cxi + c, cyi + r, px, py, den)
                    {
                        badc = true;
                    }
                    // alternative reading: floor(mv/2) in the same unit (the "natural" chroma vector)
                    let (ax, ay) = (mvx.div_euclid(2), mvy.div_euclid(2));
                    let (afx, afy, apx, apy) = (fl(ax), fl(ay), fr(ax), fr(ay));
                    if urow[c as usize]
                        != kern(
                            &su,
                            (x / 2) as i32 + afx + c,
                            (y / 2) as i32 + afy + r,
                            apx,
                            apy,
                            den,
                        )
                    {
                        badalt = true;
                    }
                    // second alternative (full-pel only): chroma vector = mv/2 chroma samples,
                    // odd component -> bilinear half-sample (floor for the integer part)
                    if den == 1 {
                        let (bx, by) = (mvx.div_euclid(2), mvy.div_euclid(2));
                        if urow[c as usize]
                            != kern(
                                &su,
                                (x / 2) as i32 + bx + c,
                                (y / 2) as i32 + by + r,
                                mvx.rem_euclid(2),
                                mvy.rem_euclid(2),
                                2,
                            )
                        {
                            badalt2 = true;
                        }
                    }
                }
            }
            if badalt2 {
                mis_c_alt2 += 1;
            }
            if badc {
                mis_c += 1;
                if mis_c <= 3 {
                    writeln!(
                        rep,
                        "  {name} chroma mismatch: x={x} y={y} mv=({mvx},{mvy}) {pw}x{ph}"
                    )
                    .unwrap();
                }
            }
            if badalt {
                mis_c_alt += 1;
            }
        }
        writeln!(rep, "MC-{name} calls={n}: luma mismatches={mis_y}; chroma (int=trunc(F/2), phase=luma phase) mismatches={mis_c}; alternative chroma (floor(mv/2) same unit) mismatches={mis_c_alt}; full-pel alternative (mv/2 with bilinear half-sample on odd) mismatches={mis_c_alt2}; phase histogram={:?}", phase_hist).unwrap();
    }
    // restore fields
    for (i, o) in [0x11b0u32, 0x11b4, 0x11bc, 0x11c0, 0x11c4]
        .iter()
        .enumerate()
    {
        w32(&mut sb, core + o, old[i]);
    }
    drop(rep);
    eprintln!(
        "{}",
        std::fs::read_to_string(out.join("direct.txt")).unwrap()
    );
}

#[test]
#[ignore = "needs locally staged vendor codec binaries + fixtures (OxideAV docs harness); run with --ignored"]
fn svq3_r10_fixture() {
    let fixture = match env("SVQ3_FIXTURE") {
        Some(f) => PathBuf::from(f),
        None => {
            eprintln!("SVQ3_FIXTURE not set; skipping");
            return;
        }
    };
    let out = PathBuf::from(env("SVQ3_OUT").unwrap_or_else(|| "/tmp/svq3-r10".into()));
    std::fs::create_dir_all(&out).unwrap();
    let samples = std::fs::read(fixture.join("samples.bin")).expect("samples.bin");
    let index = std::fs::read_to_string(fixture.join("samples-index.csv")).expect("index");
    let (mut sb, core, pool, w, h) = setup(&fixture);
    let st = r32(&sb, pool + 0x14) as i32;
    let cst = r32(&sb, pool + 0x18) as i32;
    eprintln!("{w}x{h} stride={st} cstride={cst}");
    // probe list (reg index into [eax,ecx,edx,ebx,esp,ebp,esi,edi])
    let mut probes: Vec<(u8, i32, u8)> = Vec::new();
    for k in -1..16 {
        probes.push((6, -st + k, 1)); // luma top row incl. corner, rel. esi
    }
    for r in 0..16 {
        probes.push((6, r * st - 1, 1)); // luma left column, rel. esi
    }
    for r in 0..16 {
        for c in 0..16 {
            probes.push((5, -16 * st + r * st + c, 1)); // luma 16x16 output, rel. ebp at return
        }
    }
    for k in 0..8 {
        probes.push((6, -cst + k, 1)); // chroma top row, rel. esi
    }
    for r in 0..8 {
        probes.push((6, r * cst - 1, 1)); // chroma left column, rel. esi
    }
    for r in 0..8 {
        for c in 0..8 {
            probes.push((6, -7 * cst + r * cst + c, 1)); // chroma 8x8 output, rel. esi at exit
        }
    }
    for k in 1..7 {
        probes.push((4, 4 * k, 4)); // MC stack args x,y,mvx,mvy,w,h (rel. esp at entry)
    }
    sb.cpu.snapshot_probes = probes.clone();
    let sites: &[(u32, &str)] = &[
        (0x67d255e3, "i16.mode"),
        (0x67d25768, "plane.entry"),
        (0x67d25a03, "plane.ret"),
        (0x67d25a5b, "cdc.avail"),
        (0x67d25b53, "cdc.exit_none"),
        (0x67d25dd9, "cdc.exit_left"),
        (0x67d25ff7, "cdc.exit_top_or_both"),
        (0x67d22610, "mc.full"),
        (0x67d22350, "mc.half"),
        (0x67d21e10, "mc.third"),
    ];
    let labels: std::collections::BTreeMap<u32, &str> = sites.iter().copied().collect();
    for (va, _) in sites {
        sb.cpu.add_register_watchpoint(*va);
    }
    let opts = galloc(&mut sb, 0x40);
    w32(&mut sb, opts + 0x14, 1);
    let vt = r32(&sb, core);
    let mut summary = std::fs::File::create(out.join("summary.txt")).unwrap();
    writeln!(
        summary,
        "{w}x{h} luma stride {st} chroma stride {cst} probes {}",
        probes.len()
    )
    .unwrap();
    for line in index.lines().skip(1) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 4 {
            continue;
        }
        let frame: usize = cols[0].parse().unwrap();
        let off: usize = cols[1].parse().unwrap();
        let size: usize = cols[2].parse().unwrap();
        let buf = galloc(&mut sb, (size + 64) as u32);
        sb.mmu
            .write_initializer(buf, &samples[off..off + size])
            .unwrap();
        let f = r32(&sb, vt + 0x34);
        let res = thiscall(&mut sb, f, core, &[buf, size as u32, pool, opts]);
        let regs = std::mem::take(&mut sb.cpu.register_snapshots);
        let _ = sb.cpu.take_memory_snapshots();
        let (pv, _) = sb.cpu.take_snapshot_probes();
        let mut fo = std::io::BufWriter::new(
            std::fs::File::create(out.join(format!("frame{frame}.pred.jsonl"))).unwrap(),
        );
        for (i, (eip, r)) in regs.iter().enumerate() {
            let lab = labels.get(eip).copied().unwrap_or("?");
            // keep only the probe range relevant to the site
            let (lo, hi) = match lab {
                "plane.entry" => (0, 33),
                "plane.ret" => (33, 289),
                "cdc.avail" => (289, 305),
                l if l.starts_with("cdc.exit") => (305, 369),
                l if l.starts_with("mc.") => (369, 375),
                _ => (0, 0),
            };
            let vals: Vec<String> = pv
                .get(i)
                .map(|v| {
                    v[lo..hi]
                        .iter()
                        .map(|x| x.map_or("null".to_string(), |y| y.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            writeln!(
                fo,
                "{{\"i\":{i},\"eip\":\"{eip:#010x}\",\"site\":\"{lab}\",\"regs\":[{},{},{},{},{},{},{},{}],\"probe\":[{}]}}",
                r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], vals.join(",")
            )
            .unwrap();
        }
        let line = format!(
            "frame {frame}: rc={res:?} slice_type={} snaps={}",
            r32(&sb, core + 0x1c),
            regs.len()
        );
        eprintln!("{line}");
        writeln!(summary, "{line}").unwrap();
        if res.is_err() {
            break;
        }
    }
}

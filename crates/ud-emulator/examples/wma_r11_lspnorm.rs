//! wma_r11_lspnorm — audio/wma round 11 (Validator) sandbox harness.
//!
//! SYNTHETIC-INPUT check of the LSP-path noise-band normaliser `.text 0x5200`
//! (the routine called at 0x93d2 after the LSP parser 0x4e30 when ctx+0x7c
//! == 1). No committed vendor stream reaches it (the only LSP-path stream has
//! noise substitution disabled), so this harness opens WMADMOD.DLL's flat
//! decoder for an LSP-path, noise-enabled configuration (v2, 8000 Hz mono,
//! 625 B/s, flags2 0x0026) and then calls 0x5200(state) directly T times on
//! crafted channel state: a pseudo-random positive envelope in [chan+0x6c],
//! pseudo-random band flags in [chan+8], the real open-time band partition
//! at [ctx+0x39c], the real cutoff bin / start band for the frame-length
//! block. It dumps inputs and the ratios the routine writes at [chan+0xc]
//! (and the count it writes at [chan+8][0]) to lspnorm.csv.
//!
//! Env: WMA_DLL, WMA_OUT (dir), WMA_TRIALS (default 2000), WMA_CW.
// One-off reverse-engineering harness from the OxideAV docs rounds; not
// held to the workspace pedantic lint set.
#![allow(clippy::all, clippy::pedantic)]
#![allow(clippy::all, clippy::pedantic)]

use std::io::Write;
use ud_emulator::emulator::regs::Reg32;
use ud_emulator::win32::call_guest;
use ud_emulator::{DLL_PROCESS_ATTACH, Sandbox};

const IB: u32 = 0x5370_0000;

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

fn main() {
    let dll = env("WMA_DLL").unwrap_or_else(|| {
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/WMADMOD.DLL".into()
    });
    let out = std::path::PathBuf::from(env("WMA_OUT").expect("WMA_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let trials: u32 = env("WMA_TRIALS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let cw0: u16 =
        u16::from_str_radix(&env("WMA_CW").unwrap_or_else(|| "027f".into()), 16).unwrap();
    let bytes = std::fs::read(&dll).unwrap();
    let mut sb = Sandbox::new();
    sb.cpu.set_instr_limit(u64::MAX / 2);
    sb.host.instruction_budget = Some(u64::MAX / 2);
    sb.cpu.fpu_cw = cw0;
    let (img, _) = sb.load_fail_soft("WMADMOD.DLL", &bytes).unwrap();
    assert_eq!(img.image_base, IB);
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).unwrap();
    let state = call(&mut sb, IB + 0x78b0, &[]).unwrap();
    let rc = call(
        &mut sb,
        IB + 0x79b0,
        &[state, 2, 9216, 8000, 1, 625, 320, 0x0026, 0, 0, 0],
    )
    .unwrap();
    assert!((rc as i32) >= 0);
    let ctx = r32(&sb, state);
    let chan = r32(&sb, ctx + 0x3e0);
    let mut meta = std::fs::File::create(out.join("run.meta")).unwrap();
    let flen = r32(&sb, ctx + 0x364);
    writeln!(meta, "open=v2,8000Hz,mono,625B/s,flags2=0x0026 rc={rc}\nframe_length={flen}\nnoise_enable={}\ncutoff_hz={}\nctx+0x39c={:#x}\nctx+0x400={}\nctx+0x404={}\nctx+0x370={}\nctx+0x40c(ptr)={:#x}\nchan+0x6c={:#x}\nchan+0x8={:#x}\nchan+0xc={:#x}\nchan+0x24={}",
        r32(&sb, ctx + 0x7c), f32::from_bits(r32(&sb, ctx + 0x3fc)), r32(&sb, ctx + 0x39c), r32(&sb, ctx + 0x400), r32(&sb, ctx + 0x404),
        r32(&sb, ctx + 0x370), r32(&sb, ctx + 0x40c), r32(&sb, chan + 0x6c), r32(&sb, chan + 8), r32(&sb, chan + 0xc), r32(&sb, chan + 0x24)).unwrap();
    assert_eq!(
        r32(&sb, ctx + 0x7c),
        1,
        "noise must be enabled for this configuration"
    );
    // The per-block fields (ctx+0x400 start band, ctx+0x404 cutoff bin,
    // ctx+0x39c edge pointer) are the frame-length block's: start band from
    // the open-time per-level array *ctx+0x40c, entry 0, cutoff bin = min(trunc(2N*fc/sr+0.5),N).
    let edges = r32(&sb, ctx + 0x39c);
    let cutoff_hz = f32::from_bits(r32(&sb, ctx + 0x3fc)) as f64;
    let cbin = ((2.0 * flen as f64 * cutoff_hz / 8000.0 + 0.5) as u32).min(flen);
    sb.mmu.store32(ctx + 0x404, cbin).unwrap();
    let lvl0 = r32(&sb, r32(&sb, ctx + 0x40c)); // ctx+0x40c -> per-level start-band array
    sb.mmu.store32(ctx + 0x400, lvl0).unwrap();
    let flags = if r32(&sb, chan + 8) != 0 {
        r32(&sb, chan + 8)
    } else {
        let a = galloc(&mut sb, 64);
        sb.mmu.store32(chan + 8, a).unwrap();
        a
    };
    let ratios = if r32(&sb, chan + 0xc) != 0 {
        r32(&sb, chan + 0xc)
    } else {
        let a = galloc(&mut sb, 256);
        sb.mmu.store32(chan + 0xc, a).unwrap();
        a
    };
    let envb = r32(&sb, chan + 0x6c);
    sb.mmu.store32(chan + 0x24, 1).unwrap();
    let nb: Vec<u32> = (0..40).map(|k| r32(&sb, edges + 4 * k)).collect();
    writeln!(
        meta,
        "edges={:?}\ncutoff_bin={cbin}\nstart_band={}\ncoef_end={}",
        nb,
        r32(&sb, ctx + 0x400),
        r32(&sb, ctx + 0x370)
    )
    .unwrap();
    let mut f = std::io::BufWriter::new(std::fs::File::create(out.join("lspnorm.csv")).unwrap());
    let mut s: u64 = 0x2545F4914F6CDD1D;
    let mut rnd = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for t in 0..trials {
        // envelope: positive f32 spanning ~6 decades (LSP envelopes are |A|^-1/2)
        let mut ev = Vec::with_capacity(flen as usize);
        for i in 0..flen {
            let u = (rnd() >> 11) as f64 / (1u64 << 53) as f64;
            let v = (10f64.powf(u * 6.0 - 3.0)) as f32;
            ev.push(v.to_bits());
            sb.mmu.store32(envb + 4 * i, v.to_bits()).unwrap();
        }
        // odd trials: a crafted cutoff bin inside a band (start band = the
        // band containing it, as .text 0x5b92-0x5be2 computes it); even
        // trials: the real open-time values.
        let (cb, sbnd) = if t % 2 == 1 {
            let c = 60 + (rnd() % 400) as u32;
            let mut k = 0usize;
            while k + 1 < nb.len() && nb[k + 1] <= c && nb[k + 1] != 0 {
                k += 1;
            }
            (c, k as u32)
        } else {
            (cbin, lvl0)
        };
        sb.mmu.store32(ctx + 0x404, cb).unwrap();
        sb.mmu.store32(ctx + 0x400, sbnd).unwrap();
        let mut fl = vec![0u8; 40];
        for b in 0..40 {
            fl[b] = (rnd() & 1) as u8;
            if t % 7 == 0 {
                fl[b] = 1;
            }
        }
        for b in 0..40 {
            sb.mmu.store8(flags + b as u32, fl[b]).unwrap();
        }
        for k in 0..40 {
            sb.mmu.store32(ratios + 4 * k, 0xdeadbeef).unwrap();
        }
        call(&mut sb, IB + 0x5200, &[state]).expect("0x5200");
        let g = sb.mmu.load8(flags).unwrap();
        let rs: Vec<String> = (0..40)
            .map(|k| format!("{:08x}", r32(&sb, ratios + 4 * k)))
            .collect();
        let fls: String = fl.iter().map(|x| x.to_string()).collect();
        let evs: String = ev.iter().map(|x| format!("{x:08x}")).collect();
        writeln!(f, "{t},{cb},{sbnd},{fls},{g},{},{evs}", rs.join(":")).unwrap();
    }
    writeln!(meta, "trials={trials}\ncw_after={:#06x}", sb.cpu.fpu_cw).unwrap();
    eprintln!("done: {trials} trials; meta in {:?}", out);
}

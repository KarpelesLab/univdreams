//! wma_r11_open — audio/wma round 11 (Validator) sandbox harness.
//!
//! Opens `WMADMOD.DLL`'s flat decoder (0x537078b0 alloc_state, 0x537079b0
//! open — see audio/wma provenance/03, provenance/10) once per configuration
//! row of WMA_CONFIGS (CSV: version,spb,sample_rate,channels,avg_bytes,
//! block_align,flags2) and records the stream-open state the round-11 items
//! need: noise enable ctx+0x7c, cutoff Hz ctx+0x3fc (f32), byte_offset_bits
//! ctx+0x54, bps ctx+0x80, rate ctx+0x84, class ctx+0x384, frame_length
//! ctx+0x364, ctx+0x408. No stream is decoded.
//!
//! Env: WMA_DLL, WMA_CONFIGS, WMA_OUT (csv path), WMA_CW (default 027f).
#![allow(clippy::all, clippy::pedantic)]

use std::io::Write;
use ud_emulator::emulator::regs::Reg32;
use ud_emulator::win32::call_guest;
use ud_emulator::{Sandbox, DLL_PROCESS_ATTACH};

const IB: u32 = 0x5370_0000;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}
fn call(sb: &mut Sandbox, va: u32, args: &[u32]) -> Result<u32, String> {
    let esp = sb.cpu.regs.get32(Reg32::Esp);
    let r = call_guest(&mut sb.cpu, &mut sb.mmu, &mut sb.registry, &mut sb.host, va, args)
        .map_err(|e| format!("{e:?} (eip={:#010x})", sb.cpu.regs.eip));
    sb.cpu.regs.set32(Reg32::Esp, esp);
    r
}

fn main() {
    let dll = env("WMA_DLL").unwrap_or_else(|| {
        "/Users/magicaltux/projects/oxideav-workspace/docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/WMADMOD.DLL".into()
    });
    let cfgs = std::fs::read_to_string(env("WMA_CONFIGS").expect("WMA_CONFIGS")).unwrap();
    let outp = env("WMA_OUT").expect("WMA_OUT");
    let cw0: u16 = u16::from_str_radix(&env("WMA_CW").unwrap_or_else(|| "027f".into()), 16).unwrap();
    let bytes = std::fs::read(&dll).expect("read dll");
    // A fresh sandbox every 32 opens: each open allocates from the host
    // arena and nothing is freed.
    let fresh = || {
        let mut sb = Sandbox::new();
        sb.cpu.set_instr_limit(u64::MAX / 2);
        sb.host.instruction_budget = Some(u64::MAX / 2);
        sb.cpu.fpu_cw = cw0;
        let (img, _unres) = sb.load_fail_soft("WMADMOD.DLL", &bytes).expect("load");
        assert_eq!(img.image_base, IB);
        sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
        sb
    };
    let mut sb = fresh();
    let mut out = std::io::BufWriter::new(std::fs::File::create(&outp).unwrap());
    writeln!(out, "version,spb,sample_rate,channels,avg_bytes,block_align,flags2,rc,noise_enable,cutoff_bits,cutoff_hz,byte_offset_bits,bps_bits,rate_bits,class,frame_length,ctx408,fpu_cw").unwrap();
    let mut n = 0;
    for line in cfgs.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("version") { continue; }
        let v: Vec<u32> = line.split(',').map(|s| {
            let s = s.trim();
            if let Some(h) = s.strip_prefix("0x") { u32::from_str_radix(h, 16).unwrap() } else { s.parse().unwrap() }
        }).collect();
        let (ver, spb, sr, ch, avg, ba, f2) = (v[0], v[1], v[2], v[3], v[4], v[5], v[6]);
        if n > 0 && n % 32 == 0 {
            assert_eq!(sb.cpu.fpu_cw, cw0, "module wrote the x87 control word");
            sb = fresh();
        }
        let state = call(&mut sb, IB + 0x78b0, &[]).expect("alloc_state");
        let rc = call(&mut sb, IB + 0x79b0, &[state, ver, spb, sr, ch, avg, ba, f2, 0, 0, 0]);
        let rc = match rc { Ok(x) => x as i32 as i64, Err(e) => { eprintln!("{line}: trap {e}"); -999 } };
        let ctx = sb.mmu.load32(state).unwrap_or(0);
        let g = |sb: &Sandbox, o: u32| if ctx != 0 { sb.mmu.load32(ctx + o).unwrap_or(0) } else { 0 };
        let cut = g(&sb, 0x3fc);
        writeln!(out, "{ver},{spb},{sr},{ch},{avg},{ba},{f2:#06x},{rc},{},{cut:#010x},{:.9},{},{:#010x},{:#010x},{},{},{},{:#06x}",
            g(&sb, 0x7c), f32::from_bits(cut), g(&sb, 0x54), g(&sb, 0x80), g(&sb, 0x84), g(&sb, 0x384), g(&sb, 0x364), g(&sb, 0x408), sb.cpu.fpu_cw).unwrap();
        n += 1;
    }
    eprintln!("{n} configurations opened; fpu_cw at end = {:#06x}", sb.cpu.fpu_cw);
}

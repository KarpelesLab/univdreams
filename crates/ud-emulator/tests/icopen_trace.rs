//! Trace helper for diagnosing codecs whose `ICOpen` handler
//! returns 0 (or traps on an undefined opcode).
//!
//! Loads a codec, enables stub-call tracing, drives `ICOpen`,
//! prints every Win32 call the codec made during `DllMain` and
//! `DRV_OPEN`. Marked `#[ignore]` — run on demand:
//!
//! ```text
//! cargo test --release -p ud-emulator icopen_trace -- --ignored --nocapture
//! ```
//!
//! ## Current findings (as of 2026-05-18)
//!
//! **Lagarith (`lagarith-i386.dll`, fourcc `LAGS`)** — `DRV_OPEN`
//! ends in `ExitProcess(0xff)` after a fault-handler-looking call
//! chain (`GetModuleFileNameW` → `EncodePointer(0)` →
//! `LoadLibraryW(L"USER32.DLL")` → `GetModuleHandleW(L"mscoree.dll")`
//! → `ExitProcess(0xff)`). The shape looks like MSVC's
//! `__report_gsfailure`, but the forensic harness
//! `tests/lagarith_gs_forensics.rs` falsifies that hypothesis:
//! `__security_check_cookie` fires twice during `DRV_OPEN`,
//! both times the cookie matches the global at `0x10033298`,
//! and `__report_gsfailure` (`0x10007c00`) is never entered.
//! The ExitProcess path is a *different* fatal-exit helper baked
//! into Lagarith's CRT — closing this needs static disassembly of
//! the function calling `ExitProcess` at RVA `0x4998` to find its
//! triggering condition.
//!
//! **MagicYUV (`magicyuv-i386.dll`, fourcc `M8RG`)** — past the
//! initial SSE1 traps now that `0F 12 / 13 / 16 / 17`
//! (MOV{L,H}PS load/store, MOVHLPS / MOVLHPS) are implemented
//! in `super::isa_sse`. The next blocker is the single-byte
//! opcode `0xC5` — either MagicYUV is using `LDS` (unlikely in
//! 32-bit modern code) or, more probably, the **AVX 2-byte VEX
//! prefix**. MagicYUV is a 2015+ codec; it almost certainly
//! requires AVX for its actual decode path. Closing this needs
//! VEX decoding + 256-bit YMM registers + a fresh AVX opcode
//! table — substantially larger than the SSE1 surface.
//!
//! The manifest fourcc was previously `MYUV` (wrong — not in
//! MagicYUV's supported set); changed to `M8RG`, which the
//! codec accepts past its fourcc-lookup and into its AVX
//! decode body.

mod common;

use std::path::PathBuf;
use ud_emulator::{Sandbox, DLL_PROCESS_ATTACH};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join("Cargo.toml").is_file() && p.join("crates").is_dir())
        .map(std::path::Path::to_path_buf)
        .unwrap()
}

fn fourcc(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

/// VfW `ICMODE_DECOMPRESS` from `vfw.h`.
const ICMODE_DECOMPRESS: u32 = 1;

fn trace_codec(name: &str, base_url: &str, fcc: &str) {
    let bytes = match common::fetch_or_load(base_url, name) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skip {name}: {e}");
            return;
        }
    };

    let mut sb = Sandbox::new();
    sb.host.trace_stubs = true;
    sb.host.instruction_budget = Some(50_000_000);
    sb.cpu.trace_ring_cap = 32;

    let img = sb.load(name, &bytes).expect("load");
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");

    println!(
        "=== {name} DllMain ({} calls) ===",
        sb.host.stub_calls.len()
    );
    for (i, c) in sb.host.stub_calls.iter().enumerate() {
        let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
        println!(
            "  {i:3}: {}!{}({})  -> {:#x}  @ {:#010x}",
            c.dll,
            c.name,
            args.join(", "),
            c.ret,
            c.call_site_eip,
        );
    }
    let dllmain_calls = sb.host.stub_calls.len();
    sb.host.stub_calls.clear();

    let fcc_type = fourcc("VIDC");
    let fcc_handler = fourcc(fcc);
    let result = sb.ic_open(fcc_type, fcc_handler, ICMODE_DECOMPRESS);

    println!(
        "ICOpen(VIDC, {fcc}, DECOMPRESS) -> {:?}",
        result.as_ref().map(|h| format!("HIC {h}")),
    );
    if result.is_err() {
        println!("Last 32 instruction EIPs before trap:");
        for eip in &sb.cpu.trace_ring {
            println!("  {eip:#010x}");
        }
    }
    println!("DRV_OPEN-phase calls (DllMain pre-cleared, was {dllmain_calls}):");
    for (i, c) in sb.host.stub_calls.iter().enumerate() {
        let args: Vec<String> = c.args.iter().map(|a| format!("{a:#x}")).collect();
        println!(
            "  {i:3}: {}!{}({})  -> {:#x}  @ {:#010x}",
            c.dll,
            c.name,
            args.join(", "),
            c.ret,
            c.call_site_eip,
        );
    }
    println!();
}

#[test]
#[ignore = "diagnostic helper; downloads codecs; run on demand"]
fn lagarith_icopen_trace() {
    // Make sure cache dir is set.
    let _ = workspace_root();
    trace_codec(
        "lagarith-i386.dll",
        "https://samples.oxideav.org/codecs/windows/lagarith",
        "LAGS",
    );
}

#[test]
#[ignore = "diagnostic helper; downloads codecs; run on demand"]
fn magicyuv_icopen_trace() {
    let _ = workspace_root();
    trace_codec(
        "magicyuv-i386.dll",
        "https://samples.oxideav.org/codecs/windows/magicyuv",
        "M8RG",
    );
}

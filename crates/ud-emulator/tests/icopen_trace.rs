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
//! ends in `__report_gsfailure`: the MSVC /GS stack cookie was
//! detected as corrupted inside one of the codec's own functions
//! during the DRV_OPEN handler. The fault-chain calls are
//! `GetModuleFileNameW` → `EncodePointer(0)` →
//! `LoadLibraryW(L"USER32.DLL")` → `GetModuleHandleW(L"mscoree.dll")`
//! → `ExitProcess(0xff)`. `__security_init_cookie` ran cleanly in
//! `DllMain` (the five entropy-source calls are present in order
//! in the DllMain trace), so the codec installed a fresh cookie;
//! something inside one of its DRV_OPEN-invoked functions
//! tripped the epilogue check. Reproducing this needs a
//! watchpoint on `__security_check_cookie` (à la round-69 forensics)
//! to identify the offending callee.
//!
//! **MagicYUV (`magicyuv-i386.dll`, fourcc `MYUV`)** — `DRV_OPEN`
//! traps on `UndefinedOpcode { opcode: 0xF12 }`, i.e. `0F 12`
//! (`MOVLPS` / `MOVHLPS`) — an SSE1 instruction the emulator's
//! `dispatch_0f` doesn't yet decode. The codec uses SIMD heavily,
//! so closing this likely needs a substantial SSE/SSE2 surface
//! expansion rather than a single opcode add.

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
        "MYUV",
    );
}

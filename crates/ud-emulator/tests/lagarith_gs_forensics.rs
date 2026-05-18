//! Forensic harness probing Lagarith's `DRV_OPEN`-time exit path.
//!
//! Background: `lagarith-i386.dll`'s `DRV_OPEN` handler ends in
//! `ExitProcess(0xff)` after a call chain that looks like MSVC's
//! `__report_gsfailure` (GetModuleFileNameW → EncodePointer →
//! LoadLibraryW → GetModuleHandleW → ExitProcess). The
//! `icopen_trace` harness surfaced that chain; this harness
//! checks whether the path is actually /GS-driven.
//!
//! Strategy: arm three register watchpoints — `__security_check_cookie`
//! at `0x1000_57f2`, `__report_gsfailure` entry at `0x1000_7c00`,
//! and the `ExitProcess` call site at `0x1000_4992` — then drive
//! `ICOpen` and report which fired plus, for each
//! `__security_check_cookie` hit, whether the caller's `ECX` cookie
//! matched the global `__security_cookie`.
//!
//! ## Current finding (2026-05-18)
//!
//! `__report_gsfailure` (`0x1000_7c00`) is **never** entered.
//! `__security_check_cookie` fires twice; both times `ECX` matches
//! the global `__security_cookie = 0xdadc_1e72` exactly. The
//! `ExitProcess` call site does reach. **Conclusion: the original
//! /GS-violation hypothesis is wrong**; Lagarith's `ExitProcess(0xff)`
//! goes through a different fatal-exit helper baked into the codec's
//! CRT. Closing this requires static disassembly of the function
//! at `RVA 0x4998` (and its caller chain) to find the triggering
//! condition. The only direct entry to `__report_gsfailure` in the
//! image is the `jmp` at `0x1000_57fc` from `__security_check_cookie`'s
//! mismatch branch, and no in-image references to `0x1000_7c00` exist
//! anywhere else.
//!
//! Marked `#[ignore]` — diagnostic harness, run on demand:
//!
//! ```text
//! cargo test --release -p ud-emulator lagarith_gs_forensics -- --ignored --nocapture
//! ```

mod common;

use ud_emulator::{Sandbox, DLL_PROCESS_ATTACH};

/// VA of `__security_check_cookie` inside `lagarith-i386.dll`.
/// Identified by signature-scanning the binary for the canonical
/// `3B 0D <global>` (`cmp ecx, [__security_cookie]`) followed by
/// `75 02 F3 C3 E9 ...` (`jne +2; rep ret; jmp __report_gsfailure`).
/// At this instant `ECX` holds the stack cookie the caller decoded
/// from its frame and `[ESP]` is the return address into the
/// caller — i.e. the function whose epilogue detected the
/// corruption.
const WATCHPOINT_EIP: u32 = 0x1000_57f2;

#[test]
#[ignore = "diagnostic; downloads lagarith from samples.oxideav.org"]
#[allow(clippy::too_many_lines)]
fn lagarith_gs_failure_call_chain() {
    let bytes = match common::fetch_or_load(
        "https://samples.oxideav.org/codecs/windows/lagarith",
        "lagarith-i386.dll",
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skip: {e}");
            return;
        }
    };

    let mut sb = Sandbox::new();
    sb.host.instruction_budget = Some(50_000_000);

    let img = sb.load("lagarith-i386.dll", &bytes).expect("load");
    sb.call_dll_main(&img, DLL_PROCESS_ATTACH).expect("DllMain");
    sb.install_codec(&img).expect("install_codec");

    sb.cpu.register_snapshots_cap = 256;
    sb.cpu.add_register_watchpoint(WATCHPOINT_EIP);
    // Also watch the entry of `__report_gsfailure` itself (0x1000_7c00)
    // and the call site of ExitProcess (0x1000_4992 — the `ff 15 ...`
    // instruction whose return address is 0x1000_4998). Together these
    // tell us whether the trace's ExitProcess(0xff) was reached via
    // the /GS fault path or some other route.
    sb.cpu.add_register_watchpoint(0x1000_7c00);
    sb.cpu.add_register_watchpoint(0x1000_4992);

    // Drive `ICOpen(VIDC, LAGS, ICMODE_DECOMPRESS)`. The codec
    // bails (HIC 0) — that's expected; we're after the snapshot.
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler = u32::from_le_bytes(*b"LAGS");
    let _ = sb.ic_open(fcc_type, fcc_handler, 1);

    let snaps = sb.cpu.clear_register_watchpoints();
    assert!(
        !snaps.is_empty(),
        "watchpoint at {WATCHPOINT_EIP:#010x} should have fired"
    );

    // The global `__security_cookie` lives at 0x1003_3298 (located
    // by signature-scanning lagarith for the `3B 0D <global>`
    // displacement). Read it once — it's set in DllMain and stays
    // fixed for the rest of the run.
    let global_cookie = sb.mmu.load32(0x1003_3298).unwrap_or(0);
    println!(
        "__security_cookie (global @ 0x1003_3298) = {global_cookie:#010x}\n\
         Captured {} __security_check_cookie hits:\n",
        snaps.len()
    );

    let label_for = |eip: u32| match eip {
        0x1000_57f2 => "__security_check_cookie",
        0x1000_7c00 => "__report_gsfailure ENTRY",
        0x1000_4992 => "ExitProcess call site",
        _ => "?",
    };
    let mut cookie_mismatch_idx = None;
    for (i, (hit_eip, regs)) in snaps.iter().enumerate() {
        let [_eax, ecx, _edx, _ebx, esp, _ebp, _esi, _edi] = *regs;
        let ret_addr = sb.mmu.load32(esp).unwrap_or(0);
        let lbl = label_for(*hit_eip);
        let extra = if *hit_eip == 0x1000_57f2 {
            if ecx == global_cookie {
                "cookie MATCH"
            } else {
                cookie_mismatch_idx.get_or_insert(i);
                "cookie MISMATCH ***"
            }
        } else {
            ""
        };
        println!(
            "  [{i:2}] EIP={hit_eip:#010x} ({lbl})  ECX={ecx:#010x}  ESP={esp:#010x}  [ESP]={ret_addr:#010x}  {extra}",
        );
    }

    println!();
    println!("Verdict:");
    let gs_entered = snaps.iter().any(|(eip, _)| *eip == 0x1000_7c00);
    let exit_called = snaps.iter().any(|(eip, _)| *eip == 0x1000_4992);
    println!("  __report_gsfailure entered? {gs_entered}");
    println!("  ExitProcess call site reached? {exit_called}");
    println!(
        "  __security_check_cookie cookie mismatch? {}",
        cookie_mismatch_idx.is_some(),
    );

    let Some(idx) = cookie_mismatch_idx else {
        println!(
            "\n=> Lagarith's ExitProcess(0xff) does NOT go through /GS \
             (__report_gsfailure). The path is a different fatal-exit \
             helper inside the codec; the cookie diagnosis was wrong."
        );
        return;
    };

    let (hit_eip, regs) = snaps[idx];
    let [eax, ecx, edx, ebx, esp, ebp, esi, edi] = regs;
    println!("\n=== Failing call (snap #{idx}) ===");
    println!("Watchpoint fired at EIP={hit_eip:#010x} (= __security_check_cookie)");
    println!("  EAX={eax:#010x}  ECX={ecx:#010x}  EDX={edx:#010x}  EBX={ebx:#010x}");
    println!("  ESP={esp:#010x}  EBP={ebp:#010x}  ESI={esi:#010x}  EDI={edi:#010x}");

    let ret_addr = sb.mmu.load32(esp).expect("read [ESP]");
    println!(
        "Caller's return address (= site of the call to __security_check_cookie):\n  \
         {ret_addr:#010x}  (call instruction at {:#010x})",
        ret_addr.wrapping_sub(5),
    );

    // Walk the saved-EBP chain and the raw stack to surface every
    // saved return address. A "return address" looks like a u32
    // inside Lagarith's .text section, i.e. roughly the range
    // `[ImageBase, ImageBase + 0x40000)` for a ~256 KiB codec.
    let img_lo = img.image_base;
    let img_hi = img.image_base.wrapping_add(0x10_0000);
    let is_text_ptr = |v: u32| v >= img_lo && v < img_hi;

    println!("\nSaved-EBP chain (8 frames max):");
    let mut frame_ebp = ebp;
    for depth in 0..8 {
        let Ok(saved_ebp) = sb.mmu.load32(frame_ebp) else {
            println!("  [{depth}] frame EBP={frame_ebp:#010x}  <unreadable>");
            break;
        };
        let ret_addr = sb.mmu.load32(frame_ebp.wrapping_add(4)).unwrap_or(0);
        println!(
            "  [{depth}] EBP={frame_ebp:#010x}  saved_EBP={saved_ebp:#010x}  ret_addr={ret_addr:#010x}{}",
            if is_text_ptr(ret_addr) { "  (in .text)" } else { "" },
        );
        if saved_ebp <= frame_ebp || saved_ebp == 0 {
            break;
        }
        frame_ebp = saved_ebp;
    }

    println!("\nRaw stack scan (ESP..ESP+0x400), .text-shaped values only:");
    println!("(return-address candidates: each is the byte AFTER a call instruction)");
    for off in (0..0x400).step_by(4) {
        let addr = esp.wrapping_add(off);
        if let Ok(v) = sb.mmu.load32(addr) {
            if is_text_ptr(v) {
                // Read 6 bytes BEFORE the candidate — typical
                // x86 indirect call is `ff 15 ?? ?? ?? ??` (6
                // bytes). The previous byte being `e8` (5-byte
                // direct call) is also a return-address hint.
                let prev6 = (0..6)
                    .map(|i| sb.mmu.load8(v.wrapping_sub(6 + i)).unwrap_or(0))
                    .collect::<Vec<_>>();
                let looks_like_ret = (prev6[5] == 0xff && prev6[4] == 0x15) // call [mem]
                    || prev6[4] == 0xe8 // call rel32
                    || prev6[3] == 0xe8;
                let marker = if looks_like_ret {
                    "  <-- looks like saved return address"
                } else {
                    ""
                };
                println!("  esp+{off:#05x} [{addr:#010x}] = {v:#010x}{marker}");
            }
        }
    }
}

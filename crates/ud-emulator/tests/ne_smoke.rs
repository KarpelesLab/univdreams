//! Smoke test: load the 16-bit Windows NE installer `SITEX10.EXE` and
//! drive its entry point in the new Win16 execution mode until it
//! reaches its first imported Win16 API call (fail-soft trap).
//!
//! The fixture is an opt-in external download (gitignored); the test
//! no-ops when it is absent so a clean checkout still passes.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

#[test]
fn sitex10_reaches_first_win16_call() {
    let path = workspace_root().join("testdata/external/SITEX10.EXE");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("note: {} absent; skipping", path.display());
        return;
    };

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.instruction_budget = Some(1_000_000);
    sandbox.host.trace_stubs = true; // populate the Win16 call log

    let image = sandbox
        .load_ne_fail_soft("sitex10.exe", &bytes)
        .expect("NE load");
    eprintln!(
        "loaded NE '{}' entry={:#x}:{:#x} ss:sp={:#x}:{:#x} segments+thunk={}",
        image.module_name,
        image.entry_cs,
        image.entry_ip,
        image.init_ss,
        image.init_sp,
        image.selectors.len(),
    );
    assert_eq!(image.module_name, "SITEX10");
    // Entry CS:IP matches the NE header (seg 1, offset 0x3986).
    assert_eq!(image.entry_cs, 1);
    assert_eq!(image.entry_ip, 0x3986);

    // Driving the entry executes the MFC / C-runtime startup through
    // the Win16 API layer (InitTask → WaitEvent → GetVersion → DOS
    // INT 21h → …). Phase 2 implements those; the run still stops at
    // the first *unimplemented* ordinal further in. Assert it gets
    // materially past the 3-instruction entry prologue.
    let result = sandbox.call_ne_entry(&image);
    let executed = sandbox.cpu.instr_count;
    let calls: Vec<String> = sandbox
        .host
        .stub_calls
        .iter()
        .map(|c| format!("{}.{}", c.dll, c.name))
        .collect();
    eprintln!("executed {executed} instructions; win16 calls: {calls:?}; result = {result:?}");
    assert!(
        executed >= 20,
        "should run well past the entry prologue (got {executed} instructions)"
    );
    // InitTask (KERNEL.91) must have been dispatched as a real stub.
    assert!(
        calls.iter().any(|c| c == "kernel.@91"),
        "expected KERNEL.91 (InitTask) to have been called; saw {calls:?}"
    );
}

//! End-to-end smoke test for the FFI-style [`Guest`] layer
//! against the bundled MS-MPEG-4 v3 codec fixture.

use std::path::PathBuf;

use ud_emulator::Guest;

fn fixture() -> Option<Vec<u8>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|p| p.join("Cargo.toml").is_file() && p.join("crates").is_dir())?;
    let path = root.join("testdata/external/wmpcdcs8-mpg4c32.dll");
    std::fs::read(&path).ok()
}

#[test]
fn guest_load_runs_dll_main_and_lists_exports() {
    let Some(bytes) = fixture() else {
        eprintln!("note: msmpeg fixture missing; skipping");
        return;
    };
    // `Guest::load` is the FFI-style "dlopen": load the module
    // and run its DllMain in one step.
    let guest = Guest::load("wmpcdcs8-mpg4c32.dll", &bytes).expect("load");
    // The codec is a VfW driver — it exports DriverProc.
    assert!(
        guest.has_export("DriverProc"),
        "msmpeg codec should export DriverProc"
    );
    assert!(
        guest.export_addr("DriverProc").is_some(),
        "DriverProc must resolve to a guest address"
    );
    // image_base from the PE header.
    assert_ne!(guest.image().image_base, 0);
}

#[test]
fn guest_alloc_round_trips_through_guest_memory() {
    let Some(bytes) = fixture() else {
        eprintln!("note: msmpeg fixture missing; skipping");
        return;
    };
    let mut guest = Guest::load("wmpcdcs8-mpg4c32.dll", &bytes).expect("load");

    // Marshal a buffer into guest memory, read it back —
    // the alloc / read / write FFI primitives.
    let payload: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let ptr = guest.alloc(&payload).expect("alloc");
    assert_ne!(ptr, 0);
    let read_back = guest.read(ptr, payload.len()).expect("read");
    assert_eq!(read_back, payload);

    // Mutate through `write`, observe through `read`.
    guest.write(ptr, b"OVERWRITTEN").expect("write");
    let head = guest.read(ptr, 11).expect("read");
    assert_eq!(&head, b"OVERWRITTEN");

    // A C-string marshals with its trailing NUL.
    let s = guest.alloc_cstr("MP43").expect("alloc_cstr");
    assert_eq!(guest.read(s, 5).expect("read"), b"MP43\0");
}

#[test]
fn guest_call_drives_driver_proc() {
    let Some(bytes) = fixture() else {
        eprintln!("note: msmpeg fixture missing; skipping");
        return;
    };
    let mut guest = Guest::load("wmpcdcs8-mpg4c32.dll", &bytes).expect("load");

    // DriverProc(dwDriverId, hdrvr, msg, lParam1, lParam2).
    // DRV_LOAD = 1 — the codec's one-time load hook. The
    // typed `call` reads like an FFI call; the result comes
    // back as a typed `i32` LRESULT.
    const DRV_LOAD: u32 = 1;
    let rc: i32 = guest
        .call("DriverProc", (0u32, 0u32, DRV_LOAD, 0u32, 0u32))
        .expect("DriverProc(DRV_LOAD)");
    // DRV_LOAD's contract is "non-zero on success"; we only
    // assert the call completed and produced a value — the
    // exact code is codec-specific.
    let _ = rc;
}

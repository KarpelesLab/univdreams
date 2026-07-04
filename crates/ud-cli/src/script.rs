//! `ud script <file.js>` — drive the sandbox from JavaScript.
//!
//! Backed by the pure-Rust [`kataan`] engine (feature `script`). A small set
//! of host functions is registered as JS globals, each closing over one shared
//! [`Sandbox`], so a script can load DLLs, stage guest memory, drive exports /
//! codec decodes, snapshot + restore, and read memory back — with real control
//! flow (loops, branches, functions) the flag-driven CLI can't express.
//!
//! The JS surface (all globals):
//! * `load(path) -> id` — load a PE (fail-soft) into the sandbox; returns a
//!   small integer handle used by the calls below.
//! * `dllMain(id) -> rc` — run `DllMain(DLL_PROCESS_ATTACH)`.
//! * `installCodec(id)` — register the image's `DriverProc` for VfW.
//! * `mapBlob(addr, bytes)` — stage a byte array into guest memory at `addr`
//!   (gap pages mapped R+W; write bypasses W-protection).
//! * `callExport(id, name, [args]) -> eax` — call an export stdcall with an
//!   argument list; returns the 32-bit return value.
//! * `dumpMem(addr, len) -> [byte|null]` — read guest memory (unmapped bytes
//!   come back as `null`).
//! * `readFile(path) -> [byte]` / `writeFile(path, bytes)` — host file I/O, for
//!   staging fixtures and saving dumps.
//! * `checkpoint() -> snap` / `restore(snap)` — snapshot / restore guest memory
//!   (+ heap-arena cursors) so a script can branch and roll back.
//! * `print(...args)` — write a line to stderr (diagnostics; the script's final
//!   expression value is printed to stdout).

// JS numbers are IEEE-754 doubles; every value crossing the boundary to/from a
// 32-bit guest address, handle, or byte casts across the float<->int divide by
// design (a `u32` guest value round-trips through `f64` exactly).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)]

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use anyhow::Context as _;
use kataan::parser::Parser;
use kataan::{Ctx, Interp, NanBox};
use ud_emulator::emulator::{Mmu, Perm};
use ud_emulator::{Sandbox, DLL_PROCESS_ATTACH};

/// A memory + allocator-cursor snapshot for `checkpoint` / `restore`.
struct Snapshot {
    mmu: Mmu,
    heap_cursor: u32,
    const_arena_cursor: u32,
}

/// Shared interpreter-visible sandbox state.
struct State {
    sandbox: Sandbox,
    images: Vec<ud_emulator::pe::Image>,
    snapshots: Vec<Snapshot>,
}

type Shared = Rc<RefCell<State>>;

/// Entry point for the `ud script` subcommand: run the program in `file` and
/// print its completion value (if any).
pub fn run_script(file: &Path, heap_mb: u32, max_instructions: u64) -> anyhow::Result<()> {
    let src = std::fs::read_to_string(file)
        .with_context(|| format!("reading script {}", file.display()))?;
    let out = eval_source(&src, heap_mb, max_instructions)?;
    if !out.is_empty() && out != "undefined" {
        println!("{out}");
    }
    Ok(())
}

/// Run JavaScript `src` against a fresh sandbox and return its completion
/// value rendered as a string (empty / `"undefined"` for no value).
fn eval_source(src: &str, heap_mb: u32, max_instructions: u64) -> anyhow::Result<String> {
    let program = Parser::parse_program(src).map_err(|e| anyhow::anyhow!("parse error: {e:?}"))?;

    let mut sandbox = Sandbox::new_with_heap_mb(heap_mb);
    sandbox.host.instruction_budget = Some(max_instructions);
    let state: Shared = Rc::new(RefCell::new(State {
        sandbox,
        images: Vec::new(),
        snapshots: Vec::new(),
    }));

    let mut interp = Interp::new();
    register_api(&mut interp, &state);

    match interp.run(&program) {
        Ok(v) => Ok(interp.display(v)),
        Err(e) => {
            let t = interp.exec_error_to_thrown(e, kataan::nbexec::ErrorPhase::Runtime);
            if t.message.is_empty() {
                anyhow::bail!("script threw {}", t.name)
            }
            anyhow::bail!("script threw {}: {}", t.name, t.message)
        }
    }
}

/// Read argument `i` as a 32-bit guest value (address / handle / arg).
fn arg_u32(cx: &mut Ctx, args: &[NanBox], i: usize) -> Result<u32, NanBox> {
    let v = args.get(i).copied().unwrap_or_else(|| cx.undefined());
    Ok(cx.to_number(v)? as u32)
}

/// Read argument `i` as a `usize` handle (image / snapshot index).
fn arg_usize(cx: &mut Ctx, args: &[NanBox], i: usize) -> Result<usize, NanBox> {
    let v = args.get(i).copied().unwrap_or_else(|| cx.undefined());
    Ok(cx.to_number(v)? as usize)
}

/// Read argument `i` as a host string.
fn arg_string(cx: &mut Ctx, args: &[NanBox], i: usize) -> Result<String, NanBox> {
    let v = args.get(i).copied().unwrap_or_else(|| cx.undefined());
    cx.to_string(v)
}

/// Read a JS array-like of byte values into a `Vec<u8>`.
fn arg_bytes(cx: &mut Ctx, args: &[NanBox], i: usize) -> Result<Vec<u8>, NanBox> {
    let v = args.get(i).copied().unwrap_or_else(|| cx.undefined());
    let len_v = cx.get(v, "length")?;
    let len = cx.to_number(len_v)? as usize;
    let mut out = Vec::with_capacity(len);
    for idx in 0..len {
        let el = cx.get(v, &idx.to_string())?;
        out.push(cx.to_number(el)? as u8);
    }
    Ok(out)
}

/// Stage `bytes` into guest memory at `addr`, mapping gap pages R+W and
/// writing through the initializer (bypasses per-page W-protection).
fn stage_bytes(sb: &mut Sandbox, addr: u32, bytes: &[u8]) -> Result<(), String> {
    for i in 0..bytes.len() {
        let a = addr.wrapping_add(i as u32);
        if !sb.mmu.is_mapped(a) {
            sb.mmu.map(a, 1, Perm::R | Perm::W);
        }
    }
    sb.mmu
        .write_initializer(addr, bytes)
        .map_err(|t| format!("stage at {addr:#010x}: {t:?}"))
}

/// Register the whole `ud` host API as JS globals over the shared sandbox.
#[allow(clippy::too_many_lines)]
fn register_api(interp: &mut Interp<'_>, state: &Shared) {
    // load(path) -> image id
    let st = state.clone();
    interp.register_global_fn("load", 1, move |cx, _this, args| {
        let path = arg_string(cx, args, 0)?;
        let bytes = std::fs::read(&path).map_err(|e| cx.error(&format!("read {path}: {e}")))?;
        let stem = Path::new(&path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("codec");
        let mut s = st.borrow_mut();
        let img = s
            .sandbox
            .load_fail_soft(stem, &bytes)
            .map(|(img, _)| img)
            .map_err(|e| cx.error(&format!("load {path}: {e}")))?;
        s.images.push(img);
        let id = s.images.len() - 1;
        Ok(cx.number(id as f64))
    });

    // dllMain(id) -> rc
    let st = state.clone();
    interp.register_global_fn("dllMain", 1, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let s = &mut *st.borrow_mut();
        let img = s
            .images
            .get(id)
            .ok_or_else(|| cx.error(&format!("no image #{id}")))?;
        let rc = s
            .sandbox
            .call_dll_main(img, DLL_PROCESS_ATTACH)
            .map_err(|e| cx.error(&format!("DllMain: {e}")))?;
        Ok(cx.number(rc as f64))
    });

    // installCodec(id)
    let st = state.clone();
    interp.register_global_fn("installCodec", 1, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let s = &mut *st.borrow_mut();
        let img = s
            .images
            .get(id)
            .ok_or_else(|| cx.error(&format!("no image #{id}")))?;
        s.sandbox
            .install_codec(img)
            .map_err(|e| cx.error(&format!("install_codec: {e}")))?;
        Ok(cx.undefined())
    });

    // mapBlob(addr, bytes)
    let st = state.clone();
    interp.register_global_fn("mapBlob", 2, move |cx, _this, args| {
        let addr = arg_u32(cx, args, 0)?;
        let bytes = arg_bytes(cx, args, 1)?;
        let mut s = st.borrow_mut();
        stage_bytes(&mut s.sandbox, addr, &bytes).map_err(|e| cx.error(&e))?;
        Ok(cx.number(bytes.len() as f64))
    });

    // callExport(id, name, [args]) -> eax
    let st = state.clone();
    interp.register_global_fn("callExport", 3, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let name = arg_string(cx, args, 1)?;
        // Optional arg-list (default none).
        let call_args = if args.len() > 2 {
            arg_u32_list(cx, args[2])?
        } else {
            Vec::new()
        };
        let s = &mut *st.borrow_mut();
        let img = s
            .images
            .get(id)
            .ok_or_else(|| cx.error(&format!("no image #{id}")))?;
        let eax = s
            .sandbox
            .call_export(img, &name, &call_args)
            .map_err(|e| cx.error(&format!("callExport {name}: {e}")))?;
        Ok(cx.number(eax as f64))
    });

    // dumpMem(addr, len) -> [byte|null]
    let st = state.clone();
    interp.register_global_fn("dumpMem", 2, move |cx, _this, args| {
        let addr = arg_u32(cx, args, 0)?;
        let len = arg_usize(cx, args, 1)?;
        let s = st.borrow();
        let elems: Vec<NanBox> = (0..len)
            .map(|i| match s.sandbox.mmu.load8(addr.wrapping_add(i as u32)) {
                Ok(b) => cx.number(f64::from(b)),
                Err(_) => cx.null(),
            })
            .collect();
        Ok(cx.new_array(elems))
    });

    // readFile(path) -> [byte]
    let st = state.clone();
    let _ = &st; // readFile needs no sandbox, but keep the clone shape uniform.
    interp.register_global_fn("readFile", 1, move |cx, _this, args| {
        let path = arg_string(cx, args, 0)?;
        let bytes = std::fs::read(&path).map_err(|e| cx.error(&format!("read {path}: {e}")))?;
        let elems: Vec<NanBox> = bytes.iter().map(|b| cx.number(f64::from(*b))).collect();
        Ok(cx.new_array(elems))
    });

    // writeFile(path, bytes)
    interp.register_global_fn("writeFile", 2, move |cx, _this, args| {
        let path = arg_string(cx, args, 0)?;
        let bytes = arg_bytes(cx, args, 1)?;
        std::fs::write(&path, &bytes).map_err(|e| cx.error(&format!("write {path}: {e}")))?;
        Ok(cx.number(bytes.len() as f64))
    });

    // checkpoint() -> snap id
    let st = state.clone();
    interp.register_global_fn("checkpoint", 0, move |cx, _this, _args| {
        let s = &mut *st.borrow_mut();
        let snap = Snapshot {
            mmu: s.sandbox.mmu.fork_copy(),
            heap_cursor: s.sandbox.host.heap_cursor,
            const_arena_cursor: s.sandbox.host.const_arena_cursor,
        };
        s.snapshots.push(snap);
        Ok(cx.number((s.snapshots.len() - 1) as f64))
    });

    // restore(snap)
    let st = state.clone();
    interp.register_global_fn("restore", 1, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let s = &mut *st.borrow_mut();
        let snap = s
            .snapshots
            .get(id)
            .ok_or_else(|| cx.error(&format!("no checkpoint #{id}")))?;
        s.sandbox.mmu = snap.mmu.fork_copy();
        s.sandbox.host.heap_cursor = snap.heap_cursor;
        s.sandbox.host.const_arena_cursor = snap.const_arena_cursor;
        Ok(cx.undefined())
    });

    // print(...args) -> undefined (diagnostics to stderr)
    interp.register_global_fn("print", 1, move |cx, _this, args| {
        let mut parts = Vec::with_capacity(args.len());
        for &a in args {
            parts.push(cx.to_string(a)?);
        }
        eprintln!("{}", parts.join(" "));
        Ok(cx.undefined())
    });
}

/// Read a JS array-like of numbers into a `Vec<u32>` (for `callExport` args).
fn arg_u32_list(cx: &mut Ctx, v: NanBox) -> Result<Vec<u32>, NanBox> {
    let len_v = cx.get(v, "length")?;
    let len = cx.to_number(len_v)? as usize;
    let mut out = Vec::with_capacity(len);
    for idx in 0..len {
        let el = cx.get(v, &idx.to_string())?;
        out.push(cx.to_number(el)? as u32);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::eval_source;

    fn eval(src: &str) -> String {
        eval_source(src, 96, 5_000_000).expect("script ok")
    }

    #[test]
    fn mapblob_dumpmem_roundtrip() {
        // JS stages bytes into guest memory and reads them back.
        assert_eq!(
            eval("mapBlob(0x40000000, [1,2,3,4]); dumpMem(0x40000000, 4).join(',');"),
            "1,2,3,4"
        );
    }

    #[test]
    fn checkpoint_restores_guest_memory() {
        // Clobber after a checkpoint, then roll back to it.
        let out = eval(
            "mapBlob(0x40000000,[0xAA]); var s=checkpoint(); \
             mapBlob(0x40000000,[0x11]); restore(s); \
             String(dumpMem(0x40000000,1)[0]);",
        );
        assert_eq!(out, "170"); // 0xAA
    }

    #[test]
    fn unmapped_bytes_read_back_as_null() {
        // Two unmapped bytes -> [null, null] -> join renders "".
        assert_eq!(eval("dumpMem(0x55000000, 2).join(',');"), ",");
    }

    #[test]
    fn control_flow_drives_the_host_api() {
        // A JS loop stages a ramp, host side sees every write.
        let out = eval(
            "for (var i=0;i<8;i++) mapBlob(0x40000000+i,[i]); \
             dumpMem(0x40000000,8).join(',');",
        );
        assert_eq!(out, "0,1,2,3,4,5,6,7");
    }

    #[test]
    fn host_error_surfaces_as_js_throw() {
        // callExport on a bogus image id must throw a catchable JS error.
        assert_eq!(
            eval("try { callExport(99,'x',[]); 'no throw'; } catch (e) { 'caught'; }"),
            "caught"
        );
    }
}

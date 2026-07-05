//! `ud script <file.js>` — drive the sandbox from JavaScript.
//!
//! Backed by the pure-Rust [`kataan`] engine (feature `script`). A set of host
//! functions is registered and exposed under a single `ud` namespace object,
//! each closing over one shared [`Sandbox`], so a script can load DLLs, stage
//! guest memory, drive exports / codec decodes, snapshot + restore, and read
//! memory back — with real control flow (loops, branches, functions) the
//! flag-driven CLI can't express.
//!
//! The JS surface (all under `ud.`):
//! * `ud.load(path) -> id` — load a PE (fail-soft); returns a small handle.
//! * `ud.dllMain(id) -> rc` — run `DllMain(DLL_PROCESS_ATTACH)`.
//! * `ud.installCodec(id)` — register the image's `DriverProc` for VfW.
//! * `ud.mapBlob(addr, bytes)` — stage bytes into guest memory at `addr`.
//! * `ud.callExport(id, name, [args]) -> eax` — call an export stdcall.
//! * `ud.dumpMem(addr, len) -> Uint8Array` — read guest memory (unmapped → 0).
//! * `ud.dumpMemRaw(addr, len) -> [byte|null]` — same, but unmapped → `null`.
//! * `ud.codecOpen(id, w, h[, fcc]) -> ch` — open a codec (Query+Begin) and
//!   keep it live; `ud.decodeFrame(ch, bytes) -> Uint8Array` decodes one frame
//!   in that persistent instance (call it in a loop for inter-frame state);
//!   `ud.codecClose(ch)` tears it down.
//! * `ud.watch(addr, len)` arms a watchpoint; `ud.watchLog() ->
//!   [{seq, addr, offset, width, value, eip}]` returns the ordered
//!   write-trace of every store into a watched region — a byte-exact
//!   behavioral trace of how the real codec fills a buffer.
//! * `ud.readFile(path) -> Uint8Array` / `ud.writeFile(path, bytes)`.
//! * `ud.checkpoint() -> snap` / `ud.restore(snap)` — snapshot / restore guest
//!   memory **and** the heap allocator (arena cursors + block map + module and
//!   codec-handle counters), so a script can branch and roll back faithfully.
//! * `ud.print(...args)` — write a line to stderr.

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
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use anyhow::Context as _;
use kataan::parser::Parser;
use kataan::{Ctx, Interp, NanBox};
use ud_emulator::emulator::{Mmu, Perm};
use ud_emulator::{Bih, Sandbox, DLL_PROCESS_ATTACH};

/// Prelude that assembles the `ud` namespace from the registered `__ud_*`
/// primitives, wrapping the byte-returning ones in `Uint8Array` (host closures
/// can only build plain arrays — typed-array construction is engine-side).
const PRELUDE: &str = r"
const ud = {
  load: __ud_load,
  dllMain: __ud_dllMain,
  installCodec: __ud_installCodec,
  mapBlob: __ud_mapBlob,
  callExport: __ud_callExport,
  dumpMem: function (a, l) { return new Uint8Array(__ud_dumpMem(a, l)); },
  dumpMemRaw: __ud_dumpMem,
  readFile: function (p) { return new Uint8Array(__ud_readFile(p)); },
  writeFile: __ud_writeFile,
  codecOpen: __ud_codecOpen,
  decodeFrame: function (c, b) { return new Uint8Array(__ud_decodeFrame(c, b)); },
  codecClose: __ud_codecClose,
  watch: __ud_watch,
  watchLog: __ud_watchLog,
  checkpoint: __ud_checkpoint,
  restore: __ud_restore,
  print: __ud_print,
};
";

/// A memory + heap-allocator snapshot for `checkpoint` / `restore`.
struct Snapshot {
    mmu: Mmu,
    heap: BTreeMap<u32, Vec<u8>>,
    heap_cursor: u32,
    heap_arena_end: u32,
    const_arena_cursor: u32,
    next_hic: u32,
    modules: BTreeMap<String, u32>,
}

/// A codec opened for a persistent multi-frame decode session.
#[derive(Clone, Copy)]
struct CodecCtx {
    hic: u32,
    width: u32,
    height: u32,
    fcc_handler_u32: u32,
    out_capacity: u32,
}

/// Shared interpreter-visible sandbox state.
struct State {
    sandbox: Sandbox,
    images: Vec<ud_emulator::pe::Image>,
    snapshots: Vec<Snapshot>,
    codecs: Vec<CodecCtx>,
    /// Base address of each armed watchpoint, for reporting offsets.
    watch_bases: Vec<u32>,
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
    let prelude =
        Parser::parse_program(PRELUDE).map_err(|e| anyhow::anyhow!("prelude parse: {e:?}"))?;
    let program = Parser::parse_program(src).map_err(|e| anyhow::anyhow!("parse error: {e:?}"))?;

    let mut sandbox = Sandbox::new_with_heap_mb(heap_mb);
    sandbox.host.instruction_budget = Some(max_instructions);
    let state: Shared = Rc::new(RefCell::new(State {
        sandbox,
        images: Vec::new(),
        snapshots: Vec::new(),
        codecs: Vec::new(),
        watch_bases: Vec::new(),
    }));

    let mut interp = Interp::new();
    register_api(&mut interp, &state);

    // Install the `ud` namespace, then run the user program in the same realm
    // (globals persist across runs).
    if let Err(e) = interp.run(&prelude) {
        let t = interp.exec_error_to_thrown(e, kataan::nbexec::ErrorPhase::Runtime);
        anyhow::bail!("internal prelude error: {} {}", t.name, t.message);
    }
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

/// Read argument `i` as a `usize` handle (image / snapshot / codec index).
fn arg_usize(cx: &mut Ctx, args: &[NanBox], i: usize) -> Result<usize, NanBox> {
    let v = args.get(i).copied().unwrap_or_else(|| cx.undefined());
    Ok(cx.to_number(v)? as usize)
}

/// Read argument `i` as a host string.
fn arg_string(cx: &mut Ctx, args: &[NanBox], i: usize) -> Result<String, NanBox> {
    let v = args.get(i).copied().unwrap_or_else(|| cx.undefined());
    cx.to_string(v)
}

/// Read a JS array-like of byte values into a `Vec<u8>` (accepts a plain array
/// or a `Uint8Array`).
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

/// A 24-bit `BITMAPINFOHEADER` for a codec frame of `size_image` bytes.
fn frame_bih(width: u32, height: u32, compression: [u8; 4], size_image: u32) -> Bih {
    Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression,
        size_image,
        ..Bih::default()
    }
}

/// Register the `__ud_*` primitives as globals over the shared sandbox; the
/// prelude assembles them into the `ud` namespace.
#[allow(clippy::too_many_lines)]
fn register_api(interp: &mut Interp<'_>, state: &Shared) {
    // __ud_load(path) -> image id
    let st = state.clone();
    interp.register_global_fn("__ud_load", 1, move |cx, _this, args| {
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

    // __ud_dllMain(id) -> rc
    let st = state.clone();
    interp.register_global_fn("__ud_dllMain", 1, move |cx, _this, args| {
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

    // __ud_installCodec(id)
    let st = state.clone();
    interp.register_global_fn("__ud_installCodec", 1, move |cx, _this, args| {
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

    // __ud_mapBlob(addr, bytes) -> len
    let st = state.clone();
    interp.register_global_fn("__ud_mapBlob", 2, move |cx, _this, args| {
        let addr = arg_u32(cx, args, 0)?;
        let bytes = arg_bytes(cx, args, 1)?;
        let mut s = st.borrow_mut();
        stage_bytes(&mut s.sandbox, addr, &bytes).map_err(|e| cx.error(&e))?;
        Ok(cx.number(bytes.len() as f64))
    });

    // __ud_callExport(id, name, [args]) -> eax
    let st = state.clone();
    interp.register_global_fn("__ud_callExport", 3, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let name = arg_string(cx, args, 1)?;
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

    // __ud_dumpMem(addr, len) -> [byte|null]
    let st = state.clone();
    interp.register_global_fn("__ud_dumpMem", 2, move |cx, _this, args| {
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

    // __ud_readFile(path) -> [byte]
    interp.register_global_fn("__ud_readFile", 1, move |cx, _this, args| {
        let path = arg_string(cx, args, 0)?;
        let bytes = std::fs::read(&path).map_err(|e| cx.error(&format!("read {path}: {e}")))?;
        let elems: Vec<NanBox> = bytes.iter().map(|b| cx.number(f64::from(*b))).collect();
        Ok(cx.new_array(elems))
    });

    // __ud_writeFile(path, bytes) -> len
    interp.register_global_fn("__ud_writeFile", 2, move |cx, _this, args| {
        let path = arg_string(cx, args, 0)?;
        let bytes = arg_bytes(cx, args, 1)?;
        std::fs::write(&path, &bytes).map_err(|e| cx.error(&format!("write {path}: {e}")))?;
        Ok(cx.number(bytes.len() as f64))
    });

    // __ud_watch(addr, len) — arm a watchpoint over the region.
    let st = state.clone();
    interp.register_global_fn("__ud_watch", 2, move |cx, _this, args| {
        let addr = arg_u32(cx, args, 0)?;
        let len = arg_u32(cx, args, 1)?;
        let s = &mut *st.borrow_mut();
        s.sandbox.mmu.add_watch(addr, len);
        if len != 0 {
            s.watch_bases.push(addr);
        }
        Ok(cx.undefined())
    });

    // __ud_watchLog() -> [{seq, addr, offset, width, value, eip}]
    let st = state.clone();
    interp.register_global_fn("__ud_watchLog", 0, move |cx, _this, _args| {
        let s = st.borrow();
        let bases = s.watch_bases.clone();
        let events: Vec<NanBox> = s
            .sandbox
            .mmu
            .watch_log()
            .iter()
            .map(|ev| {
                let base = bases
                    .iter()
                    .filter(|&&b| b <= ev.addr)
                    .max()
                    .copied()
                    .unwrap_or(ev.addr);
                let o = cx.new_object();
                let v = cx.number(ev.seq as f64);
                cx.set(o, "seq", v);
                let v = cx.number(f64::from(ev.addr));
                cx.set(o, "addr", v);
                let v = cx.number(f64::from(ev.addr - base));
                cx.set(o, "offset", v);
                let v = cx.number(f64::from(ev.width));
                cx.set(o, "width", v);
                let v = cx.number(ev.value as f64);
                cx.set(o, "value", v);
                let v = cx.number(f64::from(ev.eip));
                cx.set(o, "eip", v);
                o
            })
            .collect();
        Ok(cx.new_array(events))
    });

    register_codec_api(interp, state);
    register_snapshot_api(interp, state);

    // __ud_print(...args) -> undefined (diagnostics to stderr)
    interp.register_global_fn("__ud_print", 1, move |cx, _this, args| {
        let mut parts = Vec::with_capacity(args.len());
        for &a in args {
            parts.push(cx.to_string(a)?);
        }
        eprintln!("{}", parts.join(" "));
        Ok(cx.undefined())
    });
}

/// `__ud_codecOpen` / `__ud_decodeFrame` / `__ud_codecClose` — a persistent VfW
/// decode session so a JS loop can feed frames one at a time and keep
/// inter-frame decoder state.
fn register_codec_api(interp: &mut Interp<'_>, state: &Shared) {
    // __ud_codecOpen(id, width, height[, fcc]) -> codec handle
    let st = state.clone();
    interp.register_global_fn("__ud_codecOpen", 3, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let width = arg_u32(cx, args, 1)?;
        let height = arg_u32(cx, args, 2)?;
        let s = &mut *st.borrow_mut();
        if id >= s.images.len() {
            return Err(cx.error(&format!("no image #{id}")));
        }
        let has_fcc = args
            .get(3)
            .is_some_and(|a| a.to_bits() != cx.undefined().to_bits());
        let fcc = if has_fcc {
            arg_string(cx, args, 3)?
        } else {
            crate::derive_default_fcc(Path::new(&s.images[id].name))
        };
        let fcc_handler_u32 = crate::fourcc_to_u32(&fcc);
        let fcc_type = u32::from_le_bytes(*b"VIDC");
        let out_capacity = width.saturating_mul(height).saturating_mul(3);
        // Nominal in-BIH for Query/Begin; each decode rebuilds it per frame.
        let in_bih = frame_bih(width, height, fcc_handler_u32.to_le_bytes(), out_capacity);
        let out_bih = frame_bih(width, height, [0; 4], out_capacity);

        let hic = s
            .sandbox
            .ic_open(fcc_type, fcc_handler_u32, crate::ICMODE_DECOMPRESS)
            .map_err(|e| cx.error(&format!("ICOpen: {e}")))?;
        if hic == 0 {
            return Err(cx.error("codec refused DRV_OPEN"));
        }
        let q = s
            .sandbox
            .ic_decompress_query(hic, &in_bih, Some(&out_bih))
            .map_err(|e| cx.error(&format!("ICDecompressQuery: {e}")))?;
        if q != 0 {
            return Err(cx.error(&format!(
                "codec rejected format (ICDecompressQuery={})",
                q as i32
            )));
        }
        let _ = s.sandbox.ic_decompress_begin(hic, &in_bih, &out_bih);
        s.codecs.push(CodecCtx {
            hic,
            width,
            height,
            fcc_handler_u32,
            out_capacity,
        });
        Ok(cx.number((s.codecs.len() - 1) as f64))
    });

    // __ud_decodeFrame(codecHandle, bytes) -> [byte]
    let st = state.clone();
    interp.register_global_fn("__ud_decodeFrame", 2, move |cx, _this, args| {
        let ch = arg_usize(cx, args, 0)?;
        let frame = arg_bytes(cx, args, 1)?;
        let s = &mut *st.borrow_mut();
        let ctx = *s
            .codecs
            .get(ch)
            .ok_or_else(|| cx.error(&format!("no codec #{ch}")))?;
        let in_bih = frame_bih(
            ctx.width,
            ctx.height,
            ctx.fcc_handler_u32.to_le_bytes(),
            frame.len() as u32,
        );
        let out_bih = frame_bih(ctx.width, ctx.height, [0; 4], ctx.out_capacity);
        let (_rc, decoded) = s
            .sandbox
            .ic_decompress(ctx.hic, 0, &in_bih, &frame, &out_bih, ctx.out_capacity)
            .map_err(|e| cx.error(&format!("ICDecompress: {e}")))?;
        let elems: Vec<NanBox> = decoded.iter().map(|b| cx.number(f64::from(*b))).collect();
        Ok(cx.new_array(elems))
    });

    // __ud_codecClose(codecHandle)
    let st = state.clone();
    interp.register_global_fn("__ud_codecClose", 1, move |cx, _this, args| {
        let ch = arg_usize(cx, args, 0)?;
        let s = &mut *st.borrow_mut();
        let ctx = *s
            .codecs
            .get(ch)
            .ok_or_else(|| cx.error(&format!("no codec #{ch}")))?;
        let _ = s.sandbox.ic_decompress_end(ctx.hic);
        let _ = s.sandbox.ic_close(ctx.hic);
        Ok(cx.undefined())
    });
}

/// `__ud_checkpoint` / `__ud_restore` — snapshot + restore guest memory and the
/// heap allocator so a script can branch and roll back faithfully.
fn register_snapshot_api(interp: &mut Interp<'_>, state: &Shared) {
    // __ud_checkpoint() -> snap id
    let st = state.clone();
    interp.register_global_fn("__ud_checkpoint", 0, move |cx, _this, _args| {
        let s = &mut *st.borrow_mut();
        let snap = Snapshot {
            mmu: s.sandbox.mmu.fork_copy(),
            heap: s.sandbox.host.heap.clone(),
            heap_cursor: s.sandbox.host.heap_cursor,
            heap_arena_end: s.sandbox.host.heap_arena_end,
            const_arena_cursor: s.sandbox.host.const_arena_cursor,
            next_hic: s.sandbox.host.next_hic,
            modules: s.sandbox.host.modules.clone(),
        };
        s.snapshots.push(snap);
        Ok(cx.number((s.snapshots.len() - 1) as f64))
    });

    // __ud_restore(snap)
    let st = state.clone();
    interp.register_global_fn("__ud_restore", 1, move |cx, _this, args| {
        let id = arg_usize(cx, args, 0)?;
        let s = &mut *st.borrow_mut();
        let snap = s
            .snapshots
            .get(id)
            .ok_or_else(|| cx.error(&format!("no checkpoint #{id}")))?;
        s.sandbox.mmu = snap.mmu.fork_copy();
        s.sandbox.host.heap = snap.heap.clone();
        s.sandbox.host.heap_cursor = snap.heap_cursor;
        s.sandbox.host.heap_arena_end = snap.heap_arena_end;
        s.sandbox.host.const_arena_cursor = snap.const_arena_cursor;
        s.sandbox.host.next_hic = snap.next_hic;
        s.sandbox.host.modules = snap.modules.clone();
        Ok(cx.undefined())
    });
}

#[cfg(test)]
mod tests {
    use super::eval_source;

    fn eval(src: &str) -> String {
        eval_source(src, 96, 5_000_000).expect("script ok")
    }

    #[test]
    fn mapblob_dumpmem_roundtrip() {
        // Namespaced API; dumpMem returns a Uint8Array.
        assert_eq!(
            eval("ud.mapBlob(0x40000000, [1,2,3,4]); Array.from(ud.dumpMem(0x40000000, 4)).join(',');"),
            "1,2,3,4"
        );
    }

    #[test]
    fn dumpmem_returns_typed_array() {
        assert_eq!(
            eval("ud.mapBlob(0x40000000,[9]); ud.dumpMem(0x40000000,1) instanceof Uint8Array;"),
            "true"
        );
    }

    #[test]
    fn checkpoint_restores_guest_memory() {
        let out = eval(
            "ud.mapBlob(0x40000000,[0xAA]); var s=ud.checkpoint(); \
             ud.mapBlob(0x40000000,[0x11]); ud.restore(s); \
             String(ud.dumpMem(0x40000000,1)[0]);",
        );
        assert_eq!(out, "170"); // 0xAA
    }

    #[test]
    fn unmapped_bytes_raw_read_as_null() {
        // dumpMemRaw preserves holes as null; dumpMem (typed) would give 0.
        assert_eq!(eval("ud.dumpMemRaw(0x55000000, 2).join(',');"), ",");
    }

    #[test]
    fn control_flow_drives_the_host_api() {
        let out = eval(
            "for (var i=0;i<8;i++) ud.mapBlob(0x40000000+i,[i]); \
             Array.from(ud.dumpMem(0x40000000,8)).join(',');",
        );
        assert_eq!(out, "0,1,2,3,4,5,6,7");
    }

    #[test]
    fn watch_api_is_wired_and_empty_without_guest_writes() {
        // Only *guest* stores are traced (mapBlob uses the host
        // initializer path), so with no codec running the log is empty.
        // Real guest-store traces are exercised by the CLI e2e tests.
        let out = eval("ud.watch(0x41000000, 16); ud.watchLog().length;");
        assert_eq!(out, "0");
    }

    #[test]
    fn host_error_surfaces_as_js_throw() {
        assert_eq!(
            eval("try { ud.callExport(99,'x',[]); 'no throw'; } catch (e) { 'caught'; }"),
            "caught"
        );
    }
}

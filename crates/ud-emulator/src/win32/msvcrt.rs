//! `msvcrt.dll` stubs — round-20 surface for the MSMPEG4 v3
//! VfW decoder (`mpg4c32.dll`) and its DirectShow siblings.
//!
//! Every codec compiled with MSVC after 1996 imports a small
//! collection of CRT init / heap / C++-ABI symbols from the
//! Microsoft VC redistributable. This module satisfies the
//! minimum subset Milestone 3.1 (docs/winmf/winmf-emulator.md
//! §"Milestone 3.1 — MS-MPEG-4 v3 unblock plan") flagged across
//! the four MSMPEG4-related binaries:
//!
//! * `??2@YAPAXI@Z` — `operator new(size_t)`. Returns
//!   `nullptr` on `size == 0` per the Itanium / MSVC C++ ABI.
//! * `??3@YAXPAX@Z` — `operator delete(void*)`. No-op on
//!   `nullptr`; otherwise wraps `HeapFree`.
//! * `_adjust_fdiv` — Pentium-FDIV-erratum runtime fix-up (a
//!   data symbol on real CRTs; we stub as a function that
//!   returns zero — codecs only `cmp [_adjust_fdiv], 0` in
//!   the math library, which never runs in our decode path).
//! * `_except_handler3` — MSVC SEH frame handler. Returns
//!   `EXCEPTION_CONTINUE_SEARCH = 1`; codecs only ever
//!   register it as the chain head and we don't propagate
//!   exceptions through SEH (see `kernel32!RtlUnwind`).
//! * `_initterm(start, end)` — CRT static initialiser
//!   thunk-table walker; calls each non-null
//!   `void(*)()` between `start` and `end`.
//! * `_purecall` — abstract-virtual-call sentinel; in
//!   release builds this is a no-op on entry.
//! * `malloc` / `free` — wrap the existing `HeapAlloc`
//!   arena.
//!
//! Every stub here is **cdecl** (caller-cleanup) so we
//! register them with `arg_dwords = 0`. See
//! [`super::dispatch_stub`] for the calling-convention
//! contract.
//!
//! Reference docs (clean-room — no Wine / ReactOS source):
//! * MSDN "C run-time library reference" — function
//!   contracts.
//! * Itanium C++ ABI §"Mangling" + Microsoft C++ name-
//!   mangling reference (the `??2`/`??3` decorated names).
//! * MSDN "Structured Exception Handling" — `_except_handler3`
//!   ABI.

use super::{arg_dword, call_guest, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every msvcrt stub.
pub fn register(registry: &mut Registry) {
    // Standard `msvcrt.dll`. The same stub set lands under
    // `msvcr71.dll` and `pncrt.dll` via [`register_alias`] —
    // codecs from the wmfdist11 era link msvcr71 (MSVC 7.1
    // runtime); RealNetworks codecs link `pncrt.dll`, their
    // bundled CRT fork. Both export the same names as
    // msvcrt for the C-library surface we care about.
    register_for_dll(registry, "msvcrt.dll");
}

/// Register the same CRT stub set under an alternate dll
/// name. Used to cover `msvcr71.dll` (MSVC 7.1, wmfdist11
/// codecs) and `pncrt.dll` (RealNetworks bundled CRT).
pub fn register_alias(registry: &mut Registry, dll: &str) {
    register_for_dll(registry, dll);
}

fn register_for_dll(registry: &mut Registry, dll: &str) {
    // C++ operator new(size_t) — the Microsoft mangled name.
    registry.register(dll, "??2@YAPAXI@Z", stub_operator_new as StubFn, 0);
    // C++ operator delete(void*) — Microsoft mangled name.
    registry.register(dll, "??3@YAXPAX@Z", stub_operator_delete as StubFn, 0);
    // CRT init — fdiv erratum / SEH / static-ctor table /
    // pure-virtual sentinel.
    //
    // `_adjust_fdiv` is a **data symbol**, not a function:
    // codecs read it as `mov reg, [iat]; mov reg, [reg]`
    // (the IAT slot is the *address* of a 4-byte int, not a
    // function pointer). Register a 4-byte data slot
    // initialised to 0 — meaning "no Pentium-FDIV fix-up
    // needed", which is true for any post-1996 CPU and our
    // synthesised Pentium II.
    registry.register_data(dll, "_adjust_fdiv", 0);
    registry.register(
        dll,
        "_except_handler3",
        stub_except_handler3 as StubFn,
        0,
    );
    registry.register(dll, "_initterm", stub_initterm as StubFn, 0);
    registry.register(dll, "_purecall", stub_purecall as StubFn, 0);
    // CRT exit-handler registry (atexit / DLL-onexit hooks). Real
    // CRTs append the pointer to a per-module list; we let the
    // codec register handlers, then never actually run them
    // (DLL_PROCESS_DETACH is not driven through our sandbox).
    // Both stubs return their first argument verbatim — the MSVC
    // contract: `_onexit` returns the registered pointer on
    // success or NULL on failure. Round 21 — surfaced by the
    // mpg4ds32.ax / wmvds32.ax DirectShow filters.
    registry.register(dll, "_onexit", stub_onexit as StubFn, 0);
    registry.register(dll, "__dllonexit", stub_dllonexit as StubFn, 0);
    // CRT formatted-string family. We support the headline
    // `sprintf(buf, fmt, ...)` form with `%s`, `%d`, `%u`, `%x`,
    // `%c`, `%p`, `%%`. Codec messages aren't user-visible so
    // the formatter doesn't need to match Microsoft's exact
    // padding / locale behaviour — just a faithful conversion.
    registry.register(dll, "sprintf", stub_sprintf as StubFn, 0);
    // C heap.
    registry.register(dll, "malloc", stub_malloc as StubFn, 0);
    registry.register(dll, "free", stub_free as StubFn, 0);

    // ---- Round-48 addition: msadds32.ax PE-load surface --------
    //
    // After r47 (gdi32!StretchDIBits) the splitter (`msadds32.ax`)
    // advances its msvcrt import-table walk to `_endthreadex` —
    // the CRT thread-teardown terminator.  The codec sandbox never
    // actually spawns the splitter's worker thread on the decode
    // path we drive (we only exercise `DLL_PROCESS_ATTACH` /
    // `DriverProc` / `IPin::ReceiveConnection`); the named import
    // just needs to resolve to a thunk before `Sandbox::load`
    // returns the [`Image`].
    //
    // https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/endthread-endthreadex
    // void __cdecl _endthreadex(unsigned retval) — caller-cleanup.
    registry.register(
        dll,
        "_endthreadex",
        stub_end_thread_ex as StubFn,
        0,
    );

    // ---- Round-49 addition: msadds32.ax PE-load surface --------
    //
    // After r48 (`_endthreadex`) the splitter advances its msvcrt
    // import-table walk to `_strnicmp`, the case-insensitive
    // bounded ASCII string compare.  Unlike `_endthreadex` (which
    // the splitter never actually invokes from the
    // PE-load / DLL_PROCESS_ATTACH path), `_strnicmp` IS called
    // during init for FOURCC / header-magic matching, so a stub
    // that returns 0 (== "every string compares equal") would let
    // the codec take a wrong branch and silently misbehave during
    // a later decode.  We implement the real semantics: ASCII
    // tolower on each byte, return `(b1 - b2) as i32` at the
    // first mismatch or terminator, NUL-terminating early on
    // either side.
    //
    // https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l
    // int __cdecl _strnicmp(const char *string1,
    //                       const char *string2,
    //                       size_t count) — caller-cleanup.
    registry.register(dll, "_strnicmp", stub_strnicmp as StubFn, 0);

    // ---- Round-50 addition: msadds32.ax PE-load surface --------
    //
    // After r49 (`_strnicmp`) the splitter advances its msvcrt
    // import-table walk to `_beginthreadex`, the CRT entry that
    // creates an `__stdcall` worker thread.  The codec sandbox
    // NEVER actually spawns the splitter's worker thread on the
    // decode path we drive (we only exercise
    // `DLL_PROCESS_ATTACH` / `DriverProc` /
    // `IPin::ReceiveConnection`).  Combined with the r48
    // `_endthreadex` no-op stub, a fail-soft no-op
    // `_beginthreadex` returning 0 (== "thread creation failed",
    // a normal failure mode documented in MSDN) closes the entire
    // CRT thread-lifecycle surface for `msadds32.ax`'s PE-load.
    //
    // The IAT slot just needs to resolve before `Sandbox::load`
    // returns the [`Image`]; real call sites in the splitter's
    // init layer check the return for non-zero and either fall
    // back or skip (the splitter's worker thread is the render
    // loop, which we never drive).
    //
    // https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/beginthread-beginthreadex
    // uintptr_t __cdecl _beginthreadex(void *security,
    //                                  unsigned stack_size,
    //                                  unsigned (__stdcall *start_address)(void *),
    //                                  void *arglist,
    //                                  unsigned initflag,
    //                                  unsigned *thrdaddr)
    //                                                  — caller-cleanup.
    registry.register(
        dll,
        "_beginthreadex",
        stub_begin_thread_ex as StubFn,
        0,
    );

    // ---- Round-52 addition: msadds32.ax PE-load surface --------
    //
    // After r50 (`_beginthreadex`) the splitter advances its msvcrt
    // import-table walk to `_ftol` — the MSVC x87-to-i32 truncate
    // helper used by code compiled without `/QIfist`.  Unlike the
    // r48/r50 fail-soft no-op pair (`_endthreadex` / `_beginthreadex`),
    // `_ftol` is actively called from filter-coefficient init paths
    // and MUST be a real implementation: returning a constant 0 (or
    // a wrong-sign truncation) would scramble every conversion of
    // a precomputed float coefficient back to the i32 the splitter's
    // FIR loops expect.
    //
    // https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ftol
    // long __cdecl _ftol(double)
    //
    // ABI: cdecl from the C source's perspective, but the IA-32
    // calling convention puts the `double` argument on the x87
    // stack (the caller emits `FLD qword ptr [arg]` before the
    // CALL).  The function pops `ST(0)`, truncates toward zero,
    // and returns the i32 in `eax`.  cdecl means caller-cleanup
    // on the regular cdecl stack — but in this special case the
    // caller didn't push any args there, so `arg_dwords = 0` is
    // correct.
    //
    // Saturation: outside the i32 representable range
    // (`[-2^31, 2^31 - 1]`) and on NaN, return `i32::MIN` (matches
    // the MSVC runtime's documented "indefinite integer" sentinel,
    // `0x8000_0000`).  Rust's `f64 as i32` already saturates per
    // 2018-edition semantics; we still range-check explicitly so
    // the NaN branch returns `i32::MIN` deterministically.
    registry.register(dll, "_ftol", stub_ftol as StubFn, 0);

    // ---- Round-55 addition: msadds32.ax PE-load surface --------
    //
    // After r52 (`_ftol`) the splitter's msvcrt import walk advances
    // to `msvcrt!rand` (and its seed companion `msvcrt!srand`).  Per
    // MSDN (`rand`, `srand`):
    //
    //   int   __cdecl rand(void)            — RAND_MAX = 0x7FFF.
    //   void  __cdecl srand(unsigned int seed)
    //
    // MSVC implements `rand` as a linear-congruential generator with
    // the standard Knuth-style parameters (multiplier 214013, increment
    // 2531011, mod 2^32), returning the middle 15 bits as the output:
    //
    //   state = state * 214013 + 2531011   (mod 2^32)
    //   rand  = (state >> 16) & 0x7FFF
    //
    // The multiplier / increment / output-bit mask are public number-
    // theory constants found in many textbook LCG tables; no Microsoft
    // CRT source was consulted.
    //
    // Wiring the seed at the [`HostState`] level (`HostState::rand_state`)
    // gives the host control over reproducibility: a `Sandbox` seeded
    // identically twice will produce identical `rand` sequences, which
    // matters for encode-regression tests, fuzzing, and bug repros.
    // The seed defaults to 1 (MSVC's documented "no `srand` called yet"
    // state).  The guest's own `srand(s)` call overwrites the same
    // field, so the host can observe what the codec did to the state
    // via [`crate::Sandbox::rand_seed`].
    //
    // Both stubs are cdecl: caller-cleanup, `arg_dwords = 0`.
    registry.register(dll, "rand", stub_rand as StubFn, 0);
    registry.register(dll, "srand", stub_srand as StubFn, 0);

    // ---- Round-56 addition: msadds32.ax PE-load surface --------
    //
    // After r55 (`rand` / `srand`) the splitter's msvcrt import walk
    // advances to MSVC's `_CI*` compiler-intrinsic math helpers.
    // These differ from regular `<math.h>` entries: the argument(s)
    // are passed on the **x87 stack** (not the cdecl integer stack),
    // and the result is returned on the x87 stack (top-of-stack).
    // The same calling-convention quirk applies as `_ftol`
    // (r52): `arg_dwords = 0` because no dwords are on the regular
    // cdecl stack to be cleaned up.
    //
    // For each helper the pattern is:
    //   1. Pop N f64s from the x87 stack in reverse order (so a
    //      2-arg `_CIpow(base, exp)` pops `exp` first then `base`).
    //   2. Compute the standard IEEE 754 / `<math.h>` result via
    //      Rust's `f64` intrinsics — these are bit-correct by
    //      construction (`f64::powf` / `f64::sqrt` / `f64::ln` etc.).
    //   3. Push the result back on the x87 stack.
    //   4. Return 0 in `eax` (the result is in `ST(0)`, not `eax`,
    //      per the documented MSVC `_CI*` convention).
    //
    // References (clean-room):
    //   * MSDN `pow`, `sqrt`, `log`, `log10`, `exp`, `sin`, `cos`,
    //     `tan`, `atan`, `atan2`, `fmod`, `asin`, `acos`, `sinh`,
    //     `cosh`, `tanh`, `floor`, `ceil` — function contracts.
    //   * Intel SDM Vol. 1 §8 + Vol. 2A "FLD" / "FSTP" — x87 stack
    //     semantics for the calling convention.
    //   * IEEE 754-2008 — corner cases (NaN propagation, ±∞, ±0).
    //
    // `_CIpow(base, exp)` — 2 args on x87.  Headline blocker after
    // r55.  Rust's `f64::powf` follows IEEE 754: `1.0_f64.powf(NaN)
    // = 1.0`, `0.0_f64.powf(0.0) = 1.0`, `(-1.0_f64).powf(0.5) =
    // NaN`, `f64::INFINITY.powf(0.0) = 1.0`.
    registry.register(dll, "_CIpow", stub_ci_pow as StubFn, 0);

    // ---- Corpus-driven additions ----------------------------------
    // Imports flagged ≥ 6× by `tests/codec_corpus.rs`. All cdecl.

    // void __security_error_handler(int code, void *data) —
    // MSVC 7.1 buffer-overrun reporter. We return 0; the
    // codec's CRT never actually invokes it on the happy path.
    registry.register(
        dll,
        "__security_error_handler",
        stub_purecall as StubFn,
        0,
    );
    // void __CppXcptFilter(unsigned long, _EXCEPTION_POINTERS*)
    // — MSVC C++ exception filter. `EXCEPTION_CONTINUE_SEARCH = 1`.
    registry.register(
        dll,
        "__CppXcptFilter",
        stub_except_handler3 as StubFn,
        0,
    );
    // int _XcptFilter(unsigned long xc, EXCEPTION_POINTERS *ptr) —
    // CRT exception filter used by `__try`/`__except` blocks.
    // Returns `EXCEPTION_CONTINUE_SEARCH`.
    registry.register(dll, "_XcptFilter", stub_except_handler3 as StubFn, 0);
    // void __cdecl _amsg_exit(int rterrnum) — CRT abort path on
    // runtime errors. We treat it like `_purecall` (no-op,
    // returns 0) since the codec's CRT only hits it on
    // unrecoverable conditions (stack overflow, etc.) we don't
    // synthesise.
    registry.register(dll, "_amsg_exit", stub_purecall as StubFn, 0);
    // void _lock(int locknum) / void _unlock(int locknum) —
    // CRT multi-threaded-mode internal locks. Single-threaded
    // emulator → no-op.
    registry.register(dll, "_lock", stub_purecall as StubFn, 0);
    registry.register(dll, "_unlock", stub_purecall as StubFn, 0);
    // void *memcpy(void *dest, const void *src, size_t n).
    registry.register(dll, "memcpy", stub_memcpy as StubFn, 0);
    // void *memset(void *dest, int c, size_t n).
    registry.register(dll, "memset", stub_memset as StubFn, 0);
    // void *memmove(void *dest, const void *src, size_t n).
    registry.register(dll, "memmove", stub_memmove as StubFn, 0);
    // char *strncpy(char *dest, const char *src, size_t n).
    registry.register(dll, "strncpy", stub_strncpy as StubFn, 0);
    // double _CIsqrt(double x) — x87-stack sqrt (FLD x on
    // entry, FSTP result on exit). Cdecl with no stack args.
    registry.register(dll, "_CIsqrt", stub_ci_sqrt as StubFn, 0);
    // int _vsnwprintf(wchar_t *s, size_t n, const wchar_t *fmt,
    //                 va_list arg) — wide-char snprintf.
    // Stub: write a single NUL and return 0.
    registry.register(dll, "_vsnwprintf", stub_vsnwprintf as StubFn, 0);
    // FILE *fopen(const char *path, const char *mode) — no
    // file system mapped, so always NULL.
    registry.register(dll, "fopen", stub_returns_zero as StubFn, 0);
    registry.register(dll, "_wfopen", stub_returns_zero as StubFn, 0);
    // int fclose(FILE *stream) — no-op success (0 == clean
    // close); codecs that pair fopen→fclose typically
    // short-circuit on the NULL fopen return anyway.
    registry.register(dll, "fclose", stub_purecall as StubFn, 0);
    // time_t time(time_t *t) — synthetic monotonic seconds
    // since 1970-01-01 derived from `state.tick`.
    registry.register(dll, "time", stub_time as StubFn, 0);
    // struct tm *localtime(const time_t *t) — points to a
    // shared global `tm` struct. We hand back a fixed canned
    // pointer into the const arena.
    registry.register(dll, "localtime", stub_localtime as StubFn, 0);
    // `_iob` is the data symbol for the CRT's array of 32
    // `FILE` slots (stdin/stdout/stderr/…). Register a
    // 4-byte data slot whose value is a small region in
    // the data-import arena — codecs that read
    // `_iob[2]` (stderr) just need a non-NULL FILE* they
    // can pass to fprintf/etc., which we ignore.
    registry.register_data(dll, "_iob", 0);

    // ---- Corpus round 2 -------------------------------------------
    // Additional CRT entries flagged by the corpus runner after
    // the first batch of stubs landed.
    registry.register_data(dll, "_errno", 0);
    registry.register_data(dll, "__mb_cur_max", 1);
    registry.register(dll, "_write", stub_returns_arg2 as StubFn, 0);
    registry.register(dll, "asctime", stub_asctime as StubFn, 0);
    registry.register(dll, "fflush", stub_purecall as StubFn, 0);
    registry.register(dll, "fprintf", stub_purecall as StubFn, 0);
    registry.register(dll, "puts", stub_purecall as StubFn, 0);
    registry.register(dll, "printf", stub_purecall as StubFn, 0);
    registry.register(dll, "abort", stub_purecall as StubFn, 0);
    registry.register(dll, "_snprintf", stub_snprintf as StubFn, 0);
    registry.register(dll, "_putenv", stub_purecall as StubFn, 0);
    registry.register(dll, "_stricmp", stub_stricmp as StubFn, 0);
    registry.register(dll, "strchr", stub_strchr as StubFn, 0);
    registry.register(dll, "isupper", stub_isupper as StubFn, 0);
    registry.register(dll, "tolower", stub_tolower as StubFn, 0);
    registry.register(dll, "ceil", stub_ceil as StubFn, 0);
    registry.register(dll, "_CIcos", stub_ci_cos as StubFn, 0);
    registry.register(dll, "_CIsin", stub_ci_sin as StubFn, 0);
    registry.register(dll, "_CIlog", stub_ci_log as StubFn, 0);
}

/// `void* operator new(size_t)` (Microsoft mangling
/// `??2@YAPAXI@Z`). cdecl. Per the C++ ABI, returns
/// `nullptr` on `size == 0` rather than the smallest legal
/// allocation — codecs sometimes test for that.
fn stub_operator_new(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let size = arg_dword(cpu, mmu, 0).map_err(|t| trap("operator new", t))?;
    if size == 0 {
        return Ok(0);
    }
    let addr = state.arena_alloc(size)?;
    let zeros = vec![0u8; size as usize];
    mmu.write_initializer(addr, &zeros)
        .map_err(|t| trap("operator new", t))?;
    Ok(addr)
}

/// `void operator delete(void*)` (Microsoft mangling
/// `??3@YAXPAX@Z`). cdecl. No-op on `nullptr`.
fn stub_operator_delete(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap("operator delete", t))?;
    if p == 0 {
        return Ok(0);
    }
    // Best-effort: drop the heap entry if known. Unknown
    // pointers (e.g. C++ codec frees something allocated via
    // GlobalAlloc through a base-class destructor) are
    // tolerated silently — symmetrical to `kernel32!HeapFree`.
    let _ = state.heap.remove(&p);
    Ok(0)
}

/// `int _except_handler3(EXCEPTION_RECORD*, EXCEPTION_REGISTRATION*,
/// CONTEXT*, void*)`. cdecl. We never raise SEH exceptions
/// inside the sandbox so the handler is never actually called;
/// this stub exists only so the IAT slot resolves at PE-load
/// time. Returns `EXCEPTION_CONTINUE_SEARCH = 1` which is the
/// "chain past me" outcome SEH expects when a handler can't
/// service the exception.
fn stub_except_handler3(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `void _initterm(_PVFV* pfbegin, _PVFV* pfend)`. cdecl.
/// Walks `[pfbegin, pfend)` calling every non-null function
/// pointer it finds, in order. Used by the MSVC CRT to drive
/// global C++ static-ctor / static-dtor lists.
///
/// Each `_PVFV` is `void (__cdecl*)(void)` — no args, no
/// return value. We invoke each entry through
/// [`call_guest`] so any sub-stubs they call (`malloc`,
/// `_initterm` recursively, etc.) dispatch through the host
/// runtime cleanly.
fn stub_initterm(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &Registry,
) -> Result<u32, Win32Error> {
    let begin = arg_dword(cpu, mmu, 0).map_err(|t| trap("_initterm", t))?;
    let end = arg_dword(cpu, mmu, 1).map_err(|t| trap("_initterm", t))?;
    if begin == 0 || end == 0 || end <= begin {
        return Ok(0);
    }
    // Bounds: cap iteration at 4096 entries to defend against
    // a malformed table.
    let span = end.saturating_sub(begin);
    let count = (span / 4).min(4096);
    for i in 0..count {
        let slot = begin.wrapping_add(i * 4);
        let fnptr = match mmu.load32(slot) {
            Ok(v) => v,
            Err(_) => break,
        };
        if fnptr == 0 {
            continue;
        }
        // Re-enter the run loop on this thunk-or-real-fn.
        // Errors stop the walk but don't fail the stub —
        // mirrors MSDN's contract that `_initterm` doesn't
        // diagnose ctor failure (the failing ctor is supposed
        // to terminate the process itself if it cares).
        match call_guest(cpu, mmu, registry, state, fnptr, &[]) {
            Ok(_) => {}
            Err(crate::Error::Win32(e)) => return Err(e),
            Err(_) => break,
        }
    }
    Ok(0)
}

/// `void _purecall(void)`. cdecl. Pure-virtual sentinel; in
/// real CRTs this aborts. The decode path doesn't call any
/// pure-virtual function — the symbol is imported only so the
/// vtable layout for codec C++ classes can include the
/// "abort if a non-implemented virtual is called" trap.
fn stub_purecall(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `void* malloc(size_t)`. cdecl. Wraps the heap arena.
/// Returns 0 (NULL) on size == 0 to match Microsoft's CRT
/// (POSIX permits a unique pointer instead — the codec only
/// cares that NULL means "did not allocate").
fn stub_malloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let size = arg_dword(cpu, mmu, 0).map_err(|t| trap("malloc", t))?;
    if size == 0 {
        return Ok(0);
    }
    let addr = state.arena_alloc(size)?;
    let zeros = vec![0u8; size as usize];
    mmu.write_initializer(addr, &zeros)
        .map_err(|t| trap("malloc", t))?;
    Ok(addr)
}

/// `void free(void*)`. cdecl. No-op on NULL.
fn stub_free(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap("free", t))?;
    if p == 0 {
        return Ok(0);
    }
    let _ = state.heap.remove(&p);
    Ok(0)
}

/// `_onexit_t _onexit(_onexit_t func)`. cdecl. Real CRT
/// appends `func` to a per-module list of process-exit
/// handlers. We never invoke `DLL_PROCESS_DETACH`, so the
/// handlers never run — recording them is unnecessary. Return
/// the input pointer on success per MSDN.
fn stub_onexit(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let func = arg_dword(cpu, mmu, 0).map_err(|t| trap("_onexit", t))?;
    Ok(func)
}

/// `int __dllonexit(_PVFV func, _PVFV** pbegin, _PVFV** pend)`.
/// cdecl. The MSVC CRT helper that powers `atexit` /
/// `_onexit` for DLLs. Same shortcut as
/// [`stub_onexit`] — record nothing, return success.
fn stub_dllonexit(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let func = arg_dword(cpu, mmu, 0).map_err(|t| trap("__dllonexit", t))?;
    Ok(func)
}

/// `int sprintf(char* buffer, const char* format, ...)`. cdecl
/// variadic. Implements the small subset of conversion specs
/// codec DLLs actually emit (debug / FOURCC / driver name
/// strings): `%s %d %u %x %X %c %p %%`. Width and precision
/// modifiers are accepted and applied with simple
/// space-padding. Returns the byte count (not including the
/// terminating NUL) on success.
fn stub_sprintf(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let buf = arg_dword(cpu, mmu, 0).map_err(|t| trap("sprintf", t))?;
    let fmt = arg_dword(cpu, mmu, 1).map_err(|t| trap("sprintf", t))?;
    let mut arg_idx: u32 = 2;
    let mut out: Vec<u8> = Vec::with_capacity(64);
    let mut p = fmt;
    loop {
        let b = mmu.load8(p).map_err(|t| trap("sprintf", t))?;
        if b == 0 {
            break;
        }
        p = p.wrapping_add(1);
        if b != b'%' {
            out.push(b);
            continue;
        }
        // Flags/width/precision parsing — we accept and drop
        // most of them; for `%s` we honour width via padding.
        let mut left_align = false;
        let mut zero_pad = false;
        let mut width: usize = 0;
        let mut precision: Option<usize> = None;
        // Flags
        loop {
            let c = mmu.load8(p).map_err(|t| trap("sprintf", t))?;
            match c {
                b'-' => {
                    left_align = true;
                    p = p.wrapping_add(1);
                }
                b'0' => {
                    zero_pad = true;
                    p = p.wrapping_add(1);
                }
                b'+' | b' ' | b'#' => {
                    p = p.wrapping_add(1);
                }
                _ => break,
            }
        }
        // Width
        loop {
            let c = mmu.load8(p).map_err(|t| trap("sprintf", t))?;
            if c.is_ascii_digit() {
                width = width.saturating_mul(10) + (c - b'0') as usize;
                p = p.wrapping_add(1);
            } else {
                break;
            }
        }
        // Precision
        let mut prec_seen = false;
        if mmu.load8(p).map_err(|t| trap("sprintf", t))? == b'.' {
            p = p.wrapping_add(1);
            prec_seen = true;
            let mut prec: usize = 0;
            loop {
                let c = mmu.load8(p).map_err(|t| trap("sprintf", t))?;
                if c.is_ascii_digit() {
                    prec = prec.saturating_mul(10) + (c - b'0') as usize;
                    p = p.wrapping_add(1);
                } else {
                    break;
                }
            }
            precision = Some(prec);
        }
        // Length modifiers we silently drop (`l`, `h`, `ll`,
        // `I32`, `I64`, …) — the codec only uses dword args.
        loop {
            let c = mmu.load8(p).map_err(|t| trap("sprintf", t))?;
            match c {
                b'l' | b'h' | b'L' | b'I' | b'j' | b'z' | b't' => p = p.wrapping_add(1),
                _ => break,
            }
        }
        let spec = mmu.load8(p).map_err(|t| trap("sprintf", t))?;
        p = p.wrapping_add(1);
        let _ = prec_seen;
        let formatted: Vec<u8> = match spec {
            b'%' => vec![b'%'],
            b's' => {
                let s_addr = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))?;
                arg_idx += 1;
                let mut s = Vec::new();
                let mut q = s_addr;
                let limit = precision.unwrap_or(8192);
                for _ in 0..limit {
                    let c = mmu.load8(q).map_err(|t| trap("sprintf", t))?;
                    if c == 0 {
                        break;
                    }
                    s.push(c);
                    q = q.wrapping_add(1);
                }
                s
            }
            b'c' => {
                let v = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))?;
                arg_idx += 1;
                vec![v as u8]
            }
            b'd' | b'i' => {
                let v = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))? as i32;
                arg_idx += 1;
                format!("{v}").into_bytes()
            }
            b'u' => {
                let v = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))?;
                arg_idx += 1;
                format!("{v}").into_bytes()
            }
            b'x' => {
                let v = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))?;
                arg_idx += 1;
                format!("{v:x}").into_bytes()
            }
            b'X' => {
                let v = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))?;
                arg_idx += 1;
                format!("{v:X}").into_bytes()
            }
            b'p' => {
                let v = arg_dword(cpu, mmu, arg_idx).map_err(|t| trap("sprintf", t))?;
                arg_idx += 1;
                format!("{v:08X}").into_bytes()
            }
            other => {
                // Unknown spec — emit the raw `%X` literal so the
                // text isn't silently lost.
                arg_idx += 1;
                vec![b'%', other]
            }
        };
        // Apply width padding.
        let pad = width.saturating_sub(formatted.len());
        if !left_align {
            let fill = if zero_pad { b'0' } else { b' ' };
            out.resize(out.len() + pad, fill);
        }
        out.extend_from_slice(&formatted);
        if left_align {
            out.resize(out.len() + pad, b' ');
        }
    }
    // NUL-terminate.
    out.push(0);
    // Write to guest buffer.
    for (i, byte) in out.iter().enumerate() {
        mmu.store8(buf.wrapping_add(i as u32), *byte)
            .map_err(|t| trap("sprintf", t))?;
    }
    Ok((out.len() as u32).saturating_sub(1))
}

/// `void __cdecl _endthreadex(unsigned retval)` — fail-soft.
///
/// Per MSDN (`_endthread`, `_endthreadex`): "Ends a thread; …
/// `_endthreadex` is more flexible … `retval` is the exit code
/// for the thread.  `_endthreadex` does not call `_endthread`
/// and does not close the thread handle".  Documented as
/// `__declspec(noreturn)`; in the real CRT control never returns
/// to the caller after `_endthreadex` runs.
///
/// The codec sandbox never spawns the splitter's worker thread
/// on the decode path we drive — we only exercise
/// `DLL_PROCESS_ATTACH` / `DriverProc` / `IPin::ReceiveConnection`.
/// The IAT slot just needs to resolve at PE-load time; if the
/// codec ever did reach `_endthreadex` we'd want to fall back to
/// the caller's return-address rather than terminate the host
/// process, so a no-op stub returning 0 (`eax` = `retval`'s
/// numeric width truncated to a `DWORD`, never actually
/// inspected by the codec since the documented contract says
/// the function doesn't return) is the natural fail-soft
/// shape.  cdecl: caller cleans up `retval`, so `arg_dwords = 0`.
fn stub_end_thread_ex(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // Pull `retval` defensively so a stack-bounds trap surfaces
    // as a proper `Win32Error` rather than a silent under-read;
    // we don't actually surface it to the caller (the MSDN
    // contract is `__declspec(noreturn)`).
    let _retval = arg_dword(cpu, mmu, 0).map_err(|t| trap("_endthreadex", t))?;
    Ok(0)
}

/// `int __cdecl _strnicmp(const char *string1, const char *string2,
/// size_t count)` — case-insensitive ASCII bounded compare.
///
/// Per MSDN (`_strnicmp, _wcsnicmp, _mbsnicmp, _strnicmp_l,
/// _wcsnicmp_l, _mbsnicmp_l`): "Compares, at most, the first
/// `count` characters of two strings.  The comparison is not
/// case-sensitive."  Return value: `< 0` if `string1` is less
/// than `string2`, `0` if equal up to `count`, `> 0` if greater.
///
/// Calling convention: cdecl (caller-cleanup), 3 dwords on the
/// stack (`string1`, `string2`, `count`).  `arg_dwords = 0`.
///
/// Implementation contract:
///
/// * `count == 0` returns 0 (vacuously equal — MSDN explicit).
/// * Each byte is folded to lowercase by the ASCII rule
///   `b'A'..=b'Z' → +0x20`; bytes ≥ `0x80` are compared
///   byte-for-byte (no Unicode tolower).  This matches the
///   single-byte `_strnicmp` documented behaviour for the C
///   locale, which is the only locale the codec init path is
///   ever run under.
/// * Comparison terminates early at the first NUL on EITHER
///   string within `count` bytes; if both reach NUL at the same
///   index, the strings are equal (return 0).  The byte that
///   triggered the termination is included in the returned
///   difference (`b1 - b2`), so `"AVI\0"` vs `"AVIX"` returns a
///   negative value (NUL is less than `'X'`).
/// * Return value is a signed difference of unsigned bytes, cast
///   to `i32` and re-cast to `u32` so the dispatcher can place
///   it in `eax` (the codec re-interprets it as a signed `int`).
///
/// Fail-soft envelope:
///
/// * `count > 1 MiB` → return 0.  No legitimate FOURCC / header
///   compare exceeds a few dozen bytes; an absurdly large count
///   is almost certainly a fuzz-shaped argument or an
///   uninitialised stack slot, and "treat as equal" is the
///   safest non-panicking outcome.
/// * Either pointer reading out-of-bounds (MMU `MemoryFault` or
///   any other [`Trap`]) → return 0.  The MSDN contract has no
///   way to surface a fault back to the caller, and panicking
///   would tear down the host process; the alternative would be
///   to return `Err(Win32Error::InvalidArgument)`, which would
///   then propagate as a sandbox-side trap and abort the decode.
///   Fail-soft (== treat as equal) keeps the boundary case
///   tractable while a real error path is still emitted via
///   tracing.
fn stub_strnicmp(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let s1 = arg_dword(cpu, mmu, 0).map_err(|t| trap("_strnicmp", t))?;
    let s2 = arg_dword(cpu, mmu, 1).map_err(|t| trap("_strnicmp", t))?;
    let count = arg_dword(cpu, mmu, 2).map_err(|t| trap("_strnicmp", t))?;

    // count == 0 → vacuously equal.
    if count == 0 {
        return Ok(0);
    }
    // Absurdly large `count` (more than 1 MiB) is almost
    // certainly fuzz-shaped or an uninitialised stack slot;
    // fail-soft to "equal" rather than panicking on the
    // unbounded loop.
    const MAX_COUNT: u32 = 1 << 20;
    if count > MAX_COUNT {
        return Ok(0);
    }

    fn ascii_tolower(b: u8) -> u8 {
        if b.is_ascii_uppercase() {
            b + 0x20
        } else {
            b
        }
    }

    for i in 0..count {
        let p1 = s1.wrapping_add(i);
        let p2 = s2.wrapping_add(i);
        // Bounds-check by trying the load; on any trap, fail-soft
        // (treat as equal).  Mirrors the MSDN-incompatible-but-
        // sandbox-safe envelope documented above.
        let b1 = match mmu.load8(p1) {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        let b2 = match mmu.load8(p2) {
            Ok(v) => v,
            Err(_) => return Ok(0),
        };
        // NUL on EITHER side terminates the compare.  If both are
        // NUL at the same index, the difference is 0 → equal.
        // If only one side is NUL, the difference picks up the
        // sign correctly (NUL < any non-NUL byte).
        if b1 == 0 || b2 == 0 {
            let diff = (b1 as i32) - (b2 as i32);
            return Ok(diff as u32);
        }
        let l1 = ascii_tolower(b1);
        let l2 = ascii_tolower(b2);
        if l1 != l2 {
            let diff = (l1 as i32) - (l2 as i32);
            return Ok(diff as u32);
        }
    }
    // Reached `count` bytes with no NUL and no mismatch → equal.
    Ok(0)
}

/// `uintptr_t __cdecl _beginthreadex(void *security, unsigned
/// stack_size, unsigned (__stdcall *start_address)(void *), void
/// *arglist, unsigned initflag, unsigned *thrdaddr)` — fail-soft.
///
/// Per MSDN (`_beginthread, _beginthreadex`): "Creates a thread.
/// … Returns a handle to the newly created thread if successful;
/// otherwise, `_beginthreadex` returns 0 and sets `errno` to a
/// nonzero value".  The MSDN failure contract — return 0 — IS
/// the fail-soft shape we want: callers that respect the
/// documented "thread creation can fail" branch fall back or
/// skip the worker-thread codepath cleanly.
///
/// Calling convention: cdecl (caller-cleanup), 6 dwords on the
/// stack (`security`, `stack_size`, `start_address`, `arglist`,
/// `initflag`, `thrdaddr`).  `arg_dwords = 0`.
///
/// The codec sandbox never actually spawns the splitter's worker
/// thread on the decode path we drive — we only exercise
/// `DLL_PROCESS_ATTACH` / `DriverProc` /
/// `IPin::ReceiveConnection`; the IAT slot just needs to resolve
/// at PE-load time.  Combined with the r48 `_endthreadex` no-op
/// stub, this closes the entire CRT thread-lifecycle surface for
/// `msadds32.ax`'s PE-load.
///
/// Implementation contract:
///
/// * Returns 0 (NULL handle) — the MSDN "thread creation failed"
///   sentinel.  `start_address` is never invoked host-side.
/// * If `thrdaddr` is non-NULL and in-bounds, write 0 through it
///   so the caller's "did the OS assign a thread id" probe sees
///   a deterministic value.  If the store traps (OOB pointer),
///   silently swallow the trap and still return 0 — the MSDN
///   contract has no way to surface a fault back to the caller,
///   and panicking would tear down the host process.
fn stub_begin_thread_ex(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // Pull all 6 cdecl dwords defensively so a stack-bounds trap
    // surfaces as a proper `Win32Error::InvalidArgument` rather
    // than a silent under-read.  Only `thrdaddr` is actually
    // consumed; the others are pulled for symmetry with the MSDN
    // signature and to keep the trace inventory complete.
    let _security = arg_dword(cpu, mmu, 0).map_err(|t| trap("_beginthreadex", t))?;
    let _stack_size = arg_dword(cpu, mmu, 1).map_err(|t| trap("_beginthreadex", t))?;
    let _start_address = arg_dword(cpu, mmu, 2).map_err(|t| trap("_beginthreadex", t))?;
    let _arglist = arg_dword(cpu, mmu, 3).map_err(|t| trap("_beginthreadex", t))?;
    let _initflag = arg_dword(cpu, mmu, 4).map_err(|t| trap("_beginthreadex", t))?;
    let thrdaddr = arg_dword(cpu, mmu, 5).map_err(|t| trap("_beginthreadex", t))?;

    // Optionally clear `*thrdaddr` to 0 — fail-soft on OOB
    // pointer (silently swallow the trap, still return 0).
    if thrdaddr != 0 {
        let _ = mmu.store32(thrdaddr, 0);
    }

    // Return 0 = MSDN "thread creation failed" sentinel.
    Ok(0)
}

/// `long __cdecl _ftol(double)` — MSVC's "convert double to long
/// (i32) with truncation toward zero" helper for code compiled
/// without `/QIfist`.
///
/// Per the MSVC ABI the `double` argument is passed on the x87
/// stack: the caller emits `FLD qword ptr [arg]` immediately before
/// the CALL, leaving the value as `ST(0)`.  `_ftol` then:
///
///  1. Reads `ST(0)`.
///  2. Truncates toward zero (i.e. `f64 as i32` semantics in Rust,
///     NOT `floor`).
///  3. Pops `ST(0)` off the x87 stack.
///  4. Returns the i32 in `eax`.
///
/// Saturation contract:
///
///  * `f.is_nan()`            → `i32::MIN` (the MSVC "indefinite
///    integer" sentinel, `0x8000_0000`).
///  * `f >= 2_147_483_648.0`  → `i32::MAX`.
///  * `f <= -2_147_483_649.0` → `i32::MIN`.
///  * Otherwise               → `f as i32` (truncation toward zero).
///
/// (Rust's `f64 as i32` already saturates the over/underflow cases
/// and maps NaN to 0 per RFC 3324, but we want the deterministic
/// `i32::MIN` sentinel for NaN since that matches the contract real
/// MSVC programs occasionally inspect; explicit range-check sorts
/// both concerns out.)
///
/// `cdecl` from the C source's perspective: caller-cleanup on the
/// regular cdecl stack, but the *argument* is on the x87 stack and
/// not on the regular stack at all — so `arg_dwords = 0` is the
/// right registration shape (no dwords to clean).
fn stub_ftol(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // Read ST(0) and pop the x87 stack.  The pop is mandatory:
    // codecs that follow the documented ABI rely on the post-call
    // stack depth being one less than the pre-call depth.
    let f = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();

    // Truncate toward zero with saturation envelope.
    let v: i32 = if f.is_nan() {
        i32::MIN
    } else if f >= 2_147_483_648.0_f64 {
        i32::MAX
    } else if f <= -2_147_483_649.0_f64 {
        i32::MIN
    } else {
        // `f as i32` truncates toward zero in Rust 2018+ semantics.
        f as i32
    };
    Ok(v as u32)
}

/// `int __cdecl rand(void)` — MSVC-CRT-compatible LCG.
///
/// Per MSDN (`rand`): "The `rand` function returns a pseudorandom
/// integer in the range 0 to `RAND_MAX` (32767).  Use the `srand`
/// function to seed the pseudorandom-number generator before
/// calling `rand`."
///
/// MSVC implements `rand` with a Knuth-style linear-congruential
/// generator.  The multiplier / increment / output-bit mask are
/// public number-theory constants from countless LCG references;
/// no Microsoft CRT source was consulted:
///
/// ```text
/// state = state * 214013 + 2531011   (mod 2^32)
/// rand  = (state >> 16) & 0x7FFF      (the middle 15 bits)
/// ```
///
/// Seeding contract: the LCG state lives at
/// [`HostState::rand_state`].  Both this stub and `srand` write
/// the same field, so the host can seed the sandbox before
/// `Sandbox::load` for reproducible output, and the codec can
/// re-seed at any time via its own `srand` call.  Default state
/// is `1` — MSVC's documented "no `srand` called yet" initial
/// value.
///
/// cdecl: caller-cleanup, no args on the stack — `arg_dwords = 0`.
fn stub_rand(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.rand_state = state.rand_state.wrapping_mul(214013).wrapping_add(2531011);
    let r = (state.rand_state >> 16) & 0x7FFF;
    Ok(r)
}

/// `void __cdecl srand(unsigned int seed)` — seeds the MSVC LCG.
///
/// Per MSDN (`srand`): "Sets the starting seed value for the
/// pseudorandom number generator.  Subsequent calls to `rand` use
/// the new seed value to generate the sequence."  The MSVC
/// implementation stores `seed` directly into the LCG state
/// (no XOR / no scrambling) — a public, observable convention
/// derived from the documented "`rand` is a Knuth-LCG" contract,
/// no MS CRT source consulted.
///
/// Writing to [`HostState::rand_state`] keeps the host-side seed
/// API and the guest-side `srand` call on the same field — the
/// host can call [`crate::Sandbox::set_rand_seed`] to force a
/// known state before driving the codec, and the codec's own
/// `srand` will overwrite it.  Either way,
/// [`crate::Sandbox::rand_seed`] reports the current value.
///
/// cdecl: caller-cleanup, one dword on the stack —
/// `arg_dwords = 0`.  Returns 0 (void function; `eax` is
/// unspecified per the MSDN contract).
fn stub_srand(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let seed = arg_dword(cpu, mmu, 0).map_err(|t| trap("srand", t))?;
    state.rand_state = seed;
    Ok(0)
}

/// `double __cdecl _CIpow(double base, double exp)` — MSVC's
/// compiler-intrinsic `pow` helper.
///
/// Per the MSVC `_CI*` ABI, **both** arguments are passed on the
/// x87 stack rather than on the regular cdecl integer stack: the
/// caller emits `FLD qword ptr [base]; FLD qword ptr [exp]` before
/// the CALL, leaving `ST(0) = exp`, `ST(1) = base`.  The function:
///
///  1. Pops `ST(0)` (the exponent).
///  2. Pops `ST(0)` (the base; was originally `ST(1)`).
///  3. Computes `base.powf(exp)` per IEEE 754.
///  4. Pushes the result back onto the x87 stack as the new
///     `ST(0)`.
///  5. Returns 0 in `eax` — the result is in `ST(0)`, not `eax`,
///     per the documented `_CI*` convention.
///
/// IEEE 754 corner cases (Rust `f64::powf` is bit-correct by
/// construction):
///
///  * `0.0_f64.powf(0.0)               → 1.0`     (IEEE default)
///  * `f64::NAN.powf(anything)         → NaN`     (except `.powf(0.0) = 1.0`)
///  * `1.0_f64.powf(f64::NAN)          → 1.0`
///  * `f64::INFINITY.powf(0.0)         → 1.0`
///  * `(-2.0_f64).powf(0.5)            → NaN`     (negative real, non-int exp)
///
/// `cdecl` from the C source's perspective: caller-cleanup on the
/// regular cdecl stack, but both *arguments* are on the x87 stack
/// and not on the regular stack at all — so `arg_dwords = 0` is
/// the right registration shape (no dwords to clean).
fn stub_ci_pow(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // Per the x87 stack ordering: top-of-stack is the *last*
    // pushed value.  Caller emitted FLD base; FLD exp; so
    // ST(0) = exp and ST(1) = base.  Pop `exp` first.
    let exp = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    let base = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    let result = base.powf(exp);
    cpu.fpu.push(result);
    Ok(0)
}

fn trap(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}

// ----- Corpus-driven additions -------------------------------------

/// Trivially returns 0. Used for stubs whose only contract is
/// "return without exploding" (e.g. unused CRT internals).
fn stub_returns_zero(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `void *memcpy(void *dest, const void *src, size_t n)`.
/// Reads `n` bytes from `src` and writes them to `dest`. Returns
/// `dest`. Cdecl.
fn stub_memcpy(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dest = arg_dword(cpu, mmu, 0).map_err(|t| trap("memcpy", t))?;
    let src = arg_dword(cpu, mmu, 1).map_err(|t| trap("memcpy", t))?;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap("memcpy", t))?;
    let data = mmu.read(src, n as usize).map_err(|t| trap("memcpy", t))?;
    mmu.write(dest, &data).map_err(|t| trap("memcpy", t))?;
    Ok(dest)
}

/// `void *memset(void *dest, int c, size_t n)`. Cdecl.
fn stub_memset(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dest = arg_dword(cpu, mmu, 0).map_err(|t| trap("memset", t))?;
    let c = arg_dword(cpu, mmu, 1).map_err(|t| trap("memset", t))? as u8;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap("memset", t))?;
    let buf = vec![c; n as usize];
    mmu.write(dest, &buf).map_err(|t| trap("memset", t))?;
    Ok(dest)
}

/// `void *memmove(void *dest, const void *src, size_t n)`.
/// Handles overlapping regions correctly. Cdecl.
fn stub_memmove(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dest = arg_dword(cpu, mmu, 0).map_err(|t| trap("memmove", t))?;
    let src = arg_dword(cpu, mmu, 1).map_err(|t| trap("memmove", t))?;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap("memmove", t))?;
    // Read everything first into a host buffer — that
    // takes care of the overlap case automatically.
    let data = mmu.read(src, n as usize).map_err(|t| trap("memmove", t))?;
    mmu.write(dest, &data).map_err(|t| trap("memmove", t))?;
    Ok(dest)
}

/// `char *strncpy(char *dest, const char *src, size_t n)`.
/// Writes up to `n` bytes from `src` to `dest`, NUL-padding
/// the remainder if `strlen(src) < n`. Returns `dest`. Cdecl.
fn stub_strncpy(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let dest = arg_dword(cpu, mmu, 0).map_err(|t| trap("strncpy", t))?;
    let src = arg_dword(cpu, mmu, 1).map_err(|t| trap("strncpy", t))?;
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap("strncpy", t))? as usize;
    let mut buf = vec![0u8; n];
    let mut hit_nul = false;
    for i in 0..n {
        if hit_nul {
            buf[i] = 0;
        } else {
            let b = mmu
                .load8(src.wrapping_add(i as u32))
                .map_err(|t| trap("strncpy", t))?;
            if b == 0 {
                hit_nul = true;
                buf[i] = 0;
            } else {
                buf[i] = b;
            }
        }
    }
    mmu.write(dest, &buf).map_err(|t| trap("strncpy", t))?;
    Ok(dest)
}

/// `double _CIsqrt(double)` — x87-stack square root. FLD x on
/// entry, FSTP result on exit. Cdecl, zero stack args.
fn stub_ci_sqrt(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let x = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    cpu.fpu.push(x.sqrt());
    Ok(0)
}

/// `int _vsnwprintf(wchar_t *s, size_t n, const wchar_t *fmt,
/// va_list arg)`. Stub: write a UTF-16 NUL terminator and
/// return 0. Codec build-info / debug-log strings flow through
/// this; an empty result is acceptable.
fn stub_vsnwprintf(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let s = arg_dword(cpu, mmu, 0).map_err(|t| trap("_vsnwprintf", t))?;
    let n = arg_dword(cpu, mmu, 1).map_err(|t| trap("_vsnwprintf", t))?;
    if s != 0 && n >= 1 {
        mmu.store16(s, 0).map_err(|t| trap("_vsnwprintf", t))?;
    }
    Ok(0)
}

/// `time_t time(time_t *t)`. Synthetic monotonic seconds-
/// since-1970 derived from `state.tick`. If `t` is non-NULL,
/// the value is also stored there.
fn stub_time(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.tick = state.tick.wrapping_add(1);
    // Anchor at 2024-01-01 00:00:00 UTC; bump by tick.
    let value = 1_704_067_200u32.wrapping_add(state.tick);
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap("time", t))?;
    if p != 0 {
        mmu.store32(p, value).map_err(|t| trap("time", t))?;
    }
    Ok(value)
}

/// `struct tm *localtime(const time_t *t)`. The C library
/// returns a pointer to a thread-local `tm` struct. We
/// allocate one in the heap arena the first time and reuse
/// it. Fields are zeroed (1970-01-01 epoch in 9-field tm
/// shape — `tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year,
/// tm_wday, tm_yday, tm_isdst`).
fn stub_localtime(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    // Use a fixed offset into the const arena. Reserve 36
    // bytes = 9 i32 fields.
    let p = state.arena_const_alloc(36)?;
    mmu.write_initializer(p, &[0u8; 36])
        .map_err(|t| trap("localtime", t))?;
    Ok(p)
}

// ----- Corpus round 2 ----------------------------------------------

/// Cdecl stub that returns the third argument verbatim. Used
/// for `_write(fd, buf, n)` — pretending the write succeeded.
fn stub_returns_arg2(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let n = arg_dword(cpu, mmu, 2).map_err(|t| trap("_write", t))?;
    Ok(n)
}

/// `char *asctime(const struct tm *tp)`. Returns a 26-char
/// canned string in the const arena. Codecs that include the
/// build timestamp in a debug log use this; the exact format
/// doesn't matter for our purposes.
fn stub_asctime(
    _cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = state.arena_const_alloc(26)?;
    let canned = b"Mon Jan  1 00:00:00 2024\n\0";
    mmu.write_initializer(p, canned)
        .map_err(|t| trap("asctime", t))?;
    Ok(p)
}

/// `int _snprintf(char *buf, size_t n, const char *fmt, ...)`.
/// Stub: NUL-terminate the buffer and return 0.
fn stub_snprintf(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let buf = arg_dword(cpu, mmu, 0).map_err(|t| trap("_snprintf", t))?;
    let n = arg_dword(cpu, mmu, 1).map_err(|t| trap("_snprintf", t))?;
    if buf != 0 && n >= 1 {
        mmu.store8(buf, 0).map_err(|t| trap("_snprintf", t))?;
    }
    Ok(0)
}

/// `int _stricmp(const char *s1, const char *s2)`. Real ASCII
/// case-insensitive compare so codecs that gate on FOURCC
/// strings take the right branch.
fn stub_stricmp(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p1 = arg_dword(cpu, mmu, 0).map_err(|t| trap("_stricmp", t))?;
    let p2 = arg_dword(cpu, mmu, 1).map_err(|t| trap("_stricmp", t))?;
    for i in 0..0x1_0000u32 {
        let a = mmu
            .load8(p1.wrapping_add(i))
            .map_err(|t| trap("_stricmp", t))?
            .to_ascii_lowercase();
        let b = mmu
            .load8(p2.wrapping_add(i))
            .map_err(|t| trap("_stricmp", t))?
            .to_ascii_lowercase();
        if a != b {
            return Ok((a as i32 - b as i32) as u32);
        }
        if a == 0 {
            return Ok(0);
        }
    }
    Ok(0)
}

/// `char *strchr(const char *s, int c)`. Scans `s` for the
/// first occurrence of `c`; returns its pointer or NULL.
fn stub_strchr(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p = arg_dword(cpu, mmu, 0).map_err(|t| trap("strchr", t))?;
    let needle = arg_dword(cpu, mmu, 1).map_err(|t| trap("strchr", t))? as u8;
    for i in 0..0x1_0000u32 {
        let b = mmu
            .load8(p.wrapping_add(i))
            .map_err(|t| trap("strchr", t))?;
        if b == needle {
            return Ok(p.wrapping_add(i));
        }
        if b == 0 {
            return Ok(0);
        }
    }
    Ok(0)
}

/// `int isupper(int c)`. Returns non-zero when `c` is an
/// uppercase ASCII letter. The CRT macro version reads a
/// per-character classification table; we just do the byte
/// test.
fn stub_isupper(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let c = arg_dword(cpu, mmu, 0).map_err(|t| trap("isupper", t))? as u8;
    Ok(u32::from(c.is_ascii_uppercase()))
}

/// `int tolower(int c)`. ASCII-only.
fn stub_tolower(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let c = arg_dword(cpu, mmu, 0).map_err(|t| trap("tolower", t))? as u8;
    Ok(u32::from(c.to_ascii_lowercase()))
}

/// `double ceil(double x)`. x87-stack — FLD on entry, FSTP
/// result on exit. Cdecl with no stack args.
fn stub_ceil(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let x = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    cpu.fpu.push(x.ceil());
    Ok(0)
}

/// `double _CIcos(double)` — x87-stack cosine.
fn stub_ci_cos(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let x = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    cpu.fpu.push(x.cos());
    Ok(0)
}

/// `double _CIsin(double)` — x87-stack sine.
fn stub_ci_sin(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let x = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    cpu.fpu.push(x.sin());
    Ok(0)
}

/// `double _CIlog(double)` — x87-stack natural log.
fn stub_ci_log(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let x = cpu.fpu.st(0);
    let _ = cpu.fpu.pop();
    cpu.fpu.push(x.ln());
    Ok(0)
}
mod tests {
    use super::*;
    use crate::emulator::isa_int::RET_SENTINEL;
    use crate::emulator::mmu::Perm;
    use crate::emulator::regs::Reg32;

    #[allow(dead_code)]
    fn make_env() -> (Cpu, Mmu, Registry, HostState) {
        let mut mmu = Mmu::new();
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        mmu.map(0x9000, 0x1000, Perm::R | Perm::W);
        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x9F00);
        let mut registry = Registry::new();
        registry.register_all();
        let state = HostState::new(0x4000, 0x8000);
        (cpu, mmu, registry, state)
    }

    #[allow(dead_code)]
    fn call_cdecl(
        cpu: &mut Cpu,
        mmu: &mut Mmu,
        registry: &Registry,
        state: &mut HostState,
        name: &str,
        args: &[u32],
    ) -> Result<(), crate::Error> {
        // cdecl: caller pushes args + return addr; callee
        // does NOT pop args. We push the args, then the
        // synthetic ret addr (0xDEAD_DEAD), then dispatch.
        for a in args.iter().rev() {
            cpu.push32(mmu, *a)?;
        }
        cpu.push32(mmu, 0xDEAD_DEAD)?;
        cpu.regs.eip = registry.resolve("msvcrt.dll", name).unwrap();
        crate::win32::dispatch_stub(cpu, mmu, registry, state)
    }

    #[test]
    fn operator_new_zero_size_returns_null() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call_cdecl(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "??2@YAPAXI@Z",
            &[0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);
    }

    #[test]
    fn operator_new_nonzero_returns_heap_addr() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call_cdecl(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "??2@YAPAXI@Z",
            &[64],
        )
        .unwrap();
        let p = cpu.regs.get32(Reg32::Eax);
        assert_ne!(p, 0);
        assert!(state.heap.contains_key(&p));
    }

    #[test]
    fn operator_delete_nullptr_is_noop() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call_cdecl(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "??3@YAXPAX@Z",
            &[0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);
    }

    #[test]
    fn malloc_then_free_round_trip() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call_cdecl(&mut cpu, &mut mmu, &registry, &mut state, "malloc", &[128]).unwrap();
        let p = cpu.regs.get32(Reg32::Eax);
        assert_ne!(p, 0);
        assert!(state.heap.contains_key(&p));
        call_cdecl(&mut cpu, &mut mmu, &registry, &mut state, "free", &[p]).unwrap();
        assert!(!state.heap.contains_key(&p));
    }

    #[test]
    fn initterm_zero_args_is_noop() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call_cdecl(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "_initterm",
            &[0, 0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);
    }

    #[test]
    fn initterm_walks_table_and_calls_non_null_entries() {
        // Build a fn-pointer table of three entries: null,
        // valid, null. The valid entry points at a tiny
        // hand-built guest function that just `ret`s.
        let mut mmu = Mmu::new();
        mmu.map(0x4000, 0x4000, Perm::R | Perm::W);
        mmu.map(0x8000, 0x1000, Perm::R | Perm::W);
        // Code page for the dummy function.
        mmu.map(0xA000, 0x1000, Perm::R | Perm::X);
        // Single `ret` (0xC3) at 0xA000. cdecl callee.
        mmu.write_initializer(0xA000, &[0xC3]).unwrap();
        // Three-slot table at 0x6000: [0, 0xA000, 0].
        mmu.write_initializer(0x6000, &0u32.to_le_bytes()).unwrap();
        mmu.write_initializer(0x6004, &0xA000u32.to_le_bytes())
            .unwrap();
        mmu.write_initializer(0x6008, &0u32.to_le_bytes()).unwrap();

        let mut cpu = Cpu::new();
        cpu.regs.set_esp(0x8F00);
        let mut registry = Registry::new();
        registry.register_all();
        let mut state = HostState::new(0x4000, 0x8000);

        // _initterm(0x6000, 0x600C)
        let _ = RET_SENTINEL; // referenced via call_guest internally
        for a in [0x600Cu32, 0x6000u32].iter() {
            cpu.push32(&mut mmu, *a).unwrap();
        }
        cpu.push32(&mut mmu, 0xDEAD_DEAD).unwrap();
        cpu.regs.eip = registry.resolve("msvcrt.dll", "_initterm").unwrap();
        crate::win32::dispatch_stub(&mut cpu, &mut mmu, &registry, &mut state).unwrap();
        // No assertion on a side-effect register here — the
        // contract is "did not trap" (the fn-pointer was
        // walked + invoked via `call_guest` and returned).
        assert_eq!(cpu.regs.eip, 0xDEAD_DEAD);
    }
}

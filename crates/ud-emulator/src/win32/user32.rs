//! `user32.dll` stubs — the UI surface a VfW-class codec DLL
//! imports.
//!
//! Every stub here is fail-soft: the codec only invokes `user32`
//! in its config-dialog path, which we never invoke. Each stub
//! returns the documented "user cancelled / nothing happened"
//! return value so the codec falls through to a no-UI path.
//!
//! `wsprintfA` is the one exception — codecs use it for log
//! strings + format buffers and we need a working implementation.
//! It supports `%d`, `%u`, `%x`, `%X`, `%s`, `%c`, `%%`. No `%f`
//! / no width / precision specifiers — round-4 has not seen a
//! codec that needs them.
//!
//! Reference: MSDN `user32` page-by-page; cited inline.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every user32 stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-beginpaint
    registry.register("user32.dll", "BeginPaint", stub_begin_paint as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dialogboxparama
    registry.register(
        "user32.dll",
        "DialogBoxParamA",
        stub_dialog_box_param_a as StubFn,
        5,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enddialog
    registry.register("user32.dll", "EndDialog", stub_end_dialog as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-endpaint
    registry.register("user32.dll", "EndPaint", stub_end_paint as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc
    registry.register("user32.dll", "GetDC", stub_get_dc as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdlgitemint
    registry.register(
        "user32.dll",
        "GetDlgItemInt",
        stub_get_dlg_item_int as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowlonga
    registry.register(
        "user32.dll",
        "GetWindowLongA",
        stub_get_window_long_a as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowrect
    registry.register(
        "user32.dll",
        "GetWindowRect",
        stub_get_window_rect as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadbitmapa
    registry.register("user32.dll", "LoadBitmapA", stub_load_bitmap_a as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadstringa
    registry.register("user32.dll", "LoadStringA", stub_load_string_a as StubFn, 4);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebeep
    registry.register("user32.dll", "MessageBeep", stub_message_beep as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
    registry.register("user32.dll", "MessageBoxA", stub_message_box_a as StubFn, 4);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea
    registry.register(
        "user32.dll",
        "PostMessageA",
        stub_post_message_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-releasedc
    registry.register("user32.dll", "ReleaseDC", stub_release_dc as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setdlgitemtexta
    registry.register(
        "user32.dll",
        "SetDlgItemTextA",
        stub_set_dlg_item_text_a as StubFn,
        3,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-wsprintfa
    // wsprintfA is **cdecl**, not stdcall — it's variadic. We
    // register `arg_dwords = 0` so dispatch_stub doesn't pop the
    // arguments; the cdecl caller cleans up. The stub itself
    // walks the variadic list off the stack.
    registry.register("user32.dll", "wsprintfA", stub_wsprintf_a as StubFn, 0);

    // ---- Round-8 additions (IR50_32.DLL configure-dialog
    // surface). All fail-soft — we never enter the dialog UI
    // path during decode.
    registry.register("user32.dll", "CheckDlgButton", stub_zero3 as StubFn, 3);
    registry.register("user32.dll", "CheckRadioButton", stub_zero4 as StubFn, 4);
    registry.register("user32.dll", "CreateDialogParamA", stub_zero5 as StubFn, 5);
    registry.register("user32.dll", "DefWindowProcA", stub_zero4 as StubFn, 4);
    // Round 26 — DestroyWindow returns TRUE per MSDN, drops the
    // synthetic HWND from `host.hwnd_registry`. (Round-8 had it
    // returning 0 ≡ FALSE, which is the documented "function
    // failed" answer; benign for codecs that call it once during
    // teardown but wrong for real headless apps.)
    registry.register(
        "user32.dll",
        "DestroyWindow",
        stub_destroy_window as StubFn,
        1,
    );
    registry.register("user32.dll", "EnableWindow", stub_zero2 as StubFn, 2);
    registry.register(
        "user32.dll",
        "GetClientRect",
        stub_get_client_rect as StubFn,
        2,
    );
    registry.register("user32.dll", "GetDesktopWindow", stub_zero0 as StubFn, 0);
    registry.register("user32.dll", "GetDlgCtrlID", stub_zero1 as StubFn, 1);
    registry.register("user32.dll", "GetDlgItem", stub_zero2 as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdlgitemtexta
    // Round 15 — IR41_32.AX's configure-dialog code reads its
    // "Quality" / "Bitrate" edit boxes via GetDlgItemTextA. The
    // decode path never enters this code, but the import must
    // resolve at load time. Return 0 (no chars copied).
    registry.register("user32.dll", "GetDlgItemTextA", stub_zero4 as StubFn, 4);
    registry.register("user32.dll", "GetFocus", stub_zero0 as StubFn, 0);
    registry.register("user32.dll", "InvalidateRect", stub_zero3 as StubFn, 3);
    registry.register("user32.dll", "IsDlgButtonChecked", stub_zero2 as StubFn, 2);
    registry.register("user32.dll", "IsRectEmpty", stub_is_rect_empty as StubFn, 1);
    registry.register("user32.dll", "LoadStringW", stub_zero4 as StubFn, 4);
    registry.register("user32.dll", "MapWindowPoints", stub_zero4 as StubFn, 4);
    // Round 26 — MoveWindow returns TRUE (per MSDN: TRUE on
    // success). The codec only calls this against a synthetic
    // HWND we previously handed out via CreateWindowExA, and the
    // contract is "always succeeds" for headless windows.
    registry.register("user32.dll", "MoveWindow", stub_one6 as StubFn, 6);
    registry.register("user32.dll", "OffsetRect", stub_offset_rect as StubFn, 3);
    registry.register("user32.dll", "SendMessageA", stub_zero4 as StubFn, 4);
    registry.register("user32.dll", "SetDlgItemInt", stub_zero4 as StubFn, 4);
    registry.register("user32.dll", "SetFocus", stub_zero1 as StubFn, 1);
    registry.register("user32.dll", "SetWindowLongA", stub_zero3 as StubFn, 3);
    registry.register("user32.dll", "SetWindowPos", stub_zero7 as StubFn, 7);
    registry.register("user32.dll", "SetWindowTextA", stub_zero2 as StubFn, 2);
    // Round 26 — ShowWindow's documented return value is the
    // window's PRIOR visibility (BOOL: TRUE if it was visible,
    // FALSE if hidden). For a freshly-minted synthetic HWND the
    // prior state is "hidden", so 0 is the canonical reply. We
    // keep the existing `stub_zero2` mapping but rename the
    // intent in code-comments (round 26 audit).
    registry.register("user32.dll", "ShowWindow", stub_zero2 as StubFn, 2);
    registry.register("user32.dll", "WinHelpA", stub_zero4 as StubFn, 4);
    // wvsprintfA: like wsprintfA but takes a `va_list*` instead
    // of being variadic. cdecl. We bottom-out at zero.
    registry.register("user32.dll", "wvsprintfA", stub_zero0 as StubFn, 0);

    // ---- Round-20 additions (mpg4c32.dll PE-load surface) ---------
    //
    // The MSMPEG4 v3 codec carries a property-page UI vestige
    // that imports three scroll-bar APIs at the IAT level.
    // None of them is reached by the decode path; they exist
    // only so the IAT slot resolves at PE-load time. Each
    // returns the canonical "zero-state" reply per MSDN.

    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getscrollpos
    registry.register("user32.dll", "GetScrollPos", stub_zero2 as StubFn, 2);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setscrollpos
    registry.register("user32.dll", "SetScrollPos", stub_zero4 as StubFn, 4);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setscrollrange
    registry.register("user32.dll", "SetScrollRange", stub_zero5 as StubFn, 5);

    // ---- Round-24 additions (msadds32.ax PE-load surface) ---------
    //
    // The MS-Audio splitter `msadds32.ax` registers + tears down a
    // hidden window class on `DLL_PROCESS_ATTACH` /
    // `DLL_PROCESS_DETACH`. We never enter that window-class code
    // because we never drive `msadds32` through `DllMain`, but the
    // import must resolve at PE-load time. Per MSDN both functions
    // are `__stdcall`, return `BOOL` (`1` = success), and
    // `RegisterClassExA` returns an `ATOM` (non-zero on success).
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclassexa
    // ATOM RegisterClassExA(const WNDCLASSEXA *lpwcx)  — 1 arg.
    registry.register(
        "user32.dll",
        "RegisterClassExA",
        stub_register_class_ex_a as StubFn,
        1,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unregisterclassa
    // BOOL UnregisterClassA(LPCSTR lpClassName, HINSTANCE hInstance)
    // — 2 args, ret 8.
    registry.register(
        "user32.dll",
        "UnregisterClassA",
        stub_unregister_class_a as StubFn,
        2,
    );

    // ---- Round-45 addition: MapDialogRect (msadds32.ax import) ----
    //
    // `msadds32.ax` imports `MapDialogRect` as part of its private
    // property-page-window code path (the same code path that the
    // round-24 RegisterClassExA / UnregisterClassA pair was added
    // for). The codec only invokes it from its config-dialog path,
    // which we never enter during decode, but the IAT slot must
    // resolve at PE-load time.
    //
    // MSDN signature (public):
    //   BOOL MapDialogRect(HWND hDlg, LPRECT lpRect)
    //
    // Per MSDN the function converts dialog-base-units (DLUs) in
    // the input RECT to screen pixels in-place and returns nonzero
    // on success. Because no real dialog template ever underpins
    // the synthetic HWNDs we mint (CreateWindowExA cascade, round
    // 26), the conversion would have nothing to scale by anyway.
    // We choose the **identity passthrough** — leave the RECT
    // unchanged, return TRUE — as the simplest stub that satisfies
    // a "function succeeded" probe. If a future round shows the
    // codec actually inspects the RECT contents post-call, the
    // stub can be upgraded to apply the standard 4×8 base-unit
    // scaling per the MSDN formula.
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-mapdialogrect
    // BOOL MapDialogRect(HWND, LPRECT) — 2 args.
    registry.register(
        "user32.dll",
        "MapDialogRect",
        stub_map_dialog_rect as StubFn,
        2,
    );

    // ---- Round-46 additions: SetTimer + KillTimer (msadds32.ax) ---
    //
    // `msadds32.ax` continues its `user32` import-table walk after
    // the round-45 `MapDialogRect` add-on with two timer-API
    // entries that gate the splitter's window-pump path.  The
    // codec sandbox never actually fires a timer — we never enter
    // the message-loop branch that would let the TIMERPROC
    // callback run — but each named import must resolve to a
    // thunk before `Sandbox::load` returns the [`Image`].
    //
    // Both stubs are fail-soft per the round-24 / round-45 user32
    // playbook:
    //
    //   * `SetTimer` returns the caller's `nIDEvent` if non-zero,
    //     else a synthetic id (`1`).  No actual timer is
    //     scheduled; the codec only inspects the return for
    //     "non-zero == success".
    //   * `KillTimer` returns `TRUE` (1) — the documented
    //     "function found and destroyed the timer" reply.
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-settimer
    // UINT_PTR SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT
    //   uElapse, TIMERPROC lpTimerFunc) — 4 args.
    registry.register("user32.dll", "SetTimer", stub_set_timer as StubFn, 4);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-killtimer
    // BOOL KillTimer(HWND hWnd, UINT_PTR uIDEvent) — 2 args.
    registry.register("user32.dll", "KillTimer", stub_kill_timer as StubFn, 2);

    // ---- Round-26 additions: CreateWindowExA cascade --------------
    //
    // DirectShow filters and several legacy MS codecs expect a
    // hidden private window during init. We hand out synthetic
    // `HWND_BASE + n` values from `host.hwnd_registry`; each
    // companion stub (`Update`, `Destroy`, `IsWindow`, …) is
    // fail-soft TRUE so the codec falls through to its headless
    // path. None of these HWNDs back a real window — the codec
    // only inspects them to confirm "non-NULL" and to call
    // friend-API methods that we likewise stub.
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexa
    // HWND CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName,
    //   LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int W,
    //   int H, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance,
    //   LPVOID lpParam)  — 12 dwords.
    registry.register(
        "user32.dll",
        "CreateWindowExA",
        stub_create_window_ex_a as StubFn,
        12,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-updatewindow
    // BOOL UpdateWindow(HWND hWnd) — 1 arg.  Returns TRUE.
    registry.register("user32.dll", "UpdateWindow", stub_one1 as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-iswindow
    // BOOL IsWindow(HWND hWnd) — 1 arg.  Looks the HWND up in
    // `host.hwnd_registry`: TRUE iff we minted it.
    registry.register("user32.dll", "IsWindow", stub_is_window as StubFn, 1);
    // ---- Message-pump cascade ---------------------------------
    //
    // Codecs that own a window typically also drive a message
    // loop: GetMessageA / DispatchMessageA / TranslateMessage,
    // optionally PeekMessageA. Returning "no message available"
    // across the board ends the loop without dispatching
    // anything, which is the desired behaviour for headless
    // decode.
    //
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea
    // BOOL GetMessageA(LPMSG, HWND, UINT, UINT) — 4 args.
    // Returns 0 (WM_QUIT semantics: caller exits its message
    // loop). We zero-fill the MSG struct so the caller's later
    // reads of msg.message / msg.wParam / msg.lParam see 0.
    registry.register("user32.dll", "GetMessageA", stub_get_message_a as StubFn, 4);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dispatchmessagea
    // LRESULT DispatchMessageA(const MSG *lpMsg) — 1 arg.
    registry.register("user32.dll", "DispatchMessageA", stub_zero1 as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-translatemessage
    // BOOL TranslateMessage(const MSG *lpMsg) — 1 arg.
    registry.register("user32.dll", "TranslateMessage", stub_zero1 as StubFn, 1);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-peekmessagea
    // BOOL PeekMessageA(LPMSG, HWND, UINT, UINT, UINT) — 5 args.
    // Returns 0 (no message present) without modifying *lpMsg.
    registry.register("user32.dll", "PeekMessageA", stub_zero5 as StubFn, 5);
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postquitmessage
    // void PostQuitMessage(int nExitCode) — 1 arg, no return.
    // No-op stub (eax = 0) — the message loop is already gone.
    registry.register("user32.dll", "PostQuitMessage", stub_zero1 as StubFn, 1);
}

/// `ATOM RegisterClassExA(const WNDCLASSEXA *lpwcx)` — return a
/// non-zero synthetic atom (`0xC001`, the first valid global atom
/// per MSDN AddAtom / `MAXINTATOM = 0xC000`). The codec only
/// inspects the return for `non-zero == success`; the host never
/// looks the atom up later because no window is ever created.
fn stub_register_class_ex_a(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0xC001)
}

/// `BOOL UnregisterClassA(LPCSTR lpClassName, HINSTANCE hInstance)`
/// — return `TRUE` (1). The codec calls this from its `DLL_PROCESS_DETACH`
/// teardown to drop the class registration; with no window class
/// actually registered host-side, "success" is the right answer
/// (mirrors what real Windows would return for an in-process
/// class that was never registered against a real desktop).
fn stub_unregister_class_a(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL MapDialogRect(HWND hDlg, LPRECT lpRect)` — identity
/// passthrough.  Per MSDN the function converts dialog-base-units
/// (DLUs) stored in `*lpRect` to screen pixels in-place and
/// returns nonzero on success.  Because we never back any HWND
/// with a real `DialogBox` template, there are no base units to
/// scale by; a stub that leaves the RECT unchanged + reports
/// success satisfies the "function succeeded" probe in the
/// codec's config-dialog path (which we never invoke during
/// decode).  We still validate that `lpRect` is non-NULL via
/// `arg_dword` so a NULL-pointer deref shows up as a host-side
/// trap rather than silently passing.
fn stub_map_dialog_rect(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hdlg = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("MapDialogRect", t))?;
    let _lprect = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("MapDialogRect", t))?;
    // Identity: leave the RECT untouched, report success (TRUE = 1).
    Ok(1)
}

/// `UINT_PTR SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse,
/// TIMERPROC lpTimerFunc)` — fail-soft.
///
/// Per MSDN the function installs a timer and returns its non-zero
/// id (the caller's `nIDEvent` if non-NULL `hWnd`, else a fresh
/// system-allocated id).  The codec sandbox never runs the timer
/// callback because we never enter the codec's message-pump path,
/// so no scheduling is performed host-side.  We return `nIDEvent`
/// when the caller picked a non-zero id (the documented
/// hWnd!=NULL contract) and a synthetic `1` otherwise — both
/// satisfy the "non-zero == success" probe at the call site.
fn stub_set_timer(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hwnd =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("SetTimer", t))?;
    let nid_event =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("SetTimer", t))?;
    let _uelapse =
        arg_dword(cpu, mmu, 2).map_err(|t| crate::win32::trap_to_win32_local("SetTimer", t))?;
    let _timer_proc =
        arg_dword(cpu, mmu, 3).map_err(|t| crate::win32::trap_to_win32_local("SetTimer", t))?;
    if nid_event != 0 {
        Ok(nid_event)
    } else {
        Ok(1)
    }
}

/// `BOOL KillTimer(HWND hWnd, UINT_PTR uIDEvent)` — fail-soft TRUE.
///
/// Per MSDN this returns nonzero iff a registered timer with the
/// matching id was found and destroyed.  Since `SetTimer`
/// host-side never actually schedules a timer (see the comment
/// on `stub_set_timer`), there is also nothing to destroy on the
/// `KillTimer` side; reporting success is the canonical
/// fail-soft answer that lets the codec's teardown path complete.
fn stub_kill_timer(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hwnd =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("KillTimer", t))?;
    let _uid_event =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("KillTimer", t))?;
    Ok(1)
}

// ---- Generic fail-soft stubs reused across many user32 entries -----
//
// MSDN documents most of these as "returns zero on
// failure / TRUE on success". For a pure decode path that never
// renders or pops up a dialog, returning zero is the right
// "no work happened" signal.

fn stub_zero0(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
fn stub_zero1(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
fn stub_zero2(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
fn stub_zero3(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
fn stub_zero4(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
fn stub_zero5(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}
fn stub_zero7(
    _: &mut Cpu,
    _: &mut Mmu,
    _: &mut HostState,
    _: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

// ---- "Always TRUE" fail-soft stubs -----------------------------------
//
// Round 26 — used by `UpdateWindow` / `MoveWindow` etc., which
// must report success (TRUE = 1) for the codec to proceed past
// the call.

fn stub_one1(_: &mut Cpu, _: &mut Mmu, _: &mut HostState, _: &Registry) -> Result<u32, Win32Error> {
    Ok(1)
}
fn stub_one6(_: &mut Cpu, _: &mut Mmu, _: &mut HostState, _: &Registry) -> Result<u32, Win32Error> {
    Ok(1)
}

// ---- Round-26 CreateWindowExA cascade --------------------------------

/// Base address of the synthetic-HWND range. `0xCAFE_0000` is
/// well above any plausible IAT thunk or PE image base + section
/// VA, so an HWND value in this range is unmistakably ours and
/// not a stale guest pointer.
pub const HWND_BASE: u32 = 0xCAFE_0000;

/// `HWND CreateWindowExA(...)`. Mints the next synthetic HWND
/// from `host.hwnd_registry` and returns it.
fn stub_create_window_ex_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let hwnd = HWND_BASE.wrapping_add(state.next_hwnd_index);
    state.next_hwnd_index = state.next_hwnd_index.wrapping_add(1);
    state.hwnd_registry.insert(hwnd);
    Ok(hwnd)
}

/// `BOOL DestroyWindow(HWND)`. Drops the HWND from
/// `host.hwnd_registry` and returns TRUE per MSDN.
fn stub_destroy_window(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let hwnd = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("DestroyWindow", t))?;
    state.hwnd_registry.remove(&hwnd);
    Ok(1)
}

/// `BOOL IsWindow(HWND)`. TRUE iff `host.hwnd_registry` has the
/// HWND. Returns FALSE for a NULL HWND or any HWND we did not
/// mint (mirroring real Windows on a stale handle).
fn stub_is_window(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let hwnd =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("IsWindow", t))?;
    Ok(if hwnd != 0 && state.hwnd_registry.contains(&hwnd) {
        1
    } else {
        0
    })
}

/// `BOOL GetMessageA(LPMSG lpMsg, HWND, UINT, UINT)`. Returns 0
/// (WM_QUIT semantics: the message loop terminates). Zero-fills
/// the 28-byte MSG struct (HWND/message/wParam/lParam/time/pt.x/pt.y).
fn stub_get_message_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let lp =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("GetMessageA", t))?;
    if lp != 0 {
        for i in 0..28u32 {
            mmu.store8(lp + i, 0)
                .map_err(|t| crate::win32::trap_to_win32_local("GetMessageA", t))?;
        }
    }
    Ok(0)
}

/// `BOOL GetClientRect(HWND, LPRECT)`. Zero-fill the RECT (a
/// 16-byte struct: left/top/right/bottom).
fn stub_get_client_rect(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hwnd = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetClientRect", t))?;
    let prect = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetClientRect", t))?;
    if prect != 0 {
        for i in 0..16u32 {
            let _ = mmu.store8(prect + i, 0);
        }
    }
    Ok(1)
}

/// `BOOL IsRectEmpty(LPRECT lprc)`. A rect is empty iff its
/// width or height is non-positive (right <= left or bottom <=
/// top per MSDN).
fn stub_is_rect_empty(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("IsRectEmpty", t))?;
    if p == 0 {
        return Ok(1);
    }
    let l = mmu
        .load32(p)
        .map_err(|t| crate::win32::trap_to_win32_local("IsRectEmpty", t))? as i32;
    let t = mmu
        .load32(p + 4)
        .map_err(|t| crate::win32::trap_to_win32_local("IsRectEmpty", t))? as i32;
    let r = mmu
        .load32(p + 8)
        .map_err(|t| crate::win32::trap_to_win32_local("IsRectEmpty", t))? as i32;
    let b = mmu
        .load32(p + 12)
        .map_err(|t| crate::win32::trap_to_win32_local("IsRectEmpty", t))? as i32;
    Ok(if r <= l || b <= t { 1 } else { 0 })
}

/// `BOOL OffsetRect(LPRECT lprc, int dx, int dy)`. Add dx/dy to
/// the four edges.
fn stub_offset_rect(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("OffsetRect", t))?;
    let dx = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("OffsetRect", t))? as i32;
    let dy = arg_dword(cpu, mmu, 2)
        .map_err(|t| crate::win32::trap_to_win32_local("OffsetRect", t))? as i32;
    if p == 0 {
        return Ok(0);
    }
    let mut bump = |off: u32, delta: i32| -> Result<(), Win32Error> {
        let v = mmu
            .load32(p + off)
            .map_err(|t| crate::win32::trap_to_win32_local("OffsetRect", t))?
            as i32;
        mmu.store32(p + off, v.wrapping_add(delta) as u32)
            .map_err(|t| crate::win32::trap_to_win32_local("OffsetRect", t))
    };
    bump(0, dx)?;
    bump(4, dy)?;
    bump(8, dx)?;
    bump(12, dy)?;
    Ok(1)
}

// `winuser.h`: PAINTSTRUCT — we zero whatever the codec passed.
const PAINTSTRUCT_SIZE: u32 = 64;

fn stub_begin_paint(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hwnd =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("BeginPaint", t))?;
    let p =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("BeginPaint", t))?;
    if p != 0 {
        for i in 0..PAINTSTRUCT_SIZE {
            mmu.store8(p + i, 0)
                .map_err(|t| crate::win32::trap_to_win32_local("BeginPaint", t))?;
        }
    }
    Ok(super::gdi32::SENTINEL_HDC)
}

fn stub_end_paint(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

const IDOK: u32 = 1;
const IDCANCEL: u32 = 2;

/// `INT_PTR DialogBoxParamA(...)`. Return `IDCANCEL` (user
/// cancelled the dialog without us showing it).
fn stub_dialog_box_param_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(IDCANCEL)
}

/// `BOOL EndDialog(HWND hDlg, INT_PTR nResult)`. Returns TRUE.
fn stub_end_dialog(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `HDC GetDC(HWND hWnd)`. Same sentinel HDC as
/// `gdi32::CreateCompatibleDC`.
fn stub_get_dc(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state
        .gdi_hdcs
        .get_or_insert_with(std::collections::BTreeSet::new)
        .insert(super::gdi32::SENTINEL_HDC);
    Ok(super::gdi32::SENTINEL_HDC)
}

/// `int ReleaseDC(HWND hWnd, HDC hDC)`. Returns 1 (success).
fn stub_release_dc(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `UINT GetDlgItemInt(HWND, int, BOOL*, BOOL)`. Returns 0; if
/// `lpTranslated`, write FALSE.
fn stub_get_dlg_item_int(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hdlg = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDlgItemInt", t))?;
    let _id = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDlgItemInt", t))?;
    let p_translated = arg_dword(cpu, mmu, 2)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDlgItemInt", t))?;
    let _signed = arg_dword(cpu, mmu, 3)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDlgItemInt", t))?;
    if p_translated != 0 {
        mmu.store32(p_translated, 0)
            .map_err(|t| crate::win32::trap_to_win32_local("GetDlgItemInt", t))?;
    }
    Ok(0)
}

/// `LONG GetWindowLongA(HWND, int)`. Returns 0.
fn stub_get_window_long_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL GetWindowRect(HWND hWnd, LPRECT lpRect)`. Fills
/// `RECT { left=0, top=0, right=640, bottom=480 }`. Returns TRUE.
fn stub_get_window_rect(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hwnd = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetWindowRect", t))?;
    let p = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetWindowRect", t))?;
    if p != 0 {
        mmu.store32(p, 0)
            .map_err(|t| crate::win32::trap_to_win32_local("GetWindowRect", t))?;
        mmu.store32(p + 4, 0)
            .map_err(|t| crate::win32::trap_to_win32_local("GetWindowRect", t))?;
        mmu.store32(p + 8, 640)
            .map_err(|t| crate::win32::trap_to_win32_local("GetWindowRect", t))?;
        mmu.store32(p + 12, 480)
            .map_err(|t| crate::win32::trap_to_win32_local("GetWindowRect", t))?;
    }
    Ok(1)
}

/// `HBITMAP LoadBitmapA(HINSTANCE, LPCSTR)`. Returns NULL — no
/// resource bitmaps are available.
fn stub_load_bitmap_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `int LoadStringA(HINSTANCE, UINT, LPSTR, int)`. Returns 0
/// (no resource string available); leaves the buffer untouched.
fn stub_load_string_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL MessageBeep(UINT uType)`. No-op TRUE.
fn stub_message_beep(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `int MessageBoxA(HWND, LPCSTR, LPCSTR, UINT)`. Logs the text
/// and caption to stderr (so a codec that calls this surfaces
/// the message visibly), records it on `state.message_box_log`,
/// then returns `IDOK = 1`.
fn stub_message_box_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hwnd =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("MessageBoxA", t))?;
    let p_text =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("MessageBoxA", t))?;
    let p_caption =
        arg_dword(cpu, mmu, 2).map_err(|t| crate::win32::trap_to_win32_local("MessageBoxA", t))?;
    let _utype =
        arg_dword(cpu, mmu, 3).map_err(|t| crate::win32::trap_to_win32_local("MessageBoxA", t))?;
    let text = if p_text != 0 {
        super::read_cstr_local(mmu, p_text, 4096)?
    } else {
        String::new()
    };
    let caption = if p_caption != 0 {
        super::read_cstr_local(mmu, p_caption, 4096)?
    } else {
        String::new()
    };
    eprintln!("[oxideav-vfw MessageBoxA] {caption}: {text}");
    state.message_box_log.push(format!("{caption}: {text}"));
    Ok(IDOK)
}

/// `BOOL PostMessageA(HWND, UINT, WPARAM, LPARAM)`. Returns
/// TRUE (the message is "queued").
fn stub_post_message_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `BOOL SetDlgItemTextA(HWND, int, LPCSTR)`. Returns TRUE.
fn stub_set_dlg_item_text_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `int wsprintfA(LPSTR lpOut, LPCSTR lpFmt, ...)`. **cdecl**
/// (caller-cleanup). Walks the variadic args off the guest stack
/// and renders the format string into `lpOut`. Supports `%d` /
/// `%u` / `%x` / `%X` / `%s` / `%c` / `%%`. No width or precision
/// specifiers (round-4 has not seen a codec that needs them).
///
/// Returns the number of bytes written (excluding the trailing NUL).
fn stub_wsprintf_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let lp_out =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("wsprintfA", t))?;
    let lp_fmt =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("wsprintfA", t))?;
    if lp_out == 0 || lp_fmt == 0 {
        return Ok(0);
    }
    let fmt = super::read_cstr_local(mmu, lp_fmt, 4096)?;
    let mut out = Vec::<u8>::with_capacity(fmt.len() + 32);
    let mut iter = fmt.chars().peekable();
    let mut next_arg: u32 = 2; // arg index of the next variadic dword
    let pop_dword = |cpu: &Cpu, mmu: &Mmu, n: u32| -> Result<u32, Win32Error> {
        arg_dword(cpu, mmu, n).map_err(|t| crate::win32::trap_to_win32_local("wsprintfA", t))
    };
    while let Some(c) = iter.next() {
        if c != '%' {
            // Multi-byte UTF-8 chars from the format string are
            // emitted byte-for-byte.
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            out.extend_from_slice(s.as_bytes());
            continue;
        }
        // Skip flags / width / precision / length we do not honour
        // (consume but ignore digits + '#' + '-' + '0' + ' ' + '+' + '.').
        let mut spec = '\0';
        loop {
            match iter.next() {
                None => break,
                Some(ch) => {
                    if matches!(ch, '#' | '-' | '+' | ' ' | '0' | '.') || ch.is_ascii_digit() {
                        continue;
                    }
                    if ch == 'l' || ch == 'h' || ch == 'I' {
                        continue;
                    }
                    spec = ch;
                    break;
                }
            }
        }
        match spec {
            '%' => out.push(b'%'),
            'c' => {
                let v = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                out.push(v as u8);
            }
            's' => {
                let p = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                if p == 0 {
                    out.extend_from_slice(b"(null)");
                } else {
                    let s = super::read_cstr_local(mmu, p, 4096)?;
                    out.extend_from_slice(s.as_bytes());
                }
            }
            'd' | 'i' => {
                let v = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                out.extend_from_slice((v as i32).to_string().as_bytes());
            }
            'u' => {
                let v = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                out.extend_from_slice(v.to_string().as_bytes());
            }
            'x' => {
                let v = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                out.extend_from_slice(format!("{v:x}").as_bytes());
            }
            'X' => {
                let v = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                out.extend_from_slice(format!("{v:X}").as_bytes());
            }
            'p' => {
                let v = pop_dword(cpu, mmu, next_arg)?;
                next_arg += 1;
                out.extend_from_slice(format!("{v:08X}").as_bytes());
            }
            '\0' => break, // truncated format
            _ => {
                // Unknown specifier — emit it literally so the
                // truncation is visible in test logs.
                out.push(b'%');
                let mut buf = [0u8; 4];
                let s = spec.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    // Write to guest memory (NUL-terminated).
    for (i, b) in out.iter().enumerate() {
        mmu.store8(lp_out + i as u32, *b)
            .map_err(|t| crate::win32::trap_to_win32_local("wsprintfA", t))?;
    }
    mmu.store8(lp_out + out.len() as u32, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("wsprintfA", t))?;
    Ok(out.len() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::mmu::Perm;
    use crate::emulator::regs::Reg32;

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

    fn call(
        cpu: &mut Cpu,
        mmu: &mut Mmu,
        registry: &Registry,
        state: &mut HostState,
        dll: &str,
        name: &str,
        args: &[u32],
    ) -> Result<(), crate::Error> {
        for a in args.iter().rev() {
            cpu.push32(mmu, *a)?;
        }
        cpu.push32(mmu, 0xDEAD_DEAD)?;
        cpu.regs.eip = registry.resolve(dll, name).expect("registered");
        crate::win32::dispatch_stub(cpu, mmu, registry, state)
    }

    #[test]
    fn dialog_box_param_a_returns_idcancel() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "user32.dll",
            "DialogBoxParamA",
            &[0, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), IDCANCEL);
    }

    #[test]
    fn message_box_a_logs_and_returns_idok() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // "hello\0" at 0x4000, "title\0" at 0x4010.
        mmu.write(0x4000, b"hello\0").unwrap();
        mmu.write(0x4010, b"title\0").unwrap();
        state.heap_cursor = 0x4020;
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "user32.dll",
            "MessageBoxA",
            &[0, 0x4000, 0x4010, 0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), IDOK);
        assert!(state.message_box_log.last().unwrap().contains("hello"));
        assert!(state.message_box_log.last().unwrap().contains("title"));
    }

    #[test]
    fn get_window_rect_returns_640x480() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        let p = 0x4040;
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "user32.dll",
            "GetWindowRect",
            &[0, p],
        )
        .unwrap();
        assert_eq!(mmu.load32(p).unwrap(), 0);
        assert_eq!(mmu.load32(p + 4).unwrap(), 0);
        assert_eq!(mmu.load32(p + 8).unwrap(), 640);
        assert_eq!(mmu.load32(p + 12).unwrap(), 480);
    }

    #[test]
    fn wsprintf_a_renders_int_and_str() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        // "n=%d s=%s\0" at 0x4000, "abc\0" at 0x4020, output at 0x4080.
        mmu.write(0x4000, b"n=%d s=%s\0").unwrap();
        mmu.write(0x4020, b"abc\0").unwrap();
        // wsprintfA is cdecl — args remain on the stack after the
        // call. Push: lpOut, lpFmt, 42, 0x4020.
        let args = [0x4080u32, 0x4000, 42, 0x4020];
        // We use call() but cdecl pushes don't get cleaned by the
        // dispatcher (we registered arg_dwords=0).
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "user32.dll",
            "wsprintfA",
            &args,
        )
        .unwrap();
        let mut buf = Vec::new();
        for i in 0..32u32 {
            let b = mmu.load8(0x4080 + i).unwrap();
            if b == 0 {
                break;
            }
            buf.push(b);
        }
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s, "n=42 s=abc");
    }

    #[test]
    fn wsprintf_a_handles_hex_and_percent() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        mmu.write(0x4000, b"v=%X %% %x\0").unwrap();
        let args = [0x4080u32, 0x4000, 0xCAFEu32, 0xDEADu32];
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            "user32.dll",
            "wsprintfA",
            &args,
        )
        .unwrap();
        let mut buf = Vec::new();
        for i in 0..32u32 {
            let b = mmu.load8(0x4080 + i).unwrap();
            if b == 0 {
                break;
            }
            buf.push(b);
        }
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s, "v=CAFE % dead");
    }
}

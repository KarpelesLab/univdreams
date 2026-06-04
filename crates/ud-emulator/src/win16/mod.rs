//! Win16 (16-bit Windows) API stubs, imported by **ordinal** through
//! the `KERNEL` / `USER` / `GDI` / … modules and called with the
//! **FAR PASCAL** convention (arguments pushed left-to-right, callee
//! cleans the stack with `RETF n`, result in `DX:AX`).
//!
//! This is the 16-bit sibling of [`crate::win32`]. The dispatch ABI is
//! handled in [`crate::win32::dispatch_stub`] (it branches on the CPU's
//! 16-bit mode); here we register the stubs and implement them.
//!
//! Phase 2 scope: enough of the Win16 task-startup surface for an MFC /
//! C-runtime NE app to run *past* its entry prologue. The keystone is
//! `KERNEL.91` (`InitTask`), whose register outputs the C startup
//! consumes (`AX` ok-flag, `CX` stack top, `DX` nCmdShow, `SI`
//! hPrevInstance, `DI` hInstance, `ES:BX` command line).

pub mod gui;

use std::collections::BTreeMap;

use crate::emulator::mmu::Perm;
use crate::emulator::regs::{Reg16, Reg8};
use crate::emulator::{Cpu, Mmu};
use crate::win32::{HostState, Registry, Win32Error};

/// Linear base of the Win16 global-heap arena (above the segment
/// windows and PSP).
const WIN16_HEAP_BASE: u32 = 0x0040_0000;
/// First selector handed out for a `GlobalAlloc` block (avoids the
/// segment numbers, HINSTANCE, import/PSP/sentinel selectors).
const WIN16_HEAP_FIRST_SEL: u16 = 0x0200;
/// Per-block window size: a Win16 selector addresses up to 64 KiB.
const WIN16_HEAP_WINDOW: u32 = 0x0001_0000;

/// A simple Win16 global heap. Each `GlobalAlloc` gets its own linear
/// window and a unique selector (handle == selector, GMEM_FIXED-style);
/// `GlobalLock` just hands back `selector:0000`.
#[derive(Debug, Default, Clone)]
pub struct Win16Heap {
    next_base: u32,
    next_selector: u16,
    /// selector → (linear base, requested size).
    pub blocks: BTreeMap<u16, (u32, u32)>,
}

impl Win16Heap {
    /// Allocate `size` bytes: map a fresh window, assign a selector,
    /// register it on the CPU, and return the selector (the handle). Each
    /// block gets a full 64 KiB window — a Win16 selector addresses up to
    /// 64 KiB, and programs routinely read/write the whole segment.
    fn alloc(&mut self, cpu: &mut Cpu, mmu: &mut Mmu, size: u32) -> u16 {
        if self.next_base < WIN16_HEAP_BASE {
            self.next_base = WIN16_HEAP_BASE;
            self.next_selector = WIN16_HEAP_FIRST_SEL;
        }
        let window = WIN16_HEAP_WINDOW.max(size.wrapping_add(0xFFF) & !0xFFF);
        let base = self.next_base;
        let sel = self.next_selector;
        mmu.map(base, window, Perm::R | Perm::W | Perm::X);
        cpu.define_selector(sel, base);
        self.blocks.insert(sel, (base, size));
        self.next_base = self.next_base.wrapping_add(window);
        self.next_selector = self.next_selector.wrapping_add(8);
        sel
    }

    /// Resize the block at `sel`, **keeping the same selector** (handle).
    /// Win16 programs check that `GlobalReAlloc` returns the original handle
    /// (the memory may move underneath, but the handle is stable). If it
    /// fits in the already-mapped window, update in place; otherwise map a
    /// fresh window, copy the data, and rebase the selector to it.
    fn realloc(&mut self, cpu: &mut Cpu, mmu: &mut Mmu, sel: u16, new_size: u32) -> u16 {
        let Some(&(old_base, old_size)) = self.blocks.get(&sel) else {
            return self.alloc(cpu, mmu, new_size);
        };
        // Fits in the existing 64 KiB window → resize in place.
        if new_size <= WIN16_HEAP_WINDOW {
            self.blocks.insert(sel, (old_base, new_size));
            return sel;
        }
        // Huge (>64 KiB) grow: move to a fresh window and copy the contents.
        let new_window = new_size.wrapping_add(0xFFF) & !0xFFF;
        if self.next_base < WIN16_HEAP_BASE {
            self.next_base = WIN16_HEAP_BASE;
            self.next_selector = WIN16_HEAP_FIRST_SEL;
        }
        let new_base = self.next_base;
        mmu.map(new_base, new_window, Perm::R | Perm::W | Perm::X);
        for i in 0..old_size.min(new_size) {
            let b = mmu.load8(old_base.wrapping_add(i)).unwrap_or(0);
            let _ = mmu.store8(new_base.wrapping_add(i), b);
        }
        cpu.define_selector(sel, new_base); // same selector, new base
        self.blocks.insert(sel, (new_base, new_size));
        self.next_base = self.next_base.wrapping_add(new_window);
        sel
    }
}

/// Synthetic instance handle handed to the task (Win16 `HINSTANCE`).
/// Real Windows hands back the module's DGROUP selector; any stable
/// non-zero value works for a single-task sandbox.
pub const WIN16_HINSTANCE: u16 = 0x0100;
/// Synthetic current-task handle (`GetCurrentTask`).
pub const WIN16_HTASK: u16 = 0x0200;
/// `SW_SHOWNORMAL` — the default `nCmdShow` for a launched app.
const SW_SHOWNORMAL: u16 = 1;

/// Call a guest 16-bit **FAR PASCAL** callback (a window or dialog
/// procedure) from the host and return its `DX:AX` result. This is how
/// the headless GUI delivers messages — `WM_INITDIALOG`, `WM_COMMAND`,
/// … — into the program's own code so its handlers actually run.
///
/// `args` are pushed left-to-right (PASCAL order); a `WndProc`/`DlgProc`
/// is invoked as `&[hwnd, msg, wparam, lparam_hi, lparam_lo]`. A far
/// return sentinel is pushed so the callee's `RETF n` lands back here;
/// the call is stack-balanced (the callee cleans its own args).
///
/// # Errors
/// Propagates any trap raised while the callback runs.
pub fn call_guest_far16(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &mut Registry,
    state: &mut HostState,
    proc_sel: u16,
    proc_off: u16,
    args: &[u16],
) -> Result<u32, crate::Error> {
    use crate::emulator::isa_int::RET_SENTINEL;

    cpu.define_selector(crate::ne::SENTINEL_SELECTOR, RET_SENTINEL);
    for &a in args {
        cpu.push16(mmu, a)?;
    }
    // Far-return sentinel: CS = sentinel selector (base RET_SENTINEL),
    // IP = 0, so the callee's RETF returns to RET_SENTINEL and the run
    // loop halts.
    cpu.push16(mmu, crate::ne::SENTINEL_SELECTOR)?;
    cpu.push16(mmu, 0)?;
    cpu.set_cs_ip(proc_sel, proc_off);

    crate::win32::run_until_sentinel(cpu, mmu, registry, state)?;

    let ax = u32::from(cpu.regs.get16(Reg16::Ax));
    let dx = u32::from(cpu.regs.get16(Reg16::Dx));
    Ok((dx << 16) | ax)
}

/// Register the Win16 stub surface with `registry`. Safe to call once
/// per sandbox before loading an NE module; the loader's relocation
/// pass then resolves imported ordinals to these thunks (falling back
/// to trap-on-call for anything unimplemented).
pub fn register_all(registry: &mut Registry) {
    register_kernel(registry);
    register_user(registry);
    register_gdi(registry);
    register_commdlg(registry);
}

/// `COMMDLG` (common dialogs) ordinal stubs.
fn register_commdlg(registry: &mut Registry) {
    // COMMDLG.27 GetFileTitle(lpszFile far, lpszTitle far, cbBuf word).
    registry.register_far_pascal("commdlg", "@27", stub_get_file_title, 10);
}

/// `GDI` ordinal stubs.
fn register_gdi(registry: &mut Registry) {
    // GDI.80 GetDeviceCaps(hDC, index) — display capabilities MFC reads
    // off the screen DC during startup.
    registry.register_far_pascal("gdi", "@80", stub_get_device_caps, 4);
    // GDI.91 GetTextExtent(hDC, lpString far, cbString) → DWORD extent
    // (width in AX, height in DX). Return a fixed 8×16 cell metric.
    registry.register_far_pascal("gdi", "@91", stub_get_text_extent, 8);
    // GDI.66 CreateSolidBrush(COLORREF) → HBRUSH. MFC builds brushes for
    // the system colours during startup.
    registry.register_far_pascal("gdi", "@66", stub_create_object, 4);
    // GDI.61 CreatePen(style, width, COLORREF) → HPEN.
    registry.register_far_pascal("gdi", "@61", stub_create_object, 8);
    // GDI.69 DeleteObject(hObject) → BOOL success.
    registry.register_far_pascal("gdi", "@69", stub_ret1_1word, 2);
    // GDI.87 GetStockObject(fnObject) → HGDIOBJ.
    registry.register_far_pascal("gdi", "@87", stub_create_object, 2);
    // GDI.442 CreateDIBitmap(hdc, lpbmih, init, lpInit, lpbmi, usage) → HBITMAP.
    registry.register_far_pascal("gdi", "@442", stub_create_object, 20);
    // GDI.36 CreateCompatibleDC(hdc) / GDI.72 CreateBitmap / GDI.444
    // SetDIBits / GDI.27 BitBlt — bitmap plumbing the splash uses.
    registry.register_far_pascal("gdi", "@36", stub_create_object, 2);
    registry.register_far_pascal("gdi", "@72", stub_create_object, 10);
}

/// Generic GDI object factory → a fresh unique object handle. The
/// argument layout doesn't matter (the handle is opaque); the cleanup
/// byte count is supplied per-registration.
fn stub_create_object(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(u32::from(state.gui.alloc_obj_handle()))
}

/// `GDI.91 GetTextExtent` → a plausible fixed-pitch extent so MFC's font
/// measurement proceeds. width = 8·cbString, height = 16.
fn stub_get_text_extent(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let cb = cpu.stack_word(mmu, 4).unwrap_or(1); // cbString (last arg)
    let width = 8u32.wrapping_mul(u32::from(cb)) & 0xFFFF;
    Ok((16u32 << 16) | width)
}

/// `GDI.80 GetDeviceCaps(hDC, nIndex)` → plausible 640×480 8bpp,
/// 96-DPI VGA values.
fn stub_get_device_caps(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hDC pushed first (SP+6), nIndex pushed last (SP+4).
    let index = cpu.stack_word(mmu, 4).unwrap_or(0);
    let v: u16 = match index {
        8 => 640,      // HORZRES
        10 => 480,     // VERTRES
        12 => 8,       // BITSPIXEL
        14 => 1,       // PLANES
        88 | 90 => 96, // LOGPIXELSX / LOGPIXELSY
        24 => 20,      // NUMCOLORS
        _ => 0,
    };
    Ok(u32::from(v))
}

/// `USER` ordinal stubs.
fn register_user(registry: &mut Registry) {
    // USER.5 InitApp(hInstance) — set up the task's message queue.
    // Must return non-zero or the C startup aborts.
    registry.register_far_pascal("user", "@5", stub_ret1_1word, 2);
    // USER.66 GetDC(hWnd) — MFC grabs the screen DC at startup to read
    // display metrics, then releases it. Return a non-zero DC handle.
    registry.register_far_pascal("user", "@66", stub_ret_handle_1word, 2);
    // USER.68 ReleaseDC(hWnd, hDC) — release the screen DC; return 1.
    registry.register_far_pascal("user", "@68", stub_ret1_2word, 4);
    // USER.179 GetSystemMetrics(index).
    registry.register_far_pascal("user", "@179", stub_get_system_metrics, 2);
    // USER.180 GetSysColor(index) → COLORREF.
    registry.register_far_pascal("user", "@180", stub_get_sys_color, 2);
    // USER.173 LoadCursor(hInstance, lpCursorName far) → HCURSOR.
    registry.register_far_pascal("user", "@173", stub_create_object, 6);
    // USER.174 LoadIcon(hInstance, lpIconName far) → HICON.
    registry.register_far_pascal("user", "@174", stub_create_object, 6);
    // USER.266 SetMessageQueue(cMsg) → BOOL success. We have no real queue
    // sizing, so always succeed (non-zero).
    registry.register_far_pascal("user", "@266", stub_ret1_1word, 2);
    // USER.176 LoadString(hInst, uID, lpBuffer far, nBufferMax) → length.
    registry.register_far_pascal("user", "@176", stub_load_string, 10);
    // USER.291 SetWindowsHookEx(idHook, lpfn far, hMod, hTask) → HHOOK.
    registry.register_far_pascal("user", "@291", stub_set_windows_hook_ex, 10);
    // USER.57 RegisterClass(lpWndClass far) → ATOM.
    registry.register_far_pascal("user", "@57", stub_register_class, 4);
    // USER.87 DialogBox(hInst, lpTemplate far, hWndParent, lpDialogFunc far).
    registry.register_far_pascal("user", "@87", stub_dialog_box, 12);
    // USER.88 EndDialog(hDlg, nResult).
    registry.register_far_pascal("user", "@88", stub_end_dialog, 4);
    // USER.89 CreateDialog(hInst, lpTemplate far, hWndParent, lpDialogFunc far).
    registry.register_far_pascal("user", "@89", stub_create_dialog, 12);
    // USER.292 UnhookWindowsHookEx(hHook far) → BOOL.
    registry.register_far_pascal("user", "@292", stub_ret1_2word, 4);
    // USER.1 MessageBox(hWnd, lpText far, lpCaption far, wType) → int.
    registry.register_far_pascal("user", "@1", stub_message_box, 12);
    // USER.229 GetTopWindow(hWnd) → first child HWND (none in our model).
    registry.register_far_pascal("user", "@229", stub_ret0_1word, 2);
    // USER.69 SetCursor(hCursor) → previous HCURSOR.
    registry.register_far_pascal("user", "@69", stub_create_object, 2);
    // USER.42 ShowWindow(hWnd, nCmdShow) → previous visibility.
    registry.register_far_pascal("user", "@42", stub_ret1_2word, 4);
    // USER.262 GetWindow(hWnd, uCmd) → related HWND (none in our model).
    registry.register_far_pascal("user", "@262", stub_ret0_1word, 4);
    // USER.32 GetWindowRect(hWnd, lpRect far).
    registry.register_far_pascal("user", "@32", stub_get_window_rect, 6);
    // USER.232 SetWindowPos(hWnd, after, x, y, cx, cy, flags) → BOOL.
    registry.register_far_pascal("user", "@232", stub_ret1_1word, 14);
    // USER.111 SendMessage(hWnd, msg, wParam, lParam long).
    registry.register_far_pascal("user", "@111", stub_send_message, 10);
    // Dialog control accessors.
    registry.register_far_pascal("user", "@91", stub_get_dlg_item, 4);
    registry.register_far_pascal("user", "@36", stub_get_window_text, 8);
    registry.register_far_pascal("user", "@37", stub_set_window_text, 6);
    registry.register_far_pascal("user", "@38", stub_get_window_text_length, 2);
    registry.register_far_pascal("user", "@92", stub_set_dlg_item_text, 8);
    registry.register_far_pascal("user", "@93", stub_get_dlg_item_text, 10);
    // USER.404 GetClassInfo(hInst, lpClassName far, lpWndClass far) → BOOL.
    registry.register_far_pascal("user", "@404", stub_get_class_info, 10);
    // USER.268 GlobalAddAtom(lpString far) → ATOM.
    registry.register_far_pascal("user", "@268", stub_global_add_atom, 4);
    // USER.269 GlobalDeleteAtom(atom) → 0 on success.
    registry.register_far_pascal("user", "@269", stub_ret0_1word, 2);
}

/// `USER.180 GetSysColor(nIndex)` → a plausible 3-D grey scheme.
fn stub_get_sys_color(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let index = cpu.stack_word(mmu, 4).unwrap_or(0);
    let color: u32 = match index {
        15 => 0x00C0_C0C0,     // COLOR_BTNFACE
        16 => 0x0080_8080,     // COLOR_BTNSHADOW
        20 => 0x00FF_FFFF,     // COLOR_BTNHIGHLIGHT
        18 | 8 => 0x0000_0000, // COLOR_BTNTEXT / WINDOWTEXT
        5 => 0x00FF_FFFF,      // COLOR_WINDOW
        _ => 0x0080_8080,
    };
    Ok(color)
}

/// Generic FAR PASCAL stub: clean two words of args, return 1 (success).
fn stub_ret1_2word(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// Generic FAR PASCAL stub returning a fixed non-zero handle (one word
/// of args). Used for HDC / HCURSOR / HICON-returning calls whose value
/// the program only checks for non-NULL and later releases.
fn stub_ret_handle_1word(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0x0010)
}

/// `USER.179 GetSystemMetrics(nIndex)` — return plausible 640×480 VGA
/// metrics so MFC's layout math doesn't divide by zero.
fn stub_get_system_metrics(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // FAR PASCAL: the single word arg sits above the 4-byte far return.
    let index = cpu.stack_word(mmu, 4).unwrap_or(0);
    let v: u16 = match index {
        0 => 640,   // SM_CXSCREEN
        1 => 480,   // SM_CYSCREEN
        2 => 16,    // SM_CXVSCROLL
        3 => 16,    // SM_CYHSCROLL
        4 => 19,    // SM_CYCAPTION
        5 | 6 => 1, // SM_CXBORDER / SM_CYBORDER
        11 => 32,   // SM_CXICON
        12 => 32,   // SM_CYICON
        _ => 0,
    };
    Ok(u32::from(v))
}

/// Generic FAR PASCAL stub: clean one word of args, return 1 (success).
fn stub_ret1_1word(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// Service a software interrupt raised in 16-bit mode. Returns `true`
/// if handled (the run loop then resumes), `false` if the vector is
/// unknown (the run loop surfaces it as a trap).
///
/// Win16 apps still reach DOS through `INT 21h` for a handful of
/// services (get version, get/set vectors, get current drive, …). We
/// service the common ones and clear the carry flag (success);
/// anything unrecognised clears carry and returns 0 so a probe doesn't
/// derail the run.
pub fn service_interrupt(num: u8, cpu: &mut Cpu, mmu: &mut Mmu, state: &mut HostState) -> bool {
    match num {
        0x21 => {
            dos_int21(cpu, mmu, state);
            true
        }
        // INT 3 (breakpoint) / INT 0x3F (Win16 inter-segment call thunk,
        // already handled at load) — ignore and continue.
        0x03 => true,
        _ => false,
    }
}

/// DOS `INT 21h` dispatcher. Handles the version/date stubs plus the file
/// I/O handle functions (open/create/read/write/seek/close/mkdir), wired
/// to the [`crate::context::VirtualFs`] so an installer's extraction writes
/// land where `--dump-vfs` can collect them.
fn dos_int21(cpu: &mut Cpu, mmu: &mut Mmu, state: &mut HostState) {
    use crate::emulator::isa_int::Seg;
    let ah = cpu.regs.get8(Reg8::Ah);
    if std::env::var("UD_NE_DOS_DEBUG").is_ok() {
        eprintln!("DOS INT21 AH={ah:#04x}");
    }
    cpu.regs.flags.cf = false; // default: success
    match ah {
        // AH=0x30 Get DOS version → AL=major, AH=minor, BX:CX OEM/serial.
        0x30 => {
            cpu.regs.set8(Reg8::Al, 6); // DOS 6.x
            cpu.regs.set8(Reg8::Ah, 0);
            cpu.regs.set16(Reg16::Bx, 0);
            cpu.regs.set16(Reg16::Cx, 0);
        }
        // AH=0x19 Get current default drive → AL = drive (0=A, 2=C).
        0x19 => cpu.regs.set8(Reg8::Al, 2),
        // AH=0x25 Set interrupt vector — accept and ignore.
        0x25 => {}
        // AH=0x1A Set DTA (DS:DX) — remember where FindFirst writes.
        0x1A => {
            state.dos_dta = (cpu.segment_selector(Seg::Ds), cpu.regs.get16(Reg16::Dx));
        }
        // AH=0x2F Get DTA → ES:BX.
        0x2F => {
            cpu.set_segment_reg(0 /* ES */, state.dos_dta.0);
            cpu.regs.set16(Reg16::Bx, state.dos_dta.1);
        }
        // AH=0x4E FindFirst(DS:DX pathspec, CX attr) → fill the DTA with the
        // matching file's directory entry (notably its size at +0x1A) so a
        // copy/CRC loop reads the right number of bytes.
        0x4E => {
            let lin = cpu
                .seg_base(Seg::Ds)
                .wrapping_add(u32::from(cpu.regs.get16(Reg16::Dx)));
            let spec = String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 260)).into_owned();
            // Resolve a concrete match (exact path, or first VFS file whose
            // base name matches a `*.*`-style pattern's directory).
            let size = state
                .context
                .vfs
                .as_ref()
                .and_then(|v| dos_find_match(v, &spec));
            match size {
                Some((name, sz)) => {
                    let dta = cpu.far_to_linear(state.dos_dta.0, state.dos_dta.1);
                    let _ = mmu.store8(dta.wrapping_add(0x15), 0x20); // attr=archive
                    for o in [0x16u32, 0x18] {
                        let _ = mmu.store16(dta.wrapping_add(o), 0);
                    }
                    let _ = mmu.store16(dta.wrapping_add(0x1A), sz as u16);
                    let _ = mmu.store16(dta.wrapping_add(0x1C), (sz >> 16) as u16);
                    write_guest_cstr(mmu, dta.wrapping_add(0x1E), 13, name.as_bytes()).ok();
                }
                None => dos_fail(cpu, 18), // no more files
            }
        }
        // AH=0x4F FindNext — single match only; report "no more files".
        0x4F => dos_fail(cpu, 18),
        // AH=0x35 Get interrupt vector → ES:BX = 0:0.
        0x35 => {
            cpu.regs.set16(Reg16::Bx, 0);
            cpu.set_segment_reg(0, 0);
        }
        // AH=0x2A Get date / 0x2C Get time — return zeros (epoch).
        0x2A | 0x2C => {
            cpu.regs.set16(Reg16::Cx, 0);
            cpu.regs.set16(Reg16::Dx, 0);
        }
        // AH=0x39 MkDir(DS:DX path) — the VFS is flat; just succeed.
        0x39 | 0x3B | 0x3A => {}
        // AH=0x43 Get/Set file attributes — succeed (AL=0 get → CX attr 0).
        0x43 => cpu.regs.set16(Reg16::Cx, 0x20),
        // AH=0x3C Create / AH=0x3D Open file (DS:DX path) → AX = handle.
        0x3C | 0x3D => {
            let lin = cpu
                .seg_base(Seg::Ds)
                .wrapping_add(u32::from(cpu.regs.get16(Reg16::Dx)));
            let path = String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 260)).into_owned();
            if std::env::var("UD_NE_DOS_DEBUG").is_ok() {
                eprintln!(
                    "DOS {} {path:?}",
                    if ah == 0x3C { "create" } else { "open" }
                );
            }
            let access = if ah == 0x3C {
                crate::context::FileAccess::Write
            } else {
                crate::context::FileAccess::ReadWrite
            };
            let vfs = state.context.vfs.get_or_insert_with(Default::default);
            // Create truncates; Open requires the file to exist for read.
            if ah == 0x3C {
                vfs.write_path(&path, Vec::new());
            }
            match vfs.open(&path, access) {
                Some(vh) => {
                    let h = state.next_dos_handle;
                    state.next_dos_handle = state.next_dos_handle.wrapping_add(1);
                    state.dos_files.insert(h, vh);
                    cpu.regs.set16(Reg16::Ax, h);
                }
                None => dos_fail(cpu, 2), // ENOENT
            }
        }
        // AH=0x3E Close(BX handle).
        0x3E => {
            let h = cpu.regs.get16(Reg16::Bx);
            if let Some(vh) = state.dos_files.remove(&h) {
                if let Some(vfs) = state.context.vfs.as_mut() {
                    vfs.close(vh);
                }
            }
        }
        // AH=0x3F Read(BX, CX bytes, DS:DX buf) → AX = bytes read.
        0x3F => {
            let h = cpu.regs.get16(Reg16::Bx);
            let cnt = usize::from(cpu.regs.get16(Reg16::Cx));
            let lin = cpu
                .seg_base(Seg::Ds)
                .wrapping_add(u32::from(cpu.regs.get16(Reg16::Dx)));
            let mut buf = vec![0u8; cnt];
            let n = state
                .dos_files
                .get(&h)
                .copied()
                .and_then(|vh| state.context.vfs.as_mut()?.read_handle(vh, &mut buf))
                .unwrap_or(0);
            for (i, &b) in buf.iter().take(n).enumerate() {
                let _ = mmu.store8(lin.wrapping_add(i as u32), b);
            }
            if std::env::var("UD_NE_DOS_DEBUG").is_ok() {
                eprintln!("DOS read h={h} want={cnt} got={n}");
            }
            cpu.regs.set16(Reg16::Ax, n as u16);
        }
        // AH=0x40 Write(BX, CX bytes, DS:DX buf) → AX = bytes written.
        0x40 => {
            let h = cpu.regs.get16(Reg16::Bx);
            let cnt = usize::from(cpu.regs.get16(Reg16::Cx));
            let lin = cpu
                .seg_base(Seg::Ds)
                .wrapping_add(u32::from(cpu.regs.get16(Reg16::Dx)));
            let data: Vec<u8> = (0..cnt)
                .map(|i| mmu.load8(lin.wrapping_add(i as u32)).unwrap_or(0))
                .collect();
            let n = state
                .dos_files
                .get(&h)
                .copied()
                .and_then(|vh| state.context.vfs.as_mut()?.write_handle(vh, &data))
                .unwrap_or(0);
            cpu.regs.set16(Reg16::Ax, n as u16);
        }
        // AH=0x42 LSeek(BX, AL whence, CX:DX offset) → DX:AX = new position.
        0x42 => {
            let h = cpu.regs.get16(Reg16::Bx);
            let whence = cpu.regs.get8(Reg8::Al);
            let off =
                (u32::from(cpu.regs.get16(Reg16::Cx)) << 16) | u32::from(cpu.regs.get16(Reg16::Dx));
            let pos = state
                .dos_files
                .get(&h)
                .copied()
                .and_then(|vh| {
                    state
                        .context
                        .vfs
                        .as_mut()?
                        .seek_handle(vh, off as i32, whence)
                })
                .unwrap_or(0);
            if std::env::var("UD_NE_DOS_DEBUG").is_ok() {
                eprintln!("DOS seek h={h} whence={whence} off={off:#x} -> {pos:#x}");
            }
            cpu.regs.set16(Reg16::Ax, pos as u16);
            cpu.regs.set16(Reg16::Dx, (pos >> 16) as u16);
        }
        // Anything else: report success with AX cleared.
        _ => cpu.regs.set16(Reg16::Ax, 0),
    }
}

/// DOS error return: set carry and the error code in AX.
fn dos_fail(cpu: &mut Cpu, code: u16) {
    cpu.regs.flags.cf = true;
    cpu.regs.set16(Reg16::Ax, code);
}

/// Resolve a DOS `FindFirst` pathspec to a `(basename, size)` match in the
/// VFS. Handles an exact path, and a `*`/`?` pattern by matching the first
/// file sharing the spec's directory prefix.
fn dos_find_match(vfs: &crate::context::VirtualFs, spec: &str) -> Option<(String, u32)> {
    let base = |p: &str| {
        p.rsplit(['\\', '/'])
            .next()
            .unwrap_or(p)
            .to_ascii_uppercase()
    };
    if !spec.contains('*') && !spec.contains('?') {
        return vfs.read(spec).map(|b| (base(spec), b.len() as u32));
    }
    // Wildcard: compare directory prefixes case-insensitively, treating
    // '\' and '/' the same.
    let norm = |s: &str| s.replace('\\', "/").to_ascii_lowercase();
    let dir = norm(spec.rsplit_once(['\\', '/']).map_or("", |(d, _)| d));
    for (path, len) in vfs.list() {
        let p = norm(path);
        let pdir = p.rsplit_once('/').map_or("", |(d, _)| d);
        if pdir == dir.trim_start_matches(|c| c == 'c' || c == ':' || c == '/') {
            return Some((base(path), len as u32));
        }
    }
    None
}

/// `KERNEL` (KRNL286/KRNL386) ordinal stubs.
fn register_kernel(registry: &mut Registry) {
    // KERNEL.91 InitTask() — no args.
    registry.register_far_pascal("kernel", "@91", stub_init_task, 0);
    // KERNEL.23 LockSegment(seg) — lock a segment so it can't move; in
    // the sandbox segments never move, so just hand back a non-zero
    // selector (the current DGROUP) for success.
    registry.register_far_pascal("kernel", "@23", stub_lock_segment, 2);
    // KERNEL.24 UnlockSegment(seg) — inverse of LockSegment.
    registry.register_far_pascal("kernel", "@24", stub_ret0_1word, 2);
    // KERNEL.30 WaitEvent(HTASK) — yield until an event is posted; in
    // the single-task sandbox there is nothing to wait for.
    registry.register_far_pascal("kernel", "@30", stub_ret0_1word, 2);
    // KERNEL.3 GetVersion() → Windows 3.10 in AX (LOBYTE major, HIBYTE
    // minor), DOS version in DX.
    registry.register_far_pascal("kernel", "@3", stub_get_version, 0);
    // KERNEL.15 GlobalAlloc(wFlags, dwBytes) → HGLOBAL (a selector).
    registry.register_far_pascal("kernel", "@15", stub_global_alloc, 6);
    // KERNEL.16 GlobalReAlloc(hMem, dwBytes, wFlags) → HGLOBAL.
    registry.register_far_pascal("kernel", "@16", stub_global_realloc, 8);
    // KERNEL.17 GlobalFree(hMem) → 0 on success.
    registry.register_far_pascal("kernel", "@17", stub_ret0_1word, 2);
    // KERNEL.18 GlobalLock(hMem) → far pointer selector:0000.
    registry.register_far_pascal("kernel", "@18", stub_global_lock, 2);
    // KERNEL.19 GlobalUnlock(hMem) → 0.
    registry.register_far_pascal("kernel", "@19", stub_ret0_1word, 2);
    // KERNEL.20 GlobalSize(hMem) → block size in bytes (DX:AX).
    registry.register_far_pascal("kernel", "@20", stub_global_size, 2);
    // KERNEL.49 GetModuleFileName(hInst, lpFilename far, nSize) → length.
    registry.register_far_pascal("kernel", "@49", stub_get_module_filename, 8);
    // KERNEL.131 GetExePtr(handle) → the owning module handle. Echo the
    // segment/handle back (non-zero) so the caller treats it as valid.
    registry.register_far_pascal("kernel", "@131", stub_echo_1word, 2);
    // KERNEL.89 lstrcat(lpString1 far, lpString2 far) → lpString1.
    registry.register_far_pascal("kernel", "@89", stub_lstrcat, 8);
    // KERNEL.90 lstrlen(lpString far) → length.
    registry.register_far_pascal("kernel", "@90", stub_lstrlen, 4);
    // KERNEL.137 FatalAppExit(uAction, lpMessageText far).
    registry.register_far_pascal("kernel", "@137", stub_fatal_app_exit, 6);
    // KERNEL.47 GetModuleHandle(lpModuleName far) → hModule.
    registry.register_far_pascal("kernel", "@47", stub_get_module_handle, 4);
    // KERNEL.36 GetCurrentTask() → hTask.
    registry.register_far_pascal("kernel", "@36", stub_get_current_task, 0);
    // KERNEL.55 Catch(lpCatchBuf) / KERNEL.56 Throw(lpCatchBuf, nThrowBack)
    // — MFC/C setjmp / longjmp.
    registry.register_far_pascal("kernel", "@55", stub_catch, 4);
    registry.register_far_pascal("kernel", "@56", stub_throw, 6);
    // KERNEL.107 SetErrorMode(word) → previous mode (0).
    registry.register_far_pascal("kernel", "@107", stub_ret0_1word, 2);
    // KERNEL.132 GetWinFlags() → system capability flags.
    registry.register_far_pascal("kernel", "@132", stub_get_win_flags, 0);
    // Resource access: FindResource/LoadResource/LockResource/…
    registry.register_far_pascal("kernel", "@60", stub_find_resource, 10);
    registry.register_far_pascal("kernel", "@61", stub_load_resource, 4);
    registry.register_far_pascal("kernel", "@62", stub_lock_resource, 2);
    registry.register_far_pascal("kernel", "@63", stub_free_resource, 2);
    registry.register_far_pascal("kernel", "@65", stub_sizeof_resource, 4);
    // KERNEL.134 GetWindowsDirectory / KERNEL.135 GetSystemDirectory.
    registry.register_far_pascal("kernel", "@134", stub_get_windows_dir, 6);
    registry.register_far_pascal("kernel", "@135", stub_get_system_dir, 6);
}

/// `KERNEL.134 GetWindowsDirectory(lpBuffer far, uSize)` → "C:\\WINDOWS".
fn stub_get_windows_dir(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let n = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf = far_arg_linear(cpu, mmu, 6);
    write_guest_cstr(mmu, buf, n, b"C:\\WINDOWS")
}

/// `KERNEL.135 GetSystemDirectory(lpBuffer far, uSize)` → "C:\\WINDOWS\\SYSTEM".
fn stub_get_system_dir(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let n = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf = far_arg_linear(cpu, mmu, 6);
    write_guest_cstr(mmu, buf, n, b"C:\\WINDOWS\\SYSTEM")
}

/// Generic FAR PASCAL stub returning its single word argument unchanged
/// (handle/selector echo functions like `GetExePtr`).
fn stub_echo_1word(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(u32::from(cpu.stack_word(mmu, 4).unwrap_or(0)))
}

/// `KERNEL.49 GetModuleFileName(hInst, lpFilename, nSize)` — write a
/// plausible module path into the guest buffer and return its length.
fn stub_get_module_filename(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL stack: nSize (SP+4), lpFilename off (SP+6) / sel (SP+8).
    let n_size = cpu.stack_word(mmu, 4).unwrap_or(0);
    let off = cpu.stack_word(mmu, 6).unwrap_or(0);
    let sel = cpu.stack_word(mmu, 8).unwrap_or(0);
    let lin = cpu.far_to_linear(sel, off);
    write_guest_cstr(mmu, lin, n_size, b"C:\\SITEX10.EXE")
}

/// Write `text` (NUL-terminated) into a guest buffer of `max` bytes at
/// linear `addr`; returns the number of characters written (excluding
/// the terminator).
fn write_guest_cstr(mmu: &mut Mmu, addr: u32, max: u16, text: &[u8]) -> Result<u32, Win32Error> {
    if max == 0 {
        return Ok(0);
    }
    let limit = usize::from(max).saturating_sub(1).min(text.len());
    for (i, &b) in text.iter().take(limit).enumerate() {
        let _ = mmu.store8(addr.wrapping_add(i as u32), b);
    }
    let _ = mmu.store8(addr.wrapping_add(limit as u32), 0);
    Ok(limit as u32)
}

/// Read a NUL-terminated guest string at linear `addr` (capped).
fn read_guest_cstr(mmu: &Mmu, addr: u32, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..max as u32 {
        match mmu.load8(addr.wrapping_add(i)) {
            Ok(0) | Err(_) => break,
            Ok(b) => out.push(b),
        }
    }
    out
}

/// Resolve a FAR PASCAL far-pointer arg (segment:offset packed as a stack
/// dword, offset in the low word) to a linear address.
fn far_arg_linear(cpu: &Cpu, mmu: &Mmu, byte_off: u32) -> u32 {
    let v = cpu.stack_dword(mmu, byte_off).unwrap_or(0);
    cpu.far_to_linear((v >> 16) as u16, v as u16)
}

/// `KERNEL.137 FatalAppExit(uAction, lpMessageText)` — the app is
/// aborting. Record the message (it never returns on real Windows).
fn stub_fatal_app_exit(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: uAction(SP+8), lpMessageText far(SP+4).
    let lin = far_arg_linear(cpu, mmu, 4);
    let msg = String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 1024)).into_owned();
    state.message_box_log.push(format!("FatalAppExit: {msg}"));
    Err(Win32Error::InvalidArgument {
        stub: "FatalAppExit",
        reason: msg,
    })
}

/// `KERNEL.90 lstrlen(lpString far)` → the string length.
fn stub_lstrlen(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let lin = far_arg_linear(cpu, mmu, 4);
    Ok(read_guest_cstr(mmu, lin, 0x8000).len() as u32)
}

/// `KERNEL.89 lstrcat(lpString1, lpString2)` → append string2 to string1
/// in place; returns the far pointer to string1 (DX:AX).
fn stub_lstrcat(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: lpString1 pushed first (SP+8), lpString2 last (SP+4).
    let dst_ptr = cpu.stack_dword(mmu, 8).unwrap_or(0);
    let dst_lin = cpu.far_to_linear((dst_ptr >> 16) as u16, dst_ptr as u16);
    let src_lin = far_arg_linear(cpu, mmu, 4);
    let src = read_guest_cstr(mmu, src_lin, 0x4000);
    // Find the existing terminator of the destination.
    let mut end = dst_lin;
    while !matches!(mmu.load8(end), Ok(0) | Err(_)) {
        end = end.wrapping_add(1);
    }
    for (i, &b) in src.iter().enumerate() {
        let _ = mmu.store8(end.wrapping_add(i as u32), b);
    }
    let _ = mmu.store8(end.wrapping_add(src.len() as u32), 0);
    Ok(dst_ptr)
}

/// A FAR PASCAL default window procedure (`WndProc(hWnd, msg, wParam,
/// lParam)` — 10 arg bytes in Win16). Stands in for the "original" window
/// proc of predefined control classes that MFC subclasses; returns 0.
fn stub_def_window_proc(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// Far pointer (`selector:offset`) to the default window procedure thunk,
/// registering it on first use. Callable by the guest via the import
/// selector that maps onto the registry's thunk region.
fn default_wndproc_farptr(registry: &mut Registry) -> (u16, u16) {
    let thunk = registry.register_far_pascal("user", "@_defwndproc", stub_def_window_proc, 10);
    (
        crate::ne::IMPORT_SELECTOR,
        (thunk - crate::win32::THUNK_BASE) as u16,
    )
}

/// `USER.404 GetClassInfo(hInstance, lpClassName, lpWndClass)` → BOOL. We
/// report every queried class as registered and fill the caller's
/// `WNDCLASS` with a default window procedure so MFC's subclassing of
/// predefined controls has a valid proc to chain to.
fn stub_get_class_info(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hInstance (SP+10), lpClassName far (SP+6), lpWndClass far (SP+4).
    let out = far_arg_linear(cpu, mmu, 4);
    let (sel, off) = default_wndproc_farptr(registry);
    // Win16 WNDCLASS: style@0, lpfnWndProc@2 (off@2, sel@4).
    let _ = mmu.load16(out); // touch to fault early if unmapped
    let _ = mmu.store16(out, 0); // style
    let _ = mmu.store16(out.wrapping_add(2), off);
    let _ = mmu.store16(out.wrapping_add(4), sel);
    Ok(1)
}

/// `USER.57 RegisterClass(lpWndClass far)` → an ATOM. Parses the Win16
/// `WNDCLASS` (16-bit `style`), records the class + its window procedure
/// in the headless GUI model, and returns a non-zero atom.
fn stub_register_class(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let wc = far_arg_linear(cpu, mmu, 4);
    // Win16 WNDCLASS: style WORD@0, lpfnWndProc FAR@2, cbClsExtra@6,
    // cbWndExtra@8, hInstance@10, hIcon@12, hCursor@14, hbrBackground@16,
    // lpszMenuName FAR@18, lpszClassName FAR@22.
    let style = u32::from(mmu.load16(wc).unwrap_or(0));
    let wndproc_off = mmu.load16(wc.wrapping_add(2)).unwrap_or(0);
    let wndproc_sel = mmu.load16(wc.wrapping_add(4)).unwrap_or(0);
    let name_off = mmu.load16(wc.wrapping_add(22)).unwrap_or(0);
    let name_sel = mmu.load16(wc.wrapping_add(24)).unwrap_or(0);
    let name_lin = cpu.far_to_linear(name_sel, name_off);
    let name = String::from_utf8_lossy(&read_guest_cstr(mmu, name_lin, 256)).into_owned();
    state
        .gui
        .register_class(&name, wndproc_sel, wndproc_off, style);
    Ok(u32::from(state.gui.alloc_obj_handle()))
}

/// `USER.291 SetWindowsHookEx(idHook, lpfn, hMod, hTask)` → an HHOOK. We
/// don't actually dispatch hooks, but MFC stores the handle to unhook on
/// exit, so return a unique non-zero handle.
fn stub_set_windows_hook_ex(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(u32::from(state.gui.alloc_obj_handle()))
}

/// A resource parsed from the loaded NE module, with its data.
#[derive(Debug, Clone)]
pub struct LoadedResource {
    pub type_id: ud_format::ne::ResId,
    pub name_id: ud_format::ne::ResId,
    pub data: Vec<u8>,
}

/// Read a FAR PASCAL resource-id argument (a `segment:offset` packed as a
/// stack dword): a zero selector means an integer id in the offset,
/// otherwise the offset points at a NUL-terminated name string.
fn res_id_arg(cpu: &Cpu, mmu: &Mmu, byte_off: u32) -> ud_format::ne::ResId {
    use ud_format::ne::ResId;
    let v = cpu.stack_dword(mmu, byte_off).unwrap_or(0);
    let selector = (v >> 16) as u16;
    if selector == 0 {
        ResId::Int(v as u16)
    } else {
        let lin = cpu.far_to_linear(selector, v as u16);
        ResId::Name(String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 256)).into_owned())
    }
}

/// Compare two resource ids, treating names case-insensitively (Win16
/// resource lookup is case-insensitive).
fn res_id_eq(a: &ud_format::ne::ResId, b: &ud_format::ne::ResId) -> bool {
    use ud_format::ne::ResId;
    match (a, b) {
        (ResId::Int(x), ResId::Int(y)) => x == y,
        (ResId::Name(x), ResId::Name(y)) => x.eq_ignore_ascii_case(y),
        _ => false,
    }
}

/// `KERNEL.60 FindResource(hModule, lpName, lpType)` → an HRSRC (the
/// 1-based resource index, 0 if not found).
fn stub_find_resource(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL far pointers don't overlap: lpType far (SP+4), lpName far
    // (SP+8), hModule (SP+12).
    let want_type = res_id_arg(cpu, mmu, 4);
    let want_name = res_id_arg(cpu, mmu, 8);
    let hrsrc = state
        .resources
        .iter()
        .position(|r| res_id_eq(&r.type_id, &want_type) && res_id_eq(&r.name_id, &want_name))
        .map_or(0, |i| i as u32 + 1);
    if std::env::var("UD_NE_STUB_DEBUG").is_ok() {
        eprintln!("FindResource type={want_type:?} name={want_name:?} -> {hrsrc}");
    }
    Ok(hrsrc)
}

/// `KERNEL.61 LoadResource(hModule, hResInfo)` → an HGLOBAL holding a copy
/// of the resource bytes (0 if the handle is invalid).
fn stub_load_resource(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hModule (SP+6), hResInfo (SP+4).
    let hrsrc = cpu.stack_word(mmu, 4).unwrap_or(0);
    let Some(res) = state.resources.get(hrsrc.wrapping_sub(1) as usize) else {
        return Ok(0);
    };
    let data = res.data.clone();
    let sel = state.win16_heap.alloc(cpu, mmu, data.len() as u32);
    let base = cpu.far_to_linear(sel, 0);
    for (i, &b) in data.iter().enumerate() {
        let _ = mmu.store8(base.wrapping_add(i as u32), b);
    }
    Ok(u32::from(sel))
}

/// `KERNEL.62 LockResource(hResData)` → a far pointer to the resource
/// bytes. `hResData` is the HGLOBAL selector from `LoadResource`, so the
/// pointer is simply `selector:0`.
fn stub_lock_resource(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let sel = _cpu.stack_word(_mmu, 4).unwrap_or(0);
    // DX:AX = selector:offset → far pointer to offset 0 of the block.
    Ok(u32::from(sel) << 16)
}

/// `KERNEL.65 SizeofResource(hModule, hResInfo)` → the resource length.
fn stub_sizeof_resource(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hrsrc = cpu.stack_word(mmu, 4).unwrap_or(0);
    let size = state
        .resources
        .get(hrsrc.wrapping_sub(1) as usize)
        .map_or(0, |r| r.data.len() as u32);
    Ok(size)
}

/// `KERNEL.63 FreeResource(hResData)` → 0 (we leave the global block
/// mapped; nothing to do).
fn stub_free_resource(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `KERNEL.55 Catch(lpCatchBuf)` — MFC/C `setjmp`. Saves the resume
/// context (return `CS:IP`, `SS:SP`, `BP`, `SI`, `DI`, `DS`, `ES`) into
/// the caller's opaque buffer and returns 0. A later [`stub_throw`]
/// restores it. The buffer layout is private to this pair.
fn stub_catch(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    use crate::emulator::isa_int::Seg;
    let ret_off = cpu.stack_word(mmu, 0).unwrap_or(0);
    let ret_seg = cpu.stack_word(mmu, 2).unwrap_or(0);
    let buf_off = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf_seg = cpu.stack_word(mmu, 6).unwrap_or(0);
    let buf = cpu.far_to_linear(buf_seg, buf_off);
    // SP the guest will have once Catch returns and cleans its 4 arg
    // bytes: current SP + 4 (far return addr) + 4 (arg).
    let sp_after = (cpu.regs.get16(Reg16::Sp)).wrapping_add(8);
    let w = |mmu: &mut Mmu, off: u32, v: u16| {
        let _ = mmu.store16(buf.wrapping_add(off), v);
    };
    w(mmu, 0, sp_after);
    w(mmu, 2, cpu.segment_selector(Seg::Ss));
    w(mmu, 4, cpu.regs.get16(Reg16::Bp));
    w(mmu, 6, cpu.regs.get16(Reg16::Si));
    w(mmu, 8, cpu.regs.get16(Reg16::Di));
    w(mmu, 10, cpu.segment_selector(Seg::Ds));
    w(mmu, 12, cpu.segment_selector(Seg::Es));
    w(mmu, 14, ret_off);
    w(mmu, 16, ret_seg);
    Ok(0)
}

/// `KERNEL.56 Throw(lpCatchBuf, nThrowBack)` — MFC/C `longjmp`. Restores
/// the context saved by [`stub_catch`] and resumes at the Catch site with
/// `AX = nThrowBack`. Implemented by restoring the registers and crafting
/// the stack so the dispatcher's far-return lands at the saved `CS:IP`.
fn stub_throw(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    use crate::emulator::isa_int::Seg;
    // PASCAL: lpCatchBuf (SP+6), nThrowBack (SP+4).
    let throwback = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf_off = cpu.stack_word(mmu, 6).unwrap_or(0);
    let buf_seg = cpu.stack_word(mmu, 8).unwrap_or(0);
    let buf = cpu.far_to_linear(buf_seg, buf_off);
    let r = |mmu: &Mmu, off: u32| mmu.load16(buf.wrapping_add(off)).unwrap_or(0);
    let saved_sp = r(mmu, 0);
    let saved_ss = r(mmu, 2);
    let saved_bp = r(mmu, 4);
    let saved_si = r(mmu, 6);
    let saved_di = r(mmu, 8);
    let saved_ds = r(mmu, 10);
    let saved_es = r(mmu, 12);
    let ret_off = r(mmu, 14);
    let ret_seg = r(mmu, 16);
    cpu.regs.set16(Reg16::Bp, saved_bp);
    cpu.regs.set16(Reg16::Si, saved_si);
    cpu.regs.set16(Reg16::Di, saved_di);
    cpu.load_segment(Seg::Ds, saved_ds);
    cpu.load_segment(Seg::Es, saved_es);
    // Craft the stack so the dispatcher's far-return (which pops CS:IP and
    // cleans Throw's 6 arg bytes) lands at ret_seg:ret_off with SP =
    // saved_sp: final SP = sp_new + 4 + 6, so sp_new = saved_sp - 10.
    let sp_new = saved_sp.wrapping_sub(10);
    cpu.set_ss_sp(saved_ss, sp_new);
    let ss_base = cpu.seg_base(Seg::Ss);
    let _ = mmu.store16(ss_base.wrapping_add(u32::from(sp_new)), ret_off);
    let _ = mmu.store16(
        ss_base.wrapping_add(u32::from(sp_new)).wrapping_add(2),
        ret_seg,
    );
    // Returned in AX (DX cleared) — the value Catch "returns" the 2nd time.
    Ok(u32::from(throwback))
}

/// `USER.32 GetWindowRect(hWnd, lpRect far)` → fill a plausible screen
/// rectangle (the dialog uses it for centering).
fn stub_get_window_rect(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hWnd(SP+8), lpRect far(SP+4). RECT = left,top,right,bottom.
    let r = far_arg_linear(cpu, mmu, 4);
    for (i, v) in [0u16, 0, 640, 480].iter().enumerate() {
        let _ = mmu.store16(r.wrapping_add(i as u32 * 2), *v);
    }
    Ok(1)
}

/// `USER.111 SendMessage(hWnd, msg, wParam, lParam)` → route a message to
/// our headless control model. Handles the text and button-check messages
/// the dialog uses; everything else returns 0.
fn stub_send_message(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL (10 bytes): hWnd(SP+12), msg(SP+10), wParam(SP+8), lParam(SP+4).
    let hwnd = cpu.stack_word(mmu, 12).unwrap_or(0);
    let msg = cpu.stack_word(mmu, 10).unwrap_or(0);
    let wparam = cpu.stack_word(mmu, 8).unwrap_or(0);
    let lparam = cpu.stack_dword(mmu, 4).unwrap_or(0);
    let lp_lin = || cpu.far_to_linear((lparam >> 16) as u16, lparam as u16);
    match msg {
        0x000C => {
            // WM_SETTEXT: lParam → text.
            let text = String::from_utf8_lossy(&read_guest_cstr(mmu, lp_lin(), 1024)).into_owned();
            if let Some(w) = state.gui.windows.get_mut(&hwnd) {
                w.title = text;
            }
            Ok(1)
        }
        0x000D => {
            // WM_GETTEXT: wParam = max, lParam = buffer.
            let text = state
                .gui
                .windows
                .get(&hwnd)
                .map(|w| w.title.clone())
                .unwrap_or_default();
            write_guest_cstr(mmu, lp_lin(), wparam, text.as_bytes())
        }
        0x000E => {
            // WM_GETTEXTLENGTH.
            Ok(state
                .gui
                .windows
                .get(&hwnd)
                .map_or(0, |w| w.title.len() as u32))
        }
        0x00F0 => Ok(u32::from(
            state.dialog_checks.get(&hwnd).copied().unwrap_or(0),
        )), // BM_GETCHECK
        0x00F1 => {
            // BM_SETCHECK.
            state.dialog_checks.insert(hwnd, wparam);
            Ok(0)
        }
        _ => Ok(0),
    }
}

/// `USER.91 GetDlgItem(hDlg, nID)` → the child control's HWND (0 if none).
fn stub_get_dlg_item(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hDlg (SP+6), nID (SP+4).
    let id = cpu.stack_word(mmu, 4).unwrap_or(0);
    Ok(u32::from(state.dialog_items.get(&id).copied().unwrap_or(0)))
}

/// `USER.93 GetDlgItemText(hDlg, nID, lpString far, nMax)` → copy a
/// control's text; returns the length copied.
fn stub_get_dlg_item_text(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hDlg(SP+12), nID(SP+10), lpString far(SP+6), nMax(SP+4).
    let n_max = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf = far_arg_linear(cpu, mmu, 6);
    let id = cpu.stack_word(mmu, 10).unwrap_or(0);
    let text = state
        .dialog_items
        .get(&id)
        .and_then(|h| state.gui.windows.get(h))
        .map(|w| w.title.clone())
        .unwrap_or_default();
    if n_max == 0 {
        return Ok(0);
    }
    write_guest_cstr(mmu, buf, n_max, text.as_bytes())
}

/// `USER.92 SetDlgItemText(hDlg, nID, lpString far)` → set a control's text.
fn stub_set_dlg_item_text(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hDlg(SP+8), nID(SP+6), lpString far(SP+4).
    let lin = far_arg_linear(cpu, mmu, 4);
    let id = cpu.stack_word(mmu, 6).unwrap_or(0);
    let text = String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 1024)).into_owned();
    if let Some(&hwnd) = state.dialog_items.get(&id) {
        if let Some(w) = state.gui.windows.get_mut(&hwnd) {
            w.title = text.clone();
        }
        state
            .gui
            .events
            .push(gui::GuiEvent::SetWindowText { hwnd, text });
    }
    Ok(1)
}

/// `USER.38 GetWindowTextLength(hWnd)` → the window text length.
fn stub_get_window_text_length(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hwnd = cpu.stack_word(mmu, 4).unwrap_or(0);
    Ok(state
        .gui
        .windows
        .get(&hwnd)
        .map_or(0, |w| w.title.len() as u32))
}

/// `USER.36 GetWindowText(hWnd, lpString far, nMax)` → copy the window's
/// text into the buffer; returns the length copied.
fn stub_get_window_text(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hWnd (SP+8), lpString far (SP+4), nMax (... )? Layout:
    // hWnd(SP+8), lpString off(SP+6)/sel(SP+? ) — GetWindowText(hwnd, lp, max):
    // hWnd(SP+10), lpString far(SP+6), nMax(SP+4).
    let n_max = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf = far_arg_linear(cpu, mmu, 6);
    let hwnd = cpu.stack_word(mmu, 10).unwrap_or(0);
    let text = state
        .gui
        .windows
        .get(&hwnd)
        .map(|w| w.title.clone())
        .unwrap_or_default();
    if n_max == 0 {
        return Ok(0);
    }
    write_guest_cstr(mmu, buf, n_max, text.as_bytes())
}

/// `USER.37 SetWindowText(hWnd, lpString far)` → set the window text.
fn stub_set_window_text(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hWnd (SP+8), lpString far (SP+4).
    let lin = far_arg_linear(cpu, mmu, 4);
    let hwnd = cpu.stack_word(mmu, 8).unwrap_or(0);
    let text = String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 1024)).into_owned();
    if let Some(w) = state.gui.windows.get_mut(&hwnd) {
        w.title = text.clone();
    }
    state
        .gui
        .events
        .push(gui::GuiEvent::SetWindowText { hwnd, text });
    Ok(1)
}

/// `USER.1 MessageBox(hWnd, lpText, lpCaption, wType)` → record the prompt
/// in the GUI transcript and answer affirmatively (IDOK/IDYES) so the
/// installer proceeds.
fn stub_message_box(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL (12 bytes): hWnd(SP+14), lpText far(SP+10), lpCaption far(SP+6),
    // wType(SP+4).
    let wtype = cpu.stack_word(mmu, 4).unwrap_or(0);
    let cap_lin = far_arg_linear(cpu, mmu, 6);
    let text_lin = far_arg_linear(cpu, mmu, 10);
    let caption = String::from_utf8_lossy(&read_guest_cstr(mmu, cap_lin, 512)).into_owned();
    let text = String::from_utf8_lossy(&read_guest_cstr(mmu, text_lin, 2048)).into_owned();
    // Affirmative default per button set (low nibble of wType).
    let result: u16 = match wtype & 0x000F {
        3 | 4 => 6, // MB_YESNO[CANCEL] → IDYES
        5 => 4,     // MB_RETRYCANCEL → IDRETRY
        _ => 1,     // → IDOK
    };
    state.message_box_log.push(format!("[{caption}] {text}"));
    state.gui.events.push(gui::GuiEvent::MessageBox {
        caption,
        text,
        flags: wtype,
        result,
    });
    Ok(u32::from(result))
}

/// `WM_INITDIALOG` / `WM_COMMAND` message ids.
const WM_INITDIALOG: u16 = 0x0110;
const WM_COMMAND: u16 = 0x0111;

/// `USER.87 DialogBox(hInstance, lpTemplate, hWndParent, lpDialogFunc)` →
/// run a modal dialog. We parse its template into the headless GUI model,
/// invoke the dialog procedure for `WM_INITDIALOG`, then auto-drive it by
/// posting the default command until it calls `EndDialog`. Returns the
/// `EndDialog` result.
/// `USER.89 CreateDialog(hInstance, lpTemplate, hWndParent, lpDialogFunc)`
/// → HWND of a *modeless* dialog (e.g. the install progress box). Records
/// it, creates its controls, attaches the MFC CWnd and delivers
/// WM_INITDIALOG, then returns the window handle (the program pumps it
/// itself). Off the drive path it just records the dialog.
fn stub_create_dialog(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let proc_off = cpu.stack_word(mmu, 4).unwrap_or(0);
    let proc_sel = cpu.stack_word(mmu, 6).unwrap_or(0);
    let tmpl_off = cpu.stack_word(mmu, 10).unwrap_or(0);
    let tmpl_sel = cpu.stack_word(mmu, 12).unwrap_or(0);
    let this_sel = cpu.segment_selector(crate::emulator::isa_int::Seg::Es);
    let this_off = cpu.regs.get16(Reg16::Bx);
    let want = if tmpl_sel == 0 {
        ud_format::ne::ResId::Int(tmpl_off)
    } else {
        let lin = cpu.far_to_linear(tmpl_sel, tmpl_off);
        ud_format::ne::ResId::Name(
            String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 256)).into_owned(),
        )
    };
    let dlg = state
        .resources
        .iter()
        .find(|r| r.type_id == ud_format::ne::ResId::Int(5) && res_id_eq(&r.name_id, &want))
        .map(|r| r.data.clone());
    let (title, controls) = dlg
        .as_deref()
        .map_or_else(|| (String::new(), Vec::new()), gui::parse_dialog_template);
    state.gui.events.push(gui::GuiEvent::DialogStart {
        title,
        controls: controls.clone(),
    });
    let hdlg = state.gui.alloc_hwnd();
    // Record the controls so GetDlgItem on the modeless dialog resolves
    // (the installer updates the progress text via SetDlgItemText). We
    // don't run the dialog procedure here — a modeless dialog is pumped by
    // the program's own message loop, and the progress UI isn't needed for
    // the extraction to proceed.
    for c in &controls {
        let chwnd = state
            .gui
            .create_window(&c.class, &c.text, hdlg, c.id, c.style);
        state.dialog_items.insert(c.id, chwnd);
    }
    let _ = (proc_sel, proc_off, this_sel, this_off, registry);
    Ok(u32::from(hdlg))
}

fn stub_dialog_box(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL (12 bytes): hInstance(SP+14), lpTemplate far(off SP+10/sel SP+12),
    // hWndParent(SP+8), lpDialogFunc far(off SP+4/sel SP+6).
    let proc_off = cpu.stack_word(mmu, 4).unwrap_or(0);
    let proc_sel = cpu.stack_word(mmu, 6).unwrap_or(0);
    let tmpl_off = cpu.stack_word(mmu, 10).unwrap_or(0);
    let tmpl_sel = cpu.stack_word(mmu, 12).unwrap_or(0);
    // MFC's `CWnd::DoModal` keeps the dialog object (`this`) in ES:BX right
    // up to the `DialogBox` call; capture it so the drive path can attach
    // it to the synthetic HWND in MFC's handle map.
    let this_sel = cpu.segment_selector(crate::emulator::isa_int::Seg::Es);
    let this_off = cpu.regs.get16(Reg16::Bx);

    // Resolve the template id (integer resource or a name string).
    let want = if tmpl_sel == 0 {
        ud_format::ne::ResId::Int(tmpl_off)
    } else {
        let lin = cpu.far_to_linear(tmpl_sel, tmpl_off);
        ud_format::ne::ResId::Name(
            String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 256)).into_owned(),
        )
    };
    // Find the RT_DIALOG (type 5) resource whose name matches.
    let dlg = state
        .resources
        .iter()
        .find(|r| r.type_id == ud_format::ne::ResId::Int(5) && res_id_eq(&r.name_id, &want))
        .map(|r| r.data.clone());
    let (title, controls) = dlg
        .as_deref()
        .map_or_else(|| (String::new(), Vec::new()), gui::parse_dialog_template);
    state.gui.events.push(gui::GuiEvent::DialogStart {
        title,
        controls: controls.clone(),
    });

    // Driving the dialog procedure requires MFC's HWND→CWnd handle map
    // (populated by its CBT hook during real window creation), which we
    // don't yet emulate — the proc dereferences a null CWnd on
    // WM_INITDIALOG. So by default we only record the dialog and report
    // success (IDOK), letting the installer's main flow proceed. Set
    // UD_NE_DRIVE_DIALOG=1 to attempt the (currently incomplete) drive.
    if std::env::var("UD_NE_DRIVE_DIALOG").is_ok() {
        let hdlg = state.gui.alloc_hwnd();
        state.dialog_ended = false;
        state.dialog_result = 0;
        // Create a child window for every control so GetDlgItem resolves,
        // mapping control id → HWND. Seed the destination-directory edit
        // control with a default install path (the dialog input an
        // expect-style driver would supply).
        state.dialog_items.clear();
        let dest_dir = std::env::var("UD_NE_INSTALL_DIR").unwrap_or_else(|_| "C:\\EXPANDER".into());
        for c in &controls {
            let initial = if c.class.eq_ignore_ascii_case("Edit") {
                dest_dir.as_str()
            } else {
                c.text.as_str()
            };
            let chwnd = state
                .gui
                .create_window(&c.class, initial, hdlg, c.id, c.style);
            state.dialog_items.insert(c.id, chwnd);
        }
        // Replicate MFC's CBT-hook attach: register hdlg → the dialog
        // object in the handle map by calling CWnd::Attach (the function
        // right after FromHandle in the same code segment), so the proc's
        // FromHandle(hdlg) resolves. Args (FAR PASCAL): this.off, this.sel,
        // hwnd.
        let attach_off = mfc_attach_offset();
        call_guest_far16(
            cpu,
            mmu,
            registry,
            state,
            proc_sel,
            attach_off,
            &[hdlg, this_sel, this_off],
        )
        .map_err(|e| Win32Error::InvalidArgument {
            stub: "DialogBox/attach",
            reason: e.to_string(),
        })?;
        // WM_SETFONT then WM_INITDIALOG, then drive the default / OK / Cancel
        // commands until the proc calls EndDialog.
        deliver_message(
            cpu, mmu, registry, state, proc_sel, proc_off, hdlg, 0x0030, 0, 0,
        )?;
        deliver_message(
            cpu,
            mmu,
            registry,
            state,
            proc_sel,
            proc_off,
            hdlg,
            WM_INITDIALOG,
            0,
            0,
        )?;
        let mut order: Vec<u16> = controls
            .iter()
            .filter(|c| c.class.eq_ignore_ascii_case("Button") && c.style & 0x000F == 1)
            .map(|c| c.id)
            .collect();
        order.extend([1u16, 2u16]); // IDOK, IDCANCEL
        let dbg = std::env::var("UD_NE_DOS_DEBUG").is_ok();
        // The dialog-init proc (lpDialogFunc) only handles WM_INITDIALOG /
        // WM_SETFONT; it subclasses the window to MFC's AfxWndProc, which
        // is what routes WM_COMMAND through the message map to OnOK. Deliver
        // commands there (the wndproc MFC registered for the AfxWnd class).
        let (cmd_sel, cmd_off) = state
            .gui
            .classes
            .get("AfxWnd")
            .map_or((proc_sel, proc_off), |c| (c.wndproc_sel, c.wndproc_off));
        for &id in &order {
            if state.dialog_ended {
                break;
            }
            // WM_COMMAND lParam = MAKELONG(hwndCtl, BN_CLICKED=0).
            let ctl = u32::from(state.dialog_items.get(&id).copied().unwrap_or(0));
            let r = deliver_message(
                cpu, mmu, registry, state, cmd_sel, cmd_off, hdlg, WM_COMMAND, id, ctl,
            )?;
            if dbg {
                eprintln!(
                    "DRIVE WM_COMMAND id={id} -> {r:#x}, dialog_ended={}",
                    state.dialog_ended
                );
            }
        }
        return Ok(u32::from(state.dialog_result as u16));
    }
    let _ = (proc_sel, proc_off, this_sel, this_off);
    Ok(1) // IDOK
}

/// Offset of MFC's `CWnd::Attach` in the StuffIt installer's code segment.
/// Driving the dialog is binary-specific (gated behind UD_NE_DRIVE_DIALOG);
/// this lets the synthetic HWND be registered in MFC's handle map.
fn mfc_attach_offset() -> u16 {
    std::env::var("UD_NE_ATTACH_OFF")
        .ok()
        .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x91a6)
}

/// Deliver one window message to a guest dialog/window procedure
/// (`hwnd, msg, wParam, lParam`) via the FAR PASCAL callback path.
#[allow(clippy::too_many_arguments)]
fn deliver_message(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    registry: &mut Registry,
    state: &mut HostState,
    proc_sel: u16,
    proc_off: u16,
    hwnd: u16,
    msg: u16,
    wparam: u16,
    lparam: u32,
) -> Result<u32, Win32Error> {
    let args = [hwnd, msg, wparam, (lparam >> 16) as u16, lparam as u16];
    call_guest_far16(cpu, mmu, registry, state, proc_sel, proc_off, &args).map_err(|e| {
        Win32Error::InvalidArgument {
            stub: "DialogBox/dlgproc",
            reason: e.to_string(),
        }
    })
}

/// `USER.88 EndDialog(hDlg, nResult)` — mark the active modal dialog as
/// finished with `nResult`; the `DialogBox` driver returns it.
fn stub_end_dialog(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hDlg (SP+6), nResult (SP+4).
    let result = cpu.stack_word(mmu, 4).unwrap_or(0);
    if std::env::var("UD_NE_DOS_DEBUG").is_ok() {
        eprintln!("EndDialog(result={result})");
    }
    state.dialog_ended = true;
    state.dialog_result = result as i16;
    Ok(1)
}

/// First global atom value (matches Win16's `MAXINTATOM`).
const ATOM_BASE: u16 = 0xC000;

/// `USER.268 GlobalAddAtom(lpString far)` → an ATOM. Interns the string in
/// the global atom table (case-insensitive) and returns its atom.
fn stub_global_add_atom(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let lin = far_arg_linear(cpu, mmu, 4);
    let s = String::from_utf8_lossy(&read_guest_cstr(mmu, lin, 256)).into_owned();
    let atom = match state.atoms.iter().position(|a| a.eq_ignore_ascii_case(&s)) {
        Some(i) => ATOM_BASE + i as u16,
        None => {
            state.atoms.push(s);
            ATOM_BASE + (state.atoms.len() as u16 - 1)
        }
    };
    Ok(u32::from(atom))
}

/// `KERNEL.132 GetWinFlags()` → the system capability flags (DWORD).
/// Report protected mode, a 386, enhanced mode and an FPU.
fn stub_get_win_flags(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // WF_PMODE | WF_CPU386 | WF_ENHANCED | WF_80x87.
    Ok(0x0001 | 0x0004 | 0x0020 | 0x0400)
}

/// `KERNEL.36 GetCurrentTask()` → the current task handle (HTASK). We run
/// a single synthetic task.
fn stub_get_current_task(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(u32::from(WIN16_HTASK))
}

/// `KERNEL.47 GetModuleHandle(lpModuleName far)` → the module handle. If
/// the pointer's selector is 0, Win16 treats the offset as a handle and
/// echoes it; otherwise we return our single module's hInstance.
fn stub_get_module_handle(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let v = cpu.stack_dword(mmu, 4).unwrap_or(0);
    let selector = (v >> 16) as u16;
    if selector == 0 {
        return Ok(u32::from(v as u16));
    }
    Ok(u32::from(WIN16_HINSTANCE))
}

/// `USER.176 LoadString(hInstance, uID, lpBuffer, nBufferMax)` → copy a
/// string-table resource into `lpBuffer`; returns the length copied (0 if
/// the id is absent).
fn stub_load_string(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hInstance (SP+12), uID (SP+10), lpBuffer far (SP+6), nMax (SP+4).
    let n_max = cpu.stack_word(mmu, 4).unwrap_or(0);
    let buf_lin = far_arg_linear(cpu, mmu, 6);
    let uid = cpu.stack_word(mmu, 10).unwrap_or(0);
    let text = state
        .string_resources
        .get(&uid)
        .cloned()
        .unwrap_or_default();
    if n_max == 0 {
        return Ok(0);
    }
    write_guest_cstr(mmu, buf_lin, n_max, text.as_bytes())
}

/// `COMMDLG.27 GetFileTitle(lpszFile, lpszTitle, cbBuf)` → copy just the
/// filename portion of a path into `lpszTitle`; returns 0 on success.
fn stub_get_file_title(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: lpszFile (SP+10), lpszTitle (SP+6), cbBuf (SP+4).
    let cb_buf = cpu.stack_word(mmu, 4).unwrap_or(0);
    let title_lin = far_arg_linear(cpu, mmu, 6);
    let file_lin = far_arg_linear(cpu, mmu, 10);
    let path = read_guest_cstr(mmu, file_lin, 0x1000);
    // The title is the run after the last path separator (\ / :).
    let start = path
        .iter()
        .rposition(|&b| b == b'\\' || b == b'/' || b == b':')
        .map_or(0, |p| p + 1);
    let title = &path[start..];
    if u32::from(cb_buf) <= title.len() as u32 {
        // Buffer too small: return required size (incl. terminator).
        return Ok(title.len() as u32 + 1);
    }
    write_guest_cstr(mmu, title_lin, cb_buf, title)?;
    Ok(0)
}

/// `KERNEL.20 GlobalSize(hMem)` → the requested size of the block.
fn stub_global_size(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let handle = cpu.stack_word(mmu, 4).unwrap_or(0);
    let size = state
        .win16_heap
        .blocks
        .get(&handle)
        .map_or(0x1000, |&(_, s)| s);
    Ok(size)
}

/// `KERNEL.15 GlobalAlloc(wFlags, dwBytes)` → a fresh selector/handle
/// backed by a newly-mapped window.
fn stub_global_alloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: wFlags pushed first (SP+8), dwBytes (4) last (SP+4).
    let size = cpu.stack_dword(mmu, 4).unwrap_or(0);
    let sel = state.win16_heap.alloc(cpu, mmu, size);
    Ok(u32::from(sel))
}

/// `KERNEL.16 GlobalReAlloc(hMem, dwBytes, wFlags)` — allocate a new
/// block (we never move existing ones) and return its handle.
fn stub_global_realloc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // PASCAL: hMem (SP+10), dwBytes (4) (SP+6), wFlags (SP+4).
    let h_mem = cpu.stack_word(mmu, 10).unwrap_or(0);
    let size = cpu.stack_dword(mmu, 6).unwrap_or(0);
    let sel = state.win16_heap.realloc(cpu, mmu, h_mem, size);
    Ok(u32::from(sel))
}

/// `KERNEL.18 GlobalLock(hMem)` → the far pointer `selector:0000`
/// (DX = selector, AX = 0).
fn stub_global_lock(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let handle = cpu.stack_word(mmu, 4).unwrap_or(0);
    Ok(u32::from(handle) << 16)
}

/// `KERNEL.23 LockSegment(seg)` → return a non-zero selector (the
/// DGROUP) so the caller treats the lock as successful.
fn stub_lock_segment(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(u32::from(cpu.ds_selector()))
}

/// Generic FAR PASCAL stub that cleans one word of args and returns 0.
fn stub_ret0_1word(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `KERNEL.3 GetVersion()` → `0x0A03` (Windows 3.10) in AX.
fn stub_get_version(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // AX = 0x0A03: major = 0x03, minor = 0x0A (10) → 3.10.
    Ok(0x0003_0A03)
}

/// `KERNEL.91 InitTask()` — called once by the C startup. Sets up the
/// task and returns its parameters in registers. We populate the
/// outputs the startup reads:
///
/// * `AX` = 1 (success)        * `DX` = nCmdShow
/// * `CX` = stack top          * `SI` = hPrevInstance (0 = first)
/// * `DI` = hInstance          * `ES:BX` = command-line far pointer
fn stub_init_task(
    cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    // CX = top of the stack (the C startup does `add cx,0x100`; keep it
    // small so that add doesn't carry).
    cpu.regs.set16(Reg16::Cx, 0);
    // SI = hPrevInstance (0 → this is the first instance).
    cpu.regs.set16(Reg16::Si, 0);
    // DI = hInstance.
    cpu.regs.set16(Reg16::Di, WIN16_HINSTANCE);
    // ES:BX = the PSP and command tail. The C startup reads the
    // environment selector at PSP:0x2C (left 0) and the command tail at
    // PSP:0x80.
    cpu.regs.set16(Reg16::Bx, 0x80);
    cpu.set_segment_reg(0 /* ES */, crate::ne::PSP_SELECTOR);
    // DX:AX — AX = success (1), DX = nCmdShow.
    Ok((u32::from(SW_SHOWNORMAL) << 16) | 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::Cpu;

    #[test]
    fn dos_get_version_sets_al_and_clears_carry() {
        let mut cpu = Cpu::new();
        cpu.regs.flags.cf = true;
        cpu.regs.set8(Reg8::Ah, 0x30); // get DOS version
        let mut mmu = Mmu::new();
        let mut state = HostState::default();
        dos_int21(&mut cpu, &mut mmu, &mut state);
        assert_eq!(cpu.regs.get8(Reg8::Al), 6, "DOS major version in AL");
        assert!(!cpu.regs.flags.cf, "carry cleared on success");
    }

    #[test]
    fn dos_get_current_drive_returns_c() {
        let mut cpu = Cpu::new();
        cpu.regs.set8(Reg8::Ah, 0x19);
        let mut mmu = Mmu::new();
        let mut state = HostState::default();
        dos_int21(&mut cpu, &mut mmu, &mut state);
        assert_eq!(cpu.regs.get8(Reg8::Al), 2, "drive C: (0=A)");
    }

    #[test]
    fn service_interrupt_handles_21h_and_rejects_unknown() {
        let mut cpu = Cpu::new();
        let mut mmu = Mmu::new();
        let mut state = HostState::default();
        cpu.regs.set8(Reg8::Ah, 0x30);
        assert!(service_interrupt(0x21, &mut cpu, &mut mmu, &mut state));
        assert!(!service_interrupt(0x80, &mut cpu, &mut mmu, &mut state));
    }
}

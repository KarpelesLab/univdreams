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

use crate::emulator::regs::{Reg16, Reg8};
use crate::emulator::{Cpu, Mmu};
use crate::win32::{HostState, Registry, Win32Error};

/// Synthetic instance handle handed to the task (Win16 `HINSTANCE`).
/// Real Windows hands back the module's DGROUP selector; any stable
/// non-zero value works for a single-task sandbox.
pub const WIN16_HINSTANCE: u16 = 0x0100;
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
}

/// `GDI` ordinal stubs.
fn register_gdi(registry: &mut Registry) {
    // GDI.80 GetDeviceCaps(hDC, index) — display capabilities MFC reads
    // off the screen DC during startup.
    registry.register_far_pascal("gdi", "@80", stub_get_device_caps, 4);
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
    // USER.179 GetSystemMetrics(index).
    registry.register_far_pascal("user", "@179", stub_get_system_metrics, 2);
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
pub fn service_interrupt(num: u8, cpu: &mut Cpu, _mmu: &mut Mmu, _state: &mut HostState) -> bool {
    match num {
        0x21 => {
            dos_int21(cpu);
            true
        }
        // INT 3 (breakpoint) / INT 0x3F (Win16 inter-segment call thunk,
        // already handled at load) — ignore and continue.
        0x03 => true,
        _ => false,
    }
}

/// Minimal DOS `INT 21h` dispatcher keyed on `AH`.
fn dos_int21(cpu: &mut Cpu) {
    let ah = cpu.regs.get8(Reg8::Ah);
    // Default to "success": clear the carry flag.
    cpu.regs.flags.cf = false;
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
        // Anything else: report success with AX cleared. The startup
        // code stores the result but does not branch on it here.
        _ => cpu.regs.set16(Reg16::Ax, 0),
    }
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
        dos_int21(&mut cpu);
        assert_eq!(cpu.regs.get8(Reg8::Al), 6, "DOS major version in AL");
        assert!(!cpu.regs.flags.cf, "carry cleared on success");
    }

    #[test]
    fn dos_get_current_drive_returns_c() {
        let mut cpu = Cpu::new();
        cpu.regs.set8(Reg8::Ah, 0x19);
        dos_int21(&mut cpu);
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

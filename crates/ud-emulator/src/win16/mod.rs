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

use crate::emulator::regs::{Reg16, Reg8};
use crate::emulator::{Cpu, Mmu};
use crate::win32::{HostState, Registry, Win32Error};

/// Synthetic instance handle handed to the task (Win16 `HINSTANCE`).
/// Real Windows hands back the module's DGROUP selector; any stable
/// non-zero value works for a single-task sandbox.
pub const WIN16_HINSTANCE: u16 = 0x0100;
/// `SW_SHOWNORMAL` — the default `nCmdShow` for a launched app.
const SW_SHOWNORMAL: u16 = 1;

/// Register the Win16 stub surface with `registry`. Safe to call once
/// per sandbox before loading an NE module; the loader's relocation
/// pass then resolves imported ordinals to these thunks (falling back
/// to trap-on-call for anything unimplemented).
pub fn register_all(registry: &mut Registry) {
    register_kernel(registry);
    register_user(registry);
}

/// `USER` ordinal stubs.
fn register_user(registry: &mut Registry) {
    // USER.5 InitApp(hInstance) — set up the task's message queue.
    // Must return non-zero or the C startup aborts.
    registry.register_far_pascal("user", "@5", stub_ret1_1word, 2);
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
    // ES:BX = command line. Point at the DGROUP segment, offset 0x81
    // (the classic PSP command-tail offset); the tail is empty.
    cpu.regs.set16(Reg16::Bx, 0x81);
    let ds = cpu.ds_selector();
    cpu.set_segment_reg(0 /* ES */, ds);
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

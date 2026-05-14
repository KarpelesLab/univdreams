//! `winmm.dll` stubs.
//!
//! Round-4 only requires `DefDriverProc` — the system-default
//! installable-driver dispatcher. Codecs forward unknown driver
//! messages to it; we return 0 (handled, no result) for every
//! driver-system message except `DRV_CONFIGURE`, which returns
//! `DRVCNF_OK = 1` so the codec's "configure" path completes.
//!
//! Reference: MSDN `DefDriverProc` —
//! https://learn.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-defdriverproc

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

// Driver-message ids — `mmsystem.h`.
const DRV_LOAD: u32 = 0x0001;
const DRV_ENABLE: u32 = 0x0002;
const DRV_OPEN: u32 = 0x0003;
const DRV_CLOSE: u32 = 0x0004;
const DRV_DISABLE: u32 = 0x0005;
const DRV_FREE: u32 = 0x0006;
const DRV_CONFIGURE: u32 = 0x0007;
const DRV_QUERYCONFIGURE: u32 = 0x0008;
const DRV_INSTALL: u32 = 0x0009;
const DRV_REMOVE: u32 = 0x000A;

const DRVCNF_OK: u32 = 1;

/// Register every winmm stub.
pub fn register(registry: &mut Registry) {
    registry.register(
        "winmm.dll",
        "DefDriverProc",
        stub_def_driver_proc as StubFn,
        5,
    );
    // Round 8 (IR50_32.DLL): the Indeo 5 codec uses
    // `timeGetTime` as a higher-resolution wall-clock source than
    // `GetTickCount`. Both return DWORD milliseconds.
    registry.register("winmm.dll", "timeGetTime", stub_time_get_time as StubFn, 0);

    // Round 20 (mpg4c32.dll): the MSMPEG4 v3 codec calls
    // `GetDriverModuleHandle` to find its own HMODULE. We
    // return the primary module base (set by `Sandbox::load`).
    // https://learn.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-getdrivermodulehandle
    registry.register(
        "winmm.dll",
        "GetDriverModuleHandle",
        stub_get_driver_module_handle as StubFn,
        1,
    );
}

/// `LRESULT DefDriverProc(DWORD_PTR dwDriverIdentifier, HDRVR
/// hdrvr, UINT msg, LPARAM lParam1, LPARAM lParam2)`.
fn stub_def_driver_proc(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _id = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("DefDriverProc", t))?;
    let _hdrvr = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("DefDriverProc", t))?;
    let msg = arg_dword(cpu, mmu, 2)
        .map_err(|t| crate::win32::trap_to_win32_local("DefDriverProc", t))?;
    let _l1 = arg_dword(cpu, mmu, 3)
        .map_err(|t| crate::win32::trap_to_win32_local("DefDriverProc", t))?;
    let _l2 = arg_dword(cpu, mmu, 4)
        .map_err(|t| crate::win32::trap_to_win32_local("DefDriverProc", t))?;
    Ok(match msg {
        DRV_CONFIGURE => DRVCNF_OK,
        DRV_LOAD | DRV_FREE | DRV_OPEN | DRV_CLOSE | DRV_ENABLE | DRV_DISABLE
        | DRV_QUERYCONFIGURE | DRV_INSTALL | DRV_REMOVE => 0,
        _ => 0,
    })
}

/// `DWORD timeGetTime(void)`. Returns a monotonically-increasing
/// millisecond counter. Real implementations have ~1 ms
/// resolution; we synthesise a fast-counting tick — codecs only
/// use the value as a seed or rate-limiter sentinel.
fn stub_time_get_time(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    state.tick = state.tick.wrapping_add(1);
    Ok(state.tick)
}

/// `HMODULE GetDriverModuleHandle(HDRVR hdrvr)`. Returns the
/// HMODULE of the DLL that registered the driver `hdrvr`.
/// Real installable drivers store this in an internal table
/// keyed by HDRVR; our sandbox only ever has one codec loaded
/// at a time, so we return [`HostState::primary_module_base`].
/// Codecs use the value as the `hInstance` argument to
/// `LoadResource` / `FindResource` for self-relative resource
/// access — the codec's resources live in the same module.
fn stub_get_driver_module_handle(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _hdrvr = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetDriverModuleHandle", t))?;
    Ok(state.primary_module_base)
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
        args: &[u32],
    ) -> Result<(), crate::Error> {
        for a in args.iter().rev() {
            cpu.push32(mmu, *a)?;
        }
        cpu.push32(mmu, 0xDEAD_DEAD)?;
        cpu.regs.eip = registry.resolve("winmm.dll", "DefDriverProc").unwrap();
        crate::win32::dispatch_stub(cpu, mmu, registry, state)
    }

    #[test]
    fn drv_configure_returns_ok() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            &[0, 0, DRV_CONFIGURE, 0, 0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), DRVCNF_OK);
    }

    #[test]
    fn drv_load_returns_zero() {
        let (mut cpu, mut mmu, registry, mut state) = make_env();
        call(
            &mut cpu,
            &mut mmu,
            &registry,
            &mut state,
            &[0, 0, DRV_LOAD, 0, 0],
        )
        .unwrap();
        assert_eq!(cpu.regs.get32(Reg32::Eax), 0);
    }
}

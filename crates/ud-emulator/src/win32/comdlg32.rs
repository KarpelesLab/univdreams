//! `comdlg32.dll` stubs — the common-dialog surface. Codec DLLs
//! with a settings dialog (On2 `vp6vfw.dll`) import
//! `GetOpenFileNameA`; the decode path never reaches it. The stub
//! reports "user cancelled" so any accidental call fails soft.

use super::{HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every comdlg32 stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/commdlg/nf-commdlg-getopenfilenamea
    registry.register(
        "comdlg32.dll",
        "GetOpenFileNameA",
        stub_get_open_file_name_a as StubFn,
        1,
    );
}

/// `BOOL GetOpenFileNameA(LPOPENFILENAMEA lpofn)`. Returns FALSE
/// (dialog cancelled / no file chosen).
fn stub_get_open_file_name_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

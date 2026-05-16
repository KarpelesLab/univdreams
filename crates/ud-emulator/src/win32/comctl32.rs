//! `comctl32.dll` stubs — the common-controls surface.
//!
//! Codecs pull `comctl32` in only for their configuration
//! dialog (themed buttons, sliders). The sandbox never opens
//! that dialog; the single stub just needs to resolve so the
//! codec's CRT init / DllMain completes.
//!
//! Reference: MSDN `comctl32` API.

use super::{HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every comctl32.dll stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-initcommoncontrolsex
    registry.register(
        "comctl32.dll",
        "InitCommonControlsEx",
        stub_init_common_controls_ex as StubFn,
        1,
    );
}

/// `BOOL InitCommonControlsEx(const INITCOMMONCONTROLSEX *picce)`.
/// Report success — the common-control classes are "registered".
fn stub_init_common_controls_ex(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

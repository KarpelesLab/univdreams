//! `msi.dll` stubs — Windows Installer surface.
//!
//! The QuickTime 7.7.9 installer wraps an MSI payload. Round 1
//! covers only what we have observed it touching — most calls are
//! by ordinal, not by name. The current set:
//!
//! * `@112` (`MsiGetFileSignatureInformationA`) — returns
//!   `ERROR_FILE_INVALID = 0x000003EE`. The installer treats that
//!   as "no signature info, proceed without verification".
//!
//! Reference: MSDN `msi.h`.

use super::{HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every msi.dll stub.
pub fn register(registry: &mut Registry) {
    // Ordinal 112 in modern `msi.dll` exports is
    // `MsiGetFileSignatureInformationA`. The installer probes it
    // before MSI execution starts; we report "no info" so the
    // happy path continues.
    registry.register("msi.dll", "@112", stub_msi_get_file_sig_info as StubFn, 5);
}

/// `UINT MsiGetFileSignatureInformationA(...)`. Returns
/// `ERROR_FILE_INVALID` (= `0x3EE`) — the installer interprets
/// this as "the binary has no usable signature; proceed without
/// trust evaluation".
fn stub_msi_get_file_sig_info(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0x0000_03EE)
}

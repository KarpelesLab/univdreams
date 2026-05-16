//! `version.dll` stubs — the file-version-info surface.
//!
//! Codecs (notably Cinepak's `iccvid`) call into `version.dll`
//! to read their own `VS_VERSIONINFO` resource — a config-dialog
//! / "About" path the sandbox never drives. All three stubs are
//! fail-soft: they report "no version info available", which
//! makes the codec fall back to its compiled-in defaults.
//!
//! Reference: MSDN `version.dll` API — cited inline.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every version.dll stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfosizea
    registry.register(
        "version.dll",
        "GetFileVersionInfoSizeA",
        stub_get_file_version_info_size_a as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfoa
    registry.register(
        "version.dll",
        "GetFileVersionInfoA",
        stub_get_file_version_info_a as StubFn,
        4,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-verqueryvaluea
    registry.register(
        "version.dll",
        "VerQueryValueA",
        stub_ver_query_value_a as StubFn,
        4,
    );
}

/// `DWORD GetFileVersionInfoSizeA(LPCSTR lptstrFilename,
/// LPDWORD lpdwHandle)`. Report size 0 — "no version info" —
/// and clear the out handle. The codec then skips its
/// version-info read entirely.
fn stub_get_file_version_info_size_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let _filename = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoSizeA", t))?;
    let handle = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoSizeA", t))?;
    if handle != 0 {
        mmu.store32(handle, 0)
            .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoSizeA", t))?;
    }
    Ok(0)
}

/// `BOOL GetFileVersionInfoA(LPCSTR, DWORD dwHandle, DWORD dwLen,
/// LPVOID lpData)`. Fail-soft: returns FALSE.
fn stub_get_file_version_info_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

/// `BOOL VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock,
/// LPVOID *lplpBuffer, PUINT puLen)`. Fail-soft: returns FALSE.
/// A codec that reached this with a NULL block (our
/// `GetFileVersionInfoA` never filled one) handles FALSE on its
/// fallback path.
fn stub_ver_query_value_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    Ok(0)
}

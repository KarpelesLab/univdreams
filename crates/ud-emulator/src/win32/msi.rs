//! `msi.dll` stubs — Windows Installer surface.
//!
//! The QuickTime 7.7.9 installer wraps an MSI payload and its
//! extracted admin.exe drives the actual install through
//! `MsiInstallProductA` & friends. The msi.dll exports are
//! ordinal-only — we register them under their canonical
//! `@N` form and synthesise the success path: the UI mode
//! and external-UI handler are accepted but ignored, the
//! install itself reports `ERROR_SUCCESS` so the caller
//! treats the install as completed.
//!
//! Ordinals (per Windows 10 msi.dll exports):
//!
//! * `@87`  — `MsiInstallProductA`
//! * `@112` — `MsiGetFileSignatureInformationA`
//! * `@136` — `MsiSetExternalUIA`
//! * `@141` — `MsiSetInternalUI`
//!
//! Reference: MSDN `msi.h`.

use super::{arg_dword, trap_to_win32_local, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every msi.dll stub.
pub fn register(registry: &mut Registry) {
    registry.register("msi.dll", "@112", stub_msi_get_file_sig_info as StubFn, 5);
    registry.register("msi.dll", "@87", stub_msi_install_product_a as StubFn, 2);
    registry.register("msi.dll", "@136", stub_msi_set_external_ui_a as StubFn, 3);
    registry.register("msi.dll", "@141", stub_msi_set_internal_ui as StubFn, 2);
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

/// `UINT MsiInstallProductA(LPCSTR szPackagePath,
/// LPCSTR szCommandLine)`. The synthetic install: log the
/// arguments to the debug channel and return `ERROR_SUCCESS = 0`
/// so the caller's outer "install + verify" wrapper proceeds.
/// A real install would unpack the MSI into Program Files,
/// register components, etc.; the file payload is already in
/// our VirtualFs, so this stub's job is to convince the
/// caller the install succeeded.
fn stub_msi_install_product_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_pkg = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiInstallProductA", t))?;
    let p_cmd = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiInstallProductA", t))?;
    let pkg = if p_pkg != 0 {
        super::read_cstr_local(mmu, p_pkg, 260)?
    } else {
        String::new()
    };
    let cmd = if p_cmd != 0 {
        super::read_cstr_local(mmu, p_cmd, 4096)?
    } else {
        String::new()
    };
    state
        .debug_log
        .push(format!("MsiInstallProductA(pkg={pkg:?}, cmd={cmd:?})"));
    Ok(0) // ERROR_SUCCESS
}

/// `INSTALLUI_HANDLERA MsiSetExternalUIA(INSTALLUI_HANDLERA,
/// DWORD, LPVOID)`. Records the requested UI handler in the
/// debug channel for the analyst and returns NULL (= "no
/// previous handler"). The actual install runs without
/// invoking the callback.
fn stub_msi_set_external_ui_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let p_handler =
        arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiSetExternalUIA", t))?;
    let filter = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiSetExternalUIA", t))?;
    let _ctx = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiSetExternalUIA", t))?;
    state.debug_log.push(format!(
        "MsiSetExternalUIA(handler={p_handler:#010x}, filter={filter:#010x})"
    ));
    Ok(0)
}

/// `INSTALLUILEVEL MsiSetInternalUI(INSTALLUILEVEL dwUILevel,
/// HWND *phWnd)`. Accepts the requested UI level (typically
/// `INSTALLUILEVEL_NONE = 2` for silent installs) and returns
/// `INSTALLUILEVEL_DEFAULT = 1` as the "previous level".
fn stub_msi_set_internal_ui(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &Registry,
) -> Result<u32, Win32Error> {
    let level = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiSetInternalUI", t))?;
    let _hwnd = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiSetInternalUI", t))?;
    state
        .debug_log
        .push(format!("MsiSetInternalUI(level={level:#x})"));
    Ok(1) // INSTALLUILEVEL_DEFAULT
}

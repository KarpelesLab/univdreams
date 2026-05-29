//! `shell32.dll` stubs — the Windows-shell surface.
//!
//! Codecs reach `shell32` from their config dialog: a "visit
//! homepage" `ShellExecute`, a tray-icon notification, a
//! known-folder lookup for a settings file. None of that is on
//! the decode path the sandbox drives — the stubs only need to
//! resolve and return success-shaped values so CRT init /
//! DllMain completes.
//!
//! Reference: MSDN `shell32` API — cited inline.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// `ShellExecute` success sentinel — MSDN: a return value
/// greater than 32 means success.
const SE_OK: u32 = 33;

/// Register every shell32.dll stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea
    registry.register(
        "shell32.dll",
        "ShellExecuteA",
        stub_shell_execute as StubFn,
        6,
    );
    registry.register(
        "shell32.dll",
        "ShellExecuteW",
        stub_shell_execute as StubFn,
        6,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetfolderpathw
    registry.register(
        "shell32.dll",
        "SHGetFolderPathW",
        stub_sh_get_folder_path_w as StubFn,
        5,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyicona
    registry.register(
        "shell32.dll",
        "Shell_NotifyIconA",
        stub_shell_notify_icon as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
    registry.register(
        "shell32.dll",
        "CommandLineToArgvW",
        stub_command_line_to_argv_w as StubFn,
        2,
    );
}

/// `HINSTANCE ShellExecuteA/W(HWND, LPCSTR lpOperation,
/// LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory,
/// INT nShowCmd)`. No-op: the sandbox launches nothing. Return
/// the >32 success sentinel.
fn stub_shell_execute(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(SE_OK)
}

/// `HRESULT SHGetFolderPathW(HWND, int csidl, HANDLE hToken,
/// DWORD dwFlags, LPWSTR pszPath)`. Return `S_OK` and write an
/// empty wide string into `pszPath` — the codec gets a valid
/// (if empty) path buffer and skips any settings-file load.
fn stub_sh_get_folder_path_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let path = arg_dword(cpu, mmu, 4)
        .map_err(|t| crate::win32::trap_to_win32_local("SHGetFolderPathW", t))?;
    if path != 0 {
        mmu.store16(path, 0)
            .map_err(|t| crate::win32::trap_to_win32_local("SHGetFolderPathW", t))?;
    }
    Ok(0)
}

/// `LPWSTR* CommandLineToArgvW(LPCWSTR lpCmdLine, int *pNumArgs)`.
/// MSDN says the caller passes the result to `LocalFree`. We hand
/// back a single-entry argv pointing at the canned command line —
/// the analyser never inspects the actual contents — and write
/// `*pNumArgs = 1`. The returned argv lives in the const arena so
/// `LocalFree` (a no-op stub) is safe.
fn stub_command_line_to_argv_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let cmd = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("CommandLineToArgvW", t))?;
    let p_argc = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("CommandLineToArgvW", t))?;
    // Build a one-entry argv at &arena: [arg0_ptr]. Reuse the
    // command-line pointer as arg0 — the caller may pass NULL,
    // which is fine; argv[0] is then NULL.
    let argv_addr = state.arena_const_alloc(4)?;
    mmu.store32(argv_addr, cmd)
        .map_err(|t| crate::win32::trap_to_win32_local("CommandLineToArgvW", t))?;
    if p_argc != 0 {
        mmu.store32(p_argc, 1)
            .map_err(|t| crate::win32::trap_to_win32_local("CommandLineToArgvW", t))?;
    }
    Ok(argv_addr)
}

/// `BOOL Shell_NotifyIconA(DWORD dwMessage, PNOTIFYICONDATA)`.
/// No-op: report the tray operation succeeded.
fn stub_shell_notify_icon(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

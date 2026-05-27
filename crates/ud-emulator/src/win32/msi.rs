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

use super::{
    arg_dword, read_cstr_local, trap_to_win32_local, HostState, Registry, StubFn, Win32Error,
};
use crate::emulator::{Cpu, Mmu};

/// Register every msi.dll stub.
///
/// Two distinct groups:
/// 1. **Install driver** — `@87` `@112` `@136` `@141` — called
///    by the outer admin EXE that wraps an MSI install. These
///    accept-and-ignore semantics so the install proceeds.
/// 2. **In-process CA surface** — the ordinals a deferred DLL
///    CustomAction calls into to read/write the install state
///    via `MsiGetProperty` / `MsiSetProperty` / etc. These
///    consult [`HostState::msi_session`] when set.
pub fn register(registry: &mut Registry) {
    // Named exports for the install-driver surface — the outer
    // QuickTime installer EXE imports these by name. Ordinals
    // are deliberately NOT registered for these since the
    // QTInstallCode.dll inside the QuickTime MSI uses the SAME
    // ordinal numbers for different functions (msi.dll ordinals
    // varied across Windows versions).
    registry.register(
        "msi.dll",
        "MsiGetFileSignatureInformationA",
        stub_msi_get_file_sig_info as StubFn,
        5,
    );
    registry.register(
        "msi.dll",
        "MsiInstallProductA",
        stub_msi_install_product_a as StubFn,
        2,
    );
    registry.register(
        "msi.dll",
        "MsiSetExternalUIA",
        stub_msi_set_external_ui_a as StubFn,
        3,
    );
    registry.register(
        "msi.dll",
        "MsiSetInternalUI",
        stub_msi_set_internal_ui as StubFn,
        2,
    );
    // CA-surface ordinals from the QuickTime-era msi.dll
    // (matches QTInstallCode.dll / QTMSISupport.dll imports).
    // @8   MsiCloseHandle
    // @17  MsiGetActiveDatabase
    // @64  MsiCloseAllHandles (we route to MsiCloseHandle)
    // @73  MsiDatabaseOpenViewA — ERROR_INVALID_HANDLE (DB view not modelled)
    // @87  MsiInstallProductA (alias for the named entry)
    // @103 MsiFormatRecordA
    // @112 MsiGetPropertyA  ← the QT-era ordinal mapping
    // @121 MsiGetTargetPathA
    // @124 MsiGetPropertyW
    // @136 MsiSetExternalUIA
    // @141 MsiSetInternalUI
    // @144 MsiProcessMessage
    // @204 MsiSetPropertyA
    registry.register("msi.dll", "@8", stub_msi_close_handle as StubFn, 1);
    registry.register("msi.dll", "@17", stub_msi_get_active_database as StubFn, 1);
    // @49 = MsiGetMode(MSIHANDLE, MSIRUNMODE) — TRUE/FALSE for
    // a given run mode. Return FALSE for every mode (we're not
    // in admin / maintenance / rollback etc.), which is the
    // most defensive answer.
    registry.register("msi.dll", "@49", stub_msi_get_mode as StubFn, 2);
    registry.register("msi.dll", "@64", stub_msi_close_handle as StubFn, 1);
    registry.register("msi.dll", "@73", stub_msi_database_open_view as StubFn, 3);
    registry.register("msi.dll", "@87", stub_msi_install_product_a as StubFn, 2);
    registry.register("msi.dll", "@103", stub_msi_format_record_a as StubFn, 4);
    registry.register("msi.dll", "@112", stub_msi_get_property_a as StubFn, 4);
    registry.register("msi.dll", "@121", stub_msi_get_target_path_a as StubFn, 4);
    registry.register("msi.dll", "@124", stub_msi_get_property_w as StubFn, 4);
    registry.register("msi.dll", "@136", stub_msi_set_external_ui_a as StubFn, 3);
    registry.register("msi.dll", "@141", stub_msi_set_internal_ui as StubFn, 2);
    registry.register("msi.dll", "@144", stub_msi_process_message as StubFn, 3);
    registry.register("msi.dll", "@204", stub_msi_set_property_a as StubFn, 3);
    // Also expose the named entries (some consumers import by
    // name rather than ordinal). Idempotent — the second
    // `register` call returns the previously-registered thunk.
    registry.register(
        "msi.dll",
        "MsiGetPropertyA",
        stub_msi_get_property_a as StubFn,
        4,
    );
    registry.register(
        "msi.dll",
        "MsiGetPropertyW",
        stub_msi_get_property_w as StubFn,
        4,
    );
    registry.register(
        "msi.dll",
        "MsiSetPropertyA",
        stub_msi_set_property_a as StubFn,
        3,
    );
    registry.register(
        "msi.dll",
        "MsiCloseHandle",
        stub_msi_close_handle as StubFn,
        1,
    );
    registry.register(
        "msi.dll",
        "MsiGetActiveDatabase",
        stub_msi_get_active_database as StubFn,
        1,
    );
    registry.register(
        "msi.dll",
        "MsiGetTargetPathA",
        stub_msi_get_target_path_a as StubFn,
        4,
    );
    registry.register(
        "msi.dll",
        "MsiFormatRecordA",
        stub_msi_format_record_a as StubFn,
        4,
    );
    registry.register(
        "msi.dll",
        "MsiDatabaseOpenViewA",
        stub_msi_database_open_view as StubFn,
        3,
    );
    registry.register(
        "msi.dll",
        "MsiProcessMessage",
        stub_msi_process_message as StubFn,
        3,
    );
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_HANDLE: u32 = 6;
#[allow(dead_code)]
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_UNKNOWN_PROPERTY: u32 = 1608;

/// Verify the caller's `hInstall` matches the active MSI session.
fn check_session(state: &HostState, h: u32) -> bool {
    state
        .msi_session
        .as_ref()
        .is_some_and(|s| s.handle == h && h != 0)
}

/// Read a guest-side ASCII property name (NUL-terminated).
fn read_prop_name(mmu: &Mmu, ptr: u32) -> Result<String, Win32Error> {
    if ptr == 0 {
        return Ok(String::new());
    }
    read_cstr_local(mmu, ptr, 260)
}

/// Write a NUL-terminated ASCII string into a guest buffer with
/// the standard `MsiGet*` shape: `[buf, *pcch]` is the buffer +
/// in/out length (excluding the NUL). On exit `*pcch` is set
/// to the bytes written (excluding NUL). If the supplied
/// buffer is too small returns ERROR_MORE_DATA with `*pcch` =
/// required length (excluding NUL).
fn write_buf_with_len(mmu: &mut Mmu, buf: u32, pcch: u32, value: &str) -> Result<u32, Win32Error> {
    let v = value.as_bytes();
    let needed = u32::try_from(v.len()).unwrap_or(u32::MAX);
    let cap = if pcch != 0 {
        mmu.load32(pcch).unwrap_or(0)
    } else {
        0
    };
    if buf == 0 || cap == 0 {
        // Caller asked for required length.
        if pcch != 0 {
            mmu.store32(pcch, needed)
                .map_err(|t| trap_to_win32_local("Msi*", t))?;
        }
        if buf == 0 {
            return Ok(ERROR_SUCCESS);
        }
        return Ok(ERROR_MORE_DATA);
    }
    if needed + 1 > cap {
        // Buffer too small — copy what fits, NUL-terminate, set
        // *pcch to required length (excluding NUL).
        let fit = cap.saturating_sub(1);
        for i in 0..fit as usize {
            if let Some(b) = v.get(i) {
                mmu.store8(buf + i as u32, *b)
                    .map_err(|t| trap_to_win32_local("Msi*", t))?;
            }
        }
        if cap > 0 {
            mmu.store8(buf + cap - 1, 0)
                .map_err(|t| trap_to_win32_local("Msi*", t))?;
        }
        mmu.store32(pcch, needed)
            .map_err(|t| trap_to_win32_local("Msi*", t))?;
        return Ok(ERROR_MORE_DATA);
    }
    for (i, b) in v.iter().enumerate() {
        mmu.store8(buf + i as u32, *b)
            .map_err(|t| trap_to_win32_local("Msi*", t))?;
    }
    mmu.store8(buf + needed, 0)
        .map_err(|t| trap_to_win32_local("Msi*", t))?;
    mmu.store32(pcch, needed)
        .map_err(|t| trap_to_win32_local("Msi*", t))?;
    Ok(ERROR_SUCCESS)
}

/// `UINT MsiGetFileSignatureInformationA(...)`. Returns
/// `ERROR_FILE_INVALID` (= `0x3EE`) — the installer interprets
/// this as "the binary has no usable signature; proceed without
/// trust evaluation".
fn stub_msi_get_file_sig_info(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
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
    _registry: &mut Registry,
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
    _registry: &mut Registry,
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
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let level = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiSetInternalUI", t))?;
    let _hwnd = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiSetInternalUI", t))?;
    state
        .debug_log
        .push(format!("MsiSetInternalUI(level={level:#x})"));
    Ok(1) // INSTALLUILEVEL_DEFAULT
}

// ---------- in-process CA surface --------------------------------

/// `UINT MsiGetPropertyA(MSIHANDLE hInstall, LPCSTR szName,
/// LPSTR szValueBuf, DWORD *pcchValueBuf)`. Reads from the
/// active [`MsiSession`]'s property map.
fn stub_msi_get_property_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiGetPropertyA", t))?;
    let p_name = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiGetPropertyA", t))?;
    let buf = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiGetPropertyA", t))?;
    let pcch = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32_local("MsiGetPropertyA", t))?;
    if !check_session(state, h) {
        return Ok(ERROR_INVALID_HANDLE);
    }
    let name = read_prop_name(mmu, p_name)?;
    let value = state
        .msi_session
        .as_ref()
        .and_then(|s| s.properties.get(&name))
        .cloned()
        .unwrap_or_default();
    if state.trace_stubs {
        state
            .debug_log
            .push(format!("MsiGetPropertyA({name:?}) = {value:?}"));
    }
    write_buf_with_len(mmu, buf, pcch, &value)
}

/// `UINT MsiGetPropertyW(MSIHANDLE, LPCWSTR, LPWSTR, DWORD*)`.
/// Wide variant — read the UTF-16 name + write a UTF-16
/// answer. We translate via the property map (lossy on
/// non-ASCII paths, which matches QT's actual usage).
fn stub_msi_get_property_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    let p_name = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    let buf = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    let pcch = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    if !check_session(state, h) {
        return Ok(ERROR_INVALID_HANDLE);
    }
    // Inline UTF-16 read — kernel32.rs's helper is private.
    let name = {
        let mut chars = Vec::new();
        let mut a = p_name;
        for _ in 0..260 {
            let c = mmu
                .load16(a)
                .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
            if c == 0 {
                break;
            }
            chars.push(c);
            a = a.wrapping_add(2);
        }
        String::from_utf16_lossy(&chars)
    };
    let value = state
        .msi_session
        .as_ref()
        .and_then(|s| s.properties.get(&name))
        .cloned()
        .unwrap_or_default();
    // Wide-string write: pcch is in CHARACTERS, not bytes.
    let chars: Vec<u16> = value.encode_utf16().collect();
    let needed = u32::try_from(chars.len()).unwrap_or(u32::MAX);
    let cap = if pcch != 0 {
        mmu.load32(pcch).unwrap_or(0)
    } else {
        0
    };
    if buf == 0 || cap == 0 {
        if pcch != 0 {
            mmu.store32(pcch, needed)
                .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
        }
        return Ok(if buf == 0 {
            ERROR_SUCCESS
        } else {
            ERROR_MORE_DATA
        });
    }
    if needed + 1 > cap {
        let fit = cap.saturating_sub(1);
        for i in 0..fit as usize {
            if let Some(c) = chars.get(i) {
                mmu.store16(buf + i as u32 * 2, *c)
                    .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
            }
        }
        if cap > 0 {
            mmu.store16(buf + (cap - 1) * 2, 0)
                .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
        }
        mmu.store32(pcch, needed)
            .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
        return Ok(ERROR_MORE_DATA);
    }
    for (i, c) in chars.iter().enumerate() {
        mmu.store16(buf + i as u32 * 2, *c)
            .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    }
    mmu.store16(buf + needed * 2, 0)
        .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    mmu.store32(pcch, needed)
        .map_err(|t| trap_to_win32_local("MsiGetPropertyW", t))?;
    Ok(ERROR_SUCCESS)
}

/// `UINT MsiSetPropertyA(MSIHANDLE, LPCSTR szName, LPCSTR
/// szValue)`. Writes back to the active session's property
/// map. A NULL `szValue` clears the property.
fn stub_msi_set_property_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiSetPropertyA", t))?;
    let p_name = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiSetPropertyA", t))?;
    let p_val = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiSetPropertyA", t))?;
    if !check_session(state, h) {
        return Ok(ERROR_INVALID_HANDLE);
    }
    let name = read_prop_name(mmu, p_name)?;
    let value = if p_val == 0 {
        String::new()
    } else {
        read_cstr_local(mmu, p_val, 4096)?
    };
    if state.trace_stubs {
        state
            .debug_log
            .push(format!("MsiSetPropertyA({name:?}) := {value:?}"));
    }
    if let Some(s) = state.msi_session.as_mut() {
        if value.is_empty() {
            s.properties.remove(&name);
        } else {
            s.properties.insert(name, value);
        }
    }
    Ok(ERROR_SUCCESS)
}

/// `UINT MsiGetTargetPathA(MSIHANDLE, LPCSTR szFolder, LPSTR
/// szPathBuf, DWORD *pcchPathBuf)`. Reads a resolved directory
/// path. Falls through to the property map when the folder
/// isn't in the dedicated `target_paths` map.
fn stub_msi_get_target_path_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiGetTargetPathA", t))?;
    let p_name = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiGetTargetPathA", t))?;
    let buf = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiGetTargetPathA", t))?;
    let pcch = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32_local("MsiGetTargetPathA", t))?;
    if !check_session(state, h) {
        return Ok(ERROR_INVALID_HANDLE);
    }
    let name = read_prop_name(mmu, p_name)?;
    let value = state
        .msi_session
        .as_ref()
        .and_then(|s| {
            s.target_paths
                .get(&name)
                .or_else(|| s.properties.get(&name))
        })
        .cloned()
        .unwrap_or_default();
    if state.trace_stubs {
        state
            .debug_log
            .push(format!("MsiGetTargetPathA({name:?}) = {value:?}"));
    }
    if value.is_empty() {
        return Ok(ERROR_UNKNOWN_PROPERTY);
    }
    write_buf_with_len(mmu, buf, pcch, &value)
}

/// `UINT MsiFormatRecordA(MSIHANDLE, MSIHANDLE hRecord, LPSTR
/// szResultBuf, DWORD *pcchResultBuf)`. We don't fully model
/// the MSIHANDLE record API; report ERROR_INVALID_HANDLE for
/// the record so callers fall back to their default behaviour.
fn stub_msi_format_record_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiFormatRecordA", t))?;
    let _rec = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiFormatRecordA", t))?;
    let pcch = arg_dword(cpu, mmu, 3).map_err(|t| trap_to_win32_local("MsiFormatRecordA", t))?;
    if pcch != 0 {
        mmu.store32(pcch, 0)
            .map_err(|t| trap_to_win32_local("MsiFormatRecordA", t))?;
    }
    Ok(ERROR_INVALID_HANDLE)
}

/// `UINT MsiCloseHandle(MSIHANDLE)`. No-op success — our
/// session lifetime is managed by the walker, not by callers.
fn stub_msi_close_handle(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiCloseHandle", t))?;
    Ok(ERROR_SUCCESS)
}

/// `MSIHANDLE MsiGetActiveDatabase(MSIHANDLE hInstall)`. Returns
/// a synthetic database handle (we use `hInstall + 1`). Callers
/// pass it back to `MsiDatabaseOpenView` which returns
/// ERROR_INVALID_HANDLE today.
fn stub_msi_get_active_database(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiGetActiveDatabase", t))?;
    if !check_session(state, h) {
        return Ok(0);
    }
    Ok(h.wrapping_add(1))
}

/// `UINT MsiDatabaseOpenViewA(MSIHANDLE, LPCSTR szQuery,
/// MSIHANDLE *phView)`. Not modelled — return
/// ERROR_INVALID_HANDLE so the caller bails out of the query
/// path cleanly.
fn stub_msi_database_open_view(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _db = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiDatabaseOpenViewA", t))?;
    let _q = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiDatabaseOpenViewA", t))?;
    let pv = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiDatabaseOpenViewA", t))?;
    // Best-effort write of NULL to `*phView` so the caller sees
    // "no handle" before checking our return code. Swallow a
    // write-protect fault on a read-only buffer — the caller
    // is doing an unusual thing if it's passing one, but we
    // still want the return code to land cleanly.
    if pv != 0 {
        let _ = mmu.store32(pv, 0);
    }
    Ok(ERROR_INVALID_HANDLE)
}

/// `BOOL MsiGetMode(MSIHANDLE hInstall, MSIRUNMODE iRunMode)`.
/// Returns FALSE for every queried run mode — we're not in
/// admin/maintenance/rollback/scheduled-CA/etc. The most
/// defensive answer for a synthesised install.
fn stub_msi_get_mode(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiGetMode", t))?;
    let _mode = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiGetMode", t))?;
    Ok(0)
}

/// `int MsiProcessMessage(MSIHANDLE, INSTALLMESSAGE eMessage,
/// MSIHANDLE hRecord)`. Log + return IDOK (1) so any
/// confirmation prompts proceed.
fn stub_msi_process_message(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _h = arg_dword(cpu, mmu, 0).map_err(|t| trap_to_win32_local("MsiProcessMessage", t))?;
    let m = arg_dword(cpu, mmu, 1).map_err(|t| trap_to_win32_local("MsiProcessMessage", t))?;
    let _r = arg_dword(cpu, mmu, 2).map_err(|t| trap_to_win32_local("MsiProcessMessage", t))?;
    if state.trace_stubs {
        state
            .debug_log
            .push(format!("MsiProcessMessage(kind={m:#x})"));
    }
    Ok(1) // IDOK
}

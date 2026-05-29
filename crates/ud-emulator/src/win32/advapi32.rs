//! `advapi32.dll` registry stubs.
//!
//! Now backed by the attached [`VirtualRegistry`]: open / query
//! / set route through it so MSI-walker writes and other
//! pre-staged keys are visible to guest lookups. Without the
//! registry attached (or for unknown keys), keep the
//! synthetic-success fallback for paths real machines always
//! have — IR50 needs
//! `HARDWARE\DESCRIPTION\System\FloatingPointProcessor` to
//! enable its MMX kernels.
//!
//! Reference: MSDN "Registry Functions" —
//! `https://learn.microsoft.com/en-us/windows/win32/api/winreg/`.

use super::{
    arg_dword, read_cstr_local, read_wide_cstr_local, HostState, Registry, StubFn, Win32Error,
};
use crate::context::RegistryValue;
use crate::emulator::{Cpu, Mmu};

// winerror.h: common return codes.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_SUCCESS: u32 = 0;

// HKEY value handed back to callers (bare-bones; the sandbox
// doesn't model a real registry). Non-zero so RAII guards in
// the codec proceed.
const HKEY_FPU: u32 = 0xC0DE_F0F0;

/// True iff `subkey` (case-insensitive) names a registry path
/// that real Win9x/NT machines unconditionally have.
///
/// Round 20 — the Indeo IR41/IR50 DRV_LOAD-time CPUID block
/// AND-gates its "use MMX kernels" decision flag (`[0x1c4a9a38]`)
/// with `[ebp-8]`, which is set to 1 iff
/// `RegOpenKeyExA(HKLM, "HARDWARE\DESCRIPTION\System\FloatingPointProcessor", ...)`
/// succeeded. Real Indeo machines (anything Win95 SP1+ on a
/// real x86) always have that key; without success, the
/// codec falls back to the integer-only kernels and our test
/// pipeline reports `mmx_dispatch_count = 0` even though
/// every preceding precondition (CPUID, EFLAGS.ID, MMX bit)
/// is correct.
///
/// Returning ERROR_SUCCESS for this exact path (and the
/// well-known FloatingPointProcessor\0..\0N child enumeration
/// any FPU-checking caller might walk) lets the gate close
/// cleanly. Codecs that genuinely needed the registry data
/// (the codec's RegQueryValueExA path returns
/// ERROR_FILE_NOT_FOUND, so callers fall through to defaults)
/// are unaffected.
fn key_exists_synthetically(subkey: &str) -> bool {
    let s = subkey.to_ascii_lowercase();
    // Trim leading slashes some callers prepend.
    let s = s.trim_start_matches('\\');
    s == "hardware\\description\\system\\floatingpointprocessor"
        || s.starts_with("hardware\\description\\system\\floatingpointprocessor\\")
}

/// Register every advapi32 stub.
pub fn register(registry: &mut Registry) {
    registry.register(
        "advapi32.dll",
        "RegCloseKey",
        stub_reg_close_key as StubFn,
        1,
    );
    registry.register(
        "advapi32.dll",
        "RegCreateKeyA",
        stub_reg_create_key as StubFn,
        3,
    );
    registry.register(
        "advapi32.dll",
        "RegCreateKeyExA",
        stub_reg_create_key_ex as StubFn,
        9,
    );
    registry.register(
        "advapi32.dll",
        "RegDeleteKeyA",
        stub_reg_delete as StubFn,
        2,
    );
    registry.register(
        "advapi32.dll",
        "RegDeleteValueA",
        stub_reg_delete as StubFn,
        2,
    );
    registry.register(
        "advapi32.dll",
        "RegEnumKeyExA",
        stub_reg_enum_key_ex_a as StubFn,
        8,
    );
    registry.register(
        "advapi32.dll",
        "RegOpenKeyA",
        stub_reg_open_key_a as StubFn,
        3,
    );
    registry.register(
        "advapi32.dll",
        "RegOpenKeyExA",
        stub_reg_open_key_ex_a as StubFn,
        5,
    );
    registry.register(
        "advapi32.dll",
        "RegOpenKeyExW",
        stub_reg_open_key_ex_w as StubFn,
        5,
    );
    registry.register(
        "advapi32.dll",
        "RegQueryValueA",
        stub_reg_query_value as StubFn,
        4,
    );
    registry.register(
        "advapi32.dll",
        "RegQueryValueExA",
        stub_reg_query_value_ex as StubFn,
        6,
    );
    registry.register(
        "advapi32.dll",
        "RegQueryValueExW",
        stub_reg_query_value_ex_w as StubFn,
        6,
    );
    registry.register(
        "advapi32.dll",
        "RegSetValueA",
        stub_reg_set_value as StubFn,
        5,
    );
    registry.register(
        "advapi32.dll",
        "RegSetValueExA",
        stub_reg_set_value_ex_a as StubFn,
        6,
    );
}

/// `LSTATUS RegCloseKey(HKEY)`. Always succeeds.
fn stub_reg_close_key(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(ERROR_SUCCESS)
}

/// `LSTATUS RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY
/// phkResult)`. Pretend the key exists; write a non-zero handle
/// to `phkResult` so RAII wrappers proceed.
fn stub_reg_create_key(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegCreateKeyA", t))?;
    let _sub = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegCreateKeyA", t))?;
    let phk = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegCreateKeyA", t))?;
    if phk != 0 {
        let _ = mmu.store32(phk, 0xC0DE_8E0F);
    }
    Ok(ERROR_SUCCESS)
}

/// `LSTATUS RegCreateKeyExA(...)`. Same outcome as RegCreateKeyA.
fn stub_reg_create_key_ex(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let phk = arg_dword(cpu, mmu, 6).map_err(|t| trap("RegCreateKeyExA", t))?;
    if phk != 0 {
        let _ = mmu.store32(phk, 0xC0DE_8E0F);
    }
    let disposition = arg_dword(cpu, mmu, 7).map_err(|t| trap("RegCreateKeyExA", t))?;
    if disposition != 0 {
        // REG_OPENED_EXISTING_KEY = 2
        let _ = mmu.store32(disposition, 2);
    }
    Ok(ERROR_SUCCESS)
}

/// `LSTATUS RegDeleteKeyA / RegDeleteValueA(...)`. No-op success.
fn stub_reg_delete(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(ERROR_SUCCESS)
}

/// `LSTATUS RegEnumKeyExA(...)`. Return ERROR_NO_MORE_ITEMS = 259
/// on first call so codecs that iterate registry sub-keys exit
/// cleanly.
fn stub_reg_enum_key_ex_a(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    Ok(ERROR_NO_MORE_ITEMS)
}

/// Win32 REG_* type codes that match the `RegistryValue`
/// variants we model. See winnt.h.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

const ERROR_MORE_DATA: u32 = 234;

/// Common open-key body. Consults the attached
/// [`VirtualRegistry`] first; if the key is present, mints a
/// handle and stores it at `phk`. Otherwise falls back to the
/// FPU-shaped synthetic key (codecs that test for it) or
/// returns ERROR_FILE_NOT_FOUND.
fn open_key_impl(
    state: &mut HostState,
    mmu: &mut Mmu,
    hkey: u32,
    sub: &str,
    phk: u32,
    stub_name: &'static str,
) -> Result<u32, Win32Error> {
    if let Some(reg) = state.context.registry.as_mut() {
        if let Some(handle) = reg.open_key(hkey, sub) {
            if phk != 0 {
                mmu.store32(phk, handle).map_err(|t| trap(stub_name, t))?;
            }
            return Ok(ERROR_SUCCESS);
        }
    }
    if key_exists_synthetically(sub) {
        if phk != 0 {
            mmu.store32(phk, HKEY_FPU).map_err(|t| trap(stub_name, t))?;
        }
        return Ok(ERROR_SUCCESS);
    }
    if phk != 0 {
        mmu.store32(phk, 0).map_err(|t| trap(stub_name, t))?;
    }
    Ok(ERROR_FILE_NOT_FOUND)
}

/// `LSTATUS RegOpenKeyA(HKEY, LPCSTR lpSubKey, PHKEY phkResult)`.
fn stub_reg_open_key_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegOpenKeyA", t))?;
    let p_sub = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegOpenKeyA", t))?;
    let phk = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegOpenKeyA", t))?;
    let sub = if p_sub != 0 {
        read_cstr_local(mmu, p_sub, 1024).unwrap_or_default()
    } else {
        String::new()
    };
    open_key_impl(state, mmu, hkey, &sub, phk, "RegOpenKeyA")
}

/// `LSTATUS RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey,
/// DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)`.
fn stub_reg_open_key_ex_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegOpenKeyExA", t))?;
    let p_sub = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegOpenKeyExA", t))?;
    let _opts = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegOpenKeyExA", t))?;
    let _sam = arg_dword(cpu, mmu, 3).map_err(|t| trap("RegOpenKeyExA", t))?;
    let phk = arg_dword(cpu, mmu, 4).map_err(|t| trap("RegOpenKeyExA", t))?;
    let sub = if p_sub != 0 {
        read_cstr_local(mmu, p_sub, 1024).unwrap_or_default()
    } else {
        String::new()
    };
    open_key_impl(state, mmu, hkey, &sub, phk, "RegOpenKeyExA")
}

/// `LSTATUS RegOpenKeyExW(...)`. Same as A, with a UTF-16
/// subkey name.
fn stub_reg_open_key_ex_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegOpenKeyExW", t))?;
    let p_sub = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegOpenKeyExW", t))?;
    let _opts = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegOpenKeyExW", t))?;
    let _sam = arg_dword(cpu, mmu, 3).map_err(|t| trap("RegOpenKeyExW", t))?;
    let phk = arg_dword(cpu, mmu, 4).map_err(|t| trap("RegOpenKeyExW", t))?;
    let sub = if p_sub != 0 {
        read_wide_cstr_local(mmu, p_sub, 1024)
    } else {
        String::new()
    };
    open_key_impl(state, mmu, hkey, &sub, phk, "RegOpenKeyExW")
}

/// `LSTATUS RegQueryValueA(...)` — legacy 16-bit form, ANSI
/// default-value query. Return ERROR_FILE_NOT_FOUND.
fn stub_reg_query_value(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(ERROR_FILE_NOT_FOUND)
}

/// Render the registry value to the (`*lpType`, `*lpcbData`,
/// `lpData[0..*lpcbData]`) triple. If `lp_data` is NULL, only
/// the size is written (per MSDN, this lets the caller probe
/// the required buffer). If the caller's buffer is too small,
/// the size is updated and ERROR_MORE_DATA is returned.
fn write_reg_value(
    mmu: &mut Mmu,
    value: &RegistryValue,
    lp_type: u32,
    lp_data: u32,
    pcb: u32,
    is_wide: bool,
    stub_name: &'static str,
) -> Result<u32, Win32Error> {
    let (ty, bytes): (u32, Vec<u8>) = match value {
        RegistryValue::Sz(s) => {
            let mut b = if is_wide {
                let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
                v.extend_from_slice(&[0, 0]);
                v
            } else {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            };
            // Always end with a terminator.
            if !is_wide && b.last() != Some(&0) {
                b.push(0);
            }
            (REG_SZ, b)
        }
        RegistryValue::ExpandSz(s) => {
            let b = if is_wide {
                let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
                v.extend_from_slice(&[0, 0]);
                v
            } else {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            };
            (REG_EXPAND_SZ, b)
        }
        RegistryValue::Dword(d) => (REG_DWORD, d.to_le_bytes().to_vec()),
        RegistryValue::Qword(q) => (REG_QWORD, q.to_le_bytes().to_vec()),
        RegistryValue::Binary(b) => (REG_BINARY, b.clone()),
        RegistryValue::MultiSz(parts) => {
            let mut b = Vec::new();
            for p in parts {
                if is_wide {
                    b.extend(p.encode_utf16().flat_map(u16::to_le_bytes));
                    b.extend_from_slice(&[0, 0]);
                } else {
                    b.extend_from_slice(p.as_bytes());
                    b.push(0);
                }
            }
            // Final empty-string terminator.
            if is_wide {
                b.extend_from_slice(&[0, 0]);
            } else {
                b.push(0);
            }
            (REG_MULTI_SZ, b)
        }
    };
    if lp_type != 0 {
        mmu.store32(lp_type, ty).map_err(|t| trap(stub_name, t))?;
    }
    let needed = bytes.len() as u32;
    let provided = if pcb != 0 {
        mmu.load32(pcb).map_err(|t| trap(stub_name, t))?
    } else {
        0
    };
    if pcb != 0 {
        mmu.store32(pcb, needed).map_err(|t| trap(stub_name, t))?;
    }
    if lp_data == 0 {
        return Ok(ERROR_SUCCESS);
    }
    if provided < needed {
        return Ok(ERROR_MORE_DATA);
    }
    for (i, b) in bytes.iter().enumerate() {
        mmu.store8(lp_data.wrapping_add(i as u32), *b)
            .map_err(|t| trap(stub_name, t))?;
    }
    Ok(ERROR_SUCCESS)
}

/// `LSTATUS RegQueryValueExA(HKEY, LPCSTR lpValueName, LPDWORD
/// lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)`.
/// If the key handle resolves to a stored
/// [`VirtualRegistry`] key, renders the named value (or the
/// default if `lpValueName` is empty/NULL — falls back to
/// "(Default)"). Otherwise returns ERROR_FILE_NOT_FOUND with
/// `*lpcbData = 0`.
fn stub_reg_query_value_ex(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegQueryValueExA", t))?;
    let p_value = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegQueryValueExA", t))?;
    let _lp_reserved = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegQueryValueExA", t))?;
    let lp_type = arg_dword(cpu, mmu, 3).map_err(|t| trap("RegQueryValueExA", t))?;
    let lp_data = arg_dword(cpu, mmu, 4).map_err(|t| trap("RegQueryValueExA", t))?;
    let pcb = arg_dword(cpu, mmu, 5).map_err(|t| trap("RegQueryValueExA", t))?;
    let value_name = if p_value != 0 {
        read_cstr_local(mmu, p_value, 1024).unwrap_or_default()
    } else {
        String::new()
    };
    let lookup = state
        .context
        .registry
        .as_ref()
        .and_then(|r| r.path_of(hkey).map(|p| (r, p.to_string())))
        .and_then(|(r, key_path)| r.get_value(&key_path, &value_name).cloned());
    if let Some(value) = lookup {
        return write_reg_value(
            mmu,
            &value,
            lp_type,
            lp_data,
            pcb,
            false,
            "RegQueryValueExA",
        );
    }
    if pcb != 0 {
        let _ = mmu.store32(pcb, 0);
    }
    Ok(ERROR_FILE_NOT_FOUND)
}

/// `LSTATUS RegQueryValueExW(...)` — same as A with a UTF-16
/// value name and UTF-16 string data on write.
fn stub_reg_query_value_ex_w(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegQueryValueExW", t))?;
    let p_value = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegQueryValueExW", t))?;
    let _lp_reserved = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegQueryValueExW", t))?;
    let lp_type = arg_dword(cpu, mmu, 3).map_err(|t| trap("RegQueryValueExW", t))?;
    let lp_data = arg_dword(cpu, mmu, 4).map_err(|t| trap("RegQueryValueExW", t))?;
    let pcb = arg_dword(cpu, mmu, 5).map_err(|t| trap("RegQueryValueExW", t))?;
    let value_name = if p_value != 0 {
        read_wide_cstr_local(mmu, p_value, 1024)
    } else {
        String::new()
    };
    let lookup = state
        .context
        .registry
        .as_ref()
        .and_then(|r| r.path_of(hkey).map(|p| (r, p.to_string())))
        .and_then(|(r, key_path)| r.get_value(&key_path, &value_name).cloned());
    if let Some(value) = lookup {
        return write_reg_value(mmu, &value, lp_type, lp_data, pcb, true, "RegQueryValueExW");
    }
    if pcb != 0 {
        let _ = mmu.store32(pcb, 0);
    }
    Ok(ERROR_FILE_NOT_FOUND)
}

/// `LSTATUS RegSetValueA(...)` — legacy 16-bit form, only
/// writes the (Default) value. No-op success.
fn stub_reg_set_value(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(ERROR_SUCCESS)
}

/// `LSTATUS RegSetValueExA(HKEY, LPCSTR lpValueName, DWORD
/// reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)`.
/// Writes through to the attached [`VirtualRegistry`] when the
/// handle resolves to a known key — codecs that re-register
/// themselves at runtime then see their state on the next
/// query.
fn stub_reg_set_value_ex_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hkey = arg_dword(cpu, mmu, 0).map_err(|t| trap("RegSetValueExA", t))?;
    let p_value = arg_dword(cpu, mmu, 1).map_err(|t| trap("RegSetValueExA", t))?;
    let _reserved = arg_dword(cpu, mmu, 2).map_err(|t| trap("RegSetValueExA", t))?;
    let dw_type = arg_dword(cpu, mmu, 3).map_err(|t| trap("RegSetValueExA", t))?;
    let lp_data = arg_dword(cpu, mmu, 4).map_err(|t| trap("RegSetValueExA", t))?;
    let cb_data = arg_dword(cpu, mmu, 5).map_err(|t| trap("RegSetValueExA", t))?;
    let name = if p_value != 0 {
        read_cstr_local(mmu, p_value, 1024).unwrap_or_default()
    } else {
        String::new()
    };
    let mut bytes = Vec::with_capacity(cb_data as usize);
    for i in 0..cb_data {
        bytes.push(
            mmu.load8(lp_data.wrapping_add(i))
                .map_err(|t| trap("RegSetValueExA", t))?,
        );
    }
    let value = decode_reg_value(dw_type, &bytes, false);
    let key_path = state
        .context
        .registry
        .as_ref()
        .and_then(|r| r.path_of(hkey))
        .map(str::to_owned);
    if let (Some(reg), Some(key_path)) = (state.context.registry.as_mut(), key_path) {
        reg.set_value(&key_path, &name, value);
    }
    Ok(ERROR_SUCCESS)
}

/// Decode a Win32 `(REG_*, bytes)` pair into a
/// [`RegistryValue`]. Wide strings are tolerated for `REG_SZ` /
/// `REG_EXPAND_SZ` / `REG_MULTI_SZ` when `is_wide` is true.
fn decode_reg_value(ty: u32, bytes: &[u8], is_wide: bool) -> RegistryValue {
    match ty {
        REG_SZ => RegistryValue::Sz(decode_sz(bytes, is_wide)),
        REG_EXPAND_SZ => RegistryValue::ExpandSz(decode_sz(bytes, is_wide)),
        REG_DWORD => {
            let mut buf = [0u8; 4];
            for (i, b) in bytes.iter().take(4).enumerate() {
                buf[i] = *b;
            }
            RegistryValue::Dword(u32::from_le_bytes(buf))
        }
        REG_QWORD => {
            let mut buf = [0u8; 8];
            for (i, b) in bytes.iter().take(8).enumerate() {
                buf[i] = *b;
            }
            RegistryValue::Qword(u64::from_le_bytes(buf))
        }
        REG_MULTI_SZ => RegistryValue::MultiSz(decode_multi_sz(bytes, is_wide)),
        _ => RegistryValue::Binary(bytes.to_vec()),
    }
}

fn decode_sz(bytes: &[u8], is_wide: bool) -> String {
    if is_wide {
        let mut units = Vec::new();
        for chunk in bytes.chunks_exact(2) {
            let u = u16::from_le_bytes([chunk[0], chunk[1]]);
            if u == 0 {
                break;
            }
            units.push(u);
        }
        String::from_utf16_lossy(&units)
    } else {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }
}

fn decode_multi_sz(bytes: &[u8], is_wide: bool) -> Vec<String> {
    let mut out = Vec::new();
    if is_wide {
        let mut cur = Vec::new();
        for chunk in bytes.chunks_exact(2) {
            let u = u16::from_le_bytes([chunk[0], chunk[1]]);
            if u == 0 {
                if cur.is_empty() {
                    break;
                }
                out.push(String::from_utf16_lossy(&cur));
                cur.clear();
            } else {
                cur.push(u);
            }
        }
    } else {
        let mut start = 0;
        for (i, b) in bytes.iter().enumerate() {
            if *b == 0 {
                if i == start {
                    break;
                }
                out.push(String::from_utf8_lossy(&bytes[start..i]).into_owned());
                start = i + 1;
            }
        }
    }
    out
}

fn trap(stub: &'static str, t: crate::emulator::Trap) -> Win32Error {
    Win32Error::InvalidArgument {
        stub,
        reason: format!("{t}"),
    }
}

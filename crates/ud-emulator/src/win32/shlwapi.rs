//! `shlwapi.dll` stubs — the shell lightweight-utility surface.
//!
//! Codecs use `shlwapi` for path and string helpers on their
//! config / settings-file path. The stubs are fail-soft: enough
//! to let CRT init and DllMain complete.
//!
//! Reference: MSDN `shlwapi` API — cited inline.

use super::{arg_dword, HostState, Registry, StubFn, Win32Error};
use crate::emulator::{Cpu, Mmu};

/// Register every shlwapi.dll stub.
pub fn register(registry: &mut Registry) {
    // https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathappendw
    registry.register(
        "shlwapi.dll",
        "PathAppendW",
        stub_path_append_w as StubFn,
        2,
    );
    // https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-strstria
    registry.register("shlwapi.dll", "StrStrIA", stub_str_str_ia as StubFn, 2);
}

/// `BOOL PathAppendW(LPWSTR pszPath, LPCWSTR pszMore)`. No-op:
/// leave `pszPath` unchanged and report success. The codec uses
/// the result only to locate an optional settings file, which
/// our virtual filesystem won't have anyway.
fn stub_path_append_w(
    _cpu: &mut Cpu,
    _mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    Ok(1)
}

/// `PSTR StrStrIA(PCSTR pszFirst, PCSTR pszSrch)` — case-
/// insensitive substring search. Performs the real search over
/// guest memory and returns a pointer to the match (an interior
/// pointer into `pszFirst`), or NULL when absent.
fn stub_str_str_ia(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let hay =
        arg_dword(cpu, mmu, 0).map_err(|t| crate::win32::trap_to_win32_local("StrStrIA", t))?;
    let needle =
        arg_dword(cpu, mmu, 1).map_err(|t| crate::win32::trap_to_win32_local("StrStrIA", t))?;
    if hay == 0 || needle == 0 {
        return Ok(0);
    }
    let read = |base: u32| -> Result<Vec<u8>, Win32Error> {
        let mut out = Vec::new();
        for i in 0..0x10000u32 {
            match mmu.load8(base.wrapping_add(i)) {
                Ok(0) | Err(_) => break,
                Ok(b) => out.push(b.to_ascii_lowercase()),
            }
        }
        Ok(out)
    };
    let h = read(hay)?;
    let n = read(needle)?;
    if n.is_empty() {
        return Ok(hay);
    }
    for (i, w) in h.windows(n.len()).enumerate() {
        if w == n.as_slice() {
            return Ok(hay.wrapping_add(i as u32));
        }
    }
    Ok(0)
}

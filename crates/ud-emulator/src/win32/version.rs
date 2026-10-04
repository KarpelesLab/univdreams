//! `version.dll` stubs — the file-version-info surface.
//!
//! Codecs and the QT runtime call into `version.dll` to read
//! `VS_VERSIONINFO` resources. The Cinepak path doesn't inspect
//! the result, but QT's `qtmlclient!OpenComponent` does walk the
//! version block of `quicktime.qts` and bails on the open path
//! if it can't parse a `VS_FIXEDFILEINFO`. Returning size 0
//! makes QT skip its codec init and emit a NULL component
//! instance — so we synthesise a minimal valid block that
//! `VerQueryValueA("\\", …)` resolves to a sane
//! `VS_FIXEDFILEINFO` carrying QT-ish version numbers.
//!
//! Reference: MSDN `version.dll` API — cited inline.

/// Size of our synthesised version block. Fixed-layout — we
/// always emit the same blob.
const VERSION_BLOCK_SIZE: u32 = 0xA0;

/// `dwSignature` member of `VS_FIXEDFILEINFO`. MSDN constant
/// `VS_FFI_SIGNATURE = 0xFEEF04BD`.
const VS_FFI_SIGNATURE: u32 = 0xFEEF_04BD;

/// `dwStrucVersion` member: high word major, low word minor.
/// We claim VS_FIXEDFILEINFO v1.0 — `0x00010000`.
const VS_FFI_STRUCVERSION: u32 = 0x0001_0000;

/// Build the canonical 160-byte version block. Layout:
///   off  field
///    0   wLength = 0xA0
///    2   wValueLength = 52 (VS_FIXEDFILEINFO size)
///    4   wType = 0 (binary)
///    6   szKey = "VS_VERSION_INFO\0" UTF-16
///   38   padding to align Value on 4-byte boundary
///   40   VS_FIXEDFILEINFO (52 bytes)
///   92   trailing zero padding to 0xA0
///
/// `VerQueryValueA("\\")` consumers want the FIXEDFILEINFO at
/// `block + 40`, with `dwSignature = 0xFEEF04BD`.
fn build_version_block() -> [u8; VERSION_BLOCK_SIZE as usize] {
    let mut buf = [0u8; VERSION_BLOCK_SIZE as usize];
    // Header
    buf[0..2].copy_from_slice(&(VERSION_BLOCK_SIZE as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&52u16.to_le_bytes());
    buf[4..6].copy_from_slice(&0u16.to_le_bytes());
    // szKey UTF-16: "VS_VERSION_INFO\0"
    let key = "VS_VERSION_INFO";
    for (i, c) in key.encode_utf16().enumerate() {
        let off = 6 + i * 2;
        buf[off..off + 2].copy_from_slice(&c.to_le_bytes());
    }
    // VS_FIXEDFILEINFO at offset 40
    let ffi_off = 40;
    // dwSignature
    buf[ffi_off..ffi_off + 4].copy_from_slice(&VS_FFI_SIGNATURE.to_le_bytes());
    // dwStrucVersion
    buf[ffi_off + 4..ffi_off + 8].copy_from_slice(&VS_FFI_STRUCVERSION.to_le_bytes());
    // dwFileVersionMS / LS — QT 7.7.9
    buf[ffi_off + 8..ffi_off + 12].copy_from_slice(&0x0007_0007u32.to_le_bytes());
    buf[ffi_off + 12..ffi_off + 16].copy_from_slice(&0x0009_0050u32.to_le_bytes());
    // dwProductVersionMS / LS
    buf[ffi_off + 16..ffi_off + 20].copy_from_slice(&0x0007_0007u32.to_le_bytes());
    buf[ffi_off + 20..ffi_off + 24].copy_from_slice(&0x0009_0050u32.to_le_bytes());
    // dwFileFlagsMask / Flags — release build, no flags set
    buf[ffi_off + 24..ffi_off + 28].copy_from_slice(&0x0000_003Fu32.to_le_bytes());
    buf[ffi_off + 28..ffi_off + 32].copy_from_slice(&0u32.to_le_bytes());
    // dwFileOS = VOS_NT_WINDOWS32 (0x00040004)
    buf[ffi_off + 32..ffi_off + 36].copy_from_slice(&0x0004_0004u32.to_le_bytes());
    // dwFileType = VFT_DLL (2)
    buf[ffi_off + 36..ffi_off + 40].copy_from_slice(&2u32.to_le_bytes());
    // dwFileSubtype = 0
    buf[ffi_off + 40..ffi_off + 44].copy_from_slice(&0u32.to_le_bytes());
    // dwFileDateMS / LS — 0
    buf[ffi_off + 44..ffi_off + 48].copy_from_slice(&0u32.to_le_bytes());
    buf[ffi_off + 48..ffi_off + 52].copy_from_slice(&0u32.to_le_bytes());
    buf
}

use super::{HostState, Registry, StubFn, Win32Error, arg_dword};
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
/// LPDWORD lpdwHandle)`. Reports the canonical
/// `VERSION_BLOCK_SIZE` so callers allocate a matching buffer
/// for [`stub_get_file_version_info_a`]. The handle out-param
/// is cleared (MSDN says it's reserved and should be 0).
fn stub_get_file_version_info_size_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _filename = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoSizeA", t))?;
    let handle = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoSizeA", t))?;
    if handle != 0 {
        mmu.store32(handle, 0)
            .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoSizeA", t))?;
    }
    Ok(VERSION_BLOCK_SIZE)
}

/// `BOOL GetFileVersionInfoA(LPCSTR, DWORD dwHandle, DWORD dwLen,
/// LPVOID lpData)`. Writes the canonical 160-byte version block
/// produced by [`build_version_block`] into the caller buffer,
/// then returns TRUE. The caller is responsible for sizing the
/// buffer via [`stub_get_file_version_info_size_a`].
fn stub_get_file_version_info_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let _filename = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoA", t))?;
    let _handle = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoA", t))?;
    let len = arg_dword(cpu, mmu, 2)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoA", t))?;
    let data = arg_dword(cpu, mmu, 3)
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoA", t))?;
    if data == 0 || len == 0 {
        return Ok(0);
    }
    let block = build_version_block();
    let to_write = (len as usize).min(block.len());
    mmu.write_initializer(data, &block[..to_write])
        .map_err(|t| crate::win32::trap_to_win32_local("GetFileVersionInfoA", t))?;
    Ok(1)
}

/// `BOOL VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock,
/// LPVOID *lplpBuffer, PUINT puLen)`. Handles the
/// `"\\"` root sub-block: writes `*lplpBuffer = pBlock + 40`
/// (the FIXEDFILEINFO offset emitted by
/// [`build_version_block`]) and `*puLen = 52`. Every other
/// sub-block (including the "\\StringFileInfo\\…\\FieldName"
/// strings codecs query for product / company names) returns
/// FALSE — callers fall back to their compiled-in defaults.
fn stub_ver_query_value_a(
    cpu: &mut Cpu,
    mmu: &mut Mmu,
    _state: &mut HostState,
    _registry: &mut Registry,
) -> Result<u32, Win32Error> {
    let block = arg_dword(cpu, mmu, 0)
        .map_err(|t| crate::win32::trap_to_win32_local("VerQueryValueA", t))?;
    let sub_block = arg_dword(cpu, mmu, 1)
        .map_err(|t| crate::win32::trap_to_win32_local("VerQueryValueA", t))?;
    let lpp_buffer = arg_dword(cpu, mmu, 2)
        .map_err(|t| crate::win32::trap_to_win32_local("VerQueryValueA", t))?;
    let pu_len = arg_dword(cpu, mmu, 3)
        .map_err(|t| crate::win32::trap_to_win32_local("VerQueryValueA", t))?;
    if block == 0 || sub_block == 0 {
        return Ok(0);
    }
    let key = crate::win32::read_cstr_local(mmu, sub_block, 260)?;
    if key == "\\" {
        // Root → FIXEDFILEINFO. We placed it at block + 40.
        let ffi_ptr = block.wrapping_add(40);
        if lpp_buffer != 0 {
            mmu.store32(lpp_buffer, ffi_ptr)
                .map_err(|t| crate::win32::trap_to_win32_local("VerQueryValueA", t))?;
        }
        if pu_len != 0 {
            mmu.store32(pu_len, 52)
                .map_err(|t| crate::win32::trap_to_win32_local("VerQueryValueA", t))?;
        }
        return Ok(1);
    }
    Ok(0)
}

//! IAT resolution against the [`Registry`] of Win32 stubs.
//!
//! Reference: PE/COFF spec §"The .idata Section" / §"Import
//! Directory Table" / §"Import Lookup Table" / §"Import Address
//! Table".
//!
//! Each `IMAGE_IMPORT_DESCRIPTOR` (20 bytes) names a DLL plus
//! offsets to two parallel tables: the *Import Lookup Table* and
//! the *Import Address Table*. Round-1 walks the ILT (preferred
//! per spec since the IAT may have been rewritten by a previous
//! load attempt) and writes the registry's thunk address into
//! the corresponding IAT slot.

use super::header::{Parsed, IMAGE_DIRECTORY_ENTRY_IMPORT};
use super::PeError;
use crate::emulator::mmu::Mmu;
use crate::win32::Registry;

const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;

/// Walk the import descriptors, resolve every named import, and
/// patch the IAT. Strict mode: unknown imports return
/// [`PeError::UnknownImportFunction`]. Use [`resolve_with`] for
/// fail-soft handling.
///
/// `registry` is `&mut` so the fail-soft path in
/// [`resolve_with`] can install fallback thunks; strict mode
/// never mutates it.
pub fn resolve(
    mmu: &mut Mmu,
    parsed: &Parsed,
    image_base: u32,
    registry: &mut Registry,
) -> Result<(), PeError> {
    resolve_with(mmu, parsed, image_base, registry, ResolveMode::Strict, None)
}

/// PE-import resolution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    /// Strict: any unknown import is a hard load-time error.
    /// Default — what the codec path wants.
    Strict,
    /// Fail-soft: unknown imports get a fallback thunk that
    /// raises `Trap::UnresolvedImport` on first call. Loading
    /// succeeds even when the host doesn't know every API the
    /// binary lists; execution halts at the first call to an
    /// unimplemented import, naming it precisely.
    ///
    /// Intended for the install-monitor workflow on EXEs whose
    /// IAT is wider than the codec-class stub registry covers.
    FailSoft,
}

/// Like [`resolve`] but with explicit mode + optional sink for
/// "added a fail-soft thunk" callbacks. When `unresolved` is
/// `Some(&mut vec)` and mode is `FailSoft`, every unknown
/// import is appended to the vec so the caller can log the set
/// up-front (useful for a one-shot "this is what's missing"
/// summary before running).
pub fn resolve_with(
    mmu: &mut Mmu,
    parsed: &Parsed,
    image_base: u32,
    registry: &mut Registry,
    mode: ResolveMode,
    mut unresolved: Option<&mut Vec<(String, String)>>,
) -> Result<(), PeError> {
    let dir = parsed.optional.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(());
    }
    let mut desc = image_base.wrapping_add(dir.virtual_address);
    loop {
        // IMAGE_IMPORT_DESCRIPTOR layout:
        //   DWORD OriginalFirstThunk (RVA of ILT)
        //   DWORD TimeDateStamp
        //   DWORD ForwarderChain
        //   DWORD Name (RVA of DLL name)
        //   DWORD FirstThunk (RVA of IAT)
        let original_first_thunk = mmu.load32(desc)?;
        let _time_date_stamp = mmu.load32(desc.wrapping_add(4))?;
        let _forwarder_chain = mmu.load32(desc.wrapping_add(8))?;
        let name_rva = mmu.load32(desc.wrapping_add(12))?;
        let first_thunk = mmu.load32(desc.wrapping_add(16))?;
        if original_first_thunk == 0 && first_thunk == 0 && name_rva == 0 {
            break; // sentinel — end of import descriptors
        }

        let dll_name = read_cstr(mmu, image_base.wrapping_add(name_rva))?;
        let dll_lower = dll_name.to_ascii_lowercase();

        // The ILT — read entries until we hit a 0 sentinel. The
        // IAT is parallel (same length); we patch each slot with
        // the registered thunk for the named symbol.
        let ilt = if original_first_thunk != 0 {
            image_base.wrapping_add(original_first_thunk)
        } else {
            image_base.wrapping_add(first_thunk)
        };
        let iat = image_base.wrapping_add(first_thunk);
        let mut i: u32 = 0;
        loop {
            let entry = mmu.load32(ilt.wrapping_add(4 * i))?;
            if entry == 0 {
                break;
            }
            let (import_name, resolved) = if (entry & IMAGE_ORDINAL_FLAG32) != 0 {
                // Import-by-ordinal. Many system DLLs (notably
                // `oleaut32.dll`, `ws2_32.dll`) export functions
                // by ordinal only — no name. We resolve them
                // against the registry under the synthetic name
                // `@<ordinal>`; stubs that want to satisfy an
                // ordinal import register themselves with that
                // key (see `Registry::register`).
                let ord = entry & 0xFFFF;
                let name = format!("@{ord}");
                let r = registry.resolve(&dll_lower, &name);
                (name, r)
            } else {
                // Import-by-name: low 31 bits are an RVA to an
                // IMAGE_IMPORT_BY_NAME (Hint:WORD; Name:ASCIIZ).
                let by_name = image_base.wrapping_add(entry & 0x7FFF_FFFF);
                let name = read_cstr(mmu, by_name.wrapping_add(2))?;
                let r = registry.resolve(&dll_lower, &name);
                (name, r)
            };
            let thunk = match (resolved, mode) {
                (Some(addr), _) => addr,
                (None, ResolveMode::Strict) => {
                    return Err(PeError::UnknownImportFunction {
                        dll: dll_lower.clone(),
                        name: import_name,
                    });
                }
                (None, ResolveMode::FailSoft) => {
                    if let Some(sink) = unresolved.as_mut() {
                        sink.push((dll_lower.clone(), import_name.clone()));
                    }
                    registry.register_unknown_fallback(&dll_lower, &import_name)
                }
            };
            mmu.store32(iat.wrapping_add(4 * i), thunk)?;
            i = i.wrapping_add(1);
        }

        desc = desc.wrapping_add(20);
    }
    Ok(())
}

/// Strict resolver that doesn't mutate the registry. Used by
/// the child-process loader in `CreateProcessA` where the
/// caller has only `&Registry` (the `StubFn` signature). On a
/// missing import returns `PeError::UnknownImportFunction`;
/// the child-process spawn falls back to the synthetic
/// immediate-exit path in that case.
pub fn resolve_strict(
    mmu: &mut Mmu,
    parsed: &Parsed,
    image_base: u32,
    registry: &mut Registry,
) -> Result<(), PeError> {
    let dir = parsed.optional.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(());
    }
    let mut desc = image_base.wrapping_add(dir.virtual_address);
    loop {
        let original_first_thunk = mmu.load32(desc)?;
        let name_rva = mmu.load32(desc.wrapping_add(12))?;
        let first_thunk = mmu.load32(desc.wrapping_add(16))?;
        if original_first_thunk == 0 && first_thunk == 0 && name_rva == 0 {
            break;
        }
        let dll_name = read_cstr(mmu, image_base.wrapping_add(name_rva))?;
        let dll_lower = dll_name.to_ascii_lowercase();
        let ilt = if original_first_thunk != 0 {
            image_base.wrapping_add(original_first_thunk)
        } else {
            image_base.wrapping_add(first_thunk)
        };
        let iat = image_base.wrapping_add(first_thunk);
        let mut i: u32 = 0;
        loop {
            let entry = mmu.load32(ilt.wrapping_add(4 * i))?;
            if entry == 0 {
                break;
            }
            let (import_name, resolved) = if (entry & IMAGE_ORDINAL_FLAG32) != 0 {
                let ord = entry & 0xFFFF;
                let name = format!("@{ord}");
                let r = registry.resolve(&dll_lower, &name);
                (name, r)
            } else {
                let by_name = image_base.wrapping_add(entry & 0x7FFF_FFFF);
                let name = read_cstr(mmu, by_name.wrapping_add(2))?;
                let r = registry.resolve(&dll_lower, &name);
                (name, r)
            };
            let Some(thunk) = resolved else {
                return Err(PeError::UnknownImportFunction {
                    dll: dll_lower.clone(),
                    name: import_name,
                });
            };
            mmu.store32(iat.wrapping_add(4 * i), thunk)?;
            i = i.wrapping_add(1);
        }
        desc = desc.wrapping_add(20);
    }
    Ok(())
}

/// Walk the import directory of `bytes` and return the unique
/// set of DLL names referenced (preserving discovery order).
/// Operates on the raw file bytes — no MMU needed. Used by
/// the VFS-DLL-fallback resolver in [`crate::Sandbox::load_with_deps`]
/// to identify which dependent DLLs to pre-load from the VFS
/// before the primary PE is mapped.
pub fn list_imported_dlls(parsed: &Parsed, bytes: &[u8]) -> Result<Vec<String>, PeError> {
    let dir = parsed.optional.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(Vec::new());
    }
    let rva_to_off = |rva: u32| -> Option<u32> {
        for s in &parsed.sections {
            let start = s.virtual_address;
            let span = s.virtual_size.max(s.size_of_raw_data);
            let end = start.checked_add(span)?;
            if rva >= start && rva < end {
                let delta = rva - start;
                if delta < s.size_of_raw_data {
                    return Some(s.pointer_to_raw_data + delta);
                }
                return None;
            }
        }
        None
    };
    let mut off = rva_to_off(dir.virtual_address).ok_or(PeError::DirectoryOutOfRange {
        name: "IMPORT",
        rva: dir.virtual_address,
        size: dir.size,
    })? as usize;
    let mut out = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    loop {
        if off + 20 > bytes.len() {
            break;
        }
        let orig = super::header::read_u32(bytes, off)?;
        let name_rva = super::header::read_u32(bytes, off + 12)?;
        let first = super::header::read_u32(bytes, off + 16)?;
        if orig == 0 && first == 0 && name_rva == 0 {
            break;
        }
        if let Some(name_off) = rva_to_off(name_rva) {
            let no = name_off as usize;
            let mut end = no;
            while end < bytes.len() && bytes[end] != 0 {
                end += 1;
            }
            let name = String::from_utf8_lossy(&bytes[no..end]).into_owned();
            let lc = name.to_ascii_lowercase();
            if seen.insert(lc) {
                out.push(name);
            }
        }
        off += 20;
    }
    Ok(out)
}

fn read_cstr(mmu: &Mmu, mut addr: u32) -> Result<String, PeError> {
    let mut bytes = Vec::new();
    for _ in 0..1024 {
        let b = mmu.load8(addr)?;
        if b == 0 {
            break;
        }
        bytes.push(b);
        addr = addr.wrapping_add(1);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

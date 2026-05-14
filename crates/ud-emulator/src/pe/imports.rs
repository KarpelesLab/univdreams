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
/// patch the IAT.
pub fn resolve(
    mmu: &mut Mmu,
    parsed: &Parsed,
    image_base: u32,
    registry: &Registry,
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
            let thunk = if (entry & IMAGE_ORDINAL_FLAG32) != 0 {
                // Import-by-ordinal — round 1 doesn't support it.
                let ord = entry & 0xFFFF;
                let name = format!("@{ord}");
                return Err(PeError::UnknownImportFunction {
                    dll: dll_lower.clone(),
                    name,
                });
            } else {
                // Import-by-name: low 31 bits are an RVA to an
                // IMAGE_IMPORT_BY_NAME (Hint:WORD; Name:ASCIIZ).
                let by_name = image_base.wrapping_add(entry & 0x7FFF_FFFF);
                let name = read_cstr(mmu, by_name.wrapping_add(2))?;
                registry
                    .resolve(&dll_lower, &name)
                    .ok_or(PeError::UnknownImportFunction {
                        dll: dll_lower.clone(),
                        name,
                    })?
            };
            mmu.store32(iat.wrapping_add(4 * i), thunk)?;
            i = i.wrapping_add(1);
        }

        desc = desc.wrapping_add(20);
    }
    Ok(())
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

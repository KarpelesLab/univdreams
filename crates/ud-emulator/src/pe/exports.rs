//! Export-by-name lookup.
//!
//! Reference: PE/COFF spec §"Export Directory Table".
//!
//! The export directory holds three parallel tables:
//!
//! * `AddressOfFunctions` — array of N RVAs.
//! * `AddressOfNames` — array of M RVAs to ASCIIZ names.
//! * `AddressOfNameOrdinals` — array of M u16 ordinals (relative
//!   to `OrdinalBase`) into `AddressOfFunctions`.
//!
//! Round-1 only does export-by-name (no ordinal lookup). For
//! each name we read the i-th name string, take the i-th
//! ordinal, and use it to index `AddressOfFunctions`. The
//! resulting RVA is what we store in the [`crate::pe::Image`]
//! exports map.

use std::collections::BTreeMap;

use super::header::{Parsed, IMAGE_DIRECTORY_ENTRY_EXPORT};
use super::PeError;

/// Parse the export directory from the file bytes (all RVAs are
/// resolved against the file image; we don't go through the MMU
/// because this is read-only metadata that lives in the parsed
/// file).
pub fn parse_exports(
    parsed: &Parsed,
    bytes: &[u8],
    _image_base: u32,
) -> Result<BTreeMap<String, u32>, PeError> {
    let dir = parsed.optional.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(BTreeMap::new());
    }

    // To convert RVAs back to file offsets, we need to walk the
    // section table (RVA -> raw_off translation).
    let rva_to_off = |rva: u32| -> Option<u32> {
        for s in &parsed.sections {
            let start = s.virtual_address;
            let end = start.checked_add(s.virtual_size.max(s.size_of_raw_data))?;
            if rva >= start && rva < end {
                let delta = rva - start;
                if delta < s.size_of_raw_data {
                    return Some(s.pointer_to_raw_data + delta);
                } else {
                    // In the BSS tail of the section's mapped
                    // image — not represented in the file.
                    return None;
                }
            }
        }
        None
    };

    let edir_off = rva_to_off(dir.virtual_address).ok_or(PeError::DirectoryOutOfRange {
        name: "EXPORT",
        rva: dir.virtual_address,
        size: dir.size,
    })? as usize;

    if edir_off + 40 > bytes.len() {
        return Err(PeError::DirectoryOutOfRange {
            name: "EXPORT",
            rva: dir.virtual_address,
            size: dir.size,
        });
    }

    let read_u32 = |off: usize| -> Result<u32, PeError> { super::header::read_u32(bytes, off) };
    let read_u16 = |off: usize| -> Result<u16, PeError> { super::header::read_u16(bytes, off) };

    let _ordinal_base = read_u32(edir_off + 16)?;
    let address_table_entries = read_u32(edir_off + 20)?;
    let number_of_name_pointers = read_u32(edir_off + 24)?;
    let address_of_functions = read_u32(edir_off + 28)?;
    let address_of_names = read_u32(edir_off + 32)?;
    let address_of_name_ordinals = read_u32(edir_off + 36)?;
    let _ = address_table_entries;

    let funcs_off = rva_to_off(address_of_functions).ok_or(PeError::DirectoryOutOfRange {
        name: "EXPORT.AddressOfFunctions",
        rva: address_of_functions,
        size: 0,
    })? as usize;
    let names_off = rva_to_off(address_of_names).ok_or(PeError::DirectoryOutOfRange {
        name: "EXPORT.AddressOfNames",
        rva: address_of_names,
        size: 0,
    })? as usize;
    let ords_off = rva_to_off(address_of_name_ordinals).ok_or(PeError::DirectoryOutOfRange {
        name: "EXPORT.AddressOfNameOrdinals",
        rva: address_of_name_ordinals,
        size: 0,
    })? as usize;

    let mut out = BTreeMap::new();
    for i in 0..number_of_name_pointers as usize {
        let name_rva = read_u32(names_off + i * 4)?;
        let ordinal = read_u16(ords_off + i * 2)? as usize;
        let func_rva = read_u32(funcs_off + ordinal * 4)?;
        let name_off = rva_to_off(name_rva).ok_or(PeError::DirectoryOutOfRange {
            name: "EXPORT name string",
            rva: name_rva,
            size: 0,
        })? as usize;
        let mut end = name_off;
        while end < bytes.len() && bytes[end] != 0 {
            end += 1;
        }
        let name = String::from_utf8_lossy(&bytes[name_off..end]).into_owned();
        out.insert(name, func_rva);
    }
    Ok(out)
}

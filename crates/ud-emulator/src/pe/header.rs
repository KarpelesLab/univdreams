//! DOS + PE / COFF header parsers.
//!
//! Reference: Microsoft "PE Format" specification, revision 11.0
//! §"MS-DOS Stub", §"COFF File Header", §"Optional Header (Image
//! Only)", §"Optional Header Data Directories", §"Section
//! Table". All field offsets / sizes are quoted from that
//! document.

use super::PeError;

/// Subset of `IMAGE_FILE_HEADER` (a.k.a. COFF File Header) we
/// care about. PE/COFF spec §"COFF File Header (Object and
/// Image)".
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Subset of `IMAGE_OPTIONAL_HEADER32` we care about. PE/COFF
/// spec §"Optional Header Standard Fields (Image Only)" +
/// §"Optional Header Windows-Specific Fields".
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub magic: u16,
    pub address_of_entry_point: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [DataDirectory; 16],
}

/// `IMAGE_DATA_DIRECTORY` — RVA + size pair.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// `IMAGE_SECTION_HEADER`. PE/COFF spec §"Section Table (Section
/// Headers)".
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

/// Parsed PE32 image headers + section table. Held by-value so
/// downstream loader steps can consult any field without
/// re-parsing.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub file: FileHeader,
    pub optional: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    /// Offset within the file of the start of the section table.
    pub section_table_offset: u32,
}

// ---- Microsoft PE/COFF spec constants -------------------------

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COMHEADER: usize = 14;

// Section Characteristics flags (PE/COFF spec §"Section Flags").
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// ---- parsing -------------------------------------------------

/// Read a u16 little-endian from `bytes[off..off+2]`. Returns
/// `PeError::TooSmall` if out of range.
pub fn read_u16(bytes: &[u8], off: usize) -> Result<u16, PeError> {
    let s = bytes.get(off..off + 2).ok_or(PeError::TooSmall {
        got: bytes.len(),
        need: off + 2,
    })?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

pub fn read_u32(bytes: &[u8], off: usize) -> Result<u32, PeError> {
    let s = bytes.get(off..off + 4).ok_or(PeError::TooSmall {
        got: bytes.len(),
        need: off + 4,
    })?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a fixed-length ASCIIZ name (e.g. the 8-byte section
/// name). Trailing zeros are trimmed.
pub fn read_fixed_name(bytes: &[u8], off: usize, n: usize) -> Result<String, PeError> {
    let s = bytes.get(off..off + n).ok_or(PeError::TooSmall {
        got: bytes.len(),
        need: off + n,
    })?;
    let end = s.iter().position(|b| *b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&s[..end]).into_owned())
}

/// Top-level parse: validates DOS + PE signatures, file header,
/// optional header (PE32 only), and the section table.
pub fn parse(bytes: &[u8]) -> Result<Parsed, PeError> {
    if bytes.len() < 0x40 {
        return Err(PeError::TooSmall {
            got: bytes.len(),
            need: 0x40,
        });
    }
    let mz = read_u16(bytes, 0)?;
    if mz != IMAGE_DOS_SIGNATURE {
        return Err(PeError::NotMz);
    }
    let e_lfanew = read_u32(bytes, 0x3C)?;
    if (e_lfanew as usize) + 4 + 20 > bytes.len() {
        return Err(PeError::BadELfanew {
            offset: e_lfanew,
            file_len: bytes.len(),
        });
    }
    let pe_off = e_lfanew as usize;
    let pe_sig = read_u32(bytes, pe_off)?;
    if pe_sig != IMAGE_NT_SIGNATURE {
        return Err(PeError::NotPe);
    }

    // IMAGE_FILE_HEADER (20 bytes) starts at pe_off + 4.
    let fh_off = pe_off + 4;
    let machine = read_u16(bytes, fh_off)?;
    let number_of_sections = read_u16(bytes, fh_off + 2)?;
    let size_of_optional_header = read_u16(bytes, fh_off + 16)?;
    let characteristics = read_u16(bytes, fh_off + 18)?;
    if machine != IMAGE_FILE_MACHINE_I386 {
        return Err(PeError::UnsupportedMachine { machine });
    }
    let file = FileHeader {
        machine,
        number_of_sections,
        size_of_optional_header,
        characteristics,
    };

    // IMAGE_OPTIONAL_HEADER32 starts at fh_off + 20.
    let oh_off = fh_off + 20;
    let magic = read_u16(bytes, oh_off)?;
    if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
        return Err(PeError::Pe32PlusUnsupported);
    }
    if magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
        return Err(PeError::BadOptionalHeaderMagic { magic });
    }

    // Standard fields (28 bytes) + Windows-specific (68 bytes for
    // PE32) + DataDirectories (8 * NumberOfRvaAndSizes).
    let address_of_entry_point = read_u32(bytes, oh_off + 16)?;
    let image_base = read_u32(bytes, oh_off + 28)?;
    let section_alignment = read_u32(bytes, oh_off + 32)?;
    let file_alignment = read_u32(bytes, oh_off + 36)?;
    let size_of_image = read_u32(bytes, oh_off + 56)?;
    let size_of_headers = read_u32(bytes, oh_off + 60)?;
    let number_of_rva_and_sizes = read_u32(bytes, oh_off + 92)?;

    // Data directories. Per PE32, DataDirectory[] is at oh_off + 96.
    let dirs_off = oh_off + 96;
    let mut dirs = [DataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    let n_dirs = (number_of_rva_and_sizes as usize).min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    for (i, slot) in dirs.iter_mut().enumerate().take(n_dirs) {
        let off = dirs_off + i * 8;
        slot.virtual_address = read_u32(bytes, off)?;
        slot.size = read_u32(bytes, off + 4)?;
    }

    let optional = OptionalHeader {
        magic,
        address_of_entry_point,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        number_of_rva_and_sizes,
        data_directories: dirs,
    };

    // Reject managed (.NET) PE.
    if optional.data_directories[IMAGE_DIRECTORY_ENTRY_COMHEADER].size != 0 {
        return Err(PeError::ManagedPe);
    }

    // Section table — fh_off + 20 + size_of_optional_header
    let sec_off = fh_off + 20 + size_of_optional_header as usize;
    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        let off = sec_off + i * 40;
        let name = read_fixed_name(bytes, off, 8)?;
        let virtual_size = read_u32(bytes, off + 8)?;
        let virtual_address = read_u32(bytes, off + 12)?;
        let size_of_raw_data = read_u32(bytes, off + 16)?;
        let pointer_to_raw_data = read_u32(bytes, off + 20)?;
        let characteristics = read_u32(bytes, off + 36)?;
        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            characteristics,
        });
    }

    Ok(Parsed {
        file,
        optional,
        sections,
        section_table_offset: sec_off as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_image::build_minimal_dll;
    use super::*;

    #[test]
    fn parses_minimal_dll_headers() {
        let bytes = build_minimal_dll();
        let p = parse(&bytes).unwrap();
        assert_eq!(p.file.machine, IMAGE_FILE_MACHINE_I386);
        assert_eq!(p.optional.magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        assert_eq!(p.optional.image_base, 0x1000_0000);
        assert!(!p.sections.is_empty());
    }

    #[test]
    fn rejects_truncated_file() {
        let bytes = vec![0u8; 4];
        assert!(matches!(parse(&bytes), Err(PeError::TooSmall { .. })));
    }
}

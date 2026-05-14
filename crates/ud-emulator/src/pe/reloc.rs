//! Base relocations.
//!
//! Reference: PE/COFF spec §"The .reloc Section (Image Only)".
//! Each relocation block has an 8-byte header (page RVA, block
//! size in bytes including the header) followed by 16-bit type +
//! 12-bit offset entries.
//!
//! Round-1 supports the i386-relevant types:
//!
//! * `IMAGE_REL_BASED_ABSOLUTE` (0) — padding, no fixup.
//! * `IMAGE_REL_BASED_HIGHLOW` (3) — apply 32-bit delta to the
//!   referenced dword.
//!
//! Other types trip [`super::PeError::BadRelocBlock`].

use super::header::{Parsed, IMAGE_DIRECTORY_ENTRY_BASERELOC};
use super::PeError;
use crate::emulator::mmu::Mmu;

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;

/// Apply base relocations to the in-memory image.
///
/// `delta = actual_load_base - preferred_base`. The caller has
/// already mapped the image; this function patches the bytes
/// in-place via [`Mmu::store32`] (the loader has the pages
/// mapped R+W at this point — `apply_section_permissions` has
/// not yet been called).
pub fn apply(mmu: &mut Mmu, parsed: &Parsed, image_base: u32, delta: u32) -> Result<(), PeError> {
    let dir = parsed.optional.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Ok(());
    }
    let mut cursor = image_base.wrapping_add(dir.virtual_address);
    let end = cursor.wrapping_add(dir.size);
    while cursor < end {
        let page_rva = mmu.load32(cursor)?;
        let block_size = mmu.load32(cursor.wrapping_add(4))?;
        if block_size < 8 || block_size % 2 != 0 {
            return Err(PeError::BadRelocBlock {
                rva: page_rva,
                reason: "bad block_size",
            });
        }
        let entries = (block_size - 8) / 2;
        let entry_base = cursor.wrapping_add(8);
        for i in 0..entries {
            let raw = mmu.load16(entry_base.wrapping_add(2 * i))?;
            let typ = (raw >> 12) & 0xF;
            let off = (raw & 0x0FFF) as u32;
            match typ {
                IMAGE_REL_BASED_ABSOLUTE => continue,
                IMAGE_REL_BASED_HIGHLOW => {
                    let target = image_base.wrapping_add(page_rva).wrapping_add(off);
                    let v = mmu.load32(target)?;
                    mmu.store32(target, v.wrapping_add(delta))?;
                }
                _ => {
                    return Err(PeError::BadRelocBlock {
                        rva: page_rva,
                        reason: "unsupported reloc type",
                    });
                }
            }
        }
        cursor = cursor.wrapping_add(block_size);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::mmu::Perm;
    use crate::pe::header::DataDirectory;

    fn parsed_with_dir(rva: u32, size: u32) -> Parsed {
        // Build a Parsed by hand — not going through the full
        // file parser. Only the field reloc::apply touches.
        let mut dirs = [DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = DataDirectory {
            virtual_address: rva,
            size,
        };
        Parsed {
            file: crate::pe::header::FileHeader {
                machine: 0x14C,
                number_of_sections: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional: crate::pe::header::OptionalHeader {
                magic: 0x10B,
                address_of_entry_point: 0,
                image_base: 0,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                size_of_image: 0,
                size_of_headers: 0,
                number_of_rva_and_sizes: 16,
                data_directories: dirs,
            },
            sections: Vec::new(),
            section_table_offset: 0,
        }
    }

    #[test]
    fn empty_reloc_dir_is_no_op() {
        let mut mmu = Mmu::new();
        let parsed = parsed_with_dir(0, 0);
        apply(&mut mmu, &parsed, 0x1000_0000, 0x100).unwrap();
    }

    #[test]
    fn highlow_relocation_applies_delta() {
        let mut mmu = Mmu::new();
        // Map a page for the .reloc section + a page that holds
        // the value being relocated.
        mmu.map(0x1000_0000, 0x2000, Perm::R | Perm::W);
        // Place a value 0x4000 at image_base + 0x100 (RVA 0x100).
        mmu.store32(0x1000_0100, 0x4000).unwrap();

        // Build a minimal .reloc directory at RVA 0x1000:
        //   page_rva = 0x0000 (covers RVA 0..0xFFF — but we're
        //   relocating something at 0x100, so this works).
        //   block_size = 8 + 2 (one 2-byte entry) = 10.
        //   entry: type=3 (HIGHLOW), offset=0x100.
        let block_off = 0x1000_1000u32;
        mmu.store32(block_off, 0).unwrap();
        mmu.store32(block_off + 4, 10).unwrap();
        let entry: u16 = (3u16 << 12) | 0x100;
        mmu.store16(block_off + 8, entry).unwrap();

        let parsed = parsed_with_dir(0x1000, 10);
        apply(&mut mmu, &parsed, 0x1000_0000, 0x500).unwrap();
        assert_eq!(mmu.load32(0x1000_0100).unwrap(), 0x4500);
    }
}

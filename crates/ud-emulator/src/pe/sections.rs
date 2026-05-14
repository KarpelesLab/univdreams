//! Section mapping into the emulator MMU.
//!
//! Reference: PE/COFF spec §"Section Table" + §"Section Flags".

use super::header::{Parsed, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use super::PeError;
use crate::emulator::mmu::{Mmu, Perm};

/// Loaded-section descriptor — the union of the file header's
/// `IMAGE_SECTION_HEADER` and the runtime layout choices we
/// make.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// Final VA where this section was mapped.
    pub va_start: u32,
    /// Mapped size (rounded up to the page size).
    pub mapped_size: u32,
    /// Final permission bits.
    pub perm: Perm,
}

const PAGE_SIZE: u32 = 0x1000;

/// Walk the parsed section table, copy raw bytes into emulator
/// memory, zero-fill the BSS tail, and record permissions to be
/// stamped on by [`apply_section_permissions`].
pub fn map_sections(mmu: &mut Mmu, parsed: &Parsed, bytes: &[u8]) -> Result<Vec<Section>, PeError> {
    let mut out = Vec::with_capacity(parsed.sections.len());
    let image_base = parsed.optional.image_base;

    // Map the headers themselves so the codec can read them via
    // RVA-relative reads.
    let hdrs_size = round_up(parsed.optional.size_of_headers, PAGE_SIZE);
    if hdrs_size > 0 {
        mmu.map(image_base, hdrs_size, Perm::R | Perm::W);
        let n = (parsed.optional.size_of_headers as usize).min(bytes.len());
        mmu.write_initializer(image_base, &bytes[..n])?;
    }

    for sh in &parsed.sections {
        let va = image_base.wrapping_add(sh.virtual_address);
        let virt = sh.virtual_size.max(sh.size_of_raw_data);
        let mapped = round_up(virt, PAGE_SIZE);

        // Map as R+W initially so write_initializer can populate.
        mmu.map(va, mapped, Perm::R | Perm::W);

        // Copy raw bytes from the file. `SizeOfRawData` may be
        // larger than `VirtualSize` (file alignment padding); we
        // copy `min(raw, virt)` to avoid overrunning the mapped
        // region.
        let copy_n = (sh.size_of_raw_data.min(virt)) as usize;
        let raw_off = sh.pointer_to_raw_data as usize;
        if copy_n > 0 {
            let src = bytes
                .get(raw_off..raw_off + copy_n)
                .ok_or(PeError::SectionOutOfRange {
                    name: sh.name.clone(),
                    raw_off: sh.pointer_to_raw_data,
                    raw_size: sh.size_of_raw_data,
                })?;
            mmu.write_initializer(va, src)?;
        }
        // Bytes beyond `copy_n` are already zero from the
        // `Mmu::map` allocation.

        // Final permissions per Characteristics flags.
        let mut perm = Perm::from_bits(0);
        if (sh.characteristics & IMAGE_SCN_MEM_READ) != 0 {
            perm = perm | Perm::R;
        }
        if (sh.characteristics & IMAGE_SCN_MEM_WRITE) != 0 {
            perm = perm | Perm::W;
        }
        if (sh.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {
            perm = perm | Perm::X;
        }
        // Empty perm sets are coerced to R-only — codec sections
        // tend to have at least one bit but malformed binaries
        // can ship zero, and a totally-no-perm region would be
        // unreachable.
        if perm.bits() == 0 {
            perm = Perm::R;
        }
        out.push(Section {
            name: sh.name.clone(),
            va_start: va,
            mapped_size: mapped,
            perm,
        });
    }
    Ok(out)
}

/// Stamp the recorded final permissions on each mapped page.
/// Done after import resolution + relocation so that the loader
/// can write into code pages while populating the IAT / fixups.
pub fn apply_section_permissions(mmu: &mut Mmu, section: &Section) {
    mmu.map(section.va_start, section.mapped_size, section.perm);
}

fn round_up(v: u32, align: u32) -> u32 {
    if align == 0 {
        v
    } else {
        v.div_ceil(align).wrapping_mul(align)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_helper() {
        assert_eq!(round_up(0, 0x1000), 0);
        assert_eq!(round_up(1, 0x1000), 0x1000);
        assert_eq!(round_up(0x1000, 0x1000), 0x1000);
        assert_eq!(round_up(0x1001, 0x1000), 0x2000);
    }
}

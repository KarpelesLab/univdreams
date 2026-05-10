//! Format-agnostic accessor for "what's at this virtual address?"
//!
//! `build_function` annotates `lea reg, [rip+disp]` and rendered
//! call args with the section + string content at the target
//! address. Without this trait, the annotation pass would couple to
//! [`Elf64File`] and would have no way to do the same for PE inputs.
//!
//! Implementors plug in for ELF (via `Shdr64::sh_addr` / on-disk
//! section data) and PE (via `SectionHeader::virtual_address` /
//! the file's raw bytes at the section's `pointer_to_raw_data`).
//!
//! [`Elf64File`]: ud_format_elf::Elf64File

/// Look up which section contains a given virtual address.
pub trait DataLookup {
    /// Return `(section_name, section_bytes, offset_within_section)`
    /// for the section that contains `vaddr`, or `None` when no
    /// section's `[start, end)` range covers it.
    fn section_at(&self, vaddr: u64) -> Option<(&str, &[u8], usize)>;
}

impl DataLookup for ud_format_elf::Elf64File {
    fn section_at(&self, vaddr: u64) -> Option<(&str, &[u8], usize)> {
        for (idx, sh, data) in self.sections() {
            if sh.sh_size == 0 {
                continue;
            }
            let end = sh.sh_addr.checked_add(sh.sh_size)?;
            if vaddr >= sh.sh_addr && vaddr < end {
                let offset = (vaddr - sh.sh_addr) as usize;
                let name = self.section_name(idx)?;
                return Some((name, data, offset));
            }
        }
        None
    }
}

impl DataLookup for ud_format_pe::PeFile {
    fn section_at(&self, vaddr: u64) -> Option<(&str, &[u8], usize)> {
        // PE addresses come in two flavours and we accept either:
        //
        // * RVA (image-relative): matches `section.virtual_address`
        //   directly — typical of operands inside a function body
        //   that iced sets up with the function's RVA as IP.
        // * VA (full virtual address = ImageBase + RVA): typical of
        //   immediate operands like `mov [esp], 0x40A00D` where the
        //   compiler emitted the absolute address of a string.
        //
        // We try matching as RVA first; if it doesn't land in any
        // section, retry by subtracting `image_base`.
        if let Some(hit) = self.section_at_rva(vaddr) {
            return Some(hit);
        }
        if vaddr >= self.image_base {
            return self.section_at_rva(vaddr - self.image_base);
        }
        None
    }
}

trait PeFileExt {
    fn section_at_rva(&self, rva: u64) -> Option<(&str, &[u8], usize)>;
}

impl PeFileExt for ud_format_pe::PeFile {
    fn section_at_rva(&self, rva: u64) -> Option<(&str, &[u8], usize)> {
        for (idx, sh) in self.sections.iter().enumerate() {
            let start = u64::from(sh.virtual_address);
            let size = u64::from(sh.virtual_size.max(sh.size_of_raw_data));
            if size == 0 {
                continue;
            }
            let end = start.checked_add(size)?;
            if rva < start || rva >= end {
                continue;
            }
            let data = self.section_data(idx)?;
            let offset = (rva - start) as usize;
            if offset >= data.len() {
                return None;
            }
            let name = self.section_name(idx).unwrap_or("");
            return Some((name, data, offset));
        }
        None
    }
}

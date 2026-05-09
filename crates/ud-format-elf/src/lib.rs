//! ELF64 reader and writer with byte-identical round-trip.
//!
//! This crate is intentionally narrow at this stage: it parses an ELF64
//! little-endian file into header/program-header/section-header structures
//! plus the raw bytes of each section and any interstitial padding, and
//! reassembles those parts back into bytes that match the input exactly.
//!
//! The contract: for any supported input `bytes`,
//! `Elf64File::parse(bytes)?.write_to_vec() == bytes`.
//!
//! Anything not in scope for this crate is preserved as opaque bytes and
//! re-emitted verbatim. Section *contents* (bytes inside `.text`, `.rodata`,
//! `.symtab`, etc.) are never interpreted here — that belongs to the arch
//! backends and analysis crates.

#![allow(clippy::cast_possible_truncation)]

use std::ops::Range;

/// Size of `e_ident` in any ELF.
const EI_NIDENT: usize = 16;

/// ELF magic bytes (`\x7fELF`) at the start of `e_ident`.
const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// `e_ident[EI_CLASS]` value for 64-bit objects.
const ELFCLASS64: u8 = 2;

/// `e_ident[EI_DATA]` value for 2's complement little-endian.
const ELFDATA2LSB: u8 = 1;

/// `sh_type` indicating the section occupies no file space (e.g. `.bss`).
const SHT_NOBITS: u32 = 8;

/// `sh_type` for a fully-linked symbol table.
pub const SHT_SYMTAB: u32 = 2;

/// `sh_type` for a string table.
pub const SHT_STRTAB: u32 = 3;

/// `sh_type` for the dynamic-linking symbol table (always present in dynamic
/// executables and shared objects).
pub const SHT_DYNSYM: u32 = 11;

/// `sh_flags` bit indicating the section contains executable instructions.
pub const SHF_EXECINSTR: u64 = 0x4;

/// `e_machine` value for x86-64.
pub const EM_X86_64: u16 = 62;

/// `e_machine` value for `AArch64`.
pub const EM_AARCH64: u16 = 183;

/// On-disk size of an ELF64 ELF header.
const EHDR64_SIZE: u16 = 64;

/// On-disk size of an ELF64 program header entry.
const PHDR64_SIZE: u16 = 56;

/// On-disk size of an ELF64 section header entry.
const SHDR64_SIZE: u16 = 64;

/// Errors surfaced when parsing or writing an ELF64 file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file too short: needed {needed} bytes at offset {offset}, have {have}")]
    Truncated { offset: u64, needed: u64, have: u64 },

    #[error("not an ELF file: bad magic {0:02x?}")]
    BadMagic([u8; 4]),

    #[error("unsupported ELF class: {0} (only ELFCLASS64 = 2 is implemented)")]
    UnsupportedClass(u8),

    #[error("unsupported ELF data encoding: {0} (only ELFDATA2LSB = 1 is implemented)")]
    UnsupportedEncoding(u8),

    #[error("unexpected e_ehsize: header says {got}, on-disk ELF64 size is {expected}")]
    BadEhsize { got: u16, expected: u16 },

    #[error("unexpected e_phentsize: header says {got}, on-disk ELF64 phdr size is {expected}")]
    BadPhentsize { got: u16, expected: u16 },

    #[error("unexpected e_shentsize: header says {got}, on-disk ELF64 shdr size is {expected}")]
    BadShentsize { got: u16, expected: u16 },

    #[error(
        "structured regions overlap: {a_label} at {a_start}..{a_end} vs {b_label} at {b_start}..{b_end}"
    )]
    OverlappingRegions {
        a_label: String,
        a_start: u64,
        a_end: u64,
        b_label: String,
        b_start: u64,
        b_end: u64,
    },

    #[error("integer overflow computing region end for {label} at offset {offset} size {size}")]
    RegionOverflow {
        label: String,
        offset: u64,
        size: u64,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Parsed ELF64 ELF header.
///
/// Field names mirror the ELF spec verbatim. The struct is public so
/// downstream crates can read these for analysis; mutation through public
/// fields is *not* part of a stability contract yet — invariants like
/// `e_ehsize == EHDR64_SIZE` are enforced only at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ehdr64 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Ehdr64 {
    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure_len(bytes, 0, EHDR64_SIZE.into())?;
        let mut e_ident = [0u8; EI_NIDENT];
        e_ident.copy_from_slice(&bytes[..EI_NIDENT]);

        if e_ident[0..4] != ELFMAG {
            let mut bad = [0u8; 4];
            bad.copy_from_slice(&e_ident[0..4]);
            return Err(Error::BadMagic(bad));
        }
        if e_ident[4] != ELFCLASS64 {
            return Err(Error::UnsupportedClass(e_ident[4]));
        }
        if e_ident[5] != ELFDATA2LSB {
            return Err(Error::UnsupportedEncoding(e_ident[5]));
        }

        let e_type = read_u16(bytes, 16);
        let e_machine = read_u16(bytes, 18);
        let e_version = read_u32(bytes, 20);
        let e_entry = read_u64(bytes, 24);
        let e_phoff = read_u64(bytes, 32);
        let e_shoff = read_u64(bytes, 40);
        let e_flags = read_u32(bytes, 48);
        let e_ehsize = read_u16(bytes, 52);
        let e_phentsize = read_u16(bytes, 54);
        let e_phnum = read_u16(bytes, 56);
        let e_shentsize = read_u16(bytes, 58);
        let e_shnum = read_u16(bytes, 60);
        let e_shstrndx = read_u16(bytes, 62);

        if e_ehsize != EHDR64_SIZE {
            return Err(Error::BadEhsize {
                got: e_ehsize,
                expected: EHDR64_SIZE,
            });
        }
        if e_phnum > 0 && e_phentsize != PHDR64_SIZE {
            return Err(Error::BadPhentsize {
                got: e_phentsize,
                expected: PHDR64_SIZE,
            });
        }
        if e_shnum > 0 && e_shentsize != SHDR64_SIZE {
            return Err(Error::BadShentsize {
                got: e_shentsize,
                expected: SHDR64_SIZE,
            });
        }

        Ok(Self {
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }

    fn write(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= EHDR64_SIZE as usize);
        out[..EI_NIDENT].copy_from_slice(&self.e_ident);
        write_u16(out, 16, self.e_type);
        write_u16(out, 18, self.e_machine);
        write_u32(out, 20, self.e_version);
        write_u64(out, 24, self.e_entry);
        write_u64(out, 32, self.e_phoff);
        write_u64(out, 40, self.e_shoff);
        write_u32(out, 48, self.e_flags);
        write_u16(out, 52, self.e_ehsize);
        write_u16(out, 54, self.e_phentsize);
        write_u16(out, 56, self.e_phnum);
        write_u16(out, 58, self.e_shentsize);
        write_u16(out, 60, self.e_shnum);
        write_u16(out, 62, self.e_shstrndx);
    }
}

/// Parsed ELF64 program header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phdr64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Phdr64 {
    fn parse(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= PHDR64_SIZE as usize);
        Self {
            p_type: read_u32(bytes, 0),
            p_flags: read_u32(bytes, 4),
            p_offset: read_u64(bytes, 8),
            p_vaddr: read_u64(bytes, 16),
            p_paddr: read_u64(bytes, 24),
            p_filesz: read_u64(bytes, 32),
            p_memsz: read_u64(bytes, 40),
            p_align: read_u64(bytes, 48),
        }
    }

    fn write(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= PHDR64_SIZE as usize);
        write_u32(out, 0, self.p_type);
        write_u32(out, 4, self.p_flags);
        write_u64(out, 8, self.p_offset);
        write_u64(out, 16, self.p_vaddr);
        write_u64(out, 24, self.p_paddr);
        write_u64(out, 32, self.p_filesz);
        write_u64(out, 40, self.p_memsz);
        write_u64(out, 48, self.p_align);
    }
}

/// Parsed ELF64 section header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shdr64 {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Shdr64 {
    fn parse(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= SHDR64_SIZE as usize);
        Self {
            sh_name: read_u32(bytes, 0),
            sh_type: read_u32(bytes, 4),
            sh_flags: read_u64(bytes, 8),
            sh_addr: read_u64(bytes, 16),
            sh_offset: read_u64(bytes, 24),
            sh_size: read_u64(bytes, 32),
            sh_link: read_u32(bytes, 40),
            sh_info: read_u32(bytes, 44),
            sh_addralign: read_u64(bytes, 48),
            sh_entsize: read_u64(bytes, 56),
        }
    }

    fn write(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= SHDR64_SIZE as usize);
        write_u32(out, 0, self.sh_name);
        write_u32(out, 4, self.sh_type);
        write_u64(out, 8, self.sh_flags);
        write_u64(out, 16, self.sh_addr);
        write_u64(out, 24, self.sh_offset);
        write_u64(out, 32, self.sh_size);
        write_u32(out, 40, self.sh_link);
        write_u32(out, 44, self.sh_info);
        write_u64(out, 48, self.sh_addralign);
        write_u64(out, 56, self.sh_entsize);
    }

    fn occupies_file(&self) -> bool {
        self.sh_type != SHT_NOBITS && self.sh_size > 0
    }
}

/// A parsed ELF64 file in a form that round-trips byte-identically.
///
/// The structured fields (`ehdr`, `phdrs`, `shdrs`) are interpreted; the
/// raw bytes inside sections and any interstitial padding are stored
/// verbatim. On `write_to_vec`, the structured fields are reassembled and
/// the verbatim bytes are dropped back in place at their original offsets.
#[derive(Debug, Clone)]
pub struct Elf64File {
    pub ehdr: Ehdr64,
    pub phdrs: Vec<Phdr64>,
    pub shdrs: Vec<Shdr64>,

    /// Section file content, parallel to `shdrs`. Empty for NOBITS or
    /// zero-size sections.
    section_data: Vec<Vec<u8>>,

    /// Bytes that fall in the gaps between structured regions (e.g.
    /// alignment padding between sections). Stored as `(file_offset, bytes)`.
    padding: Vec<(u64, Vec<u8>)>,

    /// Total size of the file, in bytes.
    file_size: u64,
}

/// Returns true if `bytes` start with the ELF magic.
///
/// This says nothing about class (32 vs 64) or endianness — a true return
/// means *some* flavor of ELF, not necessarily one this crate supports.
#[must_use]
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ELFMAG
}

/// Returns true iff `bytes` are an ELF64 little-endian image — the only
/// flavor [`Elf64File::parse`] handles. Callers that route by format
/// (e.g. the CLI's round-trip pipeline) should gate on this and fall
/// through to a byte-copy for unsupported variants so the round-trip
/// contract still holds.
#[must_use]
pub fn is_elf64_le(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes[..4] == ELFMAG && bytes[4] == ELFCLASS64 && bytes[5] == ELFDATA2LSB
}

impl Elf64File {
    /// Parse an ELF64 LE file into a structure that round-trips byte-identically.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let ehdr = Ehdr64::parse(bytes)?;

        let phdrs = Self::parse_phdrs(bytes, &ehdr)?;
        let (shdrs, section_data) = Self::parse_shdrs_and_sections(bytes, &ehdr)?;

        let regions = build_regions(&ehdr, &shdrs)?;
        let padding = compute_padding(bytes, &regions);

        Ok(Self {
            ehdr,
            phdrs,
            shdrs,
            section_data,
            padding,
            file_size: bytes.len() as u64,
        })
    }

    fn parse_phdrs(bytes: &[u8], ehdr: &Ehdr64) -> Result<Vec<Phdr64>> {
        let count = ehdr.e_phnum as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let entry_size = PHDR64_SIZE as usize;
        let total = count
            .checked_mul(entry_size)
            .ok_or_else(|| Error::RegionOverflow {
                label: "program-header table".into(),
                offset: ehdr.e_phoff,
                size: count as u64 * entry_size as u64,
            })?;
        ensure_len(bytes, ehdr.e_phoff, total as u64)?;
        let start = ehdr.e_phoff as usize;
        let mut phdrs = Vec::with_capacity(count);
        for i in 0..count {
            let off = start + i * entry_size;
            phdrs.push(Phdr64::parse(&bytes[off..off + entry_size]));
        }
        Ok(phdrs)
    }

    fn parse_shdrs_and_sections(
        bytes: &[u8],
        ehdr: &Ehdr64,
    ) -> Result<(Vec<Shdr64>, Vec<Vec<u8>>)> {
        let count = ehdr.e_shnum as usize;
        if count == 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let entry_size = SHDR64_SIZE as usize;
        let total = count
            .checked_mul(entry_size)
            .ok_or_else(|| Error::RegionOverflow {
                label: "section-header table".into(),
                offset: ehdr.e_shoff,
                size: count as u64 * entry_size as u64,
            })?;
        ensure_len(bytes, ehdr.e_shoff, total as u64)?;
        let start = ehdr.e_shoff as usize;

        let mut shdrs = Vec::with_capacity(count);
        let mut section_data = Vec::with_capacity(count);
        for i in 0..count {
            let off = start + i * entry_size;
            let sh = Shdr64::parse(&bytes[off..off + entry_size]);
            if sh.occupies_file() {
                ensure_len(bytes, sh.sh_offset, sh.sh_size)?;
                let data_off = sh.sh_offset as usize;
                let data_end = data_off + sh.sh_size as usize;
                section_data.push(bytes[data_off..data_end].to_vec());
            } else {
                section_data.push(Vec::new());
            }
            shdrs.push(sh);
        }
        Ok((shdrs, section_data))
    }

    /// Raw on-disk bytes of the section at index `idx`, parallel to
    /// [`Self::shdrs`]. Returns an empty slice for NOBITS or zero-size
    /// sections. Returns `None` only for an out-of-range index.
    #[must_use]
    pub fn section_data(&self, idx: usize) -> Option<&[u8]> {
        self.section_data.get(idx).map(Vec::as_slice)
    }

    /// Iterator over `(index, &Shdr64, &[u8])` for every section.
    pub fn sections(&self) -> impl Iterator<Item = (usize, &Shdr64, &[u8])> {
        self.shdrs
            .iter()
            .zip(&self.section_data)
            .enumerate()
            .map(|(i, (sh, data))| (i, sh, data.as_slice()))
    }

    /// Resolve the section's name through the section-header string
    /// table (`.shstrtab`, indexed by `e_shstrndx`).
    ///
    /// Returns `None` if the section index is out of range, the
    /// `e_shstrndx` points outside the section table, the name offset
    /// is past the end of `.shstrtab`, or the bytes aren't valid UTF-8
    /// (which would indicate a malformed or non-standard ELF; real
    /// toolchains write ASCII section names).
    #[must_use]
    pub fn section_name(&self, idx: usize) -> Option<&str> {
        let shstrtab = self.section_data(self.ehdr.e_shstrndx as usize)?;
        let sh = self.shdrs.get(idx)?;
        let start = sh.sh_name as usize;
        let tail = shstrtab.get(start..)?;
        let nul = tail.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&tail[..nul]).ok()
    }

    /// Find the first section with the given name.
    ///
    /// Iterates section headers in order, so for ELFs with multiple
    /// sections sharing a name (rare but legal) the lowest-indexed one
    /// wins.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<(usize, &Shdr64, &[u8])> {
        for (i, sh, data) in self.sections() {
            if self.section_name(i) == Some(name) {
                return Some((i, sh, data));
            }
        }
        None
    }

    /// Serialize the parsed file back to bytes. For any input parsed from
    /// real bytes, the output is byte-identical to the input.
    #[must_use]
    pub fn write_to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.file_size as usize];

        self.ehdr.write(&mut out[..EHDR64_SIZE as usize]);

        if !self.phdrs.is_empty() {
            let start = self.ehdr.e_phoff as usize;
            let entry_size = PHDR64_SIZE as usize;
            for (i, ph) in self.phdrs.iter().enumerate() {
                let off = start + i * entry_size;
                ph.write(&mut out[off..off + entry_size]);
            }
        }

        if !self.shdrs.is_empty() {
            let start = self.ehdr.e_shoff as usize;
            let entry_size = SHDR64_SIZE as usize;
            for (i, sh) in self.shdrs.iter().enumerate() {
                let off = start + i * entry_size;
                sh.write(&mut out[off..off + entry_size]);
            }
        }

        for (sh, data) in self.shdrs.iter().zip(&self.section_data) {
            if sh.occupies_file() {
                let off = sh.sh_offset as usize;
                out[off..off + data.len()].copy_from_slice(data);
            }
        }

        for (offset, bytes) in &self.padding {
            let off = *offset as usize;
            out[off..off + bytes.len()].copy_from_slice(bytes);
        }

        out
    }
}

/// A "structured" file region — something the parser tracks by interpretation.
#[derive(Debug, Clone)]
struct Region {
    label: String,
    range: Range<u64>,
}

fn build_regions(ehdr: &Ehdr64, shdrs: &[Shdr64]) -> Result<Vec<Region>> {
    let mut regions = Vec::new();

    regions.push(Region {
        label: "ELF header".into(),
        range: 0..u64::from(EHDR64_SIZE),
    });

    if ehdr.e_phnum > 0 {
        let size = u64::from(ehdr.e_phnum) * u64::from(PHDR64_SIZE);
        let end = ehdr
            .e_phoff
            .checked_add(size)
            .ok_or_else(|| Error::RegionOverflow {
                label: "program-header table".into(),
                offset: ehdr.e_phoff,
                size,
            })?;
        regions.push(Region {
            label: "program-header table".into(),
            range: ehdr.e_phoff..end,
        });
    }

    if ehdr.e_shnum > 0 {
        let size = u64::from(ehdr.e_shnum) * u64::from(SHDR64_SIZE);
        let end = ehdr
            .e_shoff
            .checked_add(size)
            .ok_or_else(|| Error::RegionOverflow {
                label: "section-header table".into(),
                offset: ehdr.e_shoff,
                size,
            })?;
        regions.push(Region {
            label: "section-header table".into(),
            range: ehdr.e_shoff..end,
        });
    }

    for (i, sh) in shdrs.iter().enumerate() {
        if !sh.occupies_file() {
            continue;
        }
        let end = sh
            .sh_offset
            .checked_add(sh.sh_size)
            .ok_or_else(|| Error::RegionOverflow {
                label: format!("section #{i}"),
                offset: sh.sh_offset,
                size: sh.sh_size,
            })?;
        regions.push(Region {
            label: format!("section #{i}"),
            range: sh.sh_offset..end,
        });
    }

    regions.sort_by_key(|r| r.range.start);

    for pair in regions.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        if a.range.end > b.range.start {
            return Err(Error::OverlappingRegions {
                a_label: a.label.clone(),
                a_start: a.range.start,
                a_end: a.range.end,
                b_label: b.label.clone(),
                b_start: b.range.start,
                b_end: b.range.end,
            });
        }
    }

    Ok(regions)
}

fn compute_padding(bytes: &[u8], regions: &[Region]) -> Vec<(u64, Vec<u8>)> {
    let mut padding = Vec::new();
    let file_end = bytes.len() as u64;
    let mut cursor = 0u64;
    for region in regions {
        if region.range.start > cursor {
            let start = cursor as usize;
            let end = region.range.start as usize;
            padding.push((cursor, bytes[start..end].to_vec()));
        }
        cursor = cursor.max(region.range.end);
    }
    if cursor < file_end {
        let start = cursor as usize;
        let end = file_end as usize;
        padding.push((cursor, bytes[start..end].to_vec()));
    }
    padding
}

fn ensure_len(bytes: &[u8], offset: u64, needed: u64) -> Result<()> {
    let have = bytes.len() as u64;
    let end = offset.checked_add(needed).ok_or(Error::Truncated {
        offset,
        needed,
        have,
    })?;
    if end > have {
        return Err(Error::Truncated {
            offset,
            needed,
            have,
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("slice was 2 bytes"))
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("slice was 4 bytes"))
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("slice was 8 bytes"))
}

fn write_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ehdr_bytes() -> Vec<u8> {
        let mut v = vec![0u8; EHDR64_SIZE as usize];
        v[0..4].copy_from_slice(&ELFMAG);
        v[4] = ELFCLASS64;
        v[5] = ELFDATA2LSB;
        v[6] = 1; // EV_CURRENT
                  // e_type = ET_NONE; e_machine = 0; e_version = 1; rest zeroed.
        v[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_ehsize = 64
        v[52..54].copy_from_slice(&EHDR64_SIZE.to_le_bytes());
        // e_phnum = 0, e_shnum = 0 → e_phentsize/e_shentsize unchecked
        v
    }

    #[test]
    fn rejects_non_elf() {
        let mut v = minimal_ehdr_bytes();
        v[0] = 0xff;
        let err = Elf64File::parse(&v).unwrap_err();
        assert!(matches!(err, Error::BadMagic(_)));
    }

    #[test]
    fn rejects_32bit_class() {
        let mut v = minimal_ehdr_bytes();
        v[4] = 1; // ELFCLASS32
        let err = Elf64File::parse(&v).unwrap_err();
        assert!(matches!(err, Error::UnsupportedClass(1)));
    }

    #[test]
    fn rejects_big_endian() {
        let mut v = minimal_ehdr_bytes();
        v[5] = 2; // ELFDATA2MSB
        let err = Elf64File::parse(&v).unwrap_err();
        assert!(matches!(err, Error::UnsupportedEncoding(2)));
    }

    #[test]
    fn parses_minimal_ehdr_only() {
        let v = minimal_ehdr_bytes();
        let file = Elf64File::parse(&v).expect("minimal ehdr should parse");
        assert_eq!(file.ehdr.e_ehsize, EHDR64_SIZE);
        assert!(file.phdrs.is_empty());
        assert!(file.shdrs.is_empty());
        assert_eq!(file.write_to_vec(), v);
    }

    #[test]
    fn detects_truncation_in_phdrs() {
        let mut v = minimal_ehdr_bytes();
        v[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
        v[54..56].copy_from_slice(&PHDR64_SIZE.to_le_bytes());
        v[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
                                                         // file ends at 64 → no room for the phdr.
        let err = Elf64File::parse(&v).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }
}

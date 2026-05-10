//! PE/COFF reader and writer with byte-identical round-trip.
//!
//! v0 scope: parse the structural skeleton (DOS header, PE
//! signature, COFF file header, optional header, section header
//! table) into typed fields, and capture every byte of the input
//! file so [`PeFile::write_to_vec`] returns it back unchanged.
//! Section *contents* and any data outside the structural skeleton
//! (DOS stub, optional header body, certificate table, etc.) are
//! preserved verbatim and not re-interpreted.
//!
//! The contract: for any supported input `bytes`,
//! `PeFile::parse(bytes)?.write_to_vec() == bytes`.
//!
//! Down the road this crate will grow:
//!
//! * Structured optional-header fields and data-directory entries.
//! * Editable section data with a write path that re-derives
//!   PointerToRawData / SizeOfRawData on serialise.
//! * Import-table parsing so the analysis crate can name PE call
//!   sites the way ELF's `ud-analysis::plt` names PLT thunks.
//!
//! For now the parser exists to validate input is a real PE and
//! expose section metadata for higher layers; the byte-identity
//! comes from re-emitting the original buffer.

#![allow(clippy::cast_possible_truncation)]

/// `e_magic` value of `IMAGE_DOS_HEADER`: ASCII "MZ".
pub const DOS_MAGIC: [u8; 2] = *b"MZ";

/// PE signature appearing at `IMAGE_DOS_HEADER::e_lfanew`: ASCII
/// "PE\0\0".
pub const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";

/// `Machine` value for i386 (`IMAGE_FILE_MACHINE_I386`).
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

/// `Machine` value for x86-64 (`IMAGE_FILE_MACHINE_AMD64`).
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// `Machine` value for `AArch64` (`IMAGE_FILE_MACHINE_ARM64`).
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// On-disk size of `IMAGE_DOS_HEADER`.
const DOS_HEADER_SIZE: usize = 64;

/// Offset of `e_lfanew` within `IMAGE_DOS_HEADER`.
const E_LFANEW_OFFSET: usize = 0x3c;

/// On-disk size of `IMAGE_FILE_HEADER` (the COFF header).
const COFF_HEADER_SIZE: usize = 20;

/// On-disk size of an `IMAGE_SECTION_HEADER` entry.
pub const SECTION_HEADER_SIZE: usize = 40;

/// `Magic` value at the start of `IMAGE_OPTIONAL_HEADER` for PE32
/// (32-bit images).
pub const OPTIONAL_HEADER_MAGIC_PE32: u16 = 0x010b;

/// `Magic` value at the start of `IMAGE_OPTIONAL_HEADER64` for PE32+
/// (64-bit images).
pub const OPTIONAL_HEADER_MAGIC_PE32_PLUS: u16 = 0x020b;

/// Errors surfaced when parsing or writing a PE file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file too short: needed {needed} bytes at offset {offset}, have {have}")]
    Truncated { offset: u64, needed: u64, have: u64 },

    #[error("not a PE file: bad DOS magic {0:02x?}")]
    BadDosMagic([u8; 2]),

    #[error("`e_lfanew` 0x{e_lfanew:x} points outside the file (size {file_size})")]
    LfanewOutOfRange { e_lfanew: u32, file_size: u64 },

    #[error("not a PE file: PE signature is {0:02x?}")]
    BadPeSignature([u8; 4]),

    #[error("optional-header magic 0x{0:04x} is neither PE32 (0x10b) nor PE32+ (0x20b)")]
    UnsupportedOptionalMagic(u16),

    #[error("integer overflow computing region end for {label} at offset {offset} size {size}")]
    RegionOverflow {
        label: String,
        offset: u64,
        size: u64,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// PE32 vs PE32+ — the optional header's structural variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    /// PE32 (32-bit image).
    Pe32,
    /// PE32+ (64-bit image).
    Pe32Plus,
}

/// Parsed `IMAGE_FILE_HEADER` (a.k.a. COFF header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Parsed `IMAGE_SECTION_HEADER`.
///
/// `name` is the raw 8-byte field; for "long" names that start with
/// `'/'` followed by a decimal offset into the COFF string table,
/// callers are responsible for resolving via the symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// A parsed PE file. The structured fields are read-only views; the
/// authoritative bytes live in [`PeFile::raw`] and are what
/// [`write_to_vec`] returns. Future iterations will replace this with
/// a re-derive-on-write path; for v0 the round-trip is guaranteed
/// trivially because we don't mutate the buffer.
///
/// [`write_to_vec`]: PeFile::write_to_vec
#[derive(Debug, Clone)]
pub struct PeFile {
    /// Optional-header magic (PE32 vs PE32+).
    pub kind: PeKind,
    /// File offset of the PE signature.
    pub e_lfanew: u32,
    /// COFF header values.
    pub coff: CoffHeader,
    /// Section header table, in declaration order.
    pub sections: Vec<SectionHeader>,
    /// The complete file bytes; this is what `write_to_vec`
    /// returns, byte-for-byte.
    raw: Vec<u8>,
}

impl PeFile {
    /// Parse a PE file. Validates the structural skeleton (DOS
    /// header, PE signature, COFF + optional + section headers) but
    /// leaves the rest as opaque bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DOS_HEADER_SIZE {
            return Err(Error::Truncated {
                offset: 0,
                needed: DOS_HEADER_SIZE as u64,
                have: bytes.len() as u64,
            });
        }
        let mut dos_magic = [0u8; 2];
        dos_magic.copy_from_slice(&bytes[..2]);
        if dos_magic != DOS_MAGIC {
            return Err(Error::BadDosMagic(dos_magic));
        }

        let e_lfanew = read_u32(bytes, E_LFANEW_OFFSET);
        let pe_off = e_lfanew as usize;
        if (pe_off as u64) > bytes.len() as u64 {
            return Err(Error::LfanewOutOfRange {
                e_lfanew,
                file_size: bytes.len() as u64,
            });
        }
        ensure_len(bytes, pe_off as u64, 4)?;
        let mut sig = [0u8; 4];
        sig.copy_from_slice(&bytes[pe_off..pe_off + 4]);
        if sig != PE_SIGNATURE {
            return Err(Error::BadPeSignature(sig));
        }

        let coff_off = pe_off + 4;
        ensure_len(bytes, coff_off as u64, COFF_HEADER_SIZE as u64)?;
        let coff = parse_coff_header(&bytes[coff_off..coff_off + COFF_HEADER_SIZE]);

        let opt_off = coff_off + COFF_HEADER_SIZE;
        let opt_size = coff.size_of_optional_header as usize;
        ensure_len(bytes, opt_off as u64, opt_size as u64)?;
        let kind = if opt_size == 0 {
            // Object files have no optional header. Default to PE32+
            // for typing purposes; the kind is informational only.
            PeKind::Pe32Plus
        } else {
            ensure_len(bytes, opt_off as u64, 2)?;
            let magic = read_u16(bytes, opt_off);
            match magic {
                OPTIONAL_HEADER_MAGIC_PE32 => PeKind::Pe32,
                OPTIONAL_HEADER_MAGIC_PE32_PLUS => PeKind::Pe32Plus,
                other => return Err(Error::UnsupportedOptionalMagic(other)),
            }
        };

        let sec_off = opt_off + opt_size;
        let sec_count = coff.number_of_sections as usize;
        let sec_total =
            sec_count
                .checked_mul(SECTION_HEADER_SIZE)
                .ok_or_else(|| Error::RegionOverflow {
                    label: "section header table".into(),
                    offset: sec_off as u64,
                    size: sec_count as u64 * SECTION_HEADER_SIZE as u64,
                })?;
        ensure_len(bytes, sec_off as u64, sec_total as u64)?;
        let mut sections = Vec::with_capacity(sec_count);
        for i in 0..sec_count {
            let off = sec_off + i * SECTION_HEADER_SIZE;
            sections.push(parse_section_header(&bytes[off..off + SECTION_HEADER_SIZE]));
        }

        Ok(Self {
            kind,
            e_lfanew,
            coff,
            sections,
            raw: bytes.to_vec(),
        })
    }

    /// Total size of the parsed file in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.raw.len() as u64
    }

    /// Raw bytes of the entire file. Stable as long as `PeFile`
    /// hasn't been mutated through a (currently nonexistent) edit
    /// API.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Raw bytes of `sections[idx]`'s on-disk contents, or `None`
    /// for an out-of-range index. Returns an empty slice when the
    /// section's `SizeOfRawData` is zero (uninitialised data, e.g.
    /// `.bss`).
    #[must_use]
    pub fn section_data(&self, idx: usize) -> Option<&[u8]> {
        let sh = self.sections.get(idx)?;
        let start = sh.pointer_to_raw_data as usize;
        let size = sh.size_of_raw_data as usize;
        if size == 0 {
            return Some(&[]);
        }
        self.raw.get(start..start.checked_add(size)?)
    }

    /// Resolve a section header's "short" name as a UTF-8 string
    /// trimmed to the first NUL. Long names (those starting with
    /// `'/'` followed by a decimal offset) are returned verbatim;
    /// the COFF string table that resolves them isn't yet parsed.
    #[must_use]
    pub fn section_name(&self, idx: usize) -> Option<String> {
        let sh = self.sections.get(idx)?;
        let nul = sh
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sh.name.len());
        std::str::from_utf8(&sh.name[..nul])
            .ok()
            .map(str::to_string)
    }

    /// Serialize back to bytes. Always byte-identical to the input
    /// in v0 — the parsed file stores the original buffer and we
    /// simply hand it back.
    #[must_use]
    pub fn write_to_vec(&self) -> Vec<u8> {
        self.raw.clone()
    }
}

/// Returns true if `bytes` look like a PE file (start with the DOS
/// `MZ` magic and have a parseable `e_lfanew`).
#[must_use]
pub fn is_pe(bytes: &[u8]) -> bool {
    bytes.len() >= DOS_HEADER_SIZE && bytes[..2] == DOS_MAGIC
}

fn parse_coff_header(bytes: &[u8]) -> CoffHeader {
    debug_assert!(bytes.len() >= COFF_HEADER_SIZE);
    CoffHeader {
        machine: read_u16(bytes, 0),
        number_of_sections: read_u16(bytes, 2),
        time_date_stamp: read_u32(bytes, 4),
        pointer_to_symbol_table: read_u32(bytes, 8),
        number_of_symbols: read_u32(bytes, 12),
        size_of_optional_header: read_u16(bytes, 16),
        characteristics: read_u16(bytes, 18),
    }
}

fn parse_section_header(bytes: &[u8]) -> SectionHeader {
    debug_assert!(bytes.len() >= SECTION_HEADER_SIZE);
    let mut name = [0u8; 8];
    name.copy_from_slice(&bytes[0..8]);
    SectionHeader {
        name,
        virtual_size: read_u32(bytes, 8),
        virtual_address: read_u32(bytes, 12),
        size_of_raw_data: read_u32(bytes, 16),
        pointer_to_raw_data: read_u32(bytes, 20),
        pointer_to_relocations: read_u32(bytes, 24),
        pointer_to_linenumbers: read_u32(bytes, 28),
        number_of_relocations: read_u16(bytes, 32),
        number_of_linenumbers: read_u16(bytes, 34),
        characteristics: read_u32(bytes, 36),
    }
}

fn ensure_len(bytes: &[u8], offset: u64, needed: u64) -> Result<()> {
    let end = offset
        .checked_add(needed)
        .ok_or_else(|| Error::RegionOverflow {
            label: "ensure_len".into(),
            offset,
            size: needed,
        })?;
    if end > bytes.len() as u64 {
        return Err(Error::Truncated {
            offset,
            needed,
            have: bytes.len() as u64,
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe_bytes() -> Vec<u8> {
        // Smallest synthetic PE: DOS header → PE signature → COFF
        // header (no sections, no optional header). Used to exercise
        // the structural-validation code paths in isolation.
        let mut v = vec![0u8; 0x80];
        // DOS magic
        v[0..2].copy_from_slice(&DOS_MAGIC);
        // e_lfanew → 0x40
        v[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0x40_u32.to_le_bytes());
        // PE signature at 0x40
        v[0x40..0x44].copy_from_slice(&PE_SIGNATURE);
        // COFF header at 0x44 — Machine = i386, all other fields 0.
        v[0x44..0x46].copy_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
        // Tail-pad so total length covers the 20-byte COFF header.
        v
    }

    #[test]
    fn parses_minimal_pe() {
        let v = minimal_pe_bytes();
        let pe = PeFile::parse(&v).unwrap();
        assert_eq!(pe.coff.machine, IMAGE_FILE_MACHINE_I386);
        assert_eq!(pe.coff.number_of_sections, 0);
        assert!(pe.sections.is_empty());
    }

    #[test]
    fn round_trips_minimal_pe() {
        let v = minimal_pe_bytes();
        let pe = PeFile::parse(&v).unwrap();
        assert_eq!(pe.write_to_vec(), v);
    }

    #[test]
    fn rejects_bad_dos_magic() {
        let mut v = minimal_pe_bytes();
        v[0] = b'X';
        let err = PeFile::parse(&v).unwrap_err();
        assert!(matches!(err, Error::BadDosMagic(_)));
    }

    #[test]
    fn rejects_bad_pe_signature() {
        let mut v = minimal_pe_bytes();
        v[0x40] = b'X';
        let err = PeFile::parse(&v).unwrap_err();
        assert!(matches!(err, Error::BadPeSignature(_)));
    }

    #[test]
    fn rejects_lfanew_past_end() {
        let mut v = minimal_pe_bytes();
        v[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        let err = PeFile::parse(&v).unwrap_err();
        assert!(matches!(err, Error::LfanewOutOfRange { .. }));
    }

    #[test]
    fn is_pe_recognises_dos_header() {
        let v = minimal_pe_bytes();
        assert!(is_pe(&v));
    }

    #[test]
    fn is_pe_rejects_short_input() {
        assert!(!is_pe(&[0u8; 10]));
    }
}

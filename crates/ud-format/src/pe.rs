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

/// On-disk size of one COFF symbol-table entry (main or aux).
pub const COFF_SYMBOL_SIZE: usize = 18;

/// `Type` field high nibble: function (`IMAGE_SYM_DTYPE_FUNCTION`).
pub const COFF_DTYPE_FUNCTION: u16 = 0x20;

/// `StorageClass`: external (`IMAGE_SYM_CLASS_EXTERNAL`).
pub const COFF_SYM_CLASS_EXTERNAL: u8 = 2;

/// `StorageClass`: static (`IMAGE_SYM_CLASS_STATIC`).
pub const COFF_SYM_CLASS_STATIC: u8 = 3;

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

/// Parsed `IMAGE_DOS_HEADER` (the 64-byte prefix every PE file
/// starts with). The fields that aren't meaningful for modern
/// PE files (the original 16-bit DOS layout descriptors) round
/// through verbatim — typical values are `e_cblp = 0x90`,
/// `e_cparhdr = 0x4`, `e_minalloc = 0`, `e_maxalloc = 0xffff`,
/// `e_sp = 0xb8`, with reserved fields zero. The two fields
/// that matter for the modern format are `e_magic` (`"MZ"`)
/// and `e_lfanew` (file offset of the PE signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosHeader {
    pub e_magic: [u8; 2],
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl DosHeader {
    fn parse(bytes: &[u8]) -> Self {
        let mut h = DosHeader {
            e_magic: [bytes[0], bytes[1]],
            e_cblp: read_u16(bytes, 2),
            e_cp: read_u16(bytes, 4),
            e_crlc: read_u16(bytes, 6),
            e_cparhdr: read_u16(bytes, 8),
            e_minalloc: read_u16(bytes, 10),
            e_maxalloc: read_u16(bytes, 12),
            e_ss: read_u16(bytes, 14),
            e_sp: read_u16(bytes, 16),
            e_csum: read_u16(bytes, 18),
            e_ip: read_u16(bytes, 20),
            e_cs: read_u16(bytes, 22),
            e_lfarlc: read_u16(bytes, 24),
            e_ovno: read_u16(bytes, 26),
            e_res: [0; 4],
            e_oemid: read_u16(bytes, 36),
            e_oeminfo: read_u16(bytes, 38),
            e_res2: [0; 10],
            e_lfanew: read_u32(bytes, E_LFANEW_OFFSET),
        };
        for i in 0..4 {
            h.e_res[i] = read_u16(bytes, 28 + 2 * i);
        }
        for i in 0..10 {
            h.e_res2[i] = read_u16(bytes, 40 + 2 * i);
        }
        h
    }

    /// Encode the 64-byte DOS header.
    #[must_use]
    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..2].copy_from_slice(&self.e_magic);
        out[2..4].copy_from_slice(&self.e_cblp.to_le_bytes());
        out[4..6].copy_from_slice(&self.e_cp.to_le_bytes());
        out[6..8].copy_from_slice(&self.e_crlc.to_le_bytes());
        out[8..10].copy_from_slice(&self.e_cparhdr.to_le_bytes());
        out[10..12].copy_from_slice(&self.e_minalloc.to_le_bytes());
        out[12..14].copy_from_slice(&self.e_maxalloc.to_le_bytes());
        out[14..16].copy_from_slice(&self.e_ss.to_le_bytes());
        out[16..18].copy_from_slice(&self.e_sp.to_le_bytes());
        out[18..20].copy_from_slice(&self.e_csum.to_le_bytes());
        out[20..22].copy_from_slice(&self.e_ip.to_le_bytes());
        out[22..24].copy_from_slice(&self.e_cs.to_le_bytes());
        out[24..26].copy_from_slice(&self.e_lfarlc.to_le_bytes());
        out[26..28].copy_from_slice(&self.e_ovno.to_le_bytes());
        for i in 0..4 {
            out[28 + 2 * i..30 + 2 * i].copy_from_slice(&self.e_res[i].to_le_bytes());
        }
        out[36..38].copy_from_slice(&self.e_oemid.to_le_bytes());
        out[38..40].copy_from_slice(&self.e_oeminfo.to_le_bytes());
        for i in 0..10 {
            out[40 + 2 * i..42 + 2 * i].copy_from_slice(&self.e_res2[i].to_le_bytes());
        }
        out[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&self.e_lfanew.to_le_bytes());
        out
    }
}

/// Parsed `IMAGE_OPTIONAL_HEADER` / `IMAGE_OPTIONAL_HEADER64`.
/// One struct handles both PE32 and PE32+ variants; the
/// 32-bit ImageBase / stack / heap sizes are stored as `u64`
/// for uniformity and zero-extended on read.
///
/// The data directories at the tail of the optional header
/// aren't stored here — see [`PeFile::data_directories`]. The
/// `number_of_rva_and_sizes` field tells the encoder how many
/// directory slots to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    /// PE32 only — the address of the data section. Always 0
    /// in PE32+ since 64-bit images don't have this field.
    pub base_of_data: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

impl OptionalHeader {
    /// Parse from `bytes` (whose length is `coff.size_of_optional_header`).
    /// Returns `None` when the buffer is too short or the magic is
    /// neither PE32 nor PE32+; the parser falls back to a default-zero
    /// header in those cases.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return Option::None;
        }
        let magic = read_u16(bytes, 0);
        match magic {
            OPTIONAL_HEADER_MAGIC_PE32 => Self::parse_pe32(bytes, magic),
            OPTIONAL_HEADER_MAGIC_PE32_PLUS => Self::parse_pe32_plus(bytes, magic),
            _ => Option::None,
        }
    }

    fn parse_pe32(bytes: &[u8], magic: u16) -> Option<Self> {
        if bytes.len() < 96 {
            return Option::None;
        }
        Some(Self {
            magic,
            major_linker_version: bytes[2],
            minor_linker_version: bytes[3],
            size_of_code: read_u32(bytes, 4),
            size_of_initialized_data: read_u32(bytes, 8),
            size_of_uninitialized_data: read_u32(bytes, 12),
            address_of_entry_point: read_u32(bytes, 16),
            base_of_code: read_u32(bytes, 20),
            base_of_data: read_u32(bytes, 24),
            image_base: u64::from(read_u32(bytes, 28)),
            section_alignment: read_u32(bytes, 32),
            file_alignment: read_u32(bytes, 36),
            major_operating_system_version: read_u16(bytes, 40),
            minor_operating_system_version: read_u16(bytes, 42),
            major_image_version: read_u16(bytes, 44),
            minor_image_version: read_u16(bytes, 46),
            major_subsystem_version: read_u16(bytes, 48),
            minor_subsystem_version: read_u16(bytes, 50),
            win32_version_value: read_u32(bytes, 52),
            size_of_image: read_u32(bytes, 56),
            size_of_headers: read_u32(bytes, 60),
            check_sum: read_u32(bytes, 64),
            subsystem: read_u16(bytes, 68),
            dll_characteristics: read_u16(bytes, 70),
            size_of_stack_reserve: u64::from(read_u32(bytes, 72)),
            size_of_stack_commit: u64::from(read_u32(bytes, 76)),
            size_of_heap_reserve: u64::from(read_u32(bytes, 80)),
            size_of_heap_commit: u64::from(read_u32(bytes, 84)),
            loader_flags: read_u32(bytes, 88),
            number_of_rva_and_sizes: read_u32(bytes, 92),
        })
    }

    fn parse_pe32_plus(bytes: &[u8], magic: u16) -> Option<Self> {
        if bytes.len() < 112 {
            return Option::None;
        }
        Some(Self {
            magic,
            major_linker_version: bytes[2],
            minor_linker_version: bytes[3],
            size_of_code: read_u32(bytes, 4),
            size_of_initialized_data: read_u32(bytes, 8),
            size_of_uninitialized_data: read_u32(bytes, 12),
            address_of_entry_point: read_u32(bytes, 16),
            base_of_code: read_u32(bytes, 20),
            base_of_data: 0,
            image_base: read_u64(bytes, 24),
            section_alignment: read_u32(bytes, 32),
            file_alignment: read_u32(bytes, 36),
            major_operating_system_version: read_u16(bytes, 40),
            minor_operating_system_version: read_u16(bytes, 42),
            major_image_version: read_u16(bytes, 44),
            minor_image_version: read_u16(bytes, 46),
            major_subsystem_version: read_u16(bytes, 48),
            minor_subsystem_version: read_u16(bytes, 50),
            win32_version_value: read_u32(bytes, 52),
            size_of_image: read_u32(bytes, 56),
            size_of_headers: read_u32(bytes, 60),
            check_sum: read_u32(bytes, 64),
            subsystem: read_u16(bytes, 68),
            dll_characteristics: read_u16(bytes, 70),
            size_of_stack_reserve: read_u64(bytes, 72),
            size_of_stack_commit: read_u64(bytes, 80),
            size_of_heap_reserve: read_u64(bytes, 88),
            size_of_heap_commit: read_u64(bytes, 96),
            loader_flags: read_u32(bytes, 104),
            number_of_rva_and_sizes: read_u32(bytes, 108),
        })
    }

    /// Encode the optional header (without trailing data
    /// directories) into the buffer at offset 0. Returns the
    /// number of bytes written (96 for PE32, 112 for PE32+).
    /// The caller appends the data-directory entries after.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(112);
        out.extend_from_slice(&self.magic.to_le_bytes());
        out.push(self.major_linker_version);
        out.push(self.minor_linker_version);
        out.extend_from_slice(&self.size_of_code.to_le_bytes());
        out.extend_from_slice(&self.size_of_initialized_data.to_le_bytes());
        out.extend_from_slice(&self.size_of_uninitialized_data.to_le_bytes());
        out.extend_from_slice(&self.address_of_entry_point.to_le_bytes());
        out.extend_from_slice(&self.base_of_code.to_le_bytes());
        match self.magic {
            OPTIONAL_HEADER_MAGIC_PE32 => {
                out.extend_from_slice(&self.base_of_data.to_le_bytes());
                out.extend_from_slice(&(self.image_base as u32).to_le_bytes());
            }
            _ => {
                // OPTIONAL_HEADER_MAGIC_PE32_PLUS (and any other
                // future magic) — 64-bit `image_base`.
                out.extend_from_slice(&self.image_base.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.section_alignment.to_le_bytes());
        out.extend_from_slice(&self.file_alignment.to_le_bytes());
        out.extend_from_slice(&self.major_operating_system_version.to_le_bytes());
        out.extend_from_slice(&self.minor_operating_system_version.to_le_bytes());
        out.extend_from_slice(&self.major_image_version.to_le_bytes());
        out.extend_from_slice(&self.minor_image_version.to_le_bytes());
        out.extend_from_slice(&self.major_subsystem_version.to_le_bytes());
        out.extend_from_slice(&self.minor_subsystem_version.to_le_bytes());
        out.extend_from_slice(&self.win32_version_value.to_le_bytes());
        out.extend_from_slice(&self.size_of_image.to_le_bytes());
        out.extend_from_slice(&self.size_of_headers.to_le_bytes());
        out.extend_from_slice(&self.check_sum.to_le_bytes());
        out.extend_from_slice(&self.subsystem.to_le_bytes());
        out.extend_from_slice(&self.dll_characteristics.to_le_bytes());
        if self.magic == OPTIONAL_HEADER_MAGIC_PE32 {
            out.extend_from_slice(&(self.size_of_stack_reserve as u32).to_le_bytes());
            out.extend_from_slice(&(self.size_of_stack_commit as u32).to_le_bytes());
            out.extend_from_slice(&(self.size_of_heap_reserve as u32).to_le_bytes());
            out.extend_from_slice(&(self.size_of_heap_commit as u32).to_le_bytes());
        } else {
            out.extend_from_slice(&self.size_of_stack_reserve.to_le_bytes());
            out.extend_from_slice(&self.size_of_stack_commit.to_le_bytes());
            out.extend_from_slice(&self.size_of_heap_reserve.to_le_bytes());
            out.extend_from_slice(&self.size_of_heap_commit.to_le_bytes());
        }
        out.extend_from_slice(&self.loader_flags.to_le_bytes());
        out.extend_from_slice(&self.number_of_rva_and_sizes.to_le_bytes());
        out
    }
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

/// One main COFF symbol-table entry, with its name resolved through
/// the string table when needed. Aux records are skipped on iteration
/// (their `aux_count` field on the preceding main symbol governs
/// how many to skip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoffSymbol {
    /// The symbol's name. For "long" names (those whose first 4
    /// bytes are zero), the trailing 4 bytes index into the COFF
    /// string table; we resolve the indirection here. Empty when
    /// the indirection points outside the string table.
    pub name: String,
    /// Value associated with the symbol. For function symbols
    /// defined in a section, this is the offset within the section.
    pub value: u32,
    /// 1-indexed section number; 0 for undefined, -1 for
    /// `IMAGE_SYM_ABSOLUTE`, -2 for `IMAGE_SYM_DEBUG`.
    pub section_number: i16,
    /// Combined low-byte (base type) + high-byte (derived type).
    /// Functions have the [`COFF_DTYPE_FUNCTION`] high nibble.
    pub type_: u16,
    /// `IMAGE_SYM_CLASS_*` value.
    pub storage_class: u8,
    /// Number of trailing aux records belonging to this symbol.
    pub aux_count: u8,
}

impl CoffSymbol {
    /// True when this symbol's `Type` field marks it a function.
    #[must_use]
    pub fn is_function(&self) -> bool {
        (self.type_ & 0xf0) == COFF_DTYPE_FUNCTION
    }
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
/// authoritative bytes live in the private `raw` buffer and are what
/// [`write_to_vec`] returns. Future iterations will replace this with
/// a re-derive-on-write path; for v0 the round-trip is guaranteed
/// trivially because we don't mutate the buffer.
///
/// [`write_to_vec`]: PeFile::write_to_vec
#[derive(Debug, Clone)]
pub struct PeFile {
    /// Optional-header magic (PE32 vs PE32+).
    pub kind: PeKind,
    /// File offset of the PE signature (same value as
    /// `dos.e_lfanew`, surfaced separately for convenience).
    pub e_lfanew: u32,
    /// Parsed DOS header. The fields that don't matter for
    /// modern PE files (the original 16-bit DOS descriptors)
    /// round through verbatim.
    pub dos: DosHeader,
    /// The DOS stub program — bytes between the end of the DOS
    /// header (offset 64) and `e_lfanew`. Treated as opaque;
    /// the loader doesn't execute this in 32/64-bit OS, but
    /// most linkers ship the canonical "This program cannot be
    /// run in DOS mode" stub. We preserve whatever bytes are
    /// there.
    pub dos_stub: Vec<u8>,
    /// COFF header values.
    pub coff: CoffHeader,
    /// Optional header values. `None` for object files (which
    /// have no optional header — `coff.size_of_optional_header`
    /// is 0).
    pub optional: Option<OptionalHeader>,
    /// `ImageBase` from the optional header — the run-time virtual
    /// address the loader maps the file to. Section RVAs are added
    /// to this to form full VAs at run time. Zero when the file has
    /// no optional header (object files).
    pub image_base: u64,
    /// `AddressOfEntryPoint` from the optional header — the RVA the
    /// loader jumps to after mapping the image. For an executable
    /// this is `_start` / `mainCRTStartup`; for a DLL this is
    /// `DllMain`. Zero when the file has no optional header.
    pub address_of_entry_point: u32,
    /// Data directories from the optional header. Index 0 is the
    /// Export Table; index 1 the Import Table; etc. Standard PE
    /// reserves 16 entries; we parse `NumberOfRvaAndSizes` of them.
    pub data_directories: Vec<DataDirectory>,
    /// Section header table, in declaration order.
    pub sections: Vec<SectionHeader>,
    /// The complete file bytes; this is what `write_to_vec`
    /// returns, byte-for-byte.
    raw: Vec<u8>,
}

/// One (RVA, size) pair from the optional header's data directory
/// array. Both fields are zero when the entry is unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Index of the Export Table entry in `data_directories`.
pub const DATA_DIR_EXPORT: usize = 0;

/// Index of the Import Table entry in `data_directories`.
pub const DATA_DIR_IMPORT: usize = 1;

impl PeFile {
    /// Parse a PE file. Validates the structural skeleton (DOS
    /// header, PE signature, COFF + optional + section headers) but
    /// leaves the rest as opaque bytes.
    #[allow(clippy::too_many_lines)]
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

        let dos = DosHeader::parse(&bytes[..DOS_HEADER_SIZE]);
        let e_lfanew = dos.e_lfanew;
        let stub_end = (e_lfanew as usize).min(bytes.len());
        let dos_stub = if stub_end > DOS_HEADER_SIZE {
            bytes[DOS_HEADER_SIZE..stub_end].to_vec()
        } else {
            Vec::new()
        };
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
        let mut image_base: u64 = 0;
        let mut address_of_entry_point: u32 = 0;
        let mut data_directories: Vec<DataDirectory> = Vec::new();
        let optional = if opt_size > 0 {
            OptionalHeader::parse(&bytes[opt_off..opt_off + opt_size])
        } else {
            Option::None
        };
        let kind = if opt_size == 0 {
            // Object files have no optional header. Default to PE32+
            // for typing purposes; the kind is informational only.
            PeKind::Pe32Plus
        } else {
            ensure_len(bytes, opt_off as u64, 2)?;
            let magic = read_u16(bytes, opt_off);
            // AddressOfEntryPoint sits at offset 16 in both variants.
            if opt_size >= 20 {
                address_of_entry_point = read_u32(bytes, opt_off + 16);
            }
            let (variant, data_dir_off) = match magic {
                OPTIONAL_HEADER_MAGIC_PE32 => {
                    // PE32 ImageBase is at offset 28, 4 bytes.
                    if opt_size >= 32 {
                        image_base = u64::from(read_u32(bytes, opt_off + 28));
                    }
                    (PeKind::Pe32, 96usize)
                }
                OPTIONAL_HEADER_MAGIC_PE32_PLUS => {
                    // PE32+ ImageBase is at offset 24, 8 bytes.
                    if opt_size >= 32 {
                        image_base = read_u64(bytes, opt_off + 24);
                    }
                    (PeKind::Pe32Plus, 112usize)
                }
                other => return Err(Error::UnsupportedOptionalMagic(other)),
            };
            // NumberOfRvaAndSizes lives at data_dir_off - 4 (right
            // before the data directories table). Each entry is
            // 8 bytes (RVA + size).
            if opt_size >= data_dir_off {
                let count_off = data_dir_off - 4;
                let count = read_u32(bytes, opt_off + count_off) as usize;
                let dirs_bytes_needed = count.saturating_mul(8);
                if opt_size >= data_dir_off + dirs_bytes_needed {
                    for i in 0..count {
                        let off = opt_off + data_dir_off + i * 8;
                        data_directories.push(DataDirectory {
                            virtual_address: read_u32(bytes, off),
                            size: read_u32(bytes, off + 4),
                        });
                    }
                }
            }
            variant
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
            dos,
            dos_stub,
            coff,
            optional,
            image_base,
            address_of_entry_point,
            data_directories,
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
    pub fn section_name(&self, idx: usize) -> Option<&str> {
        let sh = self.sections.get(idx)?;
        let nul = sh
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sh.name.len());
        std::str::from_utf8(&sh.name[..nul]).ok()
    }

    /// Iterate the COFF symbol table, skipping aux records.
    ///
    /// Returns an empty iterator when the file declares no symbol
    /// table (`pointer_to_symbol_table == 0` or
    /// `number_of_symbols == 0`) or when the table runs past the
    /// end of the file.
    #[must_use]
    pub fn coff_symbols(&self) -> Vec<CoffSymbol> {
        let sym_off = self.coff.pointer_to_symbol_table as usize;
        let count = self.coff.number_of_symbols as usize;
        if sym_off == 0 || count == 0 {
            return Vec::new();
        }
        let table_size = count * COFF_SYMBOL_SIZE;
        let Some(table_end) = sym_off.checked_add(table_size) else {
            return Vec::new();
        };
        if table_end > self.raw.len() {
            return Vec::new();
        }
        let table = &self.raw[sym_off..table_end];

        // String table: contiguous block right after the symbol
        // table. First u32 is its total size (including the field
        // itself); names are NUL-terminated past offset 4.
        let str_off = table_end;
        let strtab = self.raw.get(str_off..).unwrap_or(&[]);

        let mut out = Vec::new();
        let mut i = 0usize;
        while i < count {
            let off = i * COFF_SYMBOL_SIZE;
            let chunk = &table[off..off + COFF_SYMBOL_SIZE];
            let aux_count = chunk[17] as usize;
            let name = decode_coff_symbol_name(&chunk[0..8], strtab);
            let value = read_u32(chunk, 8);
            #[allow(clippy::cast_possible_wrap)]
            let section_number = read_u16(chunk, 12) as i16;
            let type_ = read_u16(chunk, 14);
            let storage_class = chunk[16];
            out.push(CoffSymbol {
                name,
                value,
                section_number,
                type_,
                storage_class,
                aux_count: chunk[17],
            });
            i = i.saturating_add(1).saturating_add(aux_count);
        }
        out
    }

    /// Translate an RVA to a file offset by finding the section that
    /// contains it and computing `pointer_to_raw_data + (rva -
    /// virtual_address)`. Returns `None` for RVAs outside every
    /// section, or when the resulting offset would land past the
    /// file's bytes.
    #[must_use]
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for sh in &self.sections {
            let start = sh.virtual_address;
            let size = sh.virtual_size.max(sh.size_of_raw_data);
            let end = start.checked_add(size)?;
            if rva >= start && rva < end {
                let off_in_section = rva - start;
                if off_in_section >= sh.size_of_raw_data {
                    return None; // lies inside virtual-only space
                }
                let file_off = sh.pointer_to_raw_data.checked_add(off_in_section)?;
                if (file_off as usize) >= self.raw.len() {
                    return None;
                }
                return Some(file_off as usize);
            }
        }
        None
    }

    /// Read a slice of `len` bytes starting at the given RVA, or
    /// `None` if it's outside the file. Convenience over
    /// `rva_to_file_offset` + slicing.
    #[must_use]
    pub fn slice_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let off = self.rva_to_file_offset(rva)?;
        self.raw.get(off..off.checked_add(len)?)
    }

    /// Parse the Export Directory (data directory 0) if it exists
    /// and is populated, returning one [`PeExport`] per advertised
    /// export. An empty result either means "no export table" or
    /// "table present but lists zero functions".
    #[must_use]
    pub fn exports(&self) -> Vec<PeExport> {
        let Some(dir) = self.data_directories.get(DATA_DIR_EXPORT) else {
            return Vec::new();
        };
        if dir.virtual_address == 0 || dir.size == 0 {
            return Vec::new();
        }
        let Some(hdr) = self.slice_at_rva(dir.virtual_address, 40) else {
            return Vec::new();
        };
        let ordinal_base = read_u32(hdr, 16);
        let n_functions = read_u32(hdr, 20) as usize;
        let n_names = read_u32(hdr, 24) as usize;
        let addr_of_functions = read_u32(hdr, 28);
        let addr_of_names = read_u32(hdr, 32);
        let addr_of_name_ordinals = read_u32(hdr, 36);

        // Build ordinal -> name map from the parallel name + ordinal
        // arrays. Most exports are named; pure-ordinal exports leave
        // their slot in this map empty.
        let mut name_of_ordinal: std::collections::HashMap<u32, String> =
            std::collections::HashMap::new();
        if let Some(names) = self.slice_at_rva(addr_of_names, n_names.saturating_mul(4)) {
            if let Some(ords) = self.slice_at_rva(addr_of_name_ordinals, n_names.saturating_mul(2))
            {
                for i in 0..n_names {
                    let name_rva = read_u32(names, i * 4);
                    let ord_idx = u32::from(read_u16(ords, i * 2));
                    if let Some(name) = self.read_cstring_at_rva(name_rva) {
                        name_of_ordinal.insert(ord_idx, name);
                    }
                }
            }
        }

        let mut out = Vec::with_capacity(n_functions);
        let Some(funcs) = self.slice_at_rva(addr_of_functions, n_functions.saturating_mul(4))
        else {
            return out;
        };
        for i in 0..n_functions {
            let func_rva = read_u32(funcs, i * 4);
            if func_rva == 0 {
                continue; // empty slot (gap in the ordinal range)
            }
            // Forwarder exports: the RVA points into the Export
            // Directory itself (so it's an ASCII redirect string,
            // not real code). Skip those — they don't correspond
            // to local code we can lift.
            let dir_end = dir.virtual_address.wrapping_add(dir.size);
            if func_rva >= dir.virtual_address && func_rva < dir_end {
                continue;
            }
            out.push(PeExport {
                ordinal: ordinal_base + i as u32,
                rva: func_rva,
                name: name_of_ordinal.get(&(i as u32)).cloned(),
            });
        }
        out
    }

    /// Parse the Import Directory (data directory 1) if it exists
    /// and is populated, returning one [`PeImport`] per IAT slot
    /// across every imported DLL. Each entry records the slot's
    /// run-time virtual address, the DLL the symbol comes from,
    /// and either a name (for by-name imports) or an ordinal (for
    /// by-ordinal imports).
    ///
    /// Returns an empty vector when there's no import table, or
    /// when the table is malformed (missing INT/IAT data).
    #[must_use]
    pub fn imports(&self) -> Vec<PeImport> {
        let Some(dir) = self.data_directories.get(DATA_DIR_IMPORT) else {
            return Vec::new();
        };
        if dir.virtual_address == 0 || dir.size == 0 {
            return Vec::new();
        }
        // Thunk entry size: 4 bytes for PE32, 8 for PE32+.
        let thunk_size = match self.kind {
            PeKind::Pe32 => 4usize,
            PeKind::Pe32Plus => 8usize,
        };
        let mut out: Vec<PeImport> = Vec::new();
        // Each descriptor is 20 bytes; walk until we hit the
        // all-zero terminator.
        let mut desc_rva = dir.virtual_address;
        for _ in 0..1024 {
            // Bound the walk so a malformed binary can't run forever.
            let Some(desc) = self.slice_at_rva(desc_rva, 20) else {
                break;
            };
            let original_first_thunk = read_u32(desc, 0);
            let _time_date_stamp = read_u32(desc, 4);
            let _forwarder_chain = read_u32(desc, 8);
            let name_rva = read_u32(desc, 12);
            let first_thunk = read_u32(desc, 16);
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let dll_name = self.read_cstring_at_rva(name_rva).unwrap_or_default();
            // Walk INT for names, IAT slot addresses come from
            // the FirstThunk RVA + ImageBase + slot offset. If
            // OriginalFirstThunk is zero (some linkers omit it
            // for "bound" imports), fall back to FirstThunk.
            let int_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            for idx in 0..1u32 << 20 {
                let off = (idx as usize).saturating_mul(thunk_size);
                let Some(thunk_bytes) =
                    self.slice_at_rva(int_rva.wrapping_add(off as u32), thunk_size)
                else {
                    break;
                };
                let thunk_val: u64 = match self.kind {
                    PeKind::Pe32 => u64::from(read_u32(thunk_bytes, 0)),
                    PeKind::Pe32Plus => read_u64(thunk_bytes, 0),
                };
                if thunk_val == 0 {
                    break;
                }
                let iat_va = self.image_base + u64::from(first_thunk.wrapping_add(off as u32));
                let ordinal_flag: u64 = match self.kind {
                    PeKind::Pe32 => 0x8000_0000,
                    PeKind::Pe32Plus => 0x8000_0000_0000_0000,
                };
                let (ordinal, name) = if thunk_val & ordinal_flag != 0 {
                    (Some((thunk_val & 0xFFFF) as u16), None)
                } else {
                    // Low bits are an RVA to IMAGE_IMPORT_BY_NAME:
                    // 2-byte hint then the NUL-terminated name.
                    #[allow(clippy::cast_possible_truncation)]
                    let by_name_rva = (thunk_val & 0xFFFF_FFFF) as u32;
                    let name = self.read_cstring_at_rva(by_name_rva.wrapping_add(2));
                    (None, name)
                };
                out.push(PeImport {
                    iat_va,
                    dll_name: dll_name.clone(),
                    name,
                    ordinal,
                });
            }
            desc_rva = desc_rva.wrapping_add(20);
        }
        out
    }

    /// Read an ASCII NUL-terminated string at `rva`, capped at a
    /// sensible upper bound to avoid runaway scans on malformed
    /// images. Returns `None` if the RVA can't be resolved.
    fn read_cstring_at_rva(&self, rva: u32) -> Option<String> {
        let off = self.rva_to_file_offset(rva)?;
        let slice = self.raw.get(off..)?;
        let end = slice.iter().take(512).position(|&b| b == 0).unwrap_or(0);
        if end == 0 {
            return None;
        }
        std::str::from_utf8(&slice[..end]).ok().map(str::to_string)
    }

    /// Build a [`PeFile`] from already-structured pieces, without
    /// needing a pre-existing raw buffer. Used by the source
    /// lower path (`ud_compile::lower_to_pe`) when reading the
    /// PE skeleton from `@module.build` and reassembling the
    /// bytes for round-trip. The DOS stub bytes, alignment
    /// padding, and section content arrive via the `extra_bytes`
    /// list — each `(file_offset, bytes)` tuple is copied into
    /// the buffer at its offset, after the structured headers
    /// are written.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        kind: PeKind,
        dos: DosHeader,
        dos_stub: Vec<u8>,
        coff: CoffHeader,
        optional: Option<OptionalHeader>,
        image_base: u64,
        address_of_entry_point: u32,
        data_directories: Vec<DataDirectory>,
        sections: Vec<SectionHeader>,
        extra_bytes: Vec<(u64, Vec<u8>)>,
        file_size: u64,
    ) -> Self {
        let mut raw = vec![0u8; file_size as usize];
        // Lay the DOS stub down first so write_to_vec's pass
        // can overlay the structured DOS header on top.
        if !dos_stub.is_empty() && raw.len() >= DOS_HEADER_SIZE + dos_stub.len() {
            raw[DOS_HEADER_SIZE..DOS_HEADER_SIZE + dos_stub.len()].copy_from_slice(&dos_stub);
        }
        for (off, bytes) in extra_bytes {
            let off = off as usize;
            let end = off + bytes.len();
            if end <= raw.len() {
                raw[off..end].copy_from_slice(&bytes);
            }
        }
        let e_lfanew = dos.e_lfanew;
        let mut file = Self {
            kind,
            e_lfanew,
            dos,
            dos_stub,
            coff,
            optional,
            image_base,
            address_of_entry_point,
            data_directories,
            sections,
            raw,
        };
        // Overwrite the buffer with the canonical structured
        // encoding so any drift between the supplied raw bytes
        // and the structured fields lands the structured value.
        file.raw = file.write_to_vec();
        file
    }

    /// Serialize back to bytes. Always byte-identical to the
    /// parsed input — the structured DOS/optional/section headers
    /// are encoded back into the buffer over a base copy of the
    /// original raw bytes, so any field not covered by a
    /// structured field (DOS stub bytes, alignment padding,
    /// section content) rides through verbatim. Useful for
    /// callers that edit a structured field (e.g. bump the
    /// optional header's CheckSum) and want the rebuilt bytes.
    #[must_use]
    pub fn write_to_vec(&self) -> Vec<u8> {
        let mut out = self.raw.clone();
        // DOS header — always 64 bytes at offset 0.
        if out.len() >= DOS_HEADER_SIZE {
            out[..DOS_HEADER_SIZE].copy_from_slice(&self.dos.encode());
        }
        let pe_off = self.e_lfanew as usize;
        if pe_off + 4 <= out.len() {
            out[pe_off..pe_off + 4].copy_from_slice(&PE_SIGNATURE);
        }
        let coff_off = pe_off + 4;
        if coff_off + COFF_HEADER_SIZE <= out.len() {
            out[coff_off..coff_off + COFF_HEADER_SIZE].copy_from_slice(&self.coff.encode());
        }
        let opt_off = coff_off + COFF_HEADER_SIZE;
        if let Some(opt) = self.optional.as_ref() {
            let opt_bytes = opt.encode();
            if opt_off + opt_bytes.len() <= out.len() {
                out[opt_off..opt_off + opt_bytes.len()].copy_from_slice(&opt_bytes);
            }
            let dd_off = opt_off + opt_bytes.len();
            for (i, dd) in self.data_directories.iter().enumerate() {
                let off = dd_off + i * 8;
                if off + 8 > out.len() {
                    break;
                }
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }
        }
        let sec_off = opt_off + self.coff.size_of_optional_header as usize;
        for (i, sh) in self.sections.iter().enumerate() {
            let off = sec_off + i * SECTION_HEADER_SIZE;
            if off + SECTION_HEADER_SIZE > out.len() {
                break;
            }
            out[off..off + SECTION_HEADER_SIZE].copy_from_slice(&sh.encode());
        }
        out
    }
}

/// One entry from a PE file's Import Address Table (IAT). Names
/// the imported symbol the loader will patch into `iat_va` at
/// run time. Either `name` or `ordinal` is set (an import is
/// either by-name or by-ordinal); rarely both, never neither.
#[derive(Debug, Clone)]
pub struct PeImport {
    /// Run-time virtual address of the IAT slot — what the
    /// loader writes the resolved function pointer into, and
    /// what `call dword ptr [iat_va]` references in code.
    pub iat_va: u64,
    /// Name of the DLL that provides the symbol (e.g. `"KERNEL32.dll"`).
    /// Empty when the import descriptor's Name RVA didn't
    /// resolve to a readable string.
    pub dll_name: String,
    /// Symbol name when the import is by-name.
    pub name: Option<String>,
    /// Ordinal when the import is by-ordinal. Common for some
    /// system DLLs (e.g. WS2_32 uses ordinals for many entries).
    pub ordinal: Option<u16>,
}

/// One entry from a PE file's Export Address Table.
#[derive(Debug, Clone)]
pub struct PeExport {
    /// The export's ordinal (Base + index). Always present in the
    /// EAT.
    pub ordinal: u32,
    /// RVA of the export's code. Forwarder entries (which point at
    /// a redirect string instead) are excluded by [`PeFile::exports`].
    pub rva: u32,
    /// Symbolic name when the export has one; `None` for ordinal-
    /// only exports.
    pub name: Option<String>,
}

/// Returns true if `bytes` look like a PE file (start with the DOS
/// `MZ` magic and have a parseable `e_lfanew`).
#[must_use]
pub fn is_pe(bytes: &[u8]) -> bool {
    bytes.len() >= DOS_HEADER_SIZE && bytes[..2] == DOS_MAGIC
}

impl CoffHeader {
    /// Encode the 20-byte COFF header.
    #[must_use]
    pub fn encode(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out[0..2].copy_from_slice(&self.machine.to_le_bytes());
        out[2..4].copy_from_slice(&self.number_of_sections.to_le_bytes());
        out[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        out[8..12].copy_from_slice(&self.pointer_to_symbol_table.to_le_bytes());
        out[12..16].copy_from_slice(&self.number_of_symbols.to_le_bytes());
        out[16..18].copy_from_slice(&self.size_of_optional_header.to_le_bytes());
        out[18..20].copy_from_slice(&self.characteristics.to_le_bytes());
        out
    }
}

impl SectionHeader {
    /// Encode the 40-byte section header.
    #[must_use]
    pub fn encode(&self) -> [u8; SECTION_HEADER_SIZE] {
        let mut out = [0u8; SECTION_HEADER_SIZE];
        out[0..8].copy_from_slice(&self.name);
        out[8..12].copy_from_slice(&self.virtual_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.virtual_address.to_le_bytes());
        out[16..20].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        out[20..24].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        out[24..28].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        out[28..32].copy_from_slice(&self.pointer_to_linenumbers.to_le_bytes());
        out[32..34].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        out[34..36].copy_from_slice(&self.number_of_linenumbers.to_le_bytes());
        out[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
        out
    }
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

fn read_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}

/// Decode the 8-byte name field of a COFF symbol entry.
///
/// Two encodings:
///
/// * Short name (≤ 8 bytes): the bytes are the name, possibly NUL-
///   padded if shorter than 8. We trim to first NUL.
/// * Long name (> 8 bytes): the first 4 bytes are zero; the next 4
///   bytes are a u32 offset into the string table. We follow the
///   indirection and read up to the next NUL.
///
/// Returns an empty string if the bytes aren't valid UTF-8 or the
/// long-name offset overflows the string table.
fn decode_coff_symbol_name(name: &[u8], strtab: &[u8]) -> String {
    debug_assert!(name.len() == 8);
    if name[0..4] == [0u8; 4] {
        let off = u32::from_le_bytes(name[4..8].try_into().unwrap()) as usize;
        let Some(tail) = strtab.get(off..) else {
            return String::new();
        };
        let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        return std::str::from_utf8(&tail[..nul])
            .ok()
            .map(str::to_string)
            .unwrap_or_default();
    }
    let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    std::str::from_utf8(&name[..nul])
        .ok()
        .map(str::to_string)
        .unwrap_or_default()
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

    #[test]
    fn dos_header_encode_round_trip() {
        let bytes = minimal_pe_bytes();
        let dos = DosHeader::parse(&bytes[..64]);
        let re = dos.encode();
        assert_eq!(&re[..], &bytes[..64]);
    }

    #[test]
    fn optional_header_encode_round_trip_against_fixture() {
        // The synthetic `minimal_pe_bytes` has no optional
        // header, so test against a real PE fixture if one
        // is available — skip when running against a stripped
        // tree.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|p| p.join("testdata").is_dir())
            .map(|p| p.join("testdata/sqrt-mingw15-O0.exe"));
        let Some(path) = path else {
            eprintln!("note: testdata/ unavailable; skipping");
            return;
        };
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("note: {} unavailable; skipping", path.display());
            return;
        };
        let pe = PeFile::parse(&bytes).expect("parse fixture");
        let opt = pe
            .optional
            .as_ref()
            .expect("fixture should have an optional header");
        let opt_off = pe.e_lfanew as usize + 4 + COFF_HEADER_SIZE;
        let opt_tail = match pe.kind {
            PeKind::Pe32 => 96,
            PeKind::Pe32Plus => 112,
        };
        let re = opt.encode();
        assert_eq!(re.len(), opt_tail);
        assert_eq!(&re[..], &bytes[opt_off..opt_off + opt_tail]);
    }
}

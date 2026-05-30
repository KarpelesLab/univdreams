//! NE (16-bit Windows "New Executable") container — parse +
//! byte-identical write.
//!
//! NE is the executable format of Windows 1.x–3.x (and OS/2 1.x). A
//! file opens with the familiar DOS `MZ` stub, whose `e_lfanew` field
//! (at offset `0x3c`) points at a second header beginning with the
//! signature `NE`. Everything Windows needs lives after that point:
//!
//! ```text
//!   MZ header        : DOS header + stub (real-mode "requires Windows")
//!   NE header        : 64 bytes, signature 'N' 'E'
//!   segment table    : 8 bytes/entry — code & data segments
//!   resource table   : icons, dialogs, strings, …
//!   resident names   : module name + always-loaded exports
//!   module refs      : indices into the imported-names table
//!   imported names   : DLLs this module imports from (KERNEL, GDI, …)
//!   entry table       : exported entry points (ordinal → seg:offset)
//!   non-resident names: module description + on-demand exports
//!   segment data      : the actual code/data, each optionally followed
//!                       by a per-segment relocation-record table
//! ```
//!
//! Unlike PE, NE addresses are **segment:offset** pairs into a
//! segment table, not RVAs into a flat image — it is a true 16-bit
//! segmented format.
//!
//! For the round-trip invariant the whole univdreams pipeline rests
//! on, [`NeFile`] retains the verbatim input in `raw` and
//! [`NeFile::write_to_vec`] reproduces it byte-for-byte. The decoded
//! header / table views exist for *readability* (the decompiler turns
//! them into a Ghidra-style listing); they are not the authoritative
//! source of the round-trip, so a decode gap can never corrupt the
//! rebuilt bytes.

// NE fields are 16-bit by nature; the `usize → u16` casts when laying
// out table offsets are bounded by the format and never truncate in
// practice. Mirrors the same file-level allow in `pe.rs` / `macho.rs`.
#![allow(clippy::cast_possible_truncation)]

use std::ops::Range;

/// Offset of the `e_lfanew` field inside the DOS header.
const E_LFANEW_OFFSET: usize = 0x3c;

/// NE signature: the bytes `N` `E` at `e_lfanew`.
pub const NE_MAGIC: [u8; 2] = [b'N', b'E'];

/// Size of the fixed NE header in bytes.
const NE_HEADER_LEN: usize = 0x40;

/// Errors raised by [`NeFile::parse`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("buffer too short ({len} bytes); needs at least 64 for the DOS header")]
    TooShort { len: usize },
    #[error("not an MZ executable: first two bytes are {magic:?}, expected [4d, 5a]")]
    NotMz { magic: [u8; 2] },
    #[error("e_lfanew {e_lfanew:#x} points past end of file ({len} bytes)")]
    BadLfanew { e_lfanew: u32, len: usize },
    #[error("no NE signature at e_lfanew {at:#x}: found {magic:?}, expected [4e, 45]")]
    BadNeMagic { at: usize, magic: [u8; 2] },
    #[error("NE header at {at:#x} is truncated (need 64 bytes, file ends at {len})")]
    HeaderTruncated { at: usize, len: usize },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The fixed 64-byte NE header. Field names follow the historical
/// `ne_*` layout. Table offsets are relative to the start of the NE
/// header (i.e. to `e_lfanew`) **except** [`Self::nonres_name_off`],
/// which is an absolute file offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeHeader {
    /// Linker version / revision (`ne_ver`, `ne_rev`).
    pub linker_ver: u8,
    pub linker_rev: u8,
    /// Entry table: offset (relative to NE header) and byte length.
    pub entry_table_off: u16,
    pub entry_table_len: u16,
    /// 32-bit file CRC (`ne_crc`).
    pub crc: u32,
    /// Program flags (`ne_flags`): DATA model, errors, etc.
    pub flags: u16,
    /// 1-based segment number of the automatic data segment.
    pub auto_data_seg: u16,
    /// Initial local heap / stack sizes.
    pub init_heap: u16,
    pub init_stack: u16,
    /// Entry point `CS:IP` (high word = 1-based segment, low = offset).
    pub cs_ip: u32,
    /// Initial `SS:SP`.
    pub ss_sp: u32,
    /// Number of entries in the segment table.
    pub seg_count: u16,
    /// Number of entries in the module-reference table.
    pub module_ref_count: u16,
    /// Size in bytes of the non-resident name table.
    pub nonres_name_size: u16,
    /// Offsets (relative to NE header) of the four in-header tables.
    pub seg_table_off: u16,
    pub resource_table_off: u16,
    pub resident_name_off: u16,
    pub module_ref_off: u16,
    pub imported_name_off: u16,
    /// Absolute file offset of the non-resident name table.
    pub nonres_name_off: u32,
    /// Count of movable entry points.
    pub movable_entry_count: u16,
    /// Logical-sector alignment shift: segment file offsets are stored
    /// in units of `1 << align_shift` bytes. A stored value of 0 means
    /// 9 (512-byte sectors).
    pub align_shift: u16,
    /// Number of resource entries.
    pub resource_seg_count: u16,
    /// Target OS (`ne_exetyp`): 2 = Windows.
    pub target_os: u8,
    /// Additional EXE flags (`ne_flagsothers`).
    pub other_flags: u8,
    /// Fast-load / gangload area offset and length.
    pub fastload_off: u16,
    pub fastload_len: u16,
    /// Minimum code-swap-area size.
    pub min_swap: u16,
    /// Expected Windows version (e.g. `0x030a` = 3.10).
    pub expected_win_ver: u16,
}

impl NeHeader {
    /// Decode the 64-byte header from `bytes[at..]`. Caller guarantees
    /// `bytes[at..at+64]` exists and starts with [`NE_MAGIC`].
    fn decode(bytes: &[u8], at: usize) -> Self {
        let w = |off: usize| u16::from_le_bytes([bytes[at + off], bytes[at + off + 1]]);
        let d = |off: usize| {
            u32::from_le_bytes([
                bytes[at + off],
                bytes[at + off + 1],
                bytes[at + off + 2],
                bytes[at + off + 3],
            ])
        };
        Self {
            linker_ver: bytes[at + 0x02],
            linker_rev: bytes[at + 0x03],
            entry_table_off: w(0x04),
            entry_table_len: w(0x06),
            crc: d(0x08),
            flags: w(0x0c),
            auto_data_seg: w(0x0e),
            init_heap: w(0x10),
            init_stack: w(0x12),
            cs_ip: d(0x14),
            ss_sp: d(0x18),
            seg_count: w(0x1c),
            module_ref_count: w(0x1e),
            nonres_name_size: w(0x20),
            seg_table_off: w(0x22),
            resource_table_off: w(0x24),
            resident_name_off: w(0x26),
            module_ref_off: w(0x28),
            imported_name_off: w(0x2a),
            nonres_name_off: d(0x2c),
            movable_entry_count: w(0x30),
            align_shift: w(0x32),
            resource_seg_count: w(0x34),
            target_os: bytes[at + 0x36],
            other_flags: bytes[at + 0x37],
            fastload_off: w(0x38),
            fastload_len: w(0x3a),
            min_swap: w(0x3c),
            expected_win_ver: w(0x3e),
        }
    }

    /// Alignment unit in bytes: `1 << align_shift`, with the historical
    /// "0 means 9" rule applied.
    #[must_use]
    pub fn alignment(&self) -> u32 {
        let shift = if self.align_shift == 0 {
            9
        } else {
            u32::from(self.align_shift)
        };
        1u32 << shift
    }
}

/// One 8-byte segment-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeSegment {
    /// File offset in alignment units (multiply by [`NeHeader::alignment`]).
    /// 0 means the segment has no file data.
    pub sector_offset: u16,
    /// Length of the segment's data on disk in bytes. A stored 0 means
    /// 0x10000.
    pub length: u16,
    /// Segment flags: bit 0 = DATA (else CODE), 0x0800 = has relocations.
    pub flags: u16,
    /// Minimum allocation size; a stored 0 means 0x10000.
    pub min_alloc: u16,
}

impl NeSegment {
    /// File offset of the segment's data, or `None` when `sector_offset`
    /// is 0 (no file data).
    #[must_use]
    pub fn file_offset(&self, header: &NeHeader) -> Option<u64> {
        if self.sector_offset == 0 {
            None
        } else {
            Some(u64::from(self.sector_offset) * u64::from(header.alignment()))
        }
    }

    /// Effective on-disk byte length (applying the "0 means 0x10000"
    /// rule).
    #[must_use]
    pub fn data_len(&self) -> u64 {
        if self.length == 0 {
            0x1_0000
        } else {
            u64::from(self.length)
        }
    }

    /// True when this segment holds data (not code).
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// True when a per-segment relocation table follows the data.
    #[must_use]
    pub fn has_relocations(&self) -> bool {
        self.flags & 0x0800 != 0
    }
}

/// A length-prefixed name with an associated ordinal, as found in the
/// resident and non-resident name tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeName {
    pub name: String,
    pub ordinal: u16,
}

/// One decoded entry-table slot (an exported entry point).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeEntry {
    /// 1-based ordinal of this entry.
    pub ordinal: u16,
    /// 1-based segment number; for fixed entries the segment index,
    /// for movable entries the segment named in the entry record.
    pub segment: u8,
    /// Offset within the segment.
    pub offset: u16,
    /// Entry flags (bit 0 = exported).
    pub flags: u8,
    /// True if this is a movable entry (INT 3Fh thunk).
    pub movable: bool,
}

/// A parsed NE module. `raw` is the verbatim input and the
/// authoritative source for [`Self::write_to_vec`]; the decoded views
/// are for presentation.
#[derive(Debug, Clone)]
pub struct NeFile {
    /// Verbatim file bytes.
    pub raw: Vec<u8>,
    /// File offset of the NE header (the DOS `e_lfanew`).
    pub e_lfanew: u32,
    /// The DOS stub bytes between the 64-byte DOS header and the NE
    /// header (`raw[0x40..e_lfanew]`).
    pub dos_stub: Range<usize>,
    /// Decoded NE header.
    pub header: NeHeader,
    /// Segment table (`header.seg_count` entries).
    pub segments: Vec<NeSegment>,
    /// Module name + resident exports (first entry is the module name).
    pub resident_names: Vec<NeName>,
    /// Module description + non-resident exports (first entry is the
    /// description).
    pub nonresident_names: Vec<NeName>,
    /// Imported module names, resolved through the module-reference
    /// table (one per `header.module_ref_count`, in reference order).
    pub imported_modules: Vec<String>,
    /// Decoded entry table.
    pub entries: Vec<NeEntry>,
}

impl NeFile {
    /// Parse `bytes` into a [`NeFile`]. The structured tables are
    /// decoded tolerantly: a malformed sub-table yields an empty / short
    /// view rather than an error, because round-trip identity rides on
    /// the retained `raw`, not on the decode.
    ///
    /// # Errors
    /// Returns an error only when the file is not a recognisable NE
    /// container (bad `MZ`/`NE` magic, out-of-range `e_lfanew`, or a
    /// truncated NE header).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::TooShort { len: bytes.len() });
        }
        let magic = [bytes[0], bytes[1]];
        if magic != [b'M', b'Z'] {
            return Err(Error::NotMz { magic });
        }
        let e_lfanew = u32::from_le_bytes([
            bytes[E_LFANEW_OFFSET],
            bytes[E_LFANEW_OFFSET + 1],
            bytes[E_LFANEW_OFFSET + 2],
            bytes[E_LFANEW_OFFSET + 3],
        ]);
        let ne_at = e_lfanew as usize;
        if ne_at + 2 > bytes.len() {
            return Err(Error::BadLfanew {
                e_lfanew,
                len: bytes.len(),
            });
        }
        let ne_magic = [bytes[ne_at], bytes[ne_at + 1]];
        if ne_magic != NE_MAGIC {
            return Err(Error::BadNeMagic {
                at: ne_at,
                magic: ne_magic,
            });
        }
        if ne_at + NE_HEADER_LEN > bytes.len() {
            return Err(Error::HeaderTruncated {
                at: ne_at,
                len: bytes.len(),
            });
        }

        let header = NeHeader::decode(bytes, ne_at);
        let dos_stub = NE_HEADER_LEN.min(ne_at)..ne_at;

        let segments = decode_segment_table(bytes, ne_at, &header);
        let resident_names = decode_name_table(
            bytes,
            ne_at.saturating_add(header.resident_name_off as usize),
            None,
        );
        let nonresident_names = decode_name_table(
            bytes,
            header.nonres_name_off as usize,
            Some(header.nonres_name_size as usize),
        );
        let imported_modules = decode_imported_modules(bytes, ne_at, &header);
        let entries = decode_entry_table(bytes, ne_at, &header);

        Ok(Self {
            raw: bytes.to_vec(),
            e_lfanew,
            dos_stub,
            header,
            segments,
            resident_names,
            nonresident_names,
            imported_modules,
            entries,
        })
    }

    /// Reproduce the original bytes. The decoded views are never
    /// consulted — round-trip is a verbatim copy of `raw`.
    #[must_use]
    pub fn write_to_vec(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// The module's own name (first resident-name entry), if present.
    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.resident_names.first().map(|n| n.name.as_str())
    }

    /// The module description (first non-resident-name entry), if present.
    #[must_use]
    pub fn module_description(&self) -> Option<&str> {
        self.nonresident_names.first().map(|n| n.name.as_str())
    }
}

/// Is `bytes` an NE container? Checks the `MZ` magic, a readable
/// `e_lfanew`, and the `NE` signature at that offset. Strict enough to
/// distinguish NE from PE (both start with `MZ`).
#[must_use]
pub fn is_ne(bytes: &[u8]) -> bool {
    if bytes.len() < 64 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([
        bytes[E_LFANEW_OFFSET],
        bytes[E_LFANEW_OFFSET + 1],
        bytes[E_LFANEW_OFFSET + 2],
        bytes[E_LFANEW_OFFSET + 3],
    ]) as usize;
    bytes
        .get(e_lfanew..e_lfanew + 2)
        .is_some_and(|m| m == NE_MAGIC)
}

/// Decode the segment table: `header.seg_count` entries of 8 bytes
/// each at `ne_at + header.seg_table_off`.
fn decode_segment_table(bytes: &[u8], ne_at: usize, header: &NeHeader) -> Vec<NeSegment> {
    let base = ne_at.saturating_add(header.seg_table_off as usize);
    let mut out = Vec::new();
    for i in 0..header.seg_count as usize {
        let off = base + i * 8;
        let Some(rec) = bytes.get(off..off + 8) else {
            break;
        };
        out.push(NeSegment {
            sector_offset: u16::from_le_bytes([rec[0], rec[1]]),
            length: u16::from_le_bytes([rec[2], rec[3]]),
            flags: u16::from_le_bytes([rec[4], rec[5]]),
            min_alloc: u16::from_le_bytes([rec[6], rec[7]]),
        });
    }
    out
}

/// Decode a length-prefixed name table: a run of `[len:u8][bytes][ord:u16]`
/// records terminated by a zero length byte. `limit`, when given,
/// bounds the scan to that many bytes (used for the non-resident
/// table, which has an explicit size).
fn decode_name_table(bytes: &[u8], start: usize, limit: Option<usize>) -> Vec<NeName> {
    let mut out = Vec::new();
    if start == 0 || start >= bytes.len() {
        return out;
    }
    let hard_end = match limit {
        Some(n) => bytes.len().min(start.saturating_add(n)),
        None => bytes.len(),
    };
    let mut cur = start;
    loop {
        if cur >= hard_end {
            break;
        }
        let len = bytes[cur] as usize;
        if len == 0 {
            break;
        }
        let name_start = cur + 1;
        let name_end = name_start + len;
        let ord_end = name_end + 2;
        if ord_end > hard_end {
            break;
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).into_owned();
        let ordinal = u16::from_le_bytes([bytes[name_end], bytes[name_end + 1]]);
        out.push(NeName { name, ordinal });
        cur = ord_end;
    }
    out
}

/// Resolve imported module names: the module-reference table is an
/// array of `module_ref_count` WORD offsets into the imported-names
/// table, each pointing at a `[len:u8][bytes]` string.
fn decode_imported_modules(bytes: &[u8], ne_at: usize, header: &NeHeader) -> Vec<String> {
    let mod_base = ne_at.saturating_add(header.module_ref_off as usize);
    let imp_base = ne_at.saturating_add(header.imported_name_off as usize);
    let mut out = Vec::new();
    for i in 0..header.module_ref_count as usize {
        let off = mod_base + i * 2;
        let Some(rec) = bytes.get(off..off + 2) else {
            break;
        };
        let name_off = imp_base + u16::from_le_bytes([rec[0], rec[1]]) as usize;
        out.push(read_pascal_string(bytes, name_off).unwrap_or_default());
    }
    out
}

/// Read a `[len:u8][bytes]` Pascal string at `at`.
fn read_pascal_string(bytes: &[u8], at: usize) -> Option<String> {
    let len = *bytes.get(at)? as usize;
    let s = bytes.get(at + 1..at + 1 + len)?;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Decode the entry table into a flat list of entry points. The table
/// is a series of *bundles*: `[count:u8][type:u8]` followed by `count`
/// entries. A `count` of 0 ends the table. `type` 0 marks empty slots
/// (ordinals consumed but no entries), 0xFF marks movable entries
/// (6 bytes each), any other value is a fixed entry's 1-based segment
/// number (3 bytes each).
fn decode_entry_table(bytes: &[u8], ne_at: usize, header: &NeHeader) -> Vec<NeEntry> {
    let start = ne_at.saturating_add(header.entry_table_off as usize);
    let end = bytes
        .len()
        .min(start.saturating_add(header.entry_table_len as usize));
    let mut out = Vec::new();
    let mut cur = start;
    let mut ordinal: u16 = 1;
    while cur < end {
        let count = bytes[cur] as usize;
        if count == 0 {
            break;
        }
        let Some(&seg_type) = bytes.get(cur + 1) else {
            break;
        };
        cur += 2;
        if seg_type == 0x00 {
            // Empty bundle: ordinals are skipped, no bytes consumed.
            ordinal = ordinal.wrapping_add(count as u16);
            continue;
        }
        let movable = seg_type == 0xff;
        for _ in 0..count {
            if movable {
                let Some(rec) = bytes.get(cur..cur + 6) else {
                    return out;
                };
                // rec: [flags][INT 3Fh = CD 3F][segno][offset:u16]
                out.push(NeEntry {
                    ordinal,
                    segment: rec[3],
                    offset: u16::from_le_bytes([rec[4], rec[5]]),
                    flags: rec[0],
                    movable: true,
                });
                cur += 6;
            } else {
                let Some(rec) = bytes.get(cur..cur + 3) else {
                    return out;
                };
                // rec: [flags][offset:u16]; segment = seg_type.
                out.push(NeEntry {
                    ordinal,
                    segment: seg_type,
                    offset: u16::from_le_bytes([rec[1], rec[2]]),
                    flags: rec[0],
                    movable: false,
                });
                cur += 3;
            }
            ordinal = ordinal.wrapping_add(1);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid NE file by hand:
    /// DOS header + tiny stub, NE header at 0x40, one code segment with
    /// a couple of 16-bit instructions, a resident name table naming
    /// the module, and an imported-names + module-ref table.
    fn synthetic_ne() -> Vec<u8> {
        // Layout (all little-endian):
        //   0x00 DOS header (64 bytes); e_lfanew = 0x40
        //   0x40 NE header (64 bytes)
        //   0x80 segment table (1 entry, 8 bytes)
        //   0x88 resident names: "TEST"\0 module + terminator
        //   ~    imported names: \0 + "KERNEL"
        //   ~    module ref table (1 entry)
        //   0xC0 segment data (aligned to 16): two instrs
        let mut b = vec![0u8; 0x40];
        b[0] = b'M';
        b[1] = b'Z';
        b[E_LFANEW_OFFSET] = 0x40;

        let ne_at = 0x40usize;
        let mut ne = vec![0u8; NE_HEADER_LEN];
        ne[0] = b'N';
        ne[1] = b'E';
        let put_w = |ne: &mut [u8], off: usize, v: u16| {
            ne[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        // Tables are placed right after the 64-byte NE header.
        let seg_table_off = 0x40u16; // -> file 0x80 (8-byte seg entry)
        let resident_off = 0x48u16; // -> file 0x88 (8-byte resident table)
        let imported_off = 0x50u16; // -> file 0x90 (8-byte imported table)
        let modref_off = 0x58u16; // -> file 0x98 (2-byte modref table)
        put_w(&mut ne, 0x1c, 1); // seg_count
        put_w(&mut ne, 0x1e, 1); // module_ref_count
        put_w(&mut ne, 0x22, seg_table_off);
        put_w(&mut ne, 0x26, resident_off);
        put_w(&mut ne, 0x28, modref_off);
        put_w(&mut ne, 0x2a, imported_off);
        put_w(&mut ne, 0x32, 4); // align_shift -> 16-byte units

        // Segment table entry: data at file 0xC0 => sector 0xC0>>4 = 0x0C.
        let seg_data_off = 0xC0usize;
        let seg_code = [0x33u8, 0xc0, 0xc3]; // xor ax,ax ; ret
        let mut seg = vec![0u8; 8];
        seg[0..2].copy_from_slice(&((seg_data_off as u16) >> 4).to_le_bytes());
        seg[2..4].copy_from_slice(&(seg_code.len() as u16).to_le_bytes());
        seg[4..6].copy_from_slice(&0x0000u16.to_le_bytes()); // CODE, no relocs
        seg[6..8].copy_from_slice(&0x1000u16.to_le_bytes());

        // Resident names: module "TEST" (ord 0), then terminator.
        let mut resident = Vec::new();
        resident.push(4u8);
        resident.extend_from_slice(b"TEST");
        resident.extend_from_slice(&0u16.to_le_bytes());
        resident.push(0u8); // terminator

        // Imported names: leading 0-length, then "KERNEL" at +1.
        let mut imported = vec![0u8];
        imported.push(6u8);
        imported.extend_from_slice(b"KERNEL");

        // Module ref table: one entry pointing at the "KERNEL" string
        // (offset 1 into the imported-names table).
        let modref = 1u16.to_le_bytes();

        // Assemble, padding to each table's declared offset.
        let mut out = Vec::new();
        out.extend_from_slice(&b);
        out.extend_from_slice(&ne);
        // file cursor is now 0x80 == ne_at + seg_table_off
        assert_eq!(out.len(), ne_at + seg_table_off as usize);
        out.extend_from_slice(&seg);
        assert_eq!(out.len(), ne_at + resident_off as usize);
        out.extend_from_slice(&resident);
        assert_eq!(out.len(), ne_at + imported_off as usize);
        out.extend_from_slice(&imported);
        assert_eq!(out.len(), ne_at + modref_off as usize);
        out.extend_from_slice(&modref);
        // pad to segment data offset
        out.resize(seg_data_off, 0);
        out.extend_from_slice(&seg_code);
        out
    }

    #[test]
    fn is_ne_accepts_synthetic_and_rejects_others() {
        let ne = synthetic_ne();
        assert!(is_ne(&ne));
        // A PE-ish MZ with a different signature at e_lfanew is rejected.
        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[E_LFANEW_OFFSET] = 0x40;
        pe[0x40] = b'P';
        pe[0x41] = b'E';
        assert!(!is_ne(&pe));
        assert!(!is_ne(b"not an exe"));
    }

    #[test]
    fn parses_header_and_tables() {
        let ne = synthetic_ne();
        let f = NeFile::parse(&ne).expect("parse");
        assert_eq!(f.e_lfanew, 0x40);
        assert_eq!(f.header.seg_count, 1);
        assert_eq!(f.header.module_ref_count, 1);
        assert_eq!(f.header.alignment(), 16);
        assert_eq!(f.segments.len(), 1);
        assert!(!f.segments[0].is_data());
        assert_eq!(f.segments[0].file_offset(&f.header), Some(0xC0));
        assert_eq!(f.module_name(), Some("TEST"));
        assert_eq!(f.imported_modules, vec!["KERNEL".to_string()]);
    }

    #[test]
    fn write_to_vec_is_byte_identical() {
        let ne = synthetic_ne();
        let f = NeFile::parse(&ne).expect("parse");
        assert_eq!(f.write_to_vec(), ne);
    }

    #[test]
    fn rejects_non_mz() {
        assert!(matches!(
            NeFile::parse(&[0u8; 64]),
            Err(Error::NotMz { .. })
        ));
    }
}

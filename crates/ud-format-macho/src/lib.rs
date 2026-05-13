//! Mach-O reader and writer with byte-identical round-trip.
//!
//! v1 covers thin (non-fat) 64-bit little-endian Mach-O images
//! for both x86-64 and arm64. The parsed representation captures
//! the structured header and each load command's `(cmd, cmdsize)`
//! prefix; load command bodies stay as opaque bytes so the suite
//! of cmd kinds (`LC_SEGMENT_64`, `LC_SYMTAB`, `LC_CODE_SIGNATURE`,
//! `LC_DYLD_CHAINED_FIXUPS`, …) round-trip without needing per-cmd
//! decoders.
//!
//! Contract: for any supported input `bytes`,
//! `MachoFile::parse(bytes)?.write_to_vec() == bytes`.
//!
//! Fat (universal) wrappers and 32-bit Mach-O are out of scope
//! for v1. Section contents (the bytes inside `__text`, `__data`,
//! etc.) are never interpreted here — that belongs to the arch
//! backends and analysis crates.

#![allow(clippy::cast_possible_truncation)]

use std::ops::Range;

/// 64-bit little-endian Mach-O magic.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;

/// 32-bit little-endian Mach-O magic (detected; v1 parse refuses).
pub const MH_MAGIC: u32 = 0xfeed_face;

/// Fat-arch wrapper magic (big-endian). Detected so callers can
/// route appropriately; v1 parse refuses.
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;

/// `cputype` values for the architectures v1 supports.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// `LC_SEGMENT_64` load-command kind. Carries a segment descriptor
/// plus that segment's sections.
pub const LC_SEGMENT_64: u32 = 0x19;

/// Bit OR'd into `cmd` to mark a command as required for correct
/// dynamic linker behaviour. Not a kind by itself; ORed with the
/// concrete `LC_*` value.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

/// `LC_SYMTAB`: classical symbol-table command. Body is four u32s:
/// `symoff`, `nsyms`, `stroff`, `strsize`.
pub const LC_SYMTAB: u32 = 0x2;

/// `LC_DYSYMTAB`: extended dynamic-link symbol info. Body is 18
/// u32s describing partitions of the LC_SYMTAB table plus auxiliary
/// indirect-symbol / module / reference tables.
pub const LC_DYSYMTAB: u32 = 0xb;

/// `LC_LOAD_DYLINKER`: file path of the dynamic linker. Body is a
/// `lc_str` offset (u32) followed by the NUL-padded name.
pub const LC_LOAD_DYLINKER: u32 = 0xe;

/// `LC_UUID`: 16-byte randomly-generated identifier baked into the
/// binary at link time.
pub const LC_UUID: u32 = 0x1b;

/// `LC_LOAD_DYLIB`: dependent dynamic library. Body is a
/// `dylib_command` after the cmd/cmdsize prefix.
pub const LC_LOAD_DYLIB: u32 = 0xc;

/// `LC_LOAD_WEAK_DYLIB`: dependent library, weak link.
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;

/// `LC_REEXPORT_DYLIB`: dependent library to re-export.
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;

/// `LC_ID_DYLIB`: identifies this image when it is itself a dylib.
pub const LC_ID_DYLIB: u32 = 0xd;

/// `LC_BUILD_VERSION`: platform / minimum-OS / SDK / toolchain.
pub const LC_BUILD_VERSION: u32 = 0x32;

/// `LC_SOURCE_VERSION`: 64-bit packed source-control version.
pub const LC_SOURCE_VERSION: u32 = 0x2a;

/// `LC_MAIN`: entry-point load command. Body is `entryoff` (u64)
/// + `stacksize` (u64).
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;

/// `linkedit_data_command` kinds. All share the same 4 + 4 + 4 + 4
/// body shape: cmd + cmdsize prefix already eaten, then body =
/// `dataoff` (u32) + `datasize` (u32).
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

/// On-disk size of `mach_header_64`.
const MACH_HEADER_64_SIZE: u64 = 32;

/// On-disk size of a `LC_SEGMENT_64` command's fixed prefix
/// (the part before any embedded `section_64` entries):
/// 8 bytes (cmd + cmdsize) + 16 (segname) + 8 (vmaddr) + 8 (vmsize)
/// + 8 (fileoff) + 8 (filesize) + 4 (maxprot) + 4 (initprot)
/// + 4 (nsects) + 4 (flags) = 72.
const SEGMENT_64_PREFIX_SIZE: usize = 72;

/// Architecture flavour the parsed Mach-O targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachoCpu {
    X86_64,
    Arm64,
}

/// Errors surfaced when parsing or writing a Mach-O file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file too short: needed {needed} bytes at offset {offset}, have {have}")]
    Truncated { offset: u64, needed: u64, have: u64 },

    #[error("not a Mach-O file: bad magic {0:#x}")]
    BadMagic(u32),

    #[error(
        "fat (universal) Mach-O wrappers are not supported in v1; demux into thin slices first"
    )]
    FatNotSupported,

    #[error("32-bit Mach-O is not supported in v1 (magic {0:#x}); thin 64-bit only")]
    Macho32NotSupported(u32),

    #[error("unsupported cputype {0:#x}: v1 covers x86-64 (0x01000007) and arm64 (0x0100000c)")]
    UnsupportedCpu(u32),

    #[error(
        "load command at offset {offset}: declared cmdsize {cmdsize} is too small (minimum 8)"
    )]
    BadLoadCmdSize { offset: u64, cmdsize: u32 },

    #[error("load-command table runs past sizeofcmds: cursor {cursor}, end {end}")]
    LoadCmdOverrun { cursor: u64, end: u64 },

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

/// Parsed 64-bit Mach-O header.
///
/// Field names mirror Apple's `mach_header_64` verbatim. The
/// struct is public so analysis crates can read its fields;
/// invariants (`magic == MH_MAGIC_64`, `cputype` recognised)
/// are enforced only at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl MachHeader64 {
    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure_len(bytes, 0, MACH_HEADER_64_SIZE)?;
        Ok(Self {
            magic: read_u32(bytes, 0),
            cputype: read_u32(bytes, 4),
            cpusubtype: read_u32(bytes, 8),
            filetype: read_u32(bytes, 12),
            ncmds: read_u32(bytes, 16),
            sizeofcmds: read_u32(bytes, 20),
            flags: read_u32(bytes, 24),
            reserved: read_u32(bytes, 28),
        })
    }

    fn write(&self, out: &mut [u8]) {
        write_u32(out, 0, self.magic);
        write_u32(out, 4, self.cputype);
        write_u32(out, 8, self.cpusubtype);
        write_u32(out, 12, self.filetype);
        write_u32(out, 16, self.ncmds);
        write_u32(out, 20, self.sizeofcmds);
        write_u32(out, 24, self.flags);
        write_u32(out, 28, self.reserved);
    }
}

/// One load command from the table that follows the file header.
///
/// `body` excludes the 8-byte `(cmd, cmdsize)` prefix — the prefix
/// is rebuilt on write from the struct fields, and the body bytes
/// round-trip verbatim. v1 keeps every command kind opaque; richer
/// per-cmd decoding (e.g. structured `LC_SEGMENT_64`, structured
/// `LC_SYMTAB`) is left for later passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub body: Vec<u8>,
}

/// A `LC_SEGMENT_64` descriptor, structurally decoded enough to
/// drive segment-data extraction and the decompile path's
/// section iteration. The raw bytes still round-trip through
/// the matching [`LoadCommand::body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment64 {
    /// Index of this segment's `LC_SEGMENT_64` entry in
    /// [`MachoFile::commands`].
    pub cmd_index: usize,
    /// Null-padded segment name (`__TEXT`, `__DATA_CONST`,
    /// `__LINKEDIT`, …). Up to 16 bytes.
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
    pub sections: Vec<Section64>,
}

/// A `section_64` entry within an `LC_SEGMENT_64`. Field naming
/// matches Apple's struct verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section64 {
    /// Null-padded section name (`__text`, `__cstring`, …).
    pub sectname: [u8; 16],
    /// Null-padded enclosing segment name (`__TEXT`, …).
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Segment64 {
    /// UTF-8 (lossy) version of the null-padded segment name —
    /// the trailing NULs are trimmed. Used by callers that want
    /// `__TEXT` / `__DATA` style readable identifiers.
    #[must_use]
    pub fn name(&self) -> String {
        cstr_name(&self.segname)
    }
}

impl Section64 {
    /// UTF-8 (lossy) section name with trailing NULs trimmed.
    #[must_use]
    pub fn name(&self) -> String {
        cstr_name(&self.sectname)
    }

    /// UTF-8 (lossy) segment name with trailing NULs trimmed.
    #[must_use]
    pub fn segment_name(&self) -> String {
        cstr_name(&self.segname)
    }
}

fn cstr_name(buf: &[u8]) -> String {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).into_owned()
}

/// A parsed thin 64-bit Mach-O file in a form that round-trips
/// byte-identically.
///
/// The structured fields (`header`, `commands`) are interpreted;
/// every load command's `body` carries the raw bytes for that
/// command, and each segment's file data is captured in
/// `segment_data` parallel to the `LC_SEGMENT_64` entries in
/// `commands`. Gaps between structured regions land in `padding`
/// — same `(file_offset, bytes)` convention `Elf64File` uses.
#[derive(Debug, Clone)]
pub struct MachoFile {
    pub header: MachHeader64,
    pub commands: Vec<LoadCommand>,
    /// Segment file content, one entry per `LC_SEGMENT_64` load
    /// command in declaration order. `__PAGEZERO` (filesize 0)
    /// contributes an empty vec — that's fine, it just doesn't
    /// occupy file space.
    segment_data: Vec<Vec<u8>>,
    /// Index into `commands` for each entry in `segment_data`
    /// (so callers can pair them back up).
    segment_cmd_indices: Vec<usize>,
    /// Bytes in gaps between structured regions. Stored as
    /// `(file_offset, bytes)`.
    padding: Vec<(u64, Vec<u8>)>,
    file_size: u64,
}

/// True when `bytes` start with any Mach-O magic — thin 32- or
/// 64-bit, either endian, plus the fat (universal) wrapper.
/// Doesn't say whether v1 will *accept* the file (use
/// [`is_macho64`] for that gate).
#[must_use]
pub fn is_macho(bytes: &[u8]) -> bool {
    is_macho64(bytes) || is_fat(bytes) || is_macho32(bytes) || is_macho_be(bytes)
}

/// True when `bytes` are a thin 32-bit little-endian Mach-O.
/// Detected so callers can route around it; v1 parse refuses.
#[must_use]
pub fn is_macho32(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && read_u32(bytes, 0) == MH_MAGIC
}

/// True when `bytes` are a big-endian thin Mach-O (typically
/// legacy PowerPC binaries). Detected so callers can route
/// around it.
#[must_use]
fn is_macho_be(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    be == MH_MAGIC_64 || be == MH_MAGIC
}

/// True when `bytes` are a thin 64-bit little-endian Mach-O —
/// the flavour [`MachoFile::parse`] handles. Callers that route
/// by format should gate on this and fall through to a byte-copy
/// for unsupported variants so the round-trip contract still
/// holds.
#[must_use]
pub fn is_macho64(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && read_u32(bytes, 0) == MH_MAGIC_64
}

/// True when `bytes` are a fat (universal) Mach-O wrapper. Not
/// supported by v1 parse, but exposed so callers can route around
/// it.
#[must_use]
pub fn is_fat(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    // Fat magic is stored big-endian on disk.
    let magic_be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64
}

impl MachoFile {
    /// Parse a thin 64-bit little-endian Mach-O file.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(Error::Truncated {
                offset: 0,
                needed: 4,
                have: bytes.len() as u64,
            });
        }
        let magic = read_u32(bytes, 0);
        if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
            return Err(Error::FatNotSupported);
        }
        // Big-endian variants of the fat magic on a little-endian
        // host show up as the swapped values; refuse those too.
        let magic_be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64 {
            return Err(Error::FatNotSupported);
        }
        if magic == MH_MAGIC || magic == 0xcefa_edfe {
            return Err(Error::Macho32NotSupported(magic));
        }
        if magic != MH_MAGIC_64 {
            return Err(Error::BadMagic(magic));
        }
        let header = MachHeader64::parse(bytes)?;
        match header.cputype {
            CPU_TYPE_X86_64 | CPU_TYPE_ARM64 => {}
            other => return Err(Error::UnsupportedCpu(other)),
        }

        let commands = parse_load_commands(bytes, &header)?;
        let (segment_data, segment_cmd_indices) = collect_segment_data(bytes, &commands)?;
        let regions = build_regions(&header, &commands)?;
        let padding = compute_padding(bytes, &regions);

        Ok(Self {
            header,
            commands,
            segment_data,
            segment_cmd_indices,
            padding,
            file_size: bytes.len() as u64,
        })
    }

    /// Reconstruct from already-parsed pieces. Used by the lower
    /// path when assembling a Mach-O from `.ud` source.
    #[must_use]
    pub fn from_parts(
        header: MachHeader64,
        commands: Vec<LoadCommand>,
        segment_data: Vec<Vec<u8>>,
        segment_cmd_indices: Vec<usize>,
        padding: Vec<(u64, Vec<u8>)>,
        file_size: u64,
    ) -> Self {
        Self {
            header,
            commands,
            segment_data,
            segment_cmd_indices,
            padding,
            file_size,
        }
    }

    /// Architecture flavour this file targets. Returns `None`
    /// when the `cputype` isn't one v1 supports — `parse` already
    /// rejects unsupported types, so this can only happen via
    /// `from_parts`.
    #[must_use]
    pub fn cpu(&self) -> Option<MachoCpu> {
        match self.header.cputype {
            CPU_TYPE_X86_64 => Some(MachoCpu::X86_64),
            CPU_TYPE_ARM64 => Some(MachoCpu::Arm64),
            _ => None,
        }
    }

    /// Walk every `LC_SEGMENT_64` and return a structurally-decoded
    /// view of each segment + its sections. The raw bytes still
    /// live in `commands[i].body`; this is purely a read-side
    /// convenience for callers that don't want to re-parse the
    /// fixed `LC_SEGMENT_64` layout themselves.
    #[must_use]
    pub fn segments(&self) -> Vec<Segment64> {
        let mut out = Vec::new();
        for (idx, cmd) in self.commands.iter().enumerate() {
            if cmd.cmd != LC_SEGMENT_64 {
                continue;
            }
            if let Some(seg) = Segment64::parse(idx, cmd) {
                out.push(seg);
            }
        }
        out
    }

    /// Segment file data parallel to the `LC_SEGMENT_64` commands
    /// in `self.commands`.  Each entry corresponds to the segment
    /// whose `cmd_index` is at the matching slot in
    /// [`Self::segment_command_indices`].
    #[must_use]
    pub fn segment_data(&self) -> &[Vec<u8>] {
        &self.segment_data
    }

    /// Indices into `commands` for each `segment_data` entry.
    #[must_use]
    pub fn segment_command_indices(&self) -> &[usize] {
        &self.segment_cmd_indices
    }

    /// Padding bytes — gaps between structured regions, stored as
    /// `(file_offset, bytes)`.
    #[must_use]
    pub fn padding(&self) -> &[(u64, Vec<u8>)] {
        &self.padding
    }

    /// Total on-disk size in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Serialize back to bytes. The contract is byte-identity:
    /// `parse(b)?.write_to_vec() == b` for every supported input.
    #[must_use]
    pub fn write_to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.file_size as usize];
        // Segments first — they cover the bulk of the file
        // (including the bytes that overlay the header + load
        // command table for the leading `__TEXT` segment, which
        // is how Mach-O lays out executables). Writing the
        // structured header + commands AFTER segments keeps the
        // header's parsed-fields source-of-truth even when a
        // segment overlaps it.
        for (i, data) in self.segment_data.iter().enumerate() {
            let cmd_idx = self.segment_cmd_indices[i];
            let seg = self
                .commands
                .get(cmd_idx)
                .and_then(|c| Segment64::parse(cmd_idx, c));
            if let Some(seg) = seg {
                if seg.filesize > 0 && !data.is_empty() {
                    let off = seg.fileoff as usize;
                    out[off..off + data.len()].copy_from_slice(data);
                }
            }
        }

        // Header at offset 0.
        self.header.write(&mut out[..MACH_HEADER_64_SIZE as usize]);

        // Load-command table immediately after the header.
        let mut cursor = MACH_HEADER_64_SIZE as usize;
        for cmd in &self.commands {
            write_u32(&mut out, cursor, cmd.cmd);
            write_u32(&mut out, cursor + 4, cmd.cmdsize);
            out[cursor + 8..cursor + 8 + cmd.body.len()].copy_from_slice(&cmd.body);
            cursor += cmd.cmdsize as usize;
        }

        // Padding (interstitial alignment bytes the parse pass
        // captured verbatim).
        for (offset, bytes) in &self.padding {
            let off = *offset as usize;
            out[off..off + bytes.len()].copy_from_slice(bytes);
        }

        out
    }
}

impl Segment64 {
    fn parse(cmd_index: usize, cmd: &LoadCommand) -> Option<Self> {
        if cmd.cmd != LC_SEGMENT_64 {
            return None;
        }
        // body = bytes after the `cmd`/`cmdsize` prefix; the
        // SEGMENT_64_PREFIX_SIZE - 8 = 64 bytes describe the
        // segment itself, followed by `nsects` x 80-byte
        // section_64 entries.
        let body = &cmd.body;
        if body.len() < SEGMENT_64_PREFIX_SIZE - 8 {
            return None;
        }
        let mut segname = [0u8; 16];
        segname.copy_from_slice(&body[0..16]);
        let vmaddr = read_u64(body, 16);
        let vmsize = read_u64(body, 24);
        let fileoff = read_u64(body, 32);
        let filesize = read_u64(body, 40);
        let maxprot = read_u32(body, 48);
        let initprot = read_u32(body, 52);
        let nsects = read_u32(body, 56);
        let flags = read_u32(body, 60);

        let mut sections = Vec::with_capacity(nsects as usize);
        let sect_start = SEGMENT_64_PREFIX_SIZE - 8; // = 64
        let sect_size = 80;
        for i in 0..nsects as usize {
            let off = sect_start + i * sect_size;
            if body.len() < off + sect_size {
                return None;
            }
            let s = &body[off..off + sect_size];
            let mut sectname = [0u8; 16];
            sectname.copy_from_slice(&s[0..16]);
            let mut sn = [0u8; 16];
            sn.copy_from_slice(&s[16..32]);
            sections.push(Section64 {
                sectname,
                segname: sn,
                addr: read_u64(s, 32),
                size: read_u64(s, 40),
                offset: read_u32(s, 48),
                align: read_u32(s, 52),
                reloff: read_u32(s, 56),
                nreloc: read_u32(s, 60),
                flags: read_u32(s, 64),
                reserved1: read_u32(s, 68),
                reserved2: read_u32(s, 72),
                reserved3: read_u32(s, 76),
            });
        }

        Some(Self {
            cmd_index,
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects,
            flags,
            sections,
        })
    }

    /// Serialize this segment back to the bytes that follow the
    /// 8-byte `cmd`/`cmdsize` prefix of a `LC_SEGMENT_64` load
    /// command — i.e. the body that round-trips through
    /// [`LoadCommand::body`]. Output length is
    /// `64 + 80 * sections.len()`.
    #[must_use]
    pub fn write_to_body(&self) -> Vec<u8> {
        let mut out = vec![0u8; 64 + 80 * self.sections.len()];
        out[0..16].copy_from_slice(&self.segname);
        out[16..24].copy_from_slice(&self.vmaddr.to_le_bytes());
        out[24..32].copy_from_slice(&self.vmsize.to_le_bytes());
        out[32..40].copy_from_slice(&self.fileoff.to_le_bytes());
        out[40..48].copy_from_slice(&self.filesize.to_le_bytes());
        out[48..52].copy_from_slice(&self.maxprot.to_le_bytes());
        out[52..56].copy_from_slice(&self.initprot.to_le_bytes());
        out[56..60].copy_from_slice(&self.nsects.to_le_bytes());
        out[60..64].copy_from_slice(&self.flags.to_le_bytes());
        for (i, s) in self.sections.iter().enumerate() {
            let off = 64 + i * 80;
            out[off..off + 16].copy_from_slice(&s.sectname);
            out[off + 16..off + 32].copy_from_slice(&s.segname);
            out[off + 32..off + 40].copy_from_slice(&s.addr.to_le_bytes());
            out[off + 40..off + 48].copy_from_slice(&s.size.to_le_bytes());
            out[off + 48..off + 52].copy_from_slice(&s.offset.to_le_bytes());
            out[off + 52..off + 56].copy_from_slice(&s.align.to_le_bytes());
            out[off + 56..off + 60].copy_from_slice(&s.reloff.to_le_bytes());
            out[off + 60..off + 64].copy_from_slice(&s.nreloc.to_le_bytes());
            out[off + 64..off + 68].copy_from_slice(&s.flags.to_le_bytes());
            out[off + 68..off + 72].copy_from_slice(&s.reserved1.to_le_bytes());
            out[off + 72..off + 76].copy_from_slice(&s.reserved2.to_le_bytes());
            out[off + 76..off + 80].copy_from_slice(&s.reserved3.to_le_bytes());
        }
        out
    }
}

// ---------- structured load-command bodies ----------

/// Structurally decoded body of an `LC_SYMTAB` command. Four
/// `u32`s sized exactly 16 bytes on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcSymtab {
    /// File offset of the `nlist_64` table.
    pub symoff: u32,
    /// Number of symbols in the table.
    pub nsyms: u32,
    /// File offset of the string table.
    pub stroff: u32,
    /// String table size in bytes.
    pub strsize: u32,
}

impl LcSymtab {
    /// Decode from a 16-byte command body. Returns `None` on
    /// length mismatch so the caller can fall back to opaque
    /// bytes for unrecognised inputs.
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != 16 {
            return None;
        }
        Some(Self {
            symoff: read_u32(body, 0),
            nsyms: read_u32(body, 4),
            stroff: read_u32(body, 8),
            strsize: read_u32(body, 12),
        })
    }

    /// Encode back to the 16-byte body that
    /// [`LoadCommand::body`] carries.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 16];
        out[0..4].copy_from_slice(&self.symoff.to_le_bytes());
        out[4..8].copy_from_slice(&self.nsyms.to_le_bytes());
        out[8..12].copy_from_slice(&self.stroff.to_le_bytes());
        out[12..16].copy_from_slice(&self.strsize.to_le_bytes());
        out
    }
}

/// Structurally decoded body of an `LC_DYSYMTAB` command — 18
/// `u32`s describing partitions of the LC_SYMTAB table and
/// auxiliary indirect-symbol / module / reference tables.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcDysymtab {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

impl LcDysymtab {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != 72 {
            return None;
        }
        Some(Self {
            ilocalsym: read_u32(body, 0),
            nlocalsym: read_u32(body, 4),
            iextdefsym: read_u32(body, 8),
            nextdefsym: read_u32(body, 12),
            iundefsym: read_u32(body, 16),
            nundefsym: read_u32(body, 20),
            tocoff: read_u32(body, 24),
            ntoc: read_u32(body, 28),
            modtaboff: read_u32(body, 32),
            nmodtab: read_u32(body, 36),
            extrefsymoff: read_u32(body, 40),
            nextrefsyms: read_u32(body, 44),
            indirectsymoff: read_u32(body, 48),
            nindirectsyms: read_u32(body, 52),
            extreloff: read_u32(body, 56),
            nextrel: read_u32(body, 60),
            locreloff: read_u32(body, 64),
            nlocrel: read_u32(body, 68),
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 72];
        for (i, v) in [
            self.ilocalsym,
            self.nlocalsym,
            self.iextdefsym,
            self.nextdefsym,
            self.iundefsym,
            self.nundefsym,
            self.tocoff,
            self.ntoc,
            self.modtaboff,
            self.nmodtab,
            self.extrefsymoff,
            self.nextrefsyms,
            self.indirectsymoff,
            self.nindirectsyms,
            self.extreloff,
            self.nextrel,
            self.locreloff,
            self.nlocrel,
        ]
        .iter()
        .enumerate()
        {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

/// Body of `LC_LOAD_DYLINKER` (and the analogous `LC_ID_DYLINKER`
/// — same shape). The `offset` is from the start of the command
/// (including the cmd/cmdsize prefix), which in the canonical
/// linker output is `0xc` — i.e. the name begins at body offset
/// 4. `name` holds the C string up to (but not including) the
/// first NUL; `tail_padding` carries the NUL + any trailing
/// alignment NULs verbatim, so the encoded length always matches
/// the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcDylinker {
    pub offset: u32,
    pub name: Vec<u8>,
    pub tail_padding: Vec<u8>,
}

impl LcDylinker {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 4 {
            return None;
        }
        let offset = read_u32(body, 0);
        // offset is measured from start-of-command, so the name
        // begins at body offset `offset - 8`.
        let name_off = offset.checked_sub(8)? as usize;
        if name_off > body.len() {
            return None;
        }
        let tail = &body[name_off..];
        let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let name = tail[..nul].to_vec();
        let tail_padding = tail[nul..].to_vec();
        // Body offset 4..name_off is reserved zero padding the
        // linker rarely (never?) sets non-zero. We require it to
        // be zero so the structured form is unambiguous; the
        // caller falls back to opaque bytes if it isn't.
        if body[4..name_off].iter().any(|&b| b != 0) {
            return None;
        }
        Some(Self {
            offset,
            name,
            tail_padding,
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let name_off = (self.offset as usize).saturating_sub(8);
        let mut out = vec![0u8; name_off + self.name.len() + self.tail_padding.len()];
        out[0..4].copy_from_slice(&self.offset.to_le_bytes());
        // bytes 4..name_off stay zero
        out[name_off..name_off + self.name.len()].copy_from_slice(&self.name);
        out[name_off + self.name.len()..].copy_from_slice(&self.tail_padding);
        out
    }
}

/// Body of `LC_LOAD_DYLIB` / `LC_ID_DYLIB` / `LC_LOAD_WEAK_DYLIB`
/// / `LC_REEXPORT_DYLIB`. The same 4-u32 dylib record followed by
/// the NUL-padded name string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcDylib {
    pub offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
    pub name: Vec<u8>,
    pub tail_padding: Vec<u8>,
}

impl LcDylib {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 16 {
            return None;
        }
        let offset = read_u32(body, 0);
        let timestamp = read_u32(body, 4);
        let current_version = read_u32(body, 8);
        let compatibility_version = read_u32(body, 12);
        let name_off = offset.checked_sub(8)? as usize;
        if name_off > body.len() || name_off < 16 {
            return None;
        }
        if body[16..name_off].iter().any(|&b| b != 0) {
            return None;
        }
        let tail = &body[name_off..];
        let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        Some(Self {
            offset,
            timestamp,
            current_version,
            compatibility_version,
            name: tail[..nul].to_vec(),
            tail_padding: tail[nul..].to_vec(),
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let name_off = (self.offset as usize).saturating_sub(8);
        let mut out = vec![0u8; name_off + self.name.len() + self.tail_padding.len()];
        out[0..4].copy_from_slice(&self.offset.to_le_bytes());
        out[4..8].copy_from_slice(&self.timestamp.to_le_bytes());
        out[8..12].copy_from_slice(&self.current_version.to_le_bytes());
        out[12..16].copy_from_slice(&self.compatibility_version.to_le_bytes());
        out[name_off..name_off + self.name.len()].copy_from_slice(&self.name);
        out[name_off + self.name.len()..].copy_from_slice(&self.tail_padding);
        out
    }
}

/// Body of `LC_BUILD_VERSION`. Records the platform / minimum OS
/// / SDK / per-tool versions. `ntools` is recovered from
/// `tools.len()` at encode time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcBuildVersion {
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub tools: Vec<BuildVersionTool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildVersionTool {
    pub tool: u32,
    pub version: u32,
}

impl LcBuildVersion {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 16 {
            return None;
        }
        let platform = read_u32(body, 0);
        let minos = read_u32(body, 4);
        let sdk = read_u32(body, 8);
        let ntools = read_u32(body, 12) as usize;
        if body.len() != 16 + 8 * ntools {
            return None;
        }
        let mut tools = Vec::with_capacity(ntools);
        for i in 0..ntools {
            let off = 16 + 8 * i;
            tools.push(BuildVersionTool {
                tool: read_u32(body, off),
                version: read_u32(body, off + 4),
            });
        }
        Some(Self {
            platform,
            minos,
            sdk,
            tools,
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 16 + 8 * self.tools.len()];
        out[0..4].copy_from_slice(&self.platform.to_le_bytes());
        out[4..8].copy_from_slice(&self.minos.to_le_bytes());
        out[8..12].copy_from_slice(&self.sdk.to_le_bytes());
        out[12..16].copy_from_slice(&(self.tools.len() as u32).to_le_bytes());
        for (i, t) in self.tools.iter().enumerate() {
            let off = 16 + 8 * i;
            out[off..off + 4].copy_from_slice(&t.tool.to_le_bytes());
            out[off + 4..off + 8].copy_from_slice(&t.version.to_le_bytes());
        }
        out
    }
}

/// Body of `LC_MAIN`. Entry-point offset + initial stack size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcMain {
    pub entryoff: u64,
    pub stacksize: u64,
}

impl LcMain {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != 16 {
            return None;
        }
        Some(Self {
            entryoff: read_u64(body, 0),
            stacksize: read_u64(body, 8),
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 16];
        out[0..8].copy_from_slice(&self.entryoff.to_le_bytes());
        out[8..16].copy_from_slice(&self.stacksize.to_le_bytes());
        out
    }
}

/// Body of every `linkedit_data_command`-shaped load command
/// (LC_CODE_SIGNATURE, LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
/// LC_DYLD_EXPORTS_TRIE, LC_DYLD_CHAINED_FIXUPS, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcLinkeditData {
    pub dataoff: u32,
    pub datasize: u32,
}

impl LcLinkeditData {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != 8 {
            return None;
        }
        Some(Self {
            dataoff: read_u32(body, 0),
            datasize: read_u32(body, 4),
        })
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; 8];
        out[0..4].copy_from_slice(&self.dataoff.to_le_bytes());
        out[4..8].copy_from_slice(&self.datasize.to_le_bytes());
        out
    }
}

/// Body of `LC_SOURCE_VERSION`: one packed 64-bit version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcSourceVersion(pub u64);

impl LcSourceVersion {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != 8 {
            return None;
        }
        Some(Self(read_u64(body, 0)))
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

/// Body of `LC_UUID`: 16 raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcUuid(pub [u8; 16]);

impl LcUuid {
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() != 16 {
            return None;
        }
        let mut u = [0u8; 16];
        u.copy_from_slice(body);
        Some(Self(u))
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// True when `cmd` is one of the linkedit_data_command-shaped
/// load commands (the 4+4-byte body pattern).
#[must_use]
pub fn is_linkedit_data_cmd(cmd: u32) -> bool {
    matches!(
        cmd,
        LC_CODE_SIGNATURE
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
    )
}

/// True when `cmd` is one of the dylib-shaped load commands.
#[must_use]
pub fn is_dylib_cmd(cmd: u32) -> bool {
    matches!(
        cmd,
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_ID_DYLIB
    )
}

// ---------- internal helpers ----------

fn ensure_len(bytes: &[u8], offset: u64, needed: u64) -> Result<()> {
    let end = offset.saturating_add(needed);
    if (bytes.len() as u64) < end {
        return Err(Error::Truncated {
            offset,
            needed,
            have: bytes.len() as u64,
        });
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn parse_load_commands(bytes: &[u8], header: &MachHeader64) -> Result<Vec<LoadCommand>> {
    let table_start = MACH_HEADER_64_SIZE;
    let table_end = table_start + u64::from(header.sizeofcmds);
    ensure_len(bytes, table_start, u64::from(header.sizeofcmds))?;

    let mut commands = Vec::with_capacity(header.ncmds as usize);
    let mut cursor = table_start;
    for _ in 0..header.ncmds {
        if cursor + 8 > table_end {
            return Err(Error::LoadCmdOverrun {
                cursor,
                end: table_end,
            });
        }
        let cmd = read_u32(bytes, cursor as usize);
        let cmdsize = read_u32(bytes, cursor as usize + 4);
        if cmdsize < 8 {
            return Err(Error::BadLoadCmdSize {
                offset: cursor,
                cmdsize,
            });
        }
        let next = cursor + u64::from(cmdsize);
        if next > table_end {
            return Err(Error::LoadCmdOverrun {
                cursor: next,
                end: table_end,
            });
        }
        let body_start = cursor as usize + 8;
        let body_end = next as usize;
        let body = bytes[body_start..body_end].to_vec();
        commands.push(LoadCommand { cmd, cmdsize, body });
        cursor = next;
    }
    if cursor != table_end {
        return Err(Error::LoadCmdOverrun {
            cursor,
            end: table_end,
        });
    }
    Ok(commands)
}

fn collect_segment_data(
    bytes: &[u8],
    commands: &[LoadCommand],
) -> Result<(Vec<Vec<u8>>, Vec<usize>)> {
    let mut data = Vec::new();
    let mut indices = Vec::new();
    for (idx, cmd) in commands.iter().enumerate() {
        if cmd.cmd != LC_SEGMENT_64 {
            continue;
        }
        let Some(seg) = Segment64::parse(idx, cmd) else {
            continue;
        };
        indices.push(idx);
        if seg.filesize == 0 {
            data.push(Vec::new());
            continue;
        }
        let end = seg
            .fileoff
            .checked_add(seg.filesize)
            .ok_or_else(|| Error::RegionOverflow {
                label: format!("segment #{idx} ({:?})", seg.name()),
                offset: seg.fileoff,
                size: seg.filesize,
            })?;
        ensure_len(bytes, seg.fileoff, seg.filesize)?;
        data.push(bytes[seg.fileoff as usize..end as usize].to_vec());
    }
    Ok((data, indices))
}

struct Region {
    /// Human label, retained for future overlap diagnostics
    /// (matching the ELF crate's pattern); unused today because
    /// the Mach-O layout is intentionally permissive about
    /// overlapping segment / header ranges.
    #[allow(dead_code)]
    label: String,
    range: Range<u64>,
}

fn build_regions(header: &MachHeader64, commands: &[LoadCommand]) -> Result<Vec<Region>> {
    let mut regions = Vec::new();

    // Header.
    regions.push(Region {
        label: "Mach-O header".into(),
        range: 0..MACH_HEADER_64_SIZE,
    });

    // Load-command table.
    if header.sizeofcmds > 0 {
        regions.push(Region {
            label: "load-command table".into(),
            range: MACH_HEADER_64_SIZE..MACH_HEADER_64_SIZE + u64::from(header.sizeofcmds),
        });
    }

    // Segments. We treat segments as opaque regions: their file
    // ranges may overlap with the header/load-command table (the
    // leading `__TEXT` segment of an executable straddles offset
    // 0), and they may overlap with each other in pathological
    // cases — we *don't* enforce non-overlap here, just merge
    // identical-start regions into one for padding purposes.
    for (idx, cmd) in commands.iter().enumerate() {
        if cmd.cmd != LC_SEGMENT_64 {
            continue;
        }
        let Some(seg) = Segment64::parse(idx, cmd) else {
            continue;
        };
        if seg.filesize == 0 {
            continue;
        }
        let end = seg
            .fileoff
            .checked_add(seg.filesize)
            .ok_or_else(|| Error::RegionOverflow {
                label: format!("segment #{idx} ({:?})", seg.name()),
                offset: seg.fileoff,
                size: seg.filesize,
            })?;
        regions.push(Region {
            label: format!("segment #{idx} ({:?})", seg.name()),
            range: seg.fileoff..end,
        });
    }

    regions.sort_by_key(|r| r.range.start);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_detection() {
        let buf = [0xcf, 0xfa, 0xed, 0xfe];
        assert!(is_macho(&buf));
        assert!(is_macho64(&buf));
        let fat = [0xca, 0xfe, 0xba, 0xbe];
        assert!(is_macho(&fat));
        assert!(is_fat(&fat));
        assert!(!is_macho64(&fat));
    }

    #[test]
    fn rejects_short_input() {
        let err = MachoFile::parse(b"\x7fELF").unwrap_err();
        assert!(matches!(err, Error::BadMagic(_)));
    }
}

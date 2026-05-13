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

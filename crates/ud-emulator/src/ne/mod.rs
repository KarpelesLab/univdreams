//! NE (16-bit Windows "New Executable") loader for the sandbox.
//!
//! Mirrors the [`crate::pe`] loader, but for the segmented 16-bit
//! world. Where PE maps flat sections into a single linear image and
//! resolves imports through a 32-bit IAT, NE has *segments* — each its
//! own ≤64 KiB world reached through a selector — and per-segment
//! relocation records that patch `selector:offset` far pointers in
//! place.
//!
//! Strategy:
//! * Parse the container with the byte-identical [`ud_format::ne`]
//!   reader.
//! * Give every NE segment its own 64 KiB linear window in a dedicated
//!   Win16 arena and record `selector → base` (the selector token is
//!   just the 1-based segment number; the loader owns the mapping, so
//!   the tokens only have to be internally consistent).
//! * Apply each segment's relocation table: *internal* references
//!   become `segment:offset` far pointers into the assigned windows;
//!   *imported-ordinal* references become a far pointer into the Win16
//!   thunk window, so a guest `call far` to an imported entry lands on
//!   a fail-soft thunk the run loop already knows how to trap on (the
//!   same `register_unknown_fallback` mechanism PE fail-soft uses).
//!
//! The returned [`NeImage`] carries the entry `CS:IP`, initial
//! `SS:SP`, and the selector table so the caller can prime the CPU
//! into 16-bit mode and run.

use crate::emulator::mmu::{Mmu, Perm};
use crate::win32::{Registry, THUNK_BASE};
use ud_format::ne::NeFile;

/// Base of the Win16 segment arena (1 MiB). Each NE segment gets a
/// 64 KiB window: segment *i* (1-based) → `WIN16_SEG_BASE + (i-1)*64K`.
pub const WIN16_SEG_BASE: u32 = 0x0010_0000;
/// Stride between consecutive segment windows (64 KiB).
pub const WIN16_SEG_STRIDE: u32 = 0x0001_0000;
/// Selector token for the import-thunk window. Far pointers to
/// imported entry points use this selector; its base is [`THUNK_BASE`],
/// so the far target equals the registry thunk address and the run
/// loop's `is_thunk` check fires.
pub const IMPORT_SELECTOR: u16 = 0xF000;
/// Selector token whose base is the CPU's `RET_SENTINEL`, pushed as the
/// far-return target so a top-level `RETF` from the entry halts the run
/// loop cleanly (mirrors how the PE path pushes `RET_SENTINEL`).
pub const SENTINEL_SELECTOR: u16 = 0xFFF8;

/// Errors raised while loading an NE module.
#[derive(Debug, thiserror::Error)]
pub enum NeLoadError {
    #[error("NE parse failed: {0}")]
    Parse(#[from] ud_format::ne::Error),
    #[error("segment {seg} data [{off:#x}..+{len:#x}] runs past the file ({file_len} bytes)")]
    SegmentOutOfRange {
        seg: usize,
        off: usize,
        len: usize,
        file_len: usize,
    },
    #[error("memory map failed at {addr:#x}: {detail}")]
    Map { addr: u32, detail: String },
}

/// A loaded NE module, ready to run in 16-bit segmented mode.
#[derive(Debug, Clone)]
pub struct NeImage {
    pub module_name: String,
    /// Entry point as a far `CS:IP` (CS is the 1-based segment number,
    /// which doubles as the selector token).
    pub entry_cs: u16,
    pub entry_ip: u16,
    /// Initial stack `SS:SP` from the NE header.
    pub init_ss: u16,
    pub init_sp: u16,
    /// 1-based segment number of the automatic data segment (DGROUP).
    pub auto_data: u16,
    /// `selector → linear base` mappings to install on the CPU
    /// (segment windows plus the import-thunk window).
    pub selectors: Vec<(u16, u32)>,
    /// Imported `(module, "@ordinal")` references the loader pointed at
    /// fail-soft thunks — surfaced for the monitor report.
    pub unresolved: Vec<(String, String)>,
}

/// Load an NE module into `mmu`, resolving imports through `registry`
/// in fail-soft mode (every imported ordinal gets a trap-on-call
/// thunk). Returns the [`NeImage`] describing how to enter it.
///
/// # Errors
/// Returns [`NeLoadError`] if the container is not a valid NE, a
/// segment's declared data runs past the file, or a memory map fails.
pub fn load_ne(
    mmu: &mut Mmu,
    registry: &mut Registry,
    bytes: &[u8],
) -> Result<NeImage, NeLoadError> {
    let ne = NeFile::parse(bytes)?;
    let h = &ne.header;

    let mut selectors: Vec<(u16, u32)> = Vec::new();

    // 1) Map + populate each segment's 64 KiB window.
    for (i, seg) in ne.segments.iter().enumerate() {
        let segnum = u16::try_from(i + 1).unwrap_or(u16::MAX);
        let base = WIN16_SEG_BASE + (i as u32) * WIN16_SEG_STRIDE;
        mmu.map(base, WIN16_SEG_STRIDE, Perm::R | Perm::W | Perm::X);
        if let Some(file_off) = seg.file_offset(h) {
            let off = file_off as usize;
            let len = seg.data_len() as usize;
            let data = bytes
                .get(off..off + len)
                .ok_or(NeLoadError::SegmentOutOfRange {
                    seg: segnum as usize,
                    off,
                    len,
                    file_len: bytes.len(),
                })?;
            mmu.write_initializer(base, data)
                .map_err(|t| NeLoadError::Map {
                    addr: base,
                    detail: t.to_string(),
                })?;
        }
        selectors.push((segnum, base));
    }
    // The import-thunk window shares the registry's THUNK_BASE region.
    selectors.push((IMPORT_SELECTOR, THUNK_BASE));

    // 2) Apply per-segment relocations.
    let mut unresolved: Vec<(String, String)> = Vec::new();
    for (i, seg) in ne.segments.iter().enumerate() {
        if !seg.has_relocations() {
            continue;
        }
        let Some(file_off) = seg.file_offset(h) else {
            continue;
        };
        let base = WIN16_SEG_BASE + (i as u32) * WIN16_SEG_STRIDE;
        let reloc_off = file_off as usize + seg.data_len() as usize;
        apply_segment_relocs(mmu, registry, &ne, bytes, reloc_off, base, &mut unresolved);
    }

    Ok(NeImage {
        module_name: ne.module_name().unwrap_or("?").to_string(),
        entry_cs: (h.cs_ip >> 16) as u16,
        entry_ip: (h.cs_ip & 0xFFFF) as u16,
        init_ss: (h.ss_sp >> 16) as u16,
        init_sp: (h.ss_sp & 0xFFFF) as u16,
        auto_data: h.auto_data_seg,
        selectors,
        unresolved,
    })
}

/// NE relocation address types (the low nibble of record byte 0).
const RT_OFFSET_LOBYTE: u8 = 0;
const RT_SEGMENT: u8 = 2; // 16-bit selector
const RT_FAR_PTR: u8 = 3; // 32-bit selector:offset
const RT_OFFSET: u8 = 5; // 16-bit offset
/// NE relocation source types (low 2 bits of record byte 1).
const SRC_INTERNAL: u8 = 0;
const SRC_IMPORT_ORDINAL: u8 = 1;
const FLAG_ADDITIVE: u8 = 0x04;

/// Apply one segment's relocation table. The table is a `u16` record
/// count followed by that many 8-byte records, located immediately
/// after the segment's on-disk data. Malformed records are skipped —
/// the loader is best-effort, since reaching the first imported call
/// only needs the import fixups to land.
fn apply_segment_relocs(
    mmu: &mut Mmu,
    registry: &mut Registry,
    ne: &NeFile,
    bytes: &[u8],
    reloc_off: usize,
    base: u32,
    unresolved: &mut Vec<(String, String)>,
) {
    let Some(count) = read_u16(bytes, reloc_off) else {
        return;
    };
    let mut rec = reloc_off + 2;
    for _ in 0..count {
        let Some(record) = bytes.get(rec..rec + 8) else {
            break;
        };
        rec += 8;
        let addr_type = record[0] & 0x0F;
        let src_type = record[1] & 0x03;
        let additive = record[1] & FLAG_ADDITIVE != 0;
        let loc = u16::from_le_bytes([record[2], record[3]]);

        // Resolve the (selector, offset) this fixup installs.
        let target = match src_type {
            SRC_INTERNAL => {
                let seg = record[4];
                let off = u16::from_le_bytes([record[6], record[7]]);
                if seg == 0xFF {
                    // Movable internal ref (via entry table) — not yet
                    // resolved; leave the placeholder.
                    continue;
                }
                Some((u16::from(seg), off))
            }
            SRC_IMPORT_ORDINAL => {
                let mod_idx = u16::from_le_bytes([record[4], record[5]]) as usize;
                let ordinal = u16::from_le_bytes([record[6], record[7]]);
                let module = ne
                    .imported_modules
                    .get(mod_idx.wrapping_sub(1))
                    .cloned()
                    .unwrap_or_default();
                let dll = module.to_ascii_lowercase();
                let name = format!("@{ordinal}");
                // Prefer a registered Win16 stub; fall back to a
                // trap-on-call thunk (and report it) for the rest.
                let thunk = match registry.resolve(&dll, &name) {
                    Some(addr) => addr,
                    None => {
                        unresolved.push((module, name.clone()));
                        registry.register_unknown_fallback(&dll, &name)
                    }
                };
                Some((IMPORT_SELECTOR, (thunk - THUNK_BASE) as u16))
            }
            // Imported-by-name / OS fixups: skip for now.
            _ => None,
        };
        let Some((sel, off)) = target else {
            continue;
        };

        if additive {
            patch_one(mmu, base, u32::from(loc), addr_type, sel, off);
        } else {
            patch_chain(mmu, base, loc, addr_type, sel, off);
        }
    }
}

/// Walk a non-additive fixup chain: each location holds a `u16` link to
/// the next location to patch, terminated by `0xFFFF`. We read the link
/// *before* overwriting the location.
fn patch_chain(mmu: &mut Mmu, base: u32, start: u16, addr_type: u8, sel: u16, off: u16) {
    let mut cur = start;
    for _ in 0..0x1_0000 {
        let here = base.wrapping_add(u32::from(cur));
        let next = mmu.load16(here).unwrap_or(0xFFFF);
        patch_one(mmu, base, u32::from(cur), addr_type, sel, off);
        if next == 0xFFFF {
            break;
        }
        cur = next;
    }
}

/// Write a single fixup value at `base + loc` per its address type.
fn patch_one(mmu: &mut Mmu, base: u32, loc: u32, addr_type: u8, sel: u16, off: u16) {
    let at = base.wrapping_add(loc);
    match addr_type {
        RT_FAR_PTR => {
            let _ = mmu.store16(at, off);
            let _ = mmu.store16(at.wrapping_add(2), sel);
        }
        RT_SEGMENT => {
            let _ = mmu.store16(at, sel);
        }
        RT_OFFSET => {
            let _ = mmu.store16(at, off);
        }
        RT_OFFSET_LOBYTE => {
            let _ = mmu.store8(at, off as u8);
        }
        _ => {}
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

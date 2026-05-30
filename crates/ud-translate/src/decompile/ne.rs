//! Decompile a parsed [`NeFile`] into a `.ud` AST.
//!
//! v0 scope (matching the other formats' first cut): byte-identical
//! round-trip plus a Ghidra-style *readable* decode. The `@module`
//! header captures the structural metadata (NE header, segment /
//! entry / name / module tables) and informational `// …` listings
//! render the imports, exports and a per-segment 16-bit disassembly.
//! The authoritative round-trip carrier is a single
//! `@raw(0, [whole file])` item, so the listing can be as rich as we
//! like without ever endangering byte identity.
//!
//! Structured `if`/`switch`/`goto` lifting of the 16-bit segmented
//! code is deliberately out of scope here; that is the natural next
//! increment, the same way the PE/ELF paths grew from "skeleton +
//! raw" into structured lifts.
//!
//! `@module.format = "ne"` routes the lower path back to
//! [`crate::compile::lower_to_ne`].
//!
//! [`NeFile`]: ud_format::ne::NeFile

use ud_arch_x86::{decode_tolerant, format_intel, Bitness};
use ud_ast::{Field, Item, Module, UdFile, Value};
use ud_format::ne::{NeFile, NeName, NeSegment};

/// Build the AST for `ne`. Always succeeds — every byte of the input
/// is preserved by the trailing `@raw`, and the structured decode is
/// best-effort presentation on top.
#[must_use]
pub fn decompile_ne(ne: &NeFile) -> UdFile {
    let module = build_ne_module(ne);
    let items = build_ne_items(ne);
    UdFile { module, items }
}

/// Convenience: build the AST and pretty-print it to canonical text.
#[must_use]
pub fn decompile_ne_to_text(ne: &NeFile) -> String {
    ud_ast::emit(&decompile_ne(ne))
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.to_string(),
        value,
    }
}

/// `[u8]` → a `Value::List` of byte integers.
fn bytes_value(bytes: &[u8]) -> Value {
    Value::List(bytes.iter().map(|b| Value::Int(u64::from(*b))).collect())
}

#[allow(clippy::too_many_lines)]
fn build_ne_module(ne: &NeFile) -> Module {
    let h = &ne.header;

    let ne_header_block = Value::Block(vec![
        field("linker_ver", Value::Int(u64::from(h.linker_ver))),
        field("linker_rev", Value::Int(u64::from(h.linker_rev))),
        field("entry_table_off", Value::Int(u64::from(h.entry_table_off))),
        field("entry_table_len", Value::Int(u64::from(h.entry_table_len))),
        field("crc", Value::Int(u64::from(h.crc))),
        field("flags", Value::Int(u64::from(h.flags))),
        field("auto_data_seg", Value::Int(u64::from(h.auto_data_seg))),
        field("init_heap", Value::Int(u64::from(h.init_heap))),
        field("init_stack", Value::Int(u64::from(h.init_stack))),
        field("cs_ip", Value::Int(u64::from(h.cs_ip))),
        field("ss_sp", Value::Int(u64::from(h.ss_sp))),
        field("seg_count", Value::Int(u64::from(h.seg_count))),
        field(
            "module_ref_count",
            Value::Int(u64::from(h.module_ref_count)),
        ),
        field(
            "nonres_name_size",
            Value::Int(u64::from(h.nonres_name_size)),
        ),
        field("seg_table_off", Value::Int(u64::from(h.seg_table_off))),
        field(
            "resource_table_off",
            Value::Int(u64::from(h.resource_table_off)),
        ),
        field(
            "resident_name_off",
            Value::Int(u64::from(h.resident_name_off)),
        ),
        field("module_ref_off", Value::Int(u64::from(h.module_ref_off))),
        field(
            "imported_name_off",
            Value::Int(u64::from(h.imported_name_off)),
        ),
        field("nonres_name_off", Value::Int(u64::from(h.nonres_name_off))),
        field(
            "movable_entry_count",
            Value::Int(u64::from(h.movable_entry_count)),
        ),
        field("align_shift", Value::Int(u64::from(h.align_shift))),
        field(
            "resource_seg_count",
            Value::Int(u64::from(h.resource_seg_count)),
        ),
        field("target_os", Value::Int(u64::from(h.target_os))),
        field("other_flags", Value::Int(u64::from(h.other_flags))),
        field("fastload_off", Value::Int(u64::from(h.fastload_off))),
        field("fastload_len", Value::Int(u64::from(h.fastload_len))),
        field("min_swap", Value::Int(u64::from(h.min_swap))),
        field(
            "expected_win_ver",
            Value::Int(u64::from(h.expected_win_ver)),
        ),
    ]);

    let segments = Value::List(
        ne.segments
            .iter()
            .map(|s| {
                Value::Block(vec![
                    field("sector_offset", Value::Int(u64::from(s.sector_offset))),
                    field("length", Value::Int(u64::from(s.length))),
                    field("flags", Value::Int(u64::from(s.flags))),
                    field("min_alloc", Value::Int(u64::from(s.min_alloc))),
                ])
            })
            .collect(),
    );

    let name_list = |names: &[NeName]| {
        Value::List(
            names
                .iter()
                .map(|n| {
                    Value::Block(vec![
                        field("name", Value::String(n.name.clone())),
                        field("ordinal", Value::Int(u64::from(n.ordinal))),
                    ])
                })
                .collect(),
        )
    };

    let entries = Value::List(
        ne.entries
            .iter()
            .map(|e| {
                Value::Block(vec![
                    field("ordinal", Value::Int(u64::from(e.ordinal))),
                    field("segment", Value::Int(u64::from(e.segment))),
                    field("offset", Value::Int(u64::from(e.offset))),
                    field("flags", Value::Int(u64::from(e.flags))),
                    field("movable", Value::Int(u64::from(e.movable))),
                ])
            })
            .collect(),
    );

    let imported = Value::List(
        ne.imported_modules
            .iter()
            .map(|m| Value::String(m.clone()))
            .collect(),
    );

    let dos_stub = bytes_value(&ne.raw[ne.dos_stub.clone()]);

    let build = Value::Block(vec![
        field("e_lfanew", Value::Int(u64::from(ne.e_lfanew))),
        field("file_size", Value::Int(ne.raw.len() as u64)),
        field("dos_stub", dos_stub),
        field("ne_header", ne_header_block),
        field("segments", segments),
        field("entry_table", entries),
        field("resident_names", name_list(&ne.resident_names)),
        field("imported_modules", imported),
        field("nonresident_names", name_list(&ne.nonresident_names)),
    ]);

    Module {
        fields: vec![
            field("arch", Value::String("x86_16".to_string())),
            field("format", Value::String("ne".to_string())),
            field("bits", Value::Int(16)),
            field("endian", Value::String("little".to_string())),
            field("build", build),
        ],
    }
}

/// Informational `// …` listing items followed by the single
/// authoritative `@raw` covering the whole file.
fn build_ne_items(ne: &NeFile) -> Vec<Item> {
    let mut items = Vec::new();
    let h = &ne.header;

    items.push(Item::Comment(format!(
        "── NE module ── {} ({}) ──",
        ne.module_name().unwrap_or("?"),
        ne.module_description().unwrap_or("no description"),
    )));
    items.push(Item::Comment(format!(
        "target_os={} expected_windows={}.{} segments={} module_refs={}",
        os_name(h.target_os),
        h.expected_win_ver >> 8,
        h.expected_win_ver & 0xff,
        h.seg_count,
        h.module_ref_count,
    )));
    items.push(Item::Comment(format!(
        "entry CS:IP = seg{}:0x{:04x}   SS:SP = seg{}:0x{:04x}   auto_data_seg={}",
        h.cs_ip >> 16,
        h.cs_ip & 0xffff,
        h.ss_sp >> 16,
        h.ss_sp & 0xffff,
        h.auto_data_seg,
    )));

    // ── imported modules (DLL dependencies) ──
    if !ne.imported_modules.is_empty() {
        items.push(Item::Comment(
            "── imported modules ── (informational, not round-trip source)".into(),
        ));
        for (i, m) in ne.imported_modules.iter().enumerate() {
            items.push(Item::Comment(format!("  [{}] {m}", i + 1)));
        }
    }

    // ── exported entry points ──
    if !ne.entries.is_empty() {
        items.push(Item::Comment(
            "── entry table (exports) ── (informational, not round-trip source)".into(),
        ));
        for e in &ne.entries {
            let name = export_name(ne, e.ordinal);
            let kind = if e.movable { "movable" } else { "fixed" };
            let exported = if e.flags & 0x01 != 0 { " EXPORTED" } else { "" };
            items.push(Item::Comment(format!(
                "  @{:<3} seg{}:0x{:04x}  {kind}{exported}{}",
                e.ordinal,
                e.segment,
                e.offset,
                name.map(|n| format!("  {n}")).unwrap_or_default(),
            )));
        }
    }

    // ── per-segment summary + 16-bit disassembly of code segments ──
    for (i, seg) in ne.segments.iter().enumerate() {
        let segno = i + 1;
        let kind = if seg.is_data() { "DATA" } else { "CODE" };
        let file_off = seg.file_offset(h);
        items.push(Item::Comment(format!(
            "── segment {segno} ── {kind}  file@{}  len=0x{:x}  flags=0x{:04x}{} ──",
            file_off.map_or("(none)".to_string(), |o| format!("0x{o:x}")),
            seg.data_len(),
            seg.flags,
            if seg.has_relocations() {
                " +relocs"
            } else {
                ""
            },
        )));
        if !seg.is_data() {
            items.extend(disassemble_segment(ne, seg, segno));
        }
    }

    // Authoritative byte carrier: the entire file, verbatim. Every
    // listing item above is a comment and contributes no bytes, so
    // this single `@raw` is the whole coverage the lower path needs.
    items.push(Item::Raw {
        addr: 0,
        bytes: ne.raw.clone(),
    });

    items
}

/// Emit a 16-bit disassembly listing for one code segment. Offsets
/// are segment-relative (NE code is segment:offset, and the segment
/// base is not known until load time), so the listing column shows
/// the offset within the segment.
fn disassemble_segment(ne: &NeFile, seg: &NeSegment, segno: usize) -> Vec<Item> {
    let Some(file_off) = seg.file_offset(&ne.header) else {
        return Vec::new();
    };
    let start = file_off as usize;
    let end = start
        .saturating_add(seg.data_len() as usize)
        .min(ne.raw.len());
    if start >= end {
        return Vec::new();
    }
    let code = &ne.raw[start..end];

    let mut out = Vec::new();
    out.push(Item::Comment(format!(
        "  disassembly of segment {segno} ({} bytes, 16-bit) — informational, not round-trip source",
        code.len(),
    )));
    for insn in decode_tolerant(Bitness::Bits16, code, 0) {
        let hex = insn
            .original_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let text = format_intel(&insn.iced);
        out.push(Item::Comment(format!(
            "  {segno:02}:{:04x}  {hex:<24}  {text}",
            insn.iced.ip(),
        )));
    }
    out
}

/// Resolve an export ordinal to a name by scanning the resident then
/// non-resident name tables (ordinal 0 entries are the module
/// name/description, not exports).
fn export_name(ne: &NeFile, ordinal: u16) -> Option<&str> {
    ne.resident_names
        .iter()
        .chain(ne.nonresident_names.iter())
        .find(|n| n.ordinal == ordinal && n.ordinal != 0)
        .map(|n| n.name.as_str())
}

fn os_name(os: u8) -> &'static str {
    match os {
        1 => "OS/2",
        2 => "Windows",
        3 => "European MS-DOS 4.x",
        4 => "Windows 386",
        5 => "BOSS",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny NE with one 16-bit code segment (`xor ax,ax; ret`).
    fn tiny_ne() -> Vec<u8> {
        let mut out = vec![0u8; 0x40];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3c] = 0x40; // e_lfanew
        let mut ne = vec![0u8; 0x40];
        ne[0] = b'N';
        ne[1] = b'E';
        let put_w = |ne: &mut [u8], off: usize, v: u16| {
            ne[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put_w(&mut ne, 0x1c, 1); // seg_count
        put_w(&mut ne, 0x22, 0x40); // seg_table_off -> file 0x80
        put_w(&mut ne, 0x32, 4); // align_shift -> 16-byte units
        out.extend_from_slice(&ne); // 0x40..0x80
                                    // segment table entry (8 bytes) at 0x80
        let seg_code = [0x33u8, 0xc0, 0xc3]; // xor ax,ax ; ret
        let seg_data_off = 0xC0usize;
        let mut seg = vec![0u8; 8];
        seg[0..2].copy_from_slice(&((seg_data_off as u16) >> 4).to_le_bytes());
        seg[2..4].copy_from_slice(&(seg_code.len() as u16).to_le_bytes());
        out.extend_from_slice(&seg);
        out.resize(seg_data_off, 0);
        out.extend_from_slice(&seg_code);
        out
    }

    /// A code segment with `xor ax,ax ; ret` should produce a
    /// disassembly comment containing the lifted mnemonics, and the
    /// module block should advertise format "ne".
    #[test]
    fn decompiles_synthetic_ne_with_disasm() {
        let bytes = tiny_ne();
        let ne = NeFile::parse(&bytes).expect("parse");
        let text = decompile_ne_to_text(&ne);
        assert!(text.contains("format: \"ne\""));
        assert!(text.contains("arch: \"x86_16\""));
        assert!(text.contains("segment 1"));
        assert!(text.to_lowercase().contains("xor"));
        assert!(text.contains("@raw(0x0,"));
    }
}

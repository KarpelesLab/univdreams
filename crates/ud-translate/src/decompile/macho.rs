//! Decompile a parsed [`MachoFile`] into a `.ud` AST.
//!
//! v1 scope: byte-faithful skeleton. The emitted AST captures the
//! Mach-O header + load-command table + interstitial padding in
//! `@module`, then dumps each non-empty segment's file bytes as a
//! top-level `@raw(file_offset, [bytes])`. Function lift is
//! deferred — the section-by-section approach the ELF decompile
//! grew came after the format crate had round-trip byte parity;
//! we follow the same staging here.
//!
//! `@module.format = "macho"` distinguishes the lower path from
//! ELF / PE so the same `.ud` file can hold any format and the
//! compiler routes correctly.
//!
//! [`MachoFile`]: ud_format_macho::MachoFile

use ud_ast::{Field, Item, Module, UdFile, Value};
use ud_format_macho::{
    is_dylib_cmd, is_linkedit_data_cmd, LcBuildVersion, LcDylib, LcDylinker, LcDysymtab,
    LcLinkeditData, LcMain, LcSourceVersion, LcSymtab, LcUuid, LoadCommand, MachoCpu, MachoFile,
    Section64, Segment64, LC_BUILD_VERSION, LC_DYSYMTAB, LC_LOAD_DYLINKER, LC_MAIN, LC_SEGMENT_64,
    LC_SOURCE_VERSION, LC_SYMTAB, LC_UUID,
};

/// Build the AST for `macho`. Always succeeds — every byte of
/// the input is captured either via `@module` structured fields
/// or via per-segment `@raw` blocks.
#[must_use]
pub fn decompile_macho(macho: &MachoFile) -> UdFile {
    let module = build_macho_module(macho);
    let symbol_index = collect_symbol_index(macho);
    let mut items = build_macho_symbol_comments(macho, &symbol_index);
    items.extend(build_macho_disassembly_comments(macho, &symbol_index));
    items.extend(build_macho_items(macho));
    UdFile { module, items }
}

/// Convenience: build the AST and pretty-print it to canonical text.
#[must_use]
pub fn decompile_macho_to_text(macho: &MachoFile) -> String {
    ud_ast::emit(&decompile_macho(macho))
}

fn build_macho_module(macho: &MachoFile) -> Module {
    let arch = match macho.cpu() {
        Some(MachoCpu::X86_64) => "x86_64",
        Some(MachoCpu::Arm64) => "aarch64",
        None => "unknown",
    };

    // Header sub-block, mirroring Apple's `mach_header_64`.
    let header_block = Value::Block(vec![
        field("magic", Value::Int(u64::from(macho.header.magic))),
        field("cputype", Value::Int(u64::from(macho.header.cputype))),
        field("cpusubtype", Value::Int(u64::from(macho.header.cpusubtype))),
        field("filetype", Value::Int(u64::from(macho.header.filetype))),
        field("ncmds", Value::Int(u64::from(macho.header.ncmds))),
        field("sizeofcmds", Value::Int(u64::from(macho.header.sizeofcmds))),
        field("flags", Value::Int(u64::from(macho.header.flags))),
        field("reserved", Value::Int(u64::from(macho.header.reserved))),
    ]);

    // Load-command table. Each command gets either a structured
    // sub-block whose fields name the meaningful parts (segments,
    // symbol table, entry point, dylib references, build version,
    // …) or, for cmd kinds we don't decode yet, the opaque
    // `body: [bytes]` carrying the original bytes verbatim. The
    // structured form re-serializes byte-identically on the lower
    // side, so swap-in is round-trip safe.
    let segments_by_idx: std::collections::BTreeMap<usize, Segment64> = macho
        .segments()
        .into_iter()
        .map(|s| (s.cmd_index, s))
        .collect();
    let commands_value = Value::List(
        macho
            .commands
            .iter()
            .enumerate()
            .map(|(idx, cmd)| command_block(cmd, idx, &segments_by_idx))
            .collect(),
    );

    // Padding stays as `{ offset, bytes }` blocks, same shape ELF
    // and PE use. All-zero padding could be elided here later
    // (matching the ELF optimisation), but for v1 we keep every
    // gap explicit so round-trip is unconditionally safe.
    let padding_value = Value::List(
        macho
            .padding()
            .iter()
            .map(|(offset, bytes)| {
                Value::Block(vec![
                    field("offset", Value::Int(*offset)),
                    field("bytes", byte_list(bytes)),
                ])
            })
            .collect(),
    );

    let build_block = Value::Block(vec![
        field("header", header_block),
        field("commands", commands_value),
        field("padding", padding_value),
        field("file_size", Value::Int(macho.file_size())),
    ]);

    Module {
        fields: vec![
            field("arch", Value::String(arch.into())),
            field("abi", Value::String("macho".into())),
            field("format", Value::String("macho".into())),
            field("bits", Value::Int(64)),
            field("endian", Value::String("little".into())),
            field("type", Value::Int(u64::from(macho.header.filetype))),
            field("build", build_block),
        ],
    }
}

/// One top-level `@raw(fileoff, [bytes])` per non-empty
/// `LC_SEGMENT_64`. Emitted in fileoff order so the parser can
/// drop each chunk straight into a `vec![0u8; file_size]` buffer
/// at its declared offset. The bytes overlap with the header +
/// load-command table for the leading `__TEXT` segment of an
/// executable — the lower path handles that the same way the
/// parser-side `MachoFile::write_to_vec` does (segments first,
/// then header / cmds / padding overlay).
/// A parsed `LC_SYMTAB` entry, materialised for use by both the
/// symbol-listing comments and the disassembly-arrow annotator.
#[derive(Debug, Clone)]
struct MachoSymbol {
    name: String,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

/// Decode `LC_SYMTAB` once; returns the symbol vector + the
/// resolved string table so multiple downstream emitters can
/// share the work.
fn collect_symbol_index(macho: &MachoFile) -> Vec<MachoSymbol> {
    let Some(symtab_cmd) = macho.commands.iter().find(|c| c.cmd == LC_SYMTAB) else {
        return Vec::new();
    };
    let Some(symtab) = LcSymtab::decode(&symtab_cmd.body) else {
        return Vec::new();
    };
    if symtab.nsyms == 0 {
        return Vec::new();
    }
    let file_view = macho.write_to_vec();
    let n = symtab.nsyms as usize;
    let sym_start = symtab.symoff as usize;
    let sym_end = sym_start.saturating_add(n.saturating_mul(16));
    let str_start = symtab.stroff as usize;
    let str_end = str_start.saturating_add(symtab.strsize as usize);
    if sym_end > file_view.len() || str_end > file_view.len() {
        return Vec::new();
    }
    let sym_bytes = &file_view[sym_start..sym_end];
    let str_bytes = &file_view[str_start..str_end];
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = i * 16;
        let n_strx = u32::from_le_bytes(sym_bytes[off..off + 4].try_into().unwrap());
        let n_type = sym_bytes[off + 4];
        let n_sect = sym_bytes[off + 5];
        let n_desc = u16::from_le_bytes(sym_bytes[off + 6..off + 8].try_into().unwrap());
        let n_value = u64::from_le_bytes(sym_bytes[off + 8..off + 16].try_into().unwrap());
        let name = read_strtab_name(str_bytes, n_strx as usize);
        out.push(MachoSymbol {
            name,
            n_type,
            n_sect,
            n_desc,
            n_value,
        });
    }
    out
}

/// Emit one `@comment` per symbol at the top of the items list —
/// the Ghidra-equivalent "Symbol Table" / "Function Manager"
/// pane in a single readable header. Read-only annotation:
/// source-of-truth bytes still live in the surrounding `@raw`
/// for `__LINKEDIT`.
fn build_macho_symbol_comments(_macho: &MachoFile, symbols: &[MachoSymbol]) -> Vec<Item> {
    if symbols.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::with_capacity(symbols.len() + 1);
    lines.push(Item::Comment(
        "── symbols ── (decoded from LC_SYMTAB; informational, not round-trip source)".into(),
    ));
    for s in symbols {
        lines.push(Item::Comment(format_symbol_line(
            &s.name, s.n_type, s.n_sect, s.n_desc, s.n_value,
        )));
    }
    lines
}

/// Locate `__text` (typically inside `__TEXT`), disassemble its
/// bytes with the architecture's decoder, and emit one
/// `@comment` per instruction. Each row carries `addr  hex
/// bytes  mnemonic`, mirroring Ghidra's Listing view. Branch /
/// call targets are annotated with the resolved symbol name
/// where known.
fn build_macho_disassembly_comments(macho: &MachoFile, symbols: &[MachoSymbol]) -> Vec<Item> {
    let Some(cpu) = macho.cpu() else {
        return Vec::new();
    };
    // Map vmaddr → symbol name for branch-target annotation.
    let mut addr_to_name: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for s in symbols {
        // Only defined-in-section, externally-visible symbols
        // make useful branch labels; undefined imports point at
        // address 0 and would clobber the map.
        if (s.n_type & 0x0e) == 0x0e && s.n_sect != 0 {
            addr_to_name.entry(s.n_value).or_insert(s.name.clone());
        }
    }

    // Find __text + its enclosing segment.
    let segments = macho.segments();
    let mut text: Option<(Segment64, Section64)> = None;
    for seg in &segments {
        for sec in &seg.sections {
            if cstr16(&sec.sectname) == "__text" {
                text = Some((seg.clone(), sec.clone()));
                break;
            }
        }
        if text.is_some() {
            break;
        }
    }
    let Some((seg, sec)) = text else {
        return Vec::new();
    };
    if sec.size == 0 {
        return Vec::new();
    }

    // segment_data is indexed in parallel with the LC_SEGMENT_64
    // command list; locate by matching cmd_index.
    let seg_indices = macho.segment_command_indices();
    let seg_data = macho.segment_data();
    let mut seg_data_idx: Option<usize> = None;
    for (i, &ci) in seg_indices.iter().enumerate() {
        if ci == seg.cmd_index {
            seg_data_idx = Some(i);
            break;
        }
    }
    let Some(data_idx) = seg_data_idx else {
        return Vec::new();
    };
    let data = &seg_data[data_idx];
    let Some(rel) = u64::from(sec.offset).checked_sub(seg.fileoff) else {
        return Vec::new();
    };
    let lo = rel as usize;
    let hi = lo.saturating_add(sec.size as usize);
    if hi > data.len() {
        return Vec::new();
    }
    let text_bytes = &data[lo..hi];

    let mut lines = Vec::new();
    lines.push(Item::Comment(format!(
        "── disassembly of __text @ 0x{:x} ({} bytes) ── (informational, not round-trip source)",
        sec.addr, sec.size,
    )));

    let rows: Vec<(u64, Vec<u8>, String)> = match cpu {
        MachoCpu::X86_64 => disasm_x86_rows(text_bytes, sec.addr),
        MachoCpu::Arm64 => disasm_aarch64_rows(text_bytes, sec.addr),
    };
    for (addr, bytes, mnemonic) in rows {
        let hex = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let target_annot = branch_target_annotation(&mnemonic, &addr_to_name);
        lines.push(Item::Comment(format!(
            "0x{addr:016x}  {hex:<24}  {mnemonic}{target_annot}"
        )));
    }
    lines
}

fn cstr16(buf: &[u8; 16]) -> String {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul]).into_owned()
}

fn disasm_x86_rows(bytes: &[u8], addr: u64) -> Vec<(u64, Vec<u8>, String)> {
    let insns = ud_arch_x86::decode_tolerant(ud_arch_x86::Bitness::Bits64, bytes, addr);
    insns
        .into_iter()
        .map(|insn| {
            let text = ud_arch_x86::format_intel(&insn.iced);
            (insn.iced.ip(), insn.original_bytes.clone(), text)
        })
        .collect()
}

fn disasm_aarch64_rows(bytes: &[u8], addr: u64) -> Vec<(u64, Vec<u8>, String)> {
    let Ok(insns) = ud_arch_aarch64::decode(bytes, addr) else {
        return Vec::new();
    };
    insns
        .into_iter()
        .map(|insn| {
            let text = ud_arch_aarch64::format_text(&insn);
            (insn.addr.0, insn.bytes.to_vec(), text)
        })
        .collect()
}

/// Try to extract a `0x...` immediate from a branch/call mnemonic
/// and look it up in the symbol map. Keeps disassembly lines
/// readable when the user wants to know "what's at this jmp
/// target."
fn branch_target_annotation(
    mnemonic: &str,
    addr_to_name: &std::collections::HashMap<u64, String>,
) -> String {
    if !is_branch_mnemonic(mnemonic) {
        return String::new();
    }
    // The Intel formatter renders branch targets as `0x<hex>`.
    let Some(start) = mnemonic.find("0x") else {
        return String::new();
    };
    let tail = &mnemonic[start + 2..];
    let hex_end = tail
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(tail.len());
    if hex_end == 0 {
        return String::new();
    }
    let Ok(target) = u64::from_str_radix(&tail[..hex_end], 16) else {
        return String::new();
    };
    addr_to_name
        .get(&target)
        .map(|name| format!("  → {name}"))
        .unwrap_or_default()
}

fn is_branch_mnemonic(mnemonic: &str) -> bool {
    let head = mnemonic.split_whitespace().next().unwrap_or("");
    matches!(
        head,
        "call"
            | "jmp"
            | "je"
            | "jne"
            | "jg"
            | "jge"
            | "jl"
            | "jle"
            | "ja"
            | "jae"
            | "jb"
            | "jbe"
            | "jo"
            | "jno"
            | "js"
            | "jns"
            | "jp"
            | "jnp"
            | "jz"
            | "jnz"
            | "bl"
            | "b"
            | "b.eq"
            | "b.ne"
            | "b.lt"
            | "b.le"
            | "b.gt"
            | "b.ge"
            | "cbz"
            | "cbnz"
            | "tbz"
            | "tbnz"
    )
}

/// Slice a NUL-terminated C string out of the string table.
/// Returns `"<bad strx>"` for out-of-bounds indices so the
/// listing stays readable even on malformed inputs.
fn read_strtab_name(str_bytes: &[u8], strx: usize) -> String {
    if strx >= str_bytes.len() {
        return "<bad strx>".into();
    }
    let tail = &str_bytes[strx..];
    let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..nul]).into_owned()
}

/// Format one `nlist_64` row as a human-readable line:
/// `0x000000010000_3f70  T  EXT  _main       (sect 1)`.
/// Mirrors the columns Ghidra surfaces in its Symbol Table view.
fn format_symbol_line(name: &str, n_type: u8, n_sect: u8, n_desc: u16, n_value: u64) -> String {
    const N_STAB: u8 = 0xe0;
    const N_PEXT: u8 = 0x10;
    const N_TYPE: u8 = 0x0e;
    const N_EXT: u8 = 0x01;
    const N_UNDF: u8 = 0x0;
    const N_ABS: u8 = 0x2;
    const N_SECT: u8 = 0xe;
    const N_PBUD: u8 = 0xc;
    const N_INDR: u8 = 0xa;

    let kind = if n_type & N_STAB != 0 {
        "STAB"
    } else {
        match n_type & N_TYPE {
            N_UNDF => "UNDF",
            N_ABS => "ABS",
            N_SECT => "SECT",
            N_PBUD => "PBUD",
            N_INDR => "INDR",
            _ => "????",
        }
    };
    let mut flags = String::new();
    if n_type & N_EXT != 0 {
        flags.push_str(" EXT");
    }
    if n_type & N_PEXT != 0 {
        flags.push_str(" PEXT");
    }
    let display_name = if name.is_empty() {
        "<anon>".into()
    } else {
        name.to_string()
    };
    format!(
        "0x{n_value:016x}  {kind:4}{flags:<10}  sect={n_sect:<2} desc=0x{n_desc:04x}  {display_name}",
    )
}

fn build_macho_items(macho: &MachoFile) -> Vec<Item> {
    // `segments()` returns segments in the same order as
    // `segment_data()`, with `cmd_index` pointing back to the
    // matching `LC_SEGMENT_64` command. The two iterators line
    // up element-for-element, so we can zip without indexing.
    let segments = macho.segments();
    let mut entries: Vec<(u64, Vec<u8>)> = Vec::new();
    for (seg, data) in segments.iter().zip(macho.segment_data().iter()) {
        if data.is_empty() {
            continue;
        }
        entries.push((seg.fileoff, data.clone()));
    }
    entries.sort_by_key(|(offset, _)| *offset);
    entries
        .into_iter()
        .map(|(addr, bytes)| Item::Raw { addr, bytes })
        .collect()
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

fn byte_list(bytes: &[u8]) -> Value {
    Value::List(bytes.iter().map(|b| Value::Int(u64::from(*b))).collect())
}

/// Structurally emit an `LC_SEGMENT_64` body: segment header +
/// section list. The number of sections is derivable from
/// `sections.len()` on the lower side, so `nsects` is not emitted
/// separately.
fn segment_block(seg: &Segment64) -> Value {
    let sections = Value::List(seg.sections.iter().map(section_block).collect());
    Value::Block(vec![
        field("name", name_field(&seg.segname)),
        field("vmaddr", Value::Int(seg.vmaddr)),
        field("vmsize", Value::Int(seg.vmsize)),
        field("fileoff", Value::Int(seg.fileoff)),
        field("filesize", Value::Int(seg.filesize)),
        field("maxprot", Value::Int(u64::from(seg.maxprot))),
        field("initprot", Value::Int(u64::from(seg.initprot))),
        field("flags", Value::Int(u64::from(seg.flags))),
        field("sections", sections),
    ])
}

fn section_block(s: &Section64) -> Value {
    Value::Block(vec![
        field("name", name_field(&s.sectname)),
        field("segment", name_field(&s.segname)),
        field("addr", Value::Int(s.addr)),
        field("size", Value::Int(s.size)),
        field("offset", Value::Int(u64::from(s.offset))),
        field("align", Value::Int(u64::from(s.align))),
        field("reloff", Value::Int(u64::from(s.reloff))),
        field("nreloc", Value::Int(u64::from(s.nreloc))),
        field("flags", Value::Int(u64::from(s.flags))),
        field("reserved1", Value::Int(u64::from(s.reserved1))),
        field("reserved2", Value::Int(u64::from(s.reserved2))),
        field("reserved3", Value::Int(u64::from(s.reserved3))),
    ])
}

/// Build one entry in `@module.build.commands`. Picks the
/// structured branch for command kinds with a known body layout;
/// falls back to opaque `body: [bytes]` otherwise. The
/// structured branch is gated on encode/decode round-tripping the
/// exact original bytes so byte-identity is never silently lost.
fn command_block(
    cmd: &LoadCommand,
    idx: usize,
    segments_by_idx: &std::collections::BTreeMap<usize, Segment64>,
) -> Value {
    let mut fields = vec![
        field("cmd", Value::Int(u64::from(cmd.cmd))),
        field("cmdsize", Value::Int(u64::from(cmd.cmdsize))),
    ];

    let structured = decode_structured(cmd, idx, segments_by_idx);
    if let Some((name, value)) = structured {
        fields.push(field(name, value));
    } else {
        fields.push(field("body", byte_list(&cmd.body)));
    }
    Value::Block(fields)
}

/// Try every structural decoder relevant to this command's `cmd`
/// value. Each decoder must produce bytes byte-equal to the
/// original body via its own encoder, or we fall through to
/// opaque — that way `parse → emit → parse → lower` is
/// guaranteed to recover the same bytes no matter which branch
/// the AST took.
fn decode_structured(
    cmd: &LoadCommand,
    idx: usize,
    segments_by_idx: &std::collections::BTreeMap<usize, Segment64>,
) -> Option<(&'static str, Value)> {
    match cmd.cmd {
        LC_SEGMENT_64 => {
            let seg = segments_by_idx.get(&idx)?;
            if seg.write_to_body() == cmd.body {
                Some(("segment", segment_block(seg)))
            } else {
                None
            }
        }
        LC_SYMTAB => {
            let s = LcSymtab::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("symtab", symtab_block(&s)))
            } else {
                None
            }
        }
        LC_DYSYMTAB => {
            let s = LcDysymtab::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("dysymtab", dysymtab_block(&s)))
            } else {
                None
            }
        }
        LC_LOAD_DYLINKER => {
            let s = LcDylinker::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("dylinker", dylinker_block(&s)))
            } else {
                None
            }
        }
        LC_UUID => {
            let s = LcUuid::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("uuid", Value::String(format_uuid(&s.0))))
            } else {
                None
            }
        }
        LC_BUILD_VERSION => {
            let s = LcBuildVersion::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("build_version", build_version_block(&s)))
            } else {
                None
            }
        }
        LC_SOURCE_VERSION => {
            let s = LcSourceVersion::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("source_version", Value::Int(s.0)))
            } else {
                None
            }
        }
        LC_MAIN => {
            let s = LcMain::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("main", main_block(&s)))
            } else {
                None
            }
        }
        c if is_dylib_cmd(c) => {
            let s = LcDylib::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("dylib", dylib_block(&s)))
            } else {
                None
            }
        }
        c if is_linkedit_data_cmd(c) => {
            let s = LcLinkeditData::decode(&cmd.body)?;
            if s.encode() == cmd.body {
                Some(("linkedit_data", linkedit_data_block(s)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn symtab_block(s: &LcSymtab) -> Value {
    Value::Block(vec![
        field("symoff", Value::Int(u64::from(s.symoff))),
        field("nsyms", Value::Int(u64::from(s.nsyms))),
        field("stroff", Value::Int(u64::from(s.stroff))),
        field("strsize", Value::Int(u64::from(s.strsize))),
    ])
}

fn dysymtab_block(s: &LcDysymtab) -> Value {
    Value::Block(vec![
        field("ilocalsym", Value::Int(u64::from(s.ilocalsym))),
        field("nlocalsym", Value::Int(u64::from(s.nlocalsym))),
        field("iextdefsym", Value::Int(u64::from(s.iextdefsym))),
        field("nextdefsym", Value::Int(u64::from(s.nextdefsym))),
        field("iundefsym", Value::Int(u64::from(s.iundefsym))),
        field("nundefsym", Value::Int(u64::from(s.nundefsym))),
        field("tocoff", Value::Int(u64::from(s.tocoff))),
        field("ntoc", Value::Int(u64::from(s.ntoc))),
        field("modtaboff", Value::Int(u64::from(s.modtaboff))),
        field("nmodtab", Value::Int(u64::from(s.nmodtab))),
        field("extrefsymoff", Value::Int(u64::from(s.extrefsymoff))),
        field("nextrefsyms", Value::Int(u64::from(s.nextrefsyms))),
        field("indirectsymoff", Value::Int(u64::from(s.indirectsymoff))),
        field("nindirectsyms", Value::Int(u64::from(s.nindirectsyms))),
        field("extreloff", Value::Int(u64::from(s.extreloff))),
        field("nextrel", Value::Int(u64::from(s.nextrel))),
        field("locreloff", Value::Int(u64::from(s.locreloff))),
        field("nlocrel", Value::Int(u64::from(s.nlocrel))),
    ])
}

fn dylinker_block(s: &LcDylinker) -> Value {
    let mut fields = vec![
        field("offset", Value::Int(u64::from(s.offset))),
        field("name", c_string_field(&s.name)),
    ];
    if !s.tail_padding.is_empty() {
        fields.push(field("tail_padding", byte_list(&s.tail_padding)));
    }
    Value::Block(fields)
}

fn dylib_block(s: &LcDylib) -> Value {
    let mut fields = vec![
        field("name", c_string_field(&s.name)),
        field("offset", Value::Int(u64::from(s.offset))),
        field("timestamp", Value::Int(u64::from(s.timestamp))),
        field("current_version", Value::Int(u64::from(s.current_version))),
        field(
            "compatibility_version",
            Value::Int(u64::from(s.compatibility_version)),
        ),
    ];
    if !s.tail_padding.is_empty() {
        fields.push(field("tail_padding", byte_list(&s.tail_padding)));
    }
    Value::Block(fields)
}

fn build_version_block(s: &LcBuildVersion) -> Value {
    let tools = Value::List(
        s.tools
            .iter()
            .map(|t| {
                Value::Block(vec![
                    field("tool", Value::Int(u64::from(t.tool))),
                    field("version", Value::Int(u64::from(t.version))),
                ])
            })
            .collect(),
    );
    Value::Block(vec![
        field("platform", Value::Int(u64::from(s.platform))),
        field("minos", Value::Int(u64::from(s.minos))),
        field("sdk", Value::Int(u64::from(s.sdk))),
        field("tools", tools),
    ])
}

fn main_block(s: &LcMain) -> Value {
    Value::Block(vec![
        field("entryoff", Value::Int(s.entryoff)),
        field("stacksize", Value::Int(s.stacksize)),
    ])
}

fn linkedit_data_block(s: LcLinkeditData) -> Value {
    Value::Block(vec![
        field("dataoff", Value::Int(u64::from(s.dataoff))),
        field("datasize", Value::Int(u64::from(s.datasize))),
    ])
}

/// Format a 16-byte UUID as the canonical 8-4-4-4-12 hex string.
fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11],
        uuid[12], uuid[13], uuid[14], uuid[15],
    )
}

/// Emit a NUL-trimmed C-string as a `Value::String` when the
/// bytes are valid UTF-8, otherwise fall back to a raw byte list.
fn c_string_field(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) => Value::String(s.into()),
        Err(_) => byte_list(bytes),
    }
}

/// Render a `char[16]` Mach-O name buffer as a readable string
/// when it's safely zero-padded ASCII; otherwise fall back to a
/// raw 16-byte list so the round-trip stays byte-identical. Real
/// Mach-O segment / section names (`__TEXT`, `__text`,
/// `__cstring`, …) take the readable branch; the fallback only
/// fires for pathological inputs that wouldn't survive a string
/// representation anyway.
fn name_field(buf: &[u8; 16]) -> Value {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let head = &buf[..nul];
    let all_zero_after = buf[nul..].iter().all(|&b| b == 0);
    if all_zero_after && head.iter().all(u8::is_ascii) && !head.contains(&0) {
        let s = std::str::from_utf8(head).unwrap_or("");
        Value::String(s.into())
    } else {
        byte_list(buf)
    }
}

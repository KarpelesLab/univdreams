//! Decompile a parsed [`PeFile`] into a `.ud` AST.
//!
//! v0 scope: structural skeleton + raw bytes.
//!
//! The emitted AST captures enough PE metadata in `@module` for
//! [`ud_compile::lower_to_pe`](../../ud-compile/index.html) to
//! reconstruct the file byte-identically. The actual content is laid
//! out as a sequence of `@raw(file_offset, [bytes])` items in
//! file-offset order, covering every byte of the input. No
//! instruction decoding happens here — that's a later iteration's
//! work, mirroring how the ELF decompile path grew.
//!
//! `@module.format = "pe"` distinguishes the lower path from the
//! ELF case so the same `.ud` file can hold either format and the
//! compiler routes correctly.
//!
//! [`PeFile`]: ud_format_pe::PeFile
//! [`ud_compile::lower_to_pe`]: ../../ud-compile/index.html

use std::collections::HashMap;

use ud_arch_x86::{lift_function, Bitness};
use ud_ast::{Field, Item, Module, UdFile, Value};
use ud_format_pe::{
    CoffSymbol, PeExport, PeFile, PeKind, COFF_SYM_CLASS_EXTERNAL, COFF_SYM_CLASS_STATIC,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
};

use crate::build_function;

/// Build the AST for `pe`. Always succeeds — every byte of the input
/// is captured either via `@module` structured fields or via
/// per-region `@raw` blocks.
#[must_use]
pub fn decompile_pe(pe: &PeFile) -> UdFile {
    let module = build_pe_module(pe);
    let items = build_pe_items(pe);
    UdFile { module, items }
}

/// Convenience: build the AST and pretty-print it to canonical text.
#[must_use]
pub fn decompile_pe_to_text(pe: &PeFile) -> String {
    ud_ast::emit(&decompile_pe(pe))
}

fn build_pe_module(pe: &PeFile) -> Module {
    let arch = match pe.coff.machine {
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_AMD64 => "x86_64",
        _ => "unknown",
    };
    let bits = match pe.kind {
        PeKind::Pe32 => 32,
        PeKind::Pe32Plus => 64,
    };

    let coff_block = Value::Block(vec![
        field("machine", Value::Int(u64::from(pe.coff.machine))),
        field(
            "number_of_sections",
            Value::Int(u64::from(pe.coff.number_of_sections)),
        ),
        field(
            "time_date_stamp",
            Value::Int(u64::from(pe.coff.time_date_stamp)),
        ),
        field(
            "pointer_to_symbol_table",
            Value::Int(u64::from(pe.coff.pointer_to_symbol_table)),
        ),
        field(
            "number_of_symbols",
            Value::Int(u64::from(pe.coff.number_of_symbols)),
        ),
        field(
            "size_of_optional_header",
            Value::Int(u64::from(pe.coff.size_of_optional_header)),
        ),
        field(
            "characteristics",
            Value::Int(u64::from(pe.coff.characteristics)),
        ),
    ]);

    let sections_value = Value::List(
        pe.sections
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let name = pe.section_name(i).unwrap_or_default().to_string();
                Value::Block(vec![
                    field("name", Value::String(name)),
                    field("name_raw", byte_list(&s.name)),
                    field("virtual_size", Value::Int(u64::from(s.virtual_size))),
                    field("virtual_address", Value::Int(u64::from(s.virtual_address))),
                    field(
                        "size_of_raw_data",
                        Value::Int(u64::from(s.size_of_raw_data)),
                    ),
                    field(
                        "pointer_to_raw_data",
                        Value::Int(u64::from(s.pointer_to_raw_data)),
                    ),
                    field(
                        "pointer_to_relocations",
                        Value::Int(u64::from(s.pointer_to_relocations)),
                    ),
                    field(
                        "pointer_to_linenumbers",
                        Value::Int(u64::from(s.pointer_to_linenumbers)),
                    ),
                    field(
                        "number_of_relocations",
                        Value::Int(u64::from(s.number_of_relocations)),
                    ),
                    field(
                        "number_of_linenumbers",
                        Value::Int(u64::from(s.number_of_linenumbers)),
                    ),
                    field("characteristics", Value::Int(u64::from(s.characteristics))),
                ])
            })
            .collect(),
    );

    let functions_value = Value::List(build_function_blocks(pe));

    let build = Value::Block(vec![
        field("e_lfanew", Value::Int(u64::from(pe.e_lfanew))),
        field("file_size", Value::Int(pe.file_size())),
        field("coff", coff_block),
        field("sections", sections_value),
        field("functions", functions_value),
    ]);

    Module {
        fields: vec![
            field("arch", Value::String(arch.into())),
            field("format", Value::String("pe".into())),
            field("bits", Value::Int(bits)),
            field("endian", Value::String("little".into())),
            field("build", build),
        ],
    }
}

/// Build the items list. Strategy: walk file-offset order, emit
/// `@raw` blocks for every contiguous byte range. Sections are
/// emitted as standalone `@raw` blocks (rather than nested under
/// `@section`) — the format lower path identifies them via the
/// section table in `@module.build.sections` rather than via
/// structural nesting.
///
/// Within a code section, the section's flat `@raw` is split by
/// COFF function boundaries: each detected function gets its own
/// `@raw` preceded by a `// fn <name> at 0x<rva>` comment.
/// Inter-function gaps (alignment, unknown content) get their own
/// `@raw` blocks. Round-trip is unchanged because the lower path
/// concatenates `@raw` blocks in offset order.
fn build_pe_items(pe: &PeFile) -> Vec<Item> {
    let bytes = pe.raw_bytes();
    let mut items: Vec<Item> = Vec::new();

    // Group functions by section index for fast lookup when we
    // emit each section's bytes.
    let funcs_by_section = group_functions_by_section(pe);

    // Collect structured byte regions in file-offset order. Each
    // region is `(start, end_exclusive, section_idx)`.
    let mut regions: Vec<(usize, usize, usize)> = Vec::new();
    for (idx, s) in pe.sections.iter().enumerate() {
        let start = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        if size == 0 {
            continue; // uninitialised data has no on-disk presence
        }
        let end = start.saturating_add(size);
        if end > bytes.len() {
            continue; // skip out-of-range section data
        }
        regions.push((start, end, idx));
    }
    regions.sort_unstable_by_key(|(start, _, _)| *start);

    let mut cursor = 0usize;
    for (start, end, sec_idx) in &regions {
        if *start > cursor {
            // Pre-section gap (DOS header, COFF, optional header,
            // section table, alignment). Stored as one big `@raw`.
            items.push(Item::Raw {
                addr: cursor as u64,
                bytes: bytes[cursor..*start].to_vec(),
            });
        }
        if let Some(funcs) = funcs_by_section.get(sec_idx) {
            emit_section_with_function_split(pe, *sec_idx, *start, *end, funcs, bytes, &mut items);
        } else {
            items.push(Item::Raw {
                addr: *start as u64,
                bytes: bytes[*start..*end].to_vec(),
            });
        }
        cursor = *end;
    }

    if cursor < bytes.len() {
        items.push(Item::Raw {
            addr: cursor as u64,
            bytes: bytes[cursor..].to_vec(),
        });
    }

    items
}

/// Function record local to this module: the COFF symbol's name plus
/// the function's offset within its section (the COFF symbol's
/// `value` field) and the RVA derived from the section's
/// `virtual_address`. We carry the RVA explicitly so the rendered
/// comment names the user-visible address rather than the file
/// offset.
struct PeFunctionRecord {
    name: String,
    section_offset: u32,
    rva: u32,
}

fn group_functions_by_section(
    pe: &PeFile,
) -> std::collections::HashMap<usize, Vec<PeFunctionRecord>> {
    let mut out: std::collections::HashMap<usize, Vec<PeFunctionRecord>> =
        std::collections::HashMap::new();
    for sym in pe.coff_symbols() {
        if !is_code_function(pe, &sym) {
            continue;
        }
        // is_code_function rejects section_number <= 0 already.
        #[allow(clippy::cast_sign_loss)]
        let idx = (sym.section_number - 1) as usize;
        let Some(sh) = pe.sections.get(idx) else {
            continue;
        };
        let rva = sh.virtual_address.wrapping_add(sym.value);
        out.entry(idx).or_default().push(PeFunctionRecord {
            name: sym.name,
            section_offset: sym.value,
            rva,
        });
    }
    // Supplement with optional-header entry point and Export
    // Address Table entries. This is the only function source for
    // stripped DLLs / EXEs.
    add_pe_entry_point(pe, &mut out);
    add_pe_exports(pe, &mut out);
    // Walk direct `call` instructions reachable from those entries
    // and treat every target as another function. Stripped PE has
    // no symbol table to lean on; the call graph is the only
    // remaining signal.
    add_pe_call_graph_targets(pe, &mut out);
    for v in out.values_mut() {
        v.sort_by_key(|f| f.section_offset);
        v.dedup_by(|a, b| a.section_offset == b.section_offset && a.name == b.name);
    }
    out
}

/// PE `IMAGE_FILE_DLL` characteristic bit (0x2000). When set, the
/// entry point names `DllMain`; otherwise it's a plain `_start` /
/// `EntryPoint`.
const IMAGE_FILE_DLL: u16 = 0x2000;

/// Locate the section containing `rva` and return `(section_idx,
/// rva - section.virtual_address)`. None if `rva` is in no section
/// (e.g. inside a NOBITS region or past the end of the image).
fn rva_to_section(pe: &PeFile, rva: u32) -> Option<(usize, u32)> {
    for (idx, sh) in pe.sections.iter().enumerate() {
        let start = sh.virtual_address;
        let size = sh.virtual_size.max(sh.size_of_raw_data);
        if let Some(end) = start.checked_add(size) {
            if rva >= start && rva < end {
                return Some((idx, rva - start));
            }
        }
    }
    None
}

fn add_pe_entry_point(
    pe: &PeFile,
    out: &mut std::collections::HashMap<usize, Vec<PeFunctionRecord>>,
) {
    let ep = pe.address_of_entry_point;
    if ep == 0 {
        return;
    }
    let Some((idx, off)) = rva_to_section(pe, ep) else {
        return;
    };
    let already = out.get(&idx).is_some_and(|v| v.iter().any(|f| f.rva == ep));
    if already {
        return;
    }
    let name = if pe.coff.characteristics & IMAGE_FILE_DLL != 0 {
        "DllMain".to_string()
    } else {
        "_start".to_string()
    };
    out.entry(idx).or_default().push(PeFunctionRecord {
        name,
        section_offset: off,
        rva: ep,
    });
}

fn add_pe_exports(pe: &PeFile, out: &mut std::collections::HashMap<usize, Vec<PeFunctionRecord>>) {
    for export in pe.exports() {
        let Some((idx, off)) = rva_to_section(pe, export.rva) else {
            continue;
        };
        let already = out
            .get(&idx)
            .is_some_and(|v| v.iter().any(|f| f.rva == export.rva));
        if already {
            continue;
        }
        let name = export_function_name(&export);
        out.entry(idx).or_default().push(PeFunctionRecord {
            name,
            section_offset: off,
            rva: export.rva,
        });
    }
}

/// Transitive call-graph walk for stripped PE: from every seed
/// already in `out`, decode linearly up to the next function-end
/// instruction (RET / unconditional jump) and record every direct
/// `call` target. Each discovered target becomes a new seed
/// (named `sub_<rva>`). Repeat until the worklist drains.
///
/// The walk only follows targets that land inside the same section
/// as the seed (typically `.text`), since cross-section targets
/// are usually imports or jump-table references rather than local
/// functions.
/// Cap per-function decode length so a function with no clear exit
/// (e.g. unreachable padding after a tail call) doesn't sweep the
/// whole section.
const MAX_FUNCTION_BYTES: usize = 65536;

fn add_pe_call_graph_targets(
    pe: &PeFile,
    out: &mut std::collections::HashMap<usize, Vec<PeFunctionRecord>>,
) {
    let bitness = match pe.coff.machine {
        IMAGE_FILE_MACHINE_I386 => Bitness::Bits32,
        IMAGE_FILE_MACHINE_AMD64 => Bitness::Bits64,
        _ => return,
    };

    // Track every RVA we've ever decided is a function so we don't
    // re-walk the same one (cycles via recursion would loop
    // otherwise). Seeded from whatever's already in `out`.
    let mut known: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut worklist: Vec<u32> = Vec::new();
    for fns in out.values() {
        for f in fns {
            if known.insert(f.rva) {
                worklist.push(f.rva);
            }
        }
    }

    let raw = pe.raw_bytes();
    while let Some(rva) = worklist.pop() {
        let Some((sec_idx, _)) = rva_to_section(pe, rva) else {
            continue;
        };
        let Some(sec) = pe.sections.get(sec_idx) else {
            continue;
        };
        let Some(start_off) = pe.rva_to_file_offset(rva) else {
            continue;
        };
        let sec_raw_end_rva = sec.virtual_address.saturating_add(sec.size_of_raw_data);
        let in_section = (sec_raw_end_rva.saturating_sub(rva)) as usize;
        let read_len = in_section.min(MAX_FUNCTION_BYTES);
        let slice = &raw[start_off..start_off.saturating_add(read_len).min(raw.len())];
        let insns = ud_arch_x86::decode_tolerant(bitness, slice, u64::from(rva));
        if insns.is_empty() {
            continue;
        }
        // Build the CFG. This is what tells us "every instruction
        // reachable from `rva`" — including paths past early
        // returns, follow-the-conditional-branch paths, etc.
        let Ok(lifted) = lift_function(format!("seed_{rva:x}"), &insns) else {
            continue;
        };
        for block in &lifted.blocks {
            for ins in &block.insns {
                let Some(target_u64) = ud_arch_x86::direct_call_target(&ins.iced) else {
                    continue;
                };
                // The decoder's IP was set to `rva` (an RVA),
                // not `image_base + rva`, so iced's computed call
                // target is already an RVA. Just narrow to u32.
                let Ok(target_rva) = u32::try_from(target_u64) else {
                    continue;
                };
                let Some((tgt_sec, tgt_off)) = rva_to_section(pe, target_rva) else {
                    continue;
                };
                if tgt_sec != sec_idx {
                    continue;
                }
                if known.insert(target_rva) {
                    out.entry(tgt_sec).or_default().push(PeFunctionRecord {
                        name: format!("sub_{target_rva:x}"),
                        section_offset: tgt_off,
                        rva: target_rva,
                    });
                    worklist.push(target_rva);
                }
            }
        }
    }
}

fn export_function_name(export: &PeExport) -> String {
    export
        .name
        .clone()
        .unwrap_or_else(|| format!("Ord_{}", export.ordinal))
}

/// Emit one section whose contents are split by COFF function
/// boundaries. Each function gets a leading `// fn <name> at <rva>`
/// comment followed by an `@raw` covering its bytes; pre/inter/post-
/// function gaps (alignment, unknown content) get their own `@raw`
/// blocks so the byte coverage stays exhaustive.
fn emit_section_with_function_split(
    pe: &PeFile,
    sec_idx: usize,
    start: usize,
    end: usize,
    funcs: &[PeFunctionRecord],
    bytes: &[u8],
    items: &mut Vec<Item>,
) {
    let _ = &pe.sections[sec_idx]; // bounds check; structural fields used via section_name below
    let section_size = (end - start) as u32;

    // Emit leading gap before the first function.
    let first_off = funcs
        .first()
        .map_or(section_size, |f| f.section_offset.min(section_size));
    if first_off > 0 {
        let lo = start;
        let hi = start + first_off as usize;
        items.push(Item::Raw {
            addr: lo as u64,
            bytes: bytes[lo..hi].to_vec(),
        });
    }

    let bitness = match pe.coff.machine {
        IMAGE_FILE_MACHINE_I386 => Some(Bitness::Bits32),
        IMAGE_FILE_MACHINE_AMD64 => Some(Bitness::Bits64),
        _ => None,
    };
    let name_at = pe_name_at(pe);
    for (i, f) in funcs.iter().enumerate() {
        let off = f.section_offset.min(section_size);
        let next_off = funcs
            .get(i + 1)
            .map_or(section_size, |n| n.section_offset.min(section_size));
        if next_off <= off {
            continue; // zero-size or stacked symbols
        }
        let lo = start + off as usize;
        let hi = start + next_off as usize;
        let func_bytes = &bytes[lo..hi];

        // Try to lift the function body. Returns the fn item plus
        // an optional trailing `@raw` covering bytes the decoder
        // couldn't reach (jump tables, padding, data-in-code).
        // Falls back to a per-function `@raw` block on hard
        // failures (zero decoded bytes, unsupported machine type,
        // CFG construction failure).
        if let Some(bn) = bitness {
            if let Some(emitted) =
                lift_pe_function(pe, &f.name, lo as u64, f.rva, bn, func_bytes, &name_at)
            {
                items.extend(emitted);
                continue;
            }
        }
        let section_name = pe.section_name(sec_idx).unwrap_or_default();
        items.push(Item::Comment(format!(
            "fn {} at {section_name}+0x{off:x} (rva 0x{:x}, {} bytes)",
            f.name,
            f.rva,
            hi - lo,
        )));
        items.push(Item::Raw {
            addr: lo as u64,
            bytes: func_bytes.to_vec(),
        });
    }

    // Emit trailing gap after the last function.
    let last_end = funcs.last().map_or(0u32, |f| {
        // The last function's end is the next-symbol boundary,
        // which the loop above used as `section_size`. So the
        // trailing gap is empty unless the last symbol's offset
        // was past section_size (defensive).
        let off = f.section_offset.min(section_size);
        off.max(section_size)
    });
    if (last_end as usize) < (end - start) {
        let lo = start + last_end as usize;
        items.push(Item::Raw {
            addr: lo as u64,
            bytes: bytes[lo..end].to_vec(),
        });
    }
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.to_string(),
        value,
    }
}

fn byte_list(bs: &[u8]) -> Value {
    Value::List(bs.iter().map(|b| Value::Int(u64::from(*b))).collect())
}

/// Build the `name_at: addr -> name` map that arch-x86's call-site
/// analyzer uses to render call targets. For PE we key by RVA: jcc
/// and call instruction operands carry RVAs after iced sets the IP
/// to the function's RVA.
fn pe_name_at(pe: &PeFile) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for sym in pe.coff_symbols() {
        if !is_code_function(pe, &sym) {
            continue;
        }
        // is_code_function rejects section_number <= 0
        #[allow(clippy::cast_sign_loss)]
        let idx = (sym.section_number - 1) as usize;
        let Some(sh) = pe.sections.get(idx) else {
            continue;
        };
        let rva = u64::from(sh.virtual_address.wrapping_add(sym.value));
        out.insert(rva, sym.name);
    }
    out
}

/// Decode + lift + build one PE function's body as a structured
/// `FnDecl`. Returns `None` on any decoder rejection so the caller
/// can fall back to a per-function `@raw` block.
/// Lift one PE function, tolerating a decoder failure mid-stream.
///
/// Returns a list of items: a `Function` for the bytes the decoder
/// could reach, followed by an `@raw` for the trailing bytes it
/// couldn't (jump tables embedded after a `ret`, alignment padding,
/// or true data-in-code). Returns `None` when there's nothing to
/// lift — empty decode result or a CFG construction failure.
fn lift_pe_function(
    pe: &PeFile,
    name: &str,
    file_offset: u64,
    rva: u32,
    bitness: Bitness,
    func_bytes: &[u8],
    name_at: &HashMap<u64, String>,
) -> Option<Vec<Item>> {
    let insns = ud_arch_x86::decode_tolerant(bitness, func_bytes, u64::from(rva));
    if insns.is_empty() {
        return None;
    }
    let consumed: usize = insns.iter().map(|i| i.original_bytes.len()).sum();
    let lifted = lift_function(name.to_string(), &insns).ok()?;
    let fn_decl = build_function::build_function(&lifted, None, name_at, pe);
    let mut out = Vec::with_capacity(2);
    out.push(Item::Function(ud_ast::FnDecl {
        addr: Some(file_offset),
        name: name.to_string(),
        signature: fn_decl.signature,
        body: fn_decl.body,
    }));
    if consumed < func_bytes.len() {
        out.push(Item::Raw {
            addr: file_offset + consumed as u64,
            bytes: func_bytes[consumed..].to_vec(),
        });
    }
    Some(out)
}

/// `.ud` identifiers must start with an alpha character or `_` and
/// can contain `.` after that; COFF section-marker symbols (`.text`,
/// `.data`, etc.) start with `.` and would not parse back as
/// identifiers if we surfaced them as `fn` blocks. Filter them out
/// here before they reach the decompile output.
fn is_emittable_function_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c == '.' || c.is_ascii_alphanumeric())
}

fn build_function_blocks(pe: &PeFile) -> Vec<Value> {
    pe.coff_symbols()
        .iter()
        .filter(|s| is_code_function(pe, s))
        .map(|s| {
            // section_number is 1-indexed and >0 here (filter rejects
            // ABS/DEBUG/UNDEF), so the i16 → usize cast is non-lossy.
            #[allow(clippy::cast_sign_loss)]
            let section_idx = (s.section_number - 1) as usize;
            let section_va = pe
                .sections
                .get(section_idx)
                .map_or(0u32, |sh| sh.virtual_address);
            let rva = section_va.wrapping_add(s.value);
            // Likewise the section_number fits in u16 once positive.
            #[allow(clippy::cast_sign_loss)]
            let section = s.section_number as u16;
            Value::Block(vec![
                field("name", Value::String(s.name.clone())),
                field("rva", Value::Int(u64::from(rva))),
                field("section", Value::Int(u64::from(section))),
                field("section_offset", Value::Int(u64::from(s.value))),
                field("storage_class", Value::Int(u64::from(s.storage_class))),
            ])
        })
        .collect()
}

/// True for COFF symbols that look like functions in code sections —
/// the candidates for later body lifting. Filters out absolute (`-1`),
/// debug (`-2`), and undefined (`0`) section numbers, plus
/// section-marker symbols whose name doesn't make a valid `.ud`
/// identifier (`.text`, `.data`, etc.).
fn is_code_function(pe: &PeFile, sym: &CoffSymbol) -> bool {
    if sym.section_number <= 0 {
        return false;
    }
    if !is_emittable_function_name(&sym.name) {
        return false;
    }
    // section_number > 0 here, so subtracting 1 stays non-negative
    // and the cast to usize is non-lossy.
    #[allow(clippy::cast_sign_loss)]
    let section_idx = (sym.section_number - 1) as usize;
    let Some(sh) = pe.sections.get(section_idx) else {
        return false;
    };
    // IMAGE_SCN_MEM_EXECUTE
    let is_executable = sh.characteristics & 0x2000_0000 != 0;
    if !is_executable {
        return false;
    }
    // Either the symbol's Type field marks it a function (DT_FCN
    // high nibble), or its storage class is EXTERNAL/STATIC and it
    // sits in a code section. mingw frequently leaves Type = 0 even
    // for entries it generated, so we accept both forms.
    if sym.is_function() {
        return true;
    }
    matches!(
        sym.storage_class,
        COFF_SYM_CLASS_EXTERNAL | COFF_SYM_CLASS_STATIC
    )
}

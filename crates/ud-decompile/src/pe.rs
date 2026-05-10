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

use ud_ast::{Field, Item, Module, UdFile, Value};
use ud_format_pe::{PeFile, PeKind, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386};

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
                let name = pe.section_name(i).unwrap_or_default();
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

    let build = Value::Block(vec![
        field("e_lfanew", Value::Int(u64::from(pe.e_lfanew))),
        field("file_size", Value::Int(pe.file_size())),
        field("coff", coff_block),
        field("sections", sections_value),
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
fn build_pe_items(pe: &PeFile) -> Vec<Item> {
    let bytes = pe.raw_bytes();
    let mut items: Vec<Item> = Vec::new();

    // Collect structured byte regions in file-offset order. Each
    // region is `(start, end_exclusive)` — `[start, end)`.
    let mut regions: Vec<(usize, usize)> = Vec::new();
    for s in &pe.sections {
        let start = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        if size == 0 {
            continue; // uninitialised data has no on-disk presence
        }
        let end = start.saturating_add(size);
        if end > bytes.len() {
            continue; // skip out-of-range section data
        }
        regions.push((start, end));
    }
    regions.sort_unstable();

    let mut cursor = 0usize;
    for (start, end) in &regions {
        if *start > cursor {
            // Pre-section gap (DOS header, COFF, optional header,
            // section table, alignment). Stored as one big `@raw`.
            items.push(Item::Raw {
                addr: cursor as u64,
                bytes: bytes[cursor..*start].to_vec(),
            });
        }
        // The section's bytes themselves.
        items.push(Item::Raw {
            addr: *start as u64,
            bytes: bytes[*start..*end].to_vec(),
        });
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

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.to_string(),
        value,
    }
}

fn byte_list(bs: &[u8]) -> Value {
    Value::List(bs.iter().map(|b| Value::Int(u64::from(*b))).collect())
}

//! Decompile a parsed [`WasmFile`] into a `.ud` AST.
//!
//! v1 scope: byte-faithful skeleton. The emitted AST captures
//! the WASM module's magic / version in `@module`, lists every
//! section with its id and a body-length annotation, and dumps
//! each section's bytes as a top-level `@raw(file_offset, [bytes])`
//! at the section's start position (id byte included).
//!
//! Round-trip is byte-identical via the `@raw` blocks: the
//! lower path concatenates them in order, producing the
//! original file.
//!
//! Section-aware rendering (decoding function bodies as `@asm`
//! lines, name section → symbol table, type section → function
//! signatures, …) is a future iteration. For v1 every byte
//! rides as opaque `@raw` so the round-trip is unconditional.
//!
//! [`WasmFile`]: ud_format::wasm::WasmFile

use ud_ast::{Field, Item, Module, UdFile, Value};
use ud_format::wasm::{Section, WasmFile};

/// Build the AST for `wasm`. Always succeeds — every byte of
/// the input is captured either as a `@module` field or via
/// the per-section `@raw` blocks.
#[must_use]
pub fn decompile_wasm(wasm: &WasmFile) -> UdFile {
    let module = build_wasm_module(wasm);
    let items = build_wasm_items(wasm);
    UdFile { module, items }
}

/// Convenience: build the AST and pretty-print it to canonical text.
#[must_use]
pub fn decompile_wasm_to_text(wasm: &WasmFile) -> String {
    ud_ast::emit(&decompile_wasm(wasm))
}

fn build_wasm_module(wasm: &WasmFile) -> Module {
    let sections_value = Value::List(
        wasm.sections
            .iter()
            .map(|s| section_meta_block(wasm, s))
            .collect(),
    );

    let build = Value::Block(vec![
        field(
            "magic",
            Value::List(
                ud_format::wasm::MAGIC
                    .iter()
                    .map(|b| Value::Int(u64::from(*b)))
                    .collect(),
            ),
        ),
        field("version", Value::Int(u64::from(wasm.version))),
        field("sections", sections_value),
        field("file_size", Value::Int(wasm.bytes.len() as u64)),
    ]);

    Module {
        fields: vec![
            field("arch", Value::String("wasm32".into())),
            field("abi", Value::String("wasm".into())),
            field("format", Value::String("wasm".into())),
            field("bits", Value::Int(32)),
            field("endian", Value::String("little".into())),
            field("type", Value::Int(0)),
            field("build", build),
        ],
    }
}

/// One entry in `@module.build.sections` — the section's id,
/// the raw bytes of its size LEB128 (for byte-identical
/// reconstruction of padded sizes), the body length, and the
/// custom-name (when id = 0).
fn section_meta_block(wasm: &WasmFile, section: &Section) -> Value {
    let header_bytes = &wasm.bytes[section.header_range.clone()];
    let mut fields = vec![
        field("id", Value::Int(u64::from(section.id))),
        field("kind", Value::String(section_kind_name(section.id).into())),
        field("body_offset", Value::Int(section.body_range.start as u64)),
        field("body_size", Value::Int(section.body_range.len() as u64)),
        // The header (id + LEB size) is fully covered by the
        // body offset + section bytes in the @raw block;
        // it's surfaced here only as the size-LEB byte width
        // for cleanly visible padding state.
        field(
            "size_leb_bytes",
            Value::Int((header_bytes.len() - 1) as u64),
        ),
    ];
    if let Some(name) = wasm.custom_section_name(section) {
        fields.push(field("name", Value::String(name)));
    }
    Value::Block(fields)
}

fn section_kind_name(id: u8) -> &'static str {
    use ud_format::wasm::{
        SECTION_CODE, SECTION_CUSTOM, SECTION_DATA, SECTION_DATA_COUNT, SECTION_ELEMENT,
        SECTION_EXPORT, SECTION_FUNCTION, SECTION_GLOBAL, SECTION_IMPORT, SECTION_MEMORY,
        SECTION_START, SECTION_TABLE, SECTION_TYPE,
    };
    match id {
        SECTION_CUSTOM => "custom",
        SECTION_TYPE => "type",
        SECTION_IMPORT => "import",
        SECTION_FUNCTION => "function",
        SECTION_TABLE => "table",
        SECTION_MEMORY => "memory",
        SECTION_GLOBAL => "global",
        SECTION_EXPORT => "export",
        SECTION_START => "start",
        SECTION_ELEMENT => "element",
        SECTION_CODE => "code",
        SECTION_DATA => "data",
        SECTION_DATA_COUNT => "data_count",
        _ => "unknown",
    }
}

/// One top-level `@raw(file_offset, [bytes])` per section
/// (header + body together). Plus a leading `@raw` for the
/// 8-byte magic + version header.
fn build_wasm_items(wasm: &WasmFile) -> Vec<Item> {
    let mut out = Vec::with_capacity(wasm.sections.len() + 1);
    // Header (magic + version) — 8 bytes at offset 0.
    out.push(Item::Raw {
        addr: 0,
        bytes: wasm.bytes[0..8].to_vec(),
    });
    for s in &wasm.sections {
        let lo = s.header_range.start;
        let hi = s.body_range.end;
        out.push(Item::Raw {
            addr: lo as u64,
            bytes: wasm.bytes[lo..hi].to_vec(),
        });
    }
    out
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

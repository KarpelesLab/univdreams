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

use ud_ast::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};
use ud_format::wasm::{Section, WasmFile, SECTION_CODE};

use super::wasm_disasm;

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

/// One top-level item per section (mostly `@raw`), plus a
/// leading `@raw` for the 8-byte magic + version header.
///
/// The Code section is split open: its header bytes (section
/// id + size LEB + function-count LEB) ride as a small
/// `@raw`, and each function body becomes its own
/// `Item::Function` block carrying:
///
/// * a leading `@raw` for the function's size LEB (kept
///   outside the `fn { … }` so the lower path treats it as
///   independent — clang emits padded LEBs and we mustn't
///   collapse them),
/// * a `fn func_<idx>` block whose body is the locals
///   declaration (one `@asm`) followed by one `@asm` per
///   decoded WASM op.
///
/// If the Code section fails to decode (unknown opcode, etc.)
/// the whole section falls back to a single opaque `@raw` —
/// byte-identity is the contract, readability is the bonus.
fn build_wasm_items(wasm: &WasmFile) -> Vec<Item> {
    let mut out = Vec::with_capacity(wasm.sections.len() + 1);
    // Header (magic + version) — 8 bytes at offset 0.
    out.push(Item::Raw {
        addr: 0,
        bytes: wasm.bytes[0..8].to_vec(),
    });
    for s in &wasm.sections {
        if s.id == SECTION_CODE && try_emit_code_section(wasm, s, &mut out).is_some() {
            continue;
        }
        let lo = s.header_range.start;
        let hi = s.body_range.end;
        out.push(Item::Raw {
            addr: lo as u64,
            bytes: wasm.bytes[lo..hi].to_vec(),
        });
    }
    out
}

/// Try to break the Code section into per-function items.
/// Returns `Some(())` on success — the caller skips the
/// opaque-`@raw` fallback. Returns `None` on any decode
/// hiccup so the fallback can take over.
fn try_emit_code_section(wasm: &WasmFile, section: &Section, out: &mut Vec<Item>) -> Option<()> {
    let body_lo = section.body_range.start;
    let body = &wasm.bytes[section.body_range.clone()];
    let (count, count_len) = read_leb_u32(body, 0)?;
    let header_lo = section.header_range.start;
    let header_end = body_lo + count_len;
    // Stage everything in a scratch vec; only commit on
    // full success so a partial decode doesn't leave the
    // output with a gap.
    let mut scratch: Vec<Item> = Vec::with_capacity(1 + count as usize * 2);
    scratch.push(Item::Raw {
        addr: header_lo as u64,
        bytes: wasm.bytes[header_lo..header_end].to_vec(),
    });

    let mut cursor = count_len; // offset within section body
    for i in 0..count {
        let fn_size_off = cursor;
        let (fn_size, fn_size_len) = read_leb_u32(body, cursor)?;
        let fn_body_off = cursor + fn_size_len;
        let fn_body_end = fn_body_off + fn_size as usize;
        if fn_body_end > body.len() {
            return None;
        }
        // size LEB lives outside the fn block — keep its
        // padded encoding intact.
        scratch.push(Item::Raw {
            addr: (body_lo + fn_size_off) as u64,
            bytes: body[fn_size_off..fn_body_off].to_vec(),
        });
        // Decode locals + ops.
        let fn_body = &body[fn_body_off..fn_body_end];
        let (locals_end, locals_text) = wasm_disasm::decode_locals(fn_body).ok()?;
        let ops = wasm_disasm::decode_function(&fn_body[locals_end..]).ok()?;
        let fn_decl = build_fn_decl(
            i,
            (body_lo + fn_body_off) as u64,
            &fn_body[..locals_end],
            &locals_text,
            &ops,
            &fn_body[locals_end..],
        );
        scratch.push(Item::Function(fn_decl));
        cursor = fn_body_end;
    }
    if cursor != body.len() {
        return None;
    }
    out.extend(scratch);
    Some(())
}

fn build_fn_decl(
    index: u32,
    body_addr: u64,
    locals_bytes: &[u8],
    locals_text: &str,
    ops: &[wasm_disasm::Op],
    op_bytes: &[u8],
) -> FnDecl {
    let mut body: Vec<Stmt> = Vec::with_capacity(ops.len() + 2);
    // The locals declaration rides as a single `@asm` so its
    // exact byte encoding (often padded LEBs) is pinned.
    let locals_label = if locals_bytes.is_empty() {
        "locals".to_string()
    } else {
        format!("locals {locals_text}")
    };
    body.push(Stmt::Asm {
        text: locals_label,
        bytes: locals_bytes.to_vec(),
    });
    for op in ops {
        let text = if op.args.is_empty() {
            op.mnemonic.to_string()
        } else {
            format!("{} {}", op.mnemonic, op.args)
        };
        body.push(Stmt::Asm {
            text,
            bytes: op_bytes[op.bytes.clone()].to_vec(),
        });
    }
    FnDecl {
        addr: Some(body_addr),
        name: format!("func_{index}"),
        attrs: Vec::new(),
        signature: None,
        locals: Vec::new(),
        body,
    }
}

/// Two-return-value LEB128 reader: `(value, byte_count)`.
/// Mirrors the one inside `ud_format::wasm` but private —
/// the decompile path can't import private helpers.
fn read_leb_u32(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0usize;
    loop {
        let b = *bytes.get(at + i)?;
        result |= u64::from(b & 0x7f) << shift;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if i > 5 {
            return None;
        }
    }
    if result > u64::from(u32::MAX) {
        return None;
    }
    Some((result as u32, i))
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

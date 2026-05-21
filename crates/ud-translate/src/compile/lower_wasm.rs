//! Lower a parsed `.ud` file whose `@module.format` says
//! `"wasm"` back to a WASM binary.
//!
//! Strategy: walk `Item::Raw` in declared order and concatenate
//! their bytes. The decompile path emits one `@raw` for the
//! 8-byte magic + version header, then one `@raw` per section
//! (covering its id + size-LEB + body). Concatenation in order
//! reproduces the original file byte-for-byte.
//!
//! `@module.build.file_size` is checked against the
//! concatenated total to catch accidental drift — if the user
//! adds / removes a section without updating `file_size`, lower
//! complains loudly rather than silently emitting truncated
//! bytes.

use ud_ast::{Field, Item, Module, UdFile, Value};

#[derive(Debug, thiserror::Error)]
pub enum WasmLowerError {
    #[error("`@module.format` is not `\"wasm\"` (got {got:?})")]
    NotWasm { got: String },
    #[error("`@module.format` field is missing")]
    UnknownFormat,
    #[error("missing field `{field}` in `@module`")]
    MissingField { field: String },
    #[error("field `{field}` has wrong shape: expected {expected}, got something else")]
    WrongShape { field: String, expected: String },
    #[error("gap in coverage: cursor at 0x{cursor:x}, next block at 0x{addr:x}")]
    Gap { cursor: u64, addr: u64 },
    #[error(
        "overlap: cursor was at 0x{cursor:x}, next block starts at 0x{addr:x} (still inside the previous block)"
    )]
    Overlap { cursor: u64, addr: u64 },
    #[error(
        "coverage mismatch: walked 0x{covered:x} bytes but file_size declares 0x{file_size:x}"
    )]
    SizeMismatch { covered: u64, file_size: u64 },
    #[error("WASM lower only knows how to handle `@raw` items; got {kind}")]
    UnsupportedItem { kind: &'static str },
}

/// Lower a `.ud` file describing a WASM module to its bytes.
pub fn lower_to_wasm(file: &UdFile) -> Result<Vec<u8>, WasmLowerError> {
    let format = read_string(&file.module, "format").ok_or(WasmLowerError::UnknownFormat)?;
    if format != "wasm" {
        return Err(WasmLowerError::NotWasm { got: format });
    }
    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;

    // Collect `@raw` blocks in addr order; reject anything else.
    let mut blocks: Vec<(u64, Vec<u8>)> = Vec::new();
    for item in &file.items {
        match item {
            Item::Raw { addr, bytes } => blocks.push((*addr, bytes.clone())),
            Item::Comment(_) => {}
            Item::Function(_) => return Err(WasmLowerError::UnsupportedItem { kind: "function" }),
            Item::Section { .. } => {
                return Err(WasmLowerError::UnsupportedItem { kind: "section" })
            }
            Item::Strings { .. } => {
                return Err(WasmLowerError::UnsupportedItem { kind: "strings" })
            }
            Item::Notes { .. } => return Err(WasmLowerError::UnsupportedItem { kind: "notes" }),
            Item::JumpTable { .. } => {
                return Err(WasmLowerError::UnsupportedItem { kind: "jump_table" })
            }
        }
    }
    blocks.sort_by_key(|(addr, _)| *addr);

    let mut out = Vec::with_capacity(file_size as usize);
    let mut cursor: u64 = 0;
    for (addr, bytes) in &blocks {
        let len = bytes.len() as u64;
        if *addr < cursor {
            return Err(WasmLowerError::Overlap {
                cursor,
                addr: *addr,
            });
        }
        if *addr > cursor {
            return Err(WasmLowerError::Gap {
                cursor,
                addr: *addr,
            });
        }
        out.extend_from_slice(bytes);
        cursor = addr.saturating_add(len);
    }
    if cursor != file_size {
        return Err(WasmLowerError::SizeMismatch {
            covered: cursor,
            file_size,
        });
    }
    Ok(out)
}

fn build_block(module: &Module) -> Result<&[Field], WasmLowerError> {
    for f in &module.fields {
        if f.name == "build" {
            if let Value::Block(fields) = &f.value {
                return Ok(fields);
            }
            return Err(WasmLowerError::WrongShape {
                field: "build".into(),
                expected: "block".into(),
            });
        }
    }
    Err(WasmLowerError::MissingField {
        field: "build".into(),
    })
}

fn read_int(fields: &[Field], name: &str) -> Result<u64, WasmLowerError> {
    for f in fields {
        if f.name == name {
            if let Value::Int(n) = &f.value {
                return Ok(*n);
            }
            return Err(WasmLowerError::WrongShape {
                field: name.into(),
                expected: "integer".into(),
            });
        }
    }
    Err(WasmLowerError::MissingField { field: name.into() })
}

fn read_string(module: &Module, name: &str) -> Option<String> {
    module.fields.iter().find_map(|f| match &f.value {
        Value::String(s) if f.name == name => Some(s.clone()),
        _ => None,
    })
}

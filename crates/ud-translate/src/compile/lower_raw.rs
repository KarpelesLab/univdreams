//! Lower a parsed `.ud` file whose `@module.format` says `"raw"`
//! back to a flat binary.
//!
//! Contract:
//!
//! ```text
//! lower_to_raw(parse(decompile_raw_6502_to_text(image))) == image-bytes
//! ```
//!
//! Strategy: walk `Item::Function` (with `@addr`) and `Item::Raw` in
//! virtual-address order, lower each to its bytes, and copy into a
//! contiguous output buffer of size `build.file_size` starting at
//! `load_addr`. Every byte in `[load_addr, load_addr + file_size)`
//! must be covered exactly once.

use ud_ast::{Field, Item, Module, UdFile, Value};

use crate::compile::lower::lower_function_bytes;
use crate::compile::module::resolve_arch_codec;

#[derive(Debug, thiserror::Error)]
pub enum RawLowerError {
    #[error("`@module.format` is not `\"raw\"` (got {got:?})")]
    NotRaw { got: String },
    #[error("`@module.format` field is missing")]
    UnknownFormat,
    #[error("missing field `{field}` in `@module`")]
    MissingField { field: String },
    #[error("field `{field}` has wrong shape: expected {expected}, got something else")]
    WrongShape { field: String, expected: String },
    #[error("byte block at 0x{addr:x} ({len} bytes) is outside the image [0x{load:x}, 0x{end:x})")]
    OutOfRange {
        addr: u64,
        len: u64,
        load: u64,
        end: u64,
    },
    #[error(
        "overlap: cursor was at 0x{cursor:x}, next block starts at 0x{addr:x} (still inside the previous block)"
    )]
    Overlap { cursor: u64, addr: u64 },
    #[error("gap in coverage: cursor at 0x{cursor:x}, next block at 0x{addr:x}")]
    Gap { cursor: u64, addr: u64 },
    #[error(
        "coverage mismatch: walked 0x{covered:x} bytes but file_size declares 0x{file_size:x}"
    )]
    SizeMismatch { covered: u64, file_size: u64 },
    #[error("function `{name}` has no `@addr` — required for raw placement")]
    FunctionWithoutAddr { name: String },
    #[error(transparent)]
    InnerLower(#[from] crate::compile::lower::LowerError),

    #[error("module arch resolution failed: {0}")]
    ArchResolve(String),
}

impl From<ud_arch_codec::ArchError> for RawLowerError {
    fn from(e: ud_arch_codec::ArchError) -> Self {
        Self::ArchResolve(e.to_string())
    }
}

/// Lower a `.ud` file describing a raw image to its bytes.
pub fn lower_to_raw(file: &UdFile) -> Result<Vec<u8>, RawLowerError> {
    let format = read_string(&file.module, "format").ok_or(RawLowerError::UnknownFormat)?;
    if format != "raw" {
        return Err(RawLowerError::NotRaw { got: format });
    }
    let load_addr = read_int_at(&file.module, "load_addr")?;
    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;
    let end = load_addr + file_size;

    let arch = resolve_arch_codec(&file.module)?;
    let mut owned_function_bytes: Vec<Vec<u8>> = Vec::new();
    let mut blocks: Vec<(u64, Vec<u8>)> = Vec::new();
    for item in &file.items {
        match item {
            Item::Raw { addr, bytes } => blocks.push((*addr, bytes.clone())),
            Item::Function(f) => {
                let addr = f.addr.ok_or_else(|| RawLowerError::FunctionWithoutAddr {
                    name: f.name.clone(),
                })?;
                let bytes = lower_function_bytes(f, arch.as_ref())?;
                owned_function_bytes.push(bytes);
                let last = owned_function_bytes.last().unwrap();
                blocks.push((addr, last.clone()));
            }
            Item::Comment(_)
            | Item::Section { .. }
            | Item::Strings { .. }
            | Item::Notes { .. }
            | Item::JumpTable { .. } => {}
        }
    }
    blocks.sort_by_key(|(addr, _)| *addr);

    let mut out = vec![0u8; file_size as usize];
    let mut cursor = load_addr;
    for (addr, bytes) in &blocks {
        let len = bytes.len() as u64;
        if *addr < load_addr || addr.saturating_add(len) > end {
            return Err(RawLowerError::OutOfRange {
                addr: *addr,
                len,
                load: load_addr,
                end,
            });
        }
        if *addr < cursor {
            return Err(RawLowerError::Overlap {
                cursor,
                addr: *addr,
            });
        }
        if *addr > cursor {
            return Err(RawLowerError::Gap {
                cursor,
                addr: *addr,
            });
        }
        let off = (*addr - load_addr) as usize;
        out[off..off + bytes.len()].copy_from_slice(bytes);
        cursor = addr + len;
    }
    let _ = owned_function_bytes;

    let covered = cursor - load_addr;
    if covered != file_size {
        return Err(RawLowerError::SizeMismatch { covered, file_size });
    }

    Ok(out)
}

fn build_block(module: &Module) -> Result<&[Field], RawLowerError> {
    for f in &module.fields {
        if f.name == "build" {
            if let Value::Block(fields) = &f.value {
                return Ok(fields);
            }
            return Err(RawLowerError::WrongShape {
                field: "build".into(),
                expected: "block".into(),
            });
        }
    }
    Err(RawLowerError::MissingField {
        field: "build".into(),
    })
}

fn read_int(fields: &[Field], name: &str) -> Result<u64, RawLowerError> {
    for f in fields {
        if f.name == name {
            if let Value::Int(n) = &f.value {
                return Ok(*n);
            }
            return Err(RawLowerError::WrongShape {
                field: name.into(),
                expected: "integer".into(),
            });
        }
    }
    Err(RawLowerError::MissingField { field: name.into() })
}

fn read_int_at(module: &Module, name: &str) -> Result<u64, RawLowerError> {
    read_int(&module.fields, name)
}

fn read_string(module: &Module, name: &str) -> Option<String> {
    module.fields.iter().find_map(|f| match &f.value {
        Value::String(s) if f.name == name => Some(s.clone()),
        _ => None,
    })
}

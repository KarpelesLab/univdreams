//! Lower a parsed `.ud` file whose `@module.format` says `"ne"` back
//! to a 16-bit Windows New Executable.
//!
//! Contract:
//!
//! ```text
//! lower_to_ne(parse(decompile_ne_to_text(ne))) == ne-bytes
//! ```
//!
//! The NE decompile path (see [`crate::decompile::decompile_ne`])
//! captures the structural metadata in `@module` purely for
//! readability and lays the whole file down as a single
//! `@raw(0, [bytes])`. Lowering therefore just walks the `@raw` items
//! (in file-offset order), checks they cover `[0, file_size)` exactly
//! once, and stitches them back into a buffer. There is no function
//! lowering and no arch-codec resolution in this pass — the bytes are
//! carried verbatim, which is what makes the round-trip exact
//! regardless of how rich the structural decode is.

use ud_ast::{Field, Item, Module, UdFile, Value};

#[derive(Debug, thiserror::Error)]
pub enum NeLowerError {
    #[error("`@module.format` is not `\"ne\"` (got {got:?})")]
    NotNe { got: String },
    #[error("`@module.format` field is missing")]
    UnknownFormat,
    #[error("missing field `{field}` in `@module`")]
    MissingField { field: String },
    #[error("field `{field}` has wrong shape: expected {expected}, got something else")]
    WrongShape { field: String, expected: String },
    #[error("byte block at 0x{addr:x} ({len} bytes) runs past the file end 0x{end:x}")]
    OutOfRange { addr: u64, len: u64, end: u64 },
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
    #[error("NE lower expects byte content only via `@raw`; found unsupported item `{kind}`")]
    UnsupportedItem { kind: &'static str },
}

/// Lower a `.ud` file describing an NE module to its bytes.
///
/// # Errors
/// Returns an error if the `@module.format` is not `"ne"`, the
/// `build.file_size` field is missing/misshaped, or the `@raw` items
/// don't tile `[0, file_size)` contiguously without gaps or overlaps.
pub fn lower_to_ne(file: &UdFile) -> Result<Vec<u8>, NeLowerError> {
    let format = read_string(&file.module, "format").ok_or(NeLowerError::UnknownFormat)?;
    if format != "ne" {
        return Err(NeLowerError::NotNe { got: format });
    }
    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;

    let mut blocks: Vec<(u64, &[u8])> = Vec::new();
    for item in &file.items {
        match item {
            Item::Raw { addr, bytes } => blocks.push((*addr, bytes)),
            // Comments are presentation-only and carry no bytes.
            Item::Comment(_) => {}
            Item::Function(_) => return Err(NeLowerError::UnsupportedItem { kind: "function" }),
            Item::Strings { .. } => return Err(NeLowerError::UnsupportedItem { kind: "strings" }),
            Item::Notes { .. } => return Err(NeLowerError::UnsupportedItem { kind: "notes" }),
            Item::Section { .. } => return Err(NeLowerError::UnsupportedItem { kind: "section" }),
            Item::JumpTable { .. } => {
                return Err(NeLowerError::UnsupportedItem { kind: "jump_table" });
            }
        }
    }
    blocks.sort_by_key(|(addr, _)| *addr);

    let mut out = vec![0u8; file_size as usize];
    let mut cursor: u64 = 0;
    for (addr, bytes) in &blocks {
        let len = bytes.len() as u64;
        if addr.saturating_add(len) > file_size {
            return Err(NeLowerError::OutOfRange {
                addr: *addr,
                len,
                end: file_size,
            });
        }
        if *addr < cursor {
            return Err(NeLowerError::Overlap {
                cursor,
                addr: *addr,
            });
        }
        if *addr > cursor {
            return Err(NeLowerError::Gap {
                cursor,
                addr: *addr,
            });
        }
        let off = *addr as usize;
        out[off..off + bytes.len()].copy_from_slice(bytes);
        cursor = addr + len;
    }

    if cursor != file_size {
        return Err(NeLowerError::SizeMismatch {
            covered: cursor,
            file_size,
        });
    }

    Ok(out)
}

fn build_block(module: &Module) -> Result<&[Field], NeLowerError> {
    for f in &module.fields {
        if f.name == "build" {
            if let Value::Block(fields) = &f.value {
                return Ok(fields);
            }
            return Err(NeLowerError::WrongShape {
                field: "build".into(),
                expected: "block".into(),
            });
        }
    }
    Err(NeLowerError::MissingField {
        field: "build".into(),
    })
}

fn read_int(fields: &[Field], name: &str) -> Result<u64, NeLowerError> {
    for f in fields {
        if f.name == name {
            if let Value::Int(n) = &f.value {
                return Ok(*n);
            }
            return Err(NeLowerError::WrongShape {
                field: name.into(),
                expected: "integer".into(),
            });
        }
    }
    Err(NeLowerError::MissingField { field: name.into() })
}

fn read_string(module: &Module, name: &str) -> Option<String> {
    module.fields.iter().find_map(|f| match &f.value {
        Value::String(s) if f.name == name => Some(s.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_ast::{Field, Module, UdFile, Value};

    fn module_with_size(size: u64) -> Module {
        Module {
            fields: vec![
                Field {
                    name: "format".into(),
                    value: Value::String("ne".into()),
                },
                Field {
                    name: "build".into(),
                    value: Value::Block(vec![Field {
                        name: "file_size".into(),
                        value: Value::Int(size),
                    }]),
                },
            ],
        }
    }

    #[test]
    fn single_raw_round_trips() {
        let data = vec![0x4d, 0x5a, 0x01, 0x02, 0x03];
        let file = UdFile {
            module: module_with_size(data.len() as u64),
            items: vec![Item::Raw {
                addr: 0,
                bytes: data.clone(),
            }],
        };
        assert_eq!(lower_to_ne(&file).unwrap(), data);
    }

    #[test]
    fn split_raws_tile_contiguously() {
        let file = UdFile {
            module: module_with_size(4),
            items: vec![
                Item::Raw {
                    addr: 2,
                    bytes: vec![0xaa, 0xbb],
                },
                Item::Raw {
                    addr: 0,
                    bytes: vec![0x11, 0x22],
                },
            ],
        };
        assert_eq!(lower_to_ne(&file).unwrap(), vec![0x11, 0x22, 0xaa, 0xbb]);
    }

    #[test]
    fn gap_is_rejected() {
        let file = UdFile {
            module: module_with_size(4),
            items: vec![Item::Raw {
                addr: 0,
                bytes: vec![0x11, 0x22],
            }],
        };
        assert!(matches!(
            lower_to_ne(&file),
            Err(NeLowerError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn wrong_format_is_rejected() {
        let mut module = module_with_size(1);
        module.fields[0].value = Value::String("pe".into());
        let file = UdFile {
            module,
            items: vec![Item::Raw {
                addr: 0,
                bytes: vec![0x00],
            }],
        };
        assert!(matches!(
            lower_to_ne(&file),
            Err(NeLowerError::NotNe { .. })
        ));
    }
}

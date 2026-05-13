//! Lower a parsed `.ud` file whose `@module.format` says `"pe"`
//! back to a complete PE binary.
//!
//! The contract this enforces:
//!
//! ```text
//! lower_to_pe(parse(decompile_pe_to_text(pe))) == pe-bytes
//! ```
//!
//! v0 strategy: the decompile path emits one `@raw(file_offset,
//! [bytes])` per contiguous byte range covering the entire input.
//! Lower walks those `@raw` items in file-offset order and
//! concatenates them into a single buffer of the size declared by
//! `@module.build.file_size`. Any gap, overlap, or size mismatch is
//! a hard error — those would silently corrupt the round-trip.
//!
//! Functions / `@section` / `@call` / etc. are not yet meaningful
//! for PE input; those land when a future iteration replaces the
//! flat `@raw` blocks with structured items.

use ud_ast::{Field, Item, Module, UdFile, Value};

/// Errors specific to the PE lower path.
#[derive(Debug, thiserror::Error)]
pub enum PeLowerError {
    #[error("missing field `{field}` in `@module.build`")]
    MissingField { field: String },

    #[error(
        "field `@module.build.{field}` has wrong shape: expected {expected}, got something else"
    )]
    WrongShape { field: String, expected: String },

    #[error("integer value 0x{value:x} for field `{field}` is out of range for {target}")]
    ValueOutOfRange {
        field: String,
        value: u64,
        target: &'static str,
    },

    #[error("`@module.format` is not `\"pe\"` (got {got:?})")]
    NotPe { got: String },

    #[error("`@raw(0x{addr:x}, …)` is past the declared file_size {file_size}")]
    RawPastEnd { addr: u64, file_size: u64 },

    #[error("`@raw(0x{addr:x}, [{len} bytes])` would overflow past file_size {file_size}")]
    RawOverflows { addr: u64, len: u64, file_size: u64 },

    #[error(
        "@raw blocks at file offsets 0x{a_addr:x} and 0x{b_addr:x} overlap (cursor was at 0x{cursor:x})"
    )]
    OverlappingRaws {
        a_addr: u64,
        b_addr: u64,
        cursor: u64,
    },

    #[error("byte range gap: cursor at 0x{cursor:x} but next `@raw` is at 0x{next_addr:x}")]
    GapInCoverage { cursor: u64, next_addr: u64 },

    #[error(
        "@raw blocks covered 0x{covered:x} bytes but `@module.build.file_size` says 0x{file_size:x}"
    )]
    CoverageSizeMismatch { covered: u64, file_size: u64 },

    #[error("`@module.format` field is missing — can't tell which lower path to use")]
    UnknownFormat,

    #[error("function `{name}` has no `@addr` — required for PE placement")]
    FunctionWithoutAddr { name: String },

    #[error(transparent)]
    InnerLower(#[from] crate::lower::LowerError),
}

/// Lower a `.ud` file describing a PE image to its bytes.
pub fn lower_to_pe(file: &UdFile) -> Result<Vec<u8>, PeLowerError> {
    let format = read_string(&file.module, "format").ok_or(PeLowerError::UnknownFormat)?;
    if format != "pe" {
        return Err(PeLowerError::NotPe { got: format });
    }

    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;
    // Read each section's (fileoff, vaddr) so we can translate
    // function file offsets into IP-space (RVA) addresses for
    // PC-relative encoders inside `lower_function_bytes`.
    let section_vaddrs = collect_section_ip_offsets(build);

    let mut out = vec![0u8; file_size as usize];

    // Collect all byte-bearing items in file-offset order. Both
    // `@raw` and `fn name() {…}` contribute bytes; for `fn` blocks
    // we lower the body to its bytes via `lower_function_bytes`.
    // Strict: every byte in [0, file_size) must be covered by
    // exactly one such item.
    let mut owned_function_bytes: Vec<Vec<u8>> = Vec::new();
    let mut raws: Vec<(u64, Vec<u8>)> = Vec::new();
    for item in &file.items {
        match item {
            Item::Raw { addr, bytes } => raws.push((*addr, bytes.clone())),
            Item::Function(f) => {
                let addr = f.addr.ok_or_else(|| PeLowerError::FunctionWithoutAddr {
                    name: f.name.clone(),
                })?;
                // `f.addr` is a file offset in PE; the encoder
                // wants an IP-space address. Walk the section
                // table to find the section containing `addr`
                // and translate via `(vaddr - fileoff)`.
                let ip_base = file_offset_to_rva(addr, &section_vaddrs);
                let bytes = crate::lower::lower_function_bytes_at(f, ip_base)?;
                owned_function_bytes.push(bytes);
                let last = owned_function_bytes.last().unwrap();
                raws.push((addr, last.clone()));
            }
            Item::Comment(_) | Item::Section { .. } | Item::Strings { .. } | Item::Notes { .. } => {
            }
        }
    }
    raws.sort_by_key(|(addr, _)| *addr);

    let mut cursor: u64 = 0;
    for (addr, bytes) in &raws {
        let len = bytes.len() as u64;
        let end = addr.checked_add(len).ok_or(PeLowerError::RawOverflows {
            addr: *addr,
            len,
            file_size,
        })?;
        if end > file_size {
            return Err(PeLowerError::RawOverflows {
                addr: *addr,
                len,
                file_size,
            });
        }
        if *addr < cursor {
            return Err(PeLowerError::OverlappingRaws {
                a_addr: cursor.saturating_sub(1),
                b_addr: *addr,
                cursor,
            });
        }
        if *addr > cursor {
            return Err(PeLowerError::GapInCoverage {
                cursor,
                next_addr: *addr,
            });
        }
        let off = *addr as usize;
        out[off..off + bytes.len()].copy_from_slice(bytes);
        cursor = end;
    }
    let _ = owned_function_bytes; // borrow target lifetime

    if cursor != file_size {
        return Err(PeLowerError::CoverageSizeMismatch {
            covered: cursor,
            file_size,
        });
    }

    Ok(out)
}

/// `@module.build` block accessor.
fn build_block(module: &Module) -> Result<&[Field], PeLowerError> {
    for f in &module.fields {
        if f.name == "build" {
            if let Value::Block(fields) = &f.value {
                return Ok(fields);
            }
            return Err(PeLowerError::WrongShape {
                field: "build".into(),
                expected: "block".into(),
            });
        }
    }
    Err(PeLowerError::MissingField {
        field: "build".into(),
    })
}

fn read_int(fields: &[Field], name: &str) -> Result<u64, PeLowerError> {
    for f in fields {
        if f.name == name {
            if let Value::Int(n) = &f.value {
                return Ok(*n);
            }
            return Err(PeLowerError::WrongShape {
                field: name.into(),
                expected: "integer".into(),
            });
        }
    }
    Err(PeLowerError::MissingField { field: name.into() })
}

/// Parse the `@module.build.sections` list and return each
/// section's `(pointer_to_raw_data, virtual_address,
/// size_of_raw_data)` triple. Used to translate a function's
/// file-offset `addr` to a virtual-address-space IP for
/// PC-relative encoders inside the function body.
fn collect_section_ip_offsets(build: &[Field]) -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    for f in build {
        if f.name != "sections" {
            continue;
        }
        let Value::List(secs) = &f.value else {
            return out;
        };
        for s in secs {
            let Value::Block(sf) = s else { continue };
            let mut fileoff: Option<u64> = None;
            let mut vaddr: Option<u64> = None;
            let mut raw_size: Option<u64> = None;
            for x in sf {
                match (x.name.as_str(), &x.value) {
                    ("pointer_to_raw_data", Value::Int(n)) => fileoff = Some(*n),
                    ("virtual_address", Value::Int(n)) => vaddr = Some(*n),
                    ("size_of_raw_data", Value::Int(n)) => raw_size = Some(*n),
                    _ => {}
                }
            }
            if let (Some(off), Some(va), Some(sz)) = (fileoff, vaddr, raw_size) {
                out.push((off, va, sz));
            }
        }
        break;
    }
    out
}

/// Given a function's file-offset `addr` and the section table,
/// return the corresponding RVA (virtual-address-space IP). `None`
/// when the file offset doesn't fall inside any section we know
/// about — encoders that require an IP base then fail clearly
/// instead of silently using a wrong value.
fn file_offset_to_rva(addr: u64, sections: &[(u64, u64, u64)]) -> Option<u64> {
    for &(fileoff, vaddr, raw_size) in sections {
        if addr >= fileoff && addr < fileoff + raw_size {
            return Some(vaddr + (addr - fileoff));
        }
    }
    None
}

fn read_string(module: &Module, name: &str) -> Option<String> {
    module.fields.iter().find_map(|f| {
        if f.name == name {
            if let Value::String(s) = &f.value {
                Some(s.clone())
            } else {
                None
            }
        } else {
            None
        }
    })
}

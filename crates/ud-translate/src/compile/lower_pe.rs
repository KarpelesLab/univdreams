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
use ud_format_pe::{
    CoffHeader, DataDirectory, DosHeader, OptionalHeader, PeFile, PeKind, SectionHeader,
    OPTIONAL_HEADER_MAGIC_PE32, OPTIONAL_HEADER_MAGIC_PE32_PLUS,
};

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
    InnerLower(#[from] crate::compile::lower::LowerError),
}

/// Lower a `.ud` file describing a PE image to its bytes.
pub fn lower_to_pe(file: &UdFile) -> Result<Vec<u8>, PeLowerError> {
    let format = read_string(&file.module, "format").ok_or(PeLowerError::UnknownFormat)?;
    if format != "pe" {
        return Err(PeLowerError::NotPe { got: format });
    }

    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;
    let section_vaddrs = collect_section_ip_offsets(build);

    // Reassemble the PE header skeleton from the structured
    // fields in `@module.build` (DOS header, DOS stub, COFF
    // header, optional header + data directories, section
    // table). `PeFile::from_parts` lays them down at the right
    // file offsets and produces a buffer whose header region is
    // byte-identical to the input — even when no `@raw` covers
    // those bytes today, the structured fields drive the
    // reconstruction.
    let (dos, dos_stub, coff, optional, data_directories, sections) =
        read_pe_skeleton(build, file_size)?;
    let kind = match optional.as_ref().map(|o| o.magic) {
        Some(OPTIONAL_HEADER_MAGIC_PE32) => PeKind::Pe32,
        Some(OPTIONAL_HEADER_MAGIC_PE32_PLUS) | None => PeKind::Pe32Plus,
        Some(_) => PeKind::Pe32Plus,
    };
    let image_base = optional.as_ref().map_or(0, |o| o.image_base);
    let address_of_entry_point = optional.as_ref().map_or(0, |o| o.address_of_entry_point);
    let pe = PeFile::from_parts(
        kind,
        dos,
        dos_stub,
        coff,
        optional,
        image_base,
        address_of_entry_point,
        data_directories,
        sections,
        Vec::new(),
        file_size,
    );
    let mut out = pe.write_to_vec();

    // Collect each byte-bearing item's (file_offset, bytes)
    // pair, then place them in sorted order with a strict
    // overlap check past the structured header region.
    //
    // The overlap check matters because two unrelated lift
    // bugs can produce a function whose lowered bytes are
    // longer than the original function's slot — typically
    // when a `Stmt::Call`'s arg-setup prefix bytes got
    // absorbed both into the preceding `Stmt::LocalSet` AND
    // the `Stmt::Call`. The OLD PE lower path caught these by
    // erroring out on adjacent-item overlap; the new path
    // keeps that invariant so the source-pipeline round-trip
    // test sees the same skip behaviour for affected
    // fixtures.
    let header_end = pe_header_region_end_from_ast(build);
    let mut placements: Vec<(u64, Vec<u8>)> = Vec::new();
    for item in &file.items {
        match item {
            Item::Raw { addr, bytes } => placements.push((*addr, bytes.clone())),
            Item::Function(f) => {
                let addr = f.addr.ok_or_else(|| PeLowerError::FunctionWithoutAddr {
                    name: f.name.clone(),
                })?;
                let ip_base = file_offset_to_rva(addr, &section_vaddrs);
                let bytes = crate::compile::lower::lower_function_bytes_at(f, ip_base)?;
                placements.push((addr, bytes));
            }
            Item::Comment(_)
            | Item::Section { .. }
            | Item::Strings { .. }
            | Item::Notes { .. }
            | Item::JumpTable { .. } => {}
        }
    }
    placements.sort_by_key(|(addr, _)| *addr);

    let mut cursor = header_end;
    for (addr, bytes) in &placements {
        if *addr < header_end {
            place(&mut out, *addr, bytes, file_size)?;
            continue;
        }
        if *addr < cursor {
            return Err(PeLowerError::OverlappingRaws {
                a_addr: cursor.saturating_sub(1),
                b_addr: *addr,
                cursor,
            });
        }
        place(&mut out, *addr, bytes, file_size)?;
        cursor = addr.saturating_add(bytes.len() as u64);
    }

    Ok(out)
}

/// File offset at which the structured PE header region ends —
/// the same value the decompile-side `pe_header_region_end`
/// computes. Used by the overlap check so items in the header
/// region (which are covered by `from_parts`) don't trigger
/// false alarms when they coexist with `@raw` overlays from
/// older `.ud` outputs.
fn pe_header_region_end_from_ast(build: &[Field]) -> u64 {
    let e_lfanew = build
        .iter()
        .find(|f| f.name == "e_lfanew")
        .and_then(|f| match &f.value {
            Value::Int(n) => Some(*n),
            _ => Option::None,
        })
        .unwrap_or(0x40);
    let opt_size = build
        .iter()
        .find(|f| f.name == "coff")
        .and_then(|f| match &f.value {
            Value::Block(c) => c.iter().find(|x| x.name == "size_of_optional_header"),
            _ => Option::None,
        })
        .and_then(|f| match &f.value {
            Value::Int(n) => Some(*n),
            _ => Option::None,
        })
        .unwrap_or(0);
    let nsec = build
        .iter()
        .find(|f| f.name == "sections")
        .and_then(|f| match &f.value {
            Value::List(l) => Some(l.len() as u64),
            _ => Option::None,
        })
        .unwrap_or(0);
    e_lfanew + 4 + 20 + opt_size + nsec * 40
}

fn place(
    out: &mut [u8],
    addr: u64,
    bytes: &[u8],
    file_size: u64,
) -> Result<(), PeLowerError> {
    let len = bytes.len() as u64;
    let end = addr.checked_add(len).ok_or(PeLowerError::RawOverflows {
        addr,
        len,
        file_size,
    })?;
    if end > file_size {
        return Err(PeLowerError::RawOverflows {
            addr,
            len,
            file_size,
        });
    }
    let off = addr as usize;
    out[off..off + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// Read the structured PE skeleton out of `@module.build`. Each
/// field is optional from the parser's perspective (older
/// decompile output may not have them) — when absent we fall
/// back to a default-zero header and let any byte-level
/// overlays from `@raw` blocks pin the original encoding.
#[allow(clippy::type_complexity)]
fn read_pe_skeleton(
    build: &[Field],
    _file_size: u64,
) -> Result<
    (
        DosHeader,
        Vec<u8>,
        CoffHeader,
        Option<OptionalHeader>,
        Vec<DataDirectory>,
        Vec<SectionHeader>,
    ),
    PeLowerError,
> {
    let dos = read_dos_header(build);
    let dos_stub = read_byte_list(build, "dos_stub").unwrap_or_default();
    let coff = read_coff_header(build)?;
    let optional = read_optional_header(build);
    let data_directories = read_data_directories(build);
    let sections = read_sections(build)?;
    Ok((dos, dos_stub, coff, optional, data_directories, sections))
}

fn read_dos_header(build: &[Field]) -> DosHeader {
    let Some(Value::Block(d)) = lookup_value(build, "dos") else {
        // Synthesize a default DOS header pointing at e_lfanew.
        return DosHeader {
            e_magic: *b"MZ",
            e_cblp: 0,
            e_cp: 0,
            e_crlc: 0,
            e_cparhdr: 0,
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_csum: 0,
            e_ip: 0,
            e_cs: 0,
            e_lfarlc: 0,
            e_ovno: 0,
            e_res: [0; 4],
            e_oemid: 0,
            e_oeminfo: 0,
            e_res2: [0; 10],
            e_lfanew: read_int(build, "e_lfanew").unwrap_or(0x40) as u32,
        };
    };
    let e_magic_bytes = read_byte_list_block(d, "e_magic").unwrap_or_else(|| b"MZ".to_vec());
    let mut e_magic = [b'M', b'Z'];
    if e_magic_bytes.len() == 2 {
        e_magic.copy_from_slice(&e_magic_bytes);
    }
    let mut e_res = [0u16; 4];
    for (i, n) in read_int_list_block(d, "e_res")
        .unwrap_or_default()
        .iter()
        .enumerate()
        .take(4)
    {
        e_res[i] = *n as u16;
    }
    let mut e_res2 = [0u16; 10];
    for (i, n) in read_int_list_block(d, "e_res2")
        .unwrap_or_default()
        .iter()
        .enumerate()
        .take(10)
    {
        e_res2[i] = *n as u16;
    }
    DosHeader {
        e_magic,
        e_cblp: read_int_block(d, "e_cblp").unwrap_or(0) as u16,
        e_cp: read_int_block(d, "e_cp").unwrap_or(0) as u16,
        e_crlc: read_int_block(d, "e_crlc").unwrap_or(0) as u16,
        e_cparhdr: read_int_block(d, "e_cparhdr").unwrap_or(0) as u16,
        e_minalloc: read_int_block(d, "e_minalloc").unwrap_or(0) as u16,
        e_maxalloc: read_int_block(d, "e_maxalloc").unwrap_or(0) as u16,
        e_ss: read_int_block(d, "e_ss").unwrap_or(0) as u16,
        e_sp: read_int_block(d, "e_sp").unwrap_or(0) as u16,
        e_csum: read_int_block(d, "e_csum").unwrap_or(0) as u16,
        e_ip: read_int_block(d, "e_ip").unwrap_or(0) as u16,
        e_cs: read_int_block(d, "e_cs").unwrap_or(0) as u16,
        e_lfarlc: read_int_block(d, "e_lfarlc").unwrap_or(0) as u16,
        e_ovno: read_int_block(d, "e_ovno").unwrap_or(0) as u16,
        e_res,
        e_oemid: read_int_block(d, "e_oemid").unwrap_or(0) as u16,
        e_oeminfo: read_int_block(d, "e_oeminfo").unwrap_or(0) as u16,
        e_res2,
        e_lfanew: read_int_block(d, "e_lfanew").unwrap_or(0x40) as u32,
    }
}

fn read_coff_header(build: &[Field]) -> Result<CoffHeader, PeLowerError> {
    let Some(Value::Block(c)) = lookup_value(build, "coff") else {
        return Err(PeLowerError::MissingField {
            field: "coff".into(),
        });
    };
    Ok(CoffHeader {
        machine: read_int_block(c, "machine").unwrap_or(0) as u16,
        number_of_sections: read_int_block(c, "number_of_sections").unwrap_or(0) as u16,
        time_date_stamp: read_int_block(c, "time_date_stamp").unwrap_or(0) as u32,
        pointer_to_symbol_table: read_int_block(c, "pointer_to_symbol_table").unwrap_or(0) as u32,
        number_of_symbols: read_int_block(c, "number_of_symbols").unwrap_or(0) as u32,
        size_of_optional_header: read_int_block(c, "size_of_optional_header").unwrap_or(0) as u16,
        characteristics: read_int_block(c, "characteristics").unwrap_or(0) as u16,
    })
}

fn read_optional_header(build: &[Field]) -> Option<OptionalHeader> {
    let Some(Value::Block(o)) = lookup_value(build, "optional") else {
        return Option::None;
    };
    if o.is_empty() {
        return Option::None;
    }
    Some(OptionalHeader {
        magic: read_int_block(o, "magic").unwrap_or(OPTIONAL_HEADER_MAGIC_PE32_PLUS as u64) as u16,
        major_linker_version: read_int_block(o, "major_linker_version").unwrap_or(0) as u8,
        minor_linker_version: read_int_block(o, "minor_linker_version").unwrap_or(0) as u8,
        size_of_code: read_int_block(o, "size_of_code").unwrap_or(0) as u32,
        size_of_initialized_data: read_int_block(o, "size_of_initialized_data").unwrap_or(0)
            as u32,
        size_of_uninitialized_data: read_int_block(o, "size_of_uninitialized_data").unwrap_or(0)
            as u32,
        address_of_entry_point: read_int_block(o, "address_of_entry_point").unwrap_or(0) as u32,
        base_of_code: read_int_block(o, "base_of_code").unwrap_or(0) as u32,
        base_of_data: read_int_block(o, "base_of_data").unwrap_or(0) as u32,
        image_base: read_int_block(o, "image_base").unwrap_or(0),
        section_alignment: read_int_block(o, "section_alignment").unwrap_or(0) as u32,
        file_alignment: read_int_block(o, "file_alignment").unwrap_or(0) as u32,
        major_operating_system_version: read_int_block(o, "major_operating_system_version")
            .unwrap_or(0) as u16,
        minor_operating_system_version: read_int_block(o, "minor_operating_system_version")
            .unwrap_or(0) as u16,
        major_image_version: read_int_block(o, "major_image_version").unwrap_or(0) as u16,
        minor_image_version: read_int_block(o, "minor_image_version").unwrap_or(0) as u16,
        major_subsystem_version: read_int_block(o, "major_subsystem_version").unwrap_or(0) as u16,
        minor_subsystem_version: read_int_block(o, "minor_subsystem_version").unwrap_or(0) as u16,
        win32_version_value: read_int_block(o, "win32_version_value").unwrap_or(0) as u32,
        size_of_image: read_int_block(o, "size_of_image").unwrap_or(0) as u32,
        size_of_headers: read_int_block(o, "size_of_headers").unwrap_or(0) as u32,
        check_sum: read_int_block(o, "check_sum").unwrap_or(0) as u32,
        subsystem: read_int_block(o, "subsystem").unwrap_or(0) as u16,
        dll_characteristics: read_int_block(o, "dll_characteristics").unwrap_or(0) as u16,
        size_of_stack_reserve: read_int_block(o, "size_of_stack_reserve").unwrap_or(0),
        size_of_stack_commit: read_int_block(o, "size_of_stack_commit").unwrap_or(0),
        size_of_heap_reserve: read_int_block(o, "size_of_heap_reserve").unwrap_or(0),
        size_of_heap_commit: read_int_block(o, "size_of_heap_commit").unwrap_or(0),
        loader_flags: read_int_block(o, "loader_flags").unwrap_or(0) as u32,
        number_of_rva_and_sizes: read_int_block(o, "number_of_rva_and_sizes").unwrap_or(0) as u32,
    })
}

fn read_data_directories(build: &[Field]) -> Vec<DataDirectory> {
    let Some(Value::List(items)) = lookup_value(build, "data_directories") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|v| match v {
            Value::Block(fs) => Some(DataDirectory {
                virtual_address: read_int_block(fs, "virtual_address").unwrap_or(0) as u32,
                size: read_int_block(fs, "size").unwrap_or(0) as u32,
            }),
            _ => Option::None,
        })
        .collect()
}

fn read_sections(build: &[Field]) -> Result<Vec<SectionHeader>, PeLowerError> {
    let Some(Value::List(items)) = lookup_value(build, "sections") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(items.len());
    for v in items {
        let Value::Block(s) = v else {
            return Err(PeLowerError::WrongShape {
                field: "sections[]".into(),
                expected: "block".into(),
            });
        };
        let name_bytes = read_byte_list_block(s, "name_raw").unwrap_or_default();
        let mut name = [0u8; 8];
        for (i, b) in name_bytes.iter().enumerate().take(8) {
            name[i] = *b;
        }
        out.push(SectionHeader {
            name,
            virtual_size: read_int_block(s, "virtual_size").unwrap_or(0) as u32,
            virtual_address: read_int_block(s, "virtual_address").unwrap_or(0) as u32,
            size_of_raw_data: read_int_block(s, "size_of_raw_data").unwrap_or(0) as u32,
            pointer_to_raw_data: read_int_block(s, "pointer_to_raw_data").unwrap_or(0) as u32,
            pointer_to_relocations: read_int_block(s, "pointer_to_relocations").unwrap_or(0) as u32,
            pointer_to_linenumbers: read_int_block(s, "pointer_to_linenumbers").unwrap_or(0) as u32,
            number_of_relocations: read_int_block(s, "number_of_relocations").unwrap_or(0) as u16,
            number_of_linenumbers: read_int_block(s, "number_of_linenumbers").unwrap_or(0) as u16,
            characteristics: read_int_block(s, "characteristics").unwrap_or(0) as u32,
        });
    }
    Ok(out)
}

fn lookup_value<'a>(fields: &'a [Field], name: &str) -> Option<&'a Value> {
    fields.iter().find(|f| f.name == name).map(|f| &f.value)
}

fn read_int_block(fields: &[Field], name: &str) -> Option<u64> {
    match lookup_value(fields, name)? {
        Value::Int(n) => Some(*n),
        _ => Option::None,
    }
}

fn read_byte_list(fields: &[Field], name: &str) -> Option<Vec<u8>> {
    let Some(Value::List(items)) = lookup_value(fields, name) else {
        return Option::None;
    };
    items
        .iter()
        .map(|v| match v {
            Value::Int(n) => Some(*n as u8),
            _ => Option::None,
        })
        .collect()
}

fn read_byte_list_block(fields: &[Field], name: &str) -> Option<Vec<u8>> {
    read_byte_list(fields, name)
}

fn read_int_list_block(fields: &[Field], name: &str) -> Option<Vec<u64>> {
    let Some(Value::List(items)) = lookup_value(fields, name) else {
        return Option::None;
    };
    items
        .iter()
        .map(|v| match v {
            Value::Int(n) => Some(*n),
            _ => Option::None,
        })
        .collect()
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

//! Lower a parsed `.ud` file whose `@module.format` says `"macho"`
//! back to a thin 64-bit Mach-O image.
//!
//! Contract:
//!
//! ```text
//! lower_to_macho(parse(decompile_macho_to_text(macho))) == macho-bytes
//! ```
//!
//! Strategy mirrors `MachoFile::write_to_vec`: allocate a zero
//! buffer of the declared `file_size`, drop each `@raw` chunk at
//! its file offset (these are the `LC_SEGMENT_64`-described
//! segment payloads), then overlay the structured header + each
//! load command + the padding gaps. Segment data and header /
//! load-command bytes overlap by design (an executable's leading
//! `__TEXT` segment covers offset 0); the overlay order makes the
//! parsed-fields version of the header / load commands the
//! source of truth.

use ud_ast::{Field, Item, Module, UdFile, Value};
use ud_format::macho::{
    is_dylib_cmd, is_linkedit_data_cmd, BuildVersionTool, LcBuildVersion, LcDylib, LcDylinker,
    LcDysymtab, LcLinkeditData, LcMain, LcSourceVersion, LcSymtab, LcUuid, LoadCommand,
    MachHeader64, Section64, Segment64, LC_BUILD_VERSION, LC_DYSYMTAB, LC_LOAD_DYLINKER, LC_MAIN,
    LC_SEGMENT_64, LC_SOURCE_VERSION, LC_SYMTAB, LC_UUID,
};

/// Errors specific to the Mach-O lower path.
#[derive(Debug, thiserror::Error)]
pub enum MachoLowerError {
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

    #[error("`@module.format` is not `\"macho\"` (got {got:?})")]
    NotMacho { got: String },

    #[error("`@module.format` field is missing — can't tell which lower path to use")]
    UnknownFormat,

    #[error("`@raw(0x{addr:x}, …)` is past the declared file_size {file_size}")]
    RawPastEnd { addr: u64, file_size: u64 },

    #[error("`@raw(0x{addr:x}, [{len} bytes])` would overflow past file_size {file_size}")]
    RawOverflows { addr: u64, len: u64, file_size: u64 },

    #[error("function `{name}` has no `@addr` — required for Mach-O placement")]
    FunctionWithoutAddr { name: String },

    #[error(transparent)]
    InnerLower(#[from] crate::compile::lower::LowerError),

    #[error("module arch resolution failed: {0}")]
    ArchResolve(String),
}

impl From<ud_arch_codec::ArchError> for MachoLowerError {
    fn from(e: ud_arch_codec::ArchError) -> Self {
        Self::ArchResolve(e.to_string())
    }
}

/// Lower a `.ud` file describing a Mach-O image to its bytes.
pub fn lower_to_macho(file: &UdFile) -> Result<Vec<u8>, MachoLowerError> {
    let format = read_string(&file.module, "format").ok_or(MachoLowerError::UnknownFormat)?;
    if format != "macho" {
        return Err(MachoLowerError::NotMacho { got: format });
    }

    let arch = crate::compile::module::resolve_arch_codec(&file.module)?;
    let build = build_block(&file.module)?;
    let header = read_header(build)?;
    let commands = read_commands(build)?;
    let padding = read_padding(build)?;
    let file_size = read_int(build, "file_size")?;

    let mut out = vec![0u8; file_size as usize];

    // Drop every @raw / function bytes block at its declared file
    // offset. These ARE the segment payloads (one @raw per
    // `LC_SEGMENT_64` with filesize > 0). They may overlap with
    // the header / load-command bytes for the leading __TEXT
    // segment — that's handled by overlaying header + commands
    // AFTER the segments, making the structured fields the
    // source of truth.
    let mut raws: Vec<(u64, Vec<u8>)> = Vec::new();
    for item in &file.items {
        match item {
            Item::Raw { addr, bytes } => raws.push((*addr, bytes.clone())),
            Item::Function(f) => {
                let addr = f.addr.ok_or_else(|| MachoLowerError::FunctionWithoutAddr {
                    name: f.name.clone(),
                })?;
                let bytes = crate::compile::lower::lower_function_bytes(f, arch.as_ref())?;
                raws.push((addr, bytes));
            }
            Item::Comment(_)
            | Item::Section { .. }
            | Item::Strings { .. }
            | Item::Notes { .. }
            | Item::JumpTable { .. } => {}
        }
    }
    for (addr, bytes) in &raws {
        let len = bytes.len() as u64;
        let end = addr.checked_add(len).ok_or(MachoLowerError::RawOverflows {
            addr: *addr,
            len,
            file_size,
        })?;
        if *addr >= file_size {
            return Err(MachoLowerError::RawPastEnd {
                addr: *addr,
                file_size,
            });
        }
        if end > file_size {
            return Err(MachoLowerError::RawOverflows {
                addr: *addr,
                len,
                file_size,
            });
        }
        let off = *addr as usize;
        out[off..off + bytes.len()].copy_from_slice(bytes);
    }

    // Header at offset 0.
    let mut header_bytes = [0u8; 32];
    write_header(&mut header_bytes, &header);
    out[..32].copy_from_slice(&header_bytes);

    // Load-command table starts at offset 32.
    let mut cursor = 32usize;
    for cmd in &commands {
        out[cursor..cursor + 4].copy_from_slice(&cmd.cmd.to_le_bytes());
        out[cursor + 4..cursor + 8].copy_from_slice(&cmd.cmdsize.to_le_bytes());
        let body_end = cursor + 8 + cmd.body.len();
        out[cursor + 8..body_end].copy_from_slice(&cmd.body);
        cursor += cmd.cmdsize as usize;
    }

    // Padding (interstitial alignment).
    for (offset, bytes) in &padding {
        let off = *offset as usize;
        out[off..off + bytes.len()].copy_from_slice(bytes);
    }

    Ok(out)
}

fn write_header(out: &mut [u8], h: &MachHeader64) {
    out[0..4].copy_from_slice(&h.magic.to_le_bytes());
    out[4..8].copy_from_slice(&h.cputype.to_le_bytes());
    out[8..12].copy_from_slice(&h.cpusubtype.to_le_bytes());
    out[12..16].copy_from_slice(&h.filetype.to_le_bytes());
    out[16..20].copy_from_slice(&h.ncmds.to_le_bytes());
    out[20..24].copy_from_slice(&h.sizeofcmds.to_le_bytes());
    out[24..28].copy_from_slice(&h.flags.to_le_bytes());
    out[28..32].copy_from_slice(&h.reserved.to_le_bytes());
}

fn build_block(module: &Module) -> Result<&[Field], MachoLowerError> {
    for f in &module.fields {
        if f.name == "build" {
            if let Value::Block(fields) = &f.value {
                return Ok(fields);
            }
            return Err(MachoLowerError::WrongShape {
                field: "build".into(),
                expected: "block".into(),
            });
        }
    }
    Err(MachoLowerError::MissingField {
        field: "build".into(),
    })
}

fn read_header(build: &[Field]) -> Result<MachHeader64, MachoLowerError> {
    let value = lookup_field(build, "header")?;
    let Value::Block(fields) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "header".into(),
            expected: "block".into(),
        });
    };
    Ok(MachHeader64 {
        magic: read_u32(fields, "magic")?,
        cputype: read_u32(fields, "cputype")?,
        cpusubtype: read_u32(fields, "cpusubtype")?,
        filetype: read_u32(fields, "filetype")?,
        ncmds: read_u32(fields, "ncmds")?,
        sizeofcmds: read_u32(fields, "sizeofcmds")?,
        flags: read_u32(fields, "flags")?,
        reserved: read_u32(fields, "reserved")?,
    })
}

fn read_commands(build: &[Field]) -> Result<Vec<LoadCommand>, MachoLowerError> {
    let value = lookup_field(build, "commands")?;
    let Value::List(items) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "commands".into(),
            expected: "list".into(),
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Block(fields) = item else {
            return Err(MachoLowerError::WrongShape {
                field: "commands[]".into(),
                expected: "block".into(),
            });
        };
        let cmd = read_u32(fields, "cmd")?;
        let cmdsize = read_u32(fields, "cmdsize")?;
        let body = encode_command_body(cmd, fields)?;
        out.push(LoadCommand { cmd, cmdsize, body });
    }
    Ok(out)
}

/// Pick the body shape present on this command-block and
/// re-serialize it. Exactly one of the recognised structured
/// fields OR the opaque `body` may be present.
fn encode_command_body(cmd: u32, fields: &[Field]) -> Result<Vec<u8>, MachoLowerError> {
    const STRUCTURED_KEYS: &[&str] = &[
        "segment",
        "symtab",
        "dysymtab",
        "dylinker",
        "uuid",
        "build_version",
        "source_version",
        "main",
        "dylib",
        "linkedit_data",
    ];
    let mut hits: Vec<&str> = STRUCTURED_KEYS
        .iter()
        .copied()
        .filter(|k| fields.iter().any(|f| f.name == *k))
        .collect();
    let has_body = fields.iter().any(|f| f.name == "body");
    if has_body {
        hits.push("body");
    }
    match hits.len() {
        0 => Err(MachoLowerError::MissingField {
            field: format!("commands[].body (or one of {})", STRUCTURED_KEYS.join(", ")),
        }),
        1 => {
            let key = hits[0];
            match key {
                "body" => read_byte_list(fields, "body"),
                "segment" => {
                    require_cmd(cmd, LC_SEGMENT_64, "segment")?;
                    Ok(read_segment_block(fields)?.write_to_body())
                }
                "symtab" => {
                    require_cmd(cmd, LC_SYMTAB, "symtab")?;
                    Ok(read_symtab_block(fields)?.encode())
                }
                "dysymtab" => {
                    require_cmd(cmd, LC_DYSYMTAB, "dysymtab")?;
                    Ok(read_dysymtab_block(fields)?.encode())
                }
                "dylinker" => {
                    require_cmd(cmd, LC_LOAD_DYLINKER, "dylinker")?;
                    Ok(read_dylinker_block(fields)?.encode())
                }
                "uuid" => {
                    require_cmd(cmd, LC_UUID, "uuid")?;
                    Ok(read_uuid_field(fields)?.encode())
                }
                "build_version" => {
                    require_cmd(cmd, LC_BUILD_VERSION, "build_version")?;
                    Ok(read_build_version_block(fields)?.encode())
                }
                "source_version" => {
                    require_cmd(cmd, LC_SOURCE_VERSION, "source_version")?;
                    let n = read_int(fields, "source_version")?;
                    Ok(LcSourceVersion(n).encode())
                }
                "main" => {
                    require_cmd(cmd, LC_MAIN, "main")?;
                    Ok(read_main_block(fields)?.encode())
                }
                "dylib" => {
                    if !is_dylib_cmd(cmd) {
                        return Err(MachoLowerError::WrongShape {
                            field: "commands[].dylib".into(),
                            expected: format!(
                                "dylib-shaped cmd (LC_LOAD_DYLIB / LC_ID_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB), got cmd 0x{cmd:x}"
                            ),
                        });
                    }
                    Ok(read_dylib_block(fields)?.encode())
                }
                "linkedit_data" => {
                    if !is_linkedit_data_cmd(cmd) {
                        return Err(MachoLowerError::WrongShape {
                            field: "commands[].linkedit_data".into(),
                            expected: format!("linkedit_data-shaped cmd, got cmd 0x{cmd:x}"),
                        });
                    }
                    Ok(read_linkedit_data_block(fields)?.encode())
                }
                _ => unreachable!("filter and match must stay in sync"),
            }
        }
        _ => Err(MachoLowerError::WrongShape {
            field: "commands[]".into(),
            expected: format!("exactly one body shape, got: {}", hits.join(", ")),
        }),
    }
}

fn require_cmd(actual: u32, expected: u32, label: &str) -> Result<(), MachoLowerError> {
    if actual != expected {
        return Err(MachoLowerError::WrongShape {
            field: format!("commands[].{label}"),
            expected: format!("cmd 0x{expected:x}, got 0x{actual:x}"),
        });
    }
    Ok(())
}

fn read_symtab_block(cmd_fields: &[Field]) -> Result<LcSymtab, MachoLowerError> {
    let value = lookup_field(cmd_fields, "symtab")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "symtab".into(),
            expected: "block".into(),
        });
    };
    Ok(LcSymtab {
        symoff: read_u32(f, "symoff")?,
        nsyms: read_u32(f, "nsyms")?,
        stroff: read_u32(f, "stroff")?,
        strsize: read_u32(f, "strsize")?,
    })
}

fn read_dysymtab_block(cmd_fields: &[Field]) -> Result<LcDysymtab, MachoLowerError> {
    let value = lookup_field(cmd_fields, "dysymtab")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "dysymtab".into(),
            expected: "block".into(),
        });
    };
    Ok(LcDysymtab {
        ilocalsym: read_u32(f, "ilocalsym")?,
        nlocalsym: read_u32(f, "nlocalsym")?,
        iextdefsym: read_u32(f, "iextdefsym")?,
        nextdefsym: read_u32(f, "nextdefsym")?,
        iundefsym: read_u32(f, "iundefsym")?,
        nundefsym: read_u32(f, "nundefsym")?,
        tocoff: read_u32(f, "tocoff")?,
        ntoc: read_u32(f, "ntoc")?,
        modtaboff: read_u32(f, "modtaboff")?,
        nmodtab: read_u32(f, "nmodtab")?,
        extrefsymoff: read_u32(f, "extrefsymoff")?,
        nextrefsyms: read_u32(f, "nextrefsyms")?,
        indirectsymoff: read_u32(f, "indirectsymoff")?,
        nindirectsyms: read_u32(f, "nindirectsyms")?,
        extreloff: read_u32(f, "extreloff")?,
        nextrel: read_u32(f, "nextrel")?,
        locreloff: read_u32(f, "locreloff")?,
        nlocrel: read_u32(f, "nlocrel")?,
    })
}

fn read_dylinker_block(cmd_fields: &[Field]) -> Result<LcDylinker, MachoLowerError> {
    let value = lookup_field(cmd_fields, "dylinker")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "dylinker".into(),
            expected: "block".into(),
        });
    };
    Ok(LcDylinker {
        offset: read_u32(f, "offset")?,
        name: read_c_string_or_bytes(f, "name", "dylinker.name")?,
        tail_padding: read_optional_byte_list(f, "tail_padding")?,
    })
}

fn read_dylib_block(cmd_fields: &[Field]) -> Result<LcDylib, MachoLowerError> {
    let value = lookup_field(cmd_fields, "dylib")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "dylib".into(),
            expected: "block".into(),
        });
    };
    Ok(LcDylib {
        offset: read_u32(f, "offset")?,
        timestamp: read_u32(f, "timestamp")?,
        current_version: read_u32(f, "current_version")?,
        compatibility_version: read_u32(f, "compatibility_version")?,
        name: read_c_string_or_bytes(f, "name", "dylib.name")?,
        tail_padding: read_optional_byte_list(f, "tail_padding")?,
    })
}

fn read_build_version_block(cmd_fields: &[Field]) -> Result<LcBuildVersion, MachoLowerError> {
    let value = lookup_field(cmd_fields, "build_version")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "build_version".into(),
            expected: "block".into(),
        });
    };
    let platform = read_u32(f, "platform")?;
    let minos = read_u32(f, "minos")?;
    let sdk = read_u32(f, "sdk")?;
    let tools_value = lookup_field(f, "tools")?;
    let Value::List(items) = tools_value else {
        return Err(MachoLowerError::WrongShape {
            field: "build_version.tools".into(),
            expected: "list".into(),
        });
    };
    let mut tools = Vec::with_capacity(items.len());
    for item in items {
        let Value::Block(tf) = item else {
            return Err(MachoLowerError::WrongShape {
                field: "build_version.tools[]".into(),
                expected: "block".into(),
            });
        };
        tools.push(BuildVersionTool {
            tool: read_u32(tf, "tool")?,
            version: read_u32(tf, "version")?,
        });
    }
    Ok(LcBuildVersion {
        platform,
        minos,
        sdk,
        tools,
    })
}

fn read_main_block(cmd_fields: &[Field]) -> Result<LcMain, MachoLowerError> {
    let value = lookup_field(cmd_fields, "main")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "main".into(),
            expected: "block".into(),
        });
    };
    Ok(LcMain {
        entryoff: read_int(f, "entryoff")?,
        stacksize: read_int(f, "stacksize")?,
    })
}

fn read_linkedit_data_block(cmd_fields: &[Field]) -> Result<LcLinkeditData, MachoLowerError> {
    let value = lookup_field(cmd_fields, "linkedit_data")?;
    let Value::Block(f) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "linkedit_data".into(),
            expected: "block".into(),
        });
    };
    Ok(LcLinkeditData {
        dataoff: read_u32(f, "dataoff")?,
        datasize: read_u32(f, "datasize")?,
    })
}

fn read_uuid_field(cmd_fields: &[Field]) -> Result<LcUuid, MachoLowerError> {
    let value = lookup_field(cmd_fields, "uuid")?;
    match value {
        Value::String(s) => {
            let hex: String = s.chars().filter(|c| *c != '-').collect();
            if hex.len() != 32 {
                return Err(MachoLowerError::WrongShape {
                    field: "uuid".into(),
                    expected: "8-4-4-4-12 hex string (32 hex chars)".into(),
                });
            }
            let mut out = [0u8; 16];
            for i in 0..16 {
                let byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
                    MachoLowerError::WrongShape {
                        field: "uuid".into(),
                        expected: "hex digits only".into(),
                    }
                })?;
                out[i] = byte;
            }
            Ok(LcUuid(out))
        }
        Value::List(items) => {
            if items.len() != 16 {
                return Err(MachoLowerError::WrongShape {
                    field: "uuid".into(),
                    expected: format!("16-byte list, got {} elements", items.len()),
                });
            }
            let mut out = [0u8; 16];
            for (i, item) in items.iter().enumerate() {
                let Value::Int(n) = item else {
                    return Err(MachoLowerError::WrongShape {
                        field: format!("uuid[{i}]"),
                        expected: "byte integer".into(),
                    });
                };
                if *n > 0xff {
                    return Err(MachoLowerError::ValueOutOfRange {
                        field: format!("uuid[{i}]"),
                        value: *n,
                        target: "u8",
                    });
                }
                out[i] = *n as u8;
            }
            Ok(LcUuid(out))
        }
        _ => Err(MachoLowerError::WrongShape {
            field: "uuid".into(),
            expected: "string or 16-byte list".into(),
        }),
    }
}

fn read_c_string_or_bytes(
    fields: &[Field],
    name: &str,
    error_label: &str,
) -> Result<Vec<u8>, MachoLowerError> {
    let value = lookup_field(fields, name)?;
    match value {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let Value::Int(n) = item else {
                    return Err(MachoLowerError::WrongShape {
                        field: format!("{error_label}[{i}]"),
                        expected: "byte integer".into(),
                    });
                };
                if *n > 0xff {
                    return Err(MachoLowerError::ValueOutOfRange {
                        field: format!("{error_label}[{i}]"),
                        value: *n,
                        target: "u8",
                    });
                }
                out.push(*n as u8);
            }
            Ok(out)
        }
        _ => Err(MachoLowerError::WrongShape {
            field: error_label.into(),
            expected: "string or byte list".into(),
        }),
    }
}

fn read_optional_byte_list(fields: &[Field], name: &str) -> Result<Vec<u8>, MachoLowerError> {
    if !fields.iter().any(|f| f.name == name) {
        return Ok(Vec::new());
    }
    read_byte_list(fields, name)
}

fn read_segment_block(cmd_fields: &[Field]) -> Result<Segment64, MachoLowerError> {
    let value = lookup_field(cmd_fields, "segment")?;
    let Value::Block(fields) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "segment".into(),
            expected: "block".into(),
        });
    };
    let segname = read_name_field(fields, "name", "segment.name")?;
    let vmaddr = read_int(fields, "vmaddr")?;
    let vmsize = read_int(fields, "vmsize")?;
    let fileoff = read_int(fields, "fileoff")?;
    let filesize = read_int(fields, "filesize")?;
    let maxprot = read_u32(fields, "maxprot")?;
    let initprot = read_u32(fields, "initprot")?;
    let flags = read_u32(fields, "flags")?;
    let sections = read_sections(fields)?;
    let nsects = u32::try_from(sections.len()).map_err(|_| MachoLowerError::ValueOutOfRange {
        field: "segment.sections.len".into(),
        value: sections.len() as u64,
        target: "u32",
    })?;
    Ok(Segment64 {
        cmd_index: 0, // ignored by write_to_body
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        nsects,
        flags,
        sections,
    })
}

fn read_sections(seg_fields: &[Field]) -> Result<Vec<Section64>, MachoLowerError> {
    let value = lookup_field(seg_fields, "sections")?;
    let Value::List(items) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "segment.sections".into(),
            expected: "list".into(),
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Block(fields) = item else {
            return Err(MachoLowerError::WrongShape {
                field: "segment.sections[]".into(),
                expected: "block".into(),
            });
        };
        out.push(Section64 {
            sectname: read_name_field(fields, "name", "segment.sections[].name")?,
            segname: read_name_field(fields, "segment", "segment.sections[].segment")?,
            addr: read_int(fields, "addr")?,
            size: read_int(fields, "size")?,
            offset: read_u32(fields, "offset")?,
            align: read_u32(fields, "align")?,
            reloff: read_u32(fields, "reloff")?,
            nreloc: read_u32(fields, "nreloc")?,
            flags: read_u32(fields, "flags")?,
            reserved1: read_u32(fields, "reserved1")?,
            reserved2: read_u32(fields, "reserved2")?,
            reserved3: read_u32(fields, "reserved3")?,
        });
    }
    Ok(out)
}

/// Read a `char[16]` Mach-O name field. Accepts a string (zero-
/// padded to 16) or a raw 16-byte list for round-trip with names
/// that don't fit the ASCII-then-NUL shape.
fn read_name_field(
    fields: &[Field],
    name: &str,
    error_label: &str,
) -> Result<[u8; 16], MachoLowerError> {
    let value = lookup_field(fields, name)?;
    match value {
        Value::String(s) => {
            let bytes = s.as_bytes();
            if bytes.len() > 16 {
                return Err(MachoLowerError::WrongShape {
                    field: error_label.into(),
                    expected: format!("string of up to 16 bytes, got {}", bytes.len()),
                });
            }
            let mut out = [0u8; 16];
            out[..bytes.len()].copy_from_slice(bytes);
            Ok(out)
        }
        Value::List(items) => {
            if items.len() != 16 {
                return Err(MachoLowerError::WrongShape {
                    field: error_label.into(),
                    expected: format!("16-byte list, got {} elements", items.len()),
                });
            }
            let mut out = [0u8; 16];
            for (i, item) in items.iter().enumerate() {
                let Value::Int(n) = item else {
                    return Err(MachoLowerError::WrongShape {
                        field: format!("{error_label}[{i}]"),
                        expected: "byte integer".into(),
                    });
                };
                if *n > 0xff {
                    return Err(MachoLowerError::ValueOutOfRange {
                        field: format!("{error_label}[{i}]"),
                        value: *n,
                        target: "u8",
                    });
                }
                out[i] = *n as u8;
            }
            Ok(out)
        }
        _ => Err(MachoLowerError::WrongShape {
            field: error_label.into(),
            expected: "string or 16-byte list".into(),
        }),
    }
}

fn read_padding(build: &[Field]) -> Result<Vec<(u64, Vec<u8>)>, MachoLowerError> {
    let value = lookup_field(build, "padding")?;
    let Value::List(items) = value else {
        return Err(MachoLowerError::WrongShape {
            field: "padding".into(),
            expected: "list".into(),
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Block(fields) = item else {
            return Err(MachoLowerError::WrongShape {
                field: "padding[]".into(),
                expected: "block".into(),
            });
        };
        let offset = read_int(fields, "offset")?;
        let bytes = read_byte_list(fields, "bytes")?;
        out.push((offset, bytes));
    }
    Ok(out)
}

fn read_u32(fields: &[Field], name: &str) -> Result<u32, MachoLowerError> {
    let n = read_int(fields, name)?;
    u32::try_from(n).map_err(|_| MachoLowerError::ValueOutOfRange {
        field: name.into(),
        value: n,
        target: "u32",
    })
}

fn read_byte_list(fields: &[Field], name: &str) -> Result<Vec<u8>, MachoLowerError> {
    let value = lookup_field(fields, name)?;
    let Value::List(items) = value else {
        return Err(MachoLowerError::WrongShape {
            field: name.into(),
            expected: "list".into(),
        });
    };
    let mut bytes = Vec::with_capacity(items.len());
    for b in items {
        let Value::Int(n) = b else {
            return Err(MachoLowerError::WrongShape {
                field: format!("{name}[]"),
                expected: "byte".into(),
            });
        };
        if *n > 0xff {
            return Err(MachoLowerError::ValueOutOfRange {
                field: format!("{name}[]"),
                value: *n,
                target: "u8",
            });
        }
        bytes.push(*n as u8);
    }
    Ok(bytes)
}

fn lookup_field<'a>(fields: &'a [Field], name: &str) -> Result<&'a Value, MachoLowerError> {
    fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| &f.value)
        .ok_or_else(|| MachoLowerError::MissingField { field: name.into() })
}

fn read_int(fields: &[Field], name: &str) -> Result<u64, MachoLowerError> {
    for f in fields {
        if f.name == name {
            if let Value::Int(n) = &f.value {
                return Ok(*n);
            }
            return Err(MachoLowerError::WrongShape {
                field: name.into(),
                expected: "integer".into(),
            });
        }
    }
    Err(MachoLowerError::MissingField { field: name.into() })
}

fn read_string(module: &Module, name: &str) -> Option<String> {
    module.fields.iter().find_map(|f| {
        if f.name != name {
            return None;
        }
        let Value::String(s) = &f.value else {
            return None;
        };
        Some(s.clone())
    })
}

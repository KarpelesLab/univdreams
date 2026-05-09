//! Lower a parsed `.ud` AST to a complete ELF binary.
//!
//! Reads the full ELF metadata captured in `@module.build` (ehdr
//! fields, phdrs, shdrs, padding), lowers each `@section` block to its
//! bytes, matches sections to shdrs by name, and constructs an
//! [`Elf64File::from_parts`] which is then serialized via
//! [`Elf64File::write_to_vec`].
//!
//! The round-trip property:
//!
//! ```text
//! lower_to_elf(parse(decompile_to_text(elf)))   ==   elf-bytes
//! ```
//!
//! This is the strongest source-level invariant the project defends.
//!
//! [`Elf64File::from_parts`]: ud_format_elf::Elf64File::from_parts
//! [`Elf64File::write_to_vec`]: ud_format_elf::Elf64File::write_to_vec

use std::collections::HashMap;

use ud_ast::{Item, Module, UdFile, Value};
use ud_format_elf::{Ehdr64, Elf64File, Phdr64, Shdr64};

use crate::lower::{lower_section_bytes, LowerError};

/// Errors specific to the ELF lower path.
#[derive(Debug, thiserror::Error)]
pub enum ElfLowerError {
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

    #[error("`@module.build.e_ident` must be a list of exactly 16 bytes")]
    BadEIdent,

    #[error("`@section` block named `{section}` has no matching shdr in `@module.build.shdrs`")]
    UnknownSection { section: String },

    #[error("duplicate `@section` block named `{section}` (matches multiple shdrs by name)")]
    DuplicateSection { section: String },

    #[error(
        "shdr at index {idx} requires {expected} bytes of content but `@section` lowered to {got}"
    )]
    SectionSizeMismatch { idx: usize, expected: u64, got: u64 },

    #[error(transparent)]
    Lower(#[from] LowerError),
}

/// Lower a complete `.ud` file to ELF bytes.
pub fn lower_to_elf(file: &UdFile) -> Result<Vec<u8>, ElfLowerError> {
    let elf = build_elf64(file)?;
    Ok(elf.write_to_vec())
}

/// Build an [`Elf64File`] from `file`, ready for `write_to_vec`.
pub fn build_elf64(file: &UdFile) -> Result<Elf64File, ElfLowerError> {
    let build = build_block(&file.module)?;

    let ehdr = read_ehdr(&file.module, build)?;
    let phdrs = read_phdrs(build)?;
    let shdrs = read_shdrs(build)?;
    let padding = read_padding(build)?;
    let file_size = read_int(build, "file_size")?;

    // Lower every @section block; index by name.
    let mut by_name: HashMap<String, (u64, Vec<u8>)> = HashMap::new();
    for item in &file.items {
        if let Item::Section { name, addr, items } = item {
            let bytes = lower_section_bytes(name, *addr, items)?;
            if by_name.insert(name.clone(), (*addr, bytes)).is_some() {
                return Err(ElfLowerError::DuplicateSection {
                    section: name.clone(),
                });
            }
        }
    }

    // Build section_data parallel to shdrs by matching shdr.name → @section.name.
    // shdrs that don't have a matching @section get empty bytes (NULL, NOBITS,
    // and zero-size sections — none of which contribute file content).
    let mut section_data: Vec<Vec<u8>> = Vec::with_capacity(shdrs.len());
    for (idx, sh) in shdrs.iter().enumerate() {
        if !shdr_occupies_file(sh) {
            section_data.push(Vec::new());
            continue;
        }
        let name = shdr_name(file, idx)?;
        let Some((_, bytes)) = by_name.remove(&name) else {
            return Err(ElfLowerError::UnknownSection { section: name });
        };
        if bytes.len() as u64 != sh.sh_size {
            return Err(ElfLowerError::SectionSizeMismatch {
                idx,
                expected: sh.sh_size,
                got: bytes.len() as u64,
            });
        }
        section_data.push(bytes);
    }

    // Any leftover @section blocks didn't map to a shdr.
    if let Some(stray) = by_name.into_keys().next() {
        return Err(ElfLowerError::UnknownSection { section: stray });
    }

    Ok(Elf64File::from_parts(
        ehdr,
        phdrs,
        shdrs,
        section_data,
        padding,
        file_size,
    ))
}

fn shdr_occupies_file(sh: &Shdr64) -> bool {
    const SHT_NOBITS: u32 = 8;
    sh.sh_type != SHT_NOBITS && sh.sh_size > 0
}

fn shdr_name(file: &UdFile, idx: usize) -> Result<String, ElfLowerError> {
    let build = build_block(&file.module)?;
    let shdrs = lookup_field(build, "shdrs")?;
    let Value::List(list) = shdrs else {
        return Err(ElfLowerError::WrongShape {
            field: "shdrs".into(),
            expected: "list".into(),
        });
    };
    let entry = list.get(idx).ok_or_else(|| ElfLowerError::WrongShape {
        field: format!("shdrs[{idx}]"),
        expected: "in-range entry".into(),
    })?;
    let Value::Block(fields) = entry else {
        return Err(ElfLowerError::WrongShape {
            field: format!("shdrs[{idx}]"),
            expected: "block".into(),
        });
    };
    for f in fields {
        if f.name == "name" {
            if let Value::String(s) = &f.value {
                return Ok(s.clone());
            }
        }
    }
    Err(ElfLowerError::MissingField {
        field: format!("shdrs[{idx}].name"),
    })
}

fn build_block(module: &Module) -> Result<&[ud_ast::Field], ElfLowerError> {
    for f in &module.fields {
        if f.name == "build" {
            if let Value::Block(fields) = &f.value {
                return Ok(fields.as_slice());
            }
            return Err(ElfLowerError::WrongShape {
                field: "build".into(),
                expected: "block".into(),
            });
        }
    }
    Err(ElfLowerError::MissingField {
        field: "build".into(),
    })
}

fn read_ehdr(module: &Module, build: &[ud_ast::Field]) -> Result<Ehdr64, ElfLowerError> {
    let e_type = u16::try_from(read_module_int(module, "type")?).map_err(|_| {
        ElfLowerError::ValueOutOfRange {
            field: "type".into(),
            value: 0,
            target: "u16",
        }
    })?;
    let e_entry = read_module_int(module, "entry")?;

    let e_ident = read_e_ident(build)?;
    let e_machine = read_u16(build, "e_machine")?;
    let e_version = read_u32(build, "e_version")?;
    let e_phoff = read_int(build, "e_phoff")?;
    let e_shoff = read_int(build, "e_shoff")?;
    let e_flags = read_u32(build, "e_flags")?;
    let e_ehsize = read_u16(build, "e_ehsize")?;
    let e_phentsize = read_u16(build, "e_phentsize")?;
    let e_phnum = read_u16(build, "e_phnum")?;
    let e_shentsize = read_u16(build, "e_shentsize")?;
    let e_shnum = read_u16(build, "e_shnum")?;
    let e_shstrndx = read_u16(build, "e_shstrndx")?;

    Ok(Ehdr64 {
        e_ident,
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    })
}

fn read_e_ident(build: &[ud_ast::Field]) -> Result<[u8; 16], ElfLowerError> {
    let value = lookup_field(build, "e_ident")?;
    let Value::List(items) = value else {
        return Err(ElfLowerError::BadEIdent);
    };
    if items.len() != 16 {
        return Err(ElfLowerError::BadEIdent);
    }
    let mut out = [0u8; 16];
    for (i, item) in items.iter().enumerate() {
        let Value::Int(n) = item else {
            return Err(ElfLowerError::BadEIdent);
        };
        if *n > 0xff {
            return Err(ElfLowerError::BadEIdent);
        }
        out[i] = *n as u8;
    }
    Ok(out)
}

fn read_phdrs(build: &[ud_ast::Field]) -> Result<Vec<Phdr64>, ElfLowerError> {
    let value = lookup_field(build, "phdrs")?;
    let Value::List(items) = value else {
        return Err(ElfLowerError::WrongShape {
            field: "phdrs".into(),
            expected: "list".into(),
        });
    };
    items.iter().map(read_one_phdr).collect()
}

fn read_one_phdr(v: &Value) -> Result<Phdr64, ElfLowerError> {
    let Value::Block(fields) = v else {
        return Err(ElfLowerError::WrongShape {
            field: "phdrs[]".into(),
            expected: "block".into(),
        });
    };
    Ok(Phdr64 {
        p_type: read_u32(fields, "p_type")?,
        p_flags: read_u32(fields, "p_flags")?,
        p_offset: read_int(fields, "p_offset")?,
        p_vaddr: read_int(fields, "p_vaddr")?,
        p_paddr: read_int(fields, "p_paddr")?,
        p_filesz: read_int(fields, "p_filesz")?,
        p_memsz: read_int(fields, "p_memsz")?,
        p_align: read_int(fields, "p_align")?,
    })
}

fn read_shdrs(build: &[ud_ast::Field]) -> Result<Vec<Shdr64>, ElfLowerError> {
    let value = lookup_field(build, "shdrs")?;
    let Value::List(items) = value else {
        return Err(ElfLowerError::WrongShape {
            field: "shdrs".into(),
            expected: "list".into(),
        });
    };
    items.iter().map(read_one_shdr).collect()
}

fn read_one_shdr(v: &Value) -> Result<Shdr64, ElfLowerError> {
    let Value::Block(fields) = v else {
        return Err(ElfLowerError::WrongShape {
            field: "shdrs[]".into(),
            expected: "block".into(),
        });
    };
    Ok(Shdr64 {
        sh_name: read_u32(fields, "sh_name")?,
        sh_type: read_u32(fields, "sh_type")?,
        sh_flags: read_int(fields, "sh_flags")?,
        sh_addr: read_int(fields, "sh_addr")?,
        sh_offset: read_int(fields, "sh_offset")?,
        sh_size: read_int(fields, "sh_size")?,
        sh_link: read_u32(fields, "sh_link")?,
        sh_info: read_u32(fields, "sh_info")?,
        sh_addralign: read_int(fields, "sh_addralign")?,
        sh_entsize: read_int(fields, "sh_entsize")?,
    })
}

fn read_padding(build: &[ud_ast::Field]) -> Result<Vec<(u64, Vec<u8>)>, ElfLowerError> {
    let value = lookup_field(build, "padding")?;
    let Value::List(items) = value else {
        return Err(ElfLowerError::WrongShape {
            field: "padding".into(),
            expected: "list".into(),
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Block(fields) = item else {
            return Err(ElfLowerError::WrongShape {
                field: "padding[]".into(),
                expected: "block".into(),
            });
        };
        let offset = read_int(fields, "offset")?;
        let bytes_value = lookup_field(fields, "bytes")?;
        let Value::List(byte_items) = bytes_value else {
            return Err(ElfLowerError::WrongShape {
                field: "padding[].bytes".into(),
                expected: "list".into(),
            });
        };
        let mut bytes = Vec::with_capacity(byte_items.len());
        for b in byte_items {
            let Value::Int(n) = b else {
                return Err(ElfLowerError::WrongShape {
                    field: "padding[].bytes[]".into(),
                    expected: "byte".into(),
                });
            };
            if *n > 0xff {
                return Err(ElfLowerError::ValueOutOfRange {
                    field: "padding[].bytes[]".into(),
                    value: *n,
                    target: "u8",
                });
            }
            bytes.push(*n as u8);
        }
        out.push((offset, bytes));
    }
    Ok(out)
}

fn lookup_field<'a>(fields: &'a [ud_ast::Field], name: &str) -> Result<&'a Value, ElfLowerError> {
    fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| &f.value)
        .ok_or_else(|| ElfLowerError::MissingField { field: name.into() })
}

fn read_int(fields: &[ud_ast::Field], name: &str) -> Result<u64, ElfLowerError> {
    let value = lookup_field(fields, name)?;
    if let Value::Int(n) = value {
        Ok(*n)
    } else {
        Err(ElfLowerError::WrongShape {
            field: name.into(),
            expected: "integer".into(),
        })
    }
}

fn read_module_int(module: &Module, name: &str) -> Result<u64, ElfLowerError> {
    read_int(&module.fields, name)
}

fn read_u16(fields: &[ud_ast::Field], name: &str) -> Result<u16, ElfLowerError> {
    let n = read_int(fields, name)?;
    u16::try_from(n).map_err(|_| ElfLowerError::ValueOutOfRange {
        field: name.into(),
        value: n,
        target: "u16",
    })
}

fn read_u32(fields: &[ud_ast::Field], name: &str) -> Result<u32, ElfLowerError> {
    let n = read_int(fields, name)?;
    u32::try_from(n).map_err(|_| ElfLowerError::ValueOutOfRange {
        field: name.into(),
        value: n,
        target: "u32",
    })
}

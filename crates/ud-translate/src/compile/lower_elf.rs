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
//! [`Elf64File::from_parts`]: ud_format::elf::Elf64File::from_parts
//! [`Elf64File::write_to_vec`]: ud_format::elf::Elf64File::write_to_vec

use std::collections::HashMap;

use ud_ast::{Item, Module, UdFile, Value};
use ud_format::elf::{Ehdr64, Elf64File, ElfClass, Phdr64, Shdr64};

use crate::compile::lower::{lower_section_bytes, LowerError};

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

    let class = read_elf_class(&file.module)?;
    let mut ehdr = read_ehdr(&file.module, build)?;
    let mut phdrs = read_phdrs(build)?;
    let mut shdrs = read_shdrs(build)?;
    let mut padding = read_padding(build)?;
    let mut file_size = read_int(build, "file_size")?;

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
        section_data.push(bytes);
    }

    // Any leftover @section blocks didn't map to a shdr.
    if let Some(stray) = by_name.into_keys().next() {
        return Err(ElfLowerError::UnknownSection { section: stray });
    }

    // Cascade-shift the ELF layout to match any per-section
    // content-size changes. Unedited input → all deltas are 0 →
    // no shifts → byte-identical round-trip. Edits → sh_size
    // gets updated, later regions slide by the cumulative
    // delta, segment sizes containing changed sections grow
    // accordingly. See [`apply_size_changes`] for the details.
    apply_size_changes(
        &mut ehdr,
        &mut phdrs,
        &mut shdrs,
        &mut padding,
        &mut file_size,
        &section_data,
    );

    Ok(Elf64File::from_parts(
        class,
        ehdr,
        phdrs,
        shdrs,
        section_data,
        padding,
        file_size,
    ))
}

/// Walk the section table in file-offset order; for each section
/// whose lowered content size differs from its recorded
/// `sh_size`, update `sh_size` and queue a "shift everything
/// past my old end" event. After all sections are visited,
/// apply the cumulative shift to subsequent regions (sections
/// at higher offsets, padding, the section-header table, the
/// file size). For each program header whose loadable range
/// covers a grown/shrunk section, bump its `p_filesz` and
/// `p_memsz` by the section's delta and shift its `p_offset` /
/// `p_vaddr` / `p_paddr` if the segment starts past a shifted
/// region.
///
/// This is the "lenient" path: unedited input has zero deltas
/// everywhere, so the shifts are no-ops and the writer
/// reproduces the original bytes exactly. Edited input lays out
/// a new ELF that loads and runs at the cost of file/VA
/// offsets that no longer match the pristine binary.
fn apply_size_changes(
    ehdr: &mut Ehdr64,
    phdrs: &mut [Phdr64],
    shdrs: &mut [Shdr64],
    padding: &mut [(u64, Vec<u8>)],
    file_size: &mut u64,
    section_data: &[Vec<u8>],
) {
    // Snapshot every section's pre-update (offset, end) so the
    // "is this region past section S's old end?" test stays
    // consistent across multiple shifts.
    let snapshot: Vec<(u64, u64, i64)> = shdrs
        .iter()
        .enumerate()
        .map(|(idx, sh)| {
            if !shdr_occupies_file(sh) {
                return (sh.sh_offset, sh.sh_offset, 0);
            }
            let actual = section_data[idx].len() as u64;
            let delta = actual as i64 - sh.sh_size as i64;
            (sh.sh_offset, sh.sh_offset + sh.sh_size, delta)
        })
        .collect();

    // 1. Update each section's sh_size (in place) and shift its
    //    sh_offset by the cumulative delta from earlier
    //    (lower-offset) sections.
    let mut events: Vec<(u64, i64)> = snapshot
        .iter()
        .filter_map(|(_, end, d)| (*d != 0).then_some((*end, *d)))
        .collect();
    events.sort_by_key(|(off, _)| *off);
    let shift_for = |off: u64| -> i64 {
        events
            .iter()
            .filter(|(boundary, _)| *boundary <= off)
            .map(|(_, d)| *d)
            .sum()
    };

    // 2. Apply to sections.
    for (idx, sh) in shdrs.iter_mut().enumerate() {
        if shdr_occupies_file(sh) {
            sh.sh_size = section_data[idx].len() as u64;
        }
        let original_off = snapshot[idx].0;
        let shift = shift_for(original_off);
        sh.sh_offset = sh.sh_offset.saturating_add_signed(shift);
    }

    // 3. Apply to program headers. A segment's p_filesz grows by
    //    the total delta of sections living inside its OLD
    //    range; its p_offset shifts by the cumulative delta at
    //    its original position.
    for ph in phdrs.iter_mut() {
        let seg_start = ph.p_offset;
        let seg_end = ph.p_offset + ph.p_filesz;
        let mut growth: i64 = 0;
        for (idx, sh) in shdrs.iter().enumerate() {
            let (old_off, old_end, d) = snapshot[idx];
            if d == 0 {
                continue;
            }
            let _ = sh;
            if seg_start <= old_off && old_end <= seg_end {
                growth += d;
            }
        }
        let off_shift = shift_for(seg_start);
        ph.p_offset = ph.p_offset.saturating_add_signed(off_shift);
        ph.p_vaddr = ph.p_vaddr.saturating_add_signed(off_shift);
        ph.p_paddr = ph.p_paddr.saturating_add_signed(off_shift);
        if growth != 0 {
            ph.p_filesz = ph.p_filesz.saturating_add_signed(growth);
            ph.p_memsz = ph.p_memsz.saturating_add_signed(growth);
        }
    }

    // 4. Padding chunks shift by the cumulative delta at their
    //    original offset.
    for (off, _bytes) in padding.iter_mut() {
        let shift = shift_for(*off);
        *off = off.saturating_add_signed(shift);
    }

    // 5. The section-header table moves if it lives past a
    //    changed section.
    let sh_shift = shift_for(ehdr.e_shoff);
    ehdr.e_shoff = ehdr.e_shoff.saturating_add_signed(sh_shift);

    // 6. file_size grows by the sum of all deltas.
    let total: i64 = snapshot.iter().map(|(_, _, d)| *d).sum();
    *file_size = file_size.saturating_add_signed(total);
}

/// Map the `bits` field of `@module` (32 or 64) to the corresponding
/// [`ElfClass`].
fn read_elf_class(module: &Module) -> Result<ElfClass, ElfLowerError> {
    for f in &module.fields {
        if f.name == "bits" {
            if let Value::Int(n) = &f.value {
                return match *n {
                    32 => Ok(ElfClass::Elf32),
                    64 => Ok(ElfClass::Elf64),
                    other => Err(ElfLowerError::ValueOutOfRange {
                        field: "bits".into(),
                        value: other,
                        target: "ElfClass (only 32 or 64 are valid)",
                    }),
                };
            }
            return Err(ElfLowerError::WrongShape {
                field: "bits".into(),
                expected: "integer".into(),
            });
        }
    }
    Err(ElfLowerError::MissingField {
        field: "bits".into(),
    })
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

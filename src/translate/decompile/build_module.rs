//! Build the `@module { … }` AST node from ELF header data.
//!
//! The `build` sub-block contains every byte of header metadata the
//! lower path needs to reconstruct the binary. The names of the
//! sub-fields mirror the ELF spec verbatim so a round-trip via source
//! preserves enough information for [`Elf64File::from_parts`] to
//! reproduce the file's layout exactly.
//!
//! [`Elf64File::from_parts`]: crate::format::elf::Elf64File::from_parts

use crate::ast::{Field, Module, Value};
use crate::format::elf::{Elf64File, Phdr64};

/// Padding bytes given by a `@section` block (code of an ELF without
/// section headers) instead of a byte list.
#[derive(Debug, Clone)]
pub struct CodePadding {
    /// File offset.
    pub offset: u64,
    pub len: u64,
    /// Load address of its first byte.
    pub addr: u64,
    /// The `@section` block holding it.
    pub name: String,
}

/// The executable `PT_LOAD` parts of `elf`'s padding (all of its file
/// content when there are no section headers).
#[must_use]
pub fn code_padding(elf: &Elf64File) -> Vec<CodePadding> {
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 1;
    let mut out = Vec::new();
    for (i, ph) in elf.phdrs.iter().enumerate() {
        if ph.p_type != PT_LOAD || ph.p_flags & PF_X == 0 || ph.p_filesz == 0 {
            continue;
        }
        let (lo, hi) = (ph.p_offset, ph.p_offset.saturating_add(ph.p_filesz));
        for (off, bytes) in elf.padding() {
            let (start, end) = (lo.max(*off), hi.min(off + bytes.len() as u64));
            let overlaps = out
                .iter()
                .any(|c: &CodePadding| start < c.offset + c.len && c.offset < end);
            if start < end && !overlaps {
                out.push(CodePadding {
                    offset: start,
                    len: end - start,
                    addr: ph.p_vaddr + (start - ph.p_offset),
                    name: format!("segment{i}@0x{start:x}"),
                });
            }
        }
    }
    out.sort_by_key(|c| c.offset);
    out
}

/// Construct a [`Module`] capturing the full ELF metadata: the
/// interpreted header fields, the program-header table, the section-
/// header table, and the file padding regions; the `code` parts of the
/// padding name the `@section` block that holds them instead.
#[must_use]
pub fn build_module(elf: &Elf64File, code: &[CodePadding]) -> Module {
    let arch = crate::arch::opaque::elf_machine_name(elf.ehdr.e_machine).unwrap_or("unknown");
    let abi = guess_abi(elf);

    let build = Value::Block(vec![
        // Raw ehdr bytes that the parsed `Ehdr64` doesn't already
        // surface as friendly module fields.
        field(
            "e_ident",
            Value::List(elf.ehdr.e_ident.iter().copied().map(byte_value).collect()),
        ),
        field("e_machine", Value::Int(u64::from(elf.ehdr.e_machine))),
        field("e_version", Value::Int(u64::from(elf.ehdr.e_version))),
        field("e_phoff", Value::Int(elf.ehdr.e_phoff)),
        field("e_shoff", Value::Int(elf.ehdr.e_shoff)),
        field("e_flags", Value::Int(u64::from(elf.ehdr.e_flags))),
        field("e_ehsize", Value::Int(u64::from(elf.ehdr.e_ehsize))),
        field("e_phentsize", Value::Int(u64::from(elf.ehdr.e_phentsize))),
        field("e_phnum", Value::Int(u64::from(elf.ehdr.e_phnum))),
        field("e_shentsize", Value::Int(u64::from(elf.ehdr.e_shentsize))),
        field("e_shnum", Value::Int(u64::from(elf.ehdr.e_shnum))),
        field("e_shstrndx", Value::Int(u64::from(elf.ehdr.e_shstrndx))),
        field("file_size", Value::Int(elf.file_size())),
        // Program headers — one record per phdr, in original order.
        field(
            "phdrs",
            Value::List(elf.phdrs.iter().map(phdr_block).collect()),
        ),
        // Section headers — one record per shdr, in original order.
        // Each record carries an extra `name` field (the resolved
        // section name) used by the lower path to match `@section`
        // blocks; `sh_name` (the strtab offset) is what gets written
        // to disk.
        field(
            "shdrs",
            Value::List(
                elf.shdrs
                    .iter()
                    .enumerate()
                    .map(|(i, sh)| shdr_block(elf, i, sh))
                    .collect(),
            ),
        ),
        // Inter-region padding: `(file_offset, bytes)` per gap.
        //
        // All-zero entries are filtered out: `Elf64File::write_to_vec`
        // initialises its output buffer to zeros before overlaying
        // structured regions, so an omitted zero-padding region
        // produces the same bytes as a listed one. Keeping these
        // entries explicit just bloats the source (a single padding
        // region can be hundreds of bytes long in stripped binaries).
        // Non-zero padding (0xCC fills, debug guards, etc.) still
        // round-trips through its explicit byte list.
        field("padding", Value::List(padding_entries(elf, code))),
    ]);

    let bits = match elf.class {
        crate::format::elf::ElfClass::Elf32 => 32,
        crate::format::elf::ElfClass::Elf64 => 64,
    };

    Module {
        fields: vec![
            field("arch", Value::String(arch.into())),
            field("abi", Value::String(abi.into())),
            field("format", Value::String("elf".into())),
            field("bits", Value::Int(bits)),
            field("endian", Value::String("little".into())),
            field("type", Value::Int(u64::from(elf.ehdr.e_type))),
            field("entry", Value::Int(elf.ehdr.e_entry)),
            field("build", build),
        ],
    }
}

fn byte_value(b: u8) -> Value {
    Value::Int(u64::from(b))
}

fn phdr_block(p: &Phdr64) -> Value {
    Value::Block(vec![
        field("p_type", Value::Int(u64::from(p.p_type))),
        field("p_flags", Value::Int(u64::from(p.p_flags))),
        field("p_offset", Value::Int(p.p_offset)),
        field("p_vaddr", Value::Int(p.p_vaddr)),
        field("p_paddr", Value::Int(p.p_paddr)),
        field("p_filesz", Value::Int(p.p_filesz)),
        field("p_memsz", Value::Int(p.p_memsz)),
        field("p_align", Value::Int(p.p_align)),
    ])
}

fn shdr_block(elf: &Elf64File, idx: usize, s: &crate::format::elf::Shdr64) -> Value {
    let name = elf.section_name(idx).unwrap_or("").to_string();
    Value::Block(vec![
        field("name", Value::String(name)),
        field("sh_name", Value::Int(u64::from(s.sh_name))),
        field("sh_type", Value::Int(u64::from(s.sh_type))),
        field("sh_flags", Value::Int(s.sh_flags)),
        field("sh_addr", Value::Int(s.sh_addr)),
        field("sh_offset", Value::Int(s.sh_offset)),
        field("sh_size", Value::Int(s.sh_size)),
        field("sh_link", Value::Int(u64::from(s.sh_link))),
        field("sh_info", Value::Int(u64::from(s.sh_info))),
        field("sh_addralign", Value::Int(s.sh_addralign)),
        field("sh_entsize", Value::Int(s.sh_entsize)),
    ])
}

/// The padding entries: byte lists (all-zero ones left out), split
/// around the `code` parts, which name their `@section` block instead.
fn padding_entries(elf: &Elf64File, code: &[CodePadding]) -> Vec<Value> {
    let mut out = Vec::new();
    let bytes_entry = |out: &mut Vec<Value>, offset: u64, bytes: &[u8]| {
        if bytes.iter().any(|&b| b != 0) {
            out.push(padding_block(&(offset, bytes.to_vec())));
        }
    };
    for (off, bytes) in elf.padding() {
        let end = off + bytes.len() as u64;
        let slice = |from: u64, to: u64| &bytes[(from - off) as usize..(to - off) as usize];
        let mut at = *off;
        for c in code.iter().filter(|c| c.offset >= *off && c.offset < end) {
            bytes_entry(&mut out, at, slice(at, c.offset));
            out.push(Value::Block(vec![
                field("offset", Value::Int(c.offset)),
                field("section", Value::String(c.name.clone())),
            ]));
            at = c.offset + c.len;
        }
        bytes_entry(&mut out, at, slice(at, end));
    }
    out
}

fn padding_block(p: &(u64, Vec<u8>)) -> Value {
    Value::Block(vec![
        field("offset", Value::Int(p.0)),
        field(
            "bytes",
            Value::List(p.1.iter().copied().map(byte_value).collect()),
        ),
    ])
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

fn guess_abi(elf: &Elf64File) -> &'static str {
    match elf.ehdr.e_ident[7] {
        0 => "sysv",
        _ => "custom",
    }
}

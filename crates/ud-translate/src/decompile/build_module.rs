//! Build the `@module { … }` AST node from ELF header data.
//!
//! The `build` sub-block contains every byte of header metadata the
//! lower path needs to reconstruct the binary. The names of the
//! sub-fields mirror the ELF spec verbatim so a round-trip via source
//! preserves enough information for [`Elf64File::from_parts`] to
//! reproduce the file's layout exactly.
//!
//! [`Elf64File::from_parts`]: ud_format::elf::Elf64File::from_parts

use ud_ast::{Field, Module, Value};
use ud_format::elf::{Elf64File, Phdr64, EM_X86_64};

/// Construct a [`Module`] capturing the full ELF metadata: the
/// interpreted header fields, the program-header table, the section-
/// header table, and the file padding regions.
#[must_use]
pub fn build_module(elf: &Elf64File) -> Module {
    let arch = match elf.ehdr.e_machine {
        EM_X86_64 => "x86_64",
        _ => "unknown",
    };
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
        field(
            "padding",
            Value::List(
                elf.padding()
                    .iter()
                    .filter(|(_, bytes)| bytes.iter().any(|&b| b != 0))
                    .map(padding_block)
                    .collect(),
            ),
        ),
    ]);

    let bits = match elf.class {
        ud_format::elf::ElfClass::Elf32 => 32,
        ud_format::elf::ElfClass::Elf64 => 64,
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

fn shdr_block(elf: &Elf64File, idx: usize, s: &ud_format::elf::Shdr64) -> Value {
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

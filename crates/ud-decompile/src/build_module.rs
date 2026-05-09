//! Build the `@module { … }` AST node from ELF header data.

use ud_ast::{Field, Module, Value};
use ud_format_elf::{Elf64File, EM_X86_64};

/// Construct a [`Module`] capturing the file-level context: arch / abi
/// / format / bits / endian (interpreted), plus a `build` block holding
/// the non-deterministic header bits we'd need to round-trip exactly.
#[must_use]
pub fn build_module(elf: &Elf64File) -> Module {
    let arch = match elf.ehdr.e_machine {
        EM_X86_64 => "x86_64",
        _ => "unknown",
    };
    let abi = guess_abi(elf);

    let build = Value::Block(vec![
        Field {
            name: "e_flags".into(),
            value: Value::Int(u64::from(elf.ehdr.e_flags)),
        },
        Field {
            name: "e_ident".into(),
            value: Value::List(
                elf.ehdr
                    .e_ident
                    .iter()
                    .map(|b| Value::Int(u64::from(*b)))
                    .collect(),
            ),
        },
    ]);

    Module {
        fields: vec![
            field("arch", Value::String(arch.into())),
            field("abi", Value::String(abi.into())),
            field("format", Value::String("elf".into())),
            field("bits", Value::Int(64)),
            field("endian", Value::String("little".into())),
            field("type", Value::Int(u64::from(elf.ehdr.e_type))),
            field("entry", Value::Int(elf.ehdr.e_entry)),
            field("build", build),
        ],
    }
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

fn guess_abi(elf: &Elf64File) -> &'static str {
    // e_ident[7] = OS/ABI. SysV (= 0) is the overwhelming majority; we
    // surface it explicitly and treat anything else as "custom" until
    // a dedicated mapping is needed.
    match elf.ehdr.e_ident[7] {
        0 => "sysv",
        _ => "custom",
    }
}

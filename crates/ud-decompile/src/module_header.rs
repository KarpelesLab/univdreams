//! Emit the `@module { ... }` header that pins file-level context.
//!
//! Values are read straight off the ELF: `arch` and `bits` from
//! `e_machine` and the e_ident class byte; ABI is inferred from the
//! OS/ABI bytes; non-deterministic header bits land in a `build`
//! sub-block to be re-emitted verbatim on recompile.

use std::fmt::Write as _;

use ud_format_elf::{Elf64File, EM_X86_64};

/// Format the `@module` block at the top of the file. Trailing newline
/// included so the caller can concatenate without bookkeeping.
#[must_use]
pub fn emit_module_header(elf: &Elf64File) -> String {
    let arch = match elf.ehdr.e_machine {
        EM_X86_64 => "x86_64",
        _ => "unknown",
    };
    let abi = guess_abi(elf);

    let mut out = String::new();
    writeln!(out, "@module {{").unwrap();
    writeln!(out, "    arch:    \"{arch}\",").unwrap();
    writeln!(out, "    abi:     \"{abi}\",").unwrap();
    writeln!(out, "    format:  \"elf\",").unwrap();
    writeln!(out, "    bits:    64,").unwrap();
    writeln!(out, "    endian:  \"little\",").unwrap();
    writeln!(out, "    type:    0x{:x},", elf.ehdr.e_type).unwrap();
    writeln!(out, "    entry:   0x{:x},", elf.ehdr.e_entry).unwrap();
    writeln!(out, "    build: {{").unwrap();
    writeln!(out, "        e_flags:    0x{:x},", elf.ehdr.e_flags).unwrap();
    writeln!(
        out,
        "        e_ident:    {},",
        format_e_ident(&elf.ehdr.e_ident)
    )
    .unwrap();
    writeln!(out, "    }},").unwrap();
    writeln!(out, "}}").unwrap();
    out
}

fn guess_abi(elf: &Elf64File) -> &'static str {
    // e_ident[7] = OS/ABI. SysV (= 0) is the overwhelming majority; we
    // surface it explicitly and treat anything else as "custom" until a
    // dedicated mapping is needed.
    match elf.ehdr.e_ident[7] {
        0 => "sysv",
        _ => "custom",
    }
}

fn format_e_ident(ident: &[u8; 16]) -> String {
    let mut s = String::from("[");
    for (i, b) in ident.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        write!(s, "0x{b:02x}").unwrap();
    }
    s.push(']');
    s
}

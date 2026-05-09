//! Decompile a parsed ELF into a `.ud` AST.
//!
//! The output of [`decompile`] is a [`ud_ast::UdFile`] in canonical
//! shape: a `@module { … }` header pinned from the ELF header, plus
//! one [`ud_ast::Item::Function`] per discovered function (or a
//! [`ud_ast::Item::Comment`] note for ones whose bytes can't be
//! located).
//!
//! Function bodies are sequences of [`ud_ast::Stmt::Asm`]
//! (one per decoded instruction, formatted in Intel syntax) plus
//! [`ud_ast::Stmt::Comment`] markers surfacing block boundaries and
//! direct-branch targets.
//!
//! The accompanying [`decompile_to_text`] helper is just
//! `ud_ast::emit(&decompile(elf)?)`; it's the function the CLI uses.
//! Going through the AST means the canonical text form lives in one
//! place ([`ud_ast::emit`]) and `parse(decompile_to_text(elf))` is
//! structurally identical to `decompile(elf)` — defended by the test
//! suite.

#![allow(clippy::cast_possible_truncation)]

mod build_function;
mod build_module;

use ud_analysis::discover_functions;
use ud_arch_x86::{decode, lift_function, Bitness};
use ud_ast::{Item, UdFile};
use ud_format_elf::{Elf64File, EM_X86_64};

/// Errors surfaced by the top-level entry point.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("only ELF64-LE x86_64 inputs are supported; got e_machine = {0}")]
    UnsupportedMachine(u16),

    #[error(transparent)]
    Analysis(#[from] ud_analysis::Error),

    #[error(transparent)]
    Decode(#[from] ud_arch_x86::Error),

    #[error(transparent)]
    Lift(#[from] ud_arch_x86::LiftError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Build the AST for `elf`. The structural form is the primary output
/// of decompilation; [`decompile_to_text`] is a thin convenience.
pub fn decompile(elf: &Elf64File) -> Result<UdFile> {
    if elf.ehdr.e_machine != EM_X86_64 {
        return Err(Error::UnsupportedMachine(elf.ehdr.e_machine));
    }

    let module = build_module::build_module(elf);
    let mut items = Vec::new();

    let map = discover_functions(elf)?;
    for f in map.iter() {
        if f.size == 0 {
            items.push(Item::Comment(format!(
                "note: `{}` at 0x{:x} has no known size; not emitted",
                f.name, f.addr.0
            )));
            continue;
        }
        let Some(slice) = slice_function_bytes(elf, f.addr.0, f.size) else {
            items.push(Item::Comment(format!(
                "note: `{}` at 0x{:x} not found in any executable section; not emitted",
                f.name, f.addr.0
            )));
            continue;
        };
        let insns = decode(Bitness::Bits64, slice, f.addr.0)?;
        let lifted = lift_function(f.name.clone(), &insns)?;
        items.push(Item::Function(build_function::build_function(&lifted)));
    }

    Ok(UdFile { module, items })
}

/// Convenience: build the AST and pretty-print it to canonical text.
pub fn decompile_to_text(elf: &Elf64File) -> Result<String> {
    let ast = decompile(elf)?;
    Ok(ud_ast::emit(&ast))
}

fn slice_function_bytes(elf: &Elf64File, addr: u64, size: u64) -> Option<&[u8]> {
    if size == 0 {
        return None;
    }
    for (_, sh, data) in elf.sections() {
        let sh_end = sh.sh_addr.saturating_add(sh.sh_size);
        if sh.sh_addr <= addr && addr.saturating_add(size) <= sh_end {
            let offset = (addr - sh.sh_addr) as usize;
            let slice_end = offset + size as usize;
            if slice_end <= data.len() {
                return Some(&data[offset..slice_end]);
            }
        }
    }
    None
}

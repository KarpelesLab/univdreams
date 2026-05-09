//! Emit a `.ud` source file from an analyzed binary.
//!
//! v0 scope: produce a parseable-shaped `.ud` file with
//!
//! * a `@module { ... }` header pinned from the ELF header
//! * one `fn <name>() { ... }` per discovered function
//! * one `@asm("...")` line per instruction (the universal escape
//!   hatch — every later phase replaces these with structured
//!   expressions where it can lift them)
//!
//! The output is not yet fully recompilable: padding between functions
//! and non-text sections aren't represented. That's the next layer of
//! work. What we *do* defend, even at v0:
//!
//! * Determinism. Same input bytes always produce identical output
//!   text.
//! * Function-byte-identity. The bytes covered by the emitted `fn`
//!   blocks reconstitute exactly what was in the binary's executable
//!   sections at those addresses.

#![allow(clippy::cast_possible_truncation)]

use std::fmt::Write as _;

mod emitter;
mod module_header;

pub use emitter::emit_function;
pub use module_header::emit_module_header;

use ud_analysis::discover_functions;
use ud_arch_x86::{decode, lift_function, Bitness};
use ud_format_elf::{Elf64File, EM_X86_64};

/// Errors surfaced by the top-level decompile entry point.
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

/// Top-level entry point: turn a parsed ELF into a `.ud` source string.
///
/// Discovers functions, lifts each one to IR, and writes the canonical
/// `.ud` text. Functions whose bytes can't be located (no recorded
/// size after merging every discovery source, not in any executable
/// section) are emitted as a stub with a `// note:` comment so the
/// reader knows about them.
pub fn decompile(elf: &Elf64File) -> Result<String> {
    if elf.ehdr.e_machine != EM_X86_64 {
        return Err(Error::UnsupportedMachine(elf.ehdr.e_machine));
    }

    let mut out = String::new();
    out.push_str(&emit_module_header(elf));
    out.push('\n');

    let map = discover_functions(elf)?;
    for f in map.iter() {
        if f.size == 0 {
            writeln!(
                out,
                "// note: `{}` at 0x{:x} has no known size; not emitted\n",
                f.name, f.addr.0
            )
            .unwrap();
            continue;
        }
        let Some(slice) = slice_function_bytes(elf, f.addr.0, f.size) else {
            writeln!(
                out,
                "// note: `{}` at 0x{:x} not found in any executable section; not emitted\n",
                f.name, f.addr.0
            )
            .unwrap();
            continue;
        };
        let insns = decode(Bitness::Bits64, slice, f.addr.0)?;
        let lifted = lift_function(f.name.clone(), &insns)?;
        out.push_str(&emit_function(&lifted));
        out.push('\n');
    }

    Ok(out)
}

/// Locate the slice of on-disk bytes covering the address range
/// `[addr, addr + size)`. Returns `None` if no single section contains
/// the range.
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

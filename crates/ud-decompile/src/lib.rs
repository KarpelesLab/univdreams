//! Decompile a parsed ELF into a `.ud` AST.
//!
//! The output of [`decompile`] is a [`ud_ast::UdFile`] in canonical
//! shape:
//!
//! * A `@module { … }` header pinned from the ELF header.
//! * A top-level `@section("name", 0x…) { … }` block per ELF section
//!   that has on-disk content (everything except NULL, NOBITS, and
//!   debug-info sections without a virtual address). Section bodies
//!   contain `fn` declarations for discovered functions and `@raw`
//!   blocks for everything between/around them — alignment padding,
//!   data section content, etc.
//! * `// note: …` comments at the top level for functions we know
//!   exist but couldn't locate bytes for (no recorded size, missing
//!   from any executable section).
//!
//! The byte-identity invariant the decompiler defends:
//!
//! > For every section emitted, concatenating the bytes of its items
//! > in source order reproduces the section's on-disk content exactly.
//!
//! This is the precondition for full source-level binary round-trip
//! once `phdr` / `shdr` metadata makes it into `@module` (next
//! iteration).
//!
//! [`decompile_to_text`] is the thin wrapper that calls
//! [`ud_ast::emit`] on the AST.

#![allow(clippy::cast_possible_truncation)]

mod build_function;
mod build_module;

use ud_analysis::{discover_functions, FunctionMap};
use ud_arch_x86::{decode, lift_function, Bitness};
use ud_ast::{Item, UdFile};
use ud_format_elf::{Elf64File, Shdr64, EM_X86_64};

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
    let map = discover_functions(elf)?;

    let mut items = Vec::new();

    // Top-level notes for functions we know about but can't body.
    for f in map.iter() {
        if f.size == 0 {
            items.push(Item::Comment(format!(
                "note: `{}` at 0x{:x} has no known size; not bodied",
                f.name, f.addr.0
            )));
        } else if !function_lives_in_a_section(elf, f.addr.0, f.size) {
            items.push(Item::Comment(format!(
                "note: `{}` at 0x{:x} not in any on-disk section; not bodied",
                f.name, f.addr.0
            )));
        }
    }

    // One @section block per ELF section worth emitting.
    for (idx, sh, data) in elf.sections() {
        if !section_is_emittable(sh) {
            continue;
        }
        let name = elf
            .section_name(idx)
            .map_or_else(|| format!("section{idx}"), str::to_string);
        let section_items = build_section_items(elf, sh, data, &map)?;
        items.push(Item::Section {
            name,
            addr: sh.sh_addr,
            items: section_items,
        });
    }

    Ok(UdFile { module, items })
}

/// Convenience: build the AST and pretty-print it to canonical text.
pub fn decompile_to_text(elf: &Elf64File) -> Result<String> {
    let ast = decompile(elf)?;
    Ok(ud_ast::emit(&ast))
}

/// Whether a section will be emitted as `@section`. Skips sections
/// without on-disk content (NULL, NOBITS, zero-size). Sections with
/// `sh_addr == 0` (debug info, `.comment`, `.symtab`, …) ARE emitted —
/// their items are addressed in [0, sh_size) since virtual addresses
/// don't apply, and the lower path matches them to shdrs by name.
fn section_is_emittable(sh: &Shdr64) -> bool {
    const SHT_NULL: u32 = 0;
    const SHT_NOBITS: u32 = 8;
    sh.sh_type != SHT_NULL && sh.sh_type != SHT_NOBITS && sh.sh_size > 0
}

fn function_lives_in_a_section(elf: &Elf64File, addr: u64, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let end = addr.saturating_add(size);
    for (_, sh, _) in elf.sections() {
        let sh_end = sh.sh_addr.saturating_add(sh.sh_size);
        if sh.sh_addr <= addr && end <= sh_end {
            return true;
        }
    }
    false
}

/// Build the items inside one `@section` block: any functions whose
/// address range falls inside the section, plus `@raw` blocks for
/// every byte not covered by a function.
fn build_section_items(
    _elf: &Elf64File,
    sh: &Shdr64,
    data: &[u8],
    map: &FunctionMap,
) -> Result<Vec<Item>> {
    let section_start = sh.sh_addr;
    let section_end = sh.sh_addr.saturating_add(sh.sh_size);

    // Functions whose entire range falls inside this section.
    let mut funcs: Vec<_> = map
        .iter()
        .filter(|f| {
            f.size > 0
                && f.addr.0 >= section_start
                && f.addr.0.saturating_add(f.size) <= section_end
        })
        .collect();
    funcs.sort_by_key(|f| f.addr.0);

    let mut out = Vec::new();
    let mut cursor = section_start;

    for f in &funcs {
        // Gap before this function — emit raw bytes.
        if cursor < f.addr.0 {
            let lo = (cursor - section_start) as usize;
            let hi = (f.addr.0 - section_start) as usize;
            out.push(Item::Raw {
                addr: cursor,
                bytes: data[lo..hi].to_vec(),
            });
        }
        // The function itself.
        let lo = (f.addr.0 - section_start) as usize;
        let hi = lo + f.size as usize;
        let slice = &data[lo..hi];
        let insns = decode(Bitness::Bits64, slice, f.addr.0)?;
        let lifted = lift_function(f.name.clone(), &insns)?;
        out.push(Item::Function(build_function::build_function(&lifted)));
        cursor = f.addr.0.saturating_add(f.size);
    }

    // Trailing gap to the section's end.
    if cursor < section_end {
        let lo = (cursor - section_start) as usize;
        out.push(Item::Raw {
            addr: cursor,
            bytes: data[lo..].to_vec(),
        });
    }

    Ok(out)
}

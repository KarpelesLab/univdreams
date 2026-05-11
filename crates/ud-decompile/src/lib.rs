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

mod aarch64;
mod build_function;
mod build_module;
mod data_lookup;
mod patterns;
pub mod pe;
pub mod raw6502;

pub use data_lookup::DataLookup;
pub use pe::{decompile_pe, decompile_pe_to_text};
pub use raw6502::{decompile_raw_6502, decompile_raw_6502_to_text};

use std::collections::HashMap;

use ud_analysis::{discover_functions, FunctionMap};
use ud_arch_x86::{decode, lift_function, Bitness};
use ud_ast::{Item, UdFile};
use ud_debug::DebugFunction;
use ud_format_elf::{Elf64File, ElfClass, Shdr64, EM_386, EM_AARCH64, EM_X86_64};

/// Which arch backend to drive for a given ELF.
#[derive(Debug, Clone, Copy)]
enum Arch {
    X86 { bitness: Bitness },
    Aarch64,
}

/// Errors surfaced by the top-level entry point.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("only x86 ELF inputs are supported; got e_machine = {0}")]
    UnsupportedMachine(u16),

    #[error(transparent)]
    Analysis(#[from] ud_analysis::Error),

    #[error(transparent)]
    Decode(#[from] ud_arch_x86::Error),

    #[error(transparent)]
    Lift(#[from] ud_arch_x86::LiftError),

    #[error(transparent)]
    Debug(#[from] ud_debug::DebugError),

    #[error(transparent)]
    Aarch64Decode(ud_arch_aarch64::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Build the AST for `elf`. The structural form is the primary output
/// of decompilation; [`decompile_to_text`] is a thin convenience.
pub fn decompile(elf: &Elf64File) -> Result<UdFile> {
    let arch = match (elf.class, elf.ehdr.e_machine) {
        (ElfClass::Elf64, EM_X86_64) => Arch::X86 {
            bitness: Bitness::Bits64,
        },
        (ElfClass::Elf32, EM_386) => Arch::X86 {
            bitness: Bitness::Bits32,
        },
        (ElfClass::Elf64, EM_AARCH64) => Arch::Aarch64,
        _ => return Err(Error::UnsupportedMachine(elf.ehdr.e_machine)),
    };

    let module = build_module::build_module(elf);
    let map = discover_functions(elf)?;
    let debug_by_addr: HashMap<u64, DebugFunction> = ud_debug::read_debug_info(elf)?;

    // Build an address → name map once; passed to every build_function so
    // call sites can be annotated with target names.
    let name_at: HashMap<u64, String> = map.iter().map(|f| (f.addr.0, f.name.clone())).collect();

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
        let section_items =
            build_section_items(elf, sh, data, &map, &debug_by_addr, &name_at, arch)?;
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
    elf: &Elf64File,
    sh: &Shdr64,
    data: &[u8],
    map: &FunctionMap,
    debug_by_addr: &HashMap<u64, DebugFunction>,
    name_at: &HashMap<u64, String>,
    arch: Arch,
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
        let fn_decl = match arch {
            Arch::X86 { bitness } => {
                let insns = decode(bitness, slice, f.addr.0)?;
                let lifted = lift_function(f.name.clone(), &insns)?;
                let debug = debug_by_addr.get(&f.addr.0);
                build_function::build_function(&lifted, debug, name_at, elf)
            }
            Arch::Aarch64 => {
                let insns =
                    ud_arch_aarch64::decode(slice, f.addr.0).map_err(Error::Aarch64Decode)?;
                let lifted = ud_arch_aarch64::lift_function(f.name.clone(), &insns);
                aarch64::build_function(&lifted, name_at)
            }
        };
        out.push(Item::Function(fn_decl));
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

//! Debug-info reader: turns `.debug_info` (DWARF) into typed function
//! signatures the decompiler can attach to its `FnDecl` AST nodes.
//!
//! v0 scope: x86-64 ELF, DWARF 4/5. Subprogram DIEs yield names,
//! addresses, and parameter / return types. Type recovery covers
//! DW_TAG_base_type (primitives) and DW_TAG_pointer_type (recursively
//! resolved); other tags produce [`ud_ast::Type::Unknown`].
//!
//! Pluggable parsers for PDB, stabs, and Mach-O `.dSYM` will land in
//! this same crate as additional modules.

#![allow(clippy::cast_possible_truncation)]

mod dwarf;

pub use dwarf::{DebugError, DebugFunction};

use std::collections::HashMap;

use ud_format::elf::Elf64File;

/// Read every supported debug-info section from `elf` and return a
/// map keyed by function start address. Empty when no debug info is
/// present.
///
/// Today this only consults `.debug_info` (DWARF). It will grow as
/// other formats come online.
pub fn read_debug_info(elf: &Elf64File) -> Result<HashMap<u64, DebugFunction>, DebugError> {
    let mut by_addr = HashMap::new();
    for f in dwarf::read_subprograms(elf)? {
        by_addr.insert(f.addr, f);
    }
    Ok(by_addr)
}

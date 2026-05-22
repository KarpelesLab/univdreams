//! Discover the ELF entry point as a function.
//!
//! The loader jumps to `e_entry` regardless of whether the
//! address appears as a call target anywhere else. For Solana
//! BPF programs that's the only path that reaches
//! `entry_point` — nothing in `.text` calls it directly — so
//! without this source the address would get buried inside an
//! earlier `sub_<addr>` whose lifted body grows large enough
//! to cover it. The function-discovery merge then treats it as
//! "not a function," and downstream layers (function summaries,
//! per-fn idiom annotation) miss the program's actual entry.
//!
//! Confidence: address-definitive (the loader trusts `e_entry`)
//! but size-blind (no `e_entry_size` field in the ELF header).
//! The size-filling pass in [`crate::fill_in_sizes_from_neighbors`]
//! closes that gap by walking to the next discovered boundary.
//!
//! Naming policy: when the target machine is BPF / SBF the
//! placeholder name is `entry_point` (the Solana convention);
//! otherwise we fall back to `sub_<addr>` so a higher-
//! confidence source (`.symtab`, `.dynsym`) can override
//! cleanly.

use ud_core::VAddr;
use ud_format::elf::{Elf64File, EM_BPF, EM_SBF};

use crate::{Function, FunctionSource};

/// Build the per-binary entry-point list. Always returns at
/// most one entry — the ELF header has exactly one `e_entry`.
/// Returns an empty vector when `e_entry == 0` (some shared
/// objects elide it).
#[must_use]
pub fn discover_entry_point(elf: &Elf64File) -> Vec<Function> {
    if elf.ehdr.e_entry == 0 {
        return Vec::new();
    }
    let name = entry_name_for(elf.ehdr.e_machine);
    vec![Function {
        addr: VAddr(elf.ehdr.e_entry),
        size: 0,
        name: name.to_string(),
        sources: vec![FunctionSource::Entry],
    }]
}

fn entry_name_for(e_machine: u16) -> &'static str {
    match e_machine {
        EM_BPF | EM_SBF => "entry_point",
        _ => "_start",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_for_bpf_is_entry_point() {
        assert_eq!(entry_name_for(EM_BPF), "entry_point");
        assert_eq!(entry_name_for(EM_SBF), "entry_point");
    }

    #[test]
    fn name_for_x86_is_start() {
        assert_eq!(entry_name_for(62), "_start"); // EM_X86_64
        assert_eq!(entry_name_for(3), "_start"); // EM_386
    }
}

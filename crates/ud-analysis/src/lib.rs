//! Analysis passes over loaded binaries.
//!
//! Function discovery layers signals from highest to lowest confidence:
//!
//! 1. The full symbol table (`.symtab`) when present.
//! 2. The dynamic symbol table (`.dynsym`).
//! 3. Byte-pattern signatures (CRT helpers, libc primitives, …).
//! 4. `.eh_frame` (DWARF CFI) — names are addresses, but sizes are
//!    authoritative; survives stripping.
//!
//! Each [`Function`] in the produced [`FunctionMap`] records every
//! source that contributed to it. Names from higher-confidence sources
//! win over names from lower-confidence sources; sizes are merged
//! preserving any non-zero value.
//!
//! After all sources are merged, a final pass fills in sizes for
//! functions that no source supplied a size for (typically signature
//! matches), using the distance to the next discovered function in
//! the same address window.

#![allow(clippy::cast_possible_truncation)]

mod eh_frame;
mod function_map;
mod signatures;
mod symbols;

pub use eh_frame::{discover_from_eh_frame, EhFrameError};
pub use function_map::{Function, FunctionMap, FunctionSource};
pub use signatures::discover_from_signatures;
pub use symbols::{discover_from_symbol_tables, SymbolError};

use ud_core::VAddr;
use ud_format_elf::Elf64File;

/// Crate-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Symbol(#[from] SymbolError),
    #[error(transparent)]
    EhFrame(#[from] EhFrameError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Run every available discovery source and merge into a single
/// [`FunctionMap`].
///
/// Sources are run in order of ascending confidence so that, when the
/// merge resolves a name conflict, the higher-confidence record wins.
/// Provenance (`Function::sources`) accumulates from every source that
/// found the address.
///
/// After merging, a size-filling pass closes gaps for functions that
/// were only found via signatures or other size-less sources.
pub fn discover_functions(elf: &Elf64File) -> Result<FunctionMap> {
    let mut map = FunctionMap::new();

    for f in discover_from_eh_frame(elf)? {
        map.insert(f);
    }
    for f in discover_from_signatures(elf) {
        map.insert(f);
    }
    for f in discover_from_symbol_tables(elf)? {
        map.insert(f);
    }

    fill_in_sizes_from_neighbors(&mut map, elf);

    Ok(map)
}

/// For each function with `size == 0`, set its size to the distance to
/// the next function in the same executable section (or to the end of
/// the section, if it's the last). Functions without a containing
/// executable section keep `size = 0`.
fn fill_in_sizes_from_neighbors(map: &mut FunctionMap, elf: &Elf64File) {
    use ud_format_elf::SHF_EXECINSTR;

    let func_addrs: Vec<u64> = map.iter().map(|f| f.addr.0).collect();

    let exec_sections: Vec<(u64, u64)> = elf
        .sections()
        .filter(|(_, sh, _)| sh.sh_flags & SHF_EXECINSTR != 0 && sh.sh_size > 0)
        .map(|(_, sh, _)| (sh.sh_addr, sh.sh_addr.saturating_add(sh.sh_size)))
        .collect();

    let zero_sized: Vec<u64> = map
        .iter()
        .filter(|f| f.size == 0)
        .map(|f| f.addr.0)
        .collect();

    for addr in zero_sized {
        let Some(&(_, sec_end)) = exec_sections.iter().find(|(s, e)| addr >= *s && addr < *e)
        else {
            continue;
        };
        let next_in_section = func_addrs
            .iter()
            .copied()
            .filter(|&a| a > addr && a < sec_end)
            .min()
            .unwrap_or(sec_end);
        let new_size = next_in_section.saturating_sub(addr);
        map.insert(Function {
            addr: VAddr(addr),
            size: new_size,
            name: String::new(), // ignored on merge: name from existing wins (higher source)
            sources: Vec::new(),
        });
    }
}

//! Analysis passes over loaded binaries.
//!
//! Function discovery is the first pass online. It layers signals from
//! highest to lowest confidence:
//!
//! 1. The full symbol table (`.symtab`) when present.
//! 2. The dynamic symbol table (`.dynsym`).
//! 3. `.eh_frame` (DWARF CFI) — names are addresses, but sizes are
//!    authoritative; survives stripping.
//!
//! Each [`Function`] in the produced [`FunctionMap`] records every
//! source that contributed to it. Names from higher-confidence sources
//! win over names from lower-confidence sources; sizes are merged
//! preserving any non-zero value.
//!
//! Crate boundary: this crate consumes [`ud_format_elf::Elf64File`] and
//! produces structured analysis results. It does not interpret
//! instruction bytes — that's the arch backends' job.

#![allow(clippy::cast_possible_truncation)]

mod eh_frame;
mod function_map;
mod symbols;

pub use eh_frame::{discover_from_eh_frame, EhFrameError};
pub use function_map::{Function, FunctionMap, FunctionSource};
pub use symbols::{discover_from_symbol_tables, SymbolError};

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
/// Sources are run in order of increasing confidence so that, when the
/// merge resolves a conflict, the higher-confidence record's name and
/// size dominate. Provenance (`Function::sources`) accumulates from
/// every source that found the address.
pub fn discover_functions(elf: &Elf64File) -> Result<FunctionMap> {
    let mut map = FunctionMap::new();

    for f in discover_from_eh_frame(elf)? {
        map.insert(f);
    }
    for f in discover_from_symbol_tables(elf)? {
        map.insert(f);
    }

    Ok(map)
}

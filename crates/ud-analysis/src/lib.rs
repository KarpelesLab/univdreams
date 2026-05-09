//! Analysis passes over loaded binaries.
//!
//! At Phase 2 the only pass implemented is function discovery from the
//! symbol table. The shape of the [`FunctionMap`] is designed to absorb
//! additional sources (`.eh_frame`, prologue patterns, user overrides)
//! incrementally, with each function carrying provenance.
//!
//! Crate boundary: this crate consumes [`ud_format_elf::Elf64File`] and
//! produces structured analysis results. It does not interpret
//! instruction bytes — that's the arch backends' job.

#![allow(clippy::cast_possible_truncation)]

mod function_map;
mod symbols;

pub use function_map::{Function, FunctionMap, FunctionSource};
pub use symbols::{discover_from_symbol_tables, SymbolError};

/// Crate-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Symbol(#[from] SymbolError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

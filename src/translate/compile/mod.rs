//! `.ud` parser: text → AST.
//!
//! Hand-rolled lexer + recursive-descent parser. Accepts the canonical
//! form produced by [`crate::ast::emit`] plus reasonable whitespace
//! variations. Emits [`ParseError`] with a line/column for diagnostics.
//!
//! Round-trip property at the source level (defended by the test
//! suite):
//!
//! > * `parse(emit(ast))` is structurally equal to `ast`.
//! > * `emit(parse(canonical_text))` equals `canonical_text` byte-for-byte.

#![allow(clippy::cast_possible_truncation)]

mod lexer;
mod lower;
mod lower_elf;
mod lower_macho;
mod lower_ne;
mod lower_pe;
mod lower_raw;
mod lower_wasm;
mod module;
mod parser;
mod verify;

pub use module::resolve_arch_codec;

pub use lower::{
    LowerError, LoweredFunction, LoweredSection, lower_function_bytes, lower_function_bytes_at,
    lower_functions, lower_section_bytes, lower_sections,
};
pub use lower_elf::{ElfLowerError, build_elf64, lower_to_elf};
pub use lower_macho::{MachoLowerError, lower_to_macho};
pub use lower_ne::{NeLowerError, lower_to_ne};
pub use lower_pe::{PeLowerError, lower_to_pe};
pub use lower_raw::{RawLowerError, lower_to_raw};
pub use lower_wasm::{WasmLowerError, lower_to_wasm};
pub use parser::{ParseError, parse};
pub use verify::{AsmLocation, AsmWarning, verify_asm};

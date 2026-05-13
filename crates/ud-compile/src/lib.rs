//! `.ud` parser: text → AST.
//!
//! Hand-rolled lexer + recursive-descent parser. Accepts the canonical
//! form produced by [`ud_ast::emit`] plus reasonable whitespace
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
mod lower_pe;
mod lower_raw;
mod parser;
mod verify;

pub use lower::{
    lower_function_bytes, lower_functions, lower_section_bytes, lower_sections, LowerError,
    LoweredFunction, LoweredSection,
};
pub use lower_elf::{build_elf64, lower_to_elf, ElfLowerError};
pub use lower_macho::{lower_to_macho, MachoLowerError};
pub use lower_pe::{lower_to_pe, PeLowerError};
pub use lower_raw::{lower_to_raw, RawLowerError};
pub use parser::{parse, ParseError};
pub use verify::{verify_asm, AsmLocation, AsmWarning};

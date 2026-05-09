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
mod parser;

pub use parser::{parse, ParseError};

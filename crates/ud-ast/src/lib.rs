//! Abstract syntax tree for the `.ud` source language.
//!
//! This crate is the source of truth for what `.ud` *looks like*. The
//! pretty-printer in [`emit`] produces the canonical text form; both
//! the decompiler (which builds an AST and emits it) and the parser
//! (which reads text and builds an AST) speak in terms of these types.
//!
//! Round-trip property at the source level:
//!
//! > For any AST built by a producer, `parse(emit(ast)) == ast`. For
//! > any text in canonical form, `emit(parse(text)) == text`.
//!
//! Producers must therefore avoid AST shapes the pretty-printer would
//! re-canonicalise into a different shape (e.g. mismatched ordering of
//! `module.fields`). The pretty-printer is deterministic; the parser
//! is the source of permissiveness (multiple whitespace conventions,
//! all canonicalised on emit).

#![allow(clippy::cast_possible_truncation)]

mod emit;
mod types;

pub use emit::emit;
pub use types::{
    AttrValue, Attribute, EpilogueParams, Field, FnDecl, Item, LocalDecl, LocalKind, Module,
    Param, PrologueParams, Signature, Stmt, Type, UdFile, Value,
};

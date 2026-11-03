//! Headerless images of an architecture univdreams can't decode yet.
//!
//! The whole image becomes `@raw` blocks under a `format: "raw"`
//! module naming its architecture, so it compiles back byte for byte
//! and the architecture is recorded for when a decoder lands.

use crate::ast::{Field, Item, Module, UdFile, Value};

/// `@raw` blocks are split at this size so the source stays editable
/// and diffable.
const BLOCK: usize = 4096;

/// Decompile `bytes`, loaded at `load_addr`, as opaque code or data of
/// `arch` (`"unknown"` when nothing says what it is).
#[must_use]
pub fn decompile_raw_opaque(bytes: &[u8], arch: &str, load_addr: u64) -> UdFile {
    let field = |name: &str, value| Field {
        name: name.into(),
        value,
    };
    let module = Module {
        fields: vec![
            field("arch", Value::String(arch.into())),
            field("format", Value::String("raw".into())),
            field("load_addr", Value::Int(load_addr)),
            field(
                "build",
                Value::Block(vec![field("file_size", Value::Int(bytes.len() as u64))]),
            ),
        ],
    };
    let items = bytes
        .chunks(BLOCK)
        .enumerate()
        .map(|(i, chunk)| Item::Raw {
            addr: load_addr + (i * BLOCK) as u64,
            bytes: chunk.to_vec(),
        })
        .collect();
    UdFile { module, items }
}

/// [`decompile_raw_opaque`], pretty-printed.
#[must_use]
pub fn decompile_raw_opaque_to_text(bytes: &[u8], arch: &str, load_addr: u64) -> String {
    crate::ast::emit(&decompile_raw_opaque(bytes, arch, load_addr))
}

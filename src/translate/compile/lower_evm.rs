//! Lower a parsed `.ud` file whose `@module.format` says `"evm"` back
//! to contract bytecode.
//!
//! Contract:
//!
//! ```text
//! lower_to_evm(parse(decompile_evm_to_text(code))) == code
//! ```
//!
//! EVM code is a headerless image at offset 0, so the pinned bytes
//! lower as a raw image with `load_addr` fixed at zero: functions and
//! `@raw` blocks must tile `[0, build.file_size)` exactly. Lifted
//! statements whose text was edited, or that were added without
//! bytes, are then compiled from their text and the contract is laid
//! out again (see `evm_edit`); without such edits the pinned bytes are
//! the output.
//!
//! A `@section("name", 0x…) { … }` is a contract embedded in this one
//! — the runtime code initcode deploys, or a child contract a factory
//! creates — starting at that offset. Its items are addressed from 0,
//! as the embedded code runs once deployed, and must tile it the same
//! way; its size is wherever they end. Sections nest, and each is
//! lowered (edits included) as a contract of its own; when an edit
//! moves its code, the enclosing contract is laid out again with the
//! lengths and immutable offsets its deploying code uses adjusted
//! (see `evm_edit`).

use crate::ast::{Item, Module, UdFile};

use std::collections::HashMap;

use crate::translate::compile::evm_edit::{
    EvmEditError, SectionChange, apply_edits, has_lifted_statements, strip_added,
};

use crate::translate::compile::lower_raw::{
    RawLowerError, build_block, lower_flat_image, lower_flat_image_unsized, read_int, read_string,
};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EvmLowerError {
    #[error("`@module.format` is not `\"evm\"` (got {got:?})")]
    NotEvm { got: String },
    #[error("`@module.format` field is missing")]
    UnknownFormat,
    #[error(transparent)]
    Image(#[from] RawLowerError),
    #[error(transparent)]
    Edit(#[from] EvmEditError),
    #[error(
        "{0}: the pinned bytes no longer cover the code; lifted statements can be edited, added without bytes, or deleted by commenting them out (keeping their byte lists), but not removed outright or given new byte lists"
    )]
    PinnedBytes(RawLowerError),
    /// No longer produced: edits that resize an embedded contract now
    /// adjust the code deploying it, or fail with [`Self::Edit`].
    #[error(
        "embedded contract `{name}` changed size ({old} → {new} bytes); the code deploying it copies a fixed length, so edits inside it must keep its size"
    )]
    SectionResized {
        name: String,
        old: usize,
        new: usize,
    },
}

/// Lower a `.ud` file describing EVM bytecode to its bytes.
pub fn lower_to_evm(file: &UdFile) -> Result<Vec<u8>, EvmLowerError> {
    let format = read_string(&file.module, "format").ok_or(EvmLowerError::UnknownFormat)?;
    if format != "evm" {
        return Err(EvmLowerError::NotEvm { got: format });
    }
    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;
    Ok(lower_contract(&file.module, &file.items, Some(file_size))?.new)
}

/// One contract's code: its pinned bytes, and with edits applied.
struct Lowered {
    old: Vec<u8>,
    new: Vec<u8>,
    /// Where its original instructions start in `new`, when any moved.
    moved: Option<HashMap<u64, u64>>,
}

/// Lower one contract. `size` is the declared size of a top-level
/// image.
fn lower_contract(
    module: &Module,
    items: &[Item],
    size: Option<u64>,
) -> Result<Lowered, EvmLowerError> {
    let (flat, sections) = flatten_sections(module, items)?;
    let pinned = strip_added(&flat);
    let code = match size {
        Some(n) => lower_flat_image(&pinned, 0, n),
        None => lower_flat_image_unsized(&pinned, 0),
    }
    .map_err(|e| match e {
        RawLowerError::Gap { .. }
        | RawLowerError::Overlap { .. }
        | RawLowerError::SizeMismatch { .. }
            if has_lifted_statements(&flat) =>
        {
            EvmLowerError::PinnedBytes(e)
        }
        other => other.into(),
    })?;
    let edited = apply_edits(&flat, &code, &sections)?;
    Ok(match edited {
        Some(e) => Lowered {
            old: code,
            new: e.code,
            moved: e.moved,
        },
        None => Lowered {
            old: code.clone(),
            new: code,
            moved: None,
        },
    })
}

/// `items` with every embedded contract (`@section`) lowered in place
/// to a `@raw` block of its pinned bytes at its offset, and those an
/// edit changed.
fn flatten_sections(
    module: &Module,
    items: &[Item],
) -> Result<(UdFile, Vec<SectionChange>), EvmLowerError> {
    let mut flat = Vec::with_capacity(items.len());
    let mut changes = Vec::new();
    for item in items {
        match item {
            Item::Section {
                addr, items: inner, ..
            } => {
                let l = lower_contract(module, inner, None)?;
                flat.push(Item::Raw {
                    addr: *addr,
                    bytes: l.old.clone(),
                });
                if l.new != l.old || l.moved.is_some() {
                    changes.push(SectionChange {
                        addr: *addr,
                        old: l.old,
                        new: l.new,
                        moved: l.moved,
                    });
                }
            }
            other => flat.push(other.clone()),
        }
    }
    Ok((
        UdFile {
            module: module.clone(),
            items: flat,
        },
        changes,
    ))
}

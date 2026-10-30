//! Lower a parsed `.ud` file whose `@module.format` says `"evm"` back
//! to contract bytecode.
//!
//! Contract:
//!
//! ```text
//! lower_to_evm(parse(decompile_evm_to_text(code))) == code
//! ```
//!
//! EVM code is a headerless image at offset 0, so this is the raw
//! lowering with `load_addr` fixed at zero: functions and `@raw`
//! blocks must tile `[0, build.file_size)` exactly.
//!
//! A `@section("name", 0x…) { … }` is a contract embedded in this one
//! — the runtime code initcode deploys, or a child contract a factory
//! creates — starting at that offset. Its items are addressed from 0,
//! as the embedded code runs once deployed, and must tile it the same
//! way; its size is wherever they end. Sections nest.

use crate::ast::{Item, Module, UdFile};

use crate::translate::compile::lower_raw::{
    RawLowerError, build_block, lower_flat_image, lower_flat_image_unsized, read_int, read_string,
};

#[derive(Debug, thiserror::Error)]
pub enum EvmLowerError {
    #[error("`@module.format` is not `\"evm\"` (got {got:?})")]
    NotEvm { got: String },
    #[error("`@module.format` field is missing")]
    UnknownFormat,
    #[error(transparent)]
    Image(#[from] RawLowerError),
}

/// Lower a `.ud` file describing EVM bytecode to its bytes.
pub fn lower_to_evm(file: &UdFile) -> Result<Vec<u8>, EvmLowerError> {
    let format = read_string(&file.module, "format").ok_or(EvmLowerError::UnknownFormat)?;
    if format != "evm" {
        return Err(EvmLowerError::NotEvm { got: format });
    }
    let build = build_block(&file.module)?;
    let file_size = read_int(build, "file_size")?;
    let flat = flatten_sections(&file.module, &file.items)?;
    Ok(lower_flat_image(&flat, 0, file_size)?)
}

/// `items` with every embedded contract (`@section`) lowered in place
/// to a `@raw` block at its offset.
fn flatten_sections(module: &Module, items: &[Item]) -> Result<UdFile, EvmLowerError> {
    let mut flat = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Item::Section {
                addr, items: inner, ..
            } => {
                let nested = flatten_sections(module, inner)?;
                flat.push(Item::Raw {
                    addr: *addr,
                    bytes: lower_flat_image_unsized(&nested, 0)?,
                });
            }
            other => flat.push(other.clone()),
        }
    }
    Ok(UdFile {
        module: module.clone(),
        items: flat,
    })
}

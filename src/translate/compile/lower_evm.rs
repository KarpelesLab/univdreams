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

use crate::ast::UdFile;

use crate::translate::compile::lower_raw::{
    RawLowerError, build_block, lower_flat_image, read_int, read_string,
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
    Ok(lower_flat_image(file, 0, file_size)?)
}

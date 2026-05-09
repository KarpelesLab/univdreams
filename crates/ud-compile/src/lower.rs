//! Lower a parsed `.ud` AST to bytes.
//!
//! v0 scope: per-function byte concatenation. Each [`Stmt::Asm`] in
//! the body must carry pinned `bytes`; the lowerer concatenates them
//! in source order and returns the result. Empty `bytes` is a hard
//! error — there's no text assembler online yet, so an `@asm("text")`
//! without bytes is not yet recompilable.
//!
//! Future expansion:
//!
//! * When a text assembler is wired in, empty `bytes` becomes "the
//!   assembler will fill in", and a non-empty `bytes` field becomes a
//!   verification hint (assemble `text`, assert it equals `bytes`).
//! * Sectioning and inter-function padding are not yet represented in
//!   the source language; once `@raw` and `@pad` directives land, the
//!   top-level `lower_to_bytes` will produce a complete binary image.

use ud_ast::{FnDecl, Item, Stmt, UdFile};

/// One function lowered to bytes.
#[derive(Debug, Clone)]
pub struct LoweredFunction {
    pub name: String,
    pub addr: Option<u64>,
    pub bytes: Vec<u8>,
}

/// Errors specific to the lower path.
#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    #[error(
        "function `{fn_name}` has an `@asm` statement without pinned bytes \
         at body index {stmt_index} (text = {text:?})"
    )]
    MissingBytes {
        fn_name: String,
        stmt_index: usize,
        text: String,
    },
}

/// Lower one [`FnDecl`] to its byte sequence.
pub fn lower_function_bytes(f: &FnDecl) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::new();
    for (i, stmt) in f.body.iter().enumerate() {
        match stmt {
            Stmt::Asm { text, bytes } => {
                if bytes.is_empty() {
                    return Err(LowerError::MissingBytes {
                        fn_name: f.name.clone(),
                        stmt_index: i,
                        text: text.clone(),
                    });
                }
                out.extend_from_slice(bytes);
            }
            Stmt::Comment(_) => {}
        }
    }
    Ok(out)
}

/// Lower every function in the file to bytes.
///
/// Returns one [`LoweredFunction`] per [`Item::Function`] in
/// declaration order. Non-function items ([`Item::Comment`]) are
/// skipped silently.
pub fn lower_functions(file: &UdFile) -> Result<Vec<LoweredFunction>, LowerError> {
    let mut out = Vec::new();
    for item in &file.items {
        if let Item::Function(f) = item {
            let bytes = lower_function_bytes(f)?;
            out.push(LoweredFunction {
                name: f.name.clone(),
                addr: f.addr,
                bytes,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_ast::{FnDecl, Module, Stmt};

    fn empty_module() -> Module {
        Module { fields: vec![] }
    }

    #[test]
    fn lower_function_with_pinned_bytes_concatenates() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            body: vec![
                Stmt::asm("endbr64", vec![0xf3, 0x0f, 0x1e, 0xfa]),
                Stmt::asm("ret", vec![0xc3]),
            ],
        };
        let bytes = lower_function_bytes(&f).unwrap();
        assert_eq!(bytes, vec![0xf3, 0x0f, 0x1e, 0xfa, 0xc3]);
    }

    #[test]
    fn lower_function_skips_comments() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            body: vec![
                Stmt::asm("ret", vec![0xc3]),
                Stmt::Comment("block: 0x1001".into()),
            ],
        };
        assert_eq!(lower_function_bytes(&f).unwrap(), vec![0xc3]);
    }

    #[test]
    fn lower_function_without_bytes_errors() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            body: vec![Stmt::asm_text("ret")],
        };
        let err = lower_function_bytes(&f).unwrap_err();
        match err {
            LowerError::MissingBytes {
                fn_name,
                stmt_index,
                text,
            } => {
                assert_eq!(fn_name, "f");
                assert_eq!(stmt_index, 0);
                assert_eq!(text, "ret");
            }
        }
    }

    #[test]
    fn lower_functions_returns_one_entry_per_function() {
        let file = UdFile {
            module: empty_module(),
            items: vec![
                Item::Function(FnDecl {
                    addr: Some(0x1000),
                    name: "a".into(),
                    body: vec![Stmt::asm("ret", vec![0xc3])],
                }),
                Item::Comment("note: skip me".into()),
                Item::Function(FnDecl {
                    addr: Some(0x2000),
                    name: "b".into(),
                    body: vec![Stmt::asm("ret", vec![0xc3])],
                }),
            ],
        };
        let lowered = lower_functions(&file).unwrap();
        assert_eq!(lowered.len(), 2);
        assert_eq!(lowered[0].name, "a");
        assert_eq!(lowered[0].addr, Some(0x1000));
        assert_eq!(lowered[0].bytes, vec![0xc3]);
        assert_eq!(lowered[1].name, "b");
    }
}

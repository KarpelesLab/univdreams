//! Decompile a 6502 raw image into a `.ud` AST.
//!
//! v0 scope: byte-identical round-trip via linear decode.
//!
//! The 6502 has no executable file format — code is just a flat
//! image mapped at a fixed virtual address (e.g. WozMon at $FF00).
//! The reset / NMI / IRQ vectors sit at $FFFA-$FFFF for any program
//! that wants to be entered by a power-on or interrupt.
//!
//! Emitted shape:
//!
//! ```text
//! @module {
//!     arch: "6502", format: "raw", bits: 8, endian: "little",
//!     load_addr: 0xFF00,
//!     vectors: { nmi: 0x0F00, reset: 0xFF00, irq: 0x0000 },
//!     build: { file_size: 0x100 },
//! }
//!
//! fn rom() @0xFF00 {
//!     @asm("CLD",       [0xD8])
//!     @asm("CLI",       [0x58])
//!     @asm("LDY #$7F",  [0xA0, 0x7F])
//!     …
//! }
//!
//! @raw(0xFFFA, [0x00, 0x0F, 0x00, 0xFF, 0x00, 0x00])  // vectors
//! ```
//!
//! The whole image is covered: every byte before the vector region
//! is in the function body's `@asm` lines (with their pinned
//! `original_bytes`), and the 6 vector bytes are a single `@raw`.
//! Concatenating in source order reproduces the input.
//!
//! Slice 6502-E will replace the single `fn rom()` with one function
//! per JSR target plus a discovered entry function.

use ud_arch_6502::{decode_range, format_insn, DecodedInsn};
use ud_ast::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};
use ud_format_raw::RawImage;

/// 6502 reset / NMI / IRQ vectors live at $FFFA-$FFFF. Six bytes.
const VECTORS_BASE: u64 = 0xFFFA;
const VECTORS_LEN: u64 = 6;

/// Errors specific to the 6502 raw path.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("image is too small to contain reset vectors at $FFFA-$FFFF (got {got} bytes)")]
    TooSmall { got: usize },
    #[error("decode failed at offset {offset}: {source}")]
    Decode {
        offset: usize,
        #[source]
        source: ud_arch_6502::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Build the AST for a 6502 raw image.
pub fn decompile_raw_6502(image: &RawImage) -> Result<UdFile> {
    if image.bytes.len() < (VECTORS_LEN as usize) {
        return Err(Error::TooSmall {
            got: image.bytes.len(),
        });
    }
    let module = build_module(image)?;

    let code_end = image.end().saturating_sub(VECTORS_LEN);
    let code_len = (code_end - image.start()) as usize;
    let code_bytes = &image.bytes[..code_len];
    let insns = decode_range(code_bytes, image.start()).map_err(|e| Error::Decode {
        offset: 0,
        source: e,
    })?;

    let body = build_body(&insns);
    let rom = FnDecl {
        addr: Some(image.start()),
        name: "rom".into(),
        signature: None,
        body,
    };

    let vectors_bytes = image.bytes[code_len..].to_vec();
    let items = vec![
        Item::Function(rom),
        Item::Raw {
            addr: VECTORS_BASE,
            bytes: vectors_bytes,
        },
    ];

    Ok(UdFile { module, items })
}

/// Convenience: AST + canonical pretty-print.
pub fn decompile_raw_6502_to_text(image: &RawImage) -> Result<String> {
    Ok(ud_ast::emit(&decompile_raw_6502(image)?))
}

fn build_module(image: &RawImage) -> Result<Module> {
    let nmi = image.read_u16_le(0xFFFA).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?;
    let reset = image.read_u16_le(0xFFFC).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?;
    let irq = image.read_u16_le(0xFFFE).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?;

    let vectors = Value::Block(vec![
        field("nmi", Value::Int(u64::from(nmi))),
        field("reset", Value::Int(u64::from(reset))),
        field("irq", Value::Int(u64::from(irq))),
    ]);

    let build = Value::Block(vec![field(
        "file_size",
        Value::Int(image.bytes.len() as u64),
    )]);

    Ok(Module {
        fields: vec![
            field("arch", Value::String("6502".into())),
            field("format", Value::String("raw".into())),
            field("bits", Value::Int(8)),
            field("endian", Value::String("little".into())),
            field("load_addr", Value::Int(image.load_addr)),
            field("vectors", vectors),
            field("build", build),
        ],
    })
}

fn build_body(insns: &[DecodedInsn]) -> Vec<Stmt> {
    insns
        .iter()
        .map(|i| Stmt::asm(format_insn(i), i.original_bytes.clone()))
        .collect()
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

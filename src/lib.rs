//! univdreams — byte-identical binary ↔ source round-tripping.
//!
//! - [`format`](mod@format): ELF, PE/COFF, Mach-O, NE, wasm and raw containers (parse +
//!   byte-identical write).
//! - [`arch`]: per-architecture decode / encode / lift behind
//!   [`arch::codec`].
//! - [`ir`], [`ast`]: the shared IR and the `.ud` source-language AST.
//! - [`analysis`], [`debug`], [`signatures`]: function discovery, DWARF /
//!   PDB metadata, byte-pattern signatures.
//! - [`translate`]: binary → `.ud` (decompile) and `.ud` → binary (compile).
//! - [`emulator`]: x86 emulator with Win16 / Win32 / Linux hosts.
//! - `cli` (feature `cli`) and `wasm` (feature `wasm`): the `ud` driver
//!   and the browser bindings.

pub mod analysis;
pub mod arch;
pub mod ast;
#[cfg(feature = "cli")]
pub mod cli;
pub mod common;
pub mod debug;
pub mod emulator;
pub mod format;
pub mod ir;
pub mod signatures;
pub mod translate;
#[cfg(feature = "wasm")]
pub mod wasm;

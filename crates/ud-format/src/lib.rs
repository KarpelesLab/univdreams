//! Binary container formats — parse + byte-identical write.
//!
//! One module per format, each a self-contained reader/writer
//! with the same shape: `parse(bytes)` produces a structured
//! view, `write_to_vec()` reproduces the input byte-for-byte
//! (the round-trip invariant the whole univdreams pipeline
//! rests on).
//!
//! * [`elf`] — ELF32 / ELF64 (`Elf64File`).
//! * [`pe`] — PE / COFF, PE32 and PE32+ (`PeFile`).
//! * [`macho`] — thin 64-bit Mach-O (`MachoFile`).
//! * [`ne`] — 16-bit Windows New Executable (`NeFile`).
//! * [`raw`] — headerless flat images, e.g. 6502 ROMs
//!   (`RawImage`).
//! * [`wasm`] — WebAssembly modules (`WasmFile`).
//!
//! These were four separate crates (`ud-format-elf`,
//! `-pe`, `-macho`, `-raw`); they were merged because they
//! share one role — "parse and rewrite a binary container" —
//! and four single-file crates was more granularity than the
//! project's scope warranted.

pub mod elf;
pub mod macho;
pub mod ne;
pub mod pe;
pub mod raw;
pub mod solana;
pub mod wasm;

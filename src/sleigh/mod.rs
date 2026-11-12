//! SLEIGH: Ghidra's processor-specification language, compiled and run
//! to decode instructions of the architectures univdreams has no
//! hand-written decoder for.
//!
//! The engine is vendored from icicle-emu
//! (<https://github.com/icicle-emu/icicle-emu>, `sleigh/*` at 638508b),
//! dual-licensed MIT or Apache-2.0 — see `LICENCE-MIT` and
//! `LICENCE-APACHE` here. It is kept close to upstream; local changes
//! are marked `univdreams:`.

#![allow(
    clippy::all,
    clippy::pedantic,
    missing_debug_implementations,
    dead_code,
    unused_imports,
    unused_variables,
    rustdoc::all
)]

pub mod compile;
pub mod parse;
pub mod pcode;
pub mod runtime;

//! The `.ud` source-language translation engine — both
//! directions of the univdreams pipeline in one crate.
//!
//! * [`decompile`] — binary → `.ud` source. Function discovery,
//!   instruction lifting, structural pattern recovery, and the
//!   AST emit that produces editable `.ud` text.
//! * [`compile`] — `.ud` source → binary. The lexer + parser
//!   for the `.ud` language, the lowering passes that
//!   regenerate machine code, and the format writers
//!   (`lower_to_elf` / `lower_to_pe` / `lower_to_macho` /
//!   `lower_to_raw`).
//!
//! The two halves used to be separate crates (`ud-decompile`
//! and `ud-compile`); they were merged because their
//! integration tests need both at once — a decompile → edit →
//! recompile round-trip — and a mutual dev-dependency cycle
//! can't be published to crates.io. Keeping them as sibling
//! modules of one crate is both cleaner and one fewer crate
//! to track.
//!
//! Typical use:
//!
//! ```no_run
//! # use univdreams::format::elf::Elf64File;
//! # fn run(elf: &Elf64File) -> Result<(), Box<dyn std::error::Error>> {
//! // Binary → editable .ud text.
//! let text = univdreams::translate::decompile::decompile_to_text(elf)?;
//! // Edit `text` …
//! // .ud text → AST → rebuilt binary.
//! let ast = univdreams::translate::compile::parse(&text)?;
//! let bytes = univdreams::translate::compile::lower_to_elf(&ast)?;
//! # let _ = bytes;
//! # Ok(())
//! # }
//! ```

pub mod compile;
pub mod decompile;

/// Register every arch backend the workspace knows about with
/// [`crate::arch::codec`]'s registry. Call this once at process
/// startup from any binary that consumes the framework (CLI,
/// wasm, integration tests).
///
/// Re-registering is wasteful but harmless — factories run in
/// registration order on every lookup, and each factory only
/// matches its own arch.
pub fn register_all_arches() {
    crate::arch::x86::register();
    crate::arch::aarch64::register();
    crate::arch::mos6502::register();
    crate::arch::bpf::register();
}

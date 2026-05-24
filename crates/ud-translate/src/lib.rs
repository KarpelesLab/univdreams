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
//! # use ud_format::elf::Elf64File;
//! # fn run(elf: &Elf64File) -> Result<(), Box<dyn std::error::Error>> {
//! // Binary → editable .ud text.
//! let text = ud_translate::decompile::decompile_to_text(elf)?;
//! // Edit `text` …
//! // .ud text → AST → rebuilt binary.
//! let ast = ud_translate::compile::parse(&text)?;
//! let bytes = ud_translate::compile::lower_to_elf(&ast)?;
//! # let _ = bytes;
//! # Ok(())
//! # }
//! ```

pub mod compile;
pub mod decompile;

/// Register every arch backend the workspace knows about with
/// [`ud_arch_codec`]'s registry. Call this once at process
/// startup from any binary that consumes the framework (CLI,
/// wasm, integration tests).
///
/// Re-registering is wasteful but harmless — factories run in
/// registration order on every lookup, and each factory only
/// matches its own arch.
pub fn register_all_arches() {
    ud_arch_x86::register();
    ud_arch_aarch64::register();
    ud_arch_6502::register();
    ud_arch_bpf::register();
}

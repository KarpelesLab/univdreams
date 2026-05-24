//! Open registry of [`ArchCodec`] factories.
//!
//! Arch crates register a factory function at process startup
//! (typically from `<crate>::register()`); resolution happens at
//! the entry of every compile / decompile pipeline call that needs
//! to encode arch-specific instructions.
//!
//! The registry takes raw `(arch_name, e_machine)` pairs rather
//! than an AST type — that's how this crate stays independent of
//! `ud-ast` (which would otherwise cause a cycle through
//! `ud-arch-x86`). Callers (`ud-translate`) extract the pair from
//! a parsed `ud_ast::Module` and feed it in.

use std::sync::{OnceLock, RwLock};

use crate::{ArchCodec, ArchError};

/// A codec factory: inspects an `(arch_name, e_machine)` pair and
/// returns a codec instance if it recognises the arch, else
/// `None`. `arch_name` is the lowercase friendly arch identifier
/// from the parsed `@module` block (`"x86_64"`, `"bpf"`, etc.);
/// `e_machine` is the numeric ELF machine type (`EM_BPF = 247`,
/// `EM_SBF = 263`, …) — useful for sub-arch dispatch (e.g.
/// distinguishing Linux eBPF from Solana SBF when both carry
/// `arch = "bpf"`).
pub type CodecFactory =
    fn(arch_name: Option<&str>, e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>>;

static REGISTRY: OnceLock<RwLock<Vec<CodecFactory>>> = OnceLock::new();

fn registry() -> &'static RwLock<Vec<CodecFactory>> {
    REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

/// Register a codec factory. Each arch crate exposes a
/// `register()` pub fn that calls this once.
///
/// Re-registering the same factory is harmless but wasteful; the
/// registry doesn't dedupe. Production binaries call
/// `<arch_crate>::register()` once at startup.
pub fn register(factory: CodecFactory) {
    registry()
        .write()
        .expect("arch-codec registry poisoned")
        .push(factory);
}

/// Resolve the codec for an `(arch_name, e_machine)` pair.
/// Returns the first matching factory's result, or
/// [`ArchError::UnknownArch`] if nothing claims it.
///
/// Pass `None` for either component when it's unknown — factories
/// must tolerate that and either match on the other or decline.
pub fn for_arch(
    arch_name: Option<&str>,
    e_machine: Option<u64>,
) -> Result<Box<dyn ArchCodec>, ArchError> {
    let reg = registry().read().expect("arch-codec registry poisoned");
    for factory in reg.iter() {
        if let Some(codec) = factory(arch_name, e_machine) {
            return Ok(codec);
        }
    }
    Err(ArchError::UnknownArch {
        arch: arch_name.map(str::to_string),
        e_machine,
    })
}

/// Number of factories currently registered. Cheap; intended for
/// tests and diagnostics.
#[must_use]
pub fn factory_count() -> usize {
    registry()
        .read()
        .expect("arch-codec registry poisoned")
        .len()
}

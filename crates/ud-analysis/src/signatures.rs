//! Function discovery via byte-pattern signatures.
//!
//! Walks every executable section, runs the architecture-appropriate
//! signature DB from `ud-signatures`, and turns each match into a
//! [`Function`] tagged [`FunctionSource::Signature`]. Sizes start as
//! 0; the post-processing pass in [`crate::discover_functions`] fills
//! them in based on neighbouring functions.

use ud_core::VAddr;
use ud_format_elf::{Elf64File, EM_X86_64, SHF_EXECINSTR};
use ud_signatures::{scan, CRT_HELPERS_X86_64};

use crate::function_map::{Function, FunctionSource};

/// Run signature matching against every executable section in `elf`.
///
/// Picks the right DB for the binary's architecture; returns an empty
/// vector for arches we don't ship signatures for yet. Cannot fail
/// today — kept infallible because pattern matching has no I/O and no
/// arch-specific decoder state.
#[must_use]
pub fn discover_from_signatures(elf: &Elf64File) -> Vec<Function> {
    let db = match elf.ehdr.e_machine {
        EM_X86_64 => CRT_HELPERS_X86_64,
        _ => return Vec::new(),
    };

    let mut out = Vec::new();
    for (_, sh, data) in elf.sections() {
        if sh.sh_flags & SHF_EXECINSTR == 0 || data.is_empty() {
            continue;
        }
        for m in scan(data, sh.sh_addr, db) {
            out.push(Function {
                addr: VAddr(m.addr),
                size: 0,
                name: m.name.to_string(),
                sources: vec![FunctionSource::Signature],
            });
        }
    }
    out
}

//! Function discovery from `.eh_frame` (DWARF Call Frame Information).
//!
//! Every modern Unix toolchain emits a `.eh_frame` section that lists
//! one Frame Description Entry (FDE) per function with stack-unwinding
//! info. For our purposes the unwinding info is irrelevant; the FDE's
//! `initial_location` and `address_range` give us a function's start
//! address and size respectively. This survives stripping (the linker
//! keeps `.eh_frame` for runtime exception support) and fills in sizes
//! that the symbol table sometimes leaves at zero (`_init`, `_fini`).
//!
//! Parsing is done via `gimli`. We feed it the section's bytes plus
//! the section's load address so PC-relative pointer encodings resolve
//! correctly.

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, UnwindSection};
use ud_core::VAddr;
use ud_format_elf::Elf64File;

use crate::function_map::{Function, FunctionSource};

/// Errors specific to `.eh_frame` parsing.
#[derive(Debug, thiserror::Error)]
pub enum EhFrameError {
    #[error("gimli rejected the .eh_frame section: {0}")]
    Gimli(gimli::Error),
}

/// Walk every FDE in `.eh_frame` and return one [`Function`] per entry.
///
/// `name` is set to `sub_<hex_addr>` since `.eh_frame` does not carry
/// names. Higher-confidence sources (the symbol table) replace this on
/// merge inside [`FunctionMap`](crate::FunctionMap).
///
/// Returns an empty vector if the binary has no `.eh_frame` section.
pub fn discover_from_eh_frame(elf: &Elf64File) -> Result<Vec<Function>, EhFrameError> {
    let Some((_, sh, data)) = elf.section_by_name(".eh_frame") else {
        return Ok(Vec::new());
    };
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let eh_frame = EhFrame::new(data, LittleEndian);
    let mut bases = BaseAddresses::default().set_eh_frame(sh.sh_addr);

    // Some encodings resolve relative to the .text section (DW_EH_PE_textrel).
    // Setting it when present is harmless and saves a parse error if a fixture
    // uses that encoding.
    if let Some((_, text_sh, _)) = elf.section_by_name(".text") {
        bases = bases.set_text(text_sh.sh_addr);
    }

    let mut entries = eh_frame.entries(&bases);
    let mut out = Vec::new();
    while let Some(entry) = entries.next().map_err(EhFrameError::Gimli)? {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let fde = partial
            .parse(EhFrame::cie_from_offset)
            .map_err(EhFrameError::Gimli)?;
        let start = fde.initial_address();
        let len = fde.len();
        out.push(Function {
            addr: VAddr(start),
            size: len,
            name: format!("sub_{start:x}"),
            sources: vec![FunctionSource::EhFrame],
        });
    }
    Ok(out)
}

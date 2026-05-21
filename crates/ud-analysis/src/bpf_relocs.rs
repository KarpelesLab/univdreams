//! BPF / SBF call-site name resolution via `.rel.dyn`.
//!
//! LLVM emits one `R_BPF_64_32` relocation per `call <imm>`
//! site that references an imported symbol. The relocation's
//! `r_offset` is the address of the call **slot** itself (the
//! 8-byte instruction); the linker patches the imm field at
//! `r_offset + 4` once it knows the symbol's resolved value.
//! The symbol index in `r_info >> 32` resolves through
//! `.dynsym` + `.dynstr` to the import's name (`sol_log_`,
//! `abort`, `custom_panic`, …).
//!
//! The output is a `HashMap<u64, String>` keyed by the call
//! instruction's address, so the decompile path can look up
//! "is there a known syscall at this `call`?" with a single
//! map probe.
//!
//! This mirrors `plt.rs`'s shape; the differences are:
//!
//! * BPF uses `SHT_REL` (16-byte entries, no addend), not
//!   `SHT_RELA` (24-byte with addend).
//! * Only `R_BPF_64_32` matters for call-site naming. Other
//!   types reference data slots and are ignored here.

use std::collections::HashMap;

use ud_format::elf::{Elf64File, R_BPF_64_32, SHT_DYNSYM, SHT_REL};

/// On-disk size of one `Elf64_Rel` entry (no addend).
const REL_SIZE: usize = 16;
/// On-disk size of one `Elf64_Sym` entry.
const SYM_SIZE: usize = 24;

/// Errors specific to BPF relocation resolution.
#[derive(Debug, thiserror::Error)]
pub enum BpfRelocError {
    #[error("`.rel.dyn` size {size} is not a multiple of {entry}")]
    BadRelSize { size: usize, entry: usize },
}

/// Build a map from `call <imm>` instruction address to its
/// imported symbol name. Returns an empty map (not an error)
/// when the ELF has no `SHT_REL` linked to a `.dynsym` — that
/// happens for non-relocatable BPF and is a legitimate ELF
/// shape, not a failure.
///
/// Keyed by the 8-byte slot's start address (matching what
/// `DecodedInsn::addr.0` produces), so callers can probe
/// directly with `map.get(&insn.addr.0)`.
#[allow(clippy::missing_errors_doc)]
pub fn build_call_site_names(elf: &Elf64File) -> Result<HashMap<u64, String>, BpfRelocError> {
    let mut out: HashMap<u64, String> = HashMap::new();
    for (_idx, shdr, data) in elf.sections() {
        if shdr.sh_type != SHT_REL {
            continue;
        }
        let dynsym_idx = shdr.sh_link as usize;
        let dynsym_shdr = match elf.shdrs.get(dynsym_idx) {
            Some(s) if s.sh_type == SHT_DYNSYM => s,
            _ => continue,
        };
        let dynsym_data = elf.section_data(dynsym_idx).unwrap_or(&[]);
        let strtab_idx = dynsym_shdr.sh_link as usize;
        let Some(strtab) = elf.section_data(strtab_idx) else {
            continue;
        };

        if data.len() % REL_SIZE != 0 {
            return Err(BpfRelocError::BadRelSize {
                size: data.len(),
                entry: REL_SIZE,
            });
        }
        for chunk in data.chunks_exact(REL_SIZE) {
            let r_offset = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let r_info = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            #[allow(clippy::cast_possible_truncation)]
            let r_type = r_info as u32;
            let sym_idx = (r_info >> 32) as usize;
            if r_type != R_BPF_64_32 {
                // Only `call <imm>` relocations are useful for
                // syscall naming. Data references (R_BPF_64_64,
                // R_BPF_64_RELATIVE, …) point at lddw slots
                // and structured data; a future layer can
                // surface those as named pointers, but it's not
                // this layer's job.
                continue;
            }
            let Some(name) = read_dynsym_name(dynsym_data, sym_idx, strtab) else {
                continue;
            };
            // LLVM emits `r_offset` as the *instruction*
            // address — the slot start. (Internally the
            // linker writes to `r_offset + 4` for the imm
            // field, but the relocation entry itself points
            // at the whole slot.)
            out.insert(r_offset, name);
        }
    }
    Ok(out)
}

/// Read `.dynsym[idx]`'s `st_name`-resolved string, or `None`
/// when the index or string offset is out of bounds.
///
/// Mirrors `plt::read_dynsym_name`; kept local rather than
/// shared so the two modules stay independent.
fn read_dynsym_name(dynsym_data: &[u8], idx: usize, strtab: &[u8]) -> Option<String> {
    let off = idx.checked_mul(SYM_SIZE)?;
    let chunk = dynsym_data.get(off..off + SYM_SIZE)?;
    let st_name = u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as usize;
    let tail = strtab.get(st_name..)?;
    let nul = tail.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&tail[..nul]).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

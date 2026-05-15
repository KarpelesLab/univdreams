//! PLT thunk discovery: name `.plt` entries by resolving them through
//! `.rela.plt` → `.dynsym` to recover the imported symbol.
//!
//! On x86-64 SysV the typical lazy-binding `.plt` entry decodes as
//! `jmp qword ptr [rip+disp]`, where `rip+disp` is the GOT slot the
//! dynamic linker fills with the imported function's resolved address.
//! `.rela.plt` records, for each such GOT slot, the index of the
//! corresponding `.dynsym` entry; that entry's `st_name` is the
//! import's symbolic name (e.g. `printf`).
//!
//! This module does not require the `.plt` to be lazy-bound — it
//! works just as well for `BIND_NOW` / IBT-flavoured binaries, since
//! the relocation linkage is the same shape.

use std::collections::HashMap;

use ud_core::VAddr;
use ud_format::elf::{Elf64File, SHT_DYNSYM, SHT_RELA};

use crate::function_map::{Function, FunctionSource};

/// On-disk size of an `Elf64_Rela` entry: r_offset(8) + r_info(8) + r_addend(8).
const RELA_SIZE: usize = 24;
/// On-disk size of an `Elf64_Sym` entry.
const SYM_SIZE: usize = 24;
/// `R_X86_64_JUMP_SLOT` — the relocation type that fills a PLT GOT slot.
const R_X86_64_JUMP_SLOT: u32 = 7;

/// Errors specific to PLT thunk discovery.
#[derive(Debug, thiserror::Error)]
pub enum PltError {
    #[error("`.rela.plt` size {size} is not a multiple of {entry}")]
    BadRelaSize { size: usize, entry: usize },
    #[error("`.rela.plt` references invalid `.dynsym` index {idx}")]
    BadDynsymIndex { idx: usize },
}

/// Discover every PLT thunk across `.plt`, `.plt.got`, and `.plt.sec`
/// (IBT-aware variants), and return one [`Function`] per entry,
/// named by its imported symbol.
///
/// Returns an empty vector when any of the prerequisites is missing
/// (no PLT section at all, or no `.rela.plt` to resolve names) —
/// those are legitimate ELF shapes for static binaries / shared
/// objects without imports, not errors.
///
/// Two entry shapes are recognised:
///
/// * `jmp qword ptr [rip+disp32]` — the classic PLT entry (`.plt`,
///   `.plt.got`).
/// * `endbr64; jmp qword ptr [rip+disp32]; …` — IBT-aware PLT entry
///   (`.plt.sec`).
///
/// Either way, the GOT slot pointed to by the `jmp` is looked up in
/// the `.rela.plt` table to recover the import's name.
///
/// `.plt`'s first entry (the resolver stub) is skipped; the other
/// sections don't have a resolver entry.
#[allow(clippy::missing_errors_doc)]
pub fn discover_plt_thunks(elf: &Elf64File) -> Result<Vec<Function>, PltError> {
    let Some(slot_to_name) = build_jump_slot_name_map(elf)? else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for section_name in [".plt", ".plt.got", ".plt.sec"] {
        let Some((_, shdr, data)) = elf.section_by_name(section_name) else {
            continue;
        };
        let entry_size = effective_plt_entry_size(shdr.sh_entsize);
        let skip_first = section_name == ".plt"; // PLT0 resolver stub
        scan_plt_section(
            shdr.sh_addr,
            data,
            entry_size,
            skip_first,
            &slot_to_name,
            &mut out,
        );
    }
    Ok(out)
}

fn effective_plt_entry_size(sh_entsize: u64) -> usize {
    if sh_entsize == 0 {
        16
    } else {
        sh_entsize as usize
    }
}

fn scan_plt_section(
    base_addr: u64,
    data: &[u8],
    entry_size: usize,
    skip_first: bool,
    slot_to_name: &HashMap<u64, String>,
    out: &mut Vec<Function>,
) {
    if entry_size == 0 || data.len() < entry_size {
        return;
    }
    let mut offset = if skip_first { entry_size } else { 0 };
    while offset + 6 <= data.len() {
        let entry_addr = base_addr.saturating_add(offset as u64);
        if let Some(slot_addr) = decode_plt_entry_target(data, offset, entry_addr) {
            if let Some(name) = slot_to_name.get(&slot_addr) {
                out.push(Function {
                    addr: VAddr(entry_addr),
                    size: entry_size as u64,
                    name: name.clone(),
                    sources: vec![FunctionSource::Plt],
                });
            }
        }
        offset += entry_size;
    }
}

/// Decode the leading instruction(s) of a PLT entry and return the
/// absolute address of the GOT slot it jumps through. Returns `None`
/// when the bytes don't match either of the two recognised shapes:
///
/// * `ff 25 disp32` — bare `jmp qword ptr [rip+disp32]`.
/// * `f3 0f 1e fa ff 25 disp32` — `endbr64` + the same jmp.
fn decode_plt_entry_target(data: &[u8], offset: usize, entry_addr: u64) -> Option<u64> {
    // IBT-aware: endbr64 (4 bytes) + jmp [rip+disp32] (6 bytes).
    if data.len() >= offset + 10
        && data[offset..offset + 4] == [0xf3, 0x0f, 0x1e, 0xfa]
        && data[offset + 4] == 0xff
        && data[offset + 5] == 0x25
    {
        return rip_relative_target(
            entry_addr.saturating_add(10),
            i32::from_le_bytes(data[offset + 6..offset + 10].try_into().unwrap()),
        );
    }
    // Bare jmp [rip+disp32].
    let bytes = data.get(offset..offset + 6)?;
    if bytes[0] == 0xff && bytes[1] == 0x25 {
        return rip_relative_target(
            entry_addr.saturating_add(6),
            i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
        );
    }
    None
}

/// `rip + disp` where `rip` is the address of the instruction after
/// the `jmp` (the value `rip` actually has when the jmp is decoded).
fn rip_relative_target(rip_after: u64, disp: i32) -> Option<u64> {
    if disp >= 0 {
        // `disp >= 0` so the cast to u32 is non-lossy; widen to u64.
        #[allow(clippy::cast_sign_loss)]
        let disp_u = disp as u32;
        rip_after.checked_add(u64::from(disp_u))
    } else {
        rip_after.checked_sub(u64::from(disp.unsigned_abs()))
    }
}

/// Build the GOT-slot-address → import-name map by walking every
/// `Elf64_Rela` table that targets `R_X86_64_JUMP_SLOT` slots and
/// resolving the referenced `.dynsym` entries through their string
/// table.
fn build_jump_slot_name_map(elf: &Elf64File) -> Result<Option<HashMap<u64, String>>, PltError> {
    let mut slot_to_name: HashMap<u64, String> = HashMap::new();
    let mut saw_rela_for_dynsym = false;

    for (_idx, shdr, data) in elf.sections() {
        if shdr.sh_type != SHT_RELA {
            continue;
        }
        let dynsym_idx = shdr.sh_link as usize;
        let dynsym_shdr = match elf.shdrs.get(dynsym_idx) {
            Some(s) if s.sh_type == SHT_DYNSYM => s,
            _ => continue, // not a relocation table linked to .dynsym
        };
        let dynsym_data = elf.section_data(dynsym_idx).unwrap_or(&[]);
        let strtab_idx = dynsym_shdr.sh_link as usize;
        let Some(strtab) = elf.section_data(strtab_idx) else {
            continue;
        };
        saw_rela_for_dynsym = true;

        if data.len() % RELA_SIZE != 0 {
            return Err(PltError::BadRelaSize {
                size: data.len(),
                entry: RELA_SIZE,
            });
        }
        for chunk in data.chunks_exact(RELA_SIZE) {
            let r_offset = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let r_info = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            #[allow(clippy::cast_possible_truncation)]
            let r_type = r_info as u32;
            let sym_idx = (r_info >> 32) as usize;
            if r_type != R_X86_64_JUMP_SLOT {
                continue;
            }
            let Some(name) = read_dynsym_name(dynsym_data, sym_idx, strtab) else {
                continue;
            };
            slot_to_name.insert(r_offset, name);
        }
    }
    Ok(if saw_rela_for_dynsym {
        Some(slot_to_name)
    } else {
        None
    })
}

/// Read `.dynsym[idx]`'s `st_name`-resolved string, or `None` when
/// the index or string offset is out of bounds.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_plt_target_handles_positive_disp() {
        // jmp qword ptr [rip+0x10] — entry at 0x1000; rip after = 0x1006;
        // target = 0x1006 + 0x10 = 0x1016.
        let bytes = [0xff, 0x25, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(decode_plt_entry_target(&bytes, 0, 0x1000), Some(0x1016));
    }

    #[test]
    fn decode_plt_target_handles_negative_disp() {
        // jmp qword ptr [rip-0x10] — target = 0x1006 - 0x10 = 0xff6.
        let bytes = [0xff, 0x25, 0xf0, 0xff, 0xff, 0xff];
        assert_eq!(decode_plt_entry_target(&bytes, 0, 0x1000), Some(0xff6));
    }

    #[test]
    fn decode_plt_target_rejects_other_opcodes() {
        let bytes = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert!(decode_plt_entry_target(&bytes, 0, 0x1000).is_none());
    }

    #[test]
    fn decode_plt_target_handles_ibt_endbr_prefix() {
        // endbr64 (4) + jmp qword ptr [rip+0x10] (6) — entry at 0x1070;
        // rip after = 0x107a; target = 0x107a + 0x10 = 0x108a.
        let bytes = [
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xff, 0x25, 0x10, 0x00, 0x00, 0x00, // jmp qword ptr [rip+0x10]
        ];
        assert_eq!(decode_plt_entry_target(&bytes, 0, 0x1070), Some(0x108a));
    }
}

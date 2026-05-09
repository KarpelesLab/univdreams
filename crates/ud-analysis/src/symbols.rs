//! Function discovery from ELF symbol tables (`.symtab` and `.dynsym`).
//!
//! This is the highest-confidence signal we have for function boundaries
//! (when symbols are present). The implementation deliberately ignores
//! anything that isn't a function symbol with a defined address and
//! resolved section — undefined imports (`U printf`) and pseudo-symbols
//! get filtered out.

use ud_core::VAddr;
use ud_format_elf::{Elf64File, SHT_DYNSYM, SHT_SYMTAB};

use crate::function_map::{Function, FunctionSource};

/// On-disk size of an `Elf64_Sym` entry.
const SYM64_SIZE: usize = 24;

/// `st_shndx` value indicating an undefined symbol — for instance a
/// dynamic import that the loader resolves at runtime. We skip these.
const SHN_UNDEF: u16 = 0;

/// `st_info & 0xf` = symbol type. We accept `STT_FUNC` and the GNU
/// indirect-function variant; everything else is data, sections, files,
/// or absent semantics.
const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;

/// Errors specific to symbol-table parsing.
#[derive(Debug, thiserror::Error)]
pub enum SymbolError {
    #[error("symbol table section #{idx} has unexpected sh_entsize {got}, expected {expected}")]
    BadEntsize { idx: usize, got: u64, expected: u64 },

    #[error("symbol table section #{idx} has size {size} not a multiple of entry size {entry}")]
    BadTableSize { idx: usize, size: u64, entry: u64 },

    #[error("symbol table section #{idx} links to invalid string table index {strtab_idx}")]
    BadStrtabIndex { idx: usize, strtab_idx: usize },

    #[error(
        "symbol #{sym} in section #{idx} has st_name = {name} which exceeds string table size {strtab_size}"
    )]
    StrtabOutOfBounds {
        idx: usize,
        sym: usize,
        name: u64,
        strtab_size: usize,
    },

    #[error("symbol #{sym} in section #{idx} has a non-UTF-8 name at strtab offset {offset}")]
    NameNotUtf8 {
        idx: usize,
        sym: usize,
        offset: usize,
    },
}

/// Sweep every `.symtab` and `.dynsym` in `elf`, return one [`Function`]
/// per qualifying entry. Names are resolved via the linked string table.
///
/// "Qualifying" means: the symbol is a function (`STT_FUNC` or
/// `STT_GNU_IFUNC`), defines a non-zero address, and resolves to a real
/// section (`st_shndx != SHN_UNDEF`).
pub fn discover_from_symbol_tables(elf: &Elf64File) -> Result<Vec<Function>, SymbolError> {
    let mut out = Vec::new();
    for (idx, shdr, _data) in elf.sections() {
        let source = match shdr.sh_type {
            SHT_SYMTAB => FunctionSource::SymTab,
            SHT_DYNSYM => FunctionSource::DynSym,
            _ => continue,
        };
        collect_one_table(elf, idx, source, &mut out)?;
    }
    Ok(out)
}

fn collect_one_table(
    elf: &Elf64File,
    idx: usize,
    source: FunctionSource,
    out: &mut Vec<Function>,
) -> Result<(), SymbolError> {
    let shdr = &elf.shdrs[idx];

    if shdr.sh_entsize != SYM64_SIZE as u64 {
        return Err(SymbolError::BadEntsize {
            idx,
            got: shdr.sh_entsize,
            expected: SYM64_SIZE as u64,
        });
    }
    let table = elf.section_data(idx).unwrap_or(&[]);
    if table.len() % SYM64_SIZE != 0 {
        return Err(SymbolError::BadTableSize {
            idx,
            size: table.len() as u64,
            entry: SYM64_SIZE as u64,
        });
    }

    let strtab_idx = shdr.sh_link as usize;
    let strtab = elf
        .section_data(strtab_idx)
        .ok_or(SymbolError::BadStrtabIndex { idx, strtab_idx })?;

    for (sym_idx, chunk) in table.chunks_exact(SYM64_SIZE).enumerate() {
        let st_name = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let st_info = chunk[4];
        // chunk[5] is st_other (visibility) — preserved by the ELF
        // round-trip but irrelevant to function discovery.
        let st_shndx = u16::from_le_bytes(chunk[6..8].try_into().unwrap());
        let st_value = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let st_size = u64::from_le_bytes(chunk[16..24].try_into().unwrap());

        let st_type = st_info & 0xf;
        if st_type != STT_FUNC && st_type != STT_GNU_IFUNC {
            continue;
        }
        if st_value == 0 || st_shndx == SHN_UNDEF {
            continue;
        }

        let name = read_strtab_cstring(strtab, st_name as usize).map_err(|()| {
            SymbolError::StrtabOutOfBounds {
                idx,
                sym: sym_idx,
                name: u64::from(st_name),
                strtab_size: strtab.len(),
            }
        })?;
        let name = std::str::from_utf8(name)
            .map_err(|_| SymbolError::NameNotUtf8 {
                idx,
                sym: sym_idx,
                offset: st_name as usize,
            })?
            .to_string();

        out.push(Function {
            addr: VAddr(st_value),
            size: st_size,
            name,
            sources: vec![source],
        });
    }
    Ok(())
}

/// Read a NUL-terminated byte slice starting at `offset` in `strtab`.
fn read_strtab_cstring(strtab: &[u8], offset: usize) -> Result<&[u8], ()> {
    let tail = strtab.get(offset..).ok_or(())?;
    let nul = tail.iter().position(|&b| b == 0).ok_or(())?;
    Ok(&tail[..nul])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_strtab_returns_string_at_offset() {
        let strtab = b"\0main\0puts\0";
        assert_eq!(read_strtab_cstring(strtab, 1), Ok(&b"main"[..]));
        assert_eq!(read_strtab_cstring(strtab, 6), Ok(&b"puts"[..]));
        assert_eq!(read_strtab_cstring(strtab, 0), Ok(&b""[..]));
    }

    #[test]
    fn read_strtab_rejects_offset_past_end() {
        let strtab = b"\0main\0";
        assert!(read_strtab_cstring(strtab, 100).is_err());
    }

    #[test]
    fn read_strtab_rejects_unterminated() {
        let strtab = b"main"; // no trailing NUL
        assert!(read_strtab_cstring(strtab, 0).is_err());
    }
}

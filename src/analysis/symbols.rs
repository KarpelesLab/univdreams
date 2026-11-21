//! Function discovery from ELF symbol tables (`.symtab` and `.dynsym`).
//!
//! This is the highest-confidence signal we have for function boundaries
//! (when symbols are present). The implementation deliberately ignores
//! anything that isn't a function symbol with a defined address and
//! resolved section — undefined imports (`U printf`) and pseudo-symbols
//! get filtered out.

use crate::common::VAddr;
use crate::format::elf::{Elf64File, ElfClass, SHT_DYNSYM, SHT_SYMTAB};

use crate::analysis::function_map::{Function, FunctionSource};

/// On-disk size of an `Elf64_Sym` entry.
const SYM64_SIZE: usize = 24;
/// On-disk size of an `Elf32_Sym` entry.
const SYM32_SIZE: usize = 16;

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
#[non_exhaustive]
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
    let entry_size = match elf.class {
        ElfClass::Elf32 => SYM32_SIZE,
        ElfClass::Elf64 => SYM64_SIZE,
    };

    if shdr.sh_entsize != entry_size as u64 {
        return Err(SymbolError::BadEntsize {
            idx,
            got: shdr.sh_entsize,
            expected: entry_size as u64,
        });
    }
    let table = elf.section_data(idx).unwrap_or(&[]);
    if !table.len().is_multiple_of(entry_size) {
        return Err(SymbolError::BadTableSize {
            idx,
            size: table.len() as u64,
            entry: entry_size as u64,
        });
    }

    let be = elf.ehdr.is_big_endian();
    let strtab_idx = shdr.sh_link as usize;
    let strtab = elf
        .section_data(strtab_idx)
        .ok_or(SymbolError::BadStrtabIndex { idx, strtab_idx })?;

    for (sym_idx, chunk) in table.chunks_exact(entry_size).enumerate() {
        let (st_name, st_info, st_shndx, st_value, st_size) = match elf.class {
            ElfClass::Elf64 => parse_sym64(chunk, be),
            ElfClass::Elf32 => parse_sym32(chunk, be),
        };

        let st_type = st_info & 0xf;
        if st_type != STT_FUNC && st_type != STT_GNU_IFUNC {
            continue;
        }
        // SHN_UNDEF symbols are imports — not a defined
        // function in this object. We *don't* skip on
        // `st_value == 0` though: relocatable object files
        // (`.o`) commonly place the first function in `.text`
        // at offset 0, which is a legitimate address. Linked
        // executables don't put real symbols at vaddr 0, so
        // the stricter behaviour wasn't necessary even
        // historically.
        if st_shndx == SHN_UNDEF {
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

/// A `u16`, `u32` or `u64` field of a symbol, in the file's byte order.
fn field<const N: usize>(chunk: &[u8], at: usize, be: bool) -> u64 {
    let bytes: [u8; N] = chunk[at..at + N].try_into().unwrap();
    let mut value = 0u64;
    for i in 0..N {
        let byte = if be { bytes[i] } else { bytes[N - 1 - i] };
        value = value << 8 | u64::from(byte);
    }
    value
}

/// Decode an `Elf64_Sym` entry. Field order:
/// `st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)`.
#[allow(clippy::cast_possible_truncation)]
fn parse_sym64(chunk: &[u8], be: bool) -> (u32, u8, u16, u64, u64) {
    // chunk[5] is st_other (visibility); preserved on round-trip
    // but irrelevant to function discovery.
    (
        field::<4>(chunk, 0, be) as u32,
        chunk[4],
        field::<2>(chunk, 6, be) as u16,
        field::<8>(chunk, 8, be),
        field::<8>(chunk, 16, be),
    )
}

/// Decode an `Elf32_Sym` entry. Field order differs from `Elf64_Sym`:
/// `st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2)`.
#[allow(clippy::cast_possible_truncation)]
fn parse_sym32(chunk: &[u8], be: bool) -> (u32, u8, u16, u64, u64) {
    // chunk[13] is st_other.
    (
        field::<4>(chunk, 0, be) as u32,
        chunk[12],
        field::<2>(chunk, 14, be) as u16,
        field::<4>(chunk, 4, be),
        field::<4>(chunk, 8, be),
    )
}

/// What an ARM mapping symbol says about the bytes from its address on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmMapping {
    /// `$a`: ARM instructions.
    Arm,
    /// `$t`: Thumb instructions.
    Thumb,
    /// `$d`: data (literal pools, jump tables).
    Data,
}

/// The ARM mapping symbols of `elf` as `(section index, address, kind)`,
/// sorted. Without any, function symbols stand in: an odd address is a
/// Thumb function, an even one ARM.
#[must_use]
pub fn arm_mapping(elf: &Elf64File) -> Vec<(usize, u64, ArmMapping)> {
    let mut mapping = Vec::new();
    let mut functions = Vec::new();
    let be = elf.ehdr.is_big_endian();
    for (idx, shdr, _) in elf.sections() {
        if shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM {
            continue;
        }
        let entry_size = match elf.class {
            ElfClass::Elf32 => SYM32_SIZE,
            ElfClass::Elf64 => SYM64_SIZE,
        };
        let table = elf.section_data(idx).unwrap_or(&[]);
        let strtab = elf.section_data(shdr.sh_link as usize).unwrap_or(&[]);
        for chunk in table.chunks_exact(entry_size) {
            let (st_name, st_info, st_shndx, st_value, _) = match elf.class {
                ElfClass::Elf64 => parse_sym64(chunk, be),
                ElfClass::Elf32 => parse_sym32(chunk, be),
            };
            // Section indices from SHN_LORESERVE up are special.
            if st_shndx == SHN_UNDEF || st_shndx >= 0xff00 {
                continue;
            }
            let section = usize::from(st_shndx);
            let name = read_strtab_cstring(strtab, st_name as usize).unwrap_or(&[]);
            // `$a`, `$t`, `$d`, optionally followed by `.<anything>`.
            let kind = match name {
                [b'$', k] | [b'$', k, b'.', ..] => match k {
                    b'a' => Some(ArmMapping::Arm),
                    b't' => Some(ArmMapping::Thumb),
                    b'd' => Some(ArmMapping::Data),
                    _ => None,
                },
                _ => None,
            };
            if let Some(kind) = kind {
                mapping.push((section, st_value, kind));
            } else if st_info & 0xf == STT_FUNC {
                let kind = if st_value & 1 == 1 {
                    ArmMapping::Thumb
                } else {
                    ArmMapping::Arm
                };
                functions.push((section, st_value & !1, kind));
            }
        }
    }
    if mapping.is_empty() {
        mapping = functions;
    }
    mapping.sort_unstable_by_key(|&(section, addr, _)| (section, addr));
    mapping.dedup_by_key(|&mut (section, addr, _)| (section, addr));
    mapping
}

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

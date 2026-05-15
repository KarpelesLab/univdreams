//! DWARF reader: walks `.debug_info` for `DW_TAG_subprogram` DIEs and
//! produces structured function-signature records.
//!
//! Type resolution is intentionally narrow at v0: `DW_TAG_base_type`
//! becomes one of the [`ud_ast::Type`] primitives based on its
//! `DW_AT_byte_size` + `DW_AT_encoding` (signed/unsigned/float/bool/
//! char/utf), and `DW_TAG_pointer_type` recurses to its pointee. Type
//! qualifiers (`const`, `volatile`, `typedef`) transparently unwrap to
//! the underlying type. Anything else (composite types, function
//! pointers) falls through to [`ud_ast::Type::Unknown`].

use std::collections::HashMap;

use gimli::constants;
use gimli::{
    AttributeValue, DebuggingInformationEntry, EndianSlice, LittleEndian, Reader, UnitOffset,
};
use ud_ast::{Param, Type};
use ud_format::elf::Elf64File;

#[derive(Debug, thiserror::Error)]
pub enum DebugError {
    #[error("DWARF parser rejected the input: {0}")]
    Gimli(#[source] gimli::Error),
}

impl From<gimli::Error> for DebugError {
    fn from(e: gimli::Error) -> Self {
        Self::Gimli(e)
    }
}

/// One function's DWARF-recovered signature.
#[derive(Debug, Clone)]
pub struct DebugFunction {
    pub addr: u64,
    pub name: String,
    pub return_type: Type,
    pub params: Vec<Param>,
}

/// Walk every `DW_TAG_subprogram` in `.debug_info` and produce a
/// [`DebugFunction`] for each one with a known address.
pub fn read_subprograms(elf: &Elf64File) -> Result<Vec<DebugFunction>, DebugError> {
    let Some(dwarf) = load_dwarf(elf) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;
        walk_for_subprograms(&dwarf, &unit, root, &mut out)?;
    }
    Ok(out)
}

fn walk_for_subprograms<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    node: gimli::EntriesTreeNode<R>,
    out: &mut Vec<DebugFunction>,
) -> Result<(), DebugError>
where
    R: Reader<Offset = usize>,
{
    let entry_offset = node.entry().offset();
    let entry_tag = node.entry().tag();
    if entry_tag == constants::DW_TAG_subprogram {
        // Need to re-fetch via entries_at_offset to read params from
        // children — the node is consumed by `children()`.
        if let Some(func) = read_subprogram(dwarf, unit, entry_offset)? {
            out.push(func);
        }
    }
    let mut children = node.children();
    while let Some(child) = children.next()? {
        walk_for_subprograms(dwarf, unit, child, out)?;
    }
    Ok(())
}

type SectionData<'a> = EndianSlice<'a, LittleEndian>;

fn load_dwarf(elf: &Elf64File) -> Option<gimli::Dwarf<SectionData<'_>>> {
    let load_section = |id: gimli::SectionId| -> Result<SectionData<'_>, gimli::Error> {
        let name = id.name();
        let bytes = elf.section_by_name(name).map_or(&[][..], |(_, _, b)| b);
        Ok(EndianSlice::new(bytes, LittleEndian))
    };
    gimli::Dwarf::load(load_section).ok()
}

fn read_subprogram<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    offset: UnitOffset,
) -> Result<Option<DebugFunction>, DebugError>
where
    R: Reader<Offset = usize>,
{
    // entries_tree lets us re-walk the subprogram's children.
    let mut tree = unit.entries_tree(Some(offset))?;
    let root = tree.root()?;

    let entry = root.entry();
    let Some(addr) = read_low_pc(entry) else {
        return Ok(None);
    };
    let Some(name) = read_name(dwarf, unit, entry)? else {
        return Ok(None);
    };
    let return_type = match attr_unit_ref(entry, constants::DW_AT_type) {
        Some(off) => resolve_type_at(unit, off)?,
        None => Type::Void,
    };

    let mut params = Vec::new();
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let centry = child.entry();
        if centry.tag() == constants::DW_TAG_formal_parameter {
            let pname = read_name(dwarf, unit, centry)?.unwrap_or_default();
            let pty = match attr_unit_ref(centry, constants::DW_AT_type) {
                Some(off) => resolve_type_at(unit, off)?,
                None => Type::Unknown,
            };
            params.push(Param {
                name: pname,
                ty: pty,
                location: None,
            });
        }
    }

    Ok(Some(DebugFunction {
        addr,
        name,
        return_type,
        params,
    }))
}

fn attr_unit_ref<R: Reader<Offset = usize>>(
    entry: &DebuggingInformationEntry<R>,
    name: constants::DwAt,
) -> Option<UnitOffset> {
    match entry.attr_value(name) {
        Some(AttributeValue::UnitRef(off)) => Some(off),
        _ => None,
    }
}

fn read_low_pc<R: Reader>(entry: &DebuggingInformationEntry<R>) -> Option<u64> {
    if let Some(AttributeValue::Addr(a)) = entry.attr_value(constants::DW_AT_low_pc) {
        return Some(a);
    }
    None
}

fn read_name<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<String>, DebugError>
where
    R: Reader<Offset = usize>,
{
    let Some(value) = entry.attr_value(constants::DW_AT_name) else {
        return Ok(None);
    };
    attr_string(dwarf, unit, value)
}

fn attr_string<R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: AttributeValue<R>,
) -> Result<Option<String>, DebugError>
where
    R: Reader<Offset = usize>,
{
    let s = dwarf.attr_string(unit, value)?;
    let bytes = s.to_slice()?;
    Ok(std::str::from_utf8(&bytes).ok().map(str::to_owned))
}

fn resolve_type_at<R>(unit: &gimli::Unit<R>, off: UnitOffset) -> Result<Type, DebugError>
where
    R: Reader<Offset = usize>,
{
    // Bound recursion in case of malformed cycles (typedef → typedef → …).
    resolve_type_inner(unit, off, 0, &mut HashMap::new())
}

fn resolve_type_inner<R>(
    unit: &gimli::Unit<R>,
    off: UnitOffset,
    depth: u32,
    cache: &mut HashMap<UnitOffset, Type>,
) -> Result<Type, DebugError>
where
    R: Reader<Offset = usize>,
{
    if depth > 32 {
        return Ok(Type::Unknown);
    }
    if let Some(t) = cache.get(&off) {
        return Ok(t.clone());
    }
    let mut tree = unit.entries_tree(Some(off))?;
    let root = tree.root()?;
    let entry = root.entry();

    let resolved = match entry.tag() {
        constants::DW_TAG_base_type => resolve_base_type(entry),
        constants::DW_TAG_pointer_type => {
            let inner = match attr_unit_ref(entry, constants::DW_AT_type) {
                Some(o) => resolve_type_inner(unit, o, depth + 1, cache)?,
                None => Type::Void,
            };
            Type::Pointer(Box::new(inner))
        }
        constants::DW_TAG_const_type
        | constants::DW_TAG_volatile_type
        | constants::DW_TAG_restrict_type
        | constants::DW_TAG_typedef => match attr_unit_ref(entry, constants::DW_AT_type) {
            Some(o) => resolve_type_inner(unit, o, depth + 1, cache)?,
            None => Type::Unknown,
        },
        _ => Type::Unknown,
    };

    cache.insert(off, resolved.clone());
    Ok(resolved)
}

fn resolve_base_type<R: Reader>(entry: &DebuggingInformationEntry<R>) -> Type {
    let size = match entry.attr_value(constants::DW_AT_byte_size) {
        Some(AttributeValue::Udata(n) | AttributeValue::Data8(n)) => n,
        Some(AttributeValue::Data1(n)) => u64::from(n),
        Some(AttributeValue::Data2(n)) => u64::from(n),
        Some(AttributeValue::Data4(n)) => u64::from(n),
        _ => return Type::Unknown,
    };
    let Some(AttributeValue::Encoding(encoding)) = entry.attr_value(constants::DW_AT_encoding)
    else {
        return Type::Unknown;
    };

    match (encoding, size) {
        (constants::DW_ATE_boolean, _) => Type::Bool,
        (constants::DW_ATE_signed_char | constants::DW_ATE_unsigned_char, _) => Type::Char,
        (constants::DW_ATE_signed, 1) => Type::I8,
        (constants::DW_ATE_signed, 2) => Type::I16,
        (constants::DW_ATE_signed, 4) => Type::I32,
        (constants::DW_ATE_signed, 8) => Type::I64,
        (constants::DW_ATE_unsigned, 1) => Type::U8,
        (constants::DW_ATE_unsigned, 2) => Type::U16,
        (constants::DW_ATE_unsigned, 4) => Type::U32,
        (constants::DW_ATE_unsigned, 8) => Type::U64,
        (constants::DW_ATE_float, 4) => Type::F32,
        (constants::DW_ATE_float, 8) => Type::F64,
        _ => Type::Unknown,
    }
}

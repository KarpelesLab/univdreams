//! [`FunctionMap`] and its building blocks.
//!
//! Functions are keyed by virtual address. The same address can be named
//! by multiple sources (e.g. the symbol table *and* `.eh_frame`); the
//! map merges them, preferring higher-confidence sources for the name
//! and recording every source that contributed.

use std::collections::BTreeMap;

use ud_core::VAddr;

/// Where a function record came from. Ordered by ascending confidence —
/// higher-numbered sources override lower-numbered ones for fields where
/// they disagree (currently: function name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FunctionSource {
    /// Inferred from a prologue-pattern match. Lowest confidence.
    Prologue = 0,
    /// Recovered from a `.eh_frame` FDE. Yields a real address range
    /// but no name (placeholder `sub_<addr>`).
    EhFrame = 1,
    /// Matched a known byte-pattern signature (CRT helpers, libc
    /// primitives, …). Yields a meaningful name; placed above
    /// `EhFrame` so the name overrides eh_frame's placeholder.
    Signature = 2,
    /// Resolved as a `.plt` thunk via `.rela.plt` → `.dynsym`. Yields
    /// the imported symbol's name (e.g. `printf`).
    Plt = 3,
    /// Read from `.dynsym` (dynamic linker's symbol table).
    DynSym = 4,
    /// Read from `.symtab` (full symbol table; absent in stripped binaries).
    SymTab = 5,
    /// Provided by the user via an override file.
    UserOverride = 6,
}

/// A discovered function.
///
/// `size` may be zero when the source did not record one (e.g. `.eh_frame`
/// gives a range, but some symbol-table entries leave `st_size = 0`).
/// Consumers should treat zero size as "unknown" and resolve via boundary
/// inference (next-function-start, end-of-section) when needed.
#[derive(Debug, Clone)]
pub struct Function {
    pub addr: VAddr,
    pub size: u64,
    pub name: String,
    pub sources: Vec<FunctionSource>,
}

impl Function {
    fn merge_in(&mut self, other: Function) {
        // Size precedence: a [`FunctionSource::Plt`] record is
        // size-authoritative — each PLT thunk is exactly `sh_entsize`
        // bytes and the relocation linkage doesn't lie about the
        // boundary. Whatever else discovery thinks the function spans
        // (e.g. an `.eh_frame` FDE that swallows the whole `.plt.sec`
        // section as one function), the PLT size wins. Otherwise we
        // never let zero overwrite non-zero.
        let other_is_plt_authoritative =
            other.sources.contains(&FunctionSource::Plt) && other.size > 0;
        let self_is_plt_authoritative =
            self.sources.contains(&FunctionSource::Plt) && self.size > 0;
        let take_other_size = (other_is_plt_authoritative && !self_is_plt_authoritative)
            || (other.size > 0 && self.size == 0);
        if take_other_size {
            self.size = other.size;
        }

        // Highest-confidence source wins the name.
        let highest_existing = self.sources.iter().copied().max();
        let incoming = other.sources.iter().copied().max();
        if let (Some(existing), Some(incoming)) = (highest_existing, incoming) {
            if incoming > existing {
                self.name = other.name;
            }
        } else if highest_existing.is_none() {
            self.name = other.name;
        }
        for src in other.sources {
            if !self.sources.contains(&src) {
                self.sources.push(src);
            }
        }
        self.sources.sort();
    }
}

/// A collection of discovered functions, indexed by address.
///
/// Inserting a [`Function`] whose address is already present merges the
/// records: provenance (`sources`) accumulates, the highest-confidence
/// source wins the name, and a non-zero size never gets clobbered by zero.
#[derive(Debug, Clone, Default)]
pub struct FunctionMap {
    by_addr: BTreeMap<u64, Function>,
}

impl FunctionMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function, merging if one already exists at the same address.
    pub fn insert(&mut self, func: Function) {
        match self.by_addr.entry(func.addr.0) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(func);
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                e.get_mut().merge_in(func);
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }

    /// Functions in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.by_addr.values()
    }

    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&Function> {
        self.by_addr.get(&addr)
    }

    /// Find the function whose `[addr, addr + size)` range contains `addr`,
    /// if any. For functions with `size = 0` the result is `None` because
    /// the range is empty.
    #[must_use]
    pub fn containing(&self, addr: u64) -> Option<&Function> {
        self.by_addr
            .range(..=addr)
            .next_back()
            .and_then(|(start, f)| {
                let end = start.saturating_add(f.size);
                (f.size > 0 && addr < end).then_some(f)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(addr: u64, size: u64, name: &str, source: FunctionSource) -> Function {
        Function {
            addr: VAddr(addr),
            size,
            name: name.to_string(),
            sources: vec![source],
        }
    }

    #[test]
    fn empty_map_has_no_functions() {
        let m = FunctionMap::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn insert_then_get() {
        let mut m = FunctionMap::new();
        m.insert(func(0x1000, 0x40, "main", FunctionSource::SymTab));
        assert_eq!(m.len(), 1);
        let f = m.get(0x1000).unwrap();
        assert_eq!(f.name, "main");
        assert_eq!(f.size, 0x40);
    }

    #[test]
    fn merge_keeps_higher_confidence_name() {
        let mut m = FunctionMap::new();
        m.insert(func(0x1000, 0x40, "sub_1000", FunctionSource::Prologue));
        m.insert(func(0x1000, 0x40, "main", FunctionSource::SymTab));
        let f = m.get(0x1000).unwrap();
        assert_eq!(f.name, "main");
        assert_eq!(f.sources.len(), 2);
    }

    #[test]
    fn merge_does_not_replace_with_lower_confidence_name() {
        let mut m = FunctionMap::new();
        m.insert(func(0x1000, 0x40, "main", FunctionSource::SymTab));
        m.insert(func(0x1000, 0x40, "sub_1000", FunctionSource::Prologue));
        let f = m.get(0x1000).unwrap();
        assert_eq!(f.name, "main");
        assert_eq!(f.sources.len(), 2);
    }

    #[test]
    fn merge_preserves_size_when_new_record_lacks_one() {
        let mut m = FunctionMap::new();
        m.insert(func(0x1000, 0x40, "main", FunctionSource::SymTab));
        m.insert(func(0x1000, 0, "main", FunctionSource::EhFrame));
        let f = m.get(0x1000).unwrap();
        assert_eq!(f.size, 0x40);
    }

    #[test]
    fn containing_returns_function_for_address_inside_range() {
        let mut m = FunctionMap::new();
        m.insert(func(0x1000, 0x40, "a", FunctionSource::SymTab));
        m.insert(func(0x2000, 0x40, "b", FunctionSource::SymTab));
        assert_eq!(m.containing(0x1010).unwrap().name, "a");
        assert_eq!(m.containing(0x103f).unwrap().name, "a");
        assert!(m.containing(0x1040).is_none()); // exclusive end
        assert_eq!(m.containing(0x2000).unwrap().name, "b");
    }

    #[test]
    fn containing_skips_zero_sized_entries() {
        let mut m = FunctionMap::new();
        m.insert(func(0x1000, 0, "no_size", FunctionSource::EhFrame));
        assert!(m.containing(0x1000).is_none());
    }
}

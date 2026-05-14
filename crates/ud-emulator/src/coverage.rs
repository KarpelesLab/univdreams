//! Execution coverage tracker.
//!
//! Records every guest address at which an instruction was
//! fetched and every guest address that was written by the
//! interpreter, with the size of the access. Built into the
//! [`Mmu`](crate::emulator::Mmu) so the recording happens at
//! the same probe sites the trace feature uses, without
//! requiring the `trace` feature to be enabled.
//!
//! The static decompiler consumes this map to:
//!
//! * Identify code at addresses the static function-discovery
//!   pass missed (unaligned entry points, obfuscated trampolines).
//! * Flag pages that were written by the running code and then
//!   executed from — the classic unpacker / self-modifying-code
//!   signature. Bytes in those regions are not the static
//!   source-of-truth and should round-trip through `@raw`
//!   instead of a structured directive.
//!
//! The recorder does *not* attempt to resolve indirect call
//! targets. A `call eax` may dispatch to a different function
//! every time it executes; pinning the observed target into
//! the static AST would actively miscode every other caller.
//! What's recorded is "this byte was executed as the first
//! byte of an instruction at least once", which is a property
//! of the bytes themselves, not of the caller.

use std::collections::{BTreeMap, BTreeSet};

/// Per-address execution + write metadata harvested over the
/// lifetime of one (or more) interpreter runs.
///
/// The map is always-on inside the [`Mmu`](crate::emulator::Mmu);
/// callers that don't want coverage data simply ignore it.
/// Cost is two hash operations per executed instruction and
/// one per memory write, which is dwarfed by the rest of the
/// interpreter.
#[derive(Default, Clone)]
pub struct CoverageMap {
    /// Every guest address at which an instruction's first byte
    /// was fetched. Sparse set — typical workloads execute a
    /// few thousand to a few million unique addresses.
    executed: BTreeSet<u32>,
    /// Per-address memory writes. The value is the largest
    /// access width seen at that address (1, 2, 4, or 8 bytes);
    /// re-writes update the maximum so a later `mov [addr], al`
    /// after a `mov [addr], rax` doesn't shrink the recorded
    /// span.
    writes: BTreeMap<u32, u8>,
}

impl CoverageMap {
    /// Drop everything. Useful between runs when the caller
    /// wants per-export coverage instead of cumulative.
    pub fn clear(&mut self) {
        self.executed.clear();
        self.writes.clear();
    }

    /// Record an instruction fetch at `eip`. The first byte of
    /// every dispatched instruction lands here exactly once per
    /// occurrence — multiple hits at the same address share the
    /// set entry. `insn_size` lets the analyzer infer per-
    /// instruction coverage spans without re-decoding; today
    /// only the first byte is recorded (size hint is reserved
    /// for a future per-instruction-span variant).
    pub fn record_exec(&mut self, eip: u32, _insn_size: u8) {
        self.executed.insert(eip);
    }

    /// Record a guest memory write. `size` is the access width
    /// in bytes (1/2/4/8). Each address tracks the *maximum*
    /// width seen so the recorded write spans cover the
    /// widest store that touched the byte.
    pub fn record_write(&mut self, addr: u32, size: u32) {
        let size_u8 = size.min(8).max(1) as u8;
        for off in 0..size {
            let target = addr.wrapping_add(off);
            let slot = self.writes.entry(target).or_insert(size_u8);
            if size_u8 > *slot {
                *slot = size_u8;
            }
        }
    }

    /// Iterator over every executed address.
    pub fn executed_addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.executed.iter().copied()
    }

    /// Total number of distinct executed addresses.
    pub fn executed_count(&self) -> usize {
        self.executed.len()
    }

    /// Iterator over every written address. Re-yielding for
    /// each byte covered by a wider write means a single
    /// 4-byte `mov [addr], eax` produces 4 entries.
    pub fn written_addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.writes.keys().copied()
    }

    /// True when `addr` was both written and later executed
    /// (in this map's lifetime). Detection is conservative —
    /// the same address being written and executed *out of
    /// order* still trips the check, since the static
    /// decompiler treats either ordering as suspect.
    pub fn is_self_modifying(&self, addr: u32) -> bool {
        self.writes.contains_key(&addr) && self.executed.contains(&addr)
    }

    /// Every address that was both written and executed.
    pub fn self_modifying_addresses(&self) -> impl Iterator<Item = u32> + '_ {
        self.executed
            .iter()
            .copied()
            .filter(move |a| self.writes.contains_key(a))
    }

    /// Collapse the executed-address set into contiguous
    /// `[start, end)` ranges (end is exclusive). Two
    /// consecutive addresses count as contiguous; gaps of any
    /// size start a new range. Useful for spotting unaligned
    /// code chunks the static function discovery missed.
    pub fn executed_ranges(&self) -> Vec<std::ops::Range<u32>> {
        let mut out = Vec::new();
        let mut current: Option<std::ops::Range<u32>> = None;
        for &addr in &self.executed {
            match current.as_mut() {
                Some(r) if r.end == addr => {
                    r.end = addr.wrapping_add(1);
                }
                _ => {
                    if let Some(r) = current.take() {
                        out.push(r);
                    }
                    current = Some(addr..addr.wrapping_add(1));
                }
            }
        }
        if let Some(r) = current {
            out.push(r);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_exec_dedupes() {
        let mut c = CoverageMap::default();
        c.record_exec(0x1000, 3);
        c.record_exec(0x1000, 3);
        c.record_exec(0x1003, 2);
        assert_eq!(c.executed_count(), 2);
    }

    #[test]
    fn record_write_expands_per_byte() {
        let mut c = CoverageMap::default();
        c.record_write(0x2000, 4);
        assert_eq!(c.written_addresses().count(), 4);
    }

    #[test]
    fn is_self_modifying_detects_write_then_exec() {
        let mut c = CoverageMap::default();
        c.record_write(0x3000, 4);
        c.record_exec(0x3001, 1);
        assert!(c.is_self_modifying(0x3001));
        assert!(!c.is_self_modifying(0x4000));
    }

    #[test]
    fn executed_ranges_merges_adjacent() {
        let mut c = CoverageMap::default();
        // 0x1000, 0x1001, 0x1002 — contiguous.
        // 0x1005 — separate.
        for a in &[0x1000u32, 0x1001, 0x1002, 0x1005] {
            c.record_exec(*a, 1);
        }
        let ranges = c.executed_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 0x1000..0x1003);
        assert_eq!(ranges[1], 0x1005..0x1006);
    }
}

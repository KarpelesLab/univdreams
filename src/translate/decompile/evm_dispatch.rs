//! Vyper ≥0.3.10's selector tables.
//!
//! From 0.3.10 Vyper no longer tests selectors one after another: it
//! hashes the selector into a bucket, copies the bucket's entry out of
//! a table in the code's data section, and jumps through it. Two
//! layouts exist:
//!
//! * **Sparse** (`-O codesize`): `sel % n` indexes a table of 2-byte
//!   code offsets, one per bucket; each bucket is a short chain of
//!   `PUSH4 sel; DUP2; XOR; PUSH2 next; JUMPI` tests followed by the
//!   function bodies, as in Vyper 0.3.
//!
//!   ```text
//!   PUSH0 CALLDATALOAD PUSH1 0xe0 SHR
//!   PUSH1 2 PUSH1 n DUP3 MOD PUSH1 1 SHL PUSH2 table ADD
//!   PUSH1 0x1e CODECOPY PUSH0 MLOAD JUMP
//!   ```
//!
//!   (`PUSH1 n-1 … AND` when `n` is a power of two, and `PUSH1 0`
//!   for `PUSH0` before Shanghai.)
//!
//! * **Dense** (the default, `-O gas`): `sel % n` picks a 5-byte bucket
//!   header `magic(2) ‖ location(2) ‖ size(1)`; `(sel * magic >> 24) %
//!   size` then picks a 7-byte entry `selector(4) ‖ label(2) ‖
//!   flags(1)` at `location`. The selector is compared once, the flags
//!   give the minimum calldata size and payability, and the code jumps
//!   to `label`, the function body itself.
//!
//!   ```text
//!   PUSH1 5 PUSH1 5 PUSH1 n DUP4 MOD MUL PUSH2 headers ADD
//!   PUSH1 0x1b CODECOPY PUSH0 MLOAD PUSH1 7 PUSH1 7 …
//!   … DUP1 PUSH1 8 SHR PUSH2 0xffff AND JUMP
//!   ```
//!
//! The tables are read from the code, so every entry point is known:
//! the jump's targets for the CFG, the functions' names, and the
//! table words an edit that moves code has to rewrite.

use std::collections::BTreeMap;

use crate::arch::evm::{DecodedInsn, JUMPDEST, decode_range};

/// Instructions decoded from offset 0 to find the dispatcher.
const PROLOGUE_INSNS: usize = 128;
/// Cases followed along one sparse bucket's chain, at most.
const MAX_CHAIN: usize = 256;

/// A recognised selector-table dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HashDispatch {
    /// Dense (one entry per function) rather than sparse (a chain of
    /// tests per bucket).
    pub dense: bool,
    /// Offset of the `JUMP` through the table.
    pub jump: u64,
    /// Where it can go: bucket heads (sparse) or function bodies.
    pub targets: Vec<u64>,
    /// Function entry → selector.
    pub selectors: BTreeMap<u64, u32>,
    /// Table bytes, sorted and disjoint.
    pub spans: Vec<(u64, u64)>,
    /// Offsets of the big-endian 2-byte table words that hold code
    /// offsets (bucket heads, labels) or table offsets (a dense
    /// bucket's entry location).
    pub words: Vec<u64>,
    /// Offset of the `PUSH` of the table's own address.
    pub base: u64,
}

fn word16(code: &[u8], at: u64) -> Option<u64> {
    let at = usize::try_from(at).ok()?;
    let b = code.get(at..at + 2)?;
    Some(u64::from(u16::from_be_bytes([b[0], b[1]])))
}

/// The dispatcher at the start of `code`, if it is one of the two
/// table layouts and every table entry lands on a `JUMPDEST`.
pub(crate) fn find(code: &[u8]) -> Option<HashDispatch> {
    let head = decode_range(&code[..code.len().min(PROLOGUE_INSNS * 3)], 0);
    let insns = &head[..head.len().min(PROLOGUE_INSNS)];
    let d =
        (0..insns.len()).find_map(|i| sparse(code, insns, i).or_else(|| dense(code, insns, i)))?;
    let is_dest = |a: &u64| usize::try_from(*a).is_ok_and(|a| code.get(a) == Some(&JUMPDEST));
    (d.targets.iter().all(is_dest) && d.selectors.keys().all(is_dest)).then_some(d)
}

fn op(insns: &[DecodedInsn], k: usize) -> Option<u8> {
    insns.get(k).map(|x| x.opcode)
}

fn pv(insns: &[DecodedInsn], k: usize) -> Option<u64> {
    insns.get(k).and_then(DecodedInsn::push_value)
}

fn is_dup(o: Option<u8>) -> bool {
    o.is_some_and(|o| (0x80..=0x8f).contains(&o))
}

fn sparse(code: &[u8], insns: &[DecodedInsn], i: usize) -> Option<HashDispatch> {
    let shape = pv(insns, i) == Some(2)
        && is_dup(op(insns, i + 2))
        && matches!(op(insns, i + 3), Some(0x06 | 0x16))
        && pv(insns, i + 4) == Some(1)
        && op(insns, i + 5) == Some(0x1b)
        && op(insns, i + 7) == Some(0x01)
        && pv(insns, i + 8) == Some(0x1e)
        && op(insns, i + 9) == Some(0x39)
        && pv(insns, i + 10) == Some(0)
        && op(insns, i + 11) == Some(0x51)
        && op(insns, i + 12) == Some(0x56);
    if !shape {
        return None;
    }
    // `sel % n`, or `sel & (n - 1)` for a power of two.
    let n = match (op(insns, i + 3), pv(insns, i + 1)?) {
        (Some(0x16), m) => Some(m + 1).filter(|n| n.is_power_of_two()),
        (_, n) => Some(n).filter(|&n| n > 0),
    }?;
    let table = pv(insns, i + 6)?;
    if table.checked_add(2 * n)? > code.len() as u64 {
        return None;
    }
    let words: Vec<u64> = (0..n).map(|b| table + 2 * b).collect();
    let mut targets: Vec<u64> = words
        .iter()
        .map(|&w| word16(code, w))
        .collect::<Option<_>>()?;
    let mut selectors = BTreeMap::new();
    for &head in &targets {
        let mut at = head;
        for _ in 0..MAX_CHAIN {
            let Some((sel, next)) = case_at(code, at) else {
                break;
            };
            selectors.insert(at, sel);
            at = next;
        }
    }
    targets.sort_unstable();
    targets.dedup();
    Some(HashDispatch {
        dense: false,
        jump: insns[i + 12].addr.0,
        targets,
        selectors,
        spans: vec![(table, table + 2 * n)],
        words,
        base: insns[i + 6].addr.0,
    })
}

/// `JUMPDEST PUSH4 sel DUPn XOR PUSH2 next JUMPI` at `at`.
fn case_at(code: &[u8], at: u64) -> Option<(u32, u64)> {
    let start = usize::try_from(at).ok()?;
    let window = code.get(start..code.len().min(start + 16))?;
    let c = decode_range(window, at);
    (op(&c, 0) == Some(JUMPDEST)
        && op(&c, 1) == Some(0x63)
        && is_dup(op(&c, 2))
        && op(&c, 3) == Some(0x18)
        && op(&c, 5) == Some(0x57))
    .then_some(())?;
    let sel = u32::try_from(pv(&c, 1)?).ok()?;
    let next = pv(&c, 4).filter(|&n| n > at)?;
    Some((sel, next))
}

/// Header and entry sizes of the dense layout.
const HEADER: u64 = 5;
const ENTRY: u64 = 7;

fn dense(code: &[u8], insns: &[DecodedInsn], i: usize) -> Option<HashDispatch> {
    let shape = pv(insns, i) == Some(HEADER)
        && pv(insns, i + 1) == Some(HEADER)
        && is_dup(op(insns, i + 3))
        && op(insns, i + 4) == Some(0x06)
        && op(insns, i + 5) == Some(0x02)
        && op(insns, i + 7) == Some(0x01)
        && pv(insns, i + 8) == Some(32 - HEADER)
        && op(insns, i + 9) == Some(0x39)
        && pv(insns, i + 10) == Some(0)
        && op(insns, i + 11) == Some(0x51)
        && pv(insns, i + 12) == Some(ENTRY)
        && pv(insns, i + 13) == Some(ENTRY);
    if !shape {
        return None;
    }
    let n = pv(insns, i + 2).filter(|&n| n > 0)?;
    let headers = pv(insns, i + 6)?;
    // `… DUP1 PUSH1 8 SHR PUSH2 0xffff AND JUMP`: the label.
    let jump = (i + 14..insns.len()).find(|&k| {
        op(insns, k) == Some(0x56)
            && op(insns, k - 1) == Some(0x16)
            && pv(insns, k - 2) == Some(0xffff)
            && op(insns, k - 3) == Some(0x1c)
            && pv(insns, k - 4) == Some(8)
    })?;
    let mut spans = vec![(headers, headers.checked_add(HEADER * n)?)];
    let mut words = Vec::new();
    let mut selectors = BTreeMap::new();
    for b in 0..n {
        let h = headers + HEADER * b;
        let loc = word16(code, h + 2)?;
        let size = u64::from(*code.get(usize::try_from(h + 4).ok()?)?);
        words.push(h + 2);
        if size == 0 {
            continue;
        }
        spans.push((loc, loc.checked_add(ENTRY * size)?));
        for k in 0..size {
            let e = loc + ENTRY * k;
            let at = usize::try_from(e).ok()?;
            let sel = u32::from_be_bytes(code.get(at..at + 4)?.try_into().ok()?);
            selectors.insert(word16(code, e + 4)?, sel);
            words.push(e + 4);
        }
    }
    if spans.iter().any(|&(_, e)| e > code.len() as u64) {
        return None;
    }
    spans.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    Some(HashDispatch {
        dense: true,
        jump: insns[jump].addr.0,
        targets: selectors.keys().copied().collect(),
        selectors,
        spans: merged,
        words,
        base: insns[i + 6].addr.0,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A sparse dispatcher over two buckets: bucket 0 tests
    /// `transfer`, bucket 1 `approve` then `0xdeadbeef`; misses
    /// revert at 0x40, a match stops.
    pub(crate) fn sparse_contract() -> Vec<u8> {
        let mut c = vec![
            0x5f, 0x35, 0x60, 0xe0, 0x1c, // 00 sel
            0x60, 0x02, 0x60, 0x02, 0x82, 0x06, 0x60, 0x01, 0x1b, // 05 2 * (sel % 2)
            0x61, 0x00, 0x50, 0x01, 0x60, 0x1e, 0x39, 0x5f, 0x51, 0x56, // 0e table at 0x50
        ];
        let case = |c: &mut Vec<u8>, sel: [u8; 4], next: u8| {
            c.extend([0x5b, 0x63]);
            c.extend(sel);
            c.extend([0x81, 0x18, 0x61, 0x00, next, 0x57, 0x00]);
        };
        assert_eq!(c.len(), 0x18);
        case(&mut c, [0xa9, 0x05, 0x9c, 0xbb], 0x40); // 18
        case(&mut c, [0x09, 0x5e, 0xa7, 0xb3], 0x34); // 25
        c.extend([0xfe, 0xfe]);
        case(&mut c, [0xde, 0xad, 0xbe, 0xef], 0x40); // 34
        c.resize(0x40, 0xfe);
        c.extend([0x5b, 0x5f, 0x5f, 0xfd]); // 40 revert
        c.resize(0x50, 0xfe);
        c.extend([0x00, 0x18, 0x00, 0x25]); // 50 table
        c
    }

    #[test]
    fn sparse_buckets_and_chains() {
        let mut code = sparse_contract();
        let d = find(&code).expect("sparse dispatcher");
        assert!(!d.dense);
        assert_eq!(d.jump, 0x17);
        assert_eq!(d.targets, [0x18, 0x25]);
        assert_eq!(
            d.selectors,
            BTreeMap::from([
                (0x18, 0xa905_9cbb),
                (0x25, 0x095e_a7b3),
                (0x34, 0xdead_beef)
            ])
        );
        assert_eq!(d.spans, [(0x50, 0x54)]);
        assert_eq!(d.words, [0x50, 0x52]);
        assert_eq!(d.base, 0x0e);
        // A table entry off a JUMPDEST isn't a dispatcher.
        code[0x51] = 0x19;
        assert_eq!(find(&code), None);
    }

    /// A dense dispatcher with one bucket of two entries (magic 1, so
    /// the parity of the selector's top byte picks the entry):
    /// `totalSupply()` returns 0x2a, nonpayable `transfer(address,
    /// uint256)` returns 1 and wants 0x44 bytes of calldata.
    pub(crate) fn dense_contract() -> Vec<u8> {
        let mut c = vec![0x5f, 0x35, 0x60, 0xe0, 0x1c]; // sel
        // CODECOPY(0x1b, headers + 5 * (sel % 1), 5)
        c.extend([
            0x60, 0x05, 0x60, 0x05, 0x60, 0x01, 0x83, 0x06, 0x02, 0x61, 0, 0,
        ]);
        let headers_at = c.len() - 2;
        c.extend([0x01, 0x60, 0x1b, 0x39, 0x5f, 0x51]);
        // CODECOPY(0x19, loc + 7 * ((sel * magic >> 24) % size), 7)
        c.extend([
            0x60, 0x07, 0x60, 0x07, 0x82, 0x60, 0xff, 0x16, 0x84, 0x84, 0x60, 0x18, 0x1c, 0x02,
            0x60, 0x18, 0x1c, 0x06, 0x02, 0x82, 0x60, 0x08, 0x1c, 0x61, 0xff, 0xff, 0x16, 0x01,
            0x60, 0x19, 0x39, 0x50, 0x5f, 0x51,
        ]);
        // The selector matches and there is calldata, or fall back.
        c.extend([
            0x81, 0x81, 0x60, 0x18, 0x1c, 0x14, 0x60, 0x03, 0x36, 0x11, 0x16,
        ]);
        c.extend([0x61, 0, 0, 0x57, 0x61, 0, 0, 0x56]);
        let (checks_at, fallback_at) = (c.len() - 7, c.len() - 3);
        let checks = c.len();
        // Payability and calldata size from the flags, then the label.
        c.extend([
            0x5b, 0x80, 0x60, 0xfe, 0x16, 0x36, 0x10, 0x34, 0x82, 0x60, 0x01, 0x16, 0x02, 0x17,
            0x61, 0, 0, 0x57, 0x80, 0x60, 0x08, 0x1c, 0x61, 0xff, 0xff, 0x16, 0x56,
        ]);
        let fail_at = c.len() - 12;
        let ret = |c: &mut Vec<u8>, v: u8| {
            let at = c.len();
            c.extend([0x5b, 0x60, v, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
            at
        };
        let total_supply = ret(&mut c, 0x2a);
        let transfer = ret(&mut c, 0x01);
        let fail = c.len();
        c.extend([0x5b, 0x5f, 0x5f, 0xfd]);
        let headers = c.len();
        let be16 = |v: usize| u16::try_from(v).expect("small").to_be_bytes();
        c.extend([0x00, 0x01]);
        c.extend(be16(headers + 5));
        c.push(2);
        for (sel, label, flags) in [
            (0x1816_0dddu32, total_supply, 0x04u8),
            (0xa905_9cbb, transfer, 0x45),
        ] {
            c.extend(sel.to_be_bytes());
            c.extend(be16(label));
            c.push(flags);
        }
        for (at, v) in [
            (headers_at, headers),
            (checks_at, checks),
            (fallback_at, fail),
            (fail_at, fail),
        ] {
            c.splice(at..at + 2, be16(v));
        }
        c
    }

    #[test]
    fn dense_buckets_and_entries() {
        let code = dense_contract();
        let d = find(&code).expect("dense dispatcher");
        assert!(d.dense);
        let end = code.len() as u64;
        let (ts, tr) = (end - 41, end - 32);
        assert_eq!(
            d.selectors,
            BTreeMap::from([(ts, 0x1816_0ddd), (tr, 0xa905_9cbb)])
        );
        assert_eq!(d.targets, [ts, tr]);
        let headers = end - 19;
        assert_eq!(d.spans, [(headers, end)]);
        assert_eq!(d.words, [headers + 2, headers + 9, headers + 16]);
        assert_eq!(code[usize::try_from(d.jump).unwrap()], 0x56);
    }
}

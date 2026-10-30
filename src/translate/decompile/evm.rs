//! Decompile EVM contract bytecode into a `.ud` AST.
//!
//! Contract:
//!
//! ```text
//! lower_to_evm(parse(decompile_evm_to_text(code))) == code
//! ```
//!
//! Layout recovery, in order:
//!
//! 1. **Data regions.** A per-block constant tracker follows
//!    `PUSH`/`DUP`/`SWAP`/`ADD`/`SUB` and records every `CODECOPY`
//!    whose offset and size are constants: initcode copying out the
//!    runtime it deploys, or runtime code reading a constant table.
//!    Those spans become `@raw` blocks, as does the compiler metadata
//!    trailer when it isn't already inside one.
//! 2. **Functions.** The Solidity / Vyper selector dispatcher
//!    (`PUSH4 sel; EQ; PUSH2 dest; JUMPI`, optionally with `DUP2`
//!    before the `EQ`) names its targets after the selector — via
//!    the [`crate::signatures::evm`] table when the signature is
//!    known, `fn_<selector>` otherwise. Internal functions found by
//!    `evm_cfg` become `sub_<addr>`, with their argument and
//!    return counts. Code at offset 0 is `entry`. Each function runs to
//!    the next entry, giving a contiguous cover as the 6502 path does.
//! 3. **Bodies.** By default, `evm_lift` turns each function
//!    into statements over named stack slots — expressions,
//!    `sstore`/`mstore`/`log`, internal calls and returns,
//!    `if`/`while`/`do … while`, `require(…)` / `revert(Err())`. That
//!    view is read-only: every statement pins the bytes it stands for,
//!    so editing its text changes nothing.
//!
//!    [`decompile_evm_listing`] instead emits one `@asm` line per
//!    instruction, with `JUMPDEST` labels and jump-target / selector /
//!    event annotations. Bytes are dropped wherever the text
//!    re-assembles to them exactly (all instructions but truncated
//!    pushes), so in that form the text is the source of truth and
//!    edits to mnemonics or immediates recompile. Jump targets are
//!    absolute: an edit that changes code length must fix up the
//!    affected `PUSH` targets by hand.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;

use crate::arch::evm::{self, DecodedInsn, InsnKind, classify, decode_range, format_insn};
use crate::ast::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};
use crate::format::evm::{Metadata, delegation_target, metadata_trailer};
use crate::signatures::evm::{event_by_topic, function_by_selector, slot_name};
use crate::translate::decompile::{evm_cfg, evm_lift};

/// What a non-code span holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataKind {
    /// Copied out by `CODECOPY` at this instruction offset.
    CodeCopy { at: u64 },
    /// Compiler metadata trailer.
    Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataRegion {
    start: u64,
    end: u64,
    kind: DataKind,
}

/// Build the AST for a contract's bytecode, with function bodies
/// lifted to statements (see `evm_lift`).
#[must_use]
pub fn decompile_evm(code: &[u8]) -> UdFile {
    decompile_evm_impl(code, true)
}

/// Build the AST as an instruction listing: one `@asm` line per
/// instruction, with bytes dropped wherever the text re-assembles to
/// them — the form to use when editing the code itself.
#[must_use]
pub fn decompile_evm_listing(code: &[u8]) -> UdFile {
    decompile_evm_impl(code, false)
}

/// Convenience: lifted AST + canonical pretty-print.
#[must_use]
pub fn decompile_evm_to_text(code: &[u8]) -> String {
    crate::ast::emit(&decompile_evm(code))
}

/// Convenience: instruction listing + canonical pretty-print.
#[must_use]
pub fn decompile_evm_listing_to_text(code: &[u8]) -> String {
    crate::ast::emit(&decompile_evm_listing(code))
}

#[allow(clippy::too_many_lines)]
fn decompile_evm_impl(code: &[u8], lift: bool) -> UdFile {
    let metadata = metadata_trailer(code);
    let module = build_module(code, metadata.as_ref());

    if let Some(target) = delegation_target(code) {
        let items = vec![
            Item::Comment(format!(
                "EIP-7702 delegation designator: this account runs the code of 0x{}",
                hex(&target)
            )),
            Item::Raw {
                addr: 0,
                bytes: code.to_vec(),
            },
        ];
        return UdFile { module, items };
    }

    let Layout {
        regions,
        segments,
        insns,
        jumpdests,
        selectors,
    } = layout(code, metadata.as_ref());
    let cfg = evm_cfg::build(&insns);
    let internal: BTreeMap<u64, &evm_cfg::FuncInfo> = cfg
        .functions
        .iter()
        .map(|(&b, info)| (cfg.blocks[b].start, info))
        .collect();
    let names = name_functions(&segments, &selectors, internal.keys().copied());

    // Each function runs from its entry to the next entry (or the end
    // of its code segment).
    let entry_addrs: Vec<u64> = names.keys().copied().collect();
    let ranges: Vec<(u64, u64)> = entry_addrs
        .iter()
        .enumerate()
        .map(|(n, &entry)| {
            let seg_end = segments
                .iter()
                .find(|&&(s, e)| entry >= s && entry < e)
                .map_or(entry, |&(_, e)| e);
            let end = entry_addrs
                .get(n + 1)
                .copied()
                .filter(|&next| next < seg_end)
                .unwrap_or(seg_end);
            (entry, end)
        })
        .collect();

    let listing = |slice: &[DecodedInsn]| build_body(slice, &jumpdests, &names);
    let bodies: Vec<Vec<Stmt>> = if lift {
        let ctx = evm_lift::LiftCtx {
            code,
            insns: &insns,
            cfg: &cfg,
            names: &names,
            listing: &listing,
            continuations: cfg
                .conts
                .values()
                .flatten()
                .map(|&b| cfg.blocks[b].start)
                .collect(),
            params: selectors
                .iter()
                .filter_map(|(&addr, &sel)| {
                    let types = static_params(function_by_selector(sel)?)?;
                    Some((addr, types.len()))
                })
                .collect(),
        };
        evm_lift::lift_ranges(&ctx, &ranges)
    } else {
        ranges
            .iter()
            .map(|&(start, end)| {
                let lo = insns.partition_point(|i| i.addr.0 < start);
                let hi = insns.partition_point(|i| i.addr.0 < end);
                listing(&insns[lo..hi])
            })
            .collect()
    };

    // Who calls each internal function, by caller function name.
    let range_name = |addr: u64| {
        let i = ranges
            .partition_point(|&(s, _)| s <= addr)
            .saturating_sub(1);
        names[&ranges[i].0].clone()
    };
    let mut callers: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (&site, call) in &cfg.calls {
        let list = callers.entry(cfg.blocks[call.callee].start).or_default();
        let who = range_name(cfg.blocks[site].start);
        if !list.contains(&who) {
            list.push(who);
        }
    }

    let mut items: Vec<Item> = Vec::new();
    let mut region_iter = regions.iter().peekable();
    for (&(entry, _), body) in ranges.iter().zip(bodies) {
        // Data regions that sit before this function.
        while let Some(r) = region_iter.next_if(|r| r.start < entry) {
            push_region(&mut items, code, r);
        }
        if let Some(sel) = selectors.get(&entry) {
            let what = match function_by_selector(*sel) {
                // Name the parameters the body refers to.
                Some(sig) if lift && static_params(sig).is_some_and(|t| !t.is_empty()) => {
                    let types = static_params(sig).unwrap_or_default();
                    let named: Vec<String> = types
                        .iter()
                        .enumerate()
                        .map(|(k, t)| format!("{t} param{k}"))
                        .collect();
                    format!(
                        "{}({})",
                        sig.split('(').next().unwrap_or(sig),
                        named.join(", ")
                    )
                }
                Some(sig) => sig.to_string(),
                None => "unknown signature".to_string(),
            };
            items.push(Item::Comment(format!("selector 0x{sel:08x}: {what}")));
        }
        if let Some(info) = internal.get(&entry) {
            let rets = info
                .nrets
                .map_or_else(|| "unknown".to_string(), |n| n.to_string());
            let from = callers
                .get(&entry)
                .map_or_else(String::new, |c| format!("; called from {}", c.join(", ")));
            items.push(Item::Comment(format!(
                "internal function: {} argument(s), {rets} return value(s){from}",
                info.nargs
            )));
        }
        items.push(Item::Function(FnDecl {
            addr: Some(entry),
            name: names[&entry].clone(),
            attrs: Vec::new(),
            signature: None,
            locals: Vec::new(),
            body,
        }));
    }
    for r in region_iter {
        push_region(&mut items, code, r);
    }

    UdFile { module, items }
}

/// Everything recovered about where code, data and functions are.
struct Layout {
    regions: Vec<DataRegion>,
    /// Code spans, the complement of `regions`.
    segments: Vec<(u64, u64)>,
    /// Every code segment decoded, in address order.
    insns: Vec<DecodedInsn>,
    jumpdests: BTreeSet<u64>,
    /// Dispatcher target → selector.
    selectors: BTreeMap<u64, u32>,
}

fn layout(code: &[u8], metadata: Option<&Metadata>) -> Layout {
    let regions = find_data_regions(code, metadata);
    let segments = code_segments(code.len() as u64, &regions);
    let mut insns: Vec<DecodedInsn> = Vec::new();
    for &(start, end) in &segments {
        insns.extend(decode_range(&code[start as usize..end as usize], start));
    }
    let jumpdests: BTreeSet<u64> = insns
        .iter()
        .filter(|i| classify(i) == InsnKind::JumpDest)
        .map(|i| i.addr.0)
        .collect();
    let selectors = find_dispatch_targets(&insns, &jumpdests);
    Layout {
        regions,
        segments,
        insns,
        jumpdests,
        selectors,
    }
}

fn push_region(items: &mut Vec<Item>, code: &[u8], r: &DataRegion) {
    let bytes = &code[r.start as usize..r.end as usize];
    let note = match r.kind {
        DataKind::CodeCopy { at } => {
            let mut s = format!(
                "data 0x{:04x}..0x{:04x}: CODECOPY source at 0x{at:04x}",
                r.start, r.end
            );
            if crate::format::evm::looks_like_evm(bytes) {
                s.push_str(
                    " — embedded contract code (initcode deploying it?); decompile it separately",
                );
            }
            s
        }
        DataKind::Metadata => {
            let mut s = String::from("compiler metadata (CBOR)");
            if let Some(md) = metadata_trailer(bytes) {
                for (k, v) in md.entries() {
                    let _ = write!(s, ", {k}: {v}");
                }
            }
            s
        }
    };
    items.push(Item::Comment(note));
    items.push(Item::Raw {
        addr: r.start,
        bytes: bytes.to_vec(),
    });
}

/// Locate `CODECOPY` data spans and the metadata trailer. The result
/// is sorted and non-overlapping.
fn find_data_regions(code: &[u8], metadata: Option<&Metadata>) -> Vec<DataRegion> {
    let len = code.len() as u64;
    let code_end = metadata.map_or(len, |m| m.offset as u64);
    let insns = decode_range(&code[..code_end as usize], 0);

    let mut found: Vec<DataRegion> = Vec::new();
    let mut stack = ConstStack::default();
    for ins in &insns {
        if ins.opcode == 0x39 {
            // CODECOPY(destOffset, offset, size)
            let _dest = stack.pop();
            let off = stack.pop();
            let size = stack.pop();
            if let (Some(off), Some(size)) = (off, size)
                && size > 0
                && off >= ins.next_addr()
                && off.checked_add(size).is_some_and(|e| e <= len)
            {
                found.push(DataRegion {
                    start: off,
                    end: off + size,
                    kind: DataKind::CodeCopy { at: ins.addr.0 },
                });
            }
            continue;
        }
        stack.step(ins);
    }

    // Merge overlapping CODECOPY spans (several reads of one table).
    found.sort_by_key(|r| (r.start, std::cmp::Reverse(r.end)));
    let mut merged: Vec<DataRegion> = Vec::new();
    for r in found {
        match merged.last_mut() {
            Some(last) if r.start < last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }

    if let Some(md) = metadata {
        let start = md.offset as u64;
        let covered = merged.iter().any(|r| r.start <= start && r.end >= len);
        if !covered {
            // Trim anything that ran into the trailer, then add it.
            merged.retain_mut(|r| {
                r.end = r.end.min(start);
                r.start < r.end
            });
            merged.push(DataRegion {
                start,
                end: len,
                kind: DataKind::Metadata,
            });
        }
    }
    merged
}

/// Complement of `regions` within `[0, len)`.
fn code_segments(len: u64, regions: &[DataRegion]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut cursor = 0;
    for r in regions {
        if r.start > cursor {
            out.push((cursor, r.start));
        }
        cursor = cursor.max(r.end);
    }
    if cursor < len {
        out.push((cursor, len));
    }
    out
}

/// Straight-line constant propagation over the EVM stack. Values are
/// `None` when unknown; the model resets at every `JUMPDEST` and
/// after anything that ends a block, since the stack there depends on
/// the path taken.
#[derive(Debug, Default)]
struct ConstStack {
    items: Vec<Option<u64>>,
}

impl ConstStack {
    fn pop(&mut self) -> Option<u64> {
        self.items.pop().flatten()
    }

    fn peek(&self, depth: usize) -> Option<u64> {
        self.items
            .len()
            .checked_sub(depth + 1)
            .and_then(|i| self.items[i])
    }

    fn step(&mut self, ins: &DecodedInsn) {
        let info = ins.info();
        match ins.opcode {
            0x5f..=0x7f => self.items.push(ins.push_value()),
            0x80..=0x8f => {
                let n = usize::from(ins.opcode - 0x80);
                let v = self.peek(n);
                self.items.push(v);
            }
            0x90..=0x9f => {
                let n = usize::from(ins.opcode - 0x90) + 1;
                let len = self.items.len();
                if len > n {
                    self.items.swap(len - 1, len - 1 - n);
                } else {
                    // Swapping with a slot below what we've seen:
                    // the top becomes unknown.
                    if let Some(top) = self.items.last_mut() {
                        *top = None;
                    }
                }
            }
            0x01 | 0x03 => {
                let a = self.pop();
                let b = self.pop();
                let r = match (a, b) {
                    (Some(a), Some(b)) if ins.opcode == 0x01 => a.checked_add(b),
                    (Some(a), Some(b)) => a.checked_sub(b),
                    _ => None,
                };
                self.items.push(r);
            }
            _ => {
                match classify(ins) {
                    InsnKind::JumpDest | InsnKind::Jump | InsnKind::Halt => {
                        self.items.clear();
                        return;
                    }
                    InsnKind::JumpI | InsnKind::Other => {}
                }
                for _ in 0..info.pops {
                    self.items.pop();
                }
                for _ in 0..info.pushes {
                    self.items.push(None);
                }
            }
        }
    }
}

/// Map dispatcher jump targets to their selectors.
///
/// The compare shape alone also matches ordinary code testing a value
/// against a small constant (Uniswap v4 checks fees against
/// `0x800000` exactly this way). Compilers emit the dispatcher before
/// every function body, so a match is accepted only while its compare
/// site precedes all targets accepted so far.
fn find_dispatch_targets(insns: &[DecodedInsn], jumpdests: &BTreeSet<u64>) -> BTreeMap<u64, u32> {
    let mut out = BTreeMap::new();
    let mut first_body = u64::MAX;
    for (i, ins) in insns.iter().enumerate() {
        if ins.addr.0 >= first_body {
            break;
        }
        if !(0x60..=0x63).contains(&ins.opcode) {
            continue;
        }
        let Some(sel) = ins.push_value() else {
            continue;
        };
        let mut j = i + 1;
        if insns.get(j).is_some_and(|x| x.opcode == 0x81) {
            j += 1; // DUP2
        }
        if insns.get(j).is_none_or(|x| x.opcode != 0x14) {
            continue; // EQ
        }
        let Some(dest) = insns.get(j + 1).and_then(DecodedInsn::push_value) else {
            continue;
        };
        if insns.get(j + 2).is_none_or(|x| x.opcode != 0x57) {
            continue; // JUMPI
        }
        if jumpdests.contains(&dest) && dest > ins.addr.0 {
            out.entry(dest).or_insert(sel as u32);
            first_body = first_body.min(dest);
        }
    }
    out
}

/// Parameter types of `sig` when every one is a static ABI type (one
/// calldata word each), so parameter `k` is `calldataload(4 + 32k)`.
fn static_params(sig: &str) -> Option<Vec<&str>> {
    let inner = sig.split_once('(')?.1.strip_suffix(')')?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let types: Vec<&str> = inner.split(',').collect();
    let is_static = |t: &str| {
        let width = |rest: &str, max: u32| {
            rest.is_empty() || rest.parse::<u32>().is_ok_and(|n| n > 0 && n <= max)
        };
        t == "address"
            || t == "bool"
            || t.strip_prefix("uint").is_some_and(|r| width(r, 256))
            || t.strip_prefix("int").is_some_and(|r| width(r, 256))
            || t.strip_prefix("bytes")
                .is_some_and(|r| !r.is_empty() && width(r, 32))
    };
    types.iter().all(|t| is_static(t)).then_some(types)
}

/// Function names keyed by entry address: one per code segment start,
/// every dispatcher target, and every internal function (`sub_xxxx`).
fn name_functions(
    segments: &[(u64, u64)],
    selectors: &BTreeMap<u64, u32>,
    internal: impl Iterator<Item = u64>,
) -> BTreeMap<u64, String> {
    let mut names = BTreeMap::new();
    let mut used: HashSet<String> = HashSet::new();
    for &(start, _) in segments {
        let name = if start == 0 {
            "entry".to_string()
        } else {
            format!("code_{start:04x}")
        };
        used.insert(name.clone());
        names.insert(start, name);
    }
    for (&addr, &sel) in selectors {
        if names.contains_key(&addr) {
            continue;
        }
        let base = function_by_selector(sel)
            .and_then(|sig| sig.split('(').next())
            .filter(|n| !n.is_empty() && n.chars().all(|c| c == '_' || c.is_ascii_alphanumeric()))
            .map_or_else(|| format!("fn_{sel:08x}"), str::to_string);
        let name = if used.contains(&base) {
            format!("{base}_{sel:08x}")
        } else {
            base
        };
        used.insert(name.clone());
        names.insert(addr, name);
    }
    for addr in internal {
        names
            .entry(addr)
            .or_insert_with(|| format!("sub_{addr:04x}"));
    }
    names
}

fn build_body(
    insns: &[DecodedInsn],
    jumpdests: &BTreeSet<u64>,
    names: &BTreeMap<u64, String>,
) -> Vec<Stmt> {
    let mut out = Vec::with_capacity(insns.len());
    for (i, ins) in insns.iter().enumerate() {
        let addr = ins.addr.0;
        if i > 0 && ins.opcode == evm::JUMPDEST && !names.contains_key(&addr) {
            out.push(Stmt::Comment(format!("{}:", label(addr))));
        }
        let mut text = format_insn(ins);
        if let Some(note) = annotate(ins, insns.get(i + 1), jumpdests, names) {
            let _ = write!(text, "  ; {note}");
        }
        let bytes = match evm::assemble_one(&text) {
            Ok(b) if b == ins.original_bytes => Vec::new(),
            _ => ins.original_bytes.clone(),
        };
        out.push(Stmt::Asm { text, bytes });
    }
    out
}

fn label(addr: u64) -> String {
    format!("L_{addr:04x}")
}

fn target_name(addr: u64, names: &BTreeMap<u64, String>) -> String {
    names.get(&addr).cloned().unwrap_or_else(|| label(addr))
}

/// Reader-facing note for a push: jump target, selector, event topic
/// or well-known storage slot.
fn annotate(
    ins: &DecodedInsn,
    next: Option<&DecodedInsn>,
    jumpdests: &BTreeSet<u64>,
    names: &BTreeMap<u64, String>,
) -> Option<String> {
    if !(0x60..=0x7f).contains(&ins.opcode) || ins.is_truncated() {
        return None;
    }
    let width = ins.immediate().len();
    if let Some(v) = ins.push_value() {
        let feeds_jump = next.is_some_and(|n| matches!(n.opcode, 0x56 | 0x57));
        if feeds_jump && jumpdests.contains(&v) {
            return Some(format!("-> {}", target_name(v, names)));
        }
        // A 2-byte push of a JUMPDEST that isn't consumed by a jump
        // is almost always an internal-call return address.
        if width == 2 && jumpdests.contains(&v) {
            return Some(format!("&{}", target_name(v, names)));
        }
        if width == 4
            && let Some(sig) = function_by_selector(v as u32)
        {
            return Some(sig.to_string());
        }
    }
    if width == 32 {
        let word: [u8; 32] = ins.immediate().try_into().ok()?;
        if let Some(sig) = event_by_topic(&word) {
            return Some(format!("event {sig}"));
        }
        if let Some(name) = slot_name(&word) {
            return Some(name.to_string());
        }
        // `PUSH32 sel << 224`: a selector pre-shifted into position
        // (revert payloads, external calls).
        if word[4..].iter().all(|&b| b == 0) {
            let sel = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            if let Some(sig) = function_by_selector(sel) {
                return Some(format!("selector {sig}"));
            }
        }
    }
    None
}

fn build_module(code: &[u8], metadata: Option<&Metadata>) -> Module {
    let mut fields = vec![
        field("arch", Value::String("evm".into())),
        field("format", Value::String("evm".into())),
        field("bits", Value::Int(256)),
        field("endian", Value::String("big".into())),
    ];
    if let Some((name, version)) = metadata.and_then(Metadata::compiler) {
        fields.push(field(
            "compiler",
            Value::String(format!("{name} {version}")),
        ));
    }
    fields.push(field(
        "build",
        Value::Block(vec![field("file_size", Value::Int(code.len() as u64))]),
    ));
    Module { fields }
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Selector → entry address for the dispatcher of `code`, for
/// tooling that wants the function table without the AST.
#[must_use]
pub fn dispatch_table(code: &[u8]) -> BTreeMap<u32, u64> {
    let metadata = metadata_trailer(code);
    layout(code, metadata.as_ref())
        .selectors
        .into_iter()
        .map(|(addr, sel)| (sel, addr))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal dispatcher: `transfer` and one unknown selector.
    fn tiny_contract() -> Vec<u8> {
        let mut c = Vec::new();
        // 0x00: PUSH1 0x80 PUSH1 0x40 MSTORE
        c.extend([0x60, 0x80, 0x60, 0x40, 0x52]);
        // 0x05: PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
        c.extend([0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c]);
        // 0x0b: DUP1 PUSH4 a9059cbb EQ PUSH1 0x1f JUMPI
        c.extend([0x80, 0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x60, 0x1f, 0x57]);
        // 0x15: DUP1 PUSH4 deadbeef EQ ... (dest 0x22)
        c.extend([0x63, 0xde, 0xad, 0xbe, 0xef, 0x81, 0x14, 0x60, 0x22, 0x57]);
        assert_eq!(c.len(), 0x1f);
        // 0x1f: JUMPDEST PUSH0 STOP
        c.extend([0x5b, 0x5f, 0x00]);
        // 0x22: JUMPDEST PUSH1 0x1f JUMP
        c.extend([0x5b, 0x60, 0x1f, 0x56]);
        c
    }

    #[test]
    fn dispatcher_names_functions() {
        let code = tiny_contract();
        let table = dispatch_table(&code);
        assert_eq!(table.get(&0xa905_9cbb), Some(&0x1f));
        assert_eq!(table.get(&0xdead_beef), Some(&0x22));
        let listing = decompile_evm_listing_to_text(&code);
        assert!(listing.contains("fn transfer"), "{listing}");
        assert!(listing.contains("fn fn_deadbeef"), "{listing}");
        assert!(listing.contains("transfer(address,uint256)"), "{listing}");
        assert!(listing.contains("-> transfer"), "{listing}");
        let lifted = decompile_evm_to_text(&code);
        assert!(lifted.contains("if (msg.sig == 0xa9059cbb)"), "{lifted}");
        assert!(lifted.contains("jump(transfer)"), "{lifted}");
    }

    #[test]
    fn round_trip_tiny_contract() {
        let code = tiny_contract();
        let text = decompile_evm_to_text(&code);
        let ast = crate::translate::compile::parse(&text).expect("parse");
        let rebuilt = crate::translate::compile::lower_to_evm(&ast).expect("lower");
        assert_eq!(rebuilt, code);
    }

    #[test]
    fn initcode_runtime_becomes_data() {
        // PUSH1 size DUP1 PUSH1 off PUSH0 CODECOPY PUSH0 RETURN INVALID
        // followed by a 5-byte "runtime".
        let runtime = [0x60, 0x80, 0x60, 0x40, 0x52];
        let mut code = vec![0x60, 5, 0x80, 0x60, 0x0a, 0x5f, 0x39, 0x5f, 0xf3, 0xfe];
        code.extend(runtime);
        let ast = decompile_evm(&code);
        assert!(
            ast.items
                .iter()
                .any(|i| matches!(i, Item::Raw { addr: 0x0a, bytes } if bytes == &runtime))
        );
        let text = crate::ast::emit(&ast);
        assert!(text.contains("embedded contract code"), "{text}");
        let parsed = crate::translate::compile::parse(&text).unwrap();
        assert_eq!(
            crate::translate::compile::lower_to_evm(&parsed).unwrap(),
            code
        );
    }

    #[test]
    fn truncated_tail_keeps_pinned_bytes() {
        let code = [0x60, 0x80, 0x00, 0x7f, 0x01, 0x02];
        let text = decompile_evm_to_text(&code);
        assert!(text.contains("truncated"), "{text}");
        let parsed = crate::translate::compile::parse(&text).unwrap();
        assert_eq!(
            crate::translate::compile::lower_to_evm(&parsed).unwrap(),
            code
        );
    }

    #[test]
    fn delegation_round_trips() {
        let mut code = crate::format::evm::DELEGATION_PREFIX.to_vec();
        code.extend([0x42; 20]);
        let text = decompile_evm_to_text(&code);
        assert!(text.contains("EIP-7702"), "{text}");
        let parsed = crate::translate::compile::parse(&text).unwrap();
        assert_eq!(
            crate::translate::compile::lower_to_evm(&parsed).unwrap(),
            code
        );
    }

    #[test]
    fn edited_immediate_recompiles() {
        let code = tiny_contract();
        let text = decompile_evm_listing_to_text(&code).replace("PUSH1 0x80", "PUSH1 0xa0");
        let parsed = crate::translate::compile::parse(&text).unwrap();
        let rebuilt = crate::translate::compile::lower_to_evm(&parsed).unwrap();
        assert_eq!(rebuilt[1], 0xa0);
        assert_eq!(rebuilt[2..], code[2..]);
    }
}

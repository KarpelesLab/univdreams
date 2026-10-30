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
//!    `if`/`while`/`do … while`, `require(…)` / `revert(Err())`. Every
//!    statement pins the bytes it stands for; the lowerer re-lifts
//!    them (see `relift`) and compiles statements whose text was
//!    edited, or that were added without bytes, from their text.
//!
//!    [`decompile_evm_listing`] instead emits one `@asm` line per
//!    instruction, with `JUMPDEST` labels and jump-target / selector /
//!    event annotations. Bytes are dropped wherever the text
//!    re-assembles to them exactly (all instructions but truncated
//!    pushes), so in that form the text is the source of truth and
//!    edits to mnemonics or immediates recompile. Jump targets are
//!    absolute: an edit that changes code length must fix up the
//!    affected `PUSH` targets by hand.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;

use crate::arch::evm::{self, DecodedInsn, InsnKind, classify, decode_range, format_insn};
use crate::ast::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};
use crate::format::evm::{
    Blueprint, Metadata, MinimalProxy, blueprint, checksum_address, delegation_target,
    find_metadata, looks_like_evm, metadata_trailer, minimal_proxy,
};
use crate::signatures::evm::{event_by_topic, function_by_selector, slot_name};
use crate::translate::decompile::evm_dispatch::{self, HashDispatch};
use crate::translate::decompile::{evm_cfg, evm_lift};

/// What a non-code span holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataKind {
    /// Copied out by `CODECOPY` at this instruction offset. `returned`:
    /// the copy is followed by a `RETURN` before any jump or other
    /// copy, as when initcode deploys the runtime it carries.
    CodeCopy { at: u64, returned: bool },
    /// Constructor arguments: everything after the deployed runtime,
    /// which the constructor reads with `CODECOPY(…, codesize - n)`.
    CtorArgs { at: u64 },
    /// Compiler metadata trailer.
    Metadata,
    /// Data after the metadata trailer: Vyper's immutables, appended
    /// to the runtime code at deployment.
    Appended,
    /// Vyper ≥0.3.10's selector table (see `evm_dispatch`).
    SelectorTable { dense: bool },
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
    decompile_evm_impl(code, true, 0, None)
}

/// Build the AST as an instruction listing: one `@asm` line per
/// instruction, with bytes dropped wherever the text re-assembles to
/// them — the form to use when editing individual instructions.
#[must_use]
pub fn decompile_evm_listing(code: &[u8]) -> UdFile {
    decompile_evm_impl(code, false, 0, None)
}

/// The lifted AST of `code` together with what the lowerer needs to
/// compile edited statements against it.
pub(crate) struct Relift {
    pub file: UdFile,
    /// The decoded code segments, indexed like the trace.
    pub insns: Vec<DecodedInsn>,
    pub trace: evm_lift::LiftTrace,
    /// Compiled by Vyper (mapping slots hash `slot ‖ key`).
    pub vyper: bool,
    /// Vyper ≥0.3.10's selector table, whose words an edit that moves
    /// code rewrites.
    pub dispatch: Option<HashDispatch>,
}

impl Relift {
    /// The CFG the lifter built.
    pub fn cfg(&self) -> evm_cfg::Cfg {
        evm_cfg::build_with(&self.insns, &jump_tables(self.dispatch.as_ref()))
    }
}

/// Lift `code` as [`decompile_evm`] does, keeping the stack-name trace.
pub(crate) fn relift(code: &[u8]) -> Relift {
    let trace = RefCell::new(evm_lift::LiftTrace::default());
    let file = decompile_evm_impl(code, true, 0, Some(&trace));
    let (insns, vyper, dispatch) = if is_wrapper(code) {
        (Vec::new(), false, None)
    } else {
        let l = layout(code, find_metadata(code).as_ref());
        (l.insns, l.vyper, l.dispatch)
    };
    Relift {
        file,
        insns,
        trace: trace.into_inner(),
        vyper,
        dispatch,
    }
}

/// Code that isn't decompiled as a contract of its own: a delegation
/// designator, a minimal proxy, or a blueprint holding initcode.
fn is_wrapper(code: &[u8]) -> bool {
    delegation_target(code).is_some()
        || minimal_proxy(code).is_some()
        || code_blueprint(code).is_some()
}

/// An ERC-5202 blueprint whose initcode looks like EVM code.
fn code_blueprint(code: &[u8]) -> Option<Blueprint> {
    blueprint(code).filter(|b| looks_like_evm(&code[b.initcode..]))
}

fn jump_tables(dispatch: Option<&HashDispatch>) -> evm_cfg::JumpTables {
    dispatch
        .map(|d| (d.jump, d.targets.clone()))
        .into_iter()
        .collect()
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
fn decompile_evm_impl(
    code: &[u8],
    lift: bool,
    depth: u32,
    trace: Option<&RefCell<evm_lift::LiftTrace>>,
) -> UdFile {
    let metadata = find_metadata(code);
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
    if let Some(proxy) = minimal_proxy(code) {
        return minimal_proxy_file(code, &proxy, module, lift);
    }
    if let Some(bp) = code_blueprint(code)
        && depth < MAX_NESTING
    {
        return blueprint_file(code, &bp, module, lift, depth);
    }

    let Layout {
        regions,
        segments,
        insns,
        jumpdests,
        selectors,
        vyper,
        dispatch,
    } = layout(code, metadata.as_ref());
    let cfg = evm_cfg::build_with(&insns, &jump_tables(dispatch.as_ref()));
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
                .map(|(&addr, &sel)| {
                    let words = match function_by_selector(sel).and_then(abi_head) {
                        Some(head) => head.words,
                        None => (0..UNKNOWN_SIG_PARAMS)
                            .map(|k| format!("param{k}"))
                            .collect(),
                    };
                    (addr, words)
                })
                .collect(),
            dynamic: selectors
                .iter()
                .filter_map(|(&addr, &sel)| {
                    let head = abi_head(function_by_selector(sel)?)?;
                    let names = head
                        .types
                        .iter()
                        .enumerate()
                        .filter(|(_, t)| head_words(t) == Some(HeadWords::Dynamic))
                        .map(|(k, _)| format!("param{k}"))
                        .collect();
                    Some((addr, names))
                })
                .collect(),
            getters: selectors
                .iter()
                .filter_map(|(&addr, &sel)| {
                    let sig = function_by_selector(sel)?;
                    let head = abi_head(sig)?;
                    // Mapping keys are one word each.
                    let n = head.types.len();
                    (head.words.len() == n).then_some(())?;
                    Some((addr, (sig.split('(').next()?.to_string(), n)))
                })
                .collect(),
            vyper,
            trace,
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
    let mut sites: Vec<_> = cfg.calls.iter().collect();
    sites.sort_by_key(|&(&site, _)| cfg.blocks[site].start);
    for (&site, call) in sites {
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
            push_region(&mut items, code, r, lift, depth);
        }
        if let Some(sel) = selectors.get(&entry) {
            let what = match function_by_selector(*sel) {
                // Name the parameters the body refers to.
                Some(sig) if lift && abi_head(sig).is_some_and(|h| !h.types.is_empty()) => {
                    let types = abi_head(sig).map(|h| h.types).unwrap_or_default();
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
            let rets = if info.noreturn {
                "never returns".to_string()
            } else {
                let n = info
                    .nrets
                    .map_or_else(|| "unknown".to_string(), |n| n.to_string());
                format!("{n} return value(s)")
            };
            let from = callers
                .get(&entry)
                .map_or_else(String::new, |c| format!("; called from {}", c.join(", ")));
            items.push(Item::Comment(format!(
                "internal function: {} argument(s), {rets}{from}",
                info.total_args()
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
        push_region(&mut items, code, r, lift, depth);
    }

    UdFile { module, items }
}

/// An EIP-1167 clone: one function forwarding every call to the
/// implementation. Lifted, its whole body is a single statement; the
/// listing keeps the instructions. Appended immutable arguments stay
/// as data.
fn minimal_proxy_file(code: &[u8], proxy: &MinimalProxy, module: Module, lift: bool) -> UdFile {
    let target = checksum_address(&proxy.target);
    let body_code = &code[..proxy.code_len];
    let body = if lift {
        vec![Stmt::ReturnExpr {
            text: format!("delegatecall({target}, msg.data)"),
            bytes: body_code.to_vec(),
        }]
    } else {
        build_body(
            &decode_range(body_code, 0),
            &BTreeSet::from([proxy.code_len as u64 - 2]),
            &BTreeMap::new(),
        )
    };
    let mut items = vec![
        Item::Comment(format!(
            "EIP-1167 minimal proxy: every call runs the code of {target} (DELEGATECALL; return data and reverts are passed through)"
        )),
        Item::Function(FnDecl {
            addr: Some(0),
            name: "proxy".into(),
            attrs: Vec::new(),
            signature: None,
            locals: Vec::new(),
            body,
        }),
    ];
    if proxy.code_len < code.len() {
        items.push(Item::Comment(format!(
            "data 0x{:04x}..0x{:04x}: appended to the clone (immutable arguments); never executed",
            proxy.code_len,
            code.len()
        )));
        items.push(Item::Raw {
            addr: proxy.code_len as u64,
            bytes: code[proxy.code_len..].to_vec(),
        });
    }
    UdFile { module, items }
}

/// An ERC-5202 blueprint: the preamble (and any data section) as
/// data, then the initcode as a nested `@section("initcode", …)`,
/// decompiled from its own offset 0 as `create_from_blueprint` runs it.
fn blueprint_file(code: &[u8], bp: &Blueprint, module: Module, lift: bool, depth: u32) -> UdFile {
    let initcode = &code[bp.initcode..];
    let nested = decompile_evm_impl(initcode, lift, depth + 1, None);
    let mut items = vec![
        Item::Comment(format!(
            "ERC-5202 blueprint (version {}): not meant to run; factories deploy copies of the initcode after the preamble with `create_from_blueprint`",
            bp.version
        )),
        Item::Raw {
            addr: 0,
            bytes: code[..bp.preamble_len].to_vec(),
        },
    ];
    let (data_at, data_len) = bp.data;
    if data_len > 0 {
        items.push(Item::Comment(format!(
            "data 0x{data_at:04x}..0x{:04x}: blueprint data section",
            data_at + data_len
        )));
        items.push(Item::Raw {
            addr: data_at as u64,
            bytes: code[data_at..data_at + data_len].to_vec(),
        });
    }
    items.push(Item::Comment(format!(
        "0x{:04x}..0x{:04x}: initcode ({} bytes); offsets inside are its own, from 0",
        bp.initcode,
        code.len(),
        initcode.len()
    )));
    items.push(Item::Section {
        name: "initcode".into(),
        addr: bp.initcode as u64,
        items: nested.items,
    });
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
    /// Compiled by Vyper (per the metadata, or Vyper's dispatcher).
    vyper: bool,
    /// Vyper ≥0.3.10's selector table.
    dispatch: Option<HashDispatch>,
}

fn layout(code: &[u8], metadata: Option<&Metadata>) -> Layout {
    let dispatch = evm_dispatch::find(code);
    let regions = find_data_regions(code, metadata, dispatch.as_ref());
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
    let mut selectors = find_dispatch_targets(&insns, &jumpdests);
    let mut vyper = metadata
        .and_then(Metadata::compiler)
        .is_some_and(|(name, _)| name == "vyper");
    if let Some(d) = &dispatch {
        selectors.clone_from(&d.selectors);
        vyper = true;
    } else if selectors.is_empty() {
        selectors = find_vyper_dispatch(&insns, &jumpdests);
        vyper |= !selectors.is_empty();
    }
    Layout {
        regions,
        segments,
        insns,
        jumpdests,
        selectors,
        vyper,
        dispatch,
    }
}

/// Embedded contracts decompiled inside one another, at most.
const MAX_NESTING: u32 = 4;

fn push_region(items: &mut Vec<Item>, code: &[u8], r: &DataRegion, lift: bool, depth: u32) {
    let bytes = &code[r.start as usize..r.end as usize];
    let note = match r.kind {
        DataKind::CodeCopy { at, returned } => {
            let what = if returned {
                "runtime code the constructor deploys"
            } else {
                "embedded contract code"
            };
            if depth < MAX_NESTING && crate::format::evm::looks_like_evm(bytes) {
                push_embedded(items, bytes, r, at, what, lift, depth);
                return;
            }
            format!(
                "data 0x{:04x}..0x{:04x}: CODECOPY source at 0x{at:04x}",
                r.start, r.end
            )
        }
        DataKind::CtorArgs { at } => format!(
            "data 0x{:04x}..0x{:04x}: constructor arguments (ABI-encoded), read by the CODECOPY at 0x{at:04x}",
            r.start, r.end
        ),
        DataKind::Appended => format!(
            "data 0x{:04x}..0x{:04x}: appended after the metadata (immutables, read with CODECOPY)",
            r.start, r.end
        ),
        DataKind::SelectorTable { dense } => format!(
            "data 0x{:04x}..0x{:04x}: selector table ({}), read by the dispatcher in `entry`",
            r.start,
            r.end,
            if dense {
                "dense: bucket headers and entries"
            } else {
                "sparse: one bucket head per entry"
            }
        ),
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

/// An embedded contract as a `@section`, decompiled on its own: its
/// items are addressed from 0, as it runs once deployed.
fn push_embedded(
    items: &mut Vec<Item>,
    bytes: &[u8],
    r: &DataRegion,
    at: u64,
    what: &str,
    lift: bool,
    depth: u32,
) {
    let nested = decompile_evm_impl(bytes, lift, depth + 1, None);
    let compiler = nested.module.fields.iter().find_map(|f| match &f.value {
        Value::String(s) if f.name == "compiler" => Some(format!(", {s}")),
        _ => None,
    });
    items.push(Item::Comment(format!(
        "0x{:04x}..0x{:04x}: {what} ({} bytes{}), copied out by the CODECOPY at 0x{at:04x}; offsets inside are its own, from 0",
        r.start,
        r.end,
        bytes.len(),
        compiler.unwrap_or_default()
    )));
    let name = if what.starts_with("runtime") {
        "runtime"
    } else {
        "contract"
    };
    items.push(Item::Section {
        name: name.into(),
        addr: r.start,
        items: nested.items,
    });
}

/// Locate `CODECOPY` data spans and the metadata trailer. The result
/// is sorted and non-overlapping.
fn find_data_regions(
    code: &[u8],
    metadata: Option<&Metadata>,
    dispatch: Option<&HashDispatch>,
) -> Vec<DataRegion> {
    let len = code.len() as u64;
    let code_end = metadata.map_or(len, |m| m.offset as u64);
    let insns = decode_range(&code[..code_end as usize], 0);

    let mut found: Vec<DataRegion> = Vec::new();
    let mut stack = ConstStack {
        items: Vec::new(),
        codesize: len,
    };
    for (k, ins) in insns.iter().enumerate() {
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
                let returned = insns[k + 1..]
                    .iter()
                    .find(|x| classify(x) != InsnKind::Other || x.opcode == 0x39)
                    .is_some_and(|x| x.opcode == 0xf3);
                found.push(DataRegion {
                    start: off,
                    end: off + size,
                    kind: DataKind::CodeCopy {
                        at: ins.addr.0,
                        returned,
                    },
                });
            }
            continue;
        }
        stack.step(ins);
    }

    if let Some(d) = dispatch {
        found.extend(d.spans.iter().map(|&(start, end)| DataRegion {
            start,
            end,
            kind: DataKind::SelectorTable { dense: d.dense },
        }));
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
    // What follows the deployed runtime, up to the end, is the
    // constructor's arguments.
    let deployed_end = merged.iter().find_map(|r| match r.kind {
        DataKind::CodeCopy { returned: true, .. } => Some(r.end),
        _ => None,
    });
    for r in &mut merged {
        if let DataKind::CodeCopy {
            at,
            returned: false,
        } = r.kind
            && Some(r.start) == deployed_end
            && r.end == len
        {
            r.kind = DataKind::CtorArgs { at };
        }
    }

    if let Some(md) = metadata {
        let start = md.offset as u64;
        let end = md.end as u64;
        let covered = merged.iter().any(|r| r.start <= start && r.end >= len);
        if !covered {
            // Trim anything that ran into the trailer, then add it.
            merged.retain_mut(|r| {
                r.end = r.end.min(start);
                r.start < r.end
            });
            merged.push(DataRegion {
                start,
                end,
                kind: DataKind::Metadata,
            });
            if end < len {
                merged.push(DataRegion {
                    start: end,
                    end: len,
                    kind: DataKind::Appended,
                });
            }
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
#[derive(Debug)]
struct ConstStack {
    items: Vec<Option<u64>>,
    /// `CODESIZE`: constructors locate their arguments as
    /// `codesize - n`.
    codesize: u64,
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
            0x38 => self.items.push(Some(self.codesize)),
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

/// Vyper (before 0.3.10's hash-bucket tables) dispatches with a chain
/// of "not this selector? try the next one" tests, each followed
/// inline by the function's body:
///
/// ```text
/// [JUMPDEST] PUSH4 sel PUSH1 0 MLOAD EQ ISZERO PUSH2 next JUMPI   ; 0.1 / 0.2
/// [JUMPDEST] PUSH4 sel DUPn XOR PUSH2 next JUMPI                  ; 0.3
/// ```
///
/// (0.2 keeps the selector at memory 0 after `mstore(0x1c,
/// calldataload(0))`; 0.3 keeps it on the stack.) A function is named
/// from its test, so it starts with its own selector check. Tests are
/// accepted along the chain only — the first one, then each at the
/// previous one's `next` — so a body comparing against a 4-byte
/// constant isn't mistaken for a case.
fn find_vyper_dispatch(insns: &[DecodedInsn], jumpdests: &BTreeSet<u64>) -> BTreeMap<u64, u32> {
    let op = |k: usize| insns.get(k).map(|x| x.opcode);
    let mut cases: Vec<(u64, u32, u64)> = Vec::new();
    for (i, ins) in insns.iter().enumerate() {
        if !(0x60..=0x63).contains(&ins.opcode) {
            continue;
        }
        let Some(sel) = ins.push_value() else {
            continue;
        };
        let next_at = if op(i + 1) == Some(0x60)
            && insns[i + 1].push_value() == Some(0)
            && op(i + 2) == Some(0x51)
            && op(i + 3) == Some(0x14)
            && op(i + 4) == Some(0x15)
        {
            i + 5
        } else if op(i + 1).is_some_and(|o| (0x80..=0x8f).contains(&o)) && op(i + 2) == Some(0x18) {
            i + 3
        } else {
            continue;
        };
        let Some(next) = insns.get(next_at).and_then(DecodedInsn::push_value) else {
            continue;
        };
        if op(next_at + 1) != Some(0x57) || !jumpdests.contains(&next) || next <= ins.addr.0 {
            continue;
        }
        let entry = match i.checked_sub(1).map(|k| &insns[k]) {
            Some(prev) if prev.opcode == evm::JUMPDEST => prev.addr.0,
            _ => ins.addr.0,
        };
        cases.push((entry, sel as u32, next));
    }
    // Vyper 0.2 places private functions between cases and steps over
    // them with an always-taken `PUSH1 0 ISZERO PUSH2 skip JUMPI`.
    let skip = |addr: u64| -> Option<u64> {
        let k = insns.partition_point(|x| x.addr.0 < addr);
        let at = |n: usize| insns.get(k + n);
        (at(0)?.opcode == evm::JUMPDEST
            && at(1)?.opcode == 0x60
            && at(1)?.push_value() == Some(0)
            && at(2)?.opcode == 0x15
            && at(4)?.opcode == 0x57)
            .then(|| at(3)?.push_value())
            .flatten()
            .filter(|&t| t > addr)
    };
    let mut out = BTreeMap::new();
    let mut expect: Option<u64> = None;
    for (entry, sel, next) in cases {
        let mut want = expect;
        while let Some(w) = want
            && w < entry
        {
            want = skip(w);
        }
        if expect.is_none() || want == Some(entry) {
            out.insert(entry, sel);
            expect = Some(next);
        }
    }
    out
}

/// Head words named for an external function with no known
/// signature: `param0…`, whatever it really takes.
const UNKNOWN_SIG_PARAMS: usize = 16;

/// Layout of the ABI-encoded parameters of a signature.
#[derive(Debug, PartialEq, Eq)]
struct AbiHead<'s> {
    /// Top-level parameter types.
    types: Vec<&'s str>,
    /// Name of each 32-byte head word: `paramK` for a one-word
    /// parameter or the offset of a dynamic one, `paramK.fJ` for the
    /// `J`th word of a static tuple or fixed-size array.
    words: Vec<String>,
}

fn abi_head(sig: &str) -> Option<AbiHead<'_>> {
    let inner = sig.split_once('(')?.1.strip_suffix(')')?;
    let types = split_types(inner)?;
    let mut words = Vec::new();
    for (k, t) in types.iter().enumerate() {
        match head_words(t)? {
            // A well-known struct names its members (`param0.hooks`).
            HeadWords::Static(n)
                if let Some((_, fields)) = crate::signatures::evm::struct_fields(t)
                    && fields.len() == n =>
            {
                words.extend(fields.iter().map(|f| format!("param{k}.{f}")));
            }
            HeadWords::Static(n) if n > 1 => {
                words.extend((0..n).map(|j| format!("param{k}.f{j}")));
            }
            _ => words.push(format!("param{k}")),
        }
    }
    Some(AbiHead { types, words })
}

/// How many head words a call to `sig` encodes when all its
/// parameters are static (so the head is the whole encoding).
pub(crate) fn static_head_words(sig: &str) -> Option<usize> {
    let head = abi_head(sig)?;
    head.types.iter().try_fold(0, |n, t| match head_words(t)? {
        HeadWords::Static(w) => Some(n + w),
        HeadWords::Dynamic => None,
    })
}

/// Split a comma-separated type list at its top level.
fn split_types(list: &str) -> Option<Vec<&str>> {
    if list.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;
    for (i, c) in list.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                out.push(&list[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&list[start..]);
    (depth == 0 && out.iter().all(|t| !t.is_empty())).then_some(out)
}

/// How a parameter type sits in the ABI head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadWords {
    /// Encoded in place, in this many words.
    Static(usize),
    /// One word: the offset of its tail.
    Dynamic,
}

/// Head layout of type `t`, or `None` when the text doesn't parse.
fn head_words(t: &str) -> Option<HeadWords> {
    if let Some(elem) = t.strip_suffix(']') {
        let (elem, dim) = elem.rsplit_once('[')?;
        if dim.is_empty() {
            return Some(HeadWords::Dynamic);
        }
        let n: usize = dim.parse().ok()?;
        return Some(match head_words(elem)? {
            HeadWords::Static(w) => HeadWords::Static(w * n),
            HeadWords::Dynamic => HeadWords::Dynamic,
        });
    }
    if let Some(inner) = t.strip_prefix('(') {
        let mut total = 0;
        for member in split_types(inner.strip_suffix(')')?)? {
            match head_words(member)? {
                HeadWords::Static(n) => total += n,
                HeadWords::Dynamic => return Some(HeadWords::Dynamic),
            }
        }
        return Some(HeadWords::Static(total));
    }
    Some(if t == "bytes" || t == "string" {
        HeadWords::Dynamic
    } else {
        HeadWords::Static(1)
    })
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
    let metadata = find_metadata(code);
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
    fn abi_head_words() {
        let head = abi_head("transfer(address,uint256)").unwrap();
        assert_eq!(head.types, ["address", "uint256"]);
        assert_eq!(head.words, ["param0", "param1"]);
        // Dynamic parameters are an offset word; static tuples and
        // fixed arrays one word per member.
        let head = abi_head("f((address,uint24),bytes,uint8[2][3],(uint256,string))").unwrap();
        assert_eq!(head.types.len(), 4);
        let mut want = vec!["param0.f0".to_string(), "param0.f1".into(), "param1".into()];
        want.extend((0..6).map(|j| format!("param2.f{j}")));
        want.push("param3".into());
        assert_eq!(head.words, want);
        assert_eq!(abi_head("name()").unwrap().words, Vec::<String>::new());
        // Uniswap v4's `PoolKey` by its member names.
        let head = abi_head("initialize((address,address,uint24,int24,address),uint160)").unwrap();
        assert_eq!(head.words[0], "param0.currency0");
        assert_eq!(head.words[4], "param0.hooks");
        assert_eq!(head.words[5], "param1");
        assert_eq!(abi_head("bad((uint256)"), None);
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
    fn initcode_runtime_becomes_a_nested_section() {
        // PUSH1 size DUP1 PUSH1 off PUSH0 CODECOPY PUSH0 RETURN INVALID
        // followed by a 5-byte "runtime".
        let runtime = [0x60, 0x80, 0x60, 0x40, 0x52];
        let mut code = vec![0x60, 5, 0x80, 0x60, 0x0a, 0x5f, 0x39, 0x5f, 0xf3, 0xfe];
        code.extend(runtime);
        for ast in [decompile_evm(&code), decompile_evm_listing(&code)] {
            let Some(Item::Section { name, addr, items }) =
                ast.items.iter().find(|i| matches!(i, Item::Section { .. }))
            else {
                panic!("no section: {ast:?}");
            };
            assert_eq!((name.as_str(), *addr), ("runtime", 0x0a));
            // The runtime is decompiled from its own offset 0.
            assert!(
                items
                    .iter()
                    .any(|i| matches!(i, Item::Function(f) if f.addr == Some(0)))
            );
            let text = crate::ast::emit(&ast);
            assert!(
                text.contains("runtime code the constructor deploys"),
                "{text}"
            );
            let parsed = crate::translate::compile::parse(&text).unwrap();
            assert_eq!(
                crate::translate::compile::lower_to_evm(&parsed).unwrap(),
                code
            );
        }
    }

    #[test]
    fn constructor_arguments_after_the_runtime() {
        // CODECOPY(0, 0x15, 5) RETURN(0, 5), then the constructor's own
        // read of its arguments: CODECOPY(0, 0x1a, codesize - 0x1a).
        let mut code = vec![
            0x60, 0x1a, 0x38, 0x03, 0x80, 0x60, 0x1a, 0x5f, 0x39, // args copy
            0x60, 0x05, 0x80, 0x60, 0x15, 0x5f, 0x39, 0x5f, 0xf3, // runtime
            0xfe, 0xfe, 0xfe,
        ];
        assert_eq!(code.len(), 0x15);
        code.extend([0x60, 0x80, 0x60, 0x40, 0x52]);
        code.extend([0x11; 64]);
        let text = decompile_evm_to_text(&code);
        assert!(text.contains("constructor arguments"), "{text}");
        assert!(text.contains("@section(\"runtime\", 0x15)"), "{text}");
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

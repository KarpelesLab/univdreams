//! Decompile a 6502 raw image into a `.ud` AST.
//!
//! v0 scope: byte-identical round-trip with multi-entry function
//! discovery.
//!
//! The 6502 has no executable file format — code is just a flat
//! image mapped at a fixed virtual address (e.g. WozMon at $FF00).
//! The reset / NMI / IRQ vectors sit at $FFFA-$FFFF for any program
//! that wants to be entered by a power-on or interrupt.
//!
//! Function discovery: the reset address (from $FFFC) and every
//! direct `JSR $nnnn` target that lives inside the image are taken
//! as function entries. Entries are sorted by address; each
//! function's byte range runs from its entry up to (but not
//! including) the next entry, with the last one extending to the
//! start of the vector region at $FFFA. This produces a contiguous
//! cover of all code bytes — necessary for byte-identical
//! round-trip — while still surfacing the call structure.
//!
//! Branch / fall-through targets that aren't JSR-called become
//! `// LABEL:` comments inside the owning function body.

use std::collections::{BTreeSet, HashMap, HashSet};

use ud_arch_6502::{
    classify, decode_range, format_insn_with, AddressingMode, DecodedInsn, InsnKind,
};
use ud_ast::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};
use ud_format_raw::RawImage;

/// 6502 reset / NMI / IRQ vectors live at $FFFA-$FFFF. Six bytes.
const VECTORS_BASE: u64 = 0xFFFA;
const VECTORS_LEN: u64 = 6;

/// Errors specific to the 6502 raw path.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("image is too small to contain reset vectors at $FFFA-$FFFF (got {got} bytes)")]
    TooSmall { got: usize },
    #[error("decode failed at offset {offset}: {source}")]
    Decode {
        offset: usize,
        #[source]
        source: ud_arch_6502::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Build the AST for a 6502 raw image.
pub fn decompile_raw_6502(image: &RawImage) -> Result<UdFile> {
    if image.bytes.len() < (VECTORS_LEN as usize) {
        return Err(Error::TooSmall {
            got: image.bytes.len(),
        });
    }
    let module = build_module(image)?;

    let code_end = image.end().saturating_sub(VECTORS_LEN);
    let code_len = (code_end - image.start()) as usize;
    let code_bytes = &image.bytes[..code_len];
    let insns = decode_range(code_bytes, image.start()).map_err(|e| Error::Decode {
        offset: 0,
        source: e,
    })?;

    let reset_addr = u64::from(image.read_u16_le(0xFFFC).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?);

    let entries = discover_entries(&insns, reset_addr, image.start(), code_end);
    let labels = discover_labels(&insns, &entries);

    let mut items: Vec<Item> = Vec::new();
    for (idx, &entry) in entries.iter().enumerate() {
        let end = entries.get(idx + 1).copied().unwrap_or(code_end);
        let body = build_body_range(&insns, entry, end, &labels, &entries);
        let name = function_name(entry, reset_addr);
        items.push(Item::Function(FnDecl {
            addr: Some(entry),
            name,
            signature: None,
            body,
        }));
    }

    let vectors_bytes = image.bytes[code_len..].to_vec();
    items.push(Item::Raw {
        addr: VECTORS_BASE,
        bytes: vectors_bytes,
    });

    Ok(UdFile { module, items })
}

/// Convenience: AST + canonical pretty-print.
pub fn decompile_raw_6502_to_text(image: &RawImage) -> Result<String> {
    Ok(ud_ast::emit(&decompile_raw_6502(image)?))
}

/// Collect the addresses to treat as function entries: the reset
/// vector plus every direct `JSR $nnnn` whose target lives inside
/// the code region. Returns them sorted ascending.
fn discover_entries(
    insns: &[DecodedInsn],
    reset_addr: u64,
    code_start: u64,
    code_end: u64,
) -> Vec<u64> {
    let mut set: BTreeSet<u64> = BTreeSet::new();
    set.insert(reset_addr);
    for ins in insns {
        if let InsnKind::Call { target, .. } = classify(ins) {
            if target >= code_start && target < code_end {
                set.insert(target);
            }
        }
    }
    // Only retain entries that actually align with a decoded
    // instruction boundary — a target that lands in the middle of
    // an instruction is either self-modifying code or a bug, and
    // either way isn't a function we can carve out cleanly.
    let insn_addrs: HashSet<u64> = insns.iter().map(|i| i.addr.0).collect();
    set.into_iter().filter(|a| insn_addrs.contains(a)).collect()
}

/// Collect addresses that are branch / `JMP` / fall-through targets
/// other than function entries. These become `// LABEL_xxxx:`
/// comments inside the owning function body.
fn discover_labels(insns: &[DecodedInsn], entries: &[u64]) -> HashMap<u64, String> {
    let entry_set: HashSet<u64> = entries.iter().copied().collect();
    let mut labels: BTreeSet<u64> = BTreeSet::new();
    for ins in insns {
        match classify(ins) {
            InsnKind::Branch { taken, .. } => {
                labels.insert(taken);
            }
            InsnKind::JumpDirect { target } => {
                labels.insert(target);
            }
            _ => {}
        }
    }
    let insn_addrs: HashSet<u64> = insns.iter().map(|i| i.addr.0).collect();
    labels
        .into_iter()
        .filter(|a| insn_addrs.contains(a) && !entry_set.contains(a))
        .map(|a| (a, format!("L_{a:04X}")))
        .collect()
}

/// Build the body for one function: every instruction with address
/// in `[start, end)`, plus comment statements at branch-target
/// labels, plus structured `@loop` blocks for tight do-while patterns.
fn build_body_range(
    insns: &[DecodedInsn],
    start: u64,
    end: u64,
    labels: &HashMap<u64, String>,
    entries: &[u64],
) -> Vec<Stmt> {
    let entry_set: HashSet<u64> = entries.iter().copied().collect();
    let local: Vec<&DecodedInsn> = insns
        .iter()
        .filter(|i| i.addr.0 >= start && i.addr.0 < end)
        .collect();
    build_stmt_slice(&local, &entry_set, labels)
}

/// Recursive body builder: detect tight do-while loops (back-branch
/// to an earlier address in the slice) and recurse into their body
/// so nested loops are also lifted.
fn build_stmt_slice(
    local: &[&DecodedInsn],
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < local.len() {
        if let Some((j, tail)) = find_back_branch_target(local, i) {
            let body = build_stmt_slice(&local[i..j], entries, labels);
            let tail_bytes = tail.original_bytes.clone();
            let cond_text = format_branch_cond(tail, entries, labels);
            out.push(Stmt::Loop {
                entry_jmp_bytes: None,
                tail_bytes,
                cond_text,
                body,
            });
            i = j + 1;
            continue;
        }
        let ins = local[i];
        if let Some(lbl) = labels.get(&ins.addr.0) {
            out.push(Stmt::Comment(format!("{lbl}:")));
        }
        out.push(asm_stmt(ins, entries, labels));
        i += 1;
    }
    out
}

/// If a back-branch loop opens at `local[start_idx]`, return
/// `(branch_idx, branch_insn)`. The branch must be a
/// conditional Bcc whose taken target equals `local[start_idx].addr`,
/// and must appear *after* `start_idx` in the function body.
fn find_back_branch_target<'a>(
    local: &[&'a DecodedInsn],
    start_idx: usize,
) -> Option<(usize, &'a DecodedInsn)> {
    let head_addr = local[start_idx].addr.0;
    for (j, ins) in local.iter().enumerate().skip(start_idx + 1) {
        if let InsnKind::Branch { taken, .. } = classify(ins) {
            if taken == head_addr {
                return Some((j, ins));
            }
        }
    }
    None
}

fn asm_stmt(ins: &DecodedInsn, entries: &HashSet<u64>, labels: &HashMap<u64, String>) -> Stmt {
    let mut text = format_insn_with(ins, apple1_symbol);
    if let Some(annot) = call_annotation(ins, entries, labels) {
        text = format!("{text}  ; {annot}");
    }
    Stmt::asm(text, ins.original_bytes.clone())
}

fn format_branch_cond(
    ins: &DecodedInsn,
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
) -> String {
    let base = format_insn_with(ins, apple1_symbol);
    if let Some(annot) = call_annotation(ins, entries, labels) {
        format!("{base}  ; {annot}")
    } else {
        base
    }
}

/// If `ins` targets a known entry or label, return its symbolic
/// name for an inline `// → name` annotation. Returns `None` for
/// non-flow-control insns or unresolved targets.
fn call_annotation(
    ins: &DecodedInsn,
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
) -> Option<String> {
    match classify(ins) {
        InsnKind::Call { target, .. } => {
            if entries.contains(&target) {
                Some(format!("call {}", function_name(target, u64::MAX)))
            } else {
                None
            }
        }
        InsnKind::JumpDirect { target } => {
            labels.get(&target).map(|n| format!("-> {n}")).or_else(|| {
                if entries.contains(&target) {
                    Some(format!("-> {}", function_name(target, u64::MAX)))
                } else {
                    None
                }
            })
        }
        InsnKind::Branch { taken, .. } if ins.mode == AddressingMode::Relative => {
            labels.get(&taken).map(|n| format!("-> {n}")).or_else(|| {
                if entries.contains(&taken) {
                    Some(format!("-> {}", function_name(taken, u64::MAX)))
                } else {
                    None
                }
            })
        }
        _ => None,
    }
}

/// Apple I symbol resolver for the PIA-mapped keyboard / display
/// registers. Returns `None` for any address outside this region —
/// callers display those as `$XXXX` raw addresses.
///
/// References: Apple I Operation Manual, p. 4-5.
fn apple1_symbol(addr: u16) -> Option<&'static str> {
    match addr {
        0xD010 => Some("KBD"),
        0xD011 => Some("KBDCR"),
        0xD012 => Some("DSP"),
        0xD013 => Some("DSPCR"),
        _ => None,
    }
}

/// Name to use for a function at `addr`. `reset_addr` gets `"reset"`;
/// everything else becomes `"sub_XXXX"` (uppercase hex address).
fn function_name(addr: u64, reset_addr: u64) -> String {
    if addr == reset_addr {
        "reset".into()
    } else {
        format!("sub_{addr:04X}")
    }
}

fn build_module(image: &RawImage) -> Result<Module> {
    let nmi = image.read_u16_le(0xFFFA).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?;
    let reset = image.read_u16_le(0xFFFC).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?;
    let irq = image.read_u16_le(0xFFFE).map_err(|_| Error::TooSmall {
        got: image.bytes.len(),
    })?;

    let vectors = Value::Block(vec![
        field("nmi", Value::Int(u64::from(nmi))),
        field("reset", Value::Int(u64::from(reset))),
        field("irq", Value::Int(u64::from(irq))),
    ]);

    let build = Value::Block(vec![field(
        "file_size",
        Value::Int(image.bytes.len() as u64),
    )]);

    Ok(Module {
        fields: vec![
            field("arch", Value::String("6502".into())),
            field("format", Value::String("raw".into())),
            field("bits", Value::Int(8)),
            field("endian", Value::String("little".into())),
            field("load_addr", Value::Int(image.load_addr)),
            field("vectors", vectors),
            field("build", build),
        ],
    })
}

fn field(name: &str, value: Value) -> Field {
    Field {
        name: name.into(),
        value,
    }
}

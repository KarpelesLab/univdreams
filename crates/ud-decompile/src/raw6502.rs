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
    classify, decode_range, format_insn_with, AddressingMode, DecodedInsn, InsnKind, Mnemonic,
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
    let resolver = pick_resolver(image);

    let mut items: Vec<Item> = Vec::new();
    for (idx, &entry) in entries.iter().enumerate() {
        let end = entries.get(idx + 1).copied().unwrap_or(code_end);
        let body = build_body_range(&insns, entry, end, &labels, &entries, resolver);
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
    resolver: SymbolResolver,
) -> Vec<Stmt> {
    let entry_set: HashSet<u64> = entries.iter().copied().collect();
    let local: Vec<&DecodedInsn> = insns
        .iter()
        .filter(|i| i.addr.0 >= start && i.addr.0 < end)
        .collect();
    build_stmt_slice(&local, &entry_set, labels, resolver)
}

/// Recursive body builder. In priority order:
///
/// 1. Tight do-while loop — Bcc back-branch to an earlier insn in
///    the slice.
/// 2. Forward conditional `@if_branch` — Bcc whose taken target is
///    a later insn in the slice. The skipped instructions become
///    `then_body`.
/// 3. `LDA #imm; JSR known` — lift to a single `@call`.
/// 4. Fall back to a label comment + `@asm` line.
fn build_stmt_slice(
    local: &[&DecodedInsn],
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
    resolver: SymbolResolver,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < local.len() {
        // 1. Back-branch do-while.
        if let Some((j, tail)) = find_back_branch_target(local, i) {
            let body = build_stmt_slice(&local[i..j], entries, labels, resolver);
            let tail_bytes = tail.original_bytes.clone();
            let cond_text = format_branch_cond(tail, entries, labels, resolver);
            out.push(Stmt::Loop {
                entry_jmp_bytes: None,
                tail_bytes,
                cond_text,
                body,
            });
            i = j + 1;
            continue;
        }
        // 2. Forward conditional branch — try if/else first.
        if let Some((target_idx, branch)) = find_forward_branch_target(local, i) {
            let cond_text = format_branch_cond(branch, entries, labels, resolver);
            let cond_bytes = branch.original_bytes.clone();
            if let Some(x_idx) = find_jmp_over_else(local, target_idx) {
                let then_body =
                    build_stmt_slice(&local[i + 1..target_idx], entries, labels, resolver);
                let else_stmts =
                    build_stmt_slice(&local[target_idx..x_idx], entries, labels, resolver);
                out.push(Stmt::IfBranch {
                    cond_text,
                    cond_bytes,
                    then_body,
                    else_body: Some(else_stmts),
                });
                i = x_idx;
                continue;
            }
            let then_body = build_stmt_slice(&local[i + 1..target_idx], entries, labels, resolver);
            out.push(Stmt::IfBranch {
                cond_text,
                cond_bytes,
                then_body,
                else_body: None,
            });
            i = target_idx;
            continue;
        }
        // 3. LDA #imm; JSR known_target → @call with A=#$imm.
        if let Some(call_stmt) = try_lift_imm_call(local, i, entries) {
            out.push(call_stmt);
            i += 2;
            continue;
        }
        // 4. Bare JSR known_target → @call with no args.
        if let Some(call_stmt) = try_lift_bare_call(local, i, entries) {
            out.push(call_stmt);
            i += 1;
            continue;
        }
        // 5. Plain @asm.
        let ins = local[i];
        if let Some(lbl) = labels.get(&ins.addr.0) {
            out.push(Stmt::Comment(format!("{lbl}:")));
        }
        out.push(asm_stmt(ins, entries, labels, resolver));
        i += 1;
    }
    out
}

/// If `local[i]` is `LDA #imm` and `local[i+1]` is a `JSR target`
/// where `target` is a function entry, return a `Stmt::Call` for the
/// combined two-instruction sequence.
fn try_lift_imm_call(local: &[&DecodedInsn], i: usize, entries: &HashSet<u64>) -> Option<Stmt> {
    let lda = local.get(i)?;
    if lda.mnemonic != Mnemonic::LDA || lda.mode != AddressingMode::Immediate {
        return None;
    }
    let jsr = local.get(i + 1)?;
    let InsnKind::Call { target, .. } = classify(jsr) else {
        return None;
    };
    if !entries.contains(&target) {
        return None;
    }
    let mut bytes = lda.original_bytes.clone();
    bytes.extend_from_slice(&jsr.original_bytes);
    Some(Stmt::Call {
        name: function_name(target, u64::MAX),
        args: vec![format!("A=#${:02X}", lda.operand)],
        bytes,
    })
}

/// If `local[i]` is a plain `JSR target` where `target` is a
/// known function entry, return a `Stmt::Call` with no args.
fn try_lift_bare_call(local: &[&DecodedInsn], i: usize, entries: &HashSet<u64>) -> Option<Stmt> {
    let jsr = local.get(i)?;
    let InsnKind::Call { target, .. } = classify(jsr) else {
        return None;
    };
    if !entries.contains(&target) {
        return None;
    }
    Some(Stmt::Call {
        name: function_name(target, u64::MAX),
        args: Vec::new(),
        bytes: jsr.original_bytes.clone(),
    })
}

/// If `local[target_idx - 1]` is `JMP $X` (absolute direct) whose
/// target `X` is the address of `local[x_idx]` for some
/// `x_idx > target_idx`, return `x_idx`. This is the marker that
/// the bytes `[target_idx, x_idx)` are the else-body of an if/else
/// pair whose Bcc skips into the else, and whose then path ends
/// with this `JMP` over the else.
fn find_jmp_over_else(local: &[&DecodedInsn], target_idx: usize) -> Option<usize> {
    if target_idx == 0 {
        return None;
    }
    let jmp = local[target_idx - 1];
    let InsnKind::JumpDirect { target: jmp_target } = classify(jmp) else {
        return None;
    };
    // Must be a forward jump landing strictly after the target.
    local
        .iter()
        .enumerate()
        .skip(target_idx + 1)
        .find(|(_, ins)| ins.addr.0 == jmp_target)
        .map(|(idx, _)| idx)
}

/// If `local[start_idx]` is a forward conditional branch whose
/// taken target lands on a later instruction inside this same
/// slice, return `(target_idx, branch_insn)`. The branch must use
/// the relative addressing mode (so `JMP $nnnn` doesn't match).
fn find_forward_branch_target<'a>(
    local: &[&'a DecodedInsn],
    start_idx: usize,
) -> Option<(usize, &'a DecodedInsn)> {
    let branch = local[start_idx];
    if branch.mode != AddressingMode::Relative {
        return None;
    }
    let InsnKind::Branch { taken, .. } = classify(branch) else {
        return None;
    };
    let next_addr = branch
        .addr
        .0
        .wrapping_add(branch.original_bytes.len() as u64);
    if taken <= next_addr {
        return None;
    }
    let target_idx = local
        .iter()
        .enumerate()
        .skip(start_idx + 1)
        .find(|(_, ins)| ins.addr.0 == taken)
        .map(|(j, _)| j)?;
    // Must skip at least one instruction. A zero-skip Bcc with
    // target == next-insn is degenerate (Bcc would never be useful);
    // require body to be non-empty.
    if target_idx <= start_idx + 1 {
        return None;
    }
    Some((target_idx, branch))
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

fn asm_stmt(
    ins: &DecodedInsn,
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
    resolver: SymbolResolver,
) -> Stmt {
    let mut text = format_insn_with(ins, resolver);
    if let Some(annot) = call_annotation(ins, entries, labels) {
        text = format!("{text}  ; {annot}");
    }
    Stmt::asm(text, ins.original_bytes.clone())
}

fn format_branch_cond(
    ins: &DecodedInsn,
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
    resolver: SymbolResolver,
) -> String {
    let base = format_insn_with(ins, resolver);
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

/// A function pointer that maps a 16-bit address to its symbolic
/// name, or `None` if unknown. Plugged into [`format_insn_with`]
/// when rendering `@asm` text.
type SymbolResolver = fn(u16) -> Option<&'static str>;

/// Apple I symbol resolver for the PIA-mapped keyboard / display
/// registers. Returns `None` for any address outside this region.
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

/// WozMon symbol resolver: Apple I I/O plus the zero-page
/// variables Wozniak named in his 1976 source.
///
/// Source: Wozniak's commented assembly listing (e.g. the
/// `wozmon.s` shipped alongside the binary fixture).
fn wozmon_symbol(addr: u16) -> Option<&'static str> {
    match addr {
        // Apple I PIA-mapped I/O.
        0xD010 => Some("KBD"),
        0xD011 => Some("KBDCR"),
        0xD012 => Some("DSP"),
        0xD013 => Some("DSPCR"),
        // WozMon zero-page variables.
        0x0024 => Some("XAML"),
        0x0025 => Some("XAMH"),
        0x0026 => Some("STL"),
        0x0027 => Some("STH"),
        0x0028 => Some("L"),
        0x0029 => Some("H"),
        0x002A => Some("YSAV"),
        0x002B => Some("MODE"),
        // WozMon's input buffer ($0200-$027F).
        0x0200 => Some("IN"),
        _ => None,
    }
}

/// Pick a program-aware symbol resolver based on image shape.
/// A 256-byte image at $FF00 whose reset vector points back to
/// $FF00 is WozMon; otherwise we fall back to the Apple I I/O
/// resolver. Both are guaranteed to include the I/O range.
fn pick_resolver(image: &RawImage) -> SymbolResolver {
    let looks_like_wozmon = image.bytes.len() == 0x100
        && image.load_addr == 0xFF00
        && image.read_u16_le(0xFFFC).ok() == Some(0xFF00);
    if looks_like_wozmon {
        wozmon_symbol
    } else {
        apple1_symbol
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

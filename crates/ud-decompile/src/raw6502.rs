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
use ud_ast::{Field, FnDecl, Item, Module, Param, Signature, Stmt, Type, UdFile, Value};
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
    let signatures = infer_signatures(&insns, &entries);

    let mut items: Vec<Item> = Vec::new();
    for (idx, &entry) in entries.iter().enumerate() {
        let end = entries.get(idx + 1).copied().unwrap_or(code_end);
        let body = build_body_range(&insns, entry, end, &labels, &entries, resolver, &signatures);
        let name = function_name(entry, reset_addr);
        let signature = signatures.get(&entry).cloned();
        items.push(Item::Function(FnDecl {
            addr: Some(entry),
            name,
            signature,
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

/// For each discovered entry, decide whether it takes an `A`
/// parameter by looking at its first instruction: if that
/// instruction *reads* the accumulator (without first writing it),
/// the function is consuming the caller's `A` and we attach a
/// one-param signature `(a: u8 @A)`.
///
/// This is a v0 calling-convention inference: it catches all three
/// WozMon subroutines (ECHO writes via `STA DSP`, PRBYTE pushes via
/// `PHA`, PRHEX runs `AND #$0F`) and stays silent for `reset`
/// (whose first instruction is `CLD`, no A read).
fn infer_signatures(insns: &[DecodedInsn], entries: &[u64]) -> HashMap<u64, Signature> {
    let mut out = HashMap::new();
    for &entry in entries {
        let Some(first) = insns.iter().find(|i| i.addr.0 == entry) else {
            continue;
        };
        if reads_accumulator(first) {
            out.insert(
                entry,
                Signature {
                    params: vec![Param {
                        name: "a".into(),
                        ty: Type::U8,
                        location: Some("A".into()),
                    }],
                    return_type: Type::Void,
                },
            );
        }
    }
    out
}

/// Does executing this single instruction read the accumulator?
/// Used by signature inference: the first instruction in a callee
/// reading A means the function takes A as input.
fn reads_accumulator(ins: &DecodedInsn) -> bool {
    use Mnemonic as M;
    if matches!(
        ins.mnemonic,
        M::ADC
            | M::AND
            | M::EOR
            | M::ORA
            | M::SBC
            | M::CMP
            | M::STA
            | M::TAX
            | M::TAY
            | M::PHA
            | M::BIT,
    ) {
        return true;
    }
    matches!(
        (ins.mnemonic, ins.mode),
        (
            M::ASL | M::LSR | M::ROL | M::ROR,
            AddressingMode::Accumulator
        )
    )
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
    signatures: &HashMap<u64, Signature>,
) -> Vec<Stmt> {
    let entry_set: HashSet<u64> = entries.iter().copied().collect();
    let local: Vec<&DecodedInsn> = insns
        .iter()
        .filter(|i| i.addr.0 >= start && i.addr.0 < end)
        .collect();
    build_stmt_slice(&local, &entry_set, labels, resolver, signatures)
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
#[allow(clippy::too_many_lines)]
fn build_stmt_slice(
    local: &[&DecodedInsn],
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
    resolver: SymbolResolver,
    signatures: &HashMap<u64, Signature>,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < local.len() {
        // 1. Back-branch do-while. The instruction right before the
        // back-branch is often a flag-setter (CMP/CPX/CPY/BIT, or a
        // load whose loaded value is being tested for zero); when so,
        // bundle it into tail_bytes so the loop reads "do { … } while
        // (CMP X; BNE)".
        if let Some((j, tail)) = find_back_branch_target(local, i) {
            let bundle_fs = j > i + 1 && is_flag_setter(local[j - 1]);
            let body_end = if bundle_fs { j - 1 } else { j };
            let body = build_stmt_slice(&local[i..body_end], entries, labels, resolver, signatures);
            let tail_text = format_branch_cond(tail, entries, labels, resolver);
            let (cond_text, mut tail_bytes) = if bundle_fs {
                let fs = local[j - 1];
                let fs_text = format_insn_with(fs, resolver);
                (format!("{fs_text}; {tail_text}"), fs.original_bytes.clone())
            } else {
                (tail_text, Vec::new())
            };
            tail_bytes.extend_from_slice(&tail.original_bytes);
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
            // Bundle the preceding flag-setter (if it was just
            // emitted as a plain @asm into `out`) so the @if_branch
            // cond_text reads like a complete predicate.
            let (cond_text, cond_bytes) =
                build_if_cond(&mut out, local, i, branch, entries, labels, resolver);
            if let Some(x_idx) = find_jmp_over_else(local, target_idx) {
                let then_body = build_stmt_slice(
                    &local[i + 1..target_idx],
                    entries,
                    labels,
                    resolver,
                    signatures,
                );
                let else_stmts = build_stmt_slice(
                    &local[target_idx..x_idx],
                    entries,
                    labels,
                    resolver,
                    signatures,
                );
                out.push(Stmt::IfBranch {
                    cond_text,
                    cond_bytes,
                    then_body,
                    else_body: Some(else_stmts),
                });
                i = x_idx;
                continue;
            }
            let then_body = build_stmt_slice(
                &local[i + 1..target_idx],
                entries,
                labels,
                resolver,
                signatures,
            );
            out.push(Stmt::IfBranch {
                cond_text,
                cond_bytes,
                then_body,
                else_body: None,
            });
            i = target_idx;
            continue;
        }
        // 3. LDA <src>; JSR known_target → @call. If the callee has
        //    a signature placing its first param in `A`, drop the
        //    "A=" prefix so the call reads as `sub_FFEF(#$0D)`.
        if let Some(call_stmt) = try_lift_imm_call(local, i, entries, resolver, signatures) {
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
        // 5. LDA src; STA dst (and LDX/LDY variants) → @move.
        //    Chains a trailing run of same-register stores into a
        //    multi-destination assignment text.
        if let Some((move_stmt, consumed)) = try_lift_move(local, i, resolver) {
            out.push(move_stmt);
            i += consumed;
            continue;
        }
        // 6. Bare store chain — STA dst1; STA dst2 (or STX, STY).
        //    With no preceding load, the source is the register
        //    itself, holding whatever was last computed.
        if let Some((move_stmt, consumed)) = try_lift_store_chain(local, i, resolver) {
            out.push(move_stmt);
            i += consumed;
            continue;
        }
        // 7. Consecutive accumulator shifts (LSR A or ASL A) — the
        //    "shift A by N" idiom used to extract a nibble or position
        //    bits. Collapse into a single multi-byte @asm.
        if let Some((stmt, consumed)) = try_lift_acc_shift_chain(local, i) {
            out.push(stmt);
            i += consumed;
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

/// If `local[i]` is `LDA <anything>` (immediate, zero-page,
/// absolute, …) and `local[i+1]` is `JSR target` where `target`
/// is a function entry, return a `Stmt::Call` for the combined
/// two-instruction sequence. The arg renders as `"A=<src>"` —
/// `"A=#$0D"` for immediate, `"A=KBD"` / `"A=XAMH"` etc. for memory.
fn try_lift_imm_call(
    local: &[&DecodedInsn],
    i: usize,
    entries: &HashSet<u64>,
    resolver: SymbolResolver,
    signatures: &HashMap<u64, Signature>,
) -> Option<Stmt> {
    let lda = local.get(i)?;
    if lda.mnemonic != Mnemonic::LDA {
        return None;
    }
    if matches!(
        lda.mode,
        AddressingMode::Implied | AddressingMode::Accumulator | AddressingMode::IllegalOperand
    ) {
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
    let src_text = format_operand(lda, resolver);
    // If the callee's signature places its first parameter in A,
    // the register tag belongs to the function definition — the
    // call site just passes the value.
    let callee_takes_a = signatures
        .get(&target)
        .and_then(|s| s.params.first())
        .and_then(|p| p.location.as_deref())
        == Some("A");
    let arg = if callee_takes_a {
        src_text
    } else {
        format!("A={src_text}")
    };
    Some(Stmt::Call {
        name: function_name(target, u64::MAX),
        args: vec![arg],
        bytes,
    })
}

/// If `local[i..]` starts with a register load (`LDA`/`LDX`/`LDY`)
/// followed by one or more stores of that same register, return
/// `(Stmt::Move, consumed)` where `consumed` is the number of
/// instructions folded in.
///
/// The `dst` field of `Move` becomes either the single destination
/// operand or `"dst1 = dst2 = …"` when multiple stores fan out the
/// same value (catches the canonical `LDA #x; STA a; STA b` setup
/// in WozMon's reset).
fn try_lift_move(
    local: &[&DecodedInsn],
    i: usize,
    resolver: SymbolResolver,
) -> Option<(Stmt, usize)> {
    let load = local.get(i)?;
    let store_mn = match load.mnemonic {
        Mnemonic::LDA => Mnemonic::STA,
        Mnemonic::LDX => Mnemonic::STX,
        Mnemonic::LDY => Mnemonic::STY,
        _ => return None,
    };
    let mut bytes = load.original_bytes.clone();
    let mut dsts: Vec<String> = Vec::new();
    let mut j = i + 1;
    while let Some(store) = local.get(j) {
        if store.mnemonic != store_mn {
            break;
        }
        if matches!(
            store.mode,
            AddressingMode::Implied | AddressingMode::Accumulator | AddressingMode::IllegalOperand
        ) {
            break;
        }
        let dst = format_operand(store, resolver);
        // Avoid a degenerate self-move (LDA $24; STA $24) — but only
        // for the very first store; later stores in a fanout are
        // fine to repeat.
        if j == i + 1 {
            let src = format_operand(load, resolver);
            if src == dst {
                return None;
            }
        }
        bytes.extend_from_slice(&store.original_bytes);
        dsts.push(dst);
        j += 1;
    }
    if dsts.is_empty() {
        return None;
    }
    let src = format_operand(load, resolver);
    let dst = dsts.join(" = ");
    Some((Stmt::Move { dst, src, bytes }, j - i))
}

/// If `local[i..]` is two or more consecutive `LSR A` or `ASL A`
/// (accumulator-mode shifts), collapse them into a single
/// `@asm("LSR A xN", [bytes])` carrying all the shift bytes.
/// Returns `(stmt, consumed_count)`.
///
/// This is the canonical "shift A by N to extract a nibble or
/// position bits" idiom — `LSR A x4` in PRBYTE, `ASL A x4` in
/// the hex-digit shifter.
fn try_lift_acc_shift_chain(local: &[&DecodedInsn], i: usize) -> Option<(Stmt, usize)> {
    let first = local.get(i)?;
    let op_text = match (first.mnemonic, first.mode) {
        (Mnemonic::ASL, AddressingMode::Accumulator) => "ASL A",
        (Mnemonic::LSR, AddressingMode::Accumulator) => "LSR A",
        _ => return None,
    };
    let second = local.get(i + 1)?;
    if second.mnemonic != first.mnemonic || second.mode != first.mode {
        return None;
    }
    let mut bytes = first.original_bytes.clone();
    let mut count = 1usize;
    let mut j = i + 1;
    while let Some(ins) = local.get(j) {
        if ins.mnemonic != first.mnemonic || ins.mode != first.mode {
            break;
        }
        bytes.extend_from_slice(&ins.original_bytes);
        count += 1;
        j += 1;
    }
    Some((Stmt::asm(format!("{op_text} x{count}"), bytes), count))
}

/// If `local[i..]` is `STA dst1; STA dst2 [; STA dst3 ...]`
/// (or STX/STY variants) with no preceding load that consumed the
/// register's value, return `(Stmt::Move, consumed)`. The source
/// is the register name (`"A"`, `"X"`, `"Y"`); the destination is
/// `"dst1 = dst2 = …"`.
fn try_lift_store_chain(
    local: &[&DecodedInsn],
    i: usize,
    resolver: SymbolResolver,
) -> Option<(Stmt, usize)> {
    let first = local.get(i)?;
    let (store_mn, reg_name) = match first.mnemonic {
        Mnemonic::STA => (Mnemonic::STA, "A"),
        Mnemonic::STX => (Mnemonic::STX, "X"),
        Mnemonic::STY => (Mnemonic::STY, "Y"),
        _ => return None,
    };
    // Need at least two stores; a single store still reads naturally
    // as `@asm("STA addr", …)`.
    let second = local.get(i + 1)?;
    if second.mnemonic != store_mn {
        return None;
    }
    let mut dsts = vec![format_operand(first, resolver)];
    let mut bytes = first.original_bytes.clone();
    let mut j = i + 1;
    while let Some(ins) = local.get(j) {
        if ins.mnemonic != store_mn {
            break;
        }
        if matches!(
            ins.mode,
            AddressingMode::Implied | AddressingMode::Accumulator | AddressingMode::IllegalOperand
        ) {
            break;
        }
        dsts.push(format_operand(ins, resolver));
        bytes.extend_from_slice(&ins.original_bytes);
        j += 1;
    }
    let dst = dsts.join(" = ");
    Some((
        Stmt::Move {
            dst,
            src: reg_name.to_string(),
            bytes,
        },
        j - i,
    ))
}

/// Render only the operand part of an instruction (everything that
/// `format_insn_with` produces after the mnemonic). Used to build
/// the source / destination text in `@move`.
fn format_operand(ins: &DecodedInsn, resolver: SymbolResolver) -> String {
    let full = format_insn_with(ins, resolver);
    full.split_once(' ')
        .map_or(full.clone(), |(_, rest)| rest.to_string())
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

/// Build the `(cond_text, cond_bytes)` for an `@if_branch` whose
/// conditional Bcc is `branch` at `local[i]`.
///
/// If the previously-emitted statement (`out.last()`) is a plain
/// `@asm` representing the immediately preceding flag-setter
/// (`local[i - 1]`), and that flag-setter is the kind that justifies
/// the Bcc that follows (CMP, CPX, CPY, BIT, plus the LDA/LDX/LDY
/// "test for zero" idiom), pop it from `out` and merge its bytes /
/// text into the condition.
fn build_if_cond(
    out: &mut Vec<Stmt>,
    local: &[&DecodedInsn],
    i: usize,
    branch: &DecodedInsn,
    entries: &HashSet<u64>,
    labels: &HashMap<u64, String>,
    resolver: SymbolResolver,
) -> (String, Vec<u8>) {
    let branch_text = format_insn_with(branch, resolver);
    let branch_text = if let Some(annot) = call_annotation(branch, entries, labels) {
        format!("{branch_text}  ; {annot}")
    } else {
        branch_text
    };

    if i > 0 && is_flag_setter(local[i - 1]) {
        let prev = local[i - 1];
        let bundle_match = matches!(
            out.last(),
            Some(Stmt::Asm { bytes, .. }) if bytes == &prev.original_bytes,
        );
        if bundle_match {
            out.pop();
            let prev_text = format_insn_with(prev, resolver);
            let mut bytes = prev.original_bytes.clone();
            bytes.extend_from_slice(&branch.original_bytes);
            return (format!("{prev_text}; {branch_text}"), bytes);
        }
    }
    (branch_text, branch.original_bytes.clone())
}

/// Is `ins` an instruction whose primary effect (in this context)
/// is setting the flag bits that a following Bcc tests against?
/// CMP/CPX/CPY/BIT are pure tests. LDA/LDX/LDY are dual-purpose:
/// they load a register and incidentally set Z/N, which 6502 code
/// regularly relies on for "is the loaded value zero" branches.
fn is_flag_setter(ins: &DecodedInsn) -> bool {
    matches!(
        ins.mnemonic,
        Mnemonic::CMP
            | Mnemonic::CPX
            | Mnemonic::CPY
            | Mnemonic::BIT
            | Mnemonic::LDA
            | Mnemonic::LDX
            | Mnemonic::LDY
    )
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

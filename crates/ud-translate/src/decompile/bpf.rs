//! BPF function-body builder.
//!
//! Mirrors `decompile/aarch64.rs`: each decoded instruction
//! emits one `@asm` line whose text comes from
//! [`ud_arch_bpf::format_insn`] and whose pinned bytes are the
//! 8 raw encoding bytes. Round-trip is guaranteed by the byte
//! list — editing the text does not regenerate bytes (no BPF
//! assembler in v1).
//!
//! Direct calls and unconditional jumps within the function
//! get the usual `// -> name` annotations when their target is
//! a known function or symbol.
//!
//! For `call <imm>` instructions whose address appears in the
//! relocation-derived name map (`call_site_names`), the
//! rendered text has its `0x<hex>` operand replaced by the
//! imported symbol name (e.g. `call sol_log_` instead of
//! `call 0xeca`). The pinned bytes are unchanged — the rewrite
//! is purely textual, so editing the text doesn't change the
//! recompiled bytes.
//!
//! LDDW (load 64-bit immediate) is rendered as a pair of
//! `@asm` lines — one for the `lddw` slot itself plus a
//! continuation slot whose text reads `<lddw-cont 0x…>`. Both
//! slots carry their raw bytes, so the 16-byte instruction
//! round-trips intact.

use std::collections::HashMap;

use ud_arch_bpf::{call_target, format_insn, jump_target, BpfVariant, DecodedInsn, InsnKind};
use ud_ast::{FnDecl, Stmt};
use ud_ir::Function;

use super::stack_slots::rewrite_slots;

/// Name of the BPF frame-pointer register. Hard-coded by the
/// ISA — there is no other choice on any BPF variant.
const BPF_FP: &str = "r10";

/// Build a `FnDecl` from a lifted BPF function.
///
/// `name_at` maps function entry addresses → names (for jump
/// / fall-through call annotations). `call_site_names` maps
/// `call <imm>` instruction addresses → imported symbol names
/// (typically syscalls resolved through `.rel.dyn`).
#[must_use]
pub fn build_function(
    f: &Function<DecodedInsn>,
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
    variant: BpfVariant,
) -> FnDecl {
    // Layer-4 pre-pass: collect every jump target *inside*
    // this function. A target outside the function's address
    // range is a cross-function tail-call and stays as
    // numeric offset / comment annotation; only intra-function
    // jumps get `label_<addr>:` markers.
    let fn_start = f.addr.0;
    let fn_end = fn_start.saturating_add(f.size() as u64);
    let mut intra_targets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for block in &f.blocks {
        for insn in &block.insns {
            if matches!(
                insn.kind,
                InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32
            ) {
                let t = jump_target(insn);
                if (fn_start..fn_end).contains(&t) {
                    intra_targets.insert(t);
                }
            }
        }
    }

    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            // Emit a `label_<addr>:` marker before every
            // instruction that's a known jump target.
            if intra_targets.contains(&insn.addr.0) {
                body.push(Stmt::Label { addr: insn.addr.0 });
            }
            let text = render_text(insn, variant, name_at, call_site_names, &intra_targets);
            body.push(Stmt::asm(text, insn.bytes.to_vec()));
            if let Some(annotation) = call_or_branch_annotation(insn, name_at, &intra_targets) {
                body.push(Stmt::Comment(annotation));
            }
        }
    }
    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        attrs: Vec::new(),
        locals: Vec::new(),
        signature: None,
        body,
    }
}

/// Format an instruction with name-aware substitution.
///
/// Two cases for `call`:
///   1. Relocation map names the *call site* (syscall import).
///      Render as `call <symbol>`.
///   2. Otherwise, compute the local call target. If it lands
///      on a known function (layer-2 `sub_<addr>` or anything
///      else), render as `call <fn_name>`.
///
/// The pinned bytes never change; only the text does.
fn render_text(
    insn: &DecodedInsn,
    variant: BpfVariant,
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
    intra_targets: &std::collections::BTreeSet<u64>,
) -> String {
    if matches!(insn.kind, InsnKind::Call) {
        if let Some(name) = call_site_names.get(&insn.addr.0) {
            return format!("call {name}");
        }
        let target = call_target(insn);
        if let Some(name) = name_at.get(&target) {
            return format!("call {name}");
        }
    }
    // Layer-4: rewrite the relative-offset operand of intra-
    // function jumps to a `label_<addr>` reference. The trailing
    // `, +0xN` is replaced with `, label_<target_hex>`. Calls
    // already get name substitution above; jumps to other
    // functions stay as offsets and pick up a `// -> name`
    // comment via `call_or_branch_annotation`.
    let mut text = rewrite_slots(&format_insn(insn, variant), BPF_FP);
    if matches!(
        insn.kind,
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32
    ) {
        let target = jump_target(insn);
        if intra_targets.contains(&target) {
            text = rewrite_branch_offset(&text, target);
        }
    }
    text
}

/// Replace the trailing relative offset of a jump (`+0xN` or
/// `-0xN`) with `label_<target_hex>`. Keeps the rest of the
/// line unchanged so unconditional `ja` and conditional
/// `jeq r1, 0x0, +0x2` forms both work — the offset is always
/// the last token before end-of-line.
fn rewrite_branch_offset(text: &str, target: u64) -> String {
    let label_ref = format!("label_{target:x}");
    if let Some((head, _)) = text.rsplit_once(", +0x") {
        return format!("{head}, {label_ref}");
    }
    if let Some((head, _)) = text.rsplit_once(", -0x") {
        return format!("{head}, {label_ref}");
    }
    // Unconditional jump (`ja +0xN`): no comma.
    if let Some((head, _)) = text.rsplit_once(" +0x") {
        return format!("{head} {label_ref}");
    }
    if let Some((head, _)) = text.rsplit_once(" -0x") {
        return format!("{head} {label_ref}");
    }
    text.to_string()
}

/// Annotate jumps whose target is a known function — i.e.
/// cross-function tail-calls. Intra-function jumps now point
/// at named labels and need no comment.
fn call_or_branch_annotation(
    insn: &DecodedInsn,
    name_at: &HashMap<u64, String>,
    intra_targets: &std::collections::BTreeSet<u64>,
) -> Option<String> {
    match insn.kind {
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32 => {
            let target = jump_target(insn);
            if intra_targets.contains(&target) {
                // Already labelled — no extra comment needed.
                return None;
            }
            name_at.get(&target).map(|n| format!("-> {n}"))
        }
        _ => None,
    }
}

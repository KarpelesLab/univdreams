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

use ud_arch_bpf::{format_insn, jump_target, BpfVariant, DecodedInsn, InsnKind};
use ud_ast::{FnDecl, Stmt};
use ud_ir::Function;

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
    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            let text = render_text(insn, variant, call_site_names);
            body.push(Stmt::asm(text, insn.bytes.to_vec()));
            if let Some(annotation) = call_or_branch_annotation(insn, name_at, call_site_names) {
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

/// Format an instruction with name-aware substitution: a
/// `call <hex>` whose address has an entry in `call_site_names`
/// renders as `call <symbol>` instead.
fn render_text(
    insn: &DecodedInsn,
    variant: BpfVariant,
    call_site_names: &HashMap<u64, String>,
) -> String {
    let base = format_insn(insn, variant);
    if matches!(insn.kind, InsnKind::Call) {
        if let Some(name) = call_site_names.get(&insn.addr.0) {
            return format!("call {name}");
        }
    }
    base
}

/// Annotate direct calls (with relocation-resolved names) and
/// unconditional jumps whose target is a known function.
fn call_or_branch_annotation(
    insn: &DecodedInsn,
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
) -> Option<String> {
    match insn.kind {
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32 => {
            name_at.get(&jump_target(insn)).map(|n| format!("-> {n}"))
        }
        // For calls we already substituted the operand in the
        // `@asm` text; no need to add a `// -> name` comment
        // since the name is right there. Without a reloc hit,
        // a numeric `call 0xeca` stays in the text and we have
        // nothing to add.
        InsnKind::Call => {
            // Stay silent when the reloc map covered this site —
            // the text already names it. If the call wasn't in
            // the reloc map but lands on a known local function
            // (layer 2 will fill `name_at` for sub_<addr>),
            // we'll annotate; until layer 2 lands, this branch
            // is effectively unreachable for syscalls.
            if call_site_names.contains_key(&insn.addr.0) {
                None
            } else {
                let target = jump_target(insn);
                name_at.get(&target).map(|n| format!("-> {n}"))
            }
        }
        _ => None,
    }
}

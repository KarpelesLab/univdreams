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
    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            let text = render_text(insn, variant, name_at, call_site_names);
            body.push(Stmt::asm(text, insn.bytes.to_vec()));
            if let Some(annotation) = call_or_branch_annotation(insn, name_at) {
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
    // Layer-3 rewrite: `[r10 - 0x38]` → `[local_38]`,
    // `[r10 + 0x10]` → `[arg_10]`. The bytes don't change;
    // round-trip stays byte-identical via the pinned @asm
    // payload.
    rewrite_slots(&format_insn(insn, variant), BPF_FP)
}

/// Annotate jumps whose target is a known function (cross-
/// function tail-calls are rare in BPF but possible). Calls
/// are already named by `render_text` so they need no
/// extra annotation.
fn call_or_branch_annotation(insn: &DecodedInsn, name_at: &HashMap<u64, String>) -> Option<String> {
    match insn.kind {
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32 => {
            name_at.get(&jump_target(insn)).map(|n| format!("-> {n}"))
        }
        _ => None,
    }
}

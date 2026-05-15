//! AArch64 function-body builder.
//!
//! v0 mirrors the shape of `build_function` for x86 but is much
//! simpler: the aarch64 backend doesn't yet do prologue/epilogue
//! lifting, call-site analysis, or if/else grouping. Each decoded
//! instruction emits one `@asm` line whose text comes from
//! [`ud_arch_aarch64::format_text`] (a placeholder that names
//! recognised flow-control mnemonics and falls back to
//! `<arm64 0xXXXXXXXX>` for everything else).
//!
//! Direct calls and unconditional branches still get the standard
//! `// -> name` annotations when the target is a known function —
//! that's format-agnostic and uses `name_at` only.

use std::collections::HashMap;

use ud_arch_aarch64::{format_text, DecodedInsn, InsnKind};
use ud_ast::{FnDecl, Stmt};
use ud_ir::Function;

/// Build a `FnDecl` from a lifted AArch64 function.
#[must_use]
pub fn build_function(f: &Function<DecodedInsn>, name_at: &HashMap<u64, String>) -> FnDecl {
    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            body.push(Stmt::asm(format_text(insn), insn.bytes.to_vec()));
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

/// Format-agnostic annotation for direct branches/calls whose
/// target is a known function.
fn call_or_branch_annotation(insn: &DecodedInsn, name_at: &HashMap<u64, String>) -> Option<String> {
    match insn.kind {
        InsnKind::BranchLink { target } => name_at.get(&target).map(|n| format!("-> {n}")),
        InsnKind::BranchDirect { target } => name_at.get(&target).map(|n| format!("-> {n}")),
        _ => None,
    }
}

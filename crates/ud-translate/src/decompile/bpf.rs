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
#[must_use]
pub fn build_function(
    f: &Function<DecodedInsn>,
    name_at: &HashMap<u64, String>,
    variant: BpfVariant,
) -> FnDecl {
    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            body.push(Stmt::asm(format_insn(insn, variant), insn.bytes.to_vec()));
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

/// Annotate direct calls and unconditional jumps whose target
/// is a known function. BPF `call imm` is helper-id-indexed on
/// Linux and Murmur3-hash-indexed on SBF — both look like a raw
/// integer in `imm`, so we don't try to resolve them here. For
/// `ja +offset` and conditional jumps, the target is computed
/// from `addr + (offset + 1) * 8`; if that lands on a known
/// function entry, render it.
fn call_or_branch_annotation(insn: &DecodedInsn, name_at: &HashMap<u64, String>) -> Option<String> {
    match insn.kind {
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32 => {
            name_at.get(&jump_target(insn)).map(|n| format!("-> {n}"))
        }
        _ => None,
    }
}

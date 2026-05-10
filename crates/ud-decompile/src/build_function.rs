//! Build the `FnDecl` AST node for a lifted function.

use std::collections::HashMap;

use ud_arch_x86::{
    direct_call_target, direct_unconditional_branch_target, format_intel, DecodedInsn,
};
use ud_ast::{FnDecl, Signature, Stmt};
use ud_debug::DebugFunction;
use ud_ir::{Function, Terminator};

/// Convert a lifted [`Function`] into the AST's [`FnDecl`].
///
/// One [`Stmt::Asm`] per decoded instruction (Intel syntax); a
/// [`Stmt::Comment`] before each non-entry block surfacing its address;
/// a [`Stmt::Comment`] after blocks ending in a direct branch
/// surfacing the targets. Indirect / return / unreachable blocks need
/// no annotation since the asm text already says so.
#[must_use]
pub fn build_function(
    f: &Function<DecodedInsn>,
    debug: Option<&DebugFunction>,
    name_at: &HashMap<u64, String>,
) -> FnDecl {
    let mut body = Vec::new();
    for (i, block) in f.blocks.iter().enumerate() {
        if i > 0 {
            body.push(Stmt::Comment(format!("block: 0x{:x}", block.addr.0)));
        }
        for insn in &block.insns {
            body.push(Stmt::asm(
                format_intel(&insn.iced),
                insn.original_bytes.clone(),
            ));
            let func_end = f.addr.0.saturating_add(f.size() as u64);
            if let Some(annotation) = call_annotation(insn, f.addr.0, func_end, name_at) {
                body.push(Stmt::Comment(annotation));
            }
        }
        match &block.terminator {
            Terminator::ConditionalBranch { taken, fallthrough } => {
                body.push(Stmt::Comment(format!(
                    "-> {{ taken: 0x{:x}, fallthrough: 0x{:x} }}",
                    taken.0, fallthrough.0
                )));
            }
            Terminator::UnconditionalBranch { target } => {
                body.push(Stmt::Comment(format!("-> 0x{:x}", target.0)));
            }
            Terminator::Return
            | Terminator::IndirectBranch
            | Terminator::InvalidOrUnreachable
            | Terminator::Fallthrough => {}
        }
    }
    let signature = debug.map(|d| Signature {
        params: d.params.clone(),
        return_type: d.return_type.clone(),
    });
    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        signature,
        body,
    }
}

/// Decide what (if anything) to comment after an instruction based on
/// its flow control:
///
/// * Direct `call` to a known function → `// -> <name>`.
/// * Direct `jmp` to a known function *outside* the current function's
///   address range → `// tail-call -> <name>` (a real tail call to
///   another function, not a same-function branch).
/// * Anything else (returns, conditionals, indirect calls / branches,
///   normal moves) → no annotation.
fn call_annotation(
    insn: &DecodedInsn,
    fn_start: u64,
    fn_end: u64,
    name_at: &HashMap<u64, String>,
) -> Option<String> {
    if let Some(target) = direct_call_target(&insn.iced) {
        if let Some(name) = name_at.get(&target) {
            return Some(format!("-> {name}"));
        }
    }
    if let Some(target) = direct_unconditional_branch_target(&insn.iced) {
        let outside_function = target < fn_start || target >= fn_end;
        if outside_function {
            if let Some(name) = name_at.get(&target) {
                return Some(format!("tail-call -> {name}"));
            }
        }
    }
    None
}

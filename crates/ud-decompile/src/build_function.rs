//! Build the `FnDecl` AST node for a lifted function.

use std::collections::HashMap;

use ud_arch_x86::{
    direct_call_target, direct_unconditional_branch_target, format_intel, try_lift_return_pattern,
    DecodedInsn,
};
use ud_ast::{FnDecl, Signature, Stmt, Type};
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

    // Phase 7: lift the trailing instructions of the last block to a
    // structured `Stmt::Return` when they match a recognised pattern
    // and the function returns an integer-like type. Bytes are pinned,
    // so round-trip is unaffected.
    if let Some(sig) = &signature {
        if return_type_is_integer_like(&sig.return_type) {
            if let Some(last_block) = f.blocks.last() {
                if let Some(lifted) = try_lift_return_pattern(&last_block.insns) {
                    let total = last_block.insns.len();
                    let return_bytes: Vec<u8> = last_block.insns[total - lifted.insns_consumed..]
                        .iter()
                        .flat_map(|i| i.original_bytes.iter().copied())
                        .collect();
                    drop_trailing_for_return(&mut body, lifted.insns_consumed);
                    body.push(Stmt::Return {
                        value: lifted.value,
                        bytes: return_bytes,
                    });
                }
            }
        }
    }

    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        signature,
        body,
    }
}

/// Pop the last `n_asm` `Stmt::Asm` entries from `body`, along with any
/// trailing comments that sit between them (e.g. `// -> name` annotations
/// the call-target pass might have added). Used to make room for a
/// lifted `Stmt::Return`.
fn drop_trailing_for_return(body: &mut Vec<Stmt>, n_asm: usize) {
    let mut popped = 0usize;
    while popped < n_asm {
        match body.last() {
            Some(Stmt::Asm { .. }) => {
                body.pop();
                popped += 1;
            }
            Some(Stmt::Comment(_)) => {
                body.pop();
            }
            _ => break,
        }
    }
}

fn return_type_is_integer_like(t: &Type) -> bool {
    matches!(
        t,
        Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::Bool
            | Type::Char
    )
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

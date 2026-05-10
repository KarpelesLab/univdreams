//! Build the `FnDecl` AST node for a lifted function.

use std::collections::HashMap;

use ud_arch_x86::{
    arg_spill_index, direct_call_target, direct_unconditional_branch_target, format_intel,
    try_lift_epilogue_pattern, try_lift_prologue_pattern, try_lift_return_pattern,
    try_lift_return_via_jmp, DecodedInsn,
};
use ud_ast::{FnDecl, Param, Signature, Stmt, Type};
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
    let signature = debug.map(|d| Signature {
        params: d.params.clone(),
        return_type: d.return_type.clone(),
    });
    let lifts = compute_block_tail_lifts(f, signature.as_ref());

    let mut body = Vec::new();
    let func_end = f.addr.0.saturating_add(f.size() as u64);

    for (i, block) in f.blocks.iter().enumerate() {
        if i > 0 {
            body.push(Stmt::Comment(format!("block: 0x{:x}", block.addr.0)));
        }

        // First block only: try to lift a leading prologue. We skip
        // the consumed instructions when emitting @asm.
        let prologue_consumed = if i == 0 {
            if let Some(lifted) = try_lift_prologue_pattern(&block.insns) {
                let bytes: Vec<u8> = block.insns[..lifted.insns_consumed]
                    .iter()
                    .flat_map(|insn| insn.original_bytes.iter().copied())
                    .collect();
                body.push(Stmt::Prologue {
                    kind: lifted.kind.to_string(),
                    bytes,
                });
                lifted.insns_consumed
            } else {
                0
            }
        } else {
            0
        };

        // Number of trailing instructions that get folded into a
        // single Stmt::Return / Stmt::Epilogue for this block; emit
        // the rest as @asm.
        let consumed = match &lifts[i] {
            Some(
                BlockTailLift::Return { insns_consumed, .. }
                | BlockTailLift::Epilogue { insns_consumed, .. },
            ) => *insns_consumed,
            None => 0,
        };
        let asm_count = block.insns.len() - consumed;

        for insn in &block.insns[prologue_consumed..asm_count] {
            body.push(Stmt::asm(
                format_intel(&insn.iced),
                insn.original_bytes.clone(),
            ));
            if let Some(annotation) = call_annotation(insn, f.addr.0, func_end, name_at) {
                body.push(Stmt::Comment(annotation));
            }
            if let Some(annotation) = arg_spill_annotation(insn, signature.as_ref()) {
                body.push(Stmt::Comment(annotation));
            }
        }

        if let Some(lift) = &lifts[i] {
            let lifted_bytes: Vec<u8> = block.insns[asm_count..]
                .iter()
                .flat_map(|insn| insn.original_bytes.iter().copied())
                .collect();
            match lift {
                BlockTailLift::Return { value, .. } => {
                    body.push(Stmt::Return {
                        value: *value,
                        bytes: lifted_bytes,
                    });
                }
                BlockTailLift::Epilogue { kind, .. } => {
                    body.push(Stmt::Epilogue {
                        kind: (*kind).to_string(),
                        bytes: lifted_bytes,
                    });
                }
            }
            // The lift consumed the block's terminating instruction
            // (ret, jmp-to-epilogue, or an epilogue-style return); no
            // separate terminator-comment is appropriate here.
            continue;
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

    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        signature,
        body,
    }
}

/// One block's trailing-instruction lift decision.
enum BlockTailLift {
    /// The block ends with a recognised return-with-literal pattern;
    /// fold those instructions into a `Stmt::Return`.
    Return { insns_consumed: usize, value: u64 },
    /// The block ends with a recognised epilogue (`leave; ret` /
    /// `pop rbp; ret`); fold into a `Stmt::Epilogue`. Only ever set
    /// for the function's last block, and only when no `Return` lift
    /// matched.
    Epilogue {
        insns_consumed: usize,
        kind: &'static str,
    },
}

/// Per-block: which trailing instructions become a `Stmt::Return` or
/// `Stmt::Epilogue`?
///
/// * **Tail block** (the last `BasicBlock`): try
///   [`try_lift_return_pattern`] first (value-setter + optional
///   teardown + `ret`). When it doesn't match — typically because the
///   return value was computed in an earlier block — fall back to
///   [`try_lift_epilogue_pattern`] (just the teardown + `ret`).
/// * **Non-tail blocks**: try [`try_lift_return_via_jmp`] when the
///   block's last instruction is a direct `jmp` to the tail block's
///   start address (a return-via-shared-epilogue site).
///
/// Return-style lifts only fire when the function's signature says it
/// returns an integer-like type. Epilogue lifts always fire when the
/// pattern matches — the bytes are mechanical regardless of return
/// type.
fn compute_block_tail_lifts(
    f: &Function<DecodedInsn>,
    signature: Option<&Signature>,
) -> Vec<Option<BlockTailLift>> {
    let mut out: Vec<Option<BlockTailLift>> = (0..f.blocks.len()).map(|_| None).collect();
    let Some(last_idx) = f.blocks.len().checked_sub(1) else {
        return out;
    };
    let epilogue_addr = f.blocks[last_idx].addr.0;

    let return_lift_allowed =
        signature.is_some_and(|s| return_type_is_integer_like(&s.return_type));

    for (i, block) in f.blocks.iter().enumerate() {
        if i == last_idx {
            if return_lift_allowed {
                if let Some(lifted) = try_lift_return_pattern(&block.insns) {
                    out[i] = Some(BlockTailLift::Return {
                        insns_consumed: lifted.insns_consumed,
                        value: lifted.value,
                    });
                    continue;
                }
            }
            if let Some(lifted) = try_lift_epilogue_pattern(&block.insns) {
                out[i] = Some(BlockTailLift::Epilogue {
                    insns_consumed: lifted.insns_consumed,
                    kind: lifted.kind,
                });
            }
        } else if return_lift_allowed {
            if let Some(lifted) = try_lift_return_via_jmp(&block.insns, epilogue_addr) {
                out[i] = Some(BlockTailLift::Return {
                    insns_consumed: lifted.insns_consumed,
                    value: lifted.value,
                });
            }
        }
    }
    out
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

/// If `insn` is a mov of a SysV-x64 argument register to a stack slot
/// AND the function has a parameter at that argument's index, return
/// a comment string naming the parameter. The decompiler appends the
/// returned string as a `Stmt::Comment` after the insn's `@asm` line.
fn arg_spill_annotation(insn: &DecodedInsn, signature: Option<&Signature>) -> Option<String> {
    let idx = arg_spill_index(&insn.iced)?;
    let sig = signature?;
    let param = sig.params.get(idx as usize)?;
    Some(format_param_annotation(idx, param))
}

fn format_param_annotation(idx: u32, param: &Param) -> String {
    let ty = format_type(&param.ty);
    if param.name.is_empty() {
        format!("arg {idx}: {ty}")
    } else {
        format!("arg {idx}: {} ({ty})", param.name)
    }
}

fn format_type(t: &Type) -> String {
    match t {
        Type::Void => "void".into(),
        Type::I8 => "i8".into(),
        Type::I16 => "i16".into(),
        Type::I32 => "i32".into(),
        Type::I64 => "i64".into(),
        Type::U8 => "u8".into(),
        Type::U16 => "u16".into(),
        Type::U32 => "u32".into(),
        Type::U64 => "u64".into(),
        Type::F32 => "f32".into(),
        Type::F64 => "f64".into(),
        Type::Bool => "bool".into(),
        Type::Char => "char".into(),
        Type::Pointer(inner) => format!("ptr<{}>", format_type(inner)),
        Type::Unknown => "unknown".into(),
    }
}

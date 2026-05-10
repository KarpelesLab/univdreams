//! Build the `FnDecl` AST node for a lifted function.

use std::collections::HashMap;

use ud_arch_x86::{
    arg_spill_index, direct_call_target, direct_unconditional_branch_target, format_intel,
    try_lift_epilogue_pattern, try_lift_if_branch_head, try_lift_prologue_pattern,
    try_lift_return_pattern, try_lift_return_via_jmp, try_lift_value_block, DecodedInsn,
    ExprRenderCtx,
};
use ud_ast::{FnDecl, Signature, Stmt, Type};
use ud_debug::DebugFunction;
use ud_ir::{BasicBlock, Function, Terminator};

/// Convert a lifted [`Function`] into the AST's [`FnDecl`].
///
/// Most blocks emit one [`Stmt::Asm`] per decoded instruction (Intel
/// syntax). When the function's CFG matches a recognised
/// `cmp/test + jcc + then-block + else-block` shape, those three
/// blocks are folded into a single [`Stmt::IfBranch`] with the
/// branches embedded as nested statements.
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
    let slot_to_name = collect_slot_to_name(f, signature.as_ref());
    let lifts = compute_block_tail_lifts(f, signature.as_ref(), &slot_to_name, name_at);
    let groups = identify_if_else_groups(f);

    let mut body = Vec::new();
    let func_end = f.addr.0.saturating_add(f.size() as u64);
    let ctx = EmitCtx {
        fn_addr_start: f.addr.0,
        fn_addr_end: func_end,
        name_at,
        signature: signature.as_ref(),
    };

    let mut i = 0;
    while i < f.blocks.len() {
        if let Some(group) = groups[i].as_ref() {
            // Conditional block A is at i; fallthrough B is at i+1.
            // For an if-with-else group C is at i+2 and the lift owns
            // three blocks; for an if-only group C is the post-if join
            // block, owned by the outer iteration.
            emit_block_stmts(
                &mut body,
                &f.blocks[i],
                BlockEmitConfig {
                    is_first: i == 0,
                    emit_block_comment: i > 0,
                    truncate_trailing: group.head_consumed,
                    emit_terminator_comment: false,
                },
                lifts[i].as_ref(),
                &ctx,
            );

            let mut then_body = Vec::new();
            emit_block_stmts(
                &mut then_body,
                &f.blocks[i + 1],
                BlockEmitConfig {
                    is_first: false,
                    emit_block_comment: false,
                    truncate_trailing: 0,
                    emit_terminator_comment: false,
                },
                lifts[i + 1].as_ref(),
                &ctx,
            );

            let (else_body, advance) = if group.has_else {
                let mut else_body = Vec::new();
                emit_block_stmts(
                    &mut else_body,
                    &f.blocks[i + 2],
                    BlockEmitConfig {
                        is_first: false,
                        emit_block_comment: false,
                        truncate_trailing: 0,
                        emit_terminator_comment: false,
                    },
                    lifts[i + 2].as_ref(),
                    &ctx,
                );
                (Some(else_body), 3)
            } else {
                (None, 2)
            };

            body.push(Stmt::IfBranch {
                cond_text: group.cond_text.clone(),
                cond_bytes: group.cond_bytes.clone(),
                then_body,
                else_body,
            });
            i += advance;
        } else {
            emit_block_stmts(
                &mut body,
                &f.blocks[i],
                BlockEmitConfig {
                    is_first: i == 0,
                    emit_block_comment: i > 0,
                    truncate_trailing: 0,
                    emit_terminator_comment: true,
                },
                lifts[i].as_ref(),
                &ctx,
            );
            i += 1;
        }
    }

    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        signature,
        body,
    }
}

/// Per-block emission knobs.
#[derive(Clone, Copy)]
struct BlockEmitConfig {
    /// True for the function's entry block; enables prologue lifting.
    is_first: bool,
    /// Emit a leading `// block: 0x…` comment.
    emit_block_comment: bool,
    /// How many trailing instructions to skip — consumed by an outer
    /// structural directive (e.g. an enclosing `Stmt::IfBranch`'s
    /// `cmp+jcc` head).
    truncate_trailing: usize,
    /// Emit a `// -> …` comment describing the block's terminator
    /// when no other lift consumed it. Suppressed inside `IfBranch`
    /// arms — the structural directive already conveys flow.
    emit_terminator_comment: bool,
}

/// Read-only context passed through emission.
struct EmitCtx<'a> {
    fn_addr_start: u64,
    fn_addr_end: u64,
    name_at: &'a HashMap<u64, String>,
    signature: Option<&'a Signature>,
}

/// Emit one block's worth of statements into `out`.
///
/// Order: optional `// block: 0x…` header, optional prologue lift on
/// the first block, per-instruction `@asm` lines (with call-target /
/// arg-spill annotations), then either the trailing-tail lift
/// (`Stmt::Return` / `Stmt::Epilogue`) or a terminator comment.
fn emit_block_stmts(
    out: &mut Vec<Stmt>,
    block: &BasicBlock<DecodedInsn>,
    cfg: BlockEmitConfig,
    lift: Option<&BlockTailLift>,
    ctx: &EmitCtx<'_>,
) {
    if cfg.emit_block_comment {
        out.push(Stmt::Comment(format!("block: 0x{:x}", block.addr.0)));
    }

    let prologue_consumed = if cfg.is_first {
        if let Some(lifted) = try_lift_prologue_pattern(&block.insns) {
            let bytes: Vec<u8> = block.insns[..lifted.insns_consumed]
                .iter()
                .flat_map(|insn| insn.original_bytes.iter().copied())
                .collect();
            out.push(Stmt::Prologue {
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

    let tail_consumed = match lift {
        Some(
            BlockTailLift::Return { insns_consumed, .. }
            | BlockTailLift::Epilogue { insns_consumed, .. }
            | BlockTailLift::ReturnExpr { insns_consumed, .. },
        ) => *insns_consumed,
        None => 0,
    };
    let asm_count = block
        .insns
        .len()
        .saturating_sub(tail_consumed + cfg.truncate_trailing);

    for insn in &block.insns[prologue_consumed..asm_count] {
        // Lift `mov [rbp+disp], REG_arg` into `@arg_spill(N, [bytes])`
        // when the function has a parameter at that arg index. The
        // directive subsumes both the `@asm` and the
        // `// arg N: name (type)` comment that the v0 decompiler used
        // to emit as separate statements.
        if let Some(arg_index) = arg_spill_lift_index(insn, ctx.signature) {
            out.push(Stmt::ArgSpill {
                arg_index,
                bytes: insn.original_bytes.clone(),
            });
            continue;
        }
        out.push(Stmt::asm(
            format_intel(&insn.iced),
            insn.original_bytes.clone(),
        ));
        if let Some(annotation) =
            call_annotation(insn, ctx.fn_addr_start, ctx.fn_addr_end, ctx.name_at)
        {
            out.push(Stmt::Comment(annotation));
        }
    }

    if cfg.truncate_trailing > 0 {
        // Trailing instructions are owned by the outer structural
        // directive (e.g. IfBranch); the caller emits them.
        return;
    }

    if let Some(lift) = lift {
        let lifted_bytes: Vec<u8> = block.insns[asm_count..]
            .iter()
            .flat_map(|insn| insn.original_bytes.iter().copied())
            .collect();
        match lift {
            BlockTailLift::Return { value, .. } => {
                out.push(Stmt::Return {
                    value: *value,
                    bytes: lifted_bytes,
                });
            }
            BlockTailLift::Epilogue { kind, .. } => {
                out.push(Stmt::Epilogue {
                    kind: (*kind).to_string(),
                    bytes: lifted_bytes,
                });
            }
            BlockTailLift::ReturnExpr { text, .. } => {
                out.push(Stmt::ReturnExpr {
                    text: text.clone(),
                    bytes: lifted_bytes,
                });
            }
        }
        return;
    }

    if cfg.emit_terminator_comment {
        match &block.terminator {
            Terminator::ConditionalBranch { taken, fallthrough } => {
                out.push(Stmt::Comment(format!(
                    "-> {{ taken: 0x{:x}, fallthrough: 0x{:x} }}",
                    taken.0, fallthrough.0
                )));
            }
            Terminator::UnconditionalBranch { target } => {
                out.push(Stmt::Comment(format!("-> 0x{:x}", target.0)));
            }
            Terminator::Return
            | Terminator::IndirectBranch
            | Terminator::InvalidOrUnreachable
            | Terminator::Fallthrough => {}
        }
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
    /// The whole block models into a value-producing expression that
    /// lands in EAX/RAX, and the block falls through to a recognised
    /// epilogue. The lift consumes every instruction in the block;
    /// `Stmt::ReturnExpr` carries the rendered text.
    ReturnExpr { insns_consumed: usize, text: String },
}

/// Per-block: which trailing instructions become a `Stmt::Return`,
/// `Stmt::Epilogue`, or `Stmt::ReturnExpr`?
///
/// Order of preference for non-tail blocks:
///
/// 1. `try_lift_return_via_jmp` — recognised `mov eax, IMM; jmp epilogue`
///    pattern. Folds into `Stmt::Return` with a literal value.
/// 2. `try_lift_value_block` — entire block models cleanly into a
///    value expression AND falls through directly to a recognised
///    epilogue tail. Folds the whole block into `Stmt::ReturnExpr`.
///
/// The tail block is unchanged — it tries `try_lift_return_pattern`
/// then `try_lift_epilogue_pattern`.
fn compute_block_tail_lifts(
    f: &Function<DecodedInsn>,
    signature: Option<&Signature>,
    slot_to_name: &HashMap<i64, String>,
    name_at: &HashMap<u64, String>,
) -> Vec<Option<BlockTailLift>> {
    let mut out: Vec<Option<BlockTailLift>> = (0..f.blocks.len()).map(|_| None).collect();
    let Some(last_idx) = f.blocks.len().checked_sub(1) else {
        return out;
    };
    let epilogue_addr = f.blocks[last_idx].addr.0;

    let return_lift_allowed =
        signature.is_some_and(|s| return_type_is_integer_like(&s.return_type));

    let tail_is_epilogue = try_lift_epilogue_pattern(&f.blocks[last_idx].insns).is_some();

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
            continue;
        }

        if return_lift_allowed {
            if let Some(lifted) = try_lift_return_via_jmp(&block.insns, epilogue_addr) {
                out[i] = Some(BlockTailLift::Return {
                    insns_consumed: lifted.insns_consumed,
                    value: lifted.value,
                });
                continue;
            }
        }

        // ReturnExpr: this block falls through directly to the
        // function's tail block, which itself is a recognised
        // epilogue. The block's instructions all model into an
        // expression that lives in EAX at fall-through.
        if return_lift_allowed && tail_is_epilogue {
            if let Terminator::Fallthrough = block.terminator {
                if i + 1 == last_idx {
                    if let Some(lifted) = try_lift_value_block(&block.insns, name_at) {
                        let render_ctx = ExprRenderCtx {
                            slot_to_name,
                            name_at,
                        };
                        out[i] = Some(BlockTailLift::ReturnExpr {
                            insns_consumed: lifted.insns_consumed,
                            text: lifted.expr.render(&render_ctx),
                        });
                    }
                }
            }
        }
    }
    out
}

/// One detected `cmp/test + jcc + then-block [+ else-block]` group
/// whose conditional block sits at a particular index in `f.blocks`.
struct IfElseGroup {
    /// Number of trailing instructions in the conditional block that
    /// the IfBranch head consumes (always 2 for v0).
    head_consumed: usize,
    cond_text: String,
    cond_bytes: Vec<u8>,
    /// True when the fallthrough block "exits" (returns or jumps past
    /// the taken block) — the taken block is then a real `else` arm.
    /// False when the fallthrough block falls through into the taken
    /// block — the taken block is the post-if join code, and the
    /// `if` has no `else` clause.
    has_else: bool,
}

/// Per-block: is this block the head of a recognised if/else group?
///
/// v0 detection rules (tight):
///
/// * The block ends with [`Terminator::ConditionalBranch`].
/// * The trailing two instructions match
///   [`try_lift_if_branch_head`] (i.e. a `cmp/test` followed by a
///   direct `jcc`).
/// * The next block in memory is at the conditional branch's
///   fallthrough address (the "then" arm).
/// * The block after that is at the jcc's taken target.
///
/// `has_else` then distinguishes the two flavours:
///
/// * **if-with-else** — the fallthrough block "exits past" the
///   taken block (returns, or unconditionally jumps to a later
///   address). The taken block is a real `else` arm; the lift owns
///   blocks `i, i+1, i+2`.
/// * **if-only** — the fallthrough block falls through directly into
///   the taken block. The taken block is the post-`if` join code;
///   the lift owns only `i, i+1` and `else_body` is `None`.
///
/// More general CFG patterns (multi-block branches, nested ifs in
/// either arm, fallthrough into a join block at non-adjacent index)
/// don't fire yet — they need data-flow / dominator analysis.
fn identify_if_else_groups(f: &Function<DecodedInsn>) -> Vec<Option<IfElseGroup>> {
    let mut groups: Vec<Option<IfElseGroup>> = (0..f.blocks.len()).map(|_| None).collect();
    if f.blocks.len() < 3 {
        return groups;
    }

    let limit = f.blocks.len() - 2;
    #[allow(clippy::needless_range_loop)]
    for i in 0..limit {
        let a = &f.blocks[i];
        let Terminator::ConditionalBranch { taken, fallthrough } = a.terminator else {
            continue;
        };
        let Some(head) = try_lift_if_branch_head(&a.insns) else {
            continue;
        };
        if head.jcc_target != taken.0 {
            continue;
        }
        if f.blocks[i + 1].addr != fallthrough || f.blocks[i + 2].addr != taken {
            continue;
        }
        let b = &f.blocks[i + 1];
        let c_addr = f.blocks[i + 2].addr.0;
        // `has_else` iff the fallthrough block exits past the taken
        // block — i.e. it doesn't simply fall through into C, and
        // doesn't unconditionally jump straight to C either.
        let has_else = match b.terminator {
            Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable => {
                true
            }
            Terminator::UnconditionalBranch { target } => target.0 != c_addr,
            Terminator::ConditionalBranch { .. } | Terminator::Fallthrough => false,
        };
        groups[i] = Some(IfElseGroup {
            head_consumed: head.insns_consumed,
            cond_text: head.cond_text,
            cond_bytes: head.cond_bytes,
            has_else,
        });
    }
    groups
}

/// Walk the entry block looking for arg-spill instructions
/// (`mov [rbp+disp], REG_arg`); record `disp -> param_name` for every
/// match where the function has a named parameter at that arg index.
///
/// The map is consumed by [`try_lift_value_block`] via [`ExprRenderCtx`]
/// so that loads from `[rbp-4]` render as the parameter name (e.g.
/// `v`) instead of the raw memory operand.
fn collect_slot_to_name(
    f: &Function<DecodedInsn>,
    signature: Option<&Signature>,
) -> HashMap<i64, String> {
    let mut out = HashMap::new();
    let Some(sig) = signature else {
        return out;
    };
    let Some(entry) = f.blocks.first() else {
        return out;
    };
    for insn in &entry.insns {
        let Some(idx) = arg_spill_index(&insn.iced) else {
            continue;
        };
        let Some(param) = sig.params.get(idx as usize) else {
            continue;
        };
        if param.name.is_empty() {
            continue;
        }
        // The arg-spill helper validates the destination is `[rbp+disp]`,
        // so memory_displacement64() is meaningful here. Cast u64 -> i64
        // round-trips two's-complement signed displacements.
        #[allow(clippy::cast_possible_wrap)]
        let disp = insn.iced.memory_displacement64() as i64;
        out.insert(disp, param.name.clone());
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
/// AND the function has a (named) parameter at that argument's index,
/// return the index — the caller emits a `Stmt::ArgSpill`.
///
/// The unnamed-parameter case still falls through to `@asm`, since
/// without a name the spill carries no extra semantic information
/// over the raw instruction.
fn arg_spill_lift_index(insn: &DecodedInsn, signature: Option<&Signature>) -> Option<u32> {
    let idx = arg_spill_index(&insn.iced)?;
    let sig = signature?;
    let param = sig.params.get(idx as usize)?;
    if param.name.is_empty() {
        return None;
    }
    Some(idx)
}

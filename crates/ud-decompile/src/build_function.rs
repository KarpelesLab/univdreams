//! Build the `FnDecl` AST node for a lifted function.

use std::collections::{HashMap, HashSet};

use ud_arch_x86::{
    arg_spill_index, detect_post_call_spill, direct_call_target, direct_lea_rip_target,
    direct_unconditional_branch_target, format_intel, identify_call_sites,
    try_lift_epilogue_pattern, try_lift_if_branch_head, try_lift_prologue_pattern,
    try_lift_return_pattern, try_lift_return_via_jmp, try_lift_value_block, ArgValue, CallSite,
    DecodedInsn, ExprRenderCtx,
};
use ud_ast::{FnDecl, Signature, Stmt, Type};
use ud_debug::DebugFunction;
use ud_ir::{BasicBlock, Function, Terminator};

use crate::data_lookup::DataLookup;

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
    data: &dyn DataLookup,
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
        data,
    };

    let mut i = 0;
    while i < f.blocks.len() {
        if let Some(group) = groups[i].as_ref() {
            // Conditional block A at i; arms span the index ranges
            // recorded on the group. The cmp+jcc head is consumed by
            // the IfBranch (truncate_trailing).
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

            let then_body = emit_arm_blocks(f, group.then_range.clone(), lifts.as_slice(), &ctx);
            let else_body = group
                .else_range
                .clone()
                .map(|er| emit_arm_blocks(f, er, lifts.as_slice(), &ctx));

            let advance = group.end_idx() - i;
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

/// Emit every block in `range` as the body of an `@if_branch` arm.
///
/// Each block is emitted with `is_first=false` (no prologue lifting
/// inside an arm), `emit_block_comment=false` for the first block of
/// the arm (the structural directive already conveys "this is where
/// the arm starts"), and `emit_block_comment=true` between blocks
/// so multi-block arms stay navigable. Terminator comments are
/// suppressed on the arm's last block — its exit target is the join
/// point implied by the `@if_branch`.
fn emit_arm_blocks(
    f: &Function<DecodedInsn>,
    range: std::ops::Range<usize>,
    lifts: &[Option<BlockTailLift>],
    ctx: &EmitCtx<'_>,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    let arm_start = range.start;
    let arm_last = range.end.saturating_sub(1);
    for j in range {
        emit_block_stmts(
            &mut out,
            &f.blocks[j],
            BlockEmitConfig {
                is_first: false,
                emit_block_comment: j != arm_start,
                truncate_trailing: 0,
                emit_terminator_comment: j != arm_last,
            },
            lifts[j].as_ref(),
            ctx,
        );
    }
    out
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
    data: &'a dyn DataLookup,
}

/// Emit one block's worth of statements into `out`.
///
/// Order: optional `// block: 0x…` header, optional prologue lift on
/// the first block, per-instruction `@asm` lines (with call-target /
/// arg-spill annotations), then either the trailing-tail lift
/// (`Stmt::Return` / `Stmt::Epilogue`) or a terminator comment.
#[allow(clippy::too_many_lines)]
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

    // Pre-pass: identify direct-call sites in this block so we can
    // fold their arg-setup + call into a single `@call` directive.
    // We only consider sites whose `call_idx` falls within the
    // emitted-as-asm range — anything past `asm_count` belongs to a
    // tail lift (`@return_expr` etc.) that already owns those bytes.
    let call_sites = identify_call_sites(&block.insns);
    let mut call_at: HashMap<usize, &CallSite> = HashMap::new();
    let mut consumed_by_call: HashSet<usize> = HashSet::new();
    let mut call_end_idx: HashMap<usize, usize> = HashMap::new();
    let mut post_call_spill: HashMap<usize, i64> = HashMap::new();
    for (site_idx, site) in call_sites.iter().enumerate() {
        if site.call_idx >= asm_count {
            continue;
        }
        let setup_start = site.setup_start.max(prologue_consumed);
        if setup_start > site.call_idx {
            continue;
        }
        call_at.insert(site.call_idx, site);
        for i in setup_start..site.call_idx {
            consumed_by_call.insert(i);
        }
        // Try to fold the post-call result-spill into this call's
        // bytes. Skip when the spill instructions would overlap the
        // next call's setup window — those belong to the next call.
        let mut end_idx = site.call_idx;
        if let Some(spill) = detect_post_call_spill(&block.insns, site.call_idx + 1) {
            let spill_end = site.call_idx + spill.insns_consumed;
            let next_setup_start = call_sites
                .get(site_idx + 1)
                .map_or(usize::MAX, |s| s.setup_start);
            if spill_end < next_setup_start && spill_end < asm_count {
                for i in (site.call_idx + 1)..=spill_end {
                    consumed_by_call.insert(i);
                }
                post_call_spill.insert(site.call_idx, spill.displacement);
                end_idx = spill_end;
            }
        }
        call_end_idx.insert(site.call_idx, end_idx);
    }

    for (offset, insn) in block.insns[prologue_consumed..asm_count].iter().enumerate() {
        let global_idx = prologue_consumed + offset;
        if consumed_by_call.contains(&global_idx) {
            continue;
        }
        if let Some(site) = call_at.get(&global_idx) {
            let setup_start = site.setup_start.max(prologue_consumed);
            let end_idx = *call_end_idx.get(&site.call_idx).unwrap_or(&site.call_idx);
            let spill_disp = post_call_spill.get(&site.call_idx).copied();
            let mut bytes = Vec::new();
            for j in setup_start..=end_idx {
                bytes.extend_from_slice(&block.insns[j].original_bytes);
            }
            let name = ctx
                .name_at
                .get(&site.call_target)
                .cloned()
                .unwrap_or_else(|| format!("sub_{:x}", site.call_target));
            let args = site
                .args
                .iter()
                .map(|a| render_arg_value(a, ctx))
                .collect::<Vec<_>>();
            out.push(Stmt::Call { name, args, bytes });
            if let Some(disp) = spill_disp {
                let dest = if disp < 0 {
                    format!("[rbp-0x{:x}]", disp.unsigned_abs())
                } else {
                    format!("[rbp+0x{disp:x}]")
                };
                out.push(Stmt::Comment(format!("result -> {dest}")));
            }
            continue;
        }

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
        if let Some(annotation) = lea_target_annotation(insn, ctx.data, ctx.name_at) {
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

/// One detected `cmp/test + jcc + then-arm [+ else-arm]` group whose
/// conditional block sits at a particular index in `f.blocks`.
///
/// Both arms can span multiple basic blocks. The arm ranges are
/// half-open block-index intervals.
struct IfElseGroup {
    /// Number of trailing instructions in the conditional block that
    /// the IfBranch head consumes (always 2 for v0).
    head_consumed: usize,
    cond_text: String,
    cond_bytes: Vec<u8>,
    /// Block-index range of the fallthrough (`@then`) arm. Always
    /// non-empty; starts at `a_idx + 1`.
    then_range: std::ops::Range<usize>,
    /// Block-index range of the taken (`@else`) arm. `None` for
    /// if-only patterns where the fallthrough arm falls through into
    /// the would-be-else block (which is then the post-if join, owned
    /// by the outer iteration).
    else_range: Option<std::ops::Range<usize>>,
}

impl IfElseGroup {
    /// One past the last block index this group owns.
    fn end_idx(&self) -> usize {
        match &self.else_range {
            Some(r) => r.end,
            None => self.then_range.end,
        }
    }
}

/// Per-block: is this block the head of a recognised if/else group?
///
/// v0 detection rules:
///
/// * The block ends with [`Terminator::ConditionalBranch`].
/// * The trailing two instructions match [`try_lift_if_branch_head`]
///   — a `cmp/test` followed by a direct `jcc`.
/// * The block immediately after in memory is at the conditional
///   branch's fallthrough address — start of the `@then` arm.
/// * The "then" arm is a maximal contiguous run of fall-through
///   blocks ending just before the jcc's taken-target block, OR
///   ending in a single non-fallthrough exit (`jmp join_addr` /
///   `Return` / `IndirectBranch` / `InvalidOrUnreachable`).
/// * For if-with-else: the `@else` arm starts at the jcc's
///   taken-target block and runs as a similar contiguous run ending
///   at the join.
/// * For if-only: the "then" arm falls through into the jcc target —
///   that target is then the post-if join, not a separate `else` arm.
///
/// Nested if-else inside an arm isn't detected structurally yet —
/// the inner conditional stays as `@asm` until a later iteration
/// adds recursive detection.
fn identify_if_else_groups(f: &Function<DecodedInsn>) -> Vec<Option<IfElseGroup>> {
    let mut groups: Vec<Option<IfElseGroup>> = (0..f.blocks.len()).map(|_| None).collect();
    if f.blocks.len() < 2 {
        return groups;
    }

    // addr → block-index map for jumping to jcc / join targets.
    let addr_to_idx: HashMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr.0, i))
        .collect();

    let mut next_a = 0usize;
    while next_a < f.blocks.len() {
        let a_idx = next_a;
        next_a += 1;
        let Some(group) = try_detect_if_else_at(f, a_idx, &addr_to_idx) else {
            continue;
        };
        let end = group.end_idx();
        groups[a_idx] = Some(group);
        next_a = end; // skip blocks the group owns; nested detection is future work
    }

    groups
}

/// Try to recognise an if/else group whose conditional block is at
/// `a_idx`. Returns `None` when the shape doesn't fit one of the
/// supported patterns described on [`identify_if_else_groups`].
fn try_detect_if_else_at(
    f: &Function<DecodedInsn>,
    a_idx: usize,
    addr_to_idx: &HashMap<u64, usize>,
) -> Option<IfElseGroup> {
    let a = &f.blocks[a_idx];
    let Terminator::ConditionalBranch { taken, fallthrough } = a.terminator else {
        return None;
    };
    let head = try_lift_if_branch_head(&a.insns)?;
    if head.jcc_target != taken.0 {
        return None;
    }

    let f_idx = a_idx + 1;
    if f.blocks.get(f_idx).map(|b| b.addr.0) != Some(fallthrough.0) {
        return None;
    }
    let &t_idx = addr_to_idx.get(&taken.0)?;
    if t_idx <= f_idx {
        return None;
    }

    // Walk the "then" arm: blocks `f_idx..t_idx`. Every block except
    // the last must fall through; the last either falls through (=
    // if-only) or has a clean exit (= if-with-else).
    if !is_clean_fallthrough_run(f, f_idx..t_idx - 1) {
        return None;
    }
    let then_last = &f.blocks[t_idx - 1];

    let then_exit_join = match then_last.terminator {
        Terminator::Fallthrough => {
            // Falls into f.blocks[t_idx] → if-only pattern.
            return Some(IfElseGroup {
                head_consumed: head.insns_consumed,
                cond_text: head.cond_text,
                cond_bytes: head.cond_bytes,
                then_range: f_idx..t_idx,
                else_range: None,
            });
        }
        Terminator::UnconditionalBranch { target } => Some(target.0),
        Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable => None,
        Terminator::ConditionalBranch { .. } => return None,
    };

    // Walk the "else" arm: blocks `t_idx..join_idx`. Same rule:
    // non-last blocks fall through; the last either falls through
    // to the join address or jumps directly to it.
    let join_idx = match then_exit_join {
        Some(j) => *addr_to_idx.get(&j)?,
        None => f.blocks.len(),
    };
    if join_idx <= t_idx {
        return None;
    }
    if !is_clean_fallthrough_run(f, t_idx..join_idx - 1) {
        return None;
    }
    let else_last = &f.blocks[join_idx - 1];
    let else_meets_join = match (then_exit_join, &else_last.terminator) {
        // Then-arm exits the function and the else-arm runs to the
        // function's tail. Accept any tail terminator.
        (None, _) if join_idx == f.blocks.len() => true,
        (Some(j), Terminator::Fallthrough) => f.blocks.get(join_idx).is_some_and(|b| b.addr.0 == j),
        (Some(j), Terminator::UnconditionalBranch { target }) => target.0 == j,
        (
            Some(_),
            Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable,
        ) => true,
        _ => false,
    };
    if !else_meets_join {
        return None;
    }

    Some(IfElseGroup {
        head_consumed: head.insns_consumed,
        cond_text: head.cond_text,
        cond_bytes: head.cond_bytes,
        then_range: f_idx..t_idx,
        else_range: Some(t_idx..join_idx),
    })
}

/// Every block index in `range` must have `Terminator::Fallthrough`.
/// An empty range trivially satisfies this.
fn is_clean_fallthrough_run(f: &Function<DecodedInsn>, range: std::ops::Range<usize>) -> bool {
    range
        .into_iter()
        .all(|i| matches!(f.blocks[i].terminator, Terminator::Fallthrough))
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

/// Render an [`ArgValue`] into a human-readable string for the
/// `@call(name, [args], [bytes])` directive.
///
/// This is intentionally low-fidelity — the strings are
/// informational; the pinned bytes on the `Stmt::Call` are
/// authoritative for round-trip. Renderings prioritise readability
/// over preserving operand semantics: a `lea` to a function address
/// renders as `&function`, a `lea` to a `.rodata` C-string renders
/// as the string literal itself.
fn render_arg_value(value: &ArgValue, ctx: &EmitCtx<'_>) -> String {
    match value {
        ArgValue::Const(n) => n.to_string(),
        ArgValue::Lea { addr } => {
            if let Some(name) = ctx.name_at.get(addr) {
                return format!("&{name}");
            }
            if let Some((section_name, data, off)) = ctx.data.section_at(*addr) {
                if is_string_data_section(section_name) {
                    if let Some(s) = read_cstring_at(data, off) {
                        return format!("{:?}", shorten_for_display(s));
                    }
                }
                if !section_name.is_empty() {
                    return format!("{section_name} @ 0x{addr:x}");
                }
            }
            format!("&0x{addr:x}")
        }
        ArgValue::GlobalLoad { addr } => {
            if let Some(name) = ctx.name_at.get(addr) {
                return format!("*{name}");
            }
            if let Some((section_name, _, _)) = ctx.data.section_at(*addr) {
                if !section_name.is_empty() {
                    return format!("*{section_name} @ 0x{addr:x}");
                }
            }
            format!("*0x{addr:x}")
        }
        ArgValue::StackLoad { displacement } => {
            if *displacement < 0 {
                format!("[rbp-0x{:x}]", displacement.unsigned_abs())
            } else {
                format!("[rbp+0x{displacement:x}]")
            }
        }
        ArgValue::PrevCallResult => "result".into(),
    }
}

/// If `insn` is a `lea reg, [rip+disp]` whose target lives in a
/// recognisable data section, return a comment string surfacing
/// what's at that address. Goal: turn the cryptic
/// `lea rax, [2015h]` into a navigable hint like
/// `// = .rodata @ 0x2015 ("Hello from test2.c!")`.
///
/// Resolution rules:
///
/// * If the target address belongs to a known function (in `name_at`),
///   render as `// = &<function_name>` — typical for "load the
///   address of a function and indirect-call it" idioms.
/// * Else if the target falls inside a section whose name we
///   recognise as read-only data (`.rodata`, `.data.rel.ro`,
///   `.eh_frame`, `.eh_frame_hdr`), and the bytes there are a valid
///   NUL-terminated UTF-8 C-string of length ≥ 1, render as
///   `// = .rodata @ 0xADDR ("string")`.
/// * Else if the target is just inside *some* section, render as
///   `// = .secname @ 0xADDR`.
/// * Otherwise return None — the lea probably loads computed state we
///   can't surface with a single string.
fn lea_target_annotation(
    insn: &DecodedInsn,
    data: &dyn DataLookup,
    name_at: &HashMap<u64, String>,
) -> Option<String> {
    let addr = direct_lea_rip_target(&insn.iced)?;
    if let Some(name) = name_at.get(&addr) {
        return Some(format!("= &{name}"));
    }
    let (section_name, section_data, sec_offset) = data.section_at(addr)?;
    if is_string_data_section(section_name) {
        if let Some(text) = read_cstring_at(section_data, sec_offset) {
            return Some(format!(
                "= {section_name} @ 0x{addr:x} ({:?})",
                shorten_for_display(text)
            ));
        }
    }
    if section_name.is_empty() {
        return Some(format!("= 0x{addr:x}"));
    }
    Some(format!("= {section_name} @ 0x{addr:x}"))
}

fn is_string_data_section(name: &str) -> bool {
    matches!(
        name,
        ".rodata" | ".rodata.str1.1" | ".rodata.str1.8" | ".data.rel.ro" | ".data.rel.ro.local"
    )
}

/// Read a NUL-terminated UTF-8 string at `offset` in `data`. Returns
/// `None` for empty strings, missing NUL terminators, or non-UTF-8
/// content (typical of pointer/relocation tables that happen to live
/// in `.data.rel.ro`).
fn read_cstring_at(data: &[u8], offset: usize) -> Option<&str> {
    let tail = data.get(offset..)?;
    let nul = tail.iter().position(|&b| b == 0)?;
    if nul == 0 {
        return None;
    }
    std::str::from_utf8(&tail[..nul]).ok()
}

/// Truncate strings longer than 60 chars in the lea-annotation
/// comment. Long strings get a trailing `…`.
fn shorten_for_display(s: &str) -> String {
    const MAX_CHARS: usize = 60;
    if s.chars().count() <= MAX_CHARS {
        return s.to_string();
    }
    let truncated: String = s.chars().take(MAX_CHARS).collect();
    format!("{truncated}…")
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

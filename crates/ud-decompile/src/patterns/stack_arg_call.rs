//! Pattern: stack-passed-argument call.
//!
//! The canonical i386 cdecl / stdcall calling convention pushes
//! every argument onto the stack right-to-left, then issues the
//! `call`:
//!
//! ```text
//! push arg_n          ; rightmost first
//! …
//! push arg_1
//! call F              ; direct or `call dword ptr [import]`
//! [add esp, k]        ; cdecl caller-cleanup; absent for stdcall
//! ```
//!
//! The pattern folds the push chain + the call into a single
//! `Stmt::Call`. With direct calls and a name in the function
//! map, this produces `F(arg_1, …, arg_n)`; with indirect calls
//! through an import slot, the function name becomes the import
//! address expression. Either way the rendered call reads as code,
//! not as raw push/pop opcodes.

use ud_arch_x86::{
    detect_post_call_spill, format_intel, CodeSize, DecodedInsn, FlowControl, Mnemonic,
};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct StackArgCall;

impl Pattern for StackArgCall {
    fn name(&self) -> &'static str {
        "stack_arg_call"
    }

    #[allow(clippy::too_many_lines)]
    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        // i386 only. x86-64 SysV passes args in registers and has a
        // dedicated analyzer (ud_arch_x86::call_site) feeding the
        // inline `call_at` map; lifting bare calls here would
        // override its richer output.
        let first = insns.get(start)?;
        if first.iced.code_size() != CodeSize::Code32 {
            return None;
        }

        // Scan forward from `start` accumulating `push` instructions
        // until we hit a `call`. Anything else aborts the window.
        let mut args: Vec<String> = Vec::new();
        let mut bytes: Vec<u8> = Vec::new();
        let mut i = start;
        while i < insns.len() {
            let ins = &insns[i];
            if ins.iced.mnemonic() == Mnemonic::Push {
                let sp = ctx.sp_delta_at.get(&ins.iced.ip()).copied();
                args.push(render_push_arg(ins, sp));
                bytes.extend_from_slice(&ins.original_bytes);
                i += 1;
                continue;
            }
            let fc = ins.iced.flow_control();
            // Direct/indirect call: standard `push args; call F`.
            let is_call = matches!(fc, FlowControl::Call | FlowControl::IndirectCall);
            // Tail call: `push args; jmp F`. The `jmp` consumes the
            // function-return stack slot so F returns directly to our
            // caller — semantically the same as `return F(args)`.
            let is_tail_jmp = matches!(
                fc,
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
            );
            if is_call || is_tail_jmp {
                // A bare call (no preceding push) gets handled by
                // the existing call_site analyzer's `call_at`
                // path, which coordinates with consumed_by_call.
                // Lifting it here would steal an arg-setup mov the
                // analyzer had already absorbed and lose those
                // bytes. A bare jmp likewise isn't a "tail call" in
                // any useful sense — let the @asm form carry it.
                if args.is_empty() {
                    return None;
                }
                // For tail-jmps we classify the destination so the
                // call statement reads correctly:
                //   * known function entry  →  `tail_<fn>(args)`
                //   * intra-function label  →  `goto_<addr>(args)`
                //     (switch-dispatch tails, shared epilogue stubs)
                //   * indirect or off-fn    →  `tail_<expr>(args)`
                let tail_prefix: Option<String> = if is_tail_jmp {
                    let target = ins.iced.near_branch_target();
                    let in_known_fn = target != 0 && ctx.name_at.contains_key(&target);
                    let in_local_range =
                        target != 0 && target >= ctx.fn_addr_start && target < ctx.fn_addr_end;
                    if in_known_fn {
                        Some("tail_".to_string())
                    } else if in_local_range {
                        Some("goto_".to_string())
                    } else {
                        Some("tail_".to_string())
                    }
                } else {
                    None
                };
                // Determine direct-call target (only direct `call
                // rel32` qualifies; indirect calls and tail-jmps
                // keep their bytes pinned). A target of 0 means
                // iced couldn't resolve the destination — usually
                // because the bytes are data interpreted as code;
                // we don't regenerate those.
                let direct_call_target = if is_call && !is_tail_jmp {
                    ud_arch_x86::direct_call_target(&ins.iced).filter(|t| *t != 0)
                } else {
                    None
                };
                if direct_call_target.is_none() {
                    bytes.extend_from_slice(&ins.original_bytes);
                }
                // The post-call result spill (`mov [ebp+N], eax`)
                // is normally folded into the inline `call_at`'s
                // bytes. When we preempt that path we have to
                // absorb the spill ourselves; otherwise its bytes
                // get skipped via `consumed_by_call` with nothing
                // emitting them. Tail-jmps don't return so they
                // don't get spilled.
                let mut consumed_extra = 0usize;
                let mut spill_comment: Option<String> = None;
                // Only fold the call when there's no post-call
                // spill — see the matching cautious branch in
                // `call_at`. If a spill rides along we must keep
                // the call inline so the spill follows.
                let mut direct_target = direct_call_target;
                if is_call {
                    if let Some(spill) = detect_post_call_spill(insns, i + 1) {
                        // Restore the call bytes since we're not
                        // going to regenerate them.
                        if direct_target.is_some() {
                            bytes.extend_from_slice(&ins.original_bytes);
                            direct_target = None;
                        }
                        for j in 0..spill.insns_consumed {
                            if let Some(s) = insns.get(i + 1 + j) {
                                bytes.extend_from_slice(&s.original_bytes);
                            }
                        }
                        consumed_extra = spill.insns_consumed;
                        let dest = if spill.displacement < 0 {
                            format!("[rbp-0x{:x}]", spill.displacement.unsigned_abs())
                        } else {
                            format!("[rbp+0x{:x}]", spill.displacement)
                        };
                        spill_comment = Some(format!("result -> {dest}"));
                    }
                }
                // Args were pushed right-to-left; reverse for
                // natural left-to-right reading order.
                args.reverse();
                let raw_name = render_call_target(ins, ctx);
                // Prefix tail-call / goto names so they read distinctly
                // from a regular call, and so the parser can route
                // `tail_X(args)` / `goto_X(args)` through the normal
                // call-statement path. Skip the prefix when the
                // target name starts with `[` (indirect-through-
                // memory): prefixing yields `tail_[…]` which the
                // parser can't disambiguate from an assignment, and
                // the encoded bytes already distinguish call from
                // jmp anyway.
                let name = match tail_prefix {
                    Some(prefix) if !raw_name.starts_with('[') => {
                        format!("{prefix}{raw_name}")
                    }
                    _ => raw_name,
                };
                let consumed = (i + 1 - start) + consumed_extra;
                let mut stmts: Vec<Stmt> = vec![Stmt::Call {
                    name,
                    args,
                    bytes,
                    direct_target,
                }];
                if let Some(c) = spill_comment {
                    stmts.push(Stmt::Comment(c));
                }
                return Some(Candidate {
                    pattern: self.name(),
                    start,
                    consumed,
                    priority: 200,
                    stmts,
                });
            }
            return None;
        }
        // Fell off the end of `insns` with pushes still pending.
        // This shows up on i386 stdcall functions whose push chain
        // crosses a basic-block boundary (the CFG split the
        // chain because the destination block is also reachable
        // by an intra-function jmp that arrived having already
        // pushed the same args). Both paths push the same number
        // of args; the call lives in the next block.
        //
        // Emit a synthetic `to_<next_ip>(arg, …)` call so the
        // args surface structurally and the reader can follow
        // the destination by label name (`label_22b1:` for
        // `to_22b1(...)`). The bytes round-trip exactly — it's
        // only a rendering tweak.
        if !args.is_empty() && args.len() >= 2 {
            args.reverse();
            let last_ip = insns
                .last()
                .map(|ins| ins.iced.next_ip())
                .unwrap_or_default();
            let name = if last_ip != 0 {
                format!("to_{last_ip:x}")
            } else {
                "pushed_args".into()
            };
            return Some(Candidate {
                pattern: self.name(),
                start,
                consumed: i - start,
                priority: 200,
                stmts: vec![Stmt::Call {
                    name,
                    args,
                    bytes,
                    direct_target: None,
                }],
            });
        }
        None
    }
}

/// Render a `push <operand>` instruction's operand as a string.
/// `push 5` → `"5"`, `push esi` → `"esi"`, `push [ebp+8]` →
/// `"arg_8"` (renamed via [`ud_arch_x86::rename_operand_in_ctx`]
/// for stack-frame slots; raw operand text otherwise). We use the
/// iced formatter and strip the leading `"push "` so we get just
/// the operand. The SP-delta context lets `push [esp+disp]` also
/// rename when the function doesn't carry an EBP frame.
fn render_push_arg(insn: &DecodedInsn, sp_delta: Option<i64>) -> String {
    let full = format_intel(&insn.iced);
    let raw = full
        .strip_prefix("push ")
        .map_or_else(|| full.clone(), str::to_string);
    // Trim iced's verbose `dword ptr ` / `qword ptr ` size hint
    // off memory-operand pushes. On x86, `push` always pushes one
    // operand-size word, so the hint is redundant for the reader.
    let trimmed = raw
        .trim_start_matches("dword ptr ")
        .trim_start_matches("qword ptr ")
        .trim_start_matches("word ptr ")
        .to_string();
    ud_arch_x86::rename_operand_in_ctx(&trimmed, sp_delta)
}

/// Pick a name for a call target. Handles four cases:
///   * direct `call rel32` to a known function → its `name_at[target]`
///   * direct `call rel32` to an unnamed address → `sub_<hex>`
///   * direct `jmp rel32` (tail-jmp or intra-fn goto) → `name_at[target]`
///     when known, else the bare hex target so callers can stitch a
///     `tail_<hex>` / `goto_<hex>` prefix in front of it
///   * indirect `call/jmp reg` / `[mem]` → the formatted operand text
///     (`eax`, `[1C2010BCh]`, …) so the reader sees what address the
///     transfer routes through
fn render_call_target(insn: &DecodedInsn, ctx: &PatternCtx) -> String {
    if let Some(target) = ud_arch_x86::direct_call_target(&insn.iced) {
        if let Some(name) = ctx.name_at.get(&target) {
            return name.clone();
        }
        return format!("sub_{target:x}");
    }
    if let Some(target) = ud_arch_x86::direct_unconditional_branch_target(&insn.iced) {
        if let Some(name) = ctx.name_at.get(&target) {
            return name.clone();
        }
        return format!("{target:x}");
    }
    // Indirect call or jmp. Use the formatted operand.
    let full = format_intel(&insn.iced);
    let stripped = full
        .strip_prefix("call ")
        .or_else(|| full.strip_prefix("jmp "))
        .unwrap_or(&full);
    // `… dword ptr [...]` is verbose; trim the segment-size hint.
    let operand = stripped
        .trim_start_matches("dword ptr ")
        .trim_start_matches("qword ptr ")
        .trim_start_matches("near ptr ")
        .to_string();
    // If the indirect target is `[ABSOLUTE_VA]`, try the name map
    // — for PE binaries that map carries IAT-slot → import name
    // mappings injected by the decompile pipeline. A match here
    // turns `[1C201030h](...)` into `HeapAlloc(...)`.
    if let Some(name) = lookup_indirect_absolute(&operand, ctx) {
        return name;
    }
    operand
}

/// Parse `[ABS_VA_HEX]` operand text and look up the absolute VA
/// in [`PatternCtx::name_at`]. Used to resolve PE indirect calls
/// through IAT slots to the imported function's name.
///
/// Accepts the Intel-syntax hex shapes iced produces:
/// `[1C201030h]` (trailing `h`) and `[0x1C201030]` (C-style
/// prefix). Returns `None` for any other operand form (register
/// indirect, `[reg+disp]`, etc.) since those don't carry a
/// resolvable absolute address.
fn lookup_indirect_absolute(operand: &str, ctx: &PatternCtx) -> Option<String> {
    let inner = operand.strip_prefix('[')?.strip_suffix(']')?;
    if inner.contains('+') || inner.contains('-') || inner.contains('*') {
        return None;
    }
    let hex = if let Some(s) = inner.strip_suffix('h') {
        s
    } else {
        inner
            .strip_prefix("0x")
            .or_else(|| inner.strip_prefix("0X"))?
    };
    let va = u64::from_str_radix(hex, 16).ok()?;
    ctx.name_at.get(&va).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use ud_arch_x86::{decode, Bitness};

    fn ctx_empty() -> (HashMap<u64, String>, PatternCtx<'static>) {
        let map: HashMap<u64, String> = HashMap::new();
        // Static lifetime hack via leaked Box.
        let leaked: &'static HashMap<u64, String> = Box::leak(Box::new(map));
        let leaked_sp: &'static HashMap<u64, i64> = Box::leak(Box::new(HashMap::new()));
        (
            HashMap::new(),
            PatternCtx {
                fn_addr_start: 0,
                fn_addr_end: u64::MAX,
                name_at: leaked,
                sp_delta_at: leaked_sp,
            },
        )
    }

    /// `push 5; push 7; call 0x4` should lift into one Stmt::Call.
    #[test]
    fn lifts_two_push_then_call() {
        // push 5       0x6a 0x05
        // push 7       0x6a 0x07
        // call rel32 0 0xe8 0xf6 0xff 0xff 0xff   (target = 0x4 + 5 - 10 = 0xfffffff7? — use rel32)
        // simpler: call to a fixed forward address; iced computes target from IP+rel.
        // Encode: bytes = 6a 05, 6a 07, e8 00 00 00 00 (call to ip+5+0)
        let bytes = [0x6a, 0x05, 0x6a, 0x07, 0xe8, 0x00, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let (_, ctx) = ctx_empty();
        let cand = StackArgCall.tentative(&ctx, &insns, 0).expect("match");
        assert_eq!(cand.consumed, 3);
        assert!(matches!(cand.stmts.first(), Some(Stmt::Call { .. })));
        if let Some(Stmt::Call { args, .. }) = cand.stmts.first() {
            // Args reversed: arg_1 = first push from the left,
            // matching natural source order.
            assert_eq!(args, &["7", "5"]);
        }
    }

    /// Reproduces a 13-push-then-call sequence observed in
    /// msmpeg4 (stdcall i386), where the lifter was leaving every
    /// push on `@asm` instead of folding them into the call's
    /// arg list.
    #[test]
    fn lifts_thirteen_push_then_call() {
        let mut bytes: Vec<u8> = Vec::new();
        for disp in [
            0x20u8, 0x1c, 0x18, 0x14, 0x10, 0x0c, 0x30, 0x2c, 0x28, 0x24, 0x08, 0x04,
        ] {
            bytes.extend_from_slice(&[0xff, 0x70, disp]);
        }
        bytes.extend_from_slice(&[0xff, 0x30]); // push dword ptr [eax]
        bytes.extend_from_slice(&[0xff, 0x75, 0x08]); // push dword ptr [ebp+8]
        bytes.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]); // call rel32
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let (_, ctx) = ctx_empty();
        let cand = StackArgCall
            .tentative(&ctx, &insns, 0)
            .expect("14-push then call must lift");
        let Stmt::Call { args, .. } = &cand.stmts[0] else {
            panic!("expected Call stmt");
        };
        assert_eq!(args.len(), 14, "should fold every push as an arg");
    }

    /// A lone `call` with no preceding pushes should not match —
    /// zero-arg calls are handled by other paths.
    #[test]
    fn skips_call_with_no_pushes() {
        let bytes = [0xe8, 0x00, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits32, &bytes, 0x1000).unwrap();
        let (_, ctx) = ctx_empty();
        assert!(StackArgCall.tentative(&ctx, &insns, 0).is_none());
    }
}

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
                args.push(render_push_arg(ins));
                bytes.extend_from_slice(&ins.original_bytes);
                i += 1;
                continue;
            }
            // Saw the call. Must be a Call flow-control insn.
            if ins.iced.flow_control() == FlowControl::Call {
                // A bare call (no preceding push) gets handled by
                // the existing call_site analyzer's `call_at`
                // path, which coordinates with consumed_by_call.
                // Lifting it here would steal an arg-setup mov the
                // analyzer had already absorbed and lose those
                // bytes.
                if args.is_empty() {
                    return None;
                }
                bytes.extend_from_slice(&ins.original_bytes);
                // The post-call result spill (`mov [ebp+N], eax`)
                // is normally folded into the inline `call_at`'s
                // bytes. When we preempt that path we have to
                // absorb the spill ourselves; otherwise its bytes
                // get skipped via `consumed_by_call` with nothing
                // emitting them.
                let mut consumed_extra = 0usize;
                let mut spill_comment: Option<String> = None;
                if let Some(spill) = detect_post_call_spill(insns, i + 1) {
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
                // Args were pushed right-to-left; reverse for
                // natural left-to-right reading order.
                args.reverse();
                let name = render_call_target(ins, ctx);
                let consumed = (i + 1 - start) + consumed_extra;
                let mut stmts: Vec<Stmt> = vec![Stmt::Call { name, args, bytes }];
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
        None
    }
}

/// Render a `push <operand>` instruction's operand as a string.
/// `push 5` → `"5"`, `push esi` → `"esi"`, `push [ebp+8]` →
/// `"[ebp+8]"`. We use the iced formatter and strip the leading
/// `"push "` so we get just the operand.
fn render_push_arg(insn: &DecodedInsn) -> String {
    let full = format_intel(&insn.iced);
    full.strip_prefix("push ")
        .map_or(full.clone(), str::to_string)
}

/// Pick a name for a call target. Direct calls land on
/// `name_at[target]` if known, else `sub_<hex>`. Indirect calls
/// use the formatted operand text (e.g. `[1C2010BCh]`) so the
/// reader sees what address the call routes through.
fn render_call_target(insn: &DecodedInsn, ctx: &PatternCtx) -> String {
    if let Some(target) = ud_arch_x86::direct_call_target(&insn.iced) {
        if let Some(name) = ctx.name_at.get(&target) {
            return name.clone();
        }
        return format!("sub_{target:x}");
    }
    // Indirect call. Use the formatted operand.
    let full = format_intel(&insn.iced);
    let stripped = full.strip_prefix("call ").unwrap_or(&full);
    // `call dword ptr [...]` is verbose; trim the segment-size hint.
    stripped
        .trim_start_matches("dword ptr ")
        .trim_start_matches("qword ptr ")
        .trim_start_matches("near ptr ")
        .to_string()
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
        (
            HashMap::new(),
            PatternCtx {
                fn_addr_start: 0,
                fn_addr_end: u64::MAX,
                name_at: leaked,
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

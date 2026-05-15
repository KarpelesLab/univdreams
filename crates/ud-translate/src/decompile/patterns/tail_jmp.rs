//! Pattern: tail-`jmp` through an import slot.
//!
//! Windows DLLs (and many ELF objects) contain "thunk" functions
//! whose entire body is a single indirect jump through an import
//! pointer:
//!
//! ```text
//! jmp dword ptr [imp__Foo]
//! ```
//!
//! The compiler emits one of these for each imported function so
//! call sites can issue a direct `call` to the local thunk instead
//! of dereferencing the import slot every time. Surfacing the
//! shape as a structured directive makes thunks readable at a
//! glance — they read as `tail_call <addr>` rather than one bare
//! `@asm("jmp …")` floating alone.

use ud_arch_x86::{direct_unconditional_branch_target, format_intel, DecodedInsn, FlowControl};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct TailJmp;

impl Pattern for TailJmp {
    fn name(&self) -> &'static str {
        "tail_jmp"
    }

    fn tentative(
        &self,
        ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        let fc = ins.iced.flow_control();
        let next_addr = ins.iced.ip().wrapping_add(ins.original_bytes.len() as u64);
        let is_function_tail = next_addr >= ctx.fn_addr_end;
        // Two shapes count as a tail call:
        //   * indirect jump (`jmp dword ptr [...]`) at function tail —
        //     a thunk through an import slot.
        //   * direct jump (`jmp rel32`) at function tail whose target
        //     is OUTSIDE the current function (a tail call to another
        //     function). Direct jumps inside the function are intra-
        //     function loops — those route through goto/label lifting.
        match fc {
            FlowControl::IndirectBranch => {
                if !is_function_tail {
                    return None;
                }
                let formatted = format_intel(&ins.iced);
                let target = formatted
                    .strip_prefix("jmp ")
                    .unwrap_or(&formatted)
                    .trim_start_matches("dword ptr ")
                    .trim_start_matches("qword ptr ")
                    .trim_start_matches("near ptr ")
                    .to_string();
                Some(Candidate {
                    pattern: self.name(),
                    start,
                    consumed: 1,
                    priority: 150,
                    stmts: vec![Stmt::Call {
                        name: "tail_call".into(),
                        args: vec![target],
                        bytes: ins.original_bytes.clone(),
                        direct_target: None,
                    }],
                })
            }
            FlowControl::UnconditionalBranch => {
                let target = direct_unconditional_branch_target(&ins.iced)?;
                // Reject intra-function jumps — they're loops or
                // forward gotos handled by the goto/label lifter.
                if target >= ctx.fn_addr_start && target < ctx.fn_addr_end {
                    return None;
                }
                let _ = is_function_tail;
                // Out-of-function direct jmp: this is a tail call.
                // Name the target. Known function → its name with a
                // `tail_` prefix so it reads as a tail call rather
                // than an ordinary call. Unknown → `tail_call(addr)`.
                let (name, args) = if let Some(callee) = ctx.name_at.get(&target) {
                    (format!("tail_{callee}"), Vec::new())
                } else {
                    ("tail_call".into(), vec![format!("0x{target:x}")])
                };
                Some(Candidate {
                    pattern: self.name(),
                    start,
                    consumed: 1,
                    priority: 150,
                    stmts: vec![Stmt::Call {
                        name,
                        args,
                        bytes: ins.original_bytes.clone(),
                        direct_target: None,
                    }],
                })
            }
            _ => None,
        }
    }
}

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

use ud_arch_x86::{format_intel, DecodedInsn, FlowControl};
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
        // Only fire for indirect jumps — direct jumps are handled
        // elsewhere (and most direct jmps are intra-function loops,
        // not tail calls).
        if fc != FlowControl::IndirectBranch {
            return None;
        }
        // The thunk pattern is the *whole* function: just this one
        // jmp. We can't see "function boundaries" from a flat insn
        // list, but we can confirm "this is the first and last
        // instruction" via the function-address window.
        let next_addr = ins.iced.ip().wrapping_add(ins.original_bytes.len() as u64);
        let is_function_tail = next_addr >= ctx.fn_addr_end;
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
                // The `@asm`-bound bytes survive a round-trip via
                // `Stmt::Call`'s pinned bytes.
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
}

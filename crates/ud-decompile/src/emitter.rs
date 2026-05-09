//! Emit a single function as `.ud` text.
//!
//! v0 layout:
//!
//! ```text
//! @addr(0x401050)
//! fn name() {
//!     @asm("endbr64")
//!     @asm("push rbp")
//!     // … one @asm per decoded instruction, in original order
//!     @asm("ret")
//! }
//! ```
//!
//! Block boundaries from the lifted CFG are surfaced as `// block:
//! 0x...` comments so a human reader sees the structure without us
//! committing yet to a `@block { ... }` syntax.

use std::fmt::Write as _;

use ud_arch_x86::{format_intel, DecodedInsn};
use ud_ir::{Function, Terminator};

/// Format a lifted function as `.ud` text, including the `@addr`
/// directive and trailing newline.
#[must_use]
pub fn emit_function(f: &Function<DecodedInsn>) -> String {
    let mut out = String::new();

    writeln!(out, "@addr(0x{:x})", f.addr.0).expect("write");
    writeln!(out, "fn {}() {{", f.name).expect("write");

    for (i, block) in f.blocks.iter().enumerate() {
        // Emit a divider comment between blocks. The first block's
        // address equals the function entry, so we omit the comment
        // before it to reduce noise.
        if i > 0 {
            writeln!(out, "    // block: 0x{:x}", block.addr.0).expect("write");
        }
        for insn in &block.insns {
            let text = format_intel(&insn.iced);
            writeln!(out, "    @asm({})", quote_ud_string(&text)).expect("write");
        }
        // Terminator hint as a trailing comment when the terminator is
        // direct; indirect/return need no annotation since the asm
        // text already says so.
        match &block.terminator {
            Terminator::ConditionalBranch { taken, fallthrough } => {
                writeln!(
                    out,
                    "    // -> {{ taken: 0x{:x}, fallthrough: 0x{:x} }}",
                    taken.0, fallthrough.0
                )
                .expect("write");
            }
            Terminator::UnconditionalBranch { target } => {
                writeln!(out, "    // -> 0x{:x}", target.0).expect("write");
            }
            Terminator::Return
            | Terminator::IndirectBranch
            | Terminator::InvalidOrUnreachable
            | Terminator::Fallthrough => {}
        }
    }

    out.push_str("}\n");
    out
}

/// Quote a string for use inside an `@asm("…")` directive. Escapes the
/// few characters that would break the parser: backslash and
/// double-quote.
fn quote_ud_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_handles_special_characters() {
        assert_eq!(quote_ud_string("mov rax, rbx"), r#""mov rax, rbx""#);
        assert_eq!(quote_ud_string(r#"a "b" c"#), r#""a \"b\" c""#);
        assert_eq!(quote_ud_string(r"\n"), r#""\\n""#);
    }
}

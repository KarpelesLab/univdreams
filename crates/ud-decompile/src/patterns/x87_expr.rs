//! Pattern: lift x87 floating-point ops to assignment-form.
//!
//! x87 instructions use a stack model (`st(0)` = top, `st(1)` =
//! next, etc.) with implicit operand for many ops. iced renders
//! the top-of-stack as `st`. We lift each instruction's local
//! effect without a full stack-model:
//!
//! * `fild st, [mem]`   → `st0 = (f64) [mem]`  (push)
//! * `fld  st, [mem]`   → `st0 = [mem]`         (push)
//! * `fst  [mem], st`   → `[mem] = st0`
//! * `fstp [mem], st`   → `[mem] = st0` (then pop)
//! * `fistp [mem], st`  → `[mem] = (i64) st0` (then pop)
//! * `fadd  st, [mem]`  → `st0 = st0 + [mem]`
//! * `fsub  st, [mem]`  → `st0 = st0 - [mem]`
//! * `fmul  st, [mem]`  → `st0 = st0 * [mem]`
//! * `fdiv  st, [mem]`  → `st0 = st0 / [mem]`
//! * `faddp / fmulp / fsubp / fdivp`           → register-form
//!   arithmetic that pops a stack slot afterwards.
//!
//! The stack semantics ("then pop") aren't reflected in the
//! rendered C-like form — that would require a real stack model
//! per instruction sequence — but the per-instruction effect
//! reads as plain C arithmetic, which is what we want.

use ud_arch_x86::{format_intel, DecodedInsn, Mnemonic};
use ud_ast::Stmt;

use super::{Candidate, Pattern, PatternCtx};

pub struct X87Expr;

impl Pattern for X87Expr {
    fn name(&self) -> &'static str {
        "x87_expr"
    }

    fn tentative(
        &self,
        _ctx: &PatternCtx,
        insns: &[DecodedInsn],
        start: usize,
    ) -> Option<Candidate> {
        let ins = insns.get(start)?;
        let m = ins.iced.mnemonic();
        let shape = classify(m)?;
        let full = format_intel(&ins.iced);
        let rest = full.strip_prefix(shape.prefix)?;
        let (lhs_raw, rhs_raw) = split_two_ops(rest)?;
        let (dst, src) = match shape.kind {
            X87Kind::Load => ("st0".to_string(), wrap_cast(shape.cast, &rhs_raw)),
            X87Kind::Store => (lhs_raw.clone(), wrap_cast(shape.cast, "st0")),
            X87Kind::Binary(op) => {
                if lhs_raw == "st" {
                    ("st0".to_string(), format!("st0 {op} {rhs_raw}"))
                } else if rhs_raw == "st" {
                    (lhs_raw.clone(), format!("{lhs_raw} {op} st0"))
                } else {
                    (lhs_raw.clone(), format!("{lhs_raw} {op} {rhs_raw}"))
                }
            }
        };
        Some(Candidate {
            pattern: self.name(),
            start,
            consumed: 1,
            // Below mov (50) — let the GP `mov` win when both
            // could match. Above bare @asm fallback.
            priority: 28,
            stmts: vec![Stmt::Move {
                dst,
                src,
                bytes: ins.original_bytes.clone(),
            }],
        })
    }
}

struct X87Shape {
    prefix: &'static str,
    kind: X87Kind,
    /// Optional C-style cast applied to the loaded/stored value.
    cast: Option<&'static str>,
}

enum X87Kind {
    /// Loads a value onto the FP stack: `st0 = ...`.
    Load,
    /// Stores `st0` somewhere: `dst = st0`.
    Store,
    /// Binary arithmetic on `st0`: `st0 = st0 OP val`.
    Binary(&'static str),
}

fn classify(m: Mnemonic) -> Option<X87Shape> {
    Some(match m {
        // Loads onto the FP stack.
        Mnemonic::Fld => X87Shape { prefix: "fld ", kind: X87Kind::Load, cast: None },
        Mnemonic::Fild => X87Shape {
            prefix: "fild ",
            kind: X87Kind::Load,
            cast: Some("(f64)"),
        },
        // Stores from the FP stack.
        Mnemonic::Fst => X87Shape { prefix: "fst ", kind: X87Kind::Store, cast: None },
        Mnemonic::Fstp => X87Shape { prefix: "fstp ", kind: X87Kind::Store, cast: None },
        Mnemonic::Fist => X87Shape {
            prefix: "fist ",
            kind: X87Kind::Store,
            cast: Some("(i32)"),
        },
        Mnemonic::Fistp => X87Shape {
            prefix: "fistp ",
            kind: X87Kind::Store,
            cast: Some("(i64)"),
        },
        // Binary arithmetic with the FP stack top.
        Mnemonic::Fadd => X87Shape { prefix: "fadd ", kind: X87Kind::Binary("+"), cast: None },
        Mnemonic::Fsub => X87Shape { prefix: "fsub ", kind: X87Kind::Binary("-"), cast: None },
        Mnemonic::Fmul => X87Shape { prefix: "fmul ", kind: X87Kind::Binary("*"), cast: None },
        Mnemonic::Fdiv => X87Shape { prefix: "fdiv ", kind: X87Kind::Binary("/"), cast: None },
        Mnemonic::Fsubr => X87Shape {
            prefix: "fsubr ",
            kind: X87Kind::Binary("- /*rev*/"),
            cast: None,
        },
        Mnemonic::Fdivr => X87Shape {
            prefix: "fdivr ",
            kind: X87Kind::Binary("/ /*rev*/"),
            cast: None,
        },
        _ => return None,
    })
}

fn split_two_ops(rest: &str) -> Option<(String, String)> {
    // x87 operand text from iced uses `,` as the separator, no
    // commas inside the operand types we care about.
    let (l, r) = rest.split_once(',')?;
    let lhs = normalize_st(l.trim());
    let rhs = normalize_st(r.trim());
    Some((lhs, rhs))
}

/// Normalize `st(N)` operand syntax to `stN` so the rendered text
/// doesn't look like a function call to the `.ud` parser. `st` on
/// its own (the implicit top-of-stack) becomes `st0` for the same
/// reason — the rest of the renderer assumes the bare `st` is the
/// stack top.
fn normalize_st(s: &str) -> String {
    if s == "st" {
        return "st0".to_string();
    }
    if let Some(rest) = s.strip_prefix("st(") {
        if let Some(num) = rest.strip_suffix(')') {
            return format!("st{num}");
        }
    }
    s.to_string()
}

fn wrap_cast(cast: Option<&'static str>, value: &str) -> String {
    match cast {
        Some(c) => format!("{c} {value}"),
        None => value.to_string(),
    }
}

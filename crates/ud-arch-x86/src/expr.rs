//! v0 expression IR + a register-state walker for straight-line code.
//!
//! Just enough machinery to lift the body of a `-O0` block whose only
//! purpose is to compute a value into `eax` and fall through to the
//! function's epilogue. The walker threads textual `ValueExpr`s
//! through register state, so it isn't a real SSA — it can't reason
//! about aliasing, control flow, or memory writes that re-enter as
//! reads. Good enough for "load-arith-call-arith" sequences gcc emits
//! at `-O0` on the path to a return.
//!
//! Out of scope (give up and return `None`):
//!
//! * Conditionals or loops inside the block.
//! * Memory writes other than register-to-stack-slot spills, since
//!   tracking arbitrary aliasing is a real-analysis problem.
//! * Floating-point, SIMD, or string instructions.
//! * Anything we don't have a mnemonic match for.
//!
//! The walker is conservative: any unrecognised instruction makes the
//! whole block ineligible, since folding a partially-known block
//! would silently drop side effects.

use std::collections::HashMap;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::DecodedInsn;

/// Tiny expression IR. See module docs for what's intentionally not
/// represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueExpr {
    /// `[rbp+disp]` — a stack slot. Renders as a local name when the
    /// caller supplies one (typically via DWARF), otherwise as a raw
    /// memory operand.
    StackSlot { displacement: i64 },
    /// Integer constant. Stored signed so subtraction-with-immediate
    /// renders as `v - 1` rather than `v + 0xffffffff`.
    Const(i64),
    /// `lhs - rhs`
    Sub(Box<ValueExpr>, Box<ValueExpr>),
    /// `lhs * rhs`
    Mul(Box<ValueExpr>, Box<ValueExpr>),
    /// Result of a direct call. `name` is the callee's symbol when
    /// known; otherwise renders as `sub_<addr>`.
    Call {
        target: u64,
        name: Option<String>,
        args: Vec<ValueExpr>,
    },
}

/// Read-only context for rendering [`ValueExpr`].
#[derive(Debug)]
pub struct ExprRenderCtx<'a> {
    /// Stack-slot displacement → human name. Typical use:
    /// `mov [rbp-4], edi` lets the caller infer that slot `-4` holds
    /// the value of arg `0`, named (e.g.) `v`.
    pub slot_to_name: &'a HashMap<i64, String>,
    /// Call-target address → callee name.
    pub name_at: &'a HashMap<u64, String>,
}

impl ValueExpr {
    /// Render as canonical `.ud` expression text. Operator precedence
    /// is encoded by parenthesising sub-terms when needed.
    #[must_use]
    pub fn render(&self, ctx: &ExprRenderCtx<'_>) -> String {
        match self {
            ValueExpr::StackSlot { displacement } => {
                if let Some(name) = ctx.slot_to_name.get(displacement) {
                    name.clone()
                } else if *displacement < 0 {
                    format!("[rbp-{:#x}]", displacement.unsigned_abs())
                } else {
                    format!("[rbp+{displacement:#x}]")
                }
            }
            ValueExpr::Const(n) => n.to_string(),
            ValueExpr::Sub(a, b) => {
                format!("{} - {}", render_term(a, ctx), render_term(b, ctx))
            }
            ValueExpr::Mul(a, b) => {
                let render = |e: &ValueExpr| match e {
                    ValueExpr::Sub(_, _) => format!("({})", e.render(ctx)),
                    _ => render_term(e, ctx),
                };
                format!("{} * {}", render(a), render(b))
            }
            ValueExpr::Call { target, name, args } => {
                let n = name.clone().unwrap_or_else(|| format!("sub_{target:x}"));
                let arg_text: Vec<String> = args.iter().map(|a| a.render(ctx)).collect();
                format!("{}({})", n, arg_text.join(", "))
            }
        }
    }
}

fn render_term(e: &ValueExpr, ctx: &ExprRenderCtx<'_>) -> String {
    e.render(ctx)
}

/// Lifted value-block: the expression sitting in EAX/RAX after the
/// block plus the bytes the lift consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedValueBlock {
    pub expr: ValueExpr,
    pub insns_consumed: usize,
}

/// Try to lift the entire instruction sequence as a value-producing
/// block whose final state is "EAX = some expression."
///
/// Returns `None` when any instruction isn't recognised, or when EAX
/// isn't defined at the end of the block — folding a partially-known
/// sequence would silently drop side effects.
#[must_use]
#[allow(clippy::implicit_hasher)] // standard-hasher is the only caller
pub fn try_lift_value_block(
    insns: &[DecodedInsn],
    name_at: &HashMap<u64, String>,
) -> Option<LiftedValueBlock> {
    if insns.is_empty() {
        return None;
    }
    let mut state = RegState::default();
    for insn in insns {
        if !apply_one(&mut state, &insn.iced, name_at) {
            return None;
        }
    }
    let expr = state.get(Register::RAX)?.clone();
    Some(LiftedValueBlock {
        expr,
        insns_consumed: insns.len(),
    })
}

/// Register-state machine: full-width-register → expression.
///
/// Sub-registers (EAX, AX, AL) collapse to their containing 64-bit
/// register so that `mov eax, [rbp-4]` followed by reads of `rax`
/// see the same expression.
#[derive(Default, Debug, Clone)]
struct RegState {
    regs: HashMap<Register, ValueExpr>,
}

impl RegState {
    fn get(&self, reg: Register) -> Option<&ValueExpr> {
        self.regs.get(&full_reg(reg))
    }

    fn set(&mut self, reg: Register, expr: ValueExpr) {
        self.regs.insert(full_reg(reg), expr);
    }
}

fn full_reg(reg: Register) -> Register {
    let full = reg.full_register();
    if full == Register::None {
        reg
    } else {
        full
    }
}

fn apply_one(state: &mut RegState, insn: &Instruction, name_at: &HashMap<u64, String>) -> bool {
    // We only handle a handful of mnemonics; any other instruction
    // makes the whole block ineligible.
    match insn.mnemonic() {
        Mnemonic::Mov => apply_mov(state, insn),
        Mnemonic::Sub => apply_sub(state, insn),
        Mnemonic::Add => apply_add(state, insn),
        Mnemonic::Imul => apply_imul(state, insn),
        Mnemonic::Call => apply_call(state, insn, name_at),
        _ => false,
    }
}

/// `mov reg, src` where `src` is a stack slot, immediate, or another
/// register whose expression we already track. Spills (`mov [mem], reg`)
/// aren't required for the v0 do_fac shape, so we don't support them.
fn apply_mov(state: &mut RegState, insn: &Instruction) -> bool {
    if insn.op_count() != 2 {
        return false;
    }
    if insn.op0_kind() != OpKind::Register {
        // Stores / memory writes — out of scope for v0.
        return false;
    }
    let dst = insn.op0_register();
    match insn.op1_kind() {
        OpKind::Register => {
            let src = insn.op1_register();
            let Some(expr) = state.get(src).cloned() else {
                return false;
            };
            state.set(dst, expr);
            true
        }
        OpKind::Memory => {
            let Some(disp) = stack_slot_displacement(insn) else {
                return false;
            };
            state.set(dst, ValueExpr::StackSlot { displacement: disp });
            true
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            let imm = signed_immediate(insn);
            state.set(dst, ValueExpr::Const(imm));
            true
        }
        _ => false,
    }
}

fn apply_sub(state: &mut RegState, insn: &Instruction) -> bool {
    apply_binop(state, insn, |lhs, rhs| {
        ValueExpr::Sub(Box::new(lhs), Box::new(rhs))
    })
}

fn apply_add(state: &mut RegState, insn: &Instruction) -> bool {
    // `add reg, imm` → `Sub(reg, Const(-imm))` would render oddly;
    // prefer keeping addition as `Sub(lhs, Const(-rhs))` only when
    // the immediate is negative. For the do_fac shape we don't see
    // `add` in expression contexts, so accept it but render as Sub
    // with negated rhs when the rhs is a small const. To keep things
    // tight, just fold `add reg, IMM` into `Sub(reg, Const(-IMM))`.
    apply_binop(state, insn, |lhs, rhs| match rhs {
        ValueExpr::Const(n) => ValueExpr::Sub(Box::new(lhs), Box::new(ValueExpr::Const(-n))),
        other => ValueExpr::Sub(
            Box::new(lhs),
            Box::new(ValueExpr::Sub(
                Box::new(ValueExpr::Const(0)),
                Box::new(other),
            )),
        ),
    })
}

fn apply_imul(state: &mut RegState, insn: &Instruction) -> bool {
    apply_binop(state, insn, |lhs, rhs| {
        ValueExpr::Mul(Box::new(lhs), Box::new(rhs))
    })
}

/// Two-operand arithmetic: `op reg, src` → `reg = combine(reg, src)`.
fn apply_binop<F>(state: &mut RegState, insn: &Instruction, combine: F) -> bool
where
    F: FnOnce(ValueExpr, ValueExpr) -> ValueExpr,
{
    if insn.op_count() != 2 {
        return false;
    }
    if insn.op0_kind() != OpKind::Register {
        return false;
    }
    let dst = insn.op0_register();
    let Some(lhs) = state.get(dst).cloned() else {
        return false;
    };
    let rhs = match insn.op1_kind() {
        OpKind::Register => {
            let Some(e) = state.get(insn.op1_register()).cloned() else {
                return false;
            };
            e
        }
        OpKind::Memory => {
            let Some(disp) = stack_slot_displacement(insn) else {
                return false;
            };
            ValueExpr::StackSlot { displacement: disp }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => ValueExpr::Const(signed_immediate(insn)),
        _ => return false,
    };
    state.set(dst, combine(lhs, rhs));
    true
}

/// `call rel32` → result lands in `EAX`. Arguments are read from the
/// SysV-x64 integer arg registers in order; we stop when the next
/// arg register has no recorded expression (the function presumably
/// takes that many args).
fn apply_call(state: &mut RegState, insn: &Instruction, name_at: &HashMap<u64, String>) -> bool {
    if insn.flow_control() != FlowControl::Call {
        return false;
    }
    let target = insn.near_branch_target();
    if target == 0 {
        // Indirect or non-near call — out of scope.
        return false;
    }
    let arg_regs = [
        Register::RDI,
        Register::RSI,
        Register::RDX,
        Register::RCX,
        Register::R8,
        Register::R9,
    ];
    let mut args = Vec::new();
    for r in arg_regs {
        match state.get(r) {
            Some(e) => args.push(e.clone()),
            None => break,
        }
    }
    let name = name_at.get(&target).cloned();
    state.set(Register::RAX, ValueExpr::Call { target, name, args });
    true
}

/// If `insn`'s memory operand is `[rbp+disp]` with no index, return
/// the signed displacement. Filters out non-stack memory operands
/// (anything with a different base, or with an index).
fn stack_slot_displacement(insn: &Instruction) -> Option<i64> {
    if insn.memory_base() != Register::RBP {
        return None;
    }
    if insn.memory_index() != Register::None {
        return None;
    }
    // Casting `u64` to `i64` is intentional two's-complement: a
    // displacement encoded as 0xff…fc represents -4.
    #[allow(clippy::cast_possible_wrap)]
    Some(insn.memory_displacement64() as i64)
}

/// Read the immediate from a 2-operand `op reg, imm` instruction as a
/// signed 64-bit integer. Sign-extends 8/16/32-bit immediates.
//
// `u8 -> i8` etc. are intentional two's-complement reinterprets:
// iced returns the encoded immediate as an unsigned integer of the
// operand width; we treat it as signed.
#[allow(clippy::cast_possible_wrap)]
fn signed_immediate(insn: &Instruction) -> i64 {
    match insn.op1_kind() {
        OpKind::Immediate8 => i64::from(insn.immediate8() as i8),
        OpKind::Immediate16 => i64::from(insn.immediate16() as i16),
        OpKind::Immediate32 => i64::from(insn.immediate32() as i32),
        OpKind::Immediate64 => insn.immediate64() as i64,
        // Variants iced uses for "immediate8 sign-extended to N":
        OpKind::Immediate8to16 => i64::from(insn.immediate8to16()),
        OpKind::Immediate8to32 => i64::from(insn.immediate8to32()),
        OpKind::Immediate8to64 => insn.immediate8to64(),
        OpKind::Immediate32to64 => insn.immediate32to64(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, Bitness};

    fn empty_names() -> HashMap<u64, String> {
        HashMap::new()
    }

    #[test]
    fn lift_load_subtract_call_multiply_yields_expected_shape() {
        // Sequence:
        //   mov eax, [rbp-4]       8b 45 fc
        //   sub eax, 1             83 e8 01
        //   mov edi, eax           89 c7
        //   call <addr 0x1100>     e8 ?? ?? ?? ??
        //   imul eax, [rbp-4]      0f af 45 fc
        // Block lives at 0x1000; call's rel32 goes to 0x1100 from the
        // address right after the call instruction.
        // After: mov eax,[rbp-4]=3, sub=3+3=6 bytes; mov edi,eax adds 2 → 8;
        // call @0x1008, length 5, target_after = 0x100d, rel32 = 0x1100 - 0x100d = 0xf3.
        let mut bytes = vec![
            0x8b, 0x45, 0xfc, // mov eax, [rbp-4]
            0x83, 0xe8, 0x01, // sub eax, 1
            0x89, 0xc7, // mov edi, eax
            0xe8, 0xf3, 0x00, 0x00, 0x00, // call rel32 -> 0x1100
            0x0f, 0xaf, 0x45, 0xfc, // imul eax, [rbp-4]
        ];
        bytes.shrink_to_fit();
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();

        let mut names = HashMap::new();
        names.insert(0x1100u64, "do_fac".to_string());

        let lifted = try_lift_value_block(&insns, &names).expect("should lift");
        assert_eq!(lifted.insns_consumed, 5);

        let mut slot_names = HashMap::new();
        slot_names.insert(-4i64, "v".to_string());
        let ctx = ExprRenderCtx {
            slot_to_name: &slot_names,
            name_at: &names,
        };
        assert_eq!(lifted.expr.render(&ctx), "do_fac(v - 1) * v");
    }

    #[test]
    fn unsupported_instruction_aborts_lift() {
        // `xchg eax, ebx` — not in our recognised set.
        let bytes = [0x93];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(try_lift_value_block(&insns, &empty_names()).is_none());
    }

    #[test]
    fn empty_block_is_not_liftable() {
        assert!(try_lift_value_block(&[], &empty_names()).is_none());
    }

    #[test]
    fn rendering_falls_back_to_memory_form_when_no_slot_name() {
        let expr = ValueExpr::StackSlot { displacement: -8 };
        let names = empty_names();
        let slots: HashMap<i64, String> = HashMap::new();
        let ctx = ExprRenderCtx {
            slot_to_name: &slots,
            name_at: &names,
        };
        assert_eq!(expr.render(&ctx), "[rbp-0x8]");
    }
}

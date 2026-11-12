/// A restricted form of constant evaluation used for disassembly time constants.
pub fn const_eval(
    dst: crate::sleigh::pcode::VarNode,
    op: crate::sleigh::pcode::Op,
    inputs: &crate::sleigh::pcode::Inputs,
) -> Option<u64> {
    let inputs = inputs.get();
    if dst.size > 8 || inputs[0].size() > 8 || inputs[1].size() > 8 {
        return None;
    }

    match (op, inputs) {
        (crate::sleigh::pcode::Op::ZeroExtend, [crate::sleigh::pcode::Value::Const(a, _), _]) => {
            Some(a)
        }
        (
            crate::sleigh::pcode::Op::SignExtend,
            [crate::sleigh::pcode::Value::Const(a, input_size), _],
        ) => {
            let a = crate::sleigh::pcode::sxt64(a, input_size as u64 * 8);
            Some(a & crate::sleigh::pcode::mask(dst.size as u64 * 8))
        }
        (
            crate::sleigh::pcode::Op::IntAdd,
            [
                crate::sleigh::pcode::Value::Const(a, size),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => {
            let a = crate::sleigh::pcode::sxt64(a, size as u64 * 8);
            let b = crate::sleigh::pcode::sxt64(b, size as u64 * 8);
            Some(a.wrapping_add(b) & crate::sleigh::pcode::mask(size as u64 * 8))
        }
        (
            crate::sleigh::pcode::Op::IntSub,
            [
                crate::sleigh::pcode::Value::Const(a, size),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => {
            let a = crate::sleigh::pcode::sxt64(a, size as u64 * 8);
            let b = crate::sleigh::pcode::sxt64(b, size as u64 * 8);
            Some(a.wrapping_sub(b) & crate::sleigh::pcode::mask(size as u64 * 8))
        }
        (
            crate::sleigh::pcode::Op::IntRight,
            [
                crate::sleigh::pcode::Value::Const(a, size),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => {
            if b >= size as u64 * 8 {
                return Some(0);
            }
            let a = crate::sleigh::pcode::sxt64(a, size as u64 * 8);
            Some((a >> b) & crate::sleigh::pcode::mask(size as u64 * 8))
        }
        (
            crate::sleigh::pcode::Op::IntLeft,
            [
                crate::sleigh::pcode::Value::Const(a, size),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => {
            if b >= size as u64 * 8 {
                return Some(0);
            }
            Some((a << b) & crate::sleigh::pcode::mask(size as u64 * 8))
        }
        (
            crate::sleigh::pcode::Op::IntMul,
            [
                crate::sleigh::pcode::Value::Const(a, size),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => {
            let a = crate::sleigh::pcode::sxt64(a, size as u64 * 8);
            let b = crate::sleigh::pcode::sxt64(b, size as u64 * 8);
            Some(a.wrapping_mul(b) & crate::sleigh::pcode::mask(size as u64 * 8))
        }
        (
            crate::sleigh::pcode::Op::IntAnd,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(a & b),
        (
            crate::sleigh::pcode::Op::IntOr,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(a | b),
        (
            crate::sleigh::pcode::Op::IntEqual,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(if a == b { 1 } else { 0 }),
        (
            crate::sleigh::pcode::Op::IntNotEqual,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(if a != b { 1 } else { 0 }),
        (
            crate::sleigh::pcode::Op::IntLess,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(if a < b { 1 } else { 0 }),
        (
            crate::sleigh::pcode::Op::IntLessEqual,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(if a <= b { 1 } else { 0 }),
        (
            crate::sleigh::pcode::Op::BoolAnd,
            [
                crate::sleigh::pcode::Value::Const(a, _),
                crate::sleigh::pcode::Value::Const(b, _),
            ],
        ) => Some(if a != 0 && b != 0 { 1 } else { 0 }),
        (crate::sleigh::pcode::Op::BoolNot, [crate::sleigh::pcode::Value::Const(a, _), _]) => {
            Some(if a == 0 { 1 } else { 0 })
        }
        (crate::sleigh::pcode::Op::IntNot, [crate::sleigh::pcode::Value::Const(a, size), _]) => {
            Some(!a & crate::sleigh::pcode::mask(size as u64 * 8))
        }
        // x OP 0 == 0 identities.
        (
            crate::sleigh::pcode::Op::BoolAnd
            | crate::sleigh::pcode::Op::IntAnd
            | crate::sleigh::pcode::Op::IntMul,
            [crate::sleigh::pcode::Value::Const(0, _), _]
            | [_, crate::sleigh::pcode::Value::Const(0, _)],
        ) => Some(0),

        _ => None,
    }
}

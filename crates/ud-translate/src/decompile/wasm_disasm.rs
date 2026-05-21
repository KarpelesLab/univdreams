//! WASM opcode decoder for the Code section.
//!
//! Walks a function body's instruction stream byte-by-byte,
//! producing one [`Op`] per instruction. The `bytes` field of
//! each `Op` is the exact slice that was consumed, which the
//! decompile path pins into `@asm` so that concatenating bytes
//! reproduces the original function body byte-for-byte.
//!
//! Coverage: MVP + sign-extension + bulk-memory + reference-
//! types + saturating-conversion (the 0xFC prefix space).
//! Unknown opcodes return [`DisasmError::UnknownOpcode`] —
//! we'd rather fail the decode and fall back to opaque `@raw`
//! than silently emit a truncated byte run.
//!
//! Round-trip safety: this module never modifies bytes. It
//! only decides where one instruction ends and the next
//! begins. Mnemonic and immediate-text rendering is cosmetic.
//!
//! References:
//! * <https://webassembly.github.io/spec/core/binary/instructions.html>
//! * `wasm-tools print` was used to cross-check the immediate
//!   layout of every opcode covered here.

use std::ops::Range;

/// One decoded WASM instruction.
#[derive(Debug, Clone)]
pub struct Op {
    /// Bytes consumed by this instruction (opcode + immediates),
    /// expressed as a range into the slice handed to
    /// [`decode_function`]. `bytes.start` is the instruction's
    /// offset within that slice.
    pub bytes: Range<usize>,
    /// Symbolic name of the opcode, e.g. `"local.get"`.
    pub mnemonic: &'static str,
    /// Already-formatted immediate text, e.g. `"0"`, `"align=2 offset=12"`.
    /// Empty when the opcode has no immediates.
    pub args: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DisasmError {
    #[error("unexpected end of code at offset 0x{at:x}")]
    UnexpectedEof { at: usize },
    #[error("unknown opcode 0x{op:02x} at offset 0x{at:x}")]
    UnknownOpcode { op: u8, at: usize },
    #[error("unknown 0xFC sub-opcode {sub} at offset 0x{at:x}")]
    UnknownFcSubOp { sub: u32, at: usize },
    #[error("LEB128 too long or unterminated at offset 0x{at:x}")]
    BadLeb { at: usize },
}

/// Decode every instruction inside a function body.
///
/// `body` should be the bytes between the locals declaration
/// and the function's terminating `end` (inclusive). The
/// returned vector is in stream order; the final element has
/// `mnemonic == "end"`.
pub fn decode_function(body: &[u8]) -> Result<Vec<Op>, DisasmError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < body.len() {
        let start = cursor;
        let op = decode_one(body, &mut cursor)?;
        out.push(Op {
            bytes: start..cursor,
            mnemonic: op.0,
            args: op.1,
        });
    }
    Ok(out)
}

/// Decode the locals declaration at the head of a function
/// body. Returns `(end_offset, rendered_text)` where the
/// rendered text is a human-readable summary (cosmetic; the
/// byte range carries the truth).
///
/// Locals declaration: `vec((count: u32, valtype: u8))`. The
/// outer LEB is the number of groups; each group is a count
/// LEB plus one valtype byte.
pub fn decode_locals(body: &[u8]) -> Result<(usize, String), DisasmError> {
    let mut cursor = 0usize;
    let groups = read_leb_u32(body, &mut cursor)?;
    let mut parts = Vec::with_capacity(groups as usize);
    for _ in 0..groups {
        let count = read_leb_u32(body, &mut cursor)?;
        let vt = read_u8(body, &mut cursor)?;
        parts.push(format!("{count} × {}", valtype_name(vt)));
    }
    let text = if parts.is_empty() {
        "(none)".to_string()
    } else {
        parts.join(", ")
    };
    Ok((cursor, text))
}

#[allow(clippy::too_many_lines)]
fn decode_one(body: &[u8], cursor: &mut usize) -> Result<(&'static str, String), DisasmError> {
    let op = read_u8(body, cursor)?;
    Ok(match op {
        // Control instructions
        0x00 => ("unreachable", String::new()),
        0x01 => ("nop", String::new()),
        0x02 => ("block", blocktype(body, cursor)?),
        0x03 => ("loop", blocktype(body, cursor)?),
        0x04 => ("if", blocktype(body, cursor)?),
        0x05 => ("else", String::new()),
        0x0b => ("end", String::new()),
        0x0c => ("br", labelidx(body, cursor)?),
        0x0d => ("br_if", labelidx(body, cursor)?),
        0x0e => ("br_table", br_table(body, cursor)?),
        0x0f => ("return", String::new()),
        0x10 => ("call", funcidx(body, cursor)?),
        0x11 => ("call_indirect", call_indirect(body, cursor)?),
        0x12 => ("return_call", funcidx(body, cursor)?),
        0x13 => ("return_call_indirect", call_indirect(body, cursor)?),

        // Reference instructions
        0xd0 => ("ref.null", reftype(body, cursor)?),
        0xd1 => ("ref.is_null", String::new()),
        0xd2 => ("ref.func", funcidx(body, cursor)?),

        // Parametric
        0x1a => ("drop", String::new()),
        0x1b => ("select", String::new()),
        0x1c => ("select", select_t(body, cursor)?),

        // Variable
        0x20 => ("local.get", localidx(body, cursor)?),
        0x21 => ("local.set", localidx(body, cursor)?),
        0x22 => ("local.tee", localidx(body, cursor)?),
        0x23 => ("global.get", globalidx(body, cursor)?),
        0x24 => ("global.set", globalidx(body, cursor)?),

        // Table
        0x25 => ("table.get", tableidx(body, cursor)?),
        0x26 => ("table.set", tableidx(body, cursor)?),

        // Memory load / store
        0x28 => ("i32.load", memarg(body, cursor)?),
        0x29 => ("i64.load", memarg(body, cursor)?),
        0x2a => ("f32.load", memarg(body, cursor)?),
        0x2b => ("f64.load", memarg(body, cursor)?),
        0x2c => ("i32.load8_s", memarg(body, cursor)?),
        0x2d => ("i32.load8_u", memarg(body, cursor)?),
        0x2e => ("i32.load16_s", memarg(body, cursor)?),
        0x2f => ("i32.load16_u", memarg(body, cursor)?),
        0x30 => ("i64.load8_s", memarg(body, cursor)?),
        0x31 => ("i64.load8_u", memarg(body, cursor)?),
        0x32 => ("i64.load16_s", memarg(body, cursor)?),
        0x33 => ("i64.load16_u", memarg(body, cursor)?),
        0x34 => ("i64.load32_s", memarg(body, cursor)?),
        0x35 => ("i64.load32_u", memarg(body, cursor)?),
        0x36 => ("i32.store", memarg(body, cursor)?),
        0x37 => ("i64.store", memarg(body, cursor)?),
        0x38 => ("f32.store", memarg(body, cursor)?),
        0x39 => ("f64.store", memarg(body, cursor)?),
        0x3a => ("i32.store8", memarg(body, cursor)?),
        0x3b => ("i32.store16", memarg(body, cursor)?),
        0x3c => ("i64.store8", memarg(body, cursor)?),
        0x3d => ("i64.store16", memarg(body, cursor)?),
        0x3e => ("i64.store32", memarg(body, cursor)?),
        0x3f => ("memory.size", reserved_zero(body, cursor)?),
        0x40 => ("memory.grow", reserved_zero(body, cursor)?),

        // Numeric constants
        0x41 => ("i32.const", const_i32(body, cursor)?),
        0x42 => ("i64.const", const_i64(body, cursor)?),
        0x43 => ("f32.const", const_f32(body, cursor)?),
        0x44 => ("f64.const", const_f64(body, cursor)?),

        // Numeric tests / comparisons / arith (all immediate-less)
        0x45 => ("i32.eqz", String::new()),
        0x46 => ("i32.eq", String::new()),
        0x47 => ("i32.ne", String::new()),
        0x48 => ("i32.lt_s", String::new()),
        0x49 => ("i32.lt_u", String::new()),
        0x4a => ("i32.gt_s", String::new()),
        0x4b => ("i32.gt_u", String::new()),
        0x4c => ("i32.le_s", String::new()),
        0x4d => ("i32.le_u", String::new()),
        0x4e => ("i32.ge_s", String::new()),
        0x4f => ("i32.ge_u", String::new()),

        0x50 => ("i64.eqz", String::new()),
        0x51 => ("i64.eq", String::new()),
        0x52 => ("i64.ne", String::new()),
        0x53 => ("i64.lt_s", String::new()),
        0x54 => ("i64.lt_u", String::new()),
        0x55 => ("i64.gt_s", String::new()),
        0x56 => ("i64.gt_u", String::new()),
        0x57 => ("i64.le_s", String::new()),
        0x58 => ("i64.le_u", String::new()),
        0x59 => ("i64.ge_s", String::new()),
        0x5a => ("i64.ge_u", String::new()),

        0x5b => ("f32.eq", String::new()),
        0x5c => ("f32.ne", String::new()),
        0x5d => ("f32.lt", String::new()),
        0x5e => ("f32.gt", String::new()),
        0x5f => ("f32.le", String::new()),
        0x60 => ("f32.ge", String::new()),
        0x61 => ("f64.eq", String::new()),
        0x62 => ("f64.ne", String::new()),
        0x63 => ("f64.lt", String::new()),
        0x64 => ("f64.gt", String::new()),
        0x65 => ("f64.le", String::new()),
        0x66 => ("f64.ge", String::new()),

        0x67 => ("i32.clz", String::new()),
        0x68 => ("i32.ctz", String::new()),
        0x69 => ("i32.popcnt", String::new()),
        0x6a => ("i32.add", String::new()),
        0x6b => ("i32.sub", String::new()),
        0x6c => ("i32.mul", String::new()),
        0x6d => ("i32.div_s", String::new()),
        0x6e => ("i32.div_u", String::new()),
        0x6f => ("i32.rem_s", String::new()),
        0x70 => ("i32.rem_u", String::new()),
        0x71 => ("i32.and", String::new()),
        0x72 => ("i32.or", String::new()),
        0x73 => ("i32.xor", String::new()),
        0x74 => ("i32.shl", String::new()),
        0x75 => ("i32.shr_s", String::new()),
        0x76 => ("i32.shr_u", String::new()),
        0x77 => ("i32.rotl", String::new()),
        0x78 => ("i32.rotr", String::new()),

        0x79 => ("i64.clz", String::new()),
        0x7a => ("i64.ctz", String::new()),
        0x7b => ("i64.popcnt", String::new()),
        0x7c => ("i64.add", String::new()),
        0x7d => ("i64.sub", String::new()),
        0x7e => ("i64.mul", String::new()),
        0x7f => ("i64.div_s", String::new()),
        0x80 => ("i64.div_u", String::new()),
        0x81 => ("i64.rem_s", String::new()),
        0x82 => ("i64.rem_u", String::new()),
        0x83 => ("i64.and", String::new()),
        0x84 => ("i64.or", String::new()),
        0x85 => ("i64.xor", String::new()),
        0x86 => ("i64.shl", String::new()),
        0x87 => ("i64.shr_s", String::new()),
        0x88 => ("i64.shr_u", String::new()),
        0x89 => ("i64.rotl", String::new()),
        0x8a => ("i64.rotr", String::new()),

        0x8b => ("f32.abs", String::new()),
        0x8c => ("f32.neg", String::new()),
        0x8d => ("f32.ceil", String::new()),
        0x8e => ("f32.floor", String::new()),
        0x8f => ("f32.trunc", String::new()),
        0x90 => ("f32.nearest", String::new()),
        0x91 => ("f32.sqrt", String::new()),
        0x92 => ("f32.add", String::new()),
        0x93 => ("f32.sub", String::new()),
        0x94 => ("f32.mul", String::new()),
        0x95 => ("f32.div", String::new()),
        0x96 => ("f32.min", String::new()),
        0x97 => ("f32.max", String::new()),
        0x98 => ("f32.copysign", String::new()),

        0x99 => ("f64.abs", String::new()),
        0x9a => ("f64.neg", String::new()),
        0x9b => ("f64.ceil", String::new()),
        0x9c => ("f64.floor", String::new()),
        0x9d => ("f64.trunc", String::new()),
        0x9e => ("f64.nearest", String::new()),
        0x9f => ("f64.sqrt", String::new()),
        0xa0 => ("f64.add", String::new()),
        0xa1 => ("f64.sub", String::new()),
        0xa2 => ("f64.mul", String::new()),
        0xa3 => ("f64.div", String::new()),
        0xa4 => ("f64.min", String::new()),
        0xa5 => ("f64.max", String::new()),
        0xa6 => ("f64.copysign", String::new()),

        0xa7 => ("i32.wrap_i64", String::new()),
        0xa8 => ("i32.trunc_f32_s", String::new()),
        0xa9 => ("i32.trunc_f32_u", String::new()),
        0xaa => ("i32.trunc_f64_s", String::new()),
        0xab => ("i32.trunc_f64_u", String::new()),
        0xac => ("i64.extend_i32_s", String::new()),
        0xad => ("i64.extend_i32_u", String::new()),
        0xae => ("i64.trunc_f32_s", String::new()),
        0xaf => ("i64.trunc_f32_u", String::new()),
        0xb0 => ("i64.trunc_f64_s", String::new()),
        0xb1 => ("i64.trunc_f64_u", String::new()),
        0xb2 => ("f32.convert_i32_s", String::new()),
        0xb3 => ("f32.convert_i32_u", String::new()),
        0xb4 => ("f32.convert_i64_s", String::new()),
        0xb5 => ("f32.convert_i64_u", String::new()),
        0xb6 => ("f32.demote_f64", String::new()),
        0xb7 => ("f64.convert_i32_s", String::new()),
        0xb8 => ("f64.convert_i32_u", String::new()),
        0xb9 => ("f64.convert_i64_s", String::new()),
        0xba => ("f64.convert_i64_u", String::new()),
        0xbb => ("f64.promote_f32", String::new()),
        0xbc => ("i32.reinterpret_f32", String::new()),
        0xbd => ("i64.reinterpret_f64", String::new()),
        0xbe => ("f32.reinterpret_i32", String::new()),
        0xbf => ("f64.reinterpret_i64", String::new()),

        // Sign-extension proposal
        0xc0 => ("i32.extend8_s", String::new()),
        0xc1 => ("i32.extend16_s", String::new()),
        0xc2 => ("i64.extend8_s", String::new()),
        0xc3 => ("i64.extend16_s", String::new()),
        0xc4 => ("i64.extend32_s", String::new()),

        // 0xFC prefix: saturating-conversion / bulk-memory / table ops
        0xfc => decode_fc(body, cursor)?,

        op => {
            return Err(DisasmError::UnknownOpcode {
                op,
                at: *cursor - 1,
            })
        }
    })
}

fn decode_fc(body: &[u8], cursor: &mut usize) -> Result<(&'static str, String), DisasmError> {
    let at_sub = *cursor;
    let sub = read_leb_u32(body, cursor)?;
    Ok(match sub {
        // Saturating conversion
        0 => ("i32.trunc_sat_f32_s", String::new()),
        1 => ("i32.trunc_sat_f32_u", String::new()),
        2 => ("i32.trunc_sat_f64_s", String::new()),
        3 => ("i32.trunc_sat_f64_u", String::new()),
        4 => ("i64.trunc_sat_f32_s", String::new()),
        5 => ("i64.trunc_sat_f32_u", String::new()),
        6 => ("i64.trunc_sat_f64_s", String::new()),
        7 => ("i64.trunc_sat_f64_u", String::new()),

        // Bulk-memory
        8 => {
            let data_idx = read_leb_u32(body, cursor)?;
            let zero = read_u8(body, cursor)?;
            ("memory.init", format!("data={data_idx} mem={zero}"))
        }
        9 => ("data.drop", format!("data={}", read_leb_u32(body, cursor)?)),
        10 => {
            let dst = read_u8(body, cursor)?;
            let src = read_u8(body, cursor)?;
            ("memory.copy", format!("dst={dst} src={src}"))
        }
        11 => {
            let mem = read_u8(body, cursor)?;
            ("memory.fill", format!("mem={mem}"))
        }

        // Table operations
        12 => {
            let elem = read_leb_u32(body, cursor)?;
            let tbl = read_leb_u32(body, cursor)?;
            ("table.init", format!("elem={elem} table={tbl}"))
        }
        13 => ("elem.drop", format!("elem={}", read_leb_u32(body, cursor)?)),
        14 => {
            let dst = read_leb_u32(body, cursor)?;
            let src = read_leb_u32(body, cursor)?;
            ("table.copy", format!("dst={dst} src={src}"))
        }
        15 => (
            "table.grow",
            format!("table={}", read_leb_u32(body, cursor)?),
        ),
        16 => (
            "table.size",
            format!("table={}", read_leb_u32(body, cursor)?),
        ),
        17 => (
            "table.fill",
            format!("table={}", read_leb_u32(body, cursor)?),
        ),

        _ => return Err(DisasmError::UnknownFcSubOp { sub, at: at_sub }),
    })
}

// ---------- immediate decoders ----------

fn blocktype(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    // blocktype = 0x40 (empty) | valtype | s33 type-index
    let b = read_u8(body, cursor)?;
    if b == 0x40 {
        return Ok("()".to_string());
    }
    if is_valtype_byte(b) {
        return Ok(valtype_name(b).to_string());
    }
    // s33 LEB — we already consumed the first byte; finish the decode
    *cursor -= 1;
    let idx = read_leb_s64(body, cursor)?;
    Ok(format!("type={idx}"))
}

fn labelidx(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    Ok(format!("{}", read_leb_u32(body, cursor)?))
}

fn funcidx(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    Ok(format!("{}", read_leb_u32(body, cursor)?))
}

fn localidx(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    Ok(format!("{}", read_leb_u32(body, cursor)?))
}

fn globalidx(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    Ok(format!("{}", read_leb_u32(body, cursor)?))
}

fn tableidx(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    Ok(format!("{}", read_leb_u32(body, cursor)?))
}

fn br_table(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let count = read_leb_u32(body, cursor)?;
    let mut labels = Vec::with_capacity(count as usize);
    for _ in 0..count {
        labels.push(read_leb_u32(body, cursor)?.to_string());
    }
    let default = read_leb_u32(body, cursor)?;
    Ok(format!("[{}] default={default}", labels.join(", ")))
}

fn call_indirect(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let ty = read_leb_u32(body, cursor)?;
    let tbl = read_leb_u32(body, cursor)?;
    Ok(format!("type={ty} table={tbl}"))
}

fn memarg(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let align = read_leb_u32(body, cursor)?;
    let offset = read_leb_u32(body, cursor)?;
    Ok(format!("align={align} offset={offset}"))
}

fn reserved_zero(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let b = read_u8(body, cursor)?;
    Ok(format!("mem={b}"))
}

fn const_i32(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let n = read_leb_s32(body, cursor)?;
    Ok(format!("{n}"))
}

fn const_i64(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let n = read_leb_s64(body, cursor)?;
    Ok(format!("{n}"))
}

fn const_f32(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    if *cursor + 4 > body.len() {
        return Err(DisasmError::UnexpectedEof { at: *cursor });
    }
    let bits = u32::from_le_bytes([
        body[*cursor],
        body[*cursor + 1],
        body[*cursor + 2],
        body[*cursor + 3],
    ]);
    *cursor += 4;
    let f = f32::from_bits(bits);
    Ok(format!("0x{bits:08x} ({f})"))
}

fn const_f64(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    if *cursor + 8 > body.len() {
        return Err(DisasmError::UnexpectedEof { at: *cursor });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&body[*cursor..*cursor + 8]);
    *cursor += 8;
    let bits = u64::from_le_bytes(buf);
    let f = f64::from_bits(bits);
    Ok(format!("0x{bits:016x} ({f})"))
}

fn reftype(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let b = read_u8(body, cursor)?;
    Ok(match b {
        0x70 => "funcref".to_string(),
        0x6f => "externref".to_string(),
        other => format!("0x{other:02x}"),
    })
}

fn select_t(body: &[u8], cursor: &mut usize) -> Result<String, DisasmError> {
    let count = read_leb_u32(body, cursor)?;
    let mut tys = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let v = read_u8(body, cursor)?;
        tys.push(valtype_name(v).to_string());
    }
    Ok(format!("[{}]", tys.join(", ")))
}

// ---------- LEB / byte helpers ----------

fn read_u8(body: &[u8], cursor: &mut usize) -> Result<u8, DisasmError> {
    let b = *body
        .get(*cursor)
        .ok_or(DisasmError::UnexpectedEof { at: *cursor })?;
    *cursor += 1;
    Ok(b)
}

fn read_leb_u32(body: &[u8], cursor: &mut usize) -> Result<u32, DisasmError> {
    let at = *cursor;
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut bytes = 0usize;
    loop {
        let b = read_u8(body, cursor)?;
        result |= u64::from(b & 0x7f) << shift;
        bytes += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if bytes > 5 {
            return Err(DisasmError::BadLeb { at });
        }
    }
    if result > u64::from(u32::MAX) {
        return Err(DisasmError::BadLeb { at });
    }
    Ok(result as u32)
}

fn read_leb_s32(body: &[u8], cursor: &mut usize) -> Result<i32, DisasmError> {
    let v = read_leb_s64_max(body, cursor, 5)?;
    Ok(v as i32)
}

fn read_leb_s64(body: &[u8], cursor: &mut usize) -> Result<i64, DisasmError> {
    read_leb_s64_max(body, cursor, 10)
}

fn read_leb_s64_max(body: &[u8], cursor: &mut usize, max_bytes: usize) -> Result<i64, DisasmError> {
    let at = *cursor;
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut bytes = 0usize;
    let last;
    loop {
        let b = read_u8(body, cursor)?;
        result |= i64::from(b & 0x7f) << shift;
        bytes += 1;
        shift += 7;
        if b & 0x80 == 0 {
            last = b;
            break;
        }
        if bytes > max_bytes {
            return Err(DisasmError::BadLeb { at });
        }
    }
    if shift < 64 && (last & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

fn is_valtype_byte(b: u8) -> bool {
    matches!(b, 0x7f | 0x7e | 0x7d | 0x7c | 0x70 | 0x6f)
}

fn valtype_name(b: u8) -> &'static str {
    match b {
        0x7f => "i32",
        0x7e => "i64",
        0x7d => "f32",
        0x7c => "f64",
        0x70 => "funcref",
        0x6f => "externref",
        _ => "?",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_minimal_function_body() {
        // `add(a, b) -> a + b` shape: end-only.
        let body = [0x0bu8];
        let ops = decode_function(&body).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].mnemonic, "end");
        assert_eq!(ops[0].bytes, 0..1);
    }

    #[test]
    fn decode_padded_global_get() {
        // global.get 0 encoded with 5-byte padded LEB (clang style).
        let body = [0x23, 0x80, 0x80, 0x80, 0x80, 0x00, 0x0b];
        let ops = decode_function(&body).unwrap();
        assert_eq!(ops[0].mnemonic, "global.get");
        assert_eq!(ops[0].args, "0");
        assert_eq!(ops[0].bytes, 0..6);
        assert_eq!(ops[1].mnemonic, "end");
    }

    #[test]
    fn decode_memarg_store() {
        // i32.store align=2 offset=12
        let body = [0x36, 0x02, 0x0c, 0x0b];
        let ops = decode_function(&body).unwrap();
        assert_eq!(ops[0].mnemonic, "i32.store");
        assert_eq!(ops[0].args, "align=2 offset=12");
        assert_eq!(ops[0].bytes, 0..3);
    }

    #[test]
    fn decode_const_i32_signed_leb() {
        // i32.const -1 = 0x7f, then end
        let body = [0x41, 0x7f, 0x0b];
        let ops = decode_function(&body).unwrap();
        assert_eq!(ops[0].mnemonic, "i32.const");
        assert_eq!(ops[0].args, "-1");
    }

    #[test]
    fn locals_decode() {
        // 1 group of 1 i32, 2 groups (3 i64, 2 f32)
        let body = [0x01, 0x01, 0x7f];
        let (end, text) = decode_locals(&body).unwrap();
        assert_eq!(end, 3);
        assert_eq!(text, "1 × i32");
    }

    #[test]
    fn unknown_opcode_errors() {
        let body = [0xee, 0x0b];
        let err = decode_function(&body).err().unwrap();
        assert!(matches!(err, DisasmError::UnknownOpcode { .. }));
    }
}

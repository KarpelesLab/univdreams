//! BPF text → bytes assembler.
//!
//! The inverse of [`format_insn`]: given the raw textual form
//! the decoder produces (e.g. `"ldxdw r0, [r5 - 0xff8]"`,
//! `"jeq r0, 0x0, +0x7"`, `"mov64 r1, r2"`), emit the 8-byte
//! BPF slot encoding. Combined with a decompile-time
//! byte-drop pass, this turns the `@asm("text", [bytes])`
//! pairs in `.ud` source into `@asm("text")` — the bytes
//! become regenerable from the text alone.
//!
//! ## Round-trip contract
//!
//! For every opcode this assembler recognises:
//!
//! > `assemble(format_insn(decode(bytes)).text) == bytes`
//!
//! This makes the "decompile → recompile → byte-identical"
//! test meaningful: the text layer can no longer hide
//! encoding bugs the way it could when bytes were
//! shadow-pinned next to every `@asm`.
//!
//! ## Scope (phase 1)
//!
//! Handles every "pure" form `format_insn` emits — numeric
//! operands only:
//!
//! * Loads: `ldx{w,h,b,dw} rD, [rS]` / `[rS + 0xN]` / `[rS - 0xN]`
//! * Stores: `st{w,h,b,dw} [rD ±off], 0xN` and `stx{w,h,b,dw} [rD ±off], rS`
//! * ALU (32 / 64): `add/sub/mul/div/mod/or/and/lsh/rsh/arsh/xor/mov/neg`
//!   (+ sBPFv2's `udiv/urem/sdiv/srem`); reg or imm source.
//! * Endian: `le16/le32/le64/be16/be32/be64 rD`
//! * Branches: `ja ±0x…`, `j{eq,ne,gt,lt,ge,le,sgt,slt,sge,sle,set}{32?} rD, rhs, ±0x…`
//! * Calls: `call 0xN`, `callx rD`
//! * `exit`
//! * `lddw rD, 0x…` (first slot) + `<lddw-cont 0x…>` (second slot)
//! * `<bpf 0xNNNN…>` fallback — raw u64 → 8 bytes
//!
//! Symbolic forms (`call sub_X`, `jeq …, label_Y`,
//! `lddw r1, "string"`) are out of scope here. They land
//! later via a symbol-resolution layer in the translation
//! crate — at which point those texts are de-symbolised back
//! to the pure forms this module accepts.
//!
//! [`format_insn`]: super::format_insn

use crate::INSN_SIZE;

/// Errors the assembler surfaces. Each one points at the
/// specific shape that failed to parse / encode, so the
/// decompile-time byte-drop pass can keep bytes pinned for
/// the lines we can't yet handle (typically symbolic forms).
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    #[error("empty text")]
    Empty,
    #[error("unknown mnemonic {0:?}")]
    UnknownMnemonic(String),
    #[error("malformed operand {0:?} for {1}")]
    BadOperand(String, &'static str),
    #[error("expected {expected} operands for {mnemonic}, got {got}")]
    WrongArity {
        mnemonic: String,
        expected: usize,
        got: usize,
    },
    #[error("immediate {value:#x} doesn't fit in {bits} bits")]
    ImmediateOverflow { value: u64, bits: u8 },
    #[error("branch offset {0} doesn't fit in i16")]
    OffsetOverflow(i64),
    #[error("register {0} out of range 0..=10")]
    BadRegister(u32),
    #[error("not a known textual form")]
    NotRecognised,
}

/// Assemble one BPF instruction text into its 8-byte slot
/// encoding. The address argument is currently unused — BPF
/// branch offsets are encoded as slot-relative i16 values
/// taken directly from the text, so the assembler doesn't
/// need to know where in the function it lives.
///
/// Returns 8 bytes on success.
pub fn assemble_bpf(text: &str) -> Result<Vec<u8>, AssembleError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(AssembleError::Empty);
    }

    // Fallback: raw `<bpf 0xNNNN…>` form for opcodes the
    // decoder couldn't classify. Encode the u64 directly.
    if let Some(rest) = text.strip_prefix("<bpf 0x") {
        let hex = rest.strip_suffix('>').ok_or(AssembleError::NotRecognised)?;
        let v = u64::from_str_radix(hex, 16).map_err(|_| AssembleError::NotRecognised)?;
        return Ok(v.to_le_bytes().to_vec());
    }

    // LDDW continuation slot.
    if let Some(rest) = text.strip_prefix("<lddw-cont 0x") {
        let hex = rest.strip_suffix('>').ok_or(AssembleError::NotRecognised)?;
        let high = u32::from_str_radix(hex, 16).map_err(|_| AssembleError::NotRecognised)?;
        return Ok(encode_slot(0x00, 0, 0, 0, high as i32));
    }

    if text == "exit" {
        return Ok(encode_slot(0x95, 0, 0, 0, 0));
    }

    // Split into mnemonic + operand list.
    let (mnemonic, rest) = match text.find(char::is_whitespace) {
        Some(i) => (&text[..i], text[i..].trim()),
        None => (text, ""),
    };
    let operands = split_operands(rest);

    match mnemonic {
        // ---------------- LDDW + LD/LDX ----------------
        "lddw" => assemble_lddw(&operands),
        "ldxw" | "ldxh" | "ldxb" | "ldxdw" => assemble_ldx(mnemonic, &operands),

        // ---------------- ST / STX ----------------
        "stw" | "sth" | "stb" | "stdw" => assemble_st(mnemonic, &operands),
        "stxw" | "stxh" | "stxb" | "stxdw" => assemble_stx(mnemonic, &operands),

        // ---------------- Endian ----------------
        // Mnemonic forms: le16/le32/le64/be16/be32/be64.
        "le16" | "le32" | "le64" | "be16" | "be32" | "be64" => assemble_endian(mnemonic, &operands),

        // ---------------- Control flow ----------------
        "ja" => assemble_ja(&operands),
        "call" => assemble_call(&operands, /* src=*/ 0),
        // BPF-to-BPF intra-program calls have two encodings
        // in the wild:
        //
        //   * Solana sBPF: opcode `0x85`, src=1, imm=signed
        //     slot count. Emitted by `format_insn` as
        //     `call <hex>` (same as syscall — the src nibble
        //     distinguishes them in the byte stream).
        //   * Linux eBPF + a few toolchains that misuse
        //     `EM_BPF` for SBF: opcode `0x8d`, src=0,
        //     imm=signed slot count.
        //
        // Neither is in `format_insn`'s output directly —
        // the de-symbolizer in `ud-translate` rewrites the
        // user-facing `call sub_<hex>` text into one of the
        // two mnemonics below based on the original byte's
        // opcode, so the byte-drop pass can recover the
        // exact encoding.
        "call_internal" => assemble_call(&operands, /* src=*/ 1),
        "call_local" => assemble_call_local(&operands),
        "callx" => assemble_callx(&operands),

        // ---------------- ALU + jumps with suffix ----------------
        other => assemble_alu_or_jmp(other, &operands),
    }
}

// ────────────────────────────────────────────────────────────
//  Encoders
// ────────────────────────────────────────────────────────────

fn encode_slot(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Vec<u8> {
    let mut out = vec![0u8; INSN_SIZE];
    out[0] = opcode;
    out[1] = (dst & 0x0f) | ((src & 0x0f) << 4);
    out[2..4].copy_from_slice(&offset.to_le_bytes());
    out[4..8].copy_from_slice(&imm.to_le_bytes());
    out
}

fn assemble_lddw(operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 2, "lddw")?;
    let dst = parse_reg(operands[0])?;
    let imm64 = parse_uint(operands[1], "lddw")?;
    // First slot: opcode 0x18, dst=dst, src=0, imm=low32.
    #[allow(clippy::cast_possible_truncation)]
    let low = imm64 as u32 as i32;
    Ok(encode_slot(0x18, dst, 0, 0, low))
}

/// BPF MEM mode bits (top 3 of the opcode byte). All
/// memory-class instructions share `0x60`; legacy LD_ABS /
/// LD_IND use other mode bits and aren't handled here
/// (they don't appear in modern BPF binaries).
const BPF_MODE_MEM: u8 = 0x60;

fn assemble_ldx(mnemonic: &str, operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 2, mnemonic)?;
    let dst = parse_reg(operands[0])?;
    let (src, offset) = parse_mem(operands[1])?;
    let size_bits = size_letter_to_bits(&mnemonic[3..]);
    // LDX class = 0x01; size in bits 3..4; MEM mode = 0x60.
    let opcode = BPF_MODE_MEM | size_bits | 0x01;
    Ok(encode_slot(opcode, dst, src, offset, 0))
}

fn assemble_st(mnemonic: &str, operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 2, mnemonic)?;
    let (dst, offset) = parse_mem(operands[0])?;
    let imm = parse_int(operands[1], "st")?;
    let size_bits = size_letter_to_bits(&mnemonic[2..]);
    // ST class = 0x02 (imm source); size in bits 3..4; MEM mode = 0x60.
    let opcode = BPF_MODE_MEM | size_bits | 0x02;
    Ok(encode_slot(opcode, dst, 0, offset, imm))
}

fn assemble_stx(mnemonic: &str, operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 2, mnemonic)?;
    let (dst, offset) = parse_mem(operands[0])?;
    let src = parse_reg(operands[1])?;
    let size_bits = size_letter_to_bits(&mnemonic[3..]);
    // STX class = 0x03 (reg source); size in bits 3..4; MEM mode = 0x60.
    let opcode = BPF_MODE_MEM | size_bits | 0x03;
    Ok(encode_slot(opcode, dst, src, offset, 0))
}

fn size_letter_to_bits(suffix: &str) -> u8 {
    match suffix {
        "h" => 0x08,
        "b" => 0x10,
        "dw" => 0x18,
        // "w" and any other unrecognised suffix fall through
        // to the default W width (0x00). Unrecognised suffixes
        // are caught earlier by the dispatch table; this is a
        // belt-and-suspenders default.
        _ => 0x00,
    }
}

fn assemble_endian(mnemonic: &str, operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 1, mnemonic)?;
    let dst = parse_reg(operands[0])?;
    // "le" → opcode 0xd4 (ALU class + END op-nibble + imm
    // source). "be" → 0xdc (reg-source bit set).
    let opcode = match &mnemonic[..2] {
        "le" => 0xd4,
        "be" => 0xdc,
        _ => return Err(AssembleError::UnknownMnemonic(mnemonic.into())),
    };
    let width: i32 = match &mnemonic[2..] {
        "16" => 16,
        "32" => 32,
        "64" => 64,
        _ => return Err(AssembleError::UnknownMnemonic(mnemonic.into())),
    };
    Ok(encode_slot(opcode, dst, 0, 0, width))
}

fn assemble_ja(operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 1, "ja")?;
    let off = parse_branch_offset(operands[0])?;
    Ok(encode_slot(0x05, 0, 0, off, 0))
}

fn assemble_call(operands: &[&str], src: u8) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 1, "call")?;
    let imm = parse_int_signed(operands[0], "call")?;
    Ok(encode_slot(0x85, 0, src, 0, imm))
}

/// Linux BPF-to-BPF call: opcode `0x8d`, dst=0, src=0,
/// imm=signed slot count.
fn assemble_call_local(operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 1, "call_local")?;
    let imm = parse_int_signed(operands[0], "call_local")?;
    Ok(encode_slot(0x8d, 0, 0, 0, imm))
}

/// Like [`parse_int`] but accepts a leading `-` so callers
/// can pass signed slot counts (used by the desymbolised
/// `call_internal` form, whose imm may be negative when
/// calling a function earlier in the section).
fn parse_int_signed(text: &str, ctx: &'static str) -> Result<i32, AssembleError> {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix('-') {
        let v = parse_uint(rest, ctx)?;
        if v > 0x8000_0000 {
            return Err(AssembleError::ImmediateOverflow { value: v, bits: 32 });
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        return Ok(-(v as i64) as i32);
    }
    parse_int(t, ctx)
}

fn assemble_callx(operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    arity(operands, 1, "callx")?;
    let dst = parse_reg(operands[0])?;
    // callx encodes its register in `dst`; offset/imm zero.
    Ok(encode_slot(0x8d, dst, 0, 0, 0))
}

/// All ALU and conditional-jump mnemonics share the same
/// "{op}{suffix} dst, rhs" or "{op}{32} dst, rhs, +off"
/// surface. Dispatch by stripping the size suffix
/// ("32"/"64") and looking the op nibble up.
fn assemble_alu_or_jmp(mnemonic: &str, operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    // Determine size suffix.
    let (base, alu64, jmp32) = if let Some(b) = mnemonic.strip_suffix("64") {
        (b, true, false)
    } else if let Some(b) = mnemonic.strip_suffix("32") {
        // Either ALU32 (b is an ALU op like "add") or
        // JMP32 (b is a jcc like "jeq"). We decide later.
        (b, false, true)
    } else {
        (mnemonic, false, false)
    };

    // Jump opcodes (with optional 32-bit class).
    if let Some(op_nibble) = jmp_op_nibble(base) {
        return assemble_jmp(op_nibble, jmp32, operands);
    }

    // ALU opcodes. Resolve to op nibble + (alu64 default
    // when no suffix).
    let op_nibble =
        alu_op_nibble(base).ok_or_else(|| AssembleError::UnknownMnemonic(mnemonic.into()))?;
    let alu_class: u8 = if alu64 { 0x07 } else { 0x04 };

    if op_nibble == 0x8 {
        // NEG — single-operand unary.
        arity(operands, 1, mnemonic)?;
        let dst = parse_reg(operands[0])?;
        // No source bit (no src reg, no imm — pure unary
        // is encoded with the imm-source variant by
        // convention).
        let opcode = (op_nibble << 4) | alu_class;
        return Ok(encode_slot(opcode, dst, 0, 0, 0));
    }

    arity(operands, 2, mnemonic)?;
    let dst = parse_reg(operands[0])?;
    let (is_reg, src, imm) = parse_alu_rhs(operands[1])?;
    let src_bit: u8 = if is_reg { 0x08 } else { 0x00 };
    let opcode = (op_nibble << 4) | src_bit | alu_class;
    Ok(encode_slot(opcode, dst, src, 0, imm))
}

fn assemble_jmp(op_nibble: u8, is_32: bool, operands: &[&str]) -> Result<Vec<u8>, AssembleError> {
    let mnemonic_for_err = "jcc";
    if operands.len() != 3 {
        return Err(AssembleError::WrongArity {
            mnemonic: mnemonic_for_err.into(),
            expected: 3,
            got: operands.len(),
        });
    }
    let dst = parse_reg(operands[0])?;
    let (is_reg, src, imm) = parse_alu_rhs(operands[1])?;
    let off = parse_branch_offset(operands[2])?;
    let src_bit: u8 = if is_reg { 0x08 } else { 0x00 };
    let class: u8 = if is_32 { 0x06 } else { 0x05 };
    let opcode = (op_nibble << 4) | src_bit | class;
    Ok(encode_slot(opcode, dst, src, off, imm))
}

fn alu_op_nibble(base: &str) -> Option<u8> {
    // Covers Linux/sBPFv1/sBPFv2 mnemonics. Op nibble is
    // identical to the byte's high 4 bits — the variant
    // only changes the textual name.
    Some(match base {
        "add" => 0x0,
        "sub" => 0x1,
        "mul" => 0x2,
        "div" | "udiv" => 0x3,
        "or" => 0x4,
        "and" => 0x5,
        "lsh" => 0x6,
        "rsh" => 0x7,
        "neg" => 0x8,
        "mod" | "urem" => 0x9,
        "xor" => 0xa,
        "mov" => 0xb,
        "arsh" => 0xc,
        "sdiv" => 0xe,
        "srem" => 0xf,
        _ => return None,
    })
}

fn jmp_op_nibble(base: &str) -> Option<u8> {
    Some(match base {
        "jeq" => 0x1,
        "jgt" => 0x2,
        "jge" => 0x3,
        "jset" => 0x4,
        "jne" => 0x5,
        "jsgt" => 0x6,
        "jsge" => 0x7,
        "jlt" => 0xa,
        "jle" => 0xb,
        "jslt" => 0xc,
        "jsle" => 0xd,
        _ => return None,
    })
}

// ────────────────────────────────────────────────────────────
//  Operand parsing
// ────────────────────────────────────────────────────────────

fn split_operands(rest: &str) -> Vec<&str> {
    if rest.is_empty() {
        return Vec::new();
    }
    // `format_offset` produces shapes like "[r5 + 0x10]",
    // "[r5 - 0x10]", "[r5]". The contained " + " / " - " is
    // INSIDE brackets and must not split. Use a simple
    // bracket-depth-aware splitter.
    let mut out: Vec<&str> = Vec::new();
    let bytes = rest.as_bytes();
    let mut depth: i32 = 0;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(rest[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(rest[start..].trim());
    out
}

fn arity(operands: &[&str], expected: usize, mnemonic: &str) -> Result<(), AssembleError> {
    if operands.len() == expected {
        Ok(())
    } else {
        Err(AssembleError::WrongArity {
            mnemonic: mnemonic.into(),
            expected,
            got: operands.len(),
        })
    }
}

fn parse_reg(text: &str) -> Result<u8, AssembleError> {
    let t = text.trim();
    let rest = t
        .strip_prefix('r')
        .ok_or_else(|| AssembleError::BadOperand(t.into(), "register"))?;
    let n: u32 = rest
        .parse()
        .map_err(|_| AssembleError::BadOperand(t.into(), "register number"))?;
    if n > 10 {
        return Err(AssembleError::BadRegister(n));
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(n as u8)
}

/// Parse a u64 immediate as printed by `format_insn` —
/// `format!("0x{:x}", imm as u32)` for ALU/ldx/stx, or
/// `format!("0x{:x}", imm64)` for lddw. Accepts both `0x`
/// prefix and plain decimal.
fn parse_uint(text: &str, ctx: &'static str) -> Result<u64, AssembleError> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).map_err(|_| AssembleError::BadOperand(t.into(), ctx));
    }
    t.parse::<u64>()
        .map_err(|_| AssembleError::BadOperand(t.into(), ctx))
}

/// Parse a u32 immediate (or a sign-extendable u64 that
/// fits) into the i32 the BPF imm field carries. Matches
/// `format!("0x{:x}", imm as u32)` so the round-trip is
/// exact for any 32-bit pattern.
fn parse_int(text: &str, ctx: &'static str) -> Result<i32, AssembleError> {
    let v = parse_uint(text, ctx)?;
    if v > u64::from(u32::MAX) {
        return Err(AssembleError::ImmediateOverflow { value: v, bits: 32 });
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    Ok(v as u32 as i32)
}

fn parse_alu_rhs(text: &str) -> Result<(bool, u8, i32), AssembleError> {
    let t = text.trim();
    if t.starts_with('r') {
        let r = parse_reg(t)?;
        return Ok((true, r, 0));
    }
    let imm = parse_int(t, "alu rhs")?;
    Ok((false, 0, imm))
}

/// Parse `format_offset` shapes: `[rS]`, `[rS + 0xN]`,
/// `[rS - 0xN]`. Returns `(src, offset_i16)`.
fn parse_mem(text: &str) -> Result<(u8, i16), AssembleError> {
    let t = text.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| AssembleError::BadOperand(t.into(), "memory operand"))?
        .trim();
    // Split off a trailing " + 0x…" or " - 0x…".
    if let Some(idx) = inner.rfind(" + ") {
        let reg = parse_reg(inner[..idx].trim())?;
        let off = parse_offset_value(&inner[idx + 3..])?;
        let off_i16 = i16::try_from(off).map_err(|_| AssembleError::OffsetOverflow(off))?;
        return Ok((reg, off_i16));
    }
    if let Some(idx) = inner.rfind(" - ") {
        let reg = parse_reg(inner[..idx].trim())?;
        let off = parse_offset_value(&inner[idx + 3..])?;
        let neg = -off;
        let off_i16 = i16::try_from(neg).map_err(|_| AssembleError::OffsetOverflow(neg))?;
        return Ok((reg, off_i16));
    }
    Ok((parse_reg(inner)?, 0))
}

fn parse_offset_value(text: &str) -> Result<i64, AssembleError> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x") {
        let v = u64::from_str_radix(hex, 16)
            .map_err(|_| AssembleError::BadOperand(t.into(), "offset"))?;
        #[allow(clippy::cast_possible_wrap)]
        return Ok(v as i64);
    }
    t.parse::<i64>()
        .map_err(|_| AssembleError::BadOperand(t.into(), "offset"))
}

/// Parse `format_branch_offset` shapes: `+0xN` / `-0xN`.
fn parse_branch_offset(text: &str) -> Result<i16, AssembleError> {
    let t = text.trim();
    let (sign, rest) = if let Some(r) = t.strip_prefix('+') {
        (1i64, r)
    } else if let Some(r) = t.strip_prefix('-') {
        (-1i64, r)
    } else {
        return Err(AssembleError::BadOperand(t.into(), "branch offset"));
    };
    let v = if let Some(hex) = rest.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .map_err(|_| AssembleError::BadOperand(t.into(), "branch offset"))?
    } else {
        rest.parse::<u64>()
            .map_err(|_| AssembleError::BadOperand(t.into(), "branch offset"))?
    };
    #[allow(clippy::cast_possible_wrap)]
    let signed = sign * (v as i64);
    i16::try_from(signed).map_err(|_| AssembleError::OffsetOverflow(signed))
}

/// Convert a symbolic BPF @asm text — the form
/// `crates/ud-translate/src/decompile/bpf.rs` produces
/// after applying `label_<hex>` and `sub_<hex>` rewrites —
/// into the numeric form [`assemble_bpf`] accepts.
///
/// The rewrites both encode their target address into the
/// name (`label_4ab28` ↔ address 0x4ab28, same for
/// `sub_<hex>`). Recovering the address is therefore as
/// simple as parsing the hex suffix; no map lookup needed.
/// `insn_addr` is the address of the @asm being assembled
/// — branch offsets and internal-call imms are slot-relative
/// to the *next* instruction (insn_addr + 8).
///
/// When the input has no symbolic refs, the output is the
/// input unchanged. Returns `None` when a symbolic name
/// doesn't parse to a hex address — the caller treats that
/// the same as an assembler error and keeps the bytes
/// pinned.
#[must_use]
pub fn desymbolize_bpf_text(text: &str, insn_addr: u64, opcode_hint: Option<u8>) -> Option<String> {
    // Calls: `call sub_<hex>` → the right intra-program call
    // mnemonic. The opcode_hint tells us which encoding the
    // original byte stream used (`0x8d` = Linux BPF-to-BPF,
    // anything else = Solana sBPF with src=1). When the
    // caller doesn't know (lower path, no original bytes),
    // we default to `call_internal` (Solana sBPF), which
    // is the dominant convention.
    if let Some(rest) = text.strip_prefix("call sub_") {
        let target = u64::from_str_radix(rest.trim(), 16).ok()?;
        let next_slot = insn_addr.wrapping_add(INSN_SIZE as u64);
        #[allow(clippy::cast_possible_wrap)]
        let delta = (target as i64).wrapping_sub(next_slot as i64);
        if delta % (INSN_SIZE as i64) != 0 {
            return None;
        }
        let slot_count = delta / (INSN_SIZE as i64);
        let mnemonic = match opcode_hint {
            Some(0x8d) => "call_local",
            _ => "call_internal",
        };
        return Some(format!("{mnemonic} {slot_count}"));
    }

    // Conditional jumps + `ja`: replace a trailing
    // `, label_<hex>` (or `, label_<hex>` after the third
    // operand for `jXX`) with the slot-relative `+0xN` /
    // `-0xN` shape `assemble_bpf` parses.
    if let Some(label_at) = text.find(", label_").or_else(|| text.find(" label_")) {
        // Two shapes:
        //   `jXX rA, rhs, label_<hex>`  — JmpCond, 3 operands
        //   `ja label_<hex>`            — 1 operand
        let prefix = &text[..label_at];
        let suffix_offset = label_at
            + match text.as_bytes().get(label_at) {
                Some(b',') => 2, // ", "
                _ => 1,          // " "
            };
        let label_name = &text[suffix_offset..];
        let hex = label_name.strip_prefix("label_")?;
        let target = u64::from_str_radix(hex.trim(), 16).ok()?;
        let next_slot = insn_addr.wrapping_add(INSN_SIZE as u64);
        #[allow(clippy::cast_possible_wrap)]
        let delta = (target as i64).wrapping_sub(next_slot as i64);
        if delta % (INSN_SIZE as i64) != 0 {
            return None;
        }
        let slot_offset = delta / (INSN_SIZE as i64);
        let offset_text = if slot_offset >= 0 {
            format!("+0x{slot_offset:x}")
        } else {
            format!("-0x{:x}", -slot_offset)
        };
        let separator = if text.as_bytes().get(label_at) == Some(&b',') {
            ", "
        } else {
            " "
        };
        return Some(format!("{prefix}{separator}{offset_text}"));
    }

    // Nothing to de-symbolize — return as-is so the caller
    // can still attempt assembly on the pure-form path.
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, format_insn, BpfVariant};

    /// Round-trip property: for every decodable instruction
    /// the assembler reproduces the same bytes from the
    /// disassembled text.
    fn roundtrip(bytes: &[u8], variant: BpfVariant) {
        let insns = decode(bytes, 0, variant).expect("decode");
        let mut cursor = 0usize;
        for insn in &insns {
            let text = format_insn(insn, variant);
            let asm =
                assemble_bpf(&text).unwrap_or_else(|e| panic!("assemble failed: {text:?} → {e:?}"));
            assert_eq!(
                asm.as_slice(),
                &bytes[cursor..cursor + INSN_SIZE],
                "mismatch on {text:?}: assembled {asm:?}, original {:?}",
                &bytes[cursor..cursor + INSN_SIZE]
            );
            cursor += INSN_SIZE;
        }
    }

    #[test]
    fn alu_immediate_and_register() {
        roundtrip(
            &[
                0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r1, 42
                0xbf, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r1, r2
                0x07, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // add64 r1, 0x10
                0x0f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add64 r1, r2
                0xb4, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, // mov32 r3, 0xffffffff
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ],
            BpfVariant::Linux,
        );
    }

    #[test]
    fn loads_and_stores_all_widths() {
        roundtrip(
            &[
                0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, // ldxdw r1, [r10 - 8]
                0x71, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxb r2, [r1]
                0x69, 0x13, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxh r3, [r1 + 2]
                0x61, 0x14, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00, // ldxw r4, [r1 - 4]
                0x7b, 0x1a, 0xe0, 0xff, 0x00, 0x00, 0x00, 0x00, // stxdw [r10 - 32], r1
                0x73, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // stxb [r1], r2
                0x62, 0x0a, 0xf0, 0xff, 0x42, 0x00, 0x00, 0x00, // stw [r10 - 16], 0x42
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ],
            BpfVariant::Linux,
        );
    }

    #[test]
    fn branches_and_calls() {
        // jne (reg src) uses opcode 0x5d (op=jne, src=reg, class=JMP).
        // The src nibble in byte 1 carries the source register.
        roundtrip(
            &[
                0x15, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // jeq r1, 0, +2
                0x5d, 0x21, 0xfb, 0xff, 0x00, 0x00, 0x00, 0x00, // jne r1, r2, -5
                0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // ja +1
                0x85, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
                0x00, // call 0x7 (src=0, syscall-style)
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ],
            BpfVariant::Linux,
        );
    }

    /// When the disassembler can't infer the mnemonic
    /// from an opcode (e.g. an undefined op-nibble in a
    /// known class), the text comes out as `"<jcc?>"` /
    /// `"<alu?>"`. The assembler returns `Err(UnknownMnemonic)`
    /// for those — the decompile-time byte-drop pass treats
    /// the Err the same way it treats a parse failure: it
    /// keeps the pinned bytes.
    #[test]
    fn unrecognised_mnemonic_text_returns_err() {
        let err = assemble_bpf("<jcc?> r1, r2, +0x1").unwrap_err();
        assert!(matches!(err, AssembleError::UnknownMnemonic(_)));
    }

    /// `call sub_<hex>` desymbolises to `call_internal <slot_count>`,
    /// which assembles to opcode 0x85 with src=1 and the
    /// computed relative slot count in imm — matching the
    /// bytes Solana BPF emits for an intra-program call.
    #[test]
    fn desymbolise_internal_call_round_trips() {
        // Forward call from 0x1000 to 0x2000 — 0x1000 / 8 =
        // 0x200 slots forward; but the offset is computed
        // from the next slot (0x1008), so 0xff8 / 8 = 0x1ff slots.
        let text = "call sub_2000";
        let desym = desymbolize_bpf_text(text, 0x1000, None).unwrap();
        assert_eq!(desym, "call_internal 511"); // 0xff8 / 8 = 511
        let bytes = assemble_bpf(&desym).unwrap();
        assert_eq!(bytes[0], 0x85); // call opcode
        assert_eq!(bytes[1], 0x10); // src=1, dst=0
        let imm = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(imm, 511);
    }

    #[test]
    fn desymbolise_backward_call() {
        // Backward call: from 0x2000 to 0x1000.
        // Next slot = 0x2008, target = 0x1000, delta = -0x1008 / 8 = -513.
        let text = "call sub_1000";
        let desym = desymbolize_bpf_text(text, 0x2000, None).unwrap();
        assert_eq!(desym, "call_internal -513");
        let bytes = assemble_bpf(&desym).unwrap();
        let imm = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(imm, -513);
    }

    #[test]
    fn desymbolise_jcc_label_round_trips() {
        // jeq r1, 0x0, label_1010 at insn_addr 0x1000:
        //   next_slot = 0x1008, target = 0x1010, delta = 8,
        //   slot_offset = +1.
        let text = "jeq r1, 0x0, label_1010";
        let desym = desymbolize_bpf_text(text, 0x1000, None).unwrap();
        assert_eq!(desym, "jeq r1, 0x0, +0x1");
        let bytes = assemble_bpf(&desym).unwrap();
        assert_eq!(bytes[0], 0x15); // jeq imm-src JMP
        let off = i16::from_le_bytes(bytes[2..4].try_into().unwrap());
        assert_eq!(off, 1);
    }

    #[test]
    fn desymbolise_backward_jcc() {
        // jgt r2, r3, label_1000 at insn_addr 0x1020:
        //   next_slot = 0x1028, target = 0x1000, delta = -0x28,
        //   slot_offset = -5.
        let text = "jgt r2, r3, label_1000";
        let desym = desymbolize_bpf_text(text, 0x1020, None).unwrap();
        assert_eq!(desym, "jgt r2, r3, -0x5");
        let bytes = assemble_bpf(&desym).unwrap();
        let off = i16::from_le_bytes(bytes[2..4].try_into().unwrap());
        assert_eq!(off, -5);
    }

    #[test]
    fn desymbolise_ja_label() {
        // ja label_1008 at insn_addr 0x1000:
        //   next_slot = 0x1008, target = 0x1008, delta = 0.
        let text = "ja label_1008";
        let desym = desymbolize_bpf_text(text, 0x1000, None).unwrap();
        assert_eq!(desym, "ja +0x0");
        let bytes = assemble_bpf(&desym).unwrap();
        assert_eq!(bytes[0], 0x05);
        let off = i16::from_le_bytes(bytes[2..4].try_into().unwrap());
        assert_eq!(off, 0);
    }

    #[test]
    fn desymbolise_non_symbolic_text_passes_through() {
        let text = "ldxdw r0, [r5 - 0xff8]";
        assert_eq!(desymbolize_bpf_text(text, 0x1000, None).unwrap(), text);
    }

    #[test]
    fn desymbolise_syscall_call_falls_through_then_assemble_fails() {
        // `call sol_log_` has no `sub_<hex>` shape — it
        // returns unchanged. The caller then tries
        // assemble_bpf, which can't parse `sol_log_` as a
        // numeric imm and returns Err. The combined effect
        // is "byte-drop pass keeps bytes pinned" — exactly
        // what we want for syscall sites where we don't
        // know the imm.
        let through = desymbolize_bpf_text("call sol_log_", 0x1000, None).unwrap();
        assert_eq!(through, "call sol_log_");
        assert!(assemble_bpf(&through).is_err());
    }

    #[test]
    fn lddw_pair() {
        roundtrip(
            &[
                0x18, 0x01, 0x00, 0x00, 0xbe, 0xba, 0xfe, 0xca, // lddw r1, 0x...cafebabe
                0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, // continuation 0xdeadbeef
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ],
            BpfVariant::Linux,
        );
    }

    #[test]
    fn callx_and_exit() {
        roundtrip(
            &[
                0x8d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // callx r1
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ],
            BpfVariant::Sbfv1,
        );
    }

    #[test]
    fn endian_ops() {
        roundtrip(
            &[
                0xd4, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // le16 r1
                0xd4, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // le32 r2
                0xd4, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // le64 r3
                0xdc, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // be16 r4
                0xdc, 0x05, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // be64 r5
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ],
            BpfVariant::Linux,
        );
    }

    #[test]
    fn raw_bpf_form_passes_through() {
        // The `<bpf 0xNNN…>` fallback exists for forward-
        // compat with future decoder paths that may emit it
        // for truly unknown opcodes. Today no decoder path
        // produces it (every byte lands in one of the
        // class branches of `format_insn`), but the
        // assembler still accepts it so the round-trip
        // contract holds the day a new opcode arrives.
        let bytes = [0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let text = format!("<bpf 0x{:016x}>", u64::from_le_bytes(bytes));
        let asm = assemble_bpf(&text).unwrap();
        assert_eq!(asm.as_slice(), &bytes);
    }

    #[test]
    fn symbolic_text_not_recognised() {
        // The translation layer rewrites "call 0x..." into
        // "call sub_X" — that text is symbolic; the
        // assembler returns Err and the byte-drop pass
        // keeps the pinned bytes.
        let r = assemble_bpf("call sub_4ab28");
        assert!(matches!(r, Err(AssembleError::BadOperand(_, _))));
    }
}

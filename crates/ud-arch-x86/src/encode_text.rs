//! Minimal text → bytes encoder for the `cmp` / `test` instructions
//! that appear in `if (…)` cond text. Used by the source language to
//! omit `head_bytes` attributes when the encoding is the canonical
//! Intel form derivable from text alone — and to recover those
//! bytes on re-parse without needing the attribute.
//!
//! This is intentionally narrow: we don't ship a full text assembler.
//! Only the operand shapes the decompiler actually produces today
//! are recognised. Anything else returns `None`, leaving the caller
//! to keep the pinned bytes intact.
//!
//! Recognised forms (all 32-bit operand size):
//!
//! * `test reg, reg`               — same or different register
//! * `cmp  reg, reg`               — register / register compare
//! * `cmp  reg, imm`               — register / immediate compare
//! * `cmp  dword ptr [reg+disp], imm` — memory / immediate compare
//! * `cmp  dword ptr [reg+disp], 0` short form when imm fits in i8
//!
//! All forms use the canonical Intel encoding (e.g. `test r/m32, r32`
//! is `0x85 + ModRM`; sign-extended immediates pick the `imm8` opcode
//! variants over the longer `imm32` forms). When a compiler emits a
//! non-canonical encoding (rare but possible), `derive_from_text`
//! will return bytes that *don't* match the pinned ones — the caller
//! then keeps the `head_bytes` attribute.

/// Encode a `cmp`/`test` operand text (no jcc, no semicolon, no
/// leading mnemonic) to bytes. Returns `None` for unrecognised
/// shapes.
#[must_use]
pub fn encode_cmp_or_test(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("test ") {
        return encode_test(rest.trim());
    }
    if let Some(rest) = text.strip_prefix("cmp ") {
        return encode_cmp(rest.trim());
    }
    None
}

/// Convenience: pull the head out of a full cond text and encode it.
///
/// Accepts two cond-text dialects:
///
/// * **Assembly** — `"test esi,esi; jne short 18114h"`. The text
///   before the first `;` is the cmp/test; anything after is the
///   jcc (whose bytes depend on layout, not encodable from text).
/// * **C-style relational** — `"esi == 0"`, `"eax >= 5"`,
///   `"ebx <u ecx"`. The decompiler produces this when it can map
///   the cmp/jcc cleanly. The encoder picks the canonical cmp/test
///   form for the comparison: `test reg,reg` for `reg == 0`, `cmp
///   X,Y` otherwise.
#[must_use]
pub fn encode_head_from_cond_text(cond_text: &str) -> Option<Vec<u8>> {
    let head = cond_text.split(';').next()?.trim();
    if head.is_empty() {
        return None;
    }
    // Try the C-style form first; the assembly form falls out as
    // a fallback when the parse doesn't fit a relational shape.
    if let Some(bytes) = encode_relational(head) {
        return Some(bytes);
    }
    encode_cmp_or_test(head)
}

/// Try to encode a C-style relational expression like `"esi == 0"`
/// or `"eax <u 5"` as the canonical cmp/test bytes.
fn encode_relational(text: &str) -> Option<Vec<u8>> {
    let (lhs, op, rhs) = split_relational(text)?;
    // `reg <signed-op> 0` always encodes as `test reg, reg` — the
    // ZF / SF outcome of AND-ing the register with itself is the
    // same set of flags `cmp reg, 0` would produce, and `test`
    // saves one byte (no immediate). Excludes the `u`-suffixed
    // operators because unsigned-against-zero is degenerate.
    let is_signed_op = !op.ends_with('u');
    if is_signed_op && rhs == "0" {
        if let Some(r) = parse_reg32(lhs) {
            return Some(vec![0x85, mod_rm_reg_reg(r, r)]);
        }
        if let Some(r) = parse_reg8(lhs) {
            return Some(vec![0x84, mod_rm_reg_reg(r, r)]);
        }
    }
    // Everything else falls back to `cmp lhs, rhs`. The comparison
    // direction is encoded in the jcc (which we don't synthesise
    // here) — the cmp bytes are independent of `op` and signedness.
    encode_cmp(&format!("{lhs},{rhs}"))
}

/// Find the first top-level relational operator in `text` and split
/// around it. Operators tried from longest to shortest so `<u`
/// doesn't get partially-eaten as `<`.
fn split_relational(text: &str) -> Option<(&str, &str, &str)> {
    // Order matters: longer operators first.
    const OPS: &[&str] = &["<=u", ">=u", "<u", ">u", "==", "!=", "<=", ">=", "<", ">"];
    let mut depth = 0i32;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' => {
                depth += 1;
                i += 1;
                continue;
            }
            b')' | b']' => {
                depth -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        if depth == 0 {
            for op in OPS {
                if text[i..].starts_with(op) {
                    let lhs = text[..i].trim();
                    let rhs = text[i + op.len()..].trim();
                    if !lhs.is_empty() && !rhs.is_empty() {
                        return Some((lhs, op, rhs));
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn encode_test(operands: &str) -> Option<Vec<u8>> {
    let (a, b) = split_two(operands)?;
    // `test r/m32, r32` — opcode 0x85 + ModRM
    if let (Some(r1), Some(r2)) = (parse_reg32(a), parse_reg32(b)) {
        return Some(vec![0x85, mod_rm_reg_reg(r2, r1)]);
    }
    // `test r/m8, r8` — opcode 0x84 + ModRM (same ModRM layout,
    // different opcode and register encoding tables).
    if let (Some(r1), Some(r2)) = (parse_reg8(a), parse_reg8(b)) {
        return Some(vec![0x84, mod_rm_reg_reg(r2, r1)]);
    }
    None
}

fn encode_cmp(operands: &str) -> Option<Vec<u8>> {
    let (a, b) = split_two(operands)?;
    // `cmp r8, r8` — opcode 0x3A + ModRM
    if let (Some(r1), Some(r2)) = (parse_reg8(a), parse_reg8(b)) {
        return Some(vec![0x3A, mod_rm_reg_reg(r1, r2)]);
    }
    // `cmp reg, reg`
    if let (Some(r1), Some(r2)) = (parse_reg32(a), parse_reg32(b)) {
        // `cmp r32, r/m32` — opcode 0x3B + ModRM
        return Some(vec![0x3B, mod_rm_reg_reg(r1, r2)]);
    }
    // `cmp reg, imm`
    if let (Some(reg), Some(imm)) = (parse_reg32(a), parse_int_literal(b)) {
        return Some(encode_cmp_reg_imm(reg, imm, a == "eax"));
    }
    // `cmp reg, [mem]` — opcode 0x3B + memory ModRM
    if let (Some(reg), Some(mem)) = (parse_reg32(a), parse_mem_dword(b)) {
        return encode_modrm_mem(0x3B, reg, mem);
    }
    // `cmp [mem], reg` — opcode 0x39 + memory ModRM (reverse of 0x3B)
    if let (Some(mem), Some(reg)) = (parse_mem_dword(a), parse_reg32(b)) {
        return encode_modrm_mem(0x39, reg, mem);
    }
    // `cmp dword ptr [reg+disp], imm` or `cmp [reg+disp], imm`
    if let (Some(mem), Some(imm)) = (parse_mem_dword(a), parse_int_literal(b)) {
        return Some(encode_cmp_mem_imm(mem, imm));
    }
    None
}

/// A parsed memory operand. Two flavours:
///
/// * **Base + disp**: `[reg]`, `[reg+disp]`, `[reg-disp]`. The most
///   common case; uses register-relative ModRM bytes.
/// * **Absolute**: `[ADDR]` — no base register. Encoded with
///   `mod=00 rm=5` plus a 32-bit displacement (the x86 "moffs"
///   addressing mode).
#[derive(Clone, Copy)]
enum MemOperand {
    BasedDisp { base: u8, disp: i64 },
    Absolute { addr: u32 },
}

/// Encode a register/memory ModRM addressing pair: `<opcode>
/// <ModRM> [disp]`. `reg` is the "reg" field of ModRM. Returns
/// `None` for ESP-base operands which require a SIB byte we don't
/// model.
fn encode_modrm_mem(opcode: u8, reg: u8, mem: MemOperand) -> Option<Vec<u8>> {
    let mut out = vec![opcode];
    push_mem_modrm(&mut out, reg, mem)?;
    Some(out)
}

/// Push a memory-form ModRM byte (and any displacement) for the
/// given `reg` operand and parsed memory side.
fn push_mem_modrm(out: &mut Vec<u8>, reg_field: u8, mem: MemOperand) -> Option<()> {
    match mem {
        MemOperand::BasedDisp { base, disp } => {
            if base == 4 {
                return None;
            }
            let (mod_field, disp_bytes) = mem_mod_and_disp(base, disp);
            out.push((mod_field << 6) | (reg_field << 3) | base);
            out.extend_from_slice(&disp_bytes);
        }
        MemOperand::Absolute { addr } => {
            // mod=00 rm=5 = "disp32 absolute" addressing.
            out.push((reg_field << 3) | 0b101);
            out.extend_from_slice(&addr.to_le_bytes());
        }
    }
    Some(())
}

/// `cmp r/m32, imm8` (sign-extended) is `0x83 /7 imm8`; `cmp r/m32,
/// imm32` is `0x81 /7 imm32`; `cmp EAX, imm32` has its own one-byte
/// `0x3D` opcode (the accumulator shortcut). Pick the shortest form
/// the operand allows.
///
/// "Fits in a signed byte" is checked after reinterpreting the
/// immediate as a 32-bit two's-complement integer — `0xFFFFFFFF`
/// printed verbatim by the disassembler is the same 32 bits as
/// `-1`, and `-1` fits in `i8`. Without this step the encoder
/// would mistakenly take the `imm32` form for any high-bit-set
/// constant.
fn encode_cmp_reg_imm(reg: u8, imm: i64, reg_is_eax: bool) -> Vec<u8> {
    let imm32 = imm_as_i32(imm);
    if let Some(imm32) = imm32 {
        if let Ok(imm8) = i8::try_from(imm32) {
            return vec![0x83, mod_rm_op_reg(7, reg), imm8.to_ne_bytes()[0]];
        }
        if reg_is_eax {
            let mut out = vec![0x3D];
            out.extend_from_slice(&imm32.to_le_bytes());
            return out;
        }
        let mut out = vec![0x81, mod_rm_op_reg(7, reg)];
        out.extend_from_slice(&imm32.to_le_bytes());
        return out;
    }
    // Out-of-range constant — fall back to the imm32 form with a
    // truncated value. The caller still has the pinned `head_bytes`
    // to fall back on when this doesn't match.
    let mut out = vec![0x81, mod_rm_op_reg(7, reg)];
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let truncated = imm as u32;
    out.extend_from_slice(&truncated.to_le_bytes());
    out
}

/// Reinterpret an `i64` as a 32-bit two's-complement integer.
/// Accepts both signed (e.g. `-1`) and unsigned (e.g. `0xFFFFFFFF`)
/// representations; both produce the same `i32` value. Returns
/// `None` for values that don't fit either interpretation.
fn imm_as_i32(v: i64) -> Option<i32> {
    if (i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&v) {
        #[allow(clippy::cast_possible_truncation)]
        return Some(v as i32);
    }
    if (0..=i64::from(u32::MAX)).contains(&v) {
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap
        )]
        return Some(v as u32 as i32);
    }
    None
}

/// `cmp r/m32, imm` with a memory operand `[reg + disp]`. Uses the
/// `imm8` opcode (`0x83 /7`) when the immediate fits; `imm32`
/// (`0x81 /7`) otherwise. Memory addressing follows the canonical
/// ModRM/SIB rules: `disp8` when -128..=127, else `disp32`;
/// `[ebp+0]` always emits `mod=01 disp8=0` to disambiguate from the
/// special `mod=00 rm=5` form that means "disp32 absolute".
fn encode_cmp_mem_imm(mem: MemOperand, imm: i64) -> Vec<u8> {
    let imm32 = imm_as_i32(imm);
    let (opcode, imm_bytes) = match imm32 {
        Some(v) if i8::try_from(v).is_ok() => {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let b = v as u8;
            (0x83u8, vec![b])
        }
        Some(v) => (0x81u8, v.to_le_bytes().to_vec()),
        None => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let v = (imm as u32).to_le_bytes().to_vec();
            (0x81u8, v)
        }
    };
    let mut out = vec![opcode];
    // op-extension field "/7" goes in the reg slot of the memory
    // ModRM byte. Skip the ESP-base bail-out by checking now.
    if let MemOperand::BasedDisp { base: 4, .. } = mem {
        return Vec::new();
    }
    if push_mem_modrm(&mut out, 7, mem).is_none() {
        return Vec::new();
    }
    out.extend_from_slice(&imm_bytes);
    out
}

fn mem_mod_and_disp(reg_base: u8, disp: i64) -> (u8, Vec<u8>) {
    // EBP base with disp=0 still needs a disp8 to disambiguate from
    // mod=00 rm=5 (the "absolute displacement" encoding).
    if disp == 0 && reg_base != 5 {
        return (0b00, Vec::new());
    }
    if let Ok(disp8) = i8::try_from(disp) {
        return (0b01, vec![disp8.to_ne_bytes()[0]]);
    }
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let v = (disp as u32).to_le_bytes().to_vec();
    (0b10, v)
}

fn mod_rm_reg_reg(reg: u8, rm: u8) -> u8 {
    0b11_000_000 | (reg << 3) | rm
}

fn mod_rm_op_reg(op: u8, rm: u8) -> u8 {
    0b11_000_000 | (op << 3) | rm
}

fn split_two(s: &str) -> Option<(&str, &str)> {
    let comma = s.find(',')?;
    Some((s[..comma].trim(), s[comma + 1..].trim()))
}

fn parse_reg32(s: &str) -> Option<u8> {
    match s {
        "eax" => Some(0),
        "ecx" => Some(1),
        "edx" => Some(2),
        "ebx" => Some(3),
        // 4 = esp (avoided — needs SIB)
        "esp" => Some(4),
        "ebp" => Some(5),
        "esi" => Some(6),
        "edi" => Some(7),
        _ => None,
    }
}

/// Parse a memory operand. Recognised shapes:
///
/// * **Bracketed**: `[reg+disp]`, `[reg-disp]`, `[reg]`, `[ABS_ADDR]`,
///   with optional `dword ptr` / `qword ptr` prefix.
/// * **Named stack slot**: `arg_<hex>` / `var_<hex>` — the source
///   language's shorthand for `[ebp+<hex>]` / `[ebp-<hex>]`. Lets the
///   encoder process cond text that uses the renamed form straight
///   through to bytes.
///
/// Index/scale (`[reg+reg*N]`) and segment overrides aren't handled —
/// the decompiler doesn't put them in `if` cond text or `Stmt::Move`
/// operands today.
fn parse_mem_dword(s: &str) -> Option<MemOperand> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("arg_") {
        let off = u32::from_str_radix(rest, 16).ok()?;
        return Some(MemOperand::BasedDisp {
            base: 5, // ebp
            disp: i64::from(off),
        });
    }
    if let Some(rest) = s.strip_prefix("var_") {
        let off = u32::from_str_radix(rest, 16).ok()?;
        return Some(MemOperand::BasedDisp {
            base: 5, // ebp
            disp: -i64::from(off),
        });
    }
    let s = s.strip_prefix("dword ptr ").unwrap_or(s).trim();
    let s = s.strip_prefix("qword ptr ").unwrap_or(s).trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))?
        .trim();

    // Base + (optional) displacement.
    if let Some((base, disp_part)) = split_after_reg(inner) {
        if let Some(reg) = parse_reg32(base) {
            let disp = if disp_part.is_empty() {
                0i64
            } else {
                parse_int_literal(disp_part)?
            };
            return Some(MemOperand::BasedDisp { base: reg, disp });
        }
    }
    // Absolute address — just an integer literal between `[` `]`.
    if let Some(addr) = parse_int_literal(inner) {
        let addr32 = imm_as_i32(addr)?;
        #[allow(clippy::cast_sign_loss)]
        return Some(MemOperand::Absolute {
            addr: addr32 as u32,
        });
    }
    None
}

fn parse_reg8(s: &str) -> Option<u8> {
    match s {
        "al" => Some(0),
        "cl" => Some(1),
        "dl" => Some(2),
        "bl" => Some(3),
        "ah" => Some(4),
        "ch" => Some(5),
        "dh" => Some(6),
        "bh" => Some(7),
        _ => None,
    }
}

/// Split `"ebp+8"` / `"ebp-4"` / `"esi"` into `("ebp", "+8")` etc.
/// Returns the bare register name and the signed-displacement
/// suffix (which may be empty when there's no displacement).
fn split_after_reg(s: &str) -> Option<(&str, &str)> {
    let s = s.trim();
    // The register name is the leading run of letters. Anything
    // after (whitespace, sign, digits, …) is the displacement.
    let end = s
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    let (reg, rest) = s.split_at(end);
    Some((reg, rest.trim()))
}

/// Parse a signed integer literal in any of the forms used by
/// iced's Intel formatter (and the source language):
/// `0x1F`, `0X1F`, `1Fh`, `8`, `-4`.
fn parse_int_literal(s: &str) -> Option<i64> {
    let s = s.trim();
    let (sign, body) = if let Some(rest) = s.strip_prefix('-') {
        (-1i64, rest.trim())
    } else if let Some(rest) = s.strip_prefix('+') {
        (1i64, rest.trim())
    } else {
        (1i64, s)
    };
    let unsigned = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = body.strip_suffix('h').or_else(|| body.strip_suffix('H')) {
        // The Intel-formatter convention sometimes writes hex with a
        // leading `0` so it parses as a digit run; strip that too.
        i64::from_str_radix(hex, 16).ok()?
    } else {
        body.parse::<i64>().ok()?
    };
    Some(sign * unsigned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_reg_same_register() {
        assert_eq!(encode_cmp_or_test("test eax,eax"), Some(vec![0x85, 0xc0]));
        assert_eq!(encode_cmp_or_test("test esi,esi"), Some(vec![0x85, 0xf6]));
        assert_eq!(encode_cmp_or_test("test edi,edi"), Some(vec![0x85, 0xff]));
        assert_eq!(encode_cmp_or_test("test ecx,ecx"), Some(vec![0x85, 0xc9]));
        assert_eq!(encode_cmp_or_test("test ebp,ebp"), Some(vec![0x85, 0xed]));
    }

    #[test]
    fn test_reg_reg_different_registers() {
        // test r/m32, r32 — ModRM = 11 reg rm. For `test ebx, eax`,
        // reg=eax(0), rm=ebx(3) → 0xC3.
        assert_eq!(encode_cmp_or_test("test ebx,eax"), Some(vec![0x85, 0xc3]));
    }

    #[test]
    fn cmp_reg_imm8() {
        // 0x83 /7 imm8
        assert_eq!(
            encode_cmp_or_test("cmp esi,1"),
            Some(vec![0x83, 0xfe, 0x01])
        );
        assert_eq!(
            encode_cmp_or_test("cmp esi,2"),
            Some(vec![0x83, 0xfe, 0x02])
        );
        assert_eq!(
            encode_cmp_or_test("cmp eax,0"),
            Some(vec![0x83, 0xf8, 0x00])
        );
    }

    #[test]
    fn cmp_reg_imm32() {
        // `cmp eax, imm32` uses the accumulator shortcut `0x3D`, not
        // the general-purpose `0x81 /7` encoding. Both encode the
        // same operation but msvc/gcc/clang all pick the 1-byte
        // shorter form when the destination is EAX.
        assert_eq!(
            encode_cmp_or_test("cmp eax,0x10000"),
            Some(vec![0x3d, 0x00, 0x00, 0x01, 0x00])
        );
        // For a non-EAX register the general form is used.
        assert_eq!(
            encode_cmp_or_test("cmp ebx,0x10000"),
            Some(vec![0x81, 0xfb, 0x00, 0x00, 0x01, 0x00])
        );
    }

    #[test]
    fn cmp_mem_absolute_imm() {
        // `cmp dword ptr [1C26D368h], 7`: mod=00 rm=5 (absolute) →
        // ModRM = (0 << 6) | (7 << 3) | 5 = 0x3D. Wait — that's
        // 0x3D but the actual encoding is `0x83 0x3D <addr> imm8`.
        assert_eq!(
            encode_cmp_or_test("cmp dword ptr [1C26D368h],7"),
            Some(vec![0x83, 0x3d, 0x68, 0xd3, 0x26, 0x1c, 0x07])
        );
    }

    #[test]
    fn cmp_mem_with_indexed_base() {
        // `cmp [esi+4E0h],ebx` — mod=10 rm=esi(6) disp32, reg=ebx(3)
        // ModRM = (10 << 6) | (3 << 3) | 6 = 0x9E.
        assert_eq!(
            encode_cmp_or_test("cmp [esi+4E0h],ebx"),
            Some(vec![0x39, 0x9e, 0xe0, 0x04, 0x00, 0x00])
        );
    }

    #[test]
    fn cmp_reg_mem() {
        // `cmp eax,[ebp-14h]` — opcode 0x3B + ModRM (mod=01 rm=ebp(5) reg=eax(0))
        assert_eq!(
            encode_cmp_or_test("cmp eax,[ebp-14h]"),
            Some(vec![0x3b, 0x45, 0xec])
        );
    }

    #[test]
    fn test_reg8_reg8() {
        // `test al,al` — opcode 0x84 + ModRM
        assert_eq!(encode_cmp_or_test("test al,al"), Some(vec![0x84, 0xc0]));
        // `test bl,bl` — opcode 0x84 + ModRM (rm/reg = bl=3)
        assert_eq!(encode_cmp_or_test("test bl,bl"), Some(vec![0x84, 0xdb]));
    }

    #[test]
    fn cmp_reg8_reg8() {
        // `cmp dl,bl` — opcode 0x3A + ModRM
        assert_eq!(encode_cmp_or_test("cmp dl,bl"), Some(vec![0x3a, 0xd3]));
    }

    #[test]
    fn cmp_reg_reg() {
        // 0x3B + ModRM: cmp r32, r/m32. For `cmp eax,ebx`, reg=eax(0), rm=ebx(3) → 0xC3.
        assert_eq!(encode_cmp_or_test("cmp eax,ebx"), Some(vec![0x3b, 0xc3]));
    }

    #[test]
    fn cmp_mem_imm_short_displacement() {
        // `cmp dword ptr [edi+0A0h],0` → 0x83 /7 disp32 imm8 (since
        // 0xA0 = 160 doesn't fit in i8 → disp32). Wait — 0xA0 IS
        // 160, which is > 127 → disp32 needed.
        assert_eq!(
            encode_cmp_or_test("cmp dword ptr [edi+0A0h],0"),
            Some(vec![0x83, 0xbf, 0xa0, 0x00, 0x00, 0x00, 0x00])
        );
    }

    #[test]
    fn cmp_mem_imm_small_displacement() {
        // [ebp-4] uses mod=01 disp8=fc, base=ebp(5)
        // ModRM = 01 111 101 = 0x7d
        assert_eq!(
            encode_cmp_or_test("cmp [ebp-4],1"),
            Some(vec![0x83, 0x7d, 0xfc, 0x01])
        );
    }

    #[test]
    fn from_cond_text_strips_jcc() {
        assert_eq!(
            encode_head_from_cond_text("test esi,esi; jne short 18114h"),
            Some(vec![0x85, 0xf6])
        );
    }

    #[test]
    fn unrecognised_returns_none() {
        assert_eq!(encode_cmp_or_test("nop"), None);
        assert_eq!(encode_cmp_or_test("test xmm0,xmm0"), None);
    }
}

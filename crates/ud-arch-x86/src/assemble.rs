//! Text → bytes assembler for the canonical Intel syntax that
//! [`format_intel`](crate::format_intel) produces.
//!
//! Bridge between human-readable `@asm("…")` text and the iced
//! encoder. Built deliberately small — only the operand shapes
//! the decompiler actually emits are recognised, and a fixture
//! coverage survey (`testdata/`) identifies which forms those
//! are. Forms we don't yet recognise return
//! [`AssembleError::Unsupported`] so callers can fall back to
//! the pinned bytes — no silent miscoding.
//!
//! Today's coverage is the zero-operand mnemonics
//! (`endbr64`, `hlt`, `nop`, `int3`, `ret`, `cdqe`, `cwde`,
//! `leave`, …). Each future commit adds another operand shape
//! once the encoder + a round-trip test for it land.
//!
//! The parser is whitespace + comma tokenized; case folding is
//! applied so `MOV RAX, RBX` and `mov rax,rbx` parse to the
//! same Instruction.

use iced_x86::{Code, Encoder, Instruction, Register};

use crate::Bitness;

/// Errors raised by [`assemble_intel`].
#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    /// The text is empty.
    #[error("empty text — assembler needs at least a mnemonic")]
    Empty,

    /// The mnemonic + operand shape isn't covered yet. Callers
    /// fall back to pinned bytes when they see this — it's not
    /// a hard error, just a "we don't ship this form yet"
    /// signal.
    #[error("unsupported instruction form {form:?}")]
    Unsupported { form: String },

    /// iced rejected the candidate encoding. The same
    /// `(Code, operands)` tuple round-trips perfectly elsewhere,
    /// so this is rare — it usually means the operand kinds we
    /// picked don't match what `Code` wants (encoder bug on
    /// our side, not iced's).
    #[error("iced encode failed: {message}")]
    EncodeFailed { message: String },
}

/// Parse `text` as a single x86 instruction in canonical Intel
/// syntax and encode it to bytes at `rip`. Returns the encoded
/// bytes when the form is recognised, or
/// [`AssembleError::Unsupported`] when it isn't.
///
/// `rip` only matters for RIP-relative encodings (`mov rax,
/// [rip+disp]`, `jmp 0x1234`, etc.); zero-operand forms ignore
/// it.
pub fn assemble_intel(bitness: Bitness, text: &str, rip: u64) -> Result<Vec<u8>, AssembleError> {
    let normalized = normalize(text);
    if normalized.is_empty() {
        return Err(AssembleError::Empty);
    }
    let insn = parse_text(&normalized, bitness)?;
    encode_insn(&insn, bitness, rip)
}

/// Lowercase + collapse runs of whitespace + strip the trailing
/// newline. The decoder's canonical output uses lowercase, but
/// hand-written text often has stray capitals or doubled
/// spaces — fold those out before tokenising.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = true;
    for c in text.chars() {
        if c.is_ascii_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.extend(c.to_lowercase());
            prev_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Split a normalized Intel-syntax line into the mnemonic
/// (possibly with a leading "notrack" prefix) and the rest. The
/// caller dispatches per-mnemonic.
fn split_mnemonic_and_rest(s: &str) -> (&str, &str) {
    // `notrack jmp …` and `notrack call …` carry a CET prefix;
    // strip it for dispatching but remember it so the encoder
    // can put the 0x3e back. Today every zero-operand form we
    // handle lacks this prefix, so we don't yet propagate it.
    let s = s.strip_prefix("notrack ").unwrap_or(s);
    match s.find(' ') {
        Some(i) => (&s[..i], s[i + 1..].trim_start()),
        None => (s, ""),
    }
}

fn parse_text(text: &str, bitness: Bitness) -> Result<Instruction, AssembleError> {
    let (mnemonic, operands) = split_mnemonic_and_rest(text);
    if operands.is_empty() {
        let code = zero_operand_code(mnemonic).ok_or_else(|| AssembleError::Unsupported {
            form: text.to_string(),
        })?;
        return Ok(Instruction::with(code));
    }

    let ops = split_operands(operands);
    match ops.as_slice() {
        [a] => parse_single_operand(mnemonic, a, bitness, text),
        [a, b] => parse_two_operand(mnemonic, a, b, bitness, text),
        _ => Err(AssembleError::Unsupported {
            form: text.to_string(),
        }),
    }
}

/// Comma-split a normalized operand list, ignoring commas
/// inside `[ … ]` memory operands.
fn split_operands(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

fn parse_single_operand(
    mnemonic: &str,
    operand: &str,
    bitness: Bitness,
    text: &str,
) -> Result<Instruction, AssembleError> {
    // Register operand?
    if let Some(reg) = parse_register(operand) {
        let code = match mnemonic {
            "push" => match register_width(reg) {
                Some(64) => Code::Push_r64,
                Some(32) => Code::Push_r32,
                Some(16) => Code::Push_r16,
                _ => return unsupported(text),
            },
            "pop" => match register_width(reg) {
                Some(64) => Code::Pop_r64,
                Some(32) => Code::Pop_r32,
                Some(16) => Code::Pop_r16,
                _ => return unsupported(text),
            },
            "call" => match (bitness, register_width(reg)) {
                (Bitness::Bits64, Some(64)) => Code::Call_rm64,
                (Bitness::Bits32 | Bitness::Bits16, Some(32)) => Code::Call_rm32,
                _ => return unsupported(text),
            },
            "jmp" => match (bitness, register_width(reg)) {
                (Bitness::Bits64, Some(64)) => Code::Jmp_rm64,
                (Bitness::Bits32 | Bitness::Bits16, Some(32)) => Code::Jmp_rm32,
                _ => return unsupported(text),
            },
            _ => return unsupported(text),
        };
        return Instruction::with1(code, reg).map_err(|e| AssembleError::EncodeFailed {
            message: format!("{e:?}"),
        });
    }

    // Immediate operand?
    if let Some(imm) = parse_immediate(operand) {
        match mnemonic {
            "push" => {
                // Pick the shorter encoding when the immediate
                // fits sign-extended in 8 bits. iced's decoder
                // prefers the imm8 form when the source bytes
                // pick it, so we have to match that choice on
                // re-encode for the round-trip to hold.
                let (code, value): (Code, i64) = if (-128..=127).contains(&imm) {
                    (Code::Pushq_imm8, imm)
                } else {
                    (Code::Pushq_imm32, imm)
                };
                return Instruction::with1::<i32>(code, value as i32).map_err(|e| {
                    AssembleError::EncodeFailed {
                        message: format!("{e:?}"),
                    }
                });
            }
            _ => return unsupported(text),
        }
    }

    // Memory operand?
    if let Some(mem) = parse_memory(operand) {
        let code = match mnemonic {
            "call" => match (bitness, mem.size_hint) {
                (Bitness::Bits64, Some(MemSize::Qword)) => Code::Call_rm64,
                (Bitness::Bits32 | Bitness::Bits16, Some(MemSize::Dword)) => Code::Call_rm32,
                _ => return unsupported(text),
            },
            "jmp" => match (bitness, mem.size_hint) {
                (Bitness::Bits64, Some(MemSize::Qword)) => Code::Jmp_rm64,
                (Bitness::Bits32 | Bitness::Bits16, Some(MemSize::Dword)) => Code::Jmp_rm32,
                _ => return unsupported(text),
            },
            "nop" => match mem.size_hint {
                // The Intel formatter omits the size prefix for
                // `nop [mem]`. Decoded bytes `0F 1F /0` are
                // `Nop_rm32` (default 32-bit operand size in
                // 64-bit mode — no REX.W). Same opcode + REX.W
                // would be `Nop_rm64` but the decoder spells
                // that "nop qword ptr [mem]", which we don't
                // see in our output.
                Some(MemSize::None) => Code::Nop_rm32,
                _ => return unsupported(text),
            },
            _ => return unsupported(text),
        };
        let mem_op = build_memory_operand(&mem)?;
        return Instruction::with1::<iced_x86::MemoryOperand>(code, mem_op).map_err(|e| {
            AssembleError::EncodeFailed {
                message: format!("{e:?}"),
            }
        });
    }

    unsupported(text)
}

fn parse_two_operand(
    mnemonic: &str,
    a: &str,
    b: &str,
    _bitness: Bitness,
    text: &str,
) -> Result<Instruction, AssembleError> {
    let (Some(ra), Some(rb)) = (parse_register(a), parse_register(b)) else {
        return unsupported(text);
    };
    let wa = register_width(ra).ok_or_else(|| AssembleError::Unsupported {
        form: text.to_string(),
    })?;
    let wb = register_width(rb).ok_or_else(|| AssembleError::Unsupported {
        form: text.to_string(),
    })?;
    if wa != wb {
        return unsupported(text);
    }
    let code = match mnemonic {
        "xchg" => match wa {
            64 => Code::Xchg_rm64_r64,
            32 => Code::Xchg_rm32_r32,
            16 => Code::Xchg_rm16_r16,
            8 => Code::Xchg_rm8_r8,
            _ => return unsupported(text),
        },
        "mov" => match wa {
            64 => Code::Mov_rm64_r64,
            32 => Code::Mov_rm32_r32,
            16 => Code::Mov_rm16_r16,
            8 => Code::Mov_rm8_r8,
            _ => return unsupported(text),
        },
        _ => return unsupported(text),
    };
    Instruction::with2(code, ra, rb).map_err(|e| AssembleError::EncodeFailed {
        message: format!("{e:?}"),
    })
}

fn unsupported(text: &str) -> Result<Instruction, AssembleError> {
    Err(AssembleError::Unsupported {
        form: text.to_string(),
    })
}

/// Parse a hex (`0x…`) or decimal immediate. Returns `None` for
/// anything else (register names, brackets, etc.); the caller
/// falls through to other operand kinds.
fn parse_immediate(s: &str) -> Option<i64> {
    let neg = s.starts_with('-');
    let body = s.strip_prefix('-').unwrap_or(s);
    let v: i64 = if let Some(rest) = body.strip_prefix("0x") {
        i64::from_str_radix(rest, 16).ok()?
    } else if body.chars().all(|c| c.is_ascii_digit()) && !body.is_empty() {
        body.parse().ok()?
    } else {
        return Option::None;
    };
    Some(if neg { -v } else { v })
}

/// Memory operand size prefix in canonical iced output:
/// `byte ptr`, `word ptr`, `dword ptr`, `qword ptr`, plus
/// `xmmword ptr` / `ymmword ptr` for SSE/AVX. `None` indicates
/// no explicit size prefix, which is what `nop [rax]` uses
/// (size implied by the mnemonic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemSize {
    None,
    Byte,
    Word,
    Dword,
    Qword,
}

#[derive(Debug, Clone)]
struct ParsedMemory {
    size_hint: Option<MemSize>,
    base: Register,
    index: Register,
    scale: u32,
    displacement: i64,
}

/// Parse a memory operand like `[rax]`, `[rax+rbx]`,
/// `qword ptr [0x3fb8]`, `dword ptr [rbp-4]`. Returns `None`
/// if the token doesn't have the expected `[…]` shape, so the
/// caller can fall through to other operand kinds.
fn parse_memory(s: &str) -> Option<ParsedMemory> {
    let (size_hint, body) = parse_size_prefix(s);
    let inner = body.strip_prefix('[')?.strip_suffix(']')?;
    let inner = inner.trim();

    // Split on '+' and '-' while preserving the sign.
    let mut base = Register::None;
    let mut index = Register::None;
    let mut scale: u32 = 1;
    let mut disp: i64 = 0;

    for (sign, term) in tokenize_addr(inner) {
        let term = term.trim();
        // `reg*scale`?
        if let Some((reg_part, scale_part)) = term.split_once('*') {
            let r = parse_register(reg_part.trim())?;
            let sc: u32 = scale_part.trim().parse().ok()?;
            if index != Register::None {
                return Option::None;
            }
            index = r;
            scale = sc;
            continue;
        }
        // Plain register?
        if let Some(r) = parse_register(term) {
            if base == Register::None {
                base = r;
            } else if index == Register::None {
                index = r;
            } else {
                return Option::None;
            }
            continue;
        }
        // Immediate displacement?
        if let Some(v) = parse_immediate(term) {
            disp = disp.checked_add(if sign { -v } else { v })?;
            continue;
        }
        return Option::None;
    }
    Some(ParsedMemory {
        size_hint: Some(size_hint),
        base,
        index,
        scale,
        displacement: disp,
    })
}

fn parse_size_prefix(s: &str) -> (MemSize, &str) {
    for (prefix, sz) in &[
        ("qword ptr ", MemSize::Qword),
        ("dword ptr ", MemSize::Dword),
        ("word ptr ", MemSize::Word),
        ("byte ptr ", MemSize::Byte),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return (*sz, rest);
        }
    }
    (MemSize::None, s)
}

/// Split `rax+rbx*4-0x10` into `[(false, "rax"), (false, "rbx*4"),
/// (true, "0x10")]`. The first term has an implicit `+` sign.
fn tokenize_addr(s: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut neg = false;
    for (i, c) in s.char_indices() {
        if (c == '+' || c == '-') && i > start {
            out.push((neg, &s[start..i]));
            neg = c == '-';
            start = i + 1;
        }
    }
    out.push((neg, &s[start..]));
    out
}

fn build_memory_operand(mem: &ParsedMemory) -> Result<iced_x86::MemoryOperand, AssembleError> {
    use iced_x86::MemoryOperand;
    // The `displ_size` parameter selects the encoded displacement
    // width. Picking 0 lets iced choose the shortest legal
    // form. For absolute `[0x…]` addresses in 64-bit mode iced
    // wires it through as a RIP-relative or absolute encoding
    // depending on context — that's handled by the encoder
    // itself when we feed `Register::None` as the base.
    Ok(MemoryOperand::with_base_index_scale_displ_size(
        mem.base,
        mem.index,
        mem.scale,
        mem.displacement,
        if mem.displacement == 0 && mem.base != Register::None && mem.index == Register::None {
            0
        } else {
            // Let iced pick (most likely 4 bytes for absolute).
            0
        },
    ))
}

/// Map a canonical x86 register name to iced's `Register` enum.
/// Lower-case input (`rax`, `eax`, `ax`, `al`, `ah`, `r8`, `r8d`,
/// `r8w`, `r8b`, `xmm0` …); anything we don't recognise returns
/// `None` so the caller can surface `Unsupported`.
fn parse_register(name: &str) -> Option<Register> {
    use Register::*;
    Some(match name {
        // 64-bit
        "rax" => RAX, "rcx" => RCX, "rdx" => RDX, "rbx" => RBX,
        "rsp" => RSP, "rbp" => RBP, "rsi" => RSI, "rdi" => RDI,
        "r8" => R8, "r9" => R9, "r10" => R10, "r11" => R11,
        "r12" => R12, "r13" => R13, "r14" => R14, "r15" => R15,
        // 32-bit
        "eax" => EAX, "ecx" => ECX, "edx" => EDX, "ebx" => EBX,
        "esp" => ESP, "ebp" => EBP, "esi" => ESI, "edi" => EDI,
        "r8d" => R8D, "r9d" => R9D, "r10d" => R10D, "r11d" => R11D,
        "r12d" => R12D, "r13d" => R13D, "r14d" => R14D, "r15d" => R15D,
        // 16-bit
        "ax" => AX, "cx" => CX, "dx" => DX, "bx" => BX,
        "sp" => SP, "bp" => BP, "si" => SI, "di" => DI,
        "r8w" => R8W, "r9w" => R9W, "r10w" => R10W, "r11w" => R11W,
        "r12w" => R12W, "r13w" => R13W, "r14w" => R14W, "r15w" => R15W,
        // 8-bit
        "al" => AL, "cl" => CL, "dl" => DL, "bl" => BL,
        "ah" => AH, "ch" => CH, "dh" => DH, "bh" => BH,
        "spl" => SPL, "bpl" => BPL, "sil" => SIL, "dil" => DIL,
        "r8b" | "r8l" => R8L, "r9b" | "r9l" => R9L,
        "r10b" | "r10l" => R10L, "r11b" | "r11l" => R11L,
        "r12b" | "r12l" => R12L, "r13b" | "r13l" => R13L,
        "r14b" | "r14l" => R14L, "r15b" | "r15l" => R15L,
        // XMM
        "xmm0" => XMM0, "xmm1" => XMM1, "xmm2" => XMM2, "xmm3" => XMM3,
        "xmm4" => XMM4, "xmm5" => XMM5, "xmm6" => XMM6, "xmm7" => XMM7,
        "xmm8" => XMM8, "xmm9" => XMM9, "xmm10" => XMM10, "xmm11" => XMM11,
        "xmm12" => XMM12, "xmm13" => XMM13, "xmm14" => XMM14, "xmm15" => XMM15,
        _ => return Option::None, // ::None to avoid Register::None from the glob.
    })
}

/// Operand bit width for a general-purpose register. XMM and
/// segment registers return `None` because they use different
/// encoders.
fn register_width(reg: Register) -> Option<u32> {
    use Register::*;
    match reg {
        RAX | RCX | RDX | RBX | RSP | RBP | RSI | RDI | R8 | R9 | R10 | R11 | R12 | R13 | R14
        | R15 => Some(64),
        EAX | ECX | EDX | EBX | ESP | EBP | ESI | EDI | R8D | R9D | R10D | R11D | R12D | R13D
        | R14D | R15D => Some(32),
        AX | CX | DX | BX | SP | BP | SI | DI | R8W | R9W | R10W | R11W | R12W | R13W | R14W
        | R15W => Some(16),
        AL | CL | DL | BL | AH | CH | DH | BH | SPL | BPL | SIL | DIL | R8L | R9L | R10L | R11L
        | R12L | R13L | R14L | R15L => Some(8),
        _ => Option::None, // ::None to avoid Register::None from the glob.
    }
}

/// Iced's `Code` for every zero-operand mnemonic we currently
/// emit. Add entries here as new mnemonics surface — the
/// coverage survey (`tests/assemble_coverage.rs`) keeps the set
/// honest.
fn zero_operand_code(mnemonic: &str) -> Option<Code> {
    Some(match mnemonic {
        "endbr64" => Code::Endbr64,
        "endbr32" => Code::Endbr32,
        "hlt" => Code::Hlt,
        "nop" => Code::Nopd,
        "int3" => Code::Int3,
        "ret" => Code::Retnq,
        "retq" => Code::Retnq,
        "retn" => Code::Retnd,
        "cdqe" => Code::Cdqe,
        "cwde" => Code::Cwde,
        "cbw" => Code::Cbw,
        "leave" | "leaveq" => Code::Leaveq,
        "syscall" => Code::Syscall,
        "ud2" => Code::Ud2,
        "pause" => Code::Pause,
        "rdtsc" => Code::Rdtsc,
        "cpuid" => Code::Cpuid,
        _ => return None,
    })
}

fn encode_insn(insn: &Instruction, bitness: Bitness, rip: u64) -> Result<Vec<u8>, AssembleError> {
    let mut encoder = Encoder::new(bitness.as_u32());
    encoder
        .encode(insn, rip)
        .map_err(|e| AssembleError::EncodeFailed {
            message: format!("{e:?}"),
        })?;
    Ok(encoder.take_buffer())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, format_intel};

    #[track_caller]
    fn round_trip(bitness: Bitness, text: &str, expected: &[u8]) {
        let bytes =
            assemble_intel(bitness, text, 0x1000).unwrap_or_else(|e| panic!("assemble {text:?}: {e}"));
        assert_eq!(
            bytes, expected,
            "bytes mismatch for {text:?}: got {bytes:02x?}, want {expected:02x?}"
        );
        // Decode the freshly-encoded bytes and confirm the
        // canonical text matches what we asked for.
        let insns = decode(bitness, &bytes, 0x1000).expect("decode round-trip");
        assert_eq!(insns.len(), 1, "expected single instruction");
        let canonical = format_intel(&insns[0].iced);
        assert_eq!(
            normalize(&canonical),
            normalize(text),
            "canonical text diverges"
        );
    }

    #[test]
    fn zero_operand_x86_64() {
        round_trip(Bitness::Bits64, "endbr64", &[0xf3, 0x0f, 0x1e, 0xfa]);
        round_trip(Bitness::Bits64, "hlt", &[0xf4]);
        round_trip(Bitness::Bits64, "nop", &[0x90]);
        round_trip(Bitness::Bits64, "int3", &[0xcc]);
        round_trip(Bitness::Bits64, "ret", &[0xc3]);
        round_trip(Bitness::Bits64, "cdqe", &[0x48, 0x98]);
        round_trip(Bitness::Bits64, "leave", &[0xc9]);
        round_trip(Bitness::Bits64, "syscall", &[0x0f, 0x05]);
        round_trip(Bitness::Bits64, "ud2", &[0x0f, 0x0b]);
    }

    #[test]
    fn zero_operand_normalizes_case_and_whitespace() {
        round_trip(Bitness::Bits64, "  ENDBR64  ", &[0xf3, 0x0f, 0x1e, 0xfa]);
    }

    #[test]
    fn unknown_mnemonic_returns_unsupported() {
        match assemble_intel(Bitness::Bits64, "completely-fake-insn", 0x1000) {
            Err(AssembleError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn empty_text_returns_empty_error() {
        match assemble_intel(Bitness::Bits64, "", 0x1000) {
            Err(AssembleError::Empty) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn push_pop_register_x86_64() {
        round_trip(Bitness::Bits64, "push rax", &[0x50]);
        round_trip(Bitness::Bits64, "push rdi", &[0x57]);
        round_trip(Bitness::Bits64, "push r8", &[0x41, 0x50]);
        round_trip(Bitness::Bits64, "push r15", &[0x41, 0x57]);
        round_trip(Bitness::Bits64, "pop rax", &[0x58]);
        round_trip(Bitness::Bits64, "pop r12", &[0x41, 0x5c]);
    }

    #[test]
    fn xchg_register_register_x86_64() {
        // xchg rcx,rcx — used as a 3-byte NOP pad by some
        // compilers when they need to fill an exact slot.
        round_trip(Bitness::Bits64, "xchg rcx,rcx", &[0x48, 0x87, 0xc9]);
        round_trip(Bitness::Bits64, "xchg eax,edx", &[0x87, 0xd0]);
    }

    #[test]
    fn mov_register_register_x86_64() {
        round_trip(Bitness::Bits64, "mov rax,rbx", &[0x48, 0x89, 0xd8]);
        round_trip(Bitness::Bits64, "mov eax,edx", &[0x89, 0xd0]);
        round_trip(Bitness::Bits64, "mov r8,r15", &[0x4d, 0x89, 0xf8]);
    }

    #[test]
    fn call_jmp_register_x86_64() {
        round_trip(Bitness::Bits64, "call rax", &[0xff, 0xd0]);
        round_trip(Bitness::Bits64, "jmp rax", &[0xff, 0xe0]);
        round_trip(Bitness::Bits64, "call r12", &[0x41, 0xff, 0xd4]);
        round_trip(Bitness::Bits64, "jmp r12", &[0x41, 0xff, 0xe4]);
    }

    #[test]
    fn push_immediate_x86_64() {
        round_trip(Bitness::Bits64, "push 0", &[0x6a, 0x00]);
        round_trip(Bitness::Bits64, "push 1", &[0x6a, 0x01]);
    }

    #[test]
    fn nop_with_memory_operand_x86_64() {
        round_trip(Bitness::Bits64, "nop [rax]", &[0x0f, 0x1f, 0x00]);
        round_trip(
            Bitness::Bits64,
            "nop [rax+rax]",
            &[0x0f, 0x1f, 0x04, 0x00],
        );
    }

    #[test]
    fn mov_mem_operand_is_still_unsupported() {
        match assemble_intel(Bitness::Bits64, "mov rax,[rbx]", 0x1000) {
            Err(AssembleError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}

//! Structured-form codec for function prologues / epilogues.
//!
//! A function prologue / epilogue varies by FOUR independent
//! parameters:
//!
//! * Which callee-saved registers it pushes / pops.
//! * Whether it sets up a frame pointer (`push ebp; mov ebp, esp`).
//! * How many bytes of stack space it reserves (`sub esp, N`).
//! * Whether it starts with a control-flow protection landing
//!   pad (`endbr32` / `endbr64`).
//!
//! Plus, for epilogues: the `ret`'s immediate-operand
//! (callee-cleanup amount for stdcall / thiscall / fastcall).
//!
//! The KIND classifier ("std", "std-no-cf", "saves-std-no-cf",
//! "saves-imm", …) is a coarse label that captures the
//! combination of present pieces but not the parameters. This
//! module adds a parallel structured representation that pins
//! every parameter, and a pair of (decode, encode) functions
//! that map back to and from bytes.
//!
//! Used by the emitter to render `@prologue { saves: [ebx, esi,
//! edi], sub_esp: 0x40, frame: ebp }` style structured directives
//! instead of opaque `[0x55, 0x8b, 0xec, 0x83, 0xec, 0x40, 0x53,
//! 0x56, 0x57]` byte blobs. When the structured form encodes
//! back to the same bytes, we can drop the byte list entirely
//! and round-trip via the structured form alone.

/// Bit-width assumed by the codec. 32-bit and 64-bit have
/// slightly different encodings for the frame setup (REX
/// prefix) and the endbr instruction (`endbr32` vs `endbr64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecBits {
    Bits32,
    Bits64,
}

/// Structured prologue. Every field defaults to "absent" — an
/// empty `saves` list + `frame: false` + `sub_esp: 0` +
/// `cf_protect: false` means an empty prologue, which won't
/// match any real function entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredPrologue {
    /// Run of callee-saved registers pushed by the prologue, in
    /// push order. Each entry is a canonical register name
    /// (`"ebx"`, `"esi"`, `"edi"`, `"r12"`, …). Pushes that
    /// happen *after* the frame setup go into `saves_after`
    /// instead — some compilers split saves across the frame
    /// instruction.
    pub saves: Vec<String>,
    /// Pushes that happen after the frame setup (after
    /// `push ebp; mov ebp, esp`). MSVC i386 routinely does this.
    pub saves_after: Vec<String>,
    /// True when the prologue sets up `push ebp; mov ebp, esp`
    /// (or the 64-bit variant). False for noframe / saves-only
    /// shapes.
    pub frame: bool,
    /// Stack allocation in bytes, from `sub esp, IMM`. Zero when
    /// the prologue doesn't reserve stack space.
    pub sub_esp: u32,
    /// True when the prologue starts with `endbr32` / `endbr64`
    /// (Intel CET indirect-branch landing pad).
    pub cf_protect: bool,
    /// Frame-setup encoding selector for the `mov ebp, esp` move:
    /// MSVC emits `0x8b 0xec` (RM form) while GCC emits
    /// `0x89 0xe5` (MR form). Functionally identical but
    /// byte-different, so we observe at decode time and re-emit
    /// the same form at encode time to keep round-trip lossless.
    /// Only meaningful when `frame` is true.
    pub frame_alt_encoding: bool,
}

/// Structured epilogue, the mirror of [`StructuredPrologue`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredEpilogue {
    /// Callee-saved registers popped by the epilogue, in pop
    /// order (typically the reverse of the prologue's push order).
    pub saves: Vec<String>,
    /// True when the epilogue uses `leave` (atomic
    /// `mov esp, ebp; pop ebp`); false when it uses
    /// `pop ebp` directly or has no frame to tear down.
    pub leave: bool,
    /// True when the epilogue pops the frame pointer with an
    /// explicit `pop ebp` (after `leave` is False). Set with
    /// `leave: false, pop_frame: true` for "pop ebp; ret" shapes.
    pub pop_frame: bool,
    /// Stack adjustment via `add esp, IMM` before the `ret`,
    /// when the epilogue doesn't use `leave`. Zero when absent.
    pub add_esp: u32,
    /// Immediate operand of the `ret` instruction (callee-
    /// cleanup amount for stdcall / thiscall / fastcall).
    /// Zero for cdecl / bare `ret`.
    pub ret_imm: u16,
}

/// Decode a byte sequence as a prologue. Returns `None` when
/// the bytes don't match the recognised templates (handwritten
/// prologue, patched code, etc.) — caller falls back to the
/// opaque byte list.
#[must_use]
pub fn decode_prologue(bytes: &[u8], bits: CodecBits) -> Option<StructuredPrologue> {
    let mut p = StructuredPrologue::default();
    let mut i = 0;

    // Step 1: optional endbr.
    let endbr = match bits {
        CodecBits::Bits32 => &[0xf3u8, 0x0f, 0x1e, 0xfb][..],
        CodecBits::Bits64 => &[0xf3u8, 0x0f, 0x1e, 0xfa][..],
    };
    if bytes.get(i..i + endbr.len()) == Some(endbr) {
        p.cf_protect = true;
        i += endbr.len();
    }

    // Step 2: pre-frame saves.
    while let Some(&b) = bytes.get(i) {
        if (0x50..=0x57).contains(&b) {
            p.saves.push(push_reg_name(b, false)?);
            i += 1;
        } else if matches!(bits, CodecBits::Bits64)
            && bytes
                .get(i..i + 2)
                .is_some_and(|s| s[0] == 0x41 && (0x50..=0x57).contains(&s[1]))
        {
            p.saves.push(push_reg_name(bytes[i + 1], true)?);
            i += 2;
        } else {
            break;
        }
    }

    // Step 3: frame setup. `push ebp; mov ebp, esp` (and 64-bit
    // variants). The `push ebp` (0x55) may also have already
    // been counted as a save above — detect and re-attribute.
    if matches!(p.saves.last().map(String::as_str), Some("ebp" | "rbp")) {
        if let Some(mov_b) = bytes.get(i..i + mov_bp_sp_len(bits)) {
            if let Some(alt) = mov_bp_sp_form(mov_b, bits) {
                p.frame = true;
                p.frame_alt_encoding = alt;
                p.saves.pop(); // re-attribute the last push
                i += mov_bp_sp_len(bits);
            }
        }
    }

    // Step 4: sub esp, IMM.
    if let Some(consumed) = parse_sub_esp(&bytes[i..], bits) {
        p.sub_esp = consumed.imm;
        i += consumed.len;
    }

    // Step 5: post-frame saves (MSVC i386 idiom).
    while let Some(&b) = bytes.get(i) {
        if (0x50..=0x57).contains(&b) {
            p.saves_after.push(push_reg_name(b, false)?);
            i += 1;
        } else if matches!(bits, CodecBits::Bits64)
            && bytes
                .get(i..i + 2)
                .is_some_and(|s| s[0] == 0x41 && (0x50..=0x57).contains(&s[1]))
        {
            p.saves_after.push(push_reg_name(bytes[i + 1], true)?);
            i += 2;
        } else {
            break;
        }
    }

    if i != bytes.len() {
        // Didn't consume every byte → bytes aren't a clean
        // prologue. Bail so the caller falls back to the opaque
        // list.
        return None;
    }
    Some(p)
}

/// Encode a structured prologue back to bytes. Mirror of
/// [`decode_prologue`]. The encoder picks the canonical
/// encoding for each piece — small `sub esp, IMM` (≤127) uses
/// the 3-byte form, larger values the 6-byte form.
#[must_use]
pub fn encode_prologue(p: &StructuredPrologue, bits: CodecBits) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    if p.cf_protect {
        let endbr = match bits {
            CodecBits::Bits32 => &[0xf3u8, 0x0f, 0x1e, 0xfb][..],
            CodecBits::Bits64 => &[0xf3u8, 0x0f, 0x1e, 0xfa][..],
        };
        out.extend_from_slice(endbr);
    }
    for r in &p.saves {
        push_reg_encoded(r, bits, &mut out);
    }
    if p.frame {
        // push ebp; mov ebp, esp. Two equivalent encodings: MSVC
        // emits the RM form (`0x8b 0xec`), GCC the MR form
        // (`0x89 0xe5`). Pick the one the decode pass observed.
        out.push(0x55);
        let mov_bytes: &[u8] = match (bits, p.frame_alt_encoding) {
            (CodecBits::Bits32, false) => &[0x8b, 0xec],
            (CodecBits::Bits32, true) => &[0x89, 0xe5],
            (CodecBits::Bits64, false) => &[0x48, 0x8b, 0xec],
            (CodecBits::Bits64, true) => &[0x48, 0x89, 0xe5],
        };
        out.extend_from_slice(mov_bytes);
    }
    if p.sub_esp > 0 {
        encode_sub_esp(p.sub_esp, bits, &mut out);
    }
    for r in &p.saves_after {
        push_reg_encoded(r, bits, &mut out);
    }
    out
}

/// Decode an epilogue. Same Option-fallback convention as
/// [`decode_prologue`].
#[must_use]
pub fn decode_epilogue(bytes: &[u8], bits: CodecBits) -> Option<StructuredEpilogue> {
    let mut e = StructuredEpilogue::default();
    let mut i = 0;
    // Optional `leave` (0xc9) or `pop ebp` (0x5d).
    // Pre-saves get popped first.
    while let Some(&b) = bytes.get(i) {
        if (0x58..=0x5f).contains(&b) {
            // Could be the frame's `pop ebp` if it's the last
            // pop before ret/leave. For now collect them all
            // and re-attribute later.
            e.saves.push(pop_reg_name(b, false)?);
            i += 1;
        } else if matches!(bits, CodecBits::Bits64)
            && bytes
                .get(i..i + 2)
                .is_some_and(|s| s[0] == 0x41 && (0x58..=0x5f).contains(&s[1]))
        {
            e.saves.push(pop_reg_name(bytes[i + 1], true)?);
            i += 2;
        } else {
            break;
        }
    }
    // `add esp, IMM` between pops and the return tear-down.
    if let Some(consumed) = parse_add_esp(&bytes[i..], bits) {
        e.add_esp = consumed.imm;
        i += consumed.len;
    }
    // `leave` (atomic frame-tear-down).
    if bytes.get(i) == Some(&0xc9) {
        e.leave = true;
        i += 1;
    } else if matches!(e.saves.last().map(String::as_str), Some("ebp" | "rbp")) {
        e.pop_frame = true;
        e.saves.pop();
    }
    // `ret` (0xc3) or `ret imm16` (0xc2 + 2-byte imm).
    match bytes.get(i) {
        Some(&0xc3) => {
            i += 1;
        }
        Some(&0xc2) => {
            let lo = *bytes.get(i + 1)?;
            let hi = *bytes.get(i + 2)?;
            e.ret_imm = u16::from(lo) | (u16::from(hi) << 8);
            i += 3;
        }
        _ => return None,
    }
    if i != bytes.len() {
        return None;
    }
    Some(e)
}

/// Encode an epilogue. Mirror of [`decode_epilogue`].
#[must_use]
pub fn encode_epilogue(e: &StructuredEpilogue, bits: CodecBits) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for r in &e.saves {
        pop_reg_encoded(r, bits, &mut out);
    }
    if e.add_esp > 0 {
        encode_add_esp(e.add_esp, bits, &mut out);
    }
    if e.leave {
        out.push(0xc9);
    } else if e.pop_frame {
        // `pop ebp` after the named saves.
        out.push(0x5d);
    }
    if e.ret_imm == 0 {
        out.push(0xc3);
    } else {
        out.push(0xc2);
        out.push((e.ret_imm & 0xff) as u8);
        out.push(((e.ret_imm >> 8) & 0xff) as u8);
    }
    out
}

/// Compiler-profile inputs the default-prologue computation
/// uses. Today these are all derived from the function's body
/// at decompile time (callee-saved registers it writes, stack
/// it reserves, args it expects) and from the function's `abi`
/// attribute at parse time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileInputs {
    /// Callee-saved registers the function overwrites and must
    /// therefore preserve. Listed in push order (typically MSVC
    /// order: ebx, esi, edi).
    pub saves_used: Vec<String>,
    /// True when the function uses any negative-offset stack
    /// slot (i.e., it has a frame pointer's `[ebp-N]` access
    /// pattern). False for leaf functions with no stack locals.
    pub frame_required: bool,
    /// Stack reservation in bytes (`sub esp, N`). Aligned to a
    /// 4-byte boundary at minimum.
    pub sub_esp: u32,
    /// Intel CET indirect-branch landing pad. Comes from the
    /// module's compiler profile, not the function's body.
    pub cf_protect: bool,
    /// Number of stack-passed arguments. Drives the `ret IMM`
    /// callee-cleanup amount for stdcall / thiscall / fastcall.
    /// Excludes register-passed arguments (ECX in thiscall;
    /// ECX/EDX in fastcall).
    pub stack_arg_count: u32,
    /// ABI name. `"cdecl"` / `"stdcall"` / `"thiscall"` /
    /// `"fastcall"` recognised; everything else falls through
    /// to cdecl-style (no ret immediate).
    pub abi: String,
    /// Bit width — 32 or 64. Drives codec selection (`Bits32` /
    /// `Bits64`) and the callee-saved-register set.
    pub bits: u32,
    /// `mov ebp, esp` encoding selector. `false` for MSVC's RM
    /// form (`0x8b 0xec`), `true` for GCC's MR form
    /// (`0x89 0xe5`). x86-64 SysV (GCC) defaults to `true`,
    /// x86-32 MSVC to `false`.
    pub frame_alt: bool,
}

/// Compute the canonical-default prologue for a function with
/// the given profile inputs. Mirrors what MSVC's x86 codegen
/// would emit for a function that:
///
/// * pushes its callee-saved registers AFTER the frame setup,
/// * sets up `push ebp; mov ebp, esp` (frame),
/// * reserves stack with `sub esp, N` (locals).
///
/// Returns `None` when the profile says "no prologue" (e.g., a
/// leaf function with no saves and no locals — its empty
/// prologue is implicitly default).
#[must_use]
pub fn default_prologue(inputs: &ProfileInputs) -> StructuredPrologue {
    // With a frame, callee-save pushes come AFTER `push ebp; mov
    // ebp, esp` (MSVC default). Without a frame, the pushes are
    // the prologue — they go in the pre-frame slot.
    let (saves, saves_after) = if inputs.frame_required {
        (Vec::new(), inputs.saves_used.clone())
    } else {
        (inputs.saves_used.clone(), Vec::new())
    };
    // x86-64 alignment is handled in `profile_inputs_from_fn`
    // (decompile- and lower-side mirrors); pass `sub_esp`
    // through unchanged here.
    let sub_esp = inputs.sub_esp;
    StructuredPrologue {
        saves,
        saves_after,
        frame: inputs.frame_required,
        sub_esp,
        cf_protect: inputs.cf_protect,
        frame_alt_encoding: inputs.frame_alt,
    }
}

/// Compute the canonical-default epilogue paired with
/// [`default_prologue`]. Same MSVC-style choices:
///
/// * pops the callee-saved registers (reverse of push order),
/// * tears down the frame with `pop ebp` (we don't emit `leave`
///   by default — same byte count for the no-`sub_esp` case
///   and shorter when paired with explicit `pop ebp`),
/// * returns with `ret IMM` for callee-cleanup ABIs.
#[must_use]
pub fn default_epilogue(inputs: &ProfileInputs) -> StructuredEpilogue {
    let saves: Vec<String> = inputs.saves_used.iter().rev().cloned().collect();
    let ret_imm = match inputs.abi.as_str() {
        "stdcall" | "thiscall" | "fastcall" => {
            u16::try_from(inputs.stack_arg_count * 4).unwrap_or(0)
        }
        _ => 0,
    };
    // Use `leave` when there's both a frame and a non-trivial
    // sub_esp — same byte budget as `add esp, N; pop ebp` but
    // a single instruction. Otherwise plain `pop ebp` (when
    // frame, no sub) or nothing.
    let leave = inputs.frame_required && inputs.sub_esp > 0;
    let pop_frame = inputs.frame_required && !leave;
    // No frame + non-zero sub_esp (`thin` x86-64 prologue) needs
    // an explicit `add rsp, N` to tear the allocation back down
    // before `ret`. With a frame, `leave` already covers this.
    let add_esp = if inputs.frame_required {
        0
    } else {
        inputs.sub_esp
    };
    StructuredEpilogue {
        saves,
        leave,
        pop_frame,
        add_esp,
        ret_imm,
    }
}

/// Verify a structured-form's round-trip: decode → encode →
/// compare. Returns `true` when the structured form encodes to
/// exactly the original bytes, meaning the emitter can drop
/// the explicit byte list.
#[must_use]
pub fn prologue_roundtrips(bytes: &[u8], bits: CodecBits) -> Option<StructuredPrologue> {
    let p = decode_prologue(bytes, bits)?;
    if encode_prologue(&p, bits) == bytes {
        Some(p)
    } else {
        None
    }
}

#[must_use]
pub fn epilogue_roundtrips(bytes: &[u8], bits: CodecBits) -> Option<StructuredEpilogue> {
    let e = decode_epilogue(bytes, bits)?;
    if encode_epilogue(&e, bits) == bytes {
        Some(e)
    } else {
        None
    }
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

fn push_reg_name(opcode: u8, rex_b: bool) -> Option<String> {
    let n = (opcode - 0x50) | (u8::from(rex_b) << 3);
    Some(reg_name_for_opcode_index(n)?.to_string())
}

fn pop_reg_name(opcode: u8, rex_b: bool) -> Option<String> {
    let n = (opcode - 0x58) | (u8::from(rex_b) << 3);
    Some(reg_name_for_opcode_index(n)?.to_string())
}

fn reg_name_for_opcode_index(n: u8) -> Option<&'static str> {
    Some(match n {
        0 => "eax",
        1 => "ecx",
        2 => "edx",
        3 => "ebx",
        4 => "esp",
        5 => "ebp",
        6 => "esi",
        7 => "edi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        15 => "r15",
        _ => return None,
    })
}

fn push_reg_encoded(name: &str, bits: CodecBits, out: &mut Vec<u8>) {
    if let Some((idx, rex_b)) = encode_index_of(name) {
        if rex_b {
            assert!(matches!(bits, CodecBits::Bits64));
            out.push(0x41);
        }
        out.push(0x50 + idx);
    }
}

fn pop_reg_encoded(name: &str, bits: CodecBits, out: &mut Vec<u8>) {
    if let Some((idx, rex_b)) = encode_index_of(name) {
        if rex_b {
            assert!(matches!(bits, CodecBits::Bits64));
            out.push(0x41);
        }
        out.push(0x58 + idx);
    }
}

fn encode_index_of(name: &str) -> Option<(u8, bool)> {
    Some(match name {
        "eax" | "rax" => (0, false),
        "ecx" | "rcx" => (1, false),
        "edx" | "rdx" => (2, false),
        "ebx" | "rbx" => (3, false),
        "esp" | "rsp" => (4, false),
        "ebp" | "rbp" => (5, false),
        "esi" | "rsi" => (6, false),
        "edi" | "rdi" => (7, false),
        "r8" => (0, true),
        "r9" => (1, true),
        "r10" => (2, true),
        "r11" => (3, true),
        "r12" => (4, true),
        "r13" => (5, true),
        "r14" => (6, true),
        "r15" => (7, true),
        _ => return None,
    })
}

fn mov_bp_sp_len(bits: CodecBits) -> usize {
    match bits {
        CodecBits::Bits32 => 2,
        CodecBits::Bits64 => 3,
    }
}

/// `Some(false)` for the MSVC RM form (`0x8b 0xec`), `Some(true)`
/// for the GCC MR form (`0x89 0xe5`), `None` if `b` isn't a
/// recognised `mov ebp, esp` (or 64-bit variant). Used by the
/// decoder to remember which form was observed so the encoder can
/// re-emit the same bytes.
fn mov_bp_sp_form(b: &[u8], bits: CodecBits) -> Option<bool> {
    match bits {
        CodecBits::Bits32 => match b {
            [0x8b, 0xec] => Some(false),
            [0x89, 0xe5] => Some(true),
            _ => None,
        },
        CodecBits::Bits64 => match b {
            [0x48, 0x8b, 0xec] => Some(false),
            [0x48, 0x89, 0xe5] => Some(true),
            _ => None,
        },
    }
}

struct ParsedImm {
    imm: u32,
    len: usize,
}

fn parse_sub_esp(bytes: &[u8], bits: CodecBits) -> Option<ParsedImm> {
    let rex = matches!(bits, CodecBits::Bits64);
    let offset = usize::from(rex);
    if rex && bytes.first() != Some(&0x48) {
        return None;
    }
    match bytes.get(offset)? {
        // sub r/m32, imm8 (sign-extended): 83 EC ib
        0x83 if bytes.get(offset + 1) == Some(&0xec) => {
            let imm = bytes.get(offset + 2).copied()?;
            Some(ParsedImm {
                imm: u32::from(imm),
                len: offset + 3,
            })
        }
        // sub r/m32, imm32: 81 EC iw iw iw iw
        0x81 if bytes.get(offset + 1) == Some(&0xec) => {
            let b0 = bytes.get(offset + 2).copied()?;
            let b1 = bytes.get(offset + 3).copied()?;
            let b2 = bytes.get(offset + 4).copied()?;
            let b3 = bytes.get(offset + 5).copied()?;
            let imm = u32::from_le_bytes([b0, b1, b2, b3]);
            Some(ParsedImm {
                imm,
                len: offset + 6,
            })
        }
        _ => None,
    }
}

fn parse_add_esp(bytes: &[u8], bits: CodecBits) -> Option<ParsedImm> {
    let rex = matches!(bits, CodecBits::Bits64);
    let offset = usize::from(rex);
    if rex && bytes.first() != Some(&0x48) {
        return None;
    }
    match bytes.get(offset)? {
        0x83 if bytes.get(offset + 1) == Some(&0xc4) => {
            let imm = bytes.get(offset + 2).copied()?;
            Some(ParsedImm {
                imm: u32::from(imm),
                len: offset + 3,
            })
        }
        0x81 if bytes.get(offset + 1) == Some(&0xc4) => {
            let b0 = bytes.get(offset + 2).copied()?;
            let b1 = bytes.get(offset + 3).copied()?;
            let b2 = bytes.get(offset + 4).copied()?;
            let b3 = bytes.get(offset + 5).copied()?;
            let imm = u32::from_le_bytes([b0, b1, b2, b3]);
            Some(ParsedImm {
                imm,
                len: offset + 6,
            })
        }
        _ => None,
    }
}

fn encode_sub_esp(imm: u32, bits: CodecBits, out: &mut Vec<u8>) {
    if matches!(bits, CodecBits::Bits64) {
        out.push(0x48);
    }
    if imm < 0x80 {
        out.extend_from_slice(&[0x83, 0xec, imm as u8]);
    } else {
        out.push(0x81);
        out.push(0xec);
        out.extend_from_slice(&imm.to_le_bytes());
    }
}

fn encode_add_esp(imm: u32, bits: CodecBits, out: &mut Vec<u8>) {
    if matches!(bits, CodecBits::Bits64) {
        out.push(0x48);
    }
    if imm < 0x80 {
        out.extend_from_slice(&[0x83, 0xc4, imm as u8]);
    } else {
        out.push(0x81);
        out.push(0xc4);
        out.extend_from_slice(&imm.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_msvc_x86_full_prologue() {
        // push ebp; mov ebp,esp; sub esp,0x40; push ebx; push esi; push edi
        let bytes = [0x55, 0x8b, 0xec, 0x83, 0xec, 0x40, 0x53, 0x56, 0x57];
        let p = decode_prologue(&bytes, CodecBits::Bits32).expect("decode");
        assert!(p.frame);
        assert_eq!(p.sub_esp, 0x40);
        assert_eq!(p.saves_after, vec!["ebx", "esi", "edi"]);
        assert_eq!(p.saves, Vec::<String>::new());
        assert!(!p.cf_protect);
        // Re-encoding round-trips.
        assert_eq!(encode_prologue(&p, CodecBits::Bits32), bytes);
    }

    #[test]
    fn decode_pure_saves() {
        let bytes = [0x53, 0x56, 0x57];
        let p = decode_prologue(&bytes, CodecBits::Bits32).expect("decode");
        assert_eq!(p.saves, vec!["ebx", "esi", "edi"]);
        assert!(!p.frame);
        assert_eq!(p.sub_esp, 0);
        assert_eq!(encode_prologue(&p, CodecBits::Bits32), bytes);
    }

    #[test]
    fn decode_endbr_then_frame() {
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x8b, 0xec];
        let p = decode_prologue(&bytes, CodecBits::Bits64).expect("decode");
        assert!(p.cf_protect);
        assert!(p.frame);
        assert!(p.saves.is_empty());
        assert_eq!(encode_prologue(&p, CodecBits::Bits64), bytes);
    }

    #[test]
    fn decode_msvc_epilogue_saves_imm() {
        // pop edi; pop esi; pop ebx; pop ebp; ret 0x0c
        let bytes = [0x5f, 0x5e, 0x5b, 0x5d, 0xc2, 0x0c, 0x00];
        let e = decode_epilogue(&bytes, CodecBits::Bits32).expect("decode");
        assert_eq!(e.saves, vec!["edi", "esi", "ebx"]);
        assert!(e.pop_frame);
        assert_eq!(e.ret_imm, 0x0c);
        assert_eq!(encode_epilogue(&e, CodecBits::Bits32), bytes);
    }

    #[test]
    fn decode_leave_ret() {
        let bytes = [0xc9, 0xc3];
        let e = decode_epilogue(&bytes, CodecBits::Bits32).expect("decode");
        assert!(e.leave);
        assert!(!e.pop_frame);
        assert_eq!(e.ret_imm, 0);
        assert_eq!(encode_epilogue(&e, CodecBits::Bits32), bytes);
    }

    #[test]
    fn decode_bare_ret() {
        let bytes = [0xc3];
        let e = decode_epilogue(&bytes, CodecBits::Bits32).expect("decode");
        assert!(e.saves.is_empty());
        assert!(!e.leave && !e.pop_frame);
        assert_eq!(e.ret_imm, 0);
        assert_eq!(encode_epilogue(&e, CodecBits::Bits32), bytes);
    }
}

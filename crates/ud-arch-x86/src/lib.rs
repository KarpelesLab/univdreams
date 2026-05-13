//! x86 architecture backend.
//!
//! Phase 1 scope: decode an x86 byte sequence into structured instructions
//! (via [`iced_x86`]), and provide two distinct emission paths:
//!
//! * [`emit_preserved`] — concatenate each instruction's original bytes
//!   captured at decode time. This is byte-identical by construction
//!   and is what the round-trip contract is built on.
//! * [`reencode_via_iced`] — feed the structured [`Instruction`]s back
//!   through `BlockEncoder`. This is *not* byte-identical for all real
//!   inputs: iced canonicalizes redundant prefixes (e.g. drops a `66`
//!   data16 override on a NOP that doesn't need it), so for compiler-
//!   emitted alignment NOPs and `.plt` padding the bytes will differ.
//!   Useful for "I edited an instruction" workflows in later phases,
//!   not for round-trip.
//!
//! 16- and 32-bit modes are exposed through [`Bitness`] and the same
//! API; the round-trip property is identical.

#![allow(clippy::cast_possible_truncation)]

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Formatter, InstructionBlock,
    IntelFormatter,
};
pub use iced_x86::{
    CodeSize, FlowControl, Instruction, InstructionInfoFactory, MemorySize, Mnemonic, OpAccess,
    OpKind, Register, UsedRegister,
};
use ud_core::VAddr;
use ud_ir::ArchInsn;

mod call_site;
mod encode_text;
mod expr;
mod lift;
mod prologue_codec;
pub use call_site::{
    detect_post_call_spill, identify_call_sites, ArgValue, CallSite, PostCallSpill,
};
pub use encode_text::{encode_cmp_or_test, encode_head_from_cond_text};
pub use expr::{try_lift_value_block, ExprRenderCtx, LiftedValueBlock, ValueExpr};
pub use lift::{lift_function, LiftError};
pub use prologue_codec::{
    decode_epilogue, decode_prologue, default_epilogue, default_prologue, encode_epilogue,
    encode_prologue, epilogue_roundtrips, prologue_roundtrips, CodecBits, ProfileInputs,
    StructuredEpilogue, StructuredPrologue,
};

/// If `insn` is a direct (relative) `call` whose target is statically
/// known, return that target's virtual address. Indirect calls
/// (`call rax`, `call [rip+…]`) and non-call instructions return
/// `None`.
///
/// Lets downstream code annotate call sites with the destination
/// function's name without depending on iced directly.
#[must_use]
pub fn direct_call_target(insn: &Instruction) -> Option<u64> {
    match insn.flow_control() {
        FlowControl::Call => Some(insn.near_branch_target()),
        _ => None,
    }
}

/// Heuristic: does this instruction terminate a function?
/// Returns, unconditional branches (direct or indirect), and the
/// rare hardware traps (`int`, `ud2`, etc.) all qualify.
/// Conditional branches don't — they can still flow into later
/// instructions in the same function.
///
/// Used by the PE / ELF function-discovery passes to bound linear
/// decoding of a newly-seeded function.
#[must_use]
pub fn is_function_terminator(insn: &Instruction) -> bool {
    matches!(
        insn.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Interrupt
            | FlowControl::Exception,
    )
}

/// One recognised return-with-literal pattern at the tail of a
/// function: how many trailing instructions matched, and the literal
/// integer value the function returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiftedReturn {
    pub insns_consumed: usize,
    pub value: u64,
}

/// Try to recognize the trailing instructions of `insns` as a return
/// with a known integer literal: the canonical SysV-x64 epilogue
/// patterns gcc emits at `-O0`.
///
/// Recognised forms (working backwards from `ret`):
///
/// * `mov eax, IMM32; [pop rbp | leave;] ret`
/// * `xor eax, eax;   [pop rbp | leave;] ret`
/// * `mov eax, IMM32; ret`
/// * `xor eax, eax;   ret`
///
/// Only matches when the trailing instruction is a `ret` (`0xc3`); the
/// caller is expected to invoke this only on a function's last block.
/// Returns `None` when no pattern fits.
#[must_use]
pub fn try_lift_return_pattern(insns: &[DecodedInsn]) -> Option<LiftedReturn> {
    if insns.is_empty() {
        return None;
    }

    let mut i = insns.len();

    // Last instruction must be `ret` (0xc3). Iret / retf etc. are
    // beyond v0 scope.
    let ret = insns.get(i - 1)?;
    if ret.original_bytes.as_slice() != [0xc3] {
        return None;
    }
    i -= 1;

    // Optional epilogue: pop rbp (0x5d) or leave (0xc9).
    if i > 0 {
        let prev = &insns[i - 1].original_bytes;
        if prev.as_slice() == [0x5d] || prev.as_slice() == [0xc9] {
            i -= 1;
        }
    }

    if i == 0 {
        return None;
    }

    // The instruction setting the return value.
    let setter = &insns[i - 1].original_bytes;
    let value = match setter.as_slice() {
        // mov eax, imm32 — opcode 0xB8, 4 little-endian bytes follow.
        [0xb8, b0, b1, b2, b3] => u64::from(u32::from_le_bytes([*b0, *b1, *b2, *b3])),
        // xor eax, eax — clears eax to zero.
        [0x31, 0xc0] => 0,
        _ => return None,
    };
    i -= 1;

    Some(LiftedReturn {
        insns_consumed: insns.len() - i,
        value,
    })
}

/// One recognised SysV-x64 prologue at the entry of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedPrologue {
    /// Number of leading instructions matched.
    pub insns_consumed: usize,
    /// Symbolic kind name. Today: `"std"` (full standard prologue with
    /// `endbr64` and a frame), `"std-no-cf"` (no `endbr64`),
    /// `"std-noframe"` (just `endbr64`).
    pub kind: &'static str,
}

/// Try to recognize the leading instructions of `insns` as a
/// canonical SysV-x64 prologue at function entry.
///
/// Recognised forms (greediest first):
///
/// * `endbr64; push rbp; mov rbp, rsp; sub rsp, IMM` → `"std"`
///   (full prologue with cf-protection and a stack frame)
/// * `push rbp; mov rbp, rsp; sub rsp, IMM` → `"std-no-cf"`
///   (older toolchain or `-fno-cf-protection`)
/// * `endbr64; push rbp; mov rbp, rsp` → `"std"` (frame, no
///   stack-allocated locals)
/// * `push rbp; mov rbp, rsp` → `"std-no-cf"`
/// * `endbr64` alone at the top of a leaf function → `"std-noframe"`
///
/// Bytes are matched literally — instruction-encoding choices are
/// pinned, so the lifter only fires on the exact byte sequences gcc
/// emits at `-O0`. Other compilers / optimization levels add new
/// patterns to this DB.
#[must_use]
pub fn try_lift_prologue_pattern(insns: &[DecodedInsn]) -> Option<LiftedPrologue> {
    let endbr64: &[u8] = &[0xf3, 0x0f, 0x1e, 0xfa];
    let endbr32: &[u8] = &[0xf3, 0x0f, 0x1e, 0xfb];
    // `mov ebp, esp` has two equivalent encodings: the
    // destination-form `0x89 0xe5` (mov r/m32, r32) and the
    // source-form `0x8b 0xec` (mov r32, r/m32). gcc / clang emit
    // the former; MSVC/Watcom often emit the latter. The 64-bit
    // forms add a REX.W prefix.
    let mov_rbp_rsp_64_dst: &[u8] = &[0x48, 0x89, 0xe5];
    let mov_rbp_rsp_64_src: &[u8] = &[0x48, 0x8b, 0xec];
    let mov_ebp_esp_32_dst: &[u8] = &[0x89, 0xe5];
    let mov_ebp_esp_32_src: &[u8] = &[0x8b, 0xec];
    let is_mov_bp_sp = |b: &[u8]| {
        b == mov_rbp_rsp_64_dst
            || b == mov_rbp_rsp_64_src
            || b == mov_ebp_esp_32_dst
            || b == mov_ebp_esp_32_src
    };

    let bytes_at = |i: usize| insns.get(i).map(|d| d.original_bytes.as_slice());

    // Step 1: optional indirect-branch landing pad (Intel CET).
    let (has_endbr, mut start) = match bytes_at(0) {
        Some(b) if b == endbr64 || b == endbr32 => (true, 1),
        _ => (false, 0),
    };

    // Step 2: leading run of single-byte `push reg` (opcodes
    // 0x50..=0x57 → push eax..edi/r8..r15-low). Windows i386 routinely
    // saves several callee-saved registers (ebx, esi, edi) before any
    // frame setup; gcc/msvc on x86_64 can do the same with rbx/r12-r15.
    let push_start = start;
    let mut pushes: Vec<u8> = Vec::new();
    while let Some(b) = bytes_at(start) {
        if b.len() == 1 && (0x50..=0x57).contains(&b[0]) {
            pushes.push(b[0]);
            start += 1;
        } else {
            break;
        }
    }

    // Step 3: frame setup. When the final push was `push ebp/rbp`
    // (opcode 0x55) AND it is immediately followed by `mov ebp, esp`,
    // attribute that last push to the frame rather than to saves.
    // Otherwise every push is a save.
    let mut has_frame = false;
    if matches!(pushes.last(), Some(&0x55)) {
        if let Some(b) = bytes_at(start) {
            if is_mov_bp_sp(b) {
                has_frame = true;
                start += 1;
            }
        }
    }
    let mut saves_count = pushes.len() - usize::from(has_frame);

    // Step 4: optional stack-locals reservation. Only meaningful when a
    // frame was set up (or no frame and no saves — the bare CRT-stub
    // `_init`/`_fini` idiom); a `sub esp, IMM` mid-function isn't
    // really a prologue.
    let sub_matched = matches!(
        bytes_at(start),
        Some(
            &[0x48, 0x83, 0xec, _]
                | &[0x48, 0x81, 0xec, _, _, _, _]
                | &[0x83, 0xec, _]
                | &[0x81, 0xec, _, _, _, _]
        )
    );
    let has_sub = sub_matched && (has_frame || saves_count == 0);
    if has_sub {
        start += 1;
    }

    // Step 5: additional callee-save pushes that come *after* the
    // frame setup. The MSVC i386 prologue often looks like
    // `push ebp; mov ebp,esp; push esi; push edi` — the frame is
    // set up first, then the function spills the extra callee-saved
    // registers it'll need.
    if has_frame {
        while let Some(b) = bytes_at(start) {
            if b.len() == 1 && (0x50..=0x57).contains(&b[0]) {
                saves_count += 1;
                start += 1;
            } else {
                break;
            }
        }
    }

    // Step 5: classify. If nothing was consumed beyond the (optional)
    // endbr, there's nothing to lift.
    if !has_endbr && saves_count == 0 && !has_frame && !has_sub {
        return None;
    }
    let _ = push_start; // kept for future use when emitting save-list text

    let kind = match (has_endbr, saves_count > 0, has_frame, has_sub) {
        // Pure endbr leaf.
        (true, false, false, false) => "std-noframe",
        // CRT-stub `sub esp, N; ...; add esp, N; ret` with optional CET.
        (true, false, false, true) => "thin",
        (false, false, false, true) => "thin-no-cf",
        // Frame-only (no saves). `sub esp, IMM` doesn't change the
        // kind label — it's still a standard frame.
        (true, false, true, _) => "std",
        (false, false, true, _) => "std-no-cf",
        // Saves-only (no frame).
        (true, true, false, false) => "saves-cf",
        (false, true, false, false) => "saves",
        // Saves + frame.
        (true, true, true, _) => "saves-std",
        (false, true, true, _) => "saves-std-no-cf",
        // Saves + sub-without-frame: unusual; label it.
        (_, true, false, true) => "saves-thin",
        // Guarded by the `!has_endbr && saves_count == 0 && !has_frame &&
        // !has_sub` early-return above.
        (false, false, false, false) => unreachable!("nothing-to-lift case already returned None"),
    };
    Some(LiftedPrologue {
        insns_consumed: start,
        kind,
    })
}

/// One recognised SysV-x64 epilogue at the tail of a function or
/// shared between branches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedEpilogue {
    /// Number of trailing instructions matched.
    pub insns_consumed: usize,
    /// Symbolic kind: `"std"` for `leave; ret`, `"std-pop-rbp"` for
    /// `pop rbp; ret`.
    pub kind: &'static str,
}

/// Try to recognize the trailing instructions of `insns` as a stack-
/// frame-tearing-down epilogue:
///
/// * `leave; ret`                  → `"std"`
/// * `pop rbp; ret`                → `"std-pop-rbp"`
/// * `add rsp/esp, IMM; ret`       → `"thin"`
/// * `add rsp/esp, IMM; pop rbp; ret` → `"thin-pop-rbp"`
///
/// Used when [`try_lift_return_pattern`] doesn't fire (e.g. the last
/// block has no value-setter — the return value was set in an earlier
/// block by a non-trivial expression). Lifting just the epilogue still
/// removes the boilerplate from the decompile output.
#[must_use]
pub fn try_lift_epilogue_pattern(insns: &[DecodedInsn]) -> Option<LiftedEpilogue> {
    if insns.is_empty() {
        return None;
    }
    let last = insns.last()?;
    let last_b = last.original_bytes.as_slice();
    // The trailing instruction must terminate the function:
    //   c3       ret
    //   c2 ww ww ret IMM16 (stdcall callee-cleans-up)
    let is_ret_bare = last_b == [0xc3];
    let is_ret_imm = matches!(last_b, [0xc2, _, _]);
    if !is_ret_bare && !is_ret_imm {
        return None;
    }

    if insns.len() >= 2 {
        let prev = &insns[insns.len() - 2].original_bytes;

        // Two-instruction tails: leave/ret, pop rbp/ret.
        if is_ret_bare {
            let two_kind = match prev.as_slice() {
                [0xc9] => Some("std"),         // leave
                [0x5d] => Some("std-pop-rbp"), // pop rbp
                _ => None,
            };
            if let Some(kind) = two_kind {
                // Check if it can be widened to a thin form (`add rsp, IMM`
                // immediately before the `pop rbp`/`leave`). Only for
                // `pop rbp`, since `leave` already restores rsp.
                if kind == "std-pop-rbp" && insns.len() >= 3 {
                    let before_pop = insns[insns.len() - 3].original_bytes.as_slice();
                    if is_add_rsp_imm(before_pop) {
                        return Some(LiftedEpilogue {
                            insns_consumed: 3,
                            kind: "thin-pop-rbp",
                        });
                    }
                }
                return Some(LiftedEpilogue {
                    insns_consumed: 2,
                    kind,
                });
            }

            // `add rsp, IMM; ret` — bare CRT-stub epilogue.
            if is_add_rsp_imm(prev.as_slice()) {
                return Some(LiftedEpilogue {
                    insns_consumed: 2,
                    kind: "thin",
                });
            }
        }
    }

    // Generic "restore saved registers + return" epilogue: a tail of
    // pop-like instructions followed by `ret` or `ret IMM16`. Counts
    // every preceding insn that's a `pop reg` (single-byte opcodes
    // 0x58..=0x5f), `leave` (0xc9), or `add rsp/esp, IMM` (the manual
    // stack-cleanup form). Common on Windows i386 (callee-saves
    // ebx/esi/edi + leave) and useful any time a function exits
    // through more than one block with the same teardown sequence.
    let mut restore_count = 0usize;
    if insns.len() >= 2 {
        for i in (0..insns.len() - 1).rev() {
            let b = insns[i].original_bytes.as_slice();
            let is_pop_reg = b.len() == 1 && (0x58..=0x5f).contains(&b[0]);
            let is_leave = b == [0xc9];
            let is_add_rsp = is_add_rsp_imm(b);
            if is_pop_reg || is_leave || is_add_rsp {
                restore_count += 1;
            } else {
                break;
            }
        }
    }
    if restore_count >= 1 {
        let kind = if is_ret_imm { "saves-imm" } else { "saves" };
        return Some(LiftedEpilogue {
            insns_consumed: restore_count + 1,
            kind,
        });
    }

    // Bare ret (or ret IMM16) with nothing in front to lift — still
    // worth labelling. Makes function exits land on `@epilogue`
    // consistently whether there's a frame teardown or not, and the
    // `ret-imm` kind tells you stdcall is in play.
    if is_ret_imm {
        return Some(LiftedEpilogue {
            insns_consumed: 1,
            kind: "ret-imm",
        });
    }
    if is_ret_bare {
        return Some(LiftedEpilogue {
            insns_consumed: 1,
            kind: "ret",
        });
    }

    None
}

fn is_add_rsp_imm(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [0x48, 0x83, 0xc4, _]
            | [0x48, 0x81, 0xc4, _, _, _, _]
            | [0x83, 0xc4, _]
            | [0x81, 0xc4, _, _, _, _]
    )
}

/// Try to recognize the trailing instructions of `insns` as a
/// "return with literal, then jump to a shared epilogue" pattern.
///
/// gcc emits this for functions with multiple return sites and a
/// single `leave; ret` (or `pop rbp; ret`) tail block. Each
/// non-final block ends with `mov eax, IMM; jmp <epilogue_addr>` (or
/// `xor eax, eax; jmp <epilogue_addr>`); the lifter matches that
/// pattern and folds it into a single `Stmt::Return`. The shared
/// epilogue itself is left as `@asm` since it doesn't carry a value
/// — it's just `[leave|pop rbp;] ret`.
///
/// Recognised forms (working backwards from the final `jmp`):
///
/// * `mov eax, IMM32; jmp short rel8 -> epilogue_addr`
/// * `mov eax, IMM32; jmp near rel32 -> epilogue_addr`
/// * `xor eax, eax;   jmp short rel8 -> epilogue_addr`
/// * `xor eax, eax;   jmp near rel32 -> epilogue_addr`
///
/// Only matches when the final instruction is a direct jump whose
/// `near_branch_target()` equals `epilogue_addr`.
#[must_use]
pub fn try_lift_return_via_jmp(insns: &[DecodedInsn], epilogue_addr: u64) -> Option<LiftedReturn> {
    if insns.len() < 2 {
        return None;
    }

    let last = insns.last()?;
    if last.iced.flow_control() != FlowControl::UnconditionalBranch {
        return None;
    }
    if last.iced.near_branch_target() != epilogue_addr {
        return None;
    }

    // The instruction before the jmp must be a value-setter.
    let setter = &insns[insns.len() - 2].original_bytes;
    let value = match setter.as_slice() {
        [0xb8, b0, b1, b2, b3] => u64::from(u32::from_le_bytes([*b0, *b1, *b2, *b3])),
        [0x31, 0xc0] => 0,
        _ => return None,
    };

    Some(LiftedReturn {
        insns_consumed: 2,
        value,
    })
}

/// One recognised `cmp/test + jcc` pair at the tail of a basic block,
/// suitable for lifting into a structured `if/else` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedIfBranchHead {
    /// Number of trailing instructions matched. Always 2 in v0
    /// (one comparison + one conditional jump).
    pub insns_consumed: usize,
    /// Human-readable form of the head, e.g.
    /// `"cmp dword ptr [rbp-4],1; jne short 11F6h"`.
    pub cond_text: String,
    /// Raw encoded bytes of the comparison and conditional jump,
    /// concatenated. The lower path emits these unchanged.
    pub cond_bytes: Vec<u8>,
    /// Absolute virtual address the jcc transfers control to when
    /// taken. Used to find the "taken" basic block in the CFG.
    pub jcc_target: u64,
}

/// Try to recognise the trailing two instructions of `insns` as a
/// `cmp` (or `test`) followed by a direct conditional jump.
///
/// Returns `None` when the pair doesn't fit; in particular the jcc
/// must be a *direct* conditional branch with a constant near target —
/// indirect / unsupported jcc forms aren't lifted because we can't
/// statically point at a "taken" block address.
///
/// The function does not look further back than the last two
/// instructions; chained comparisons or short-circuit boolean rebuilds
/// are out of scope for v0.
#[must_use]
pub fn try_lift_if_branch_head(insns: &[DecodedInsn]) -> Option<LiftedIfBranchHead> {
    if insns.len() < 2 {
        return None;
    }
    let jcc = insns.last()?;
    if jcc.iced.flow_control() != FlowControl::ConditionalBranch {
        return None;
    }
    // Only direct jcc — `near_branch_target()` is meaningful only for
    // direct near branches; indirect forms (rare for jcc but possible
    // in obfuscated code) would return 0 or a stale value.
    let target = jcc.iced.near_branch_target();
    if target == 0 {
        return None;
    }

    // Adjacent cmp/test: the canonical shape. Consume both
    // instructions; the IfBranch owns their bytes.
    let cmp_idx = insns.len() - 2;
    let cmp = &insns[cmp_idx];
    if matches!(cmp.iced.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
        let cond_text = render_cond_source(&cmp.iced, &jcc.iced);
        let mut cond_bytes =
            Vec::with_capacity(cmp.original_bytes.len() + jcc.original_bytes.len());
        cond_bytes.extend_from_slice(&cmp.original_bytes);
        cond_bytes.extend_from_slice(&jcc.original_bytes);
        return Some(LiftedIfBranchHead {
            insns_consumed: 2,
            cond_text,
            cond_bytes,
            jcc_target: target,
        });
    }

    // Separated cmp/test: scan backward through flag-preserving
    // instructions (mov, lea, push, pop, etc.) for the last cmp/test.
    // If one is found, the IfBranch owns only the jcc's bytes — the
    // cmp/test stays as @asm at its original position in the block.
    // This lets the if-detection fire even when the compiler
    // interleaved unrelated setup between the comparison and the
    // branch (a common optimised-codegen shape).
    let mut probe = insns.len() - 2;
    loop {
        let ins = &insns[probe];
        if matches!(ins.iced.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
            let cond_text = render_cond_source(&ins.iced, &jcc.iced);
            return Some(LiftedIfBranchHead {
                insns_consumed: 1,
                cond_text,
                cond_bytes: jcc.original_bytes.clone(),
                jcc_target: target,
            });
        }
        // Any instruction that writes flags poisons the comparison —
        // its result reaches the jcc before the older cmp/test does.
        if ins.iced.rflags_modified() != 0 {
            return None;
        }
        if probe == 0 {
            return None;
        }
        probe -= 1;
    }
}

/// Rename a memory operand to its source-language slot name —
/// handling both frame-pointer (`[ebp+N]`) and stack-pointer
/// (`[esp+N]`, with an optional SP delta context) forms.
///
/// For SP-relative accesses, `sp_delta` is the signed change in ESP
/// from function entry at the instruction that contains the
/// operand. The stable slot offset is `sp_delta + disp + 4` — the
/// `+4` normalises onto the same coordinate system as the EBP-based
/// names (where `arg_8` = first arg = `entry_ESP + 4`).
///
/// Returns `None` for shapes the renamer doesn't recognise (indexed
/// addressing, non-ebp/esp bases, bare operands, mismatched
/// addressing modes); the caller falls back to the raw text. The
/// no-context [`rename_operand_if_slot`] is a thin wrapper that
/// passes `sp_delta = None`.
#[must_use]
pub fn rename_operand_with_ctx(text: &str, sp_delta: Option<i64>) -> Option<String> {
    if let Some(name) = rename_ebp_slot(text) {
        return Some(name);
    }
    if let Some(delta) = sp_delta {
        return rename_esp_slot(text, delta);
    }
    None
}

/// SP-relative slot rename. The caller-supplied `sp_delta` is the
/// SP change relative to function entry at the point of the
/// access; `[esp+disp]` at `sp_delta = -12` lands on
/// `entry_ESP + 8`, which is `arg_c` in the EBP-relative
/// convention.
fn rename_esp_slot(text: &str, sp_delta: i64) -> Option<String> {
    let core = text.strip_prefix("dword ptr ").unwrap_or(text);
    let core = core.strip_prefix("qword ptr ").unwrap_or(core);
    let inner = core
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))?
        .trim();
    let disp: i64 = if inner == "esp" {
        0
    } else if let Some(rest) = inner.strip_prefix("esp+") {
        let off = parse_unsigned_disp(rest.trim())?;
        i64::try_from(off).ok()?
    } else if let Some(rest) = inner.strip_prefix("esp-") {
        let off = parse_unsigned_disp(rest.trim())?;
        -(i64::try_from(off).ok()?)
    } else {
        return None;
    };
    let stable = sp_delta + disp + 4;
    if stable == 0 || stable == 4 {
        // Saved EBP slot / return address slot — internal, not a
        // source-language variable. Keep the raw text so the reader
        // can tell it's the ABI's spill, not user data.
        return None;
    }
    if stable >= 8 {
        let off = u64::try_from(stable).ok()?;
        return Some(format!("arg_{off:x}"));
    }
    // stable < 0 — local slot (negative offsets from the conceptual
    // EBP-frame origin).
    let off = u64::try_from(-stable).ok()?;
    Some(format!("var_{off:x}"))
}

/// Compute SP delta at every instruction in `insns`. The first
/// instruction sees delta = 0 (function entry: SP points at the
/// return address). Subsequent deltas accumulate stack effects
/// from `push` / `pop` / `enter` / `leave` (via iced's built-in
/// `stack_pointer_increment`) plus the arithmetic forms `sub
/// esp/rsp, IMM` / `add esp/rsp, IMM` which iced doesn't model.
///
/// Each entry maps an instruction's IP to its delta. The map is
/// keyed by IP because patterns get instructions by reference and
/// IP is the cheap stable identifier.
#[must_use]
pub fn compute_sp_delta_table(insns: &[DecodedInsn]) -> std::collections::HashMap<u64, i64> {
    use std::collections::HashMap;
    let mut out: HashMap<u64, i64> = HashMap::with_capacity(insns.len());
    let mut delta: i64 = 0;
    for ins in insns {
        out.insert(ins.iced.ip(), delta);
        delta = delta.saturating_add(sp_change_for(&ins.iced));
    }
    out
}

/// Per-instruction stack-pointer change. Uses iced's intrinsic
/// `stack_pointer_increment` for push / pop / call / ret / enter /
/// leave; falls back to operand inspection for `sub esp, IMM` and
/// `add esp, IMM` which iced doesn't compute.
#[must_use]
pub fn sp_change_for(insn: &Instruction) -> i64 {
    let intrinsic = i64::from(insn.stack_pointer_increment());
    if intrinsic != 0 {
        return intrinsic;
    }
    match insn.mnemonic() {
        Mnemonic::Sub | Mnemonic::Add => {
            if insn.op0_kind() != OpKind::Register {
                return 0;
            }
            let r = insn.op0_register();
            if r != Register::ESP && r != Register::RSP {
                return 0;
            }
            let imm = match insn.op1_kind() {
                OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate8 => {
                    #[allow(clippy::cast_possible_wrap)]
                    let v = i64::from(insn.immediate8() as i8);
                    v
                }
                OpKind::Immediate32 | OpKind::Immediate32to64 => {
                    #[allow(clippy::cast_possible_wrap)]
                    let v = i64::from(insn.immediate32() as i32);
                    v
                }
                _ => return 0,
            };
            if insn.mnemonic() == Mnemonic::Sub {
                -imm
            } else {
                imm
            }
        }
        _ => 0,
    }
}

/// Rename a frame-pointer memory operand to its source-language slot
/// name. `[ebp+N]` becomes `arg_<hex>` and `[ebp-N]` becomes
/// `var_<hex>` — the offset (always positive) is the hex part of the
/// name, matching the Ghidra/IDA convention. Bare `[ebp]` (offset 0)
/// renders as `var_0`. Anything else (indexed addressing, non-EBP
/// bases, non-memory operands, …) returns `None` so the caller can
/// fall back to the raw text.
///
/// The mapping is purely syntactic — there is no ABI inference yet,
/// just "slot at `[ebp+N]`" gets a stable name. The encoder in
/// `encode_text` recognises both forms so byte derivation continues
/// to work when the cond/operand text uses the named slot.
#[must_use]
pub fn rename_ebp_slot(text: &str) -> Option<String> {
    let core = text.strip_prefix("dword ptr ").unwrap_or(text);
    let core = core.strip_prefix("qword ptr ").unwrap_or(core);
    let inner = core
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))?
        .trim();
    if inner == "ebp" {
        return Some("var_0".into());
    }
    if let Some(rest) = inner.strip_prefix("ebp+") {
        let offset = parse_unsigned_disp(rest.trim())?;
        return Some(format!("arg_{offset:x}"));
    }
    if let Some(rest) = inner.strip_prefix("ebp-") {
        let offset = parse_unsigned_disp(rest.trim())?;
        return Some(format!("var_{offset:x}"));
    }
    None
}

/// Apply [`rename_ebp_slot`] when it matches; otherwise return the
/// input unchanged. Useful as a one-call helper for places that want
/// to rename operands without branching on the result.
#[must_use]
pub fn rename_operand_if_slot(text: &str) -> String {
    rename_ebp_slot(text).unwrap_or_else(|| text.to_string())
}

/// Apply [`rename_operand_with_ctx`] (which handles both `[ebp+N]`
/// and `[esp+N]` with the supplied SP delta) and return the renamed
/// text — or the original input unchanged when no rename rule
/// matches.
#[must_use]
pub fn rename_operand_in_ctx(text: &str, sp_delta: Option<i64>) -> String {
    rename_operand_with_ctx(text, sp_delta).unwrap_or_else(|| text.to_string())
}

fn parse_unsigned_disp(s: &str) -> Option<u64> {
    // Reject anything that's not a plain integer literal — we don't
    // want to rename `[ebp+esi*4]` or other indexed forms.
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse::<u64>().ok()
}

/// Render a `cmp` / `test` + `jcc` pair as a C-style relational
/// expression evaluated against the source-language `if`'s body.
///
/// The body of an `if (cond) { … }` runs on the JCC's *not-taken*
/// path, so we invert the jcc's branch sense to get the body-side
/// operator. Worked examples:
///
/// * `test esi,esi; jne …`   →  `"esi == 0"`     (jne taken when ≠0
///   so body runs when =0)
/// * `cmp eax,5; jl …`        →  `"eax >= 5"`     (jl is *signed*
///   less-than; body runs on ≥)
/// * `cmp ebx,ecx; jb …`      →  `"ebx >=u ecx"`  (`jb` is unsigned;
///   `u` suffix marks the comparison)
///
/// Falls back to the literal assembly form (`"cmp X,Y; jcc T"`) when
/// the jcc isn't one we have a clean source-level mapping for (e.g.
/// `js`, `jp`, `jo`). The encoder in [`encode_text`] accepts the
/// high-level form and continues to auto-derive `head_bytes`.
#[must_use]
pub fn render_cond_source(cmp: &Instruction, jcc: &Instruction) -> String {
    let cmp_text = format_intel(cmp);
    let Some((lhs_raw, rhs_raw)) = split_cmp_test_operands(&cmp_text) else {
        return format!("{cmp_text}; {}", format_intel(jcc));
    };
    let is_test = cmp.mnemonic() == Mnemonic::Test;
    let Some(op) = body_operator_from_jcc(jcc.mnemonic()) else {
        return format!("{cmp_text}; {}", format_intel(jcc));
    };
    let lhs = rename_operand_if_slot(&lhs_raw);
    let rhs = rename_operand_if_slot(&rhs_raw);
    // `test reg, reg` AND-s the register with itself — the result is
    // the register's value, so the jcc effectively compares the
    // register against zero (ZF for `==/!=`, SF for signed
    // ordering). Render that as `reg <op> 0` instead of the
    // redundant `reg <op> reg`. The unsigned-suffix form drops
    // because unsigned compare-with-zero is always trivially true
    // or false; the comparison is meaningful only in the signed
    // interpretation. (Renames don't matter here — the same-register
    // check fires on the raw text, before renaming.)
    if is_test && lhs_raw == rhs_raw {
        let signed_op = op.strip_suffix('u').unwrap_or(op);
        return format!("{lhs} {signed_op} 0");
    }
    format!("{lhs} {op} {rhs}")
}

fn body_operator_from_jcc(jcc: Mnemonic) -> Option<&'static str> {
    use Mnemonic::{Ja, Jae, Jb, Jbe, Je, Jg, Jge, Jl, Jle, Jne};
    Some(match jcc {
        // ZF tests — same in signed and unsigned interpretations.
        Je => "!=",
        Jne => "==",
        // Signed magnitude tests. The jcc takes when its name
        // describes the relation; body runs on the inverse.
        Jl => ">=",
        Jle => ">",
        Jg => "<=",
        Jge => "<",
        // Unsigned magnitude tests. `u`-suffixed operators tell the
        // reader (and the encoder) the comparison is unsigned.
        Jb => ">=u",
        Jbe => ">u",
        Ja => "<=u",
        Jae => "<u",
        _ => return None,
    })
}

/// Split the operand portion of `format_intel(cmp_or_test)` into a
/// `(lhs, rhs)` pair. Strips the `cmp ` / `test ` prefix; splits on
/// the first top-level comma (commas inside `[…]` don't count, even
/// though Intel syntax doesn't actually use them inside memory
/// operands — be defensive).
fn split_cmp_test_operands(formatted: &str) -> Option<(String, String)> {
    let rest = formatted
        .strip_prefix("cmp ")
        .or_else(|| formatted.strip_prefix("test "))?;
    let mut depth = 0i32;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                let (l, r) = rest.split_at(i);
                return Some((l.trim().to_string(), r[1..].trim().to_string()));
            }
            _ => {}
        }
    }
    None
}

/// If `insn` is an "argument spill" — `mov [rbp+disp], REG` (or
/// `movss/movsd [rbp+disp], xmm`) where `REG` is one of the SysV
/// x86-64 argument-passing registers — return that argument's
/// 0-based index.
///
/// SysV x86-64 calling convention:
///
/// | Arg index | Int / ptr | Float (xmm) |
/// |-----------|-----------|-------------|
/// | 0         | rdi/edi/di/dil | xmm0  |
/// | 1         | rsi/esi/si/sil | xmm1  |
/// | 2         | rdx/edx/dx/dl  | xmm2  |
/// | 3         | rcx/ecx/cx/cl  | xmm3  |
/// | 4         | r8/r8d/r8w/r8b | xmm4  |
/// | 5         | r9/r9d/r9w/r9b | xmm5  |
///
/// Used by the decompiler to annotate `mov [rbp-N], edi` (etc.) at
/// function entry with the corresponding parameter name from DWARF.
#[must_use]
pub fn arg_spill_index(insn: &Instruction) -> Option<u32> {
    let m = insn.mnemonic();
    if !matches!(m, Mnemonic::Mov | Mnemonic::Movss | Mnemonic::Movsd) {
        return None;
    }
    if insn.op_count() < 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if insn.memory_base() != Register::RBP {
        return None;
    }
    if insn.op1_kind() != OpKind::Register {
        return None;
    }
    sysv_arg_index(insn.op_register(1))
}

#[allow(clippy::match_same_arms)] // each line is one register width
fn sysv_arg_index(reg: Register) -> Option<u32> {
    Some(match reg {
        Register::RDI | Register::EDI | Register::DI | Register::DIL | Register::XMM0 => 0,
        Register::RSI | Register::ESI | Register::SI | Register::SIL | Register::XMM1 => 1,
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::XMM2 => 2,
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::XMM3 => 3,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L | Register::XMM4 => 4,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L | Register::XMM5 => 5,
        _ => return None,
    })
}

/// Like [`direct_call_target`], but for unconditional direct branches
/// (`jmp rel32` / `jmp short rel8`). Useful for spotting tail calls
/// when the target lives in another discovered function.
#[must_use]
pub fn direct_unconditional_branch_target(insn: &Instruction) -> Option<u64> {
    match insn.flow_control() {
        FlowControl::UnconditionalBranch => Some(insn.near_branch_target()),
        _ => None,
    }
}

/// Read the memory operand's displacement as a signed 64-bit value,
/// honouring the addressing mode's actual width.
///
/// iced's `memory_displacement64()` returns the displacement
/// "extended to 64 bits" but in 32-bit addressing mode (e.g. when
/// the base is `EBP`/`ESP`) it doesn't sign-extend small negative
/// displacements past bit 31 — `[ebp-0x20]` comes back as
/// `0x00000000_ffffffe0` rather than `0xffffffff_ffffffe0`. We
/// detect 32-bit addressing via the base register and re-extend
/// from i32 in that case.
#[must_use]
#[allow(clippy::cast_possible_wrap)]
pub fn signed_memory_displacement(insn: &Instruction) -> i64 {
    let raw = insn.memory_displacement64();
    let is_32bit_addressing = matches!(
        insn.memory_base(),
        Register::EAX
            | Register::EBX
            | Register::ECX
            | Register::EDX
            | Register::ESI
            | Register::EDI
            | Register::EBP
            | Register::ESP
            | Register::EIP
    );
    if is_32bit_addressing {
        i64::from(raw as i32)
    } else {
        raw as i64
    }
}

/// If `insn` is `add/sub dword/qword ptr [rbp/ebp+disp], IMM` —
/// a stack-frame local being incremented or decremented by a
/// literal — return `(slot, op, value)` where `op` is `"+="` for
/// `add` and `"-="` for `sub`.
#[must_use]
pub fn match_local_arith_immediate(insn: &Instruction) -> Option<(i64, &'static str, i64)> {
    let op = match insn.mnemonic() {
        Mnemonic::Add => "+=",
        Mnemonic::Sub => "-=",
        _ => return None,
    };
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if !matches!(insn.memory_base(), Register::RBP | Register::EBP) {
        return None;
    }
    if insn.memory_index() != Register::None {
        return None;
    }
    #[allow(clippy::cast_possible_wrap)]
    let value = match insn.op1_kind() {
        OpKind::Immediate8 => i64::from(insn.immediate8() as i8),
        OpKind::Immediate16 => i64::from(insn.immediate16() as i16),
        OpKind::Immediate32 => i64::from(insn.immediate32() as i32),
        OpKind::Immediate64 => insn.immediate64() as i64,
        OpKind::Immediate8to16 => i64::from(insn.immediate8to16()),
        OpKind::Immediate8to32 => i64::from(insn.immediate8to32()),
        OpKind::Immediate8to64 => insn.immediate8to64(),
        OpKind::Immediate32to64 => insn.immediate32to64(),
        _ => return None,
    };
    Some((signed_memory_displacement(insn), op, value))
}

/// If the instruction window starts with a recognised compound
/// stack-slot pattern (`[rbp+dst] op= [rbp+src]`), return
/// `(consumed, dst, op, src)`.
///
/// Two shapes are handled:
///
/// * 2-insn (`add`, `sub`, `and`, `or`, `xor`) —
///   `mov reg, [rbp+src]; <op> [rbp+dst], reg`.
///   Possible because these ops have a memory-destination form.
///
/// * 3-insn (`imul`) —
///   `mov reg, [rbp+dst]; imul reg, [rbp+src]; mov [rbp+dst], reg`.
///   `imul` has no memory-destination form, so the compiler routes
///   through a register.
///
/// The temp register must be the same across the window, the memory
/// operands must all be `[rbp/ebp+disp]` with no index, and (for the
/// 3-insn form) the dst displacement must match between the load and
/// the store-back. Returns `None` for any other shape.
#[must_use]
pub fn match_local_compound(insns: &[Instruction]) -> Option<(usize, i64, &'static str, i64)> {
    if insns.len() >= 2 {
        let i0 = &insns[0];
        let i1 = &insns[1];
        if let Some(out) = match_compound_two(i0, i1) {
            return Some(out);
        }
    }
    if insns.len() >= 3 {
        let i0 = &insns[0];
        let i1 = &insns[1];
        let i2 = &insns[2];
        if let Some(out) = match_compound_three(i0, i1, i2) {
            return Some(out);
        }
    }
    None
}

fn is_rbp_local(insn: &Instruction) -> bool {
    insn.op_count() == 2
        && matches!(insn.memory_base(), Register::RBP | Register::EBP)
        && insn.memory_index() == Register::None
}

fn match_compound_two(
    i0: &Instruction,
    i1: &Instruction,
) -> Option<(usize, i64, &'static str, i64)> {
    if i0.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if i0.op_count() != 2 || i0.op0_kind() != OpKind::Register || i0.op1_kind() != OpKind::Memory {
        return None;
    }
    if !is_rbp_local(i0) {
        return None;
    }
    let op = match i1.mnemonic() {
        Mnemonic::Add => "+=",
        Mnemonic::Sub => "-=",
        Mnemonic::And => "&=",
        Mnemonic::Or => "|=",
        Mnemonic::Xor => "^=",
        _ => return None,
    };
    if i1.op_count() != 2 || i1.op0_kind() != OpKind::Memory || i1.op1_kind() != OpKind::Register {
        return None;
    }
    if !is_rbp_local(i1) {
        return None;
    }
    if i0.op0_register() != i1.op1_register() {
        return None;
    }
    let src = signed_memory_displacement(i0);
    let dst = signed_memory_displacement(i1);
    Some((2, dst, op, src))
}

fn match_compound_three(
    i0: &Instruction,
    i1: &Instruction,
    i2: &Instruction,
) -> Option<(usize, i64, &'static str, i64)> {
    if i0.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if i0.op_count() != 2 || i0.op0_kind() != OpKind::Register || i0.op1_kind() != OpKind::Memory {
        return None;
    }
    if !is_rbp_local(i0) {
        return None;
    }
    let op = match i1.mnemonic() {
        Mnemonic::Imul => "*=",
        _ => return None,
    };
    if i1.op_count() != 2 || i1.op0_kind() != OpKind::Register || i1.op1_kind() != OpKind::Memory {
        return None;
    }
    if !is_rbp_local(i1) {
        return None;
    }
    if i0.op0_register() != i1.op0_register() {
        return None;
    }
    if i2.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if i2.op_count() != 2 || i2.op0_kind() != OpKind::Memory || i2.op1_kind() != OpKind::Register {
        return None;
    }
    if !is_rbp_local(i2) {
        return None;
    }
    if i2.op1_register() != i0.op0_register() {
        return None;
    }
    let dst_load = signed_memory_displacement(i0);
    let src = signed_memory_displacement(i1);
    let dst_store = signed_memory_displacement(i2);
    if dst_load != dst_store {
        return None;
    }
    Some((3, dst_load, op, src))
}

/// If `insn` is a `mov [rbp/ebp+disp], IMM` — a stack-frame local
/// being initialised or assigned a literal — return the signed
/// displacement and the immediate value. The displacement honours
/// 32-bit addressing mode (so `[ebp-0x8]` round-trips as `-8`,
/// not `0xffff_fff8`).
#[must_use]
pub fn match_local_set_immediate(insn: &Instruction) -> Option<(i64, i64)> {
    if insn.mnemonic() != Mnemonic::Mov {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory {
        return None;
    }
    if !matches!(insn.memory_base(), Register::RBP | Register::EBP) {
        return None;
    }
    if insn.memory_index() != Register::None {
        return None;
    }
    #[allow(clippy::cast_possible_wrap)]
    let value = match insn.op1_kind() {
        OpKind::Immediate8 => i64::from(insn.immediate8() as i8),
        OpKind::Immediate16 => i64::from(insn.immediate16() as i16),
        OpKind::Immediate32 => i64::from(insn.immediate32() as i32),
        OpKind::Immediate64 => insn.immediate64() as i64,
        OpKind::Immediate8to16 => i64::from(insn.immediate8to16()),
        OpKind::Immediate8to32 => i64::from(insn.immediate8to32()),
        OpKind::Immediate8to64 => insn.immediate8to64(),
        OpKind::Immediate32to64 => insn.immediate32to64(),
        _ => return None,
    };
    Some((signed_memory_displacement(insn), value))
}

/// If `insn` is a `lea reg, [rip+disp]` (compiler-typical
/// "load address of a global / string-constant"), return the absolute
/// virtual address of the target. Returns `None` for non-`lea`s, or
/// for `lea`s with a non-RIP base or a non-trivial index.
///
/// Iced computes the rip-relative target for us in
/// `memory_displacement64()` when the operand's base is `RIP`.
#[must_use]
pub fn direct_lea_rip_target(insn: &Instruction) -> Option<u64> {
    if insn.mnemonic() != Mnemonic::Lea {
        return None;
    }
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Register {
        return None;
    }
    if insn.op1_kind() != OpKind::Memory {
        return None;
    }
    if insn.memory_base() != Register::RIP {
        return None;
    }
    if insn.memory_index() != Register::None {
        return None;
    }
    Some(insn.memory_displacement64())
}

/// Format `insn` as Intel-syntax assembly text, suitable for embedding
/// inside an `@asm("...")` directive in a `.ud` file.
///
/// Goes through iced's [`IntelFormatter`] with default options so the
/// output matches the ubiquitous Intel-syntax convention (`mov rax,
/// rbx`, source on the right). Fresh formatter per call: deterministic,
/// no shared mutable state.
#[must_use]
pub fn format_intel(insn: &Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    let mut out = String::new();
    formatter.format(insn, &mut out);
    out
}

/// Result of [`verify_intel_text`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyAsm {
    /// `text` matches the canonical Intel-syntax form for `bytes`.
    Match,
    /// `text` and the canonical form diverge; the canonical form is
    /// what `bytes` actually decode to.
    Diverged { canonical: String },
    /// `bytes` couldn't be decoded as a single x86 instruction.
    Undecodable,
    /// `bytes` decoded to multiple instructions instead of one.
    MultipleInsns { count: usize },
}

/// Decode `bytes` as a single x86 instruction at `rip`, format it via
/// [`format_intel`], and compare against `text` (after a light
/// normalization that ignores case and folds whitespace runs).
///
/// Returns [`VerifyAsm::Match`] when the user's text agrees with what
/// the bytes actually encode — i.e. nothing has been edited away from
/// the canonical form. A divergence is the cleanest signal we have
/// today that a user edited the text without updating the bytes (or
/// vice versa); a stricter "would the edited text re-encode to the
/// same length" check needs a text assembler we don't ship yet.
#[must_use]
pub fn verify_intel_text(bitness: Bitness, text: &str, bytes: &[u8], rip: u64) -> VerifyAsm {
    let mut decoder = Decoder::with_ip(bitness.as_u32(), bytes, rip, DecoderOptions::NONE);
    let mut count = 0usize;
    let mut first: Option<Instruction> = None;
    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            return VerifyAsm::Undecodable;
        }
        if first.is_none() {
            first = Some(insn);
        }
        count += 1;
    }
    let Some(insn) = first else {
        return VerifyAsm::Undecodable;
    };
    if count != 1 {
        return VerifyAsm::MultipleInsns { count };
    }
    let canonical = format_intel(&insn);
    if normalize(text) == normalize(&canonical) {
        VerifyAsm::Match
    } else {
        VerifyAsm::Diverged { canonical }
    }
}

/// Lower-case + strip all whitespace. The canonical form iced emits is
/// inconsistent about spaces (no space after a comma in operands; space
/// between mnemonic and first operand), and we don't want benign user
/// whitespace edits to surface as warnings — only the actual tokens.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_ascii_whitespace() {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// Errors produced by decode / encode / round-trip helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("instruction decoder rejected bytes at offset {offset}")]
    DecodeFailed { offset: usize },

    #[error("encoder rejected instructions: {0}")]
    Encode(String),

    #[error("round-trip diverged at offset {offset}: expected 0x{expected:02x}, got 0x{got:02x}")]
    ByteMismatch {
        offset: usize,
        expected: u8,
        got: u8,
    },

    #[error("round-trip length mismatch: input was {input} bytes, output is {output}")]
    LengthMismatch { input: usize, output: usize },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Bitness of an x86 decode/encode pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bitness {
    Bits16,
    Bits32,
    Bits64,
}

impl Bitness {
    fn as_u32(self) -> u32 {
        match self {
            Self::Bits16 => 16,
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

/// A single decoded instruction together with the exact bytes it
/// occupied in the source buffer.
///
/// `iced` is the structured form, useful for analysis (operand kinds,
/// branch targets, register usage, etc.). `original_bytes` is the byte
/// slice from the input — used by [`emit_preserved`] to re-emit a
/// byte-identical copy regardless of any encoding choices iced would
/// pick if asked to encode the structured form.
#[derive(Debug, Clone)]
pub struct DecodedInsn {
    pub iced: Instruction,
    pub original_bytes: Vec<u8>,
}

impl ArchInsn for DecodedInsn {
    fn addr(&self) -> VAddr {
        VAddr(self.iced.ip())
    }

    fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }
}

/// Decode `bytes` as a contiguous x86 instruction stream starting at
/// virtual address `rip`. Captures each instruction's exact bytes for
/// later byte-faithful re-emission.
///
/// Stops only when the buffer is exhausted. An invalid instruction is
/// a hard error — for code containing data-in-code, slice the
/// executable regions before calling.
pub fn decode(bitness: Bitness, bytes: &[u8], rip: u64) -> Result<Vec<DecodedInsn>> {
    let mut decoder = Decoder::with_ip(bitness.as_u32(), bytes, rip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let pos = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(Error::DecodeFailed { offset: pos });
        }
        let len = insn.len();
        let end = pos.saturating_add(len);
        if end > bytes.len() {
            return Err(Error::DecodeFailed { offset: pos });
        }
        out.push(DecodedInsn {
            iced: insn,
            original_bytes: bytes[pos..end].to_vec(),
        });
    }
    Ok(out)
}

/// Like [`decode`] but tolerates a decoder failure mid-stream: on
/// hitting an invalid byte the walk stops and returns every
/// instruction successfully decoded up to that point plus the
/// failure offset. Used by function-discovery passes that scan
/// past data-in-code regions (e.g. jump-table embedded inside a
/// `.text` section).
#[must_use]
pub fn decode_tolerant(bitness: Bitness, bytes: &[u8], rip: u64) -> Vec<DecodedInsn> {
    let mut decoder = Decoder::with_ip(bitness.as_u32(), bytes, rip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while decoder.can_decode() {
        let pos = decoder.position();
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
        }
        let len = insn.len();
        let end = pos.saturating_add(len);
        if end > bytes.len() {
            break;
        }
        out.push(DecodedInsn {
            iced: insn,
            original_bytes: bytes[pos..end].to_vec(),
        });
    }
    out
}

/// Re-emit a decoded instruction stream using each instruction's
/// preserved original bytes. Byte-identical by construction.
#[must_use]
pub fn emit_preserved(insns: &[DecodedInsn]) -> Vec<u8> {
    let total: usize = insns.iter().map(|i| i.original_bytes.len()).sum();
    let mut out = Vec::with_capacity(total);
    for insn in insns {
        out.extend_from_slice(&insn.original_bytes);
    }
    out
}

/// Re-encode the structured instructions through iced's `BlockEncoder`.
///
/// **Warning**: this does not preserve redundant encoding choices. If
/// the input used a non-canonical encoding (redundant prefixes,
/// alignment NOPs with `66` data16 overrides, larger-than-necessary
/// displacement sizes), the output will differ from the input. Use
/// [`emit_preserved`] for byte-identical round-trip.
pub fn reencode_via_iced(bitness: Bitness, insns: &[DecodedInsn], rip: u64) -> Result<Vec<u8>> {
    let iced_insns: Vec<Instruction> = insns.iter().map(|i| i.iced).collect();
    let block = InstructionBlock::new(&iced_insns, rip);
    let result = BlockEncoder::encode(bitness.as_u32(), block, BlockEncoderOptions::NONE)
        .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(result.code_buffer)
}

/// Decode `bytes` and re-emit via [`emit_preserved`]; verify the result
/// equals the input. This is the format-agnostic round-trip property
/// for the x86 backend, and it must hold for every byte sequence we
/// claim to support.
pub fn roundtrip_bytes(bitness: Bitness, bytes: &[u8], rip: u64) -> Result<Vec<DecodedInsn>> {
    let insns = decode(bitness, bytes, rip)?;
    let emitted = emit_preserved(&insns);
    if emitted.len() != bytes.len() {
        return Err(Error::LengthMismatch {
            input: bytes.len(),
            output: emitted.len(),
        });
    }
    if let Some((offset, (&expected, &got))) = bytes
        .iter()
        .zip(&emitted)
        .enumerate()
        .find(|(_, (a, b))| a != b)
    {
        return Err(Error::ByteMismatch {
            offset,
            expected,
            got,
        });
    }
    Ok(insns)
}

/// Errors emitted by [`encode_jmp`].
#[derive(Debug, thiserror::Error)]
pub enum JumpEncodeError {
    #[error("jmp rel32 target out of i32 range: from=0x{from:x} to=0x{to:x}")]
    OutOfRange { from: u64, to: u64 },
}

/// Encode an unconditional `jmp` from `source_ip` (the address of
/// the jmp instruction itself) to `target`.
///
/// * `wide=false` and the displacement fits in `i8`: `jmp rel8`
///   (2 bytes, opcode `0xeb`).
/// * otherwise (`wide=true`, or `i8` displacement doesn't fit):
///   `jmp rel32` (5 bytes, opcode `0xe9`).
///
/// The `wide` flag exists because compilers don't always pick
/// the shortest encoding — most do, but MSVC in particular
/// occasionally emits `jmp rel32` when `jmp rel8` would fit.
/// Setting `wide=true` reproduces that choice for round-trip
/// fidelity on unedited inputs. Edits that push a target beyond
/// `i8` reach auto-promote to `rel32` regardless of the flag.
pub fn encode_jmp(
    source_ip: u64,
    target: u64,
    wide: bool,
) -> std::result::Result<Vec<u8>, JumpEncodeError> {
    if !wide {
        let after_rel8 = source_ip.wrapping_add(2);
        let rel8 = i128::from(target).wrapping_sub(i128::from(after_rel8));
        if (-128..=127).contains(&rel8) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let imm = rel8 as i8 as u8;
            return Ok(vec![0xeb, imm]);
        }
    }
    let after_rel32 = source_ip.wrapping_add(5);
    let rel = i128::from(target).wrapping_sub(i128::from(after_rel32));
    let rel32 = i32::try_from(rel).map_err(|_| JumpEncodeError::OutOfRange {
        from: source_ip,
        to: target,
    })?;
    let mut out = Vec::with_capacity(5);
    out.push(0xe9);
    out.extend_from_slice(&rel32.to_le_bytes());
    Ok(out)
}

/// Pre-computed byte size of [`encode_jmp`]'s output.
#[must_use]
pub fn encoded_jmp_size(source_ip: u64, target: u64, wide: bool) -> usize {
    if !wide {
        let after_rel8 = source_ip.wrapping_add(2);
        let rel8 = i128::from(target).wrapping_sub(i128::from(after_rel8));
        if (-128..=127).contains(&rel8) {
            return 2;
        }
    }
    5
}

/// Encode a conditional `jcc` from `source_ip` (the address of
/// the jcc instruction itself) to `target`.
///
/// `cond_code` is the low nibble of the jcc opcode (0..=15):
///
/// * 0x0 = jo,  0x1 = jno,  0x2 = jb/jnae,  0x3 = jae/jnb
/// * 0x4 = je,  0x5 = jne,  0x6 = jbe,      0x7 = ja
/// * 0x8 = js,  0x9 = jns,  0xA = jp,       0xB = jnp
/// * 0xC = jl,  0xD = jge,  0xE = jle,      0xF = jg
///
/// * `wide=false` and the displacement fits in `i8`: `jcc rel8`
///   (2 bytes, opcode `0x70 | cond`).
/// * otherwise: `jcc rel32` (6 bytes, opcodes `0x0F 0x80 | cond`).
pub fn encode_jcc(
    source_ip: u64,
    target: u64,
    cond_code: u8,
    wide: bool,
) -> std::result::Result<Vec<u8>, JumpEncodeError> {
    let cc = cond_code & 0x0f;
    if !wide {
        let after_rel8 = source_ip.wrapping_add(2);
        let rel8 = i128::from(target).wrapping_sub(i128::from(after_rel8));
        if (-128..=127).contains(&rel8) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let imm = rel8 as i8 as u8;
            return Ok(vec![0x70 | cc, imm]);
        }
    }
    let after_rel32 = source_ip.wrapping_add(6);
    let rel = i128::from(target).wrapping_sub(i128::from(after_rel32));
    let rel32 = i32::try_from(rel).map_err(|_| JumpEncodeError::OutOfRange {
        from: source_ip,
        to: target,
    })?;
    let mut out = Vec::with_capacity(6);
    out.push(0x0f);
    out.push(0x80 | cc);
    out.extend_from_slice(&rel32.to_le_bytes());
    Ok(out)
}

/// Encode `call rel32` from `source_ip` to `target` — 5 bytes
/// (`0xe8` + i32). Direct near calls on x86 are always rel32 in
/// 32- and 64-bit modes, so there's no narrow/wide choice here.
pub fn encode_call_rel32(
    source_ip: u64,
    target: u64,
) -> std::result::Result<Vec<u8>, JumpEncodeError> {
    let after = source_ip.wrapping_add(5);
    let rel = i128::from(target).wrapping_sub(i128::from(after));
    let rel32 = i32::try_from(rel).map_err(|_| JumpEncodeError::OutOfRange {
        from: source_ip,
        to: target,
    })?;
    let mut out = Vec::with_capacity(5);
    out.push(0xe8);
    out.extend_from_slice(&rel32.to_le_bytes());
    Ok(out)
}

/// Pre-computed byte size of [`encode_jcc`]'s output.
#[must_use]
pub fn encoded_jcc_size(source_ip: u64, target: u64, wide: bool) -> usize {
    if !wide {
        let after_rel8 = source_ip.wrapping_add(2);
        let rel8 = i128::from(target).wrapping_sub(i128::from(after_rel8));
        if (-128..=127).contains(&rel8) {
            return 2;
        }
    }
    6
}

/// Extract the jcc condition code (0..=15) from an already-
/// decoded jcc's opcode bytes. Returns `None` when `bytes` isn't
/// a recognised jcc encoding.
#[must_use]
pub fn jcc_cond_code_from_bytes(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [op, ..] if (0x70..=0x7f).contains(op) => Some(op - 0x70),
        [0x0f, op, ..] if (0x80..=0x8f).contains(op) => Some(op - 0x80),
        _ => None,
    }
}

/// Symbolic name for a jcc condition code, lowercase.
#[must_use]
pub fn jcc_cond_name(cond_code: u8) -> &'static str {
    match cond_code & 0x0f {
        0x0 => "jo",
        0x1 => "jno",
        0x2 => "jb",
        0x3 => "jae",
        0x4 => "je",
        0x5 => "jne",
        0x6 => "jbe",
        0x7 => "ja",
        0x8 => "js",
        0x9 => "jns",
        0xa => "jp",
        0xb => "jnp",
        0xc => "jl",
        0xd => "jge",
        0xe => "jle",
        _ => "jg",
    }
}

/// Inverse of [`jcc_cond_name`].
#[must_use]
pub fn jcc_cond_code_from_name(name: &str) -> Option<u8> {
    Some(match name {
        "jo" => 0x0,
        "jno" => 0x1,
        "jb" | "jc" | "jnae" => 0x2,
        "jae" | "jnb" | "jnc" => 0x3,
        "je" | "jz" => 0x4,
        "jne" | "jnz" => 0x5,
        "jbe" | "jna" => 0x6,
        "ja" | "jnbe" => 0x7,
        "js" => 0x8,
        "jns" => 0x9,
        "jp" | "jpe" => 0xa,
        "jnp" | "jpo" => 0xb,
        "jl" | "jnge" => 0xc,
        "jge" | "jnl" => 0xd,
        "jle" | "jng" => 0xe,
        "jg" | "jnle" => 0xf,
        _ => return None,
    })
}

/// Errors emitted by [`encode_msvc_jmp_table_dispatch`].
#[derive(Debug, thiserror::Error)]
pub enum SwitchEncodeError {
    #[error("unsupported selector register {0:?} (expected eax/ecx/edx/ebx/esi/edi/ebp)")]
    UnsupportedSelector(String),
    #[error("case count {0} doesn't fit in u32")]
    TooManyCases(usize),
    #[error("ja rel32 target out of i32 range: cmp_ip={cmp_ip:#x} default={default:#x}")]
    JaOutOfRange { cmp_ip: u64, default: u64 },
}

/// Encode an MSVC-style switch dispatch sequence:
///
/// ```text
/// cmp <reg>, <max>           ; 3 bytes (imm8 if max≤127) or 6 (imm32)
/// ja <default>               ; 6 bytes (rel32)
/// jmp dword ptr [<reg>*4 + <table_va>]  ; 7 bytes
/// ```
///
/// `cmp_ip` is the absolute address where the cmp instruction
/// will live — used to compute the `ja` rel32. `cases` is the
/// number of jump-table entries; the bounds-check uses
/// `MAX = cases - 1`. Returns the encoded bytes.
///
/// This is the inverse of the dispatch-recogniser in
/// `ud-decompile`'s `try_switch_pair`. Together they form the
/// round-trip: structural Switch → bytes → structural Switch.
pub fn encode_msvc_jmp_table_dispatch(
    selector: &str,
    cases: usize,
    default_addr: u64,
    table_va: u64,
    cmp_ip: u64,
) -> std::result::Result<Vec<u8>, SwitchEncodeError> {
    let reg_code = gpr32_code(selector)
        .ok_or_else(|| SwitchEncodeError::UnsupportedSelector(selector.into()))?;
    let max_value = u32::try_from(cases.saturating_sub(1))
        .map_err(|_| SwitchEncodeError::TooManyCases(cases))?;

    let mut out = Vec::with_capacity(16);

    // cmp REG, imm
    let cmp_modrm = 0xc0 | (7 << 3) | reg_code; // mod=11, reg=/7, r/m=reg_code
    if max_value <= 0x7f {
        out.push(0x83);
        out.push(cmp_modrm);
        out.push(max_value as u8);
    } else {
        out.push(0x81);
        out.push(cmp_modrm);
        out.extend_from_slice(&max_value.to_le_bytes());
    }

    // ja rel32 — target = default; rel = default - (cmp_ip + cmp_len + 6)
    let cmp_len = out.len() as u64;
    let ja_end = cmp_ip
        .checked_add(cmp_len)
        .and_then(|x| x.checked_add(6))
        .ok_or(SwitchEncodeError::JaOutOfRange {
            cmp_ip,
            default: default_addr,
        })?;
    let rel = i128::from(default_addr) - i128::from(ja_end);
    let rel32 = i32::try_from(rel).map_err(|_| SwitchEncodeError::JaOutOfRange {
        cmp_ip,
        default: default_addr,
    })?;
    out.push(0x0f);
    out.push(0x87);
    out.extend_from_slice(&rel32.to_le_bytes());

    // jmp dword ptr [REG*4 + TABLE_VA]
    //   opcode = ff
    //   ModR/M = 00_100_100 (mod=00 SIB-follows, reg=/4, r/m=100 SIB)
    //   SIB    = 10_<reg_code>_101  (scale=2 bits = *4, index=reg, base=101 no-base+disp32)
    //   DISP32 = table_va (LE)
    out.push(0xff);
    out.push(0x24);
    out.push(0x80 | (reg_code << 3) | 0x05);
    out.extend_from_slice(&(table_va as u32).to_le_bytes());

    Ok(out)
}

/// 32-bit GPR register-code lookup by name. Returns `None` for
/// names that don't map to a usable index/r-m register in the
/// switch-dispatch encoding above.
fn gpr32_code(name: &str) -> Option<u8> {
    match name.trim().to_ascii_lowercase().as_str() {
        "eax" => Some(0),
        "ecx" => Some(1),
        "edx" => Some(2),
        "ebx" => Some(3),
        // esp (4) can't be an index register in SIB; rejected.
        "ebp" => Some(5),
        "esi" => Some(6),
        "edi" => Some(7),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoding regression: the dispatch we lift from the msmpeg4
    /// codec's `DriverProc` switch round-trips. Verifies the
    /// `cmp ecx, 9; ja 0x23e8; jmp [ecx*4+0x1c20246a]` form
    /// re-emits to the exact bytes the compiler put down.
    #[test]
    fn encode_msmpeg4_driverproc_switch() {
        // cmp_ip = 0x208d (where the cmp lives in the original
        // .text). default = 0x23e8. table_va = 0x1c20246a.
        let bytes = encode_msvc_jmp_table_dispatch("ecx", 10, 0x23e8, 0x1c20_246a, 0x208d).unwrap();
        assert_eq!(
            bytes,
            vec![
                0x83, 0xf9, 0x09, // cmp ecx, 9
                0x0f, 0x87, 0x52, 0x03, 0x00, 0x00, // ja 0x23e8 (rel32 = 0x352)
                0xff, 0x24, 0x8d, 0x6a, 0x24, 0x20, 0x1c, // jmp [ecx*4 + 0x1c20246a]
            ]
        );
    }

    /// `endbr64`: 0xf3 0x0f 0x1e 0xfa — gcc with -fcf-protection emits
    /// this at every function entry, so the fixtures all start with it.
    #[test]
    fn endbr64_roundtrips() {
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
    }

    #[test]
    fn prologue_roundtrips() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20
        let bytes = [
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
        ];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 3);
    }

    #[test]
    fn short_jump_roundtrips() {
        let bytes = [0xeb, 0x05];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    #[test]
    fn near_jump_roundtrips() {
        let bytes = [0xe9, 0x34, 0x12, 0x00, 0x00];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    #[test]
    fn call_rel32_roundtrips() {
        let bytes = [0xe8, 0x80, 0x00, 0x00, 0x00];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    #[test]
    fn xor_zero_idiom_roundtrips() {
        let bytes = [0x48, 0x31, 0xc0];
        roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
    }

    /// Multi-byte NOP with the redundant 66 data16 prefix — the exact
    /// pattern compilers use for alignment, and the one that exposed
    /// iced's canonicalization issue. emit_preserved must keep it
    /// verbatim; reencode_via_iced is allowed to drop the 66.
    #[test]
    fn multibyte_nop_with_data16_prefix_preserved() {
        let bytes = [0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].original_bytes, bytes);

        // iced's encoder drops the redundant prefix; that's fine and
        // documented — the emit_preserved path is what guards round-trip.
        let reencoded = reencode_via_iced(Bitness::Bits64, &insns, 0x1000).unwrap();
        assert!(
            reencoded.len() <= bytes.len(),
            "iced should produce a shorter or equal canonical encoding"
        );
    }

    #[test]
    fn small_function_roundtrips() {
        let bytes = [
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x31, 0xc0, // xor eax, eax
            0x5d, // pop rbp
            0xc3, // ret
        ];
        let insns = roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 6);
    }

    #[test]
    fn verify_matches_canonical_form() {
        let bytes = [0xc3]; // ret
        match verify_intel_text(Bitness::Bits64, "ret", &bytes, 0x1000) {
            VerifyAsm::Match => {}
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn verify_tolerates_whitespace_and_case() {
        let bytes = [0x48, 0x89, 0xd8]; // mov rax, rbx
        match verify_intel_text(Bitness::Bits64, "MOV  RAX,   RBX", &bytes, 0x1000) {
            VerifyAsm::Match => {}
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn verify_diverges_when_text_disagrees() {
        let bytes = [0xc3]; // ret
        match verify_intel_text(Bitness::Bits64, "nop", &bytes, 0x1000) {
            VerifyAsm::Diverged { canonical } => {
                assert_eq!(canonical, "ret");
            }
            other => panic!("expected Diverged, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_multi_insn_byte_sequence() {
        // ret; ret  — two instructions in one @asm line is wrong
        let bytes = [0xc3, 0xc3];
        let result = verify_intel_text(Bitness::Bits64, "ret", &bytes, 0x1000);
        assert!(matches!(result, VerifyAsm::MultipleInsns { count: 2 }));
    }

    #[test]
    fn verify_rejects_undecodable_bytes() {
        let bytes = [0x06]; // invalid in 64-bit mode
        let result = verify_intel_text(Bitness::Bits64, "ret", &bytes, 0x1000);
        assert!(matches!(result, VerifyAsm::Undecodable));
    }

    #[test]
    fn lift_return_recognizes_mov_eax_pop_rbp_ret() {
        // mov eax, 0; pop rbp; ret
        let bytes = [0xb8, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_return_pattern(&insns).unwrap();
        assert_eq!(lifted.value, 0);
        assert_eq!(lifted.insns_consumed, 3);
    }

    #[test]
    fn lift_return_recognizes_xor_zero_pop_rbp_ret() {
        // xor eax, eax; pop rbp; ret
        let bytes = [0x31, 0xc0, 0x5d, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_return_pattern(&insns).unwrap();
        assert_eq!(lifted.value, 0);
        assert_eq!(lifted.insns_consumed, 3);
    }

    #[test]
    fn lift_return_recognizes_mov_eax_leave_ret() {
        // mov eax, 1; leave; ret
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc9, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_return_pattern(&insns).unwrap();
        assert_eq!(lifted.value, 1);
        assert_eq!(lifted.insns_consumed, 3);
    }

    #[test]
    fn lift_return_recognizes_mov_ret_without_epilogue() {
        // mov eax, 42; ret
        let bytes = [0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_return_pattern(&insns).unwrap();
        assert_eq!(lifted.value, 0x2a);
        assert_eq!(lifted.insns_consumed, 2);
    }

    #[test]
    fn lift_return_rejects_bare_ret() {
        // ret only — no value-setter, no pattern
        let bytes = [0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(try_lift_return_pattern(&insns).is_none());
    }

    #[test]
    fn lift_return_rejects_unrecognized_setter() {
        // mov rax, rbx; ret — not a literal value
        let bytes = [0x48, 0x89, 0xd8, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(try_lift_return_pattern(&insns).is_none());
    }

    #[test]
    fn lift_epilogue_recognizes_leave_ret() {
        let bytes = [0xc9, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_epilogue_pattern(&insns).unwrap();
        assert_eq!(lifted.kind, "std");
        assert_eq!(lifted.insns_consumed, 2);
    }

    #[test]
    fn lift_epilogue_recognizes_pop_rbp_ret() {
        let bytes = [0x5d, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_epilogue_pattern(&insns).unwrap();
        assert_eq!(lifted.kind, "std-pop-rbp");
        assert_eq!(lifted.insns_consumed, 2);
    }

    #[test]
    fn lift_epilogue_bare_ret_is_minimal_kind() {
        // A standalone `ret` lifts as the minimal `"ret"` epilogue —
        // no register restore to fold in, but the kind tells the
        // reader they're at a function exit rather than mid-flow.
        let bytes = [0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_epilogue_pattern(&insns).expect("bare ret should lift");
        assert_eq!(lifted.kind, "ret");
        assert_eq!(lifted.insns_consumed, 1);
    }

    #[test]
    fn lift_epilogue_non_teardown_predecessor_lifts_only_the_ret() {
        // `mov rax, rbx; ret` — the mov isn't part of an epilogue
        // (it's a value materialisation that landed before the
        // exit), so the lift consumes only the trailing ret.
        let bytes = [0x48, 0x89, 0xd8, 0xc3];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_epilogue_pattern(&insns).expect("ret should lift");
        assert_eq!(lifted.kind, "ret");
        assert_eq!(lifted.insns_consumed, 1);
    }

    #[test]
    fn lift_prologue_full_std() {
        // endbr64; push rbp; mov rbp,rsp; sub rsp,0x10
        let bytes = [
            0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10,
        ];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_prologue_pattern(&insns).unwrap();
        assert_eq!(lifted.kind, "std");
        assert_eq!(lifted.insns_consumed, 4);
    }

    #[test]
    fn lift_prologue_without_sub() {
        // endbr64; push rbp; mov rbp,rsp (no sub rsp)
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_prologue_pattern(&insns).unwrap();
        assert_eq!(lifted.kind, "std");
        assert_eq!(lifted.insns_consumed, 3);
    }

    #[test]
    fn lift_prologue_no_cf_protection() {
        // push rbp; mov rbp,rsp; sub rsp,0x20  (no endbr64)
        let bytes = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_prologue_pattern(&insns).unwrap();
        assert_eq!(lifted.kind, "std-no-cf");
        assert_eq!(lifted.insns_consumed, 3);
    }

    #[test]
    fn lift_prologue_noframe() {
        // Lone endbr64 (leaf function, no frame setup)
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xc0, 0xc3]; // endbr64; xor eax,eax; ret
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_prologue_pattern(&insns).unwrap();
        assert_eq!(lifted.kind, "std-noframe");
        assert_eq!(lifted.insns_consumed, 1);
    }

    #[test]
    fn lift_prologue_rejects_nonstandard() {
        // mov rax, rbx — not a prologue
        let bytes = [0x48, 0x89, 0xd8];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(try_lift_prologue_pattern(&insns).is_none());
    }

    #[test]
    fn arg_spill_recognizes_int_register_to_stack() {
        // mov [rbp-4], edi
        let bytes = [0x89, 0x7d, 0xfc];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(arg_spill_index(&insns[0].iced), Some(0));
    }

    #[test]
    fn arg_spill_recognizes_xmm_register_to_stack() {
        // movsd [rbp-0x10], xmm0
        let bytes = [0xf2, 0x0f, 0x11, 0x45, 0xf0];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(arg_spill_index(&insns[0].iced), Some(0));
    }

    #[test]
    fn arg_spill_rejects_non_arg_register() {
        // mov [rbp-4], eax (eax is not a SysV arg register)
        let bytes = [0x89, 0x45, 0xfc];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(arg_spill_index(&insns[0].iced), None);
    }

    #[test]
    fn arg_spill_rejects_non_rbp_dst() {
        // mov [rax-4], edi (not rbp-relative)
        let bytes = [0x89, 0x78, 0xfc];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(arg_spill_index(&insns[0].iced), None);
    }

    #[test]
    fn lift_return_via_jmp_recognizes_mov_jmp_short() {
        // mov eax, 1; jmp short +0x14
        // Block at 0x1000, jmp short rel8 lands at 0x1009 + signed 0x14 = 0x101d
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x14];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_return_via_jmp(&insns, 0x101b).unwrap();
        assert_eq!(lifted.value, 1);
        assert_eq!(lifted.insns_consumed, 2);
    }

    #[test]
    fn lift_return_via_jmp_rejects_wrong_target() {
        let bytes = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x14];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        // pass a non-matching epilogue address
        assert!(try_lift_return_via_jmp(&insns, 0x9999).is_none());
    }

    #[test]
    fn lift_return_via_jmp_rejects_non_setter() {
        // mov rax, rbx; jmp +5
        let bytes = [0x48, 0x89, 0xd8, 0xeb, 0x05];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let target = insns.last().unwrap().iced.near_branch_target();
        assert!(try_lift_return_via_jmp(&insns, target).is_none());
    }

    #[test]
    fn lift_return_only_consumes_tail() {
        // some_other_insn; mov eax, 0; ret
        let bytes = [0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, 0xc3]; // nop, mov, ret
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_return_pattern(&insns).unwrap();
        assert_eq!(lifted.insns_consumed, 2);
    }

    #[test]
    fn invalid_bytes_fail_decode() {
        let bytes = [0x06];
        assert!(matches!(
            roundtrip_bytes(Bitness::Bits64, &bytes, 0x1000),
            Err(Error::DecodeFailed { .. })
        ));
    }

    #[test]
    fn lift_if_branch_head_recognizes_cmp_jne() {
        // cmp dword ptr [rbp-4], 1; jne short 0x1007 (rel8 = +1)
        // Block at 0x1000: cmp is 4 bytes (ends at 0x1004), jne short
        // is 2 bytes at 0x1004; rel8=1 lands at 0x1004+2+1 = 0x1007.
        let bytes = [0x83, 0x7d, 0xfc, 0x01, 0x75, 0x01];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_if_branch_head(&insns).expect("should match");
        assert_eq!(lifted.insns_consumed, 2);
        assert_eq!(lifted.jcc_target, 0x1007);
        assert_eq!(lifted.cond_bytes, bytes.to_vec());
        // `cmp X,1; jne` → body runs when X == 1 → `"X == 1"`.
        assert!(
            lifted.cond_text.contains("=="),
            "got cond_text: {}",
            lifted.cond_text
        );
    }

    #[test]
    fn lift_if_branch_head_recognizes_test_je() {
        // test eax, eax; je short 0x1004 (off=0)
        let bytes = [0x85, 0xc0, 0x74, 0x00];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let lifted = try_lift_if_branch_head(&insns).expect("should match");
        assert_eq!(lifted.insns_consumed, 2);
        assert_eq!(lifted.jcc_target, 0x1004);
        // `test eax,eax; je` → body runs when eax != 0 → `"eax != 0"`.
        assert_eq!(lifted.cond_text, "eax != 0");
    }

    #[test]
    fn lift_if_branch_head_rejects_unconditional_jmp() {
        // cmp eax,0; jmp +5 — second insn is not a conditional branch
        let bytes = [0x83, 0xf8, 0x00, 0xeb, 0x05];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(try_lift_if_branch_head(&insns).is_none());
    }

    #[test]
    fn direct_lea_rip_target_resolves_rip_relative_load() {
        // lea rax, [rip+0x10]  encoded as 48 8d 05 10 00 00 00 (7 bytes).
        // Block at 0x1000; rip-after-this-insn = 0x1007; target = 0x1017.
        let bytes = [0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(direct_lea_rip_target(&insns[0].iced), Some(0x1017));
    }

    #[test]
    fn direct_lea_rip_target_rejects_non_lea() {
        // mov rax, [rip+0x10]  (also rip-relative but not lea)
        let bytes = [0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(direct_lea_rip_target(&insns[0].iced), None);
    }

    #[test]
    fn direct_lea_rip_target_rejects_non_rip_base() {
        // lea rax, [rbx+0x10] — base is rbx, not rip.
        let bytes = [0x48, 0x8d, 0x43, 0x10];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert_eq!(direct_lea_rip_target(&insns[0].iced), None);
    }

    #[test]
    fn lift_if_branch_head_rejects_non_compare_predecessor() {
        // mov eax, ebx; je short +5 — first insn is not cmp/test
        let bytes = [0x89, 0xd8, 0x74, 0x05];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(try_lift_if_branch_head(&insns).is_none());
    }
}

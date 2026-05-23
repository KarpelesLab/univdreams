//! Linux eBPF + Solana SBF (sBPFv1 / sBPFv2) decoder + minimal
//! lifter.
//!
//! Every BPF "slot" is 8 bytes: a 1-byte opcode, a 1-byte
//! pair of dst/src nibbles, a signed `le16` offset, and a
//! signed `le32` immediate. One special instruction — `lddw`
//! (load 64-bit immediate, opcode 0x18) — takes two
//! consecutive slots: the first carries bits [31:0] in `imm`,
//! the second has opcode 0 and bits [63:32] in its `imm`.
//!
//! Solana SBF (classic / sBPFv1) and Agave sBPFv2 reuse the
//! same encoding with a handful of extra opcodes:
//!   * `CALL_REG` (0x8d) — register-indexed dynamic call (added
//!     in sBPFv1).
//!   * `UDIV` / `SDIV` / `UREM` / `SREM` PQR variants — sBPFv2
//!     dedicated division/remainder ops (the Linux eBPF
//!     opcodes for these slots mean different things or are
//!     absent).
//!   * Explicit sign-extends (`SXH`/`SXW`/`SXD`) — sBPFv2.
//!
//! The decoder is variant-gated. Opcodes we know the mnemonic
//! for in the configured variant emit `InsnKind::*` with a
//! readable text rendering; opcodes we don't recognise emit
//! `InsnKind::Unknown` and the raw 8 bytes are preserved
//! verbatim — the round-trip property holds via byte identity
//! regardless of whether we can name the instruction.
//!
//! References:
//! * Linux Kernel — eBPF Instruction Set, v6.5 docs.
//! * solana_rbpf — text format and SBF-specific opcode set.

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use std::collections::BTreeSet;

use ud_core::VAddr;
use ud_ir::{ArchInsn, BasicBlock, Function, Terminator};

mod assemble;
pub use assemble::{assemble_bpf, desymbolize_bpf_text, AssembleError};

/// On-disk size of one BPF instruction slot.
pub const INSN_SIZE: usize = 8;

/// Variant selector. The bytes for shared opcodes are identical
/// across variants; the variant only changes which opcodes we
/// know the mnemonic for and which ones are *legal* per the
/// runtime that consumes the bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfVariant {
    /// Linux eBPF — base ISA. ELF `e_machine = EM_BPF` (247).
    Linux,
    /// Solana SBF (classic / sBPFv1). Adds `CALL_REG` (0x8d).
    /// The `CALL_IMM` immediate, after relocation, is the
    /// Murmur3 hash of the syscall name (we render the raw
    /// hash; name resolution is out of scope for v1).
    Sbfv1,
    /// Agave sBPFv2. Adds PQR ops (UDIV/SDIV/UREM/SREM) and
    /// explicit sign-extends. Some classic ALU32 implicit
    /// sign-extends behave differently here.
    Sbfv2,
}

/// Errors specific to the BPF backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "byte buffer length {len} is not a multiple of {INSN_SIZE} (BPF slots are fixed-width)"
    )]
    Misaligned { len: usize },
    #[error("lddw at offset {offset:#x} truncated — second slot missing")]
    LddwTruncated { offset: usize },
    #[error("lddw at offset {offset:#x} continuation slot has non-zero opcode {opcode:#x}")]
    LddwBadContinuation { offset: usize, opcode: u8 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Coarse classification — enough to drive CFG construction and
/// to pick the text rendering. The variant-specific mnemonic
/// (e.g. `udiv64` vs `udiv32` for sBPFv2) is derived from the
/// raw `opcode` byte at format time; we don't carry a separate
/// mnemonic field on `DecodedInsn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    /// 32-bit ALU op (`add32`, `mov32`, etc.).
    Alu32,
    /// 64-bit ALU op (`add64`, `mov64`, etc.).
    Alu64,
    /// Unconditional 64-bit jump (`ja +offset`).
    Jmp,
    /// Conditional 64-bit jump (`jeq`, `jne`, `jgt`, …).
    JmpCond,
    /// Conditional 32-bit jump (`jeq32`, `jne32`, …) — eBPF JMP32 class.
    JmpCond32,
    /// `call imm` (helper / syscall — imm is a numeric id or
    /// Murmur3 hash on SBF).
    Call,
    /// `callx r` (register-indirect call) — SBFv1+.
    CallReg,
    /// `exit`.
    Exit,
    /// Memory load (LD / LDX class).
    Load,
    /// Memory store (ST / STX class).
    Store,
    /// First slot of `lddw r, imm64` — `imm64` carries the
    /// combined 64-bit immediate.
    Lddw,
    /// Second slot of `lddw` (opcode 0, imm is the high 32 of
    /// the 64-bit value).
    LddwSecondHalf,
    /// Endian conversion (`be16`/`be32`/`be64`/`le16`/`le32`/`le64`).
    Endian,
    /// Bytes don't match any opcode we know in the configured
    /// variant. The raw 8 bytes survive on `DecodedInsn::bytes`.
    Unknown,
}

/// One decoded BPF slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    pub addr: VAddr,
    pub bytes: [u8; INSN_SIZE],
    pub kind: InsnKind,
    pub opcode: u8,
    /// Destination register (low nibble of byte 1).
    pub dst: u8,
    /// Source register (high nibble of byte 1).
    pub src: u8,
    /// 16-bit signed offset, little-endian.
    pub offset: i16,
    /// 32-bit signed immediate, little-endian.
    pub imm: i32,
    /// Combined 64-bit immediate — populated only on the first
    /// slot of LDDW (opcode 0x18); `None` everywhere else.
    pub imm64: Option<u64>,
}

impl DecodedInsn {
    /// Raw 8-byte encoding interpreted as a `u64` (little-endian).
    #[must_use]
    pub fn raw_u64(&self) -> u64 {
        u64::from_le_bytes(self.bytes)
    }
}

impl ArchInsn for DecodedInsn {
    fn addr(&self) -> VAddr {
        self.addr
    }
    fn original_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Decode `bytes` as a BPF instruction stream starting at
/// virtual address `start`. Buffer length must be a multiple of
/// `INSN_SIZE`. The decoder recognises `lddw` (opcode 0x18) and
/// emits two `DecodedInsn`s for it — one `Lddw` carrying the
/// 64-bit immediate, plus a `LddwSecondHalf` continuation —
/// so each output `DecodedInsn` still has exactly 8 bytes.
pub fn decode(bytes: &[u8], start: u64, variant: BpfVariant) -> Result<Vec<DecodedInsn>> {
    if bytes.len() % INSN_SIZE != 0 {
        return Err(Error::Misaligned { len: bytes.len() });
    }
    let mut out = Vec::with_capacity(bytes.len() / INSN_SIZE);
    let mut i = 0usize;
    while i < bytes.len() {
        let slot = &bytes[i..i + INSN_SIZE];
        let raw: [u8; INSN_SIZE] = slot.try_into().expect("INSN_SIZE chunk");
        let addr = start.saturating_add(i as u64);
        let opcode = raw[0];
        let dst = raw[1] & 0x0f;
        let src = (raw[1] >> 4) & 0x0f;
        let offset = i16::from_le_bytes([raw[2], raw[3]]);
        let imm = i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);

        if opcode == 0x18 {
            // LDDW — coalesce with the following slot. When
            // the continuation slot is missing or starts with
            // a non-zero opcode (e.g. a function boundary that
            // happens to land mid-`lddw` after layer-2's
            // call-target harvest), fall through to the
            // generic slot emission below. That way the orphan
            // bytes survive as a `@bpf 0x…` placeholder and
            // round-trip stays byte-identical.
            let has_well_formed_pair =
                i + 2 * INSN_SIZE <= bytes.len() && bytes[i + INSN_SIZE] == 0;
            if !has_well_formed_pair {
                // Treat as a regular slot (no LDDW pairing).
                out.push(DecodedInsn {
                    addr: VAddr(addr),
                    bytes: raw,
                    kind: InsnKind::Unknown,
                    opcode,
                    dst,
                    src,
                    offset,
                    imm,
                    imm64: None,
                });
                i += INSN_SIZE;
                continue;
            }
            let cont = &bytes[i + INSN_SIZE..i + 2 * INSN_SIZE];
            let imm_hi = u32::from_le_bytes([cont[4], cont[5], cont[6], cont[7]]);
            let imm_lo = imm as u32;
            let imm64 = (u64::from(imm_hi) << 32) | u64::from(imm_lo);
            out.push(DecodedInsn {
                addr: VAddr(addr),
                bytes: raw,
                kind: InsnKind::Lddw,
                opcode,
                dst,
                src,
                offset,
                imm,
                imm64: Some(imm64),
            });
            let cont_raw: [u8; INSN_SIZE] = cont.try_into().expect("INSN_SIZE chunk");
            let cont_addr = addr.wrapping_add(INSN_SIZE as u64);
            out.push(DecodedInsn {
                addr: VAddr(cont_addr),
                bytes: cont_raw,
                kind: InsnKind::LddwSecondHalf,
                opcode: 0,
                dst: cont_raw[1] & 0x0f,
                src: (cont_raw[1] >> 4) & 0x0f,
                offset: i16::from_le_bytes([cont_raw[2], cont_raw[3]]),
                imm: i32::from_le_bytes([cont_raw[4], cont_raw[5], cont_raw[6], cont_raw[7]]),
                imm64: None,
            });
            i += 2 * INSN_SIZE;
            continue;
        }

        let kind = classify_opcode(opcode, variant);
        out.push(DecodedInsn {
            addr: VAddr(addr),
            bytes: raw,
            kind,
            opcode,
            dst,
            src,
            offset,
            imm,
            imm64: None,
        });
        i += INSN_SIZE;
    }
    Ok(out)
}

/// Pure re-classifier — re-derives `kind` from `opcode` + the
/// configured variant. Useful when something wants to re-walk a
/// slice of decoded slots after the fact (matches the
/// `classify` contract from other arch crates).
#[must_use]
pub fn classify(insn: &DecodedInsn, variant: BpfVariant) -> InsnKind {
    classify_opcode(insn.opcode, variant)
}

fn classify_opcode(opcode: u8, variant: BpfVariant) -> InsnKind {
    let class = opcode & 0x07;
    // sBPFv2 reuses the ALU32 div/mod opcode bytes for explicit
    // PQR variants (UDIV / UREM / SDIV / SREM 32-bit) — same
    // raw bytes, different runtime semantics. Pattern-match the
    // ones we know so future passes can render the right
    // mnemonic.
    let _ = variant;
    match class {
        // BPF_LD (0x00) — non-register-indexed loads, and
        // BPF_LDX (0x01) — register-indexed (`ldxb/h/w/dw`).
        // Both reach us as `Load`; the formatter picks the
        // exact mnemonic from the opcode byte.
        0x00 | 0x01 => InsnKind::Load,
        // BPF_ST (0x02) — immediate store; BPF_STX (0x03) —
        // register store. Same `Store` classification for CFG
        // purposes.
        0x02 | 0x03 => InsnKind::Store,
        // BPF_ALU (0x04) — 32-bit ALU; `END` (byte-swap /
        // endian conversion) lives at op nibble 0xd.
        0x04 => {
            if (opcode >> 4) == 0xd {
                InsnKind::Endian
            } else {
                InsnKind::Alu32
            }
        }
        // BPF_JMP (0x05) — 64-bit jumps.
        0x05 => classify_jmp(opcode, variant),
        // BPF_JMP32 (0x06) — 32-bit-compare conditional jumps.
        0x06 => classify_jmp32(opcode),
        // BPF_ALU64 (0x07) — 64-bit ALU; 0xd is the (rare)
        // 64-bit endian slot.
        0x07 => {
            if (opcode >> 4) == 0xd {
                InsnKind::Endian
            } else {
                InsnKind::Alu64
            }
        }
        _ => InsnKind::Unknown,
    }
}

/// Classify an opcode in `BPF_JMP` class (low 3 bits = 5).
fn classify_jmp(opcode: u8, variant: BpfVariant) -> InsnKind {
    let op = opcode >> 4;
    match op {
        // JA = 0x05 (op nibble 0, class 5).
        0x0 => InsnKind::Jmp,
        // CALL (0x85) and CALL-with-src=1 (0x8d) both live in
        // JMP class with op nibble 0x8. On Linux eBPF 0x8d is
        // a BPF-to-BPF local call (imm is a relative slot
        // offset); on SBF it's CALLX (register-source). Either
        // way it's a call, not a conditional jump.
        0x8 => {
            if opcode == 0x8d && matches!(variant, BpfVariant::Sbfv1 | BpfVariant::Sbfv2) {
                InsnKind::CallReg
            } else if opcode == 0x8d {
                // Linux BPF-to-BPF call: target = next + imm*8,
                // same shape as a CALL_IMM. Classify as Call so
                // layer-2 picks up the target.
                InsnKind::Call
            } else if opcode == 0x85 {
                InsnKind::Call
            } else {
                InsnKind::JmpCond
            }
        }
        // EXIT = 0x95.
        0x9 if opcode == 0x95 => InsnKind::Exit,
        // Everything else in JMP class is a conditional jump
        // (JEQ/JGT/JGE/JSET/JNE/JSGT/JSGE/JLT/JLE/JSLT/JSLE),
        // either reg- or imm-source. Either way the CFG cares
        // about the offset to the taken branch.
        _ => InsnKind::JmpCond,
    }
}

fn classify_jmp32(opcode: u8) -> InsnKind {
    // All JMP32 opcodes are conditional (there's no unconditional
    // ja32; ja stays in the JMP class).
    let _ = opcode;
    InsnKind::JmpCond32
}

/// Compute the absolute byte-address target of a relative jump.
/// BPF offsets are in *slots* (8 bytes each) and apply to the
/// instruction *after* this one.
#[must_use]
pub fn jump_target(insn: &DecodedInsn) -> u64 {
    let next_slot = insn.addr.0.wrapping_add(INSN_SIZE as u64);
    let off_bytes = i64::from(insn.offset).wrapping_mul(INSN_SIZE as i64);
    next_slot.wrapping_add(off_bytes as u64)
}

/// Compute the absolute byte-address target of a `call <imm>`
/// instruction *for a local call*. The `imm` field on a BPF
/// `call` is a signed slot offset relative to the next slot.
///
/// Callers should first verify the call isn't a syscall — for
/// the Linux kernel the `imm` is a helper-id and is *not* a
/// code offset; for SBF the `imm` is a Murmur3 hash (or `-1`
/// before relocation) and again is not a code offset. The
/// usual discriminator is "is this call site in the
/// relocation-resolved syscall map?" — see
/// `ud_analysis::bpf_relocs::build_call_site_names`.
#[must_use]
pub fn call_target(insn: &DecodedInsn) -> u64 {
    let next_slot = insn.addr.0.wrapping_add(INSN_SIZE as u64);
    let off_bytes = i64::from(insn.imm).wrapping_mul(INSN_SIZE as i64);
    next_slot.wrapping_add(off_bytes as u64)
}

/// Lift a decoded instruction stream into a CFG.
///
/// Slices the stream into basic blocks at every intra-function
/// jump target and immediately after every control-flow exit
/// (`exit` / unconditional `ja` / conditional `j*`). The
/// resulting `Function<DecodedInsn>` is suitable for
/// downstream SSA / dominance / liveness analyses — joins at
/// reconvergence points generate proper phi placement, which
/// the previous single-block-per-function shape could never
/// produce.
///
/// Calls (`call imm` and indirect `callx`) are **not** block
/// terminators: control flow returns through them
/// normally and the following slot stays in the same block.
/// Only when a call is the function's last instruction does
/// `Terminator::IndirectBranch` surface on its block.
///
/// The byte-identity contract still holds — every instruction
/// rides in some block in original address order, and
/// `Function::emit_bytes` concatenates blocks back into the
/// original byte stream.
#[must_use]
pub fn lift_function(name: String, insns: &[DecodedInsn]) -> Function<DecodedInsn> {
    let addr = insns.first().map_or(VAddr(0), |i| i.addr);
    if insns.is_empty() {
        return Function {
            addr,
            name,
            blocks: Vec::new(),
        };
    }
    let fn_start = addr.0;
    let fn_end = insns
        .last()
        .map_or(fn_start, |i| i.addr.0.wrapping_add(INSN_SIZE as u64));

    // Collect block boundaries: function entry, every intra-
    // function jump target, and the slot immediately after
    // every control-flow exit (jmp/jcc/exit). LDDW second
    // halves are never boundary candidates — the verifier
    // forbids jumps into mid-`lddw` and we never need to
    // split between the two slots of an `lddw` pair.
    let mut boundaries: BTreeSet<u64> = BTreeSet::new();
    boundaries.insert(fn_start);
    for i in insns {
        if matches!(
            i.kind,
            InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32
        ) {
            let t = jump_target(i);
            if (fn_start..fn_end).contains(&t) {
                boundaries.insert(t);
            }
        }
        if matches!(
            i.kind,
            InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32 | InsnKind::Exit
        ) {
            let next = i.addr.0.wrapping_add(INSN_SIZE as u64);
            if next < fn_end {
                boundaries.insert(next);
            }
        }
    }

    // Walk the stream once, emitting a block whenever the
    // current insn lands on a boundary (and we have prior
    // insns accumulated).
    let mut blocks: Vec<BasicBlock<DecodedInsn>> = Vec::new();
    let mut current: Vec<DecodedInsn> = Vec::new();
    let mut current_addr: u64 = fn_start;
    for i in insns {
        if boundaries.contains(&i.addr.0) && !current.is_empty() {
            let term = block_terminator(&current);
            blocks.push(BasicBlock {
                addr: VAddr(current_addr),
                insns: std::mem::take(&mut current),
                terminator: term,
            });
            current_addr = i.addr.0;
        }
        current.push(i.clone());
    }
    if !current.is_empty() {
        let term = block_terminator(&current);
        blocks.push(BasicBlock {
            addr: VAddr(current_addr),
            insns: current,
            terminator: term,
        });
    }

    Function { addr, name, blocks }
}

/// Pick the terminator for a block from its last instruction's
/// kind. Falls through to the next block when the last insn
/// isn't a control-flow primitive — typically because the
/// block ended at a jump target rather than at an exit.
fn block_terminator(insns: &[DecodedInsn]) -> Terminator {
    let Some(last) = insns.last() else {
        return Terminator::Fallthrough;
    };
    match last.kind {
        InsnKind::Exit => Terminator::Return,
        InsnKind::Jmp => Terminator::UnconditionalBranch {
            target: VAddr(jump_target(last)),
        },
        InsnKind::JmpCond | InsnKind::JmpCond32 => Terminator::ConditionalBranch {
            taken: VAddr(jump_target(last)),
            fallthrough: VAddr(last.addr.0.wrapping_add(INSN_SIZE as u64)),
        },
        InsnKind::CallReg => Terminator::IndirectBranch,
        _ => Terminator::Fallthrough,
    }
}

// ============================================================
// Text rendering — solana_rbpf / llvm-objdump style.
// ============================================================

/// Render a decoded instruction as text. Matches the
/// solana_rbpf / llvm-objdump dialect closely enough that a
/// reader who knows BPF will recognise everything.
#[must_use]
pub fn format_insn(insn: &DecodedInsn, variant: BpfVariant) -> String {
    if matches!(insn.kind, InsnKind::LddwSecondHalf) {
        // The continuation half of LDDW has no standalone
        // mnemonic; render it as bytes-only so the .ud reader
        // sees the pair clearly.
        return format!("<lddw-cont 0x{:08x}>", insn.imm as u32);
    }
    let class = insn.opcode & 0x07;
    match class {
        0x00 | 0x01 => format_ld(insn),
        0x02 | 0x03 => format_st(insn),
        0x04 => format_alu(insn, /* alu64 */ false, variant),
        0x05 => format_jmp(insn, /* is_32 */ false, variant),
        0x06 => format_jmp(insn, /* is_32 */ true, variant),
        0x07 => format_alu(insn, /* alu64 */ true, variant),
        _ => format!("<bpf 0x{:016x}>", insn.raw_u64()),
    }
}

fn format_ld(insn: &DecodedInsn) -> String {
    // LDDW (opcode 0x18) — load 64-bit immediate.
    if insn.opcode == 0x18 {
        let imm = insn.imm64.unwrap_or(0);
        return format!("lddw r{}, 0x{:x}", insn.dst, imm);
    }
    // LD_ABS / LD_IND (legacy packet loads, opcodes 0x20, 0x28,
    // 0x30, 0x38, 0x40, 0x48, 0x50). Render generically; corpus
    // codecs rarely use them.
    if matches!(insn.opcode, 0x20 | 0x28 | 0x30 | 0x38 | 0x40 | 0x48 | 0x50) {
        let sz = size_letter(insn.opcode);
        return format!("ld_abs_{sz} r0, 0x{:x}", insn.imm as u32);
    }
    // LDX class — `ldx{b,h,w,dw} dst, [src + offset]`.
    let sz = size_letter(insn.opcode);
    let offset = format_offset(insn.offset);
    format!("ldx{sz} r{}, [r{}{offset}]", insn.dst, insn.src)
}

fn format_st(insn: &DecodedInsn) -> String {
    let sz = size_letter(insn.opcode);
    let offset = format_offset(insn.offset);
    if (insn.opcode & 0x07) == 0x02 {
        // ST_IMM — immediate store.
        format!("st{sz} [r{}{offset}], 0x{:x}", insn.dst, insn.imm as u32)
    } else {
        // STX — register store.
        format!("stx{sz} [r{}{offset}], r{}", insn.dst, insn.src)
    }
}

fn size_letter(opcode: u8) -> &'static str {
    // BPF size field is bits 3..4 of the opcode (mask 0x18):
    //   0x00 = W (32-bit), 0x08 = H (16-bit), 0x10 = B (8-bit),
    //   0x18 = DW (64-bit).
    match opcode & 0x18 {
        0x00 => "w",
        0x08 => "h",
        0x10 => "b",
        0x18 => "dw",
        _ => unreachable!(),
    }
}

fn format_offset(offset: i16) -> String {
    use std::cmp::Ordering;
    match offset.cmp(&0) {
        Ordering::Equal => String::new(),
        Ordering::Greater => format!(" + 0x{offset:x}"),
        Ordering::Less => {
            let abs = u32::from(offset.unsigned_abs());
            format!(" - 0x{abs:x}")
        }
    }
}

fn format_alu(insn: &DecodedInsn, alu64: bool, variant: BpfVariant) -> String {
    // Source bit (bit 3 of opcode): 0 = imm source, 1 = reg source.
    let is_reg = (insn.opcode & 0x08) != 0;
    let op_nibble = insn.opcode >> 4;
    let suffix = if alu64 { "64" } else { "32" };
    let mnemonic = match (op_nibble, alu64, variant) {
        (0x0, _, _) => "add",
        (0x1, _, _) => "sub",
        (0x2, _, _) => "mul",
        (0x3, _, BpfVariant::Linux | BpfVariant::Sbfv1) => "div",
        // sBPFv2: 0x3 in ALU class is `udiv` per the PQR spec.
        // Same byte; the mnemonic differs.
        (0x3, _, BpfVariant::Sbfv2) => "udiv",
        (0x4, _, _) => "or",
        (0x5, _, _) => "and",
        (0x6, _, _) => "lsh",
        (0x7, _, _) => "rsh",
        (0x8, _, _) => "neg",
        (0x9, _, BpfVariant::Linux | BpfVariant::Sbfv1) => "mod",
        (0x9, _, BpfVariant::Sbfv2) => "urem",
        (0xa, _, _) => "xor",
        (0xb, _, _) => "mov",
        (0xc, _, _) => "arsh",
        (0xd, _, _) => return format_endian(insn),
        // sBPFv2 added SDIV / SREM in op-nibbles 0xe / 0xf.
        (0xe, _, BpfVariant::Sbfv2) => "sdiv",
        (0xf, _, BpfVariant::Sbfv2) => "srem",
        _ => "<alu?>",
    };
    if matches!(op_nibble, 0x8) {
        // `neg` is single-operand.
        return format!("neg{suffix} r{}", insn.dst);
    }
    if is_reg {
        format!("{mnemonic}{suffix} r{}, r{}", insn.dst, insn.src)
    } else {
        format!("{mnemonic}{suffix} r{}, 0x{:x}", insn.dst, insn.imm as u32)
    }
}

fn format_endian(insn: &DecodedInsn) -> String {
    // `be`/`le` family: opcode = 0xd4 (le) or 0xdc (be); imm
    // carries the width (16, 32, or 64).
    let dir = if (insn.opcode & 0x08) == 0 {
        "le"
    } else {
        "be"
    };
    format!("{dir}{} r{}", insn.imm, insn.dst)
}

fn format_jmp(insn: &DecodedInsn, is_32: bool, _variant: BpfVariant) -> String {
    let op = insn.opcode >> 4;
    // JA — unconditional.
    if op == 0 && !is_32 && insn.opcode == 0x05 {
        return format!("ja {}", format_branch_offset(insn.offset));
    }
    // CALL — imm-source helper / syscall.
    if insn.opcode == 0x85 {
        return format!("call 0x{:x}", insn.imm as u32);
    }
    // CALLX — register-indirect call (SBF).
    if insn.opcode == 0x8d {
        return format!("callx r{}", insn.dst);
    }
    // EXIT.
    if insn.opcode == 0x95 {
        return "exit".into();
    }
    let is_reg = (insn.opcode & 0x08) != 0;
    let suffix = if is_32 { "32" } else { "" };
    let mnemonic = match op {
        0x1 => "jeq",
        0x2 => "jgt",
        0x3 => "jge",
        0x4 => "jset",
        0x5 => "jne",
        0x6 => "jsgt",
        0x7 => "jsge",
        0xa => "jlt",
        0xb => "jle",
        0xc => "jslt",
        0xd => "jsle",
        _ => "<jcc?>",
    };
    let rhs = if is_reg {
        format!("r{}", insn.src)
    } else {
        format!("0x{:x}", insn.imm as u32)
    };
    format!(
        "{mnemonic}{suffix} r{}, {rhs}, {}",
        insn.dst,
        format_branch_offset(insn.offset)
    )
}

fn format_branch_offset(offset: i16) -> String {
    if offset >= 0 {
        format!("+0x{offset:x}")
    } else {
        let abs = u32::from(offset.unsigned_abs());
        format!("-0x{abs:x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decoded shape for the fixture filter() function:
    /// 79 11 00 00 ... — ldxdw r1, [r1 + 0]
    /// b4 00 00 00 ... — mov32 r0, 0
    /// 15 01 02 00 ... — jeq r1, 0, +2
    /// 04 01 00 00 01 00 00 00 — add32 r1, 1
    /// bc 10 00 00 ... — mov32 r0, r1
    /// 95 00 00 00 ... — exit
    #[test]
    fn decodes_fixture_filter() {
        let bytes: Vec<u8> = vec![
            0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ldxdw r1, [r1+0]
            0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
            0x15, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // jeq r1, 0, +2
            0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r1, 1
            0xbc, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, r1
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let insns = decode(&bytes, 0, BpfVariant::Linux).unwrap();
        assert_eq!(insns.len(), 6);
        assert_eq!(insns[0].kind, InsnKind::Load);
        assert_eq!(insns[1].kind, InsnKind::Alu32);
        assert_eq!(insns[2].kind, InsnKind::JmpCond);
        assert_eq!(insns[5].kind, InsnKind::Exit);

        // Round-trip property — every decoded slot's bytes equal
        // the input bytes at its offset.
        let mut reconstructed: Vec<u8> = Vec::with_capacity(bytes.len());
        for i in &insns {
            reconstructed.extend_from_slice(&i.bytes);
        }
        assert_eq!(reconstructed, bytes);
    }

    #[test]
    fn rejects_misaligned_buffer() {
        let bytes = [0u8; 7];
        assert!(matches!(
            decode(&bytes, 0, BpfVariant::Linux),
            Err(Error::Misaligned { len: 7 })
        ));
    }

    #[test]
    fn lddw_pairs_two_slots() {
        // 18 01 00 00 78 56 34 12 — lddw r1, 0x...12345678 (low)
        // 00 00 00 00 ef cd ab 90 — continuation        (high = 0x90abcdef)
        let bytes: Vec<u8> = vec![
            0x18, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0xef, 0xcd,
            0xab, 0x90,
        ];
        let insns = decode(&bytes, 0, BpfVariant::Linux).unwrap();
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].kind, InsnKind::Lddw);
        assert_eq!(insns[0].imm64, Some(0x90ab_cdef_1234_5678));
        assert_eq!(insns[1].kind, InsnKind::LddwSecondHalf);
        assert_eq!(insns[1].bytes, [0, 0, 0, 0, 0xef, 0xcd, 0xab, 0x90]);
    }

    #[test]
    fn exit_drives_return_terminator() {
        let bytes = [0x95, 0, 0, 0, 0, 0, 0, 0];
        let insns = decode(&bytes, 0x100, BpfVariant::Linux).unwrap();
        let f = lift_function("f".into(), &insns);
        assert_eq!(f.blocks[0].terminator, Terminator::Return);
    }

    #[test]
    fn opcode_8d_classification_per_variant() {
        // 0x8d in JMP class with the source bit set:
        //   * SBFv1+: register-source callx (`callx r3`).
        //   * Linux eBPF: BPF-to-BPF local call (`imm` is a
        //     relative slot offset).
        // Both classify as a "call" — register-target on SBF,
        // imm-target on Linux.
        let bytes = [0x8d, 0x30, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode(&bytes, 0, BpfVariant::Linux).unwrap()[0].kind,
            InsnKind::Call,
        );
        assert_eq!(
            decode(&bytes, 0, BpfVariant::Sbfv1).unwrap()[0].kind,
            InsnKind::CallReg,
        );
    }

    #[test]
    fn formats_basic_ops() {
        let bytes: Vec<u8> = vec![
            0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let insns = decode(&bytes, 0, BpfVariant::Linux).unwrap();
        assert_eq!(format_insn(&insns[0], BpfVariant::Linux), "ldxdw r1, [r1]");
        assert_eq!(format_insn(&insns[1], BpfVariant::Linux), "mov32 r0, 0x0");
        assert_eq!(format_insn(&insns[2], BpfVariant::Linux), "exit");
    }
}

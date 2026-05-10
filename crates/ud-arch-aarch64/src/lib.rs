//! AArch64 instruction decoder + minimal lifter.
//!
//! v0 scope is intentionally narrow: AArch64 instructions are
//! fixed-width 4 bytes, so the decoder just splits the input into
//! 4-byte chunks. Each chunk gets a coarse classification —
//! enough to extract direct branch targets and identify returns,
//! which is what the IR layer needs to build basic blocks. Full
//! mnemonic + operand printing isn't here yet; instructions render
//! as `<arm64 0xXXXXXXXX>` placeholder text alongside their pinned
//! bytes, so the round-trip property holds via byte identity.
//!
//! Future iterations will wire in a real disassembler (`bad64` or
//! similar) to produce readable `@asm` text and unlock the same
//! lifting passes the x86 backend has (prologue/epilogue lift,
//! call-site analysis, if/else groups).

#![allow(clippy::cast_possible_truncation)]

use ud_core::VAddr;
use ud_ir::{ArchInsn, BasicBlock, Function, Terminator};

/// On-disk size of every AArch64 instruction.
pub const INSN_SIZE: usize = 4;

/// Errors specific to the AArch64 backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "byte buffer length {len} is not a multiple of {INSN_SIZE} (AArch64 insns are fixed-width)"
    )]
    Misaligned { len: usize },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Coarse classification of an AArch64 instruction. Enough to pick
/// out flow-control behaviour for CFG construction; everything else
/// falls into `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnKind {
    /// Unconditional direct branch (`B target`).
    BranchDirect { target: u64 },
    /// Conditional direct branch (`B.cond target`).
    BranchConditional { taken: u64, fallthrough: u64 },
    /// Compare-and-branch zero / non-zero (`CBZ`, `CBNZ`) — also a
    /// conditional direct branch in CFG terms.
    CompareAndBranch { taken: u64, fallthrough: u64 },
    /// Test-bit-and-branch zero / non-zero (`TBZ`, `TBNZ`).
    TestBitAndBranch { taken: u64, fallthrough: u64 },
    /// Direct call (`BL target`).
    BranchLink { target: u64 },
    /// Indirect branch (`BR Xn`).
    BranchRegister,
    /// Indirect call (`BLR Xn`).
    BranchLinkRegister,
    /// Return (`RET [Xn]`). Defaults to `RET X30` when no register
    /// is given.
    Return,
    /// `NOP` — encoded as `D503201F` (HINT #0).
    Nop,
    /// Anything else.
    Other,
}

/// One decoded AArch64 instruction. Carries the raw 4-byte
/// encoding, the address it lived at, and a coarse `InsnKind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInsn {
    pub addr: VAddr,
    pub bytes: [u8; INSN_SIZE],
    pub kind: InsnKind,
}

impl DecodedInsn {
    /// The 32-bit little-endian encoding as a `u32`.
    #[must_use]
    pub fn opcode(&self) -> u32 {
        u32::from_le_bytes(self.bytes)
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

/// Decode `bytes` as an AArch64 instruction stream starting at
/// virtual address `start`. The buffer length must be a multiple of
/// `INSN_SIZE` — AArch64 has no concept of "the rest is data" the
/// way x86 does, so a misaligned tail is a hard error.
pub fn decode(bytes: &[u8], start: u64) -> Result<Vec<DecodedInsn>> {
    if bytes.len() % INSN_SIZE != 0 {
        return Err(Error::Misaligned { len: bytes.len() });
    }
    let mut out = Vec::with_capacity(bytes.len() / INSN_SIZE);
    for (i, chunk) in bytes.chunks_exact(INSN_SIZE).enumerate() {
        let addr = start.saturating_add((i * INSN_SIZE) as u64);
        let mut raw = [0u8; INSN_SIZE];
        raw.copy_from_slice(chunk);
        let opcode = u32::from_le_bytes(raw);
        let kind = classify(opcode, addr);
        out.push(DecodedInsn {
            addr: VAddr(addr),
            bytes: raw,
            kind,
        });
    }
    Ok(out)
}

/// Classify a single 32-bit instruction word. Recognises the
/// branch / return / nop encodings; everything else is `Other`.
///
/// Encodings (per the AArch64 ARM):
///
/// * `B target`           — `0001_01ii_iiii_iiii_iiii_iiii_iiii_iiii`
///   (top 6 bits 000101); imm26 is a signed `<<2` PC-relative offset.
/// * `BL target`          — `1001_01ii_iiii_iiii_iiii_iiii_iiii_iiii`
///   (top 6 bits 100101); same imm26.
/// * `B.cond target`      — `0101_0100_iiii_iiii_iiii_iiii_iii0_cccc`
///   (top byte 0x54, bit 4 zero); imm19 is a signed `<<2` PC-rel offset.
/// * `CBZ/CBNZ Rt, target` — `?011_010?_iiii_iiii_iiii_iiii_iiit_tttt`;
///   imm19 is a signed `<<2` PC-relative offset.
/// * `TBZ/TBNZ Rt, #b, target` — `?011_011?_bbbb_biii_iiii_iiii_iiit_tttt`;
///   imm14 is a signed `<<2` PC-relative offset.
/// * `BR Xn`              — `1101_0110_0001_1111_0000_00nn_nnn0_0000`
/// * `BLR Xn`             — `1101_0110_0011_1111_0000_00nn_nnn0_0000`
/// * `RET [Xn]`           — `1101_0110_0101_1111_0000_00nn_nnn0_0000`
/// * `NOP`                — `1101_0101_0000_0011_0010_0000_0001_1111`
fn classify(opcode: u32, addr: u64) -> InsnKind {
    /// Mask used to identify the RET / BR / BLR encoding shape
    /// `1101_0110_xxxx_1111_0000_00nn_nnn0_0000` — the `xxxx` field
    /// distinguishes the variant.
    const INDIRECT_BRANCH_MASK: u32 = 0xffff_fc1f;

    // NOP — exact encoding D503201F.
    if opcode == 0xd503_201f {
        return InsnKind::Nop;
    }
    if (opcode & INDIRECT_BRANCH_MASK) == 0xd65f_0000 {
        return InsnKind::Return;
    }
    if (opcode & INDIRECT_BRANCH_MASK) == 0xd61f_0000 {
        return InsnKind::BranchRegister;
    }
    if (opcode & INDIRECT_BRANCH_MASK) == 0xd63f_0000 {
        return InsnKind::BranchLinkRegister;
    }
    // B / BL — top 6 bits 000101 / 100101.
    if (opcode & 0xfc00_0000) == 0x1400_0000 {
        let target = pc_rel26(addr, opcode);
        return InsnKind::BranchDirect { target };
    }
    if (opcode & 0xfc00_0000) == 0x9400_0000 {
        let target = pc_rel26(addr, opcode);
        return InsnKind::BranchLink { target };
    }
    // B.cond — top byte 0x54, bit 4 zero.
    if (opcode & 0xff00_0010) == 0x5400_0000 {
        let taken = pc_rel19(addr, opcode);
        let fallthrough = addr.wrapping_add(INSN_SIZE as u64);
        return InsnKind::BranchConditional { taken, fallthrough };
    }
    // CBZ / CBNZ — bits [30:25] == 011010.
    if (opcode & 0x7e00_0000) == 0x3400_0000 {
        let taken = pc_rel19(addr, opcode);
        let fallthrough = addr.wrapping_add(INSN_SIZE as u64);
        return InsnKind::CompareAndBranch { taken, fallthrough };
    }
    // TBZ / TBNZ — bits [30:25] == 011011.
    if (opcode & 0x7e00_0000) == 0x3600_0000 {
        let taken = pc_rel14(addr, opcode);
        let fallthrough = addr.wrapping_add(INSN_SIZE as u64);
        return InsnKind::TestBitAndBranch { taken, fallthrough };
    }
    InsnKind::Other
}

/// PC-relative target for a 26-bit `<<2` immediate (B / BL).
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn pc_rel26(addr: u64, opcode: u32) -> u64 {
    let imm26 = opcode & 0x03ff_ffff;
    // Sign-extend from 26 bits and shift left 2.
    let signed = ((imm26 as i32) << 6) >> 6;
    let off = i64::from(signed) << 2;
    addr.wrapping_add(off as u64) // sign bits roll into u64; intentional
}

/// PC-relative target for a 19-bit `<<2` immediate (B.cond, CBZ).
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn pc_rel19(addr: u64, opcode: u32) -> u64 {
    let imm19 = (opcode >> 5) & 0x0007_ffff;
    let signed = ((imm19 as i32) << 13) >> 13;
    let off = i64::from(signed) << 2;
    addr.wrapping_add(off as u64) // sign bits roll into u64; intentional
}

/// PC-relative target for a 14-bit `<<2` immediate (TBZ).
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn pc_rel14(addr: u64, opcode: u32) -> u64 {
    let imm14 = (opcode >> 5) & 0x0000_3fff;
    let signed = ((imm14 as i32) << 18) >> 18;
    let off = i64::from(signed) << 2;
    addr.wrapping_add(off as u64) // sign bits roll into u64; intentional
}

/// Render an instruction as placeholder text alongside its bytes.
/// v0: emits `<arm64 0xXXXXXXXX>` (mnemonic-based when classified)
/// — full disassembly comes when we wire a real decoder.
#[must_use]
pub fn format_text(insn: &DecodedInsn) -> String {
    match insn.kind {
        InsnKind::BranchDirect { target } => format!("b 0x{target:x}"),
        InsnKind::BranchLink { target } => format!("bl 0x{target:x}"),
        InsnKind::BranchConditional { taken, .. } => format!("b.cond 0x{taken:x}"),
        InsnKind::CompareAndBranch { taken, .. } => format!("cbz/cbnz 0x{taken:x}"),
        InsnKind::TestBitAndBranch { taken, .. } => format!("tbz/tbnz 0x{taken:x}"),
        InsnKind::BranchRegister => "br".into(),
        InsnKind::BranchLinkRegister => "blr".into(),
        InsnKind::Return => "ret".into(),
        InsnKind::Nop => "nop".into(),
        InsnKind::Other => format!("<arm64 0x{:08x}>", insn.opcode()),
    }
}

/// Lift a decoded instruction stream into a CFG.
///
/// v0: build a single basic block for the whole function. Once we
/// have full mnemonic decoding we can wire in proper block splitting
/// at branch targets (mirroring the x86 lift in
/// `ud_arch_x86::lift_function`).
#[must_use]
pub fn lift_function(name: String, insns: &[DecodedInsn]) -> Function<DecodedInsn> {
    let addr = insns.first().map_or(VAddr(0), |i| i.addr);
    let terminator = insns
        .last()
        .map_or(Terminator::Fallthrough, |i| match i.kind {
            InsnKind::Return => Terminator::Return,
            InsnKind::BranchDirect { target } => Terminator::UnconditionalBranch {
                target: VAddr(target),
            },
            InsnKind::BranchConditional { taken, fallthrough }
            | InsnKind::CompareAndBranch { taken, fallthrough }
            | InsnKind::TestBitAndBranch { taken, fallthrough } => Terminator::ConditionalBranch {
                taken: VAddr(taken),
                fallthrough: VAddr(fallthrough),
            },
            InsnKind::BranchRegister | InsnKind::BranchLinkRegister => Terminator::IndirectBranch,
            _ => Terminator::Fallthrough,
        });
    Function {
        addr,
        name,
        blocks: vec![BasicBlock {
            addr,
            insns: insns.to_vec(),
            terminator,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_splits_into_4byte_words() {
        // ret = 0xd65f03c0 (encoded little-endian on disk).
        let bytes = [
            0xc0, 0x03, 0x5f, 0xd6, // ret
            0x1f, 0x20, 0x03, 0xd5, // nop
        ];
        let insns = decode(&bytes, 0x1000).unwrap();
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].addr, VAddr(0x1000));
        assert_eq!(insns[0].kind, InsnKind::Return);
        assert_eq!(insns[1].addr, VAddr(0x1004));
        assert_eq!(insns[1].kind, InsnKind::Nop);
    }

    #[test]
    fn rejects_misaligned_buffer() {
        let bytes = [0x00, 0x01, 0x02];
        assert!(matches!(
            decode(&bytes, 0x1000),
            Err(Error::Misaligned { len: 3 })
        ));
    }

    #[test]
    fn classifies_b_with_signed_target() {
        // B +0x10 — opcode 0x14000004 (imm26 = 4, target = pc + 16).
        let opcode: u32 = 0x14_00_00_04;
        let bytes = opcode.to_le_bytes();
        let insns = decode(&bytes, 0x1000).unwrap();
        assert_eq!(insns[0].kind, InsnKind::BranchDirect { target: 0x1010 });
    }

    #[test]
    fn classifies_bl_with_negative_target() {
        // BL -8 — bits 100101 + imm26 = -2 (= 0x03ff_fffe).
        // Encoding: 0x97_ff_ff_fe.
        let opcode: u32 = 0x97_ff_ff_fe;
        let bytes = opcode.to_le_bytes();
        let insns = decode(&bytes, 0x2000).unwrap();
        assert_eq!(insns[0].kind, InsnKind::BranchLink { target: 0x1ff8 });
    }

    #[test]
    fn classifies_b_cond() {
        // B.EQ +8 — top byte 0x54, imm19 = 2 (target = pc+8), cond = 0.
        // 0x5400_0040.
        let opcode: u32 = 0x54_00_00_40;
        let bytes = opcode.to_le_bytes();
        let insns = decode(&bytes, 0x1000).unwrap();
        assert!(matches!(
            insns[0].kind,
            InsnKind::BranchConditional { taken: 0x1008, .. }
        ));
    }

    #[test]
    fn ret_kind_drives_terminator() {
        // mov; ret (mov w0, #0 = 0x52800000; ret = 0xd65f03c0).
        let bytes = [0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
        let insns = decode(&bytes, 0x1000).unwrap();
        let f = lift_function("f".into(), &insns);
        assert_eq!(f.blocks.len(), 1);
        assert_eq!(f.blocks[0].terminator, Terminator::Return);
    }
}

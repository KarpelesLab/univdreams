//! `ArchCodec` implementation for BPF (Linux eBPF + Solana SBF
//! v1 / v2).
//!
//! Each codec instance carries a [`BpfVariant`]. The trait
//! methods that need slot-offset arithmetic compute it from
//! `(source_ip, target)` then delegate to the existing
//! `assemble_bpf_*` family.
//!
//! `register()` submits one factory that picks a variant from the
//! parsed module's `arch` field plus its numeric `e_machine`
//! (`EM_BPF = 247` for Linux eBPF; `EM_SBF = 263` for Solana SBF).

use crate::{
    assemble_bpf, assemble_bpf_ifblock_cond, assemble_bpf_ja, desymbolize_bpf_text, BpfVariant,
    INSN_SIZE,
};
use ud_arch_codec::{ArchCodec, ArchError, EncodeHints, SwitchSpec};

/// One codec per BPF variant.
#[derive(Debug, Clone, Copy)]
pub struct BpfCodec(pub BpfVariant);

impl BpfCodec {
    /// Linux eBPF (base ISA).
    pub const LINUX: Self = Self(BpfVariant::Linux);
    /// Solana sBPFv1.
    pub const SBF_V1: Self = Self(BpfVariant::Sbfv1);
    /// Agave sBPFv2.
    pub const SBF_V2: Self = Self(BpfVariant::Sbfv2);
}

/// Compute the slot offset for a relative branch: `(target -
/// next_slot) / 8`. Returns the i16 the BPF encoder expects,
/// or an `OutOfRange` error if the displacement doesn't fit /
/// isn't slot-aligned.
fn slot_offset(source_ip: u64, target: u64) -> Result<i16, ArchError> {
    let next_slot = source_ip.wrapping_add(INSN_SIZE as u64);
    #[allow(clippy::cast_possible_wrap)]
    let delta = (target as i64).wrapping_sub(next_slot as i64);
    if delta % (INSN_SIZE as i64) != 0 {
        return Err(ArchError::OutOfRange(format!(
            "BPF branch displacement {delta} bytes is not slot-aligned"
        )));
    }
    let slots = delta / (INSN_SIZE as i64);
    i16::try_from(slots).map_err(|_| {
        ArchError::OutOfRange(format!(
            "BPF branch displacement {slots} slots overflows i16 (max ±32768)"
        ))
    })
}

impl ArchCodec for BpfCodec {
    fn name(&self) -> &'static str {
        match self.0 {
            BpfVariant::Linux => "bpf-linux",
            BpfVariant::Sbfv1 => "bpf-sbf-v1",
            BpfVariant::Sbfv2 => "bpf-sbf-v2",
        }
    }

    fn assemble_one(&self, text: &str, _addr: u64) -> Result<Vec<u8>, ArchError> {
        assemble_bpf(text).map_err(|e| ArchError::Assemble(e.to_string()))
    }

    fn desymbolize(&self, text: &str, addr: u64) -> String {
        desymbolize_bpf_text(text, addr, None).unwrap_or_else(|| text.to_string())
    }

    fn encode_jump(
        &self,
        source_ip: u64,
        target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        let off = slot_offset(source_ip, target)?;
        assemble_bpf_ja(off).map_err(|e| ArchError::Assemble(e.to_string()))
    }

    /// Encode an intra-program call. The choice between
    /// `call_local` (opcode 0x8d, Linux eBPF convention) and
    /// `call_internal` (opcode 0x85 src=1, Solana sBPF
    /// convention) is hinted by `EncodeHints::bpf_call_local`:
    /// `Some(true)` → call_local, `Some(false)` → call_internal,
    /// `None` → default to call_internal (Solana sBPF, the
    /// dominant convention in practice; Solana programs
    /// often carry `e_machine = EM_BPF (247)` despite using
    /// the sBPF call form, so the EM marker alone can't
    /// disambiguate). The imm is the slot delta from the
    /// next slot to the target, signed.
    ///
    /// Syscalls (opcode 0x85 src=0, imm = a name hash or -1)
    /// don't go through this method — they remain pinned in
    /// `Stmt::Call.bytes` because the imm depends on
    /// relocation context the codec doesn't carry.
    fn encode_call(
        &self,
        source_ip: u64,
        target: u64,
        hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        let slots = slot_offset(source_ip, target)?;
        let imm32 = i32::from(slots);
        let mnemonic = if hints.bpf_call_local.unwrap_or(false) {
            "call_local"
        } else {
            "call_internal"
        };
        assemble_bpf(&format!("{mnemonic} {imm32}")).map_err(|e| ArchError::Assemble(e.to_string()))
    }

    fn encode_cond_jump(
        &self,
        cond_text: &str,
        source_ip: u64,
        target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        let off = slot_offset(source_ip, target)?;
        assemble_bpf_ifblock_cond(cond_text, off).map_err(|e| ArchError::Assemble(e.to_string()))
    }

    fn encode_switch_dispatch(&self, _spec: &SwitchSpec) -> Result<Vec<u8>, ArchError> {
        // BPF doesn't model jump-table dispatch as a single
        // structural form today.
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "switch_dispatch",
        })
    }

    fn encoded_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        INSN_SIZE
    }

    fn encoded_cond_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        INSN_SIZE
    }

    fn encoded_call_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        INSN_SIZE
    }

    /// BPF calls are single 8-byte instructions — pinned
    /// `Stmt::Call.bytes` (when present) is the complete call.
    fn direct_call_bytes_contain_call(&self) -> bool {
        true
    }

    /// Encode `dst = src` as one BPF instruction.
    ///
    /// Supported shapes:
    ///
    /// * `("rN", "rM")` → `mov64 rN, rM` (8 bytes)
    /// * `("rN", "0xN")` → `mov64 rN, imm32` (8 bytes)
    /// * `("rN", "[rM ± off]")` (optional `:uNN` suffix) →
    ///   `ldxdw / ldxw / ldxh / ldxb rN, [rM ± off]` (8 bytes)
    /// * `("[rN ± off]", "rM")` (optional `:uNN` suffix on dst) →
    ///   `stxdw / stxw / stxh / stxb [rN ± off], rM` (8 bytes)
    /// * `("rN", "0x<imm>:u64")` → `lddw rN, 0x<imm>` (16 bytes,
    ///   two BPF slots — the second being a zero-opcode
    ///   continuation slot carrying the high 32 bits)
    ///
    /// The `:u<bits>` size suffix on a memory operand picks the
    /// access width (`:u8 / :u16 / :u32 / :u64`); the bare
    /// `[rN ± off]` form defaults to `:u64` (BPF `dw`).
    fn encode_move(&self, dst: &str, src: &str) -> Result<Vec<u8>, ArchError> {
        let dst = dst.trim();
        let src = src.trim();
        // Strip optional `:u<bits>` suffix from each side;
        // remember the size and which side carried it (the
        // memory operand always carries the suffix when
        // present).
        let (dst_core, dst_size) = split_size_suffix(dst);
        let (src_core, src_size) = split_size_suffix(src);

        // LDDW: register dst, 64-bit immediate src.
        if is_bpf_reg(dst_core) && (src_size == Some(64) || is_lddw_imm(src_core)) {
            let imm_str = src_core.trim();
            return assemble_bpf(&format!("lddw {dst_core}, {imm_str}"))
                .map_err(|e| ArchError::Assemble(e.to_string()));
        }

        // ldx: register dst, [memory] src.
        if is_bpf_reg(dst_core) && is_bracket_mem(src_core) {
            let bits = src_size.unwrap_or(64);
            let suffix = size_suffix_for_bits(bits)?;
            let mem = desymbolize_mem(src_core);
            return assemble_bpf(&format!("ldx{suffix} {dst_core}, {mem}"))
                .map_err(|e| ArchError::Assemble(e.to_string()));
        }

        // stx: [memory] dst, register src.
        if is_bracket_mem(dst_core) && is_bpf_reg(src_core) {
            let bits = dst_size.unwrap_or(64);
            let suffix = size_suffix_for_bits(bits)?;
            let mem = desymbolize_mem(dst_core);
            return assemble_bpf(&format!("stx{suffix} {mem}, {src_core}"))
                .map_err(|e| ArchError::Assemble(e.to_string()));
        }

        // mov64: register dst, register or imm32 src.
        if is_bpf_reg(dst_core) && (is_bpf_reg(src_core) || is_bpf_imm(src_core)) {
            return assemble_bpf(&format!("mov64 {dst_core}, {src_core}"))
                .map_err(|e| ArchError::Assemble(e.to_string()));
        }

        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "move (unrecognised operand shape)",
        })
    }

    /// Encode a function return. BPF returns r0 implicitly via
    /// the `exit` instruction; the `value` field is ignored.
    fn encode_return(&self, _value: Option<u64>) -> Result<Vec<u8>, ArchError> {
        assemble_bpf("exit").map_err(|e| ArchError::Assemble(e.to_string()))
    }
}

/// Recognise a BPF general-purpose register name (`r0`..`r10`).
fn is_bpf_reg(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with('r') {
        return false;
    }
    let n = &s[1..];
    matches!(
        n,
        "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10"
    )
}

/// Recognise a `[...]` memory operand (BPF ldx / stx form).
/// The contents aren't validated here — the underlying
/// assembler's `parse_mem` does that.
fn is_bracket_mem(s: &str) -> bool {
    let s = s.trim();
    s.starts_with('[') && s.ends_with(']')
}

/// Rewrite a memory operand's symbolic stack-slot reference
/// (`[local_<hex>]` or `[arg_<hex>]`) back to the
/// `[r10 ± 0x<hex>]` form `parse_mem` accepts. The shared
/// `desymbolize_bpf_text` does the same for `@asm` lines —
/// this routes a single operand through that helper rather
/// than reimplementing the rewrite.
fn desymbolize_mem(operand: &str) -> String {
    desymbolize_bpf_text(operand, 0, None).unwrap_or_else(|| operand.to_string())
}

/// Strip an optional trailing `:uNN` size suffix from a Move
/// operand. Returns the operand without the suffix plus the
/// parsed bit width (`Some(8/16/32/64)`) when one was found.
fn split_size_suffix(s: &str) -> (&str, Option<u32>) {
    let s = s.trim();
    if let Some(idx) = s.rfind(":u") {
        let suffix = &s[idx + 2..];
        if let Ok(n) = suffix.parse::<u32>() {
            if matches!(n, 8 | 16 | 32 | 64) {
                return (s[..idx].trim_end(), Some(n));
            }
        }
    }
    (s, None)
}

/// Map a `:uNN` width to the BPF ldx/stx mnemonic suffix.
fn size_suffix_for_bits(bits: u32) -> Result<&'static str, ArchError> {
    match bits {
        8 => Ok("b"),
        16 => Ok("h"),
        32 => Ok("w"),
        64 => Ok("dw"),
        _ => Err(ArchError::OutOfRange(format!(
            "unsupported memory access width :u{bits}"
        ))),
    }
}

/// Detect a 64-bit-only immediate (i.e. one that requires LDDW
/// rather than `mov64 reg, imm32`): explicit `0x` literal whose
/// value exceeds u32::MAX, OR explicit `:u64` suffix on the src
/// (handled by the caller). Returns `false` for small hex
/// constants that fit `mov64 reg, imm`.
fn is_lddw_imm(s: &str) -> bool {
    let s = s.trim();
    let s = s.strip_prefix('-').unwrap_or(s);
    if let Some(hex) = s.strip_prefix("0x") {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        u64::from_str_radix(hex, 16).is_ok_and(|v| v > u64::from(u32::MAX))
    } else {
        false
    }
}

/// Recognise a BPF immediate constant in textual form.
/// Accepts decimal, `0x`-prefixed hex, and an optional leading
/// minus sign. Used by `encode_move`'s src classifier.
fn is_bpf_imm(s: &str) -> bool {
    let s = s.trim();
    let s = s.strip_prefix('-').unwrap_or(s);
    if let Some(hex) = s.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// Register the BPF codec factory with [`ud_arch_codec::registry`].
///
/// Variant selection prefers numeric `e_machine` when both signals
/// are present (more specific); falls back to the friendly `arch`
/// string. EM_BPF (247) → Linux; EM_SBF (263) → sBPFv1 by default
/// (sBPFv2 distinction requires e_flags inspection which the
/// trait doesn't yet surface — out of scope for now).
pub fn register() {
    ud_arch_codec::register(factory);
}

/// `EM_BPF` from the ELF spec (Linux eBPF).
pub const EM_BPF: u64 = 247;
/// `EM_SBF` from Solana's ELF extension (sBPFv1 / sBPFv2 — variant
/// distinction needs `e_flags`).
pub const EM_SBF: u64 = 263;

fn factory(arch_name: Option<&str>, e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>> {
    if let Some(em) = e_machine {
        match em {
            EM_BPF => return Some(Box::new(BpfCodec(BpfVariant::Linux))),
            EM_SBF => return Some(Box::new(BpfCodec(BpfVariant::Sbfv1))),
            _ => {}
        }
    }
    match arch_name {
        Some("bpf") => Some(Box::new(BpfCodec(BpfVariant::Linux))),
        Some("sbf" | "sbfv1") => Some(Box::new(BpfCodec(BpfVariant::Sbfv1))),
        Some("sbfv2") => Some(Box::new(BpfCodec(BpfVariant::Sbfv2))),
        _ => None,
    }
}

//! `ArchCodec` implementation for x86 (16 / 32 / 64-bit).
//!
//! Each codec instance carries a [`crate::Bitness`]; one Bitness =
//! one codec. `register()` submits three factories — one for each
//! bitness — so the registry can pick by `module.arch`:
//! `"x86_64"`, `"i386"`, or `"x86_16"` (the last currently never
//! seen in the wild but trivially supported).
//!
//! Every method except `desymbolize` forwards to the existing
//! free-standing functions in the crate root. The trait shape is
//! the long-term API; the free functions stay for now because
//! callers (tests, internal lifters) reference them directly.

use crate::{
    assemble_intel, encode_call_rel32, encode_jcc, encode_jmp, encode_msvc_jmp_table_dispatch,
    encoded_jcc_size, encoded_jmp_size, Bitness,
};
use ud_arch_codec::{ArchCodec, ArchError, EncodeHints, SwitchSpec};

/// One codec per bitness. Cheap to construct, no state.
#[derive(Debug, Clone, Copy)]
pub struct X86Codec(pub Bitness);

impl X86Codec {
    /// 64-bit codec singleton — most common case.
    pub const BITS64: Self = Self(Bitness::Bits64);
    /// 32-bit codec singleton.
    pub const BITS32: Self = Self(Bitness::Bits32);
}

impl ArchCodec for X86Codec {
    fn name(&self) -> &'static str {
        match self.0 {
            Bitness::Bits16 => "x86-16",
            Bitness::Bits32 => "x86-32",
            Bitness::Bits64 => "x86-64",
        }
    }

    fn assemble_one(&self, text: &str, addr: u64) -> Result<Vec<u8>, ArchError> {
        assemble_intel(self.0, text, addr).map_err(|e| ArchError::Assemble(e.to_string()))
    }

    fn encode_jump(
        &self,
        source_ip: u64,
        target: u64,
        hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        encode_jmp(source_ip, target, hints.wide_or(false))
            .map_err(|e| ArchError::OutOfRange(e.to_string()))
    }

    fn encode_call(
        &self,
        source_ip: u64,
        target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        encode_call_rel32(source_ip, target).map_err(|e| ArchError::OutOfRange(e.to_string()))
    }

    /// x86 doesn't have a single text-driven cond-jump form (the
    /// existing path uses the cond_code-driven encoder); BPF-style
    /// IfBlock/WhileBlock Stmts don't originate from the x86 lifter.
    fn encode_cond_jump(
        &self,
        _cond_text: &str,
        _source_ip: u64,
        _target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "cond_jump (text)",
        })
    }

    fn encode_cond_jump_with_code(
        &self,
        cond_code: u8,
        source_ip: u64,
        target: u64,
        hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        encode_jcc(source_ip, target, cond_code, hints.wide_or(false))
            .map_err(|e| ArchError::OutOfRange(e.to_string()))
    }

    fn encode_switch_dispatch(&self, spec: &SwitchSpec) -> Result<Vec<u8>, ArchError> {
        if spec.dispatch != "msvc-jmp-table" {
            return Err(ArchError::Unsupported {
                arch: self.name(),
                operation: "switch_dispatch (non-msvc)",
            });
        }
        encode_msvc_jmp_table_dispatch(
            spec.selector,
            spec.cases.len(),
            spec.default_addr,
            spec.table_va,
            spec.cmp_ip,
        )
        .map_err(|e| ArchError::OutOfRange(e.to_string()))
    }

    fn encoded_jump_size(&self, source_ip: u64, target: u64, hints: EncodeHints) -> usize {
        encoded_jmp_size(source_ip, target, hints.wide_or(false))
    }

    fn encoded_cond_jump_size(&self, source_ip: u64, target: u64, hints: EncodeHints) -> usize {
        encoded_jcc_size(source_ip, target, hints.wide_or(false))
    }

    fn encoded_call_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        5
    }

    /// Encode a `dst = src` Move whose operand text uses the
    /// x86 lifter's symbolic forms (`var_<hex>` for stack
    /// slots, `arg_<hex>` for stack args, plain register
    /// names, decimal/hex immediates).
    ///
    /// The width default is 32-bit (`mov dword ptr [...]`) —
    /// matches the gcc -O0 idiom that emits 32-bit slot
    /// access for int locals. 64-bit Moves keep their pinned
    /// bytes because the codec can't disambiguate width
    /// without function-local-decl context.
    ///
    /// Returns `Unsupported` for shapes the resolver can't
    /// model (compound expressions, sized memory access with
    /// non-standard width, etc.) so the byte-drop pass
    /// leaves the bytes pinned for those.
    fn encode_move(&self, dst: &str, src: &str) -> Result<Vec<u8>, ArchError> {
        let (asm_dst, dst_width) =
            resolve_x86_operand(dst).ok_or_else(|| ArchError::Unsupported {
                arch: self.name(),
                operation: "move (unresolved dst)",
            })?;
        let (asm_src, src_width) =
            resolve_x86_operand(src).ok_or_else(|| ArchError::Unsupported {
                arch: self.name(),
                operation: "move (unresolved src)",
            })?;
        // Width preference: a register operand carries width
        // info (eax = 32, rax = 64). Memory operand inherits
        // from register if present, else defaults to 32 (the
        // gcc -O0 idiom for int locals).
        let width = dst_width.or(src_width).unwrap_or(32);
        let size_prefix = match width {
            8 => "byte ptr",
            16 => "word ptr",
            32 => "dword ptr",
            _ => "qword ptr",
        };
        // Memory operands need an explicit size prefix; bare
        // register dst/src don't.
        let dst_text = if asm_dst.starts_with('[') {
            format!("{size_prefix} {asm_dst}")
        } else {
            asm_dst
        };
        let src_text = if asm_src.starts_with('[') {
            format!("{size_prefix} {asm_src}")
        } else {
            asm_src
        };
        let text = format!("mov {dst_text}, {src_text}");
        assemble_intel(self.0, &text, 0).map_err(|e| ArchError::Assemble(e.to_string()))
    }
}

/// Map an x86 lifter operand text to (iced-assembly text,
/// known width in bits). Returns `None` when the shape isn't
/// recognised; the caller falls back to `Unsupported` so the
/// byte-drop pass leaves the pinned bytes alone.
///
/// Supported shapes:
/// * `var_<hex>` → `[rbp - 0x<hex>]`, width unknown (None)
/// * `arg_<hex>` → `[rbp + 0x<hex>]`, width unknown (None)
/// * register names (`eax`, `rax`, `edi`, `dil`, …) → as-is,
///   width inferred from the register (8 / 16 / 32 / 64)
/// * decimal / `0x`-prefixed integer literals → as-is,
///   width unknown
fn resolve_x86_operand(s: &str) -> Option<(String, Option<u32>)> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("var_") {
        let disp = u64::from_str_radix(hex, 16).ok()?;
        return Some((format!("[rbp - 0x{disp:x}]"), None));
    }
    if let Some(hex) = s.strip_prefix("arg_") {
        let disp = u64::from_str_radix(hex, 16).ok()?;
        return Some((format!("[rbp + 0x{disp:x}]"), None));
    }
    if let Some(w) = x86_gpr_width(s) {
        return Some((s.to_string(), Some(w)));
    }
    if is_integer_literal(s) {
        return Some((s.to_string(), None));
    }
    None
}

/// Return the bit width of a named x86 GPR, or `None` when
/// the name doesn't match a recognised register. Covers
/// 8/16/32/64-bit GPRs including the AMD64-extended set
/// (`r8..r15` plus `r8b`/`r8w`/`r8d` aliases).
fn x86_gpr_width(s: &str) -> Option<u32> {
    let s = s.trim();
    // 64-bit
    if matches!(
        s,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    ) {
        return Some(64);
    }
    // 32-bit
    if matches!(
        s,
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp"
    ) || (s.starts_with('r')
        && s.ends_with('d')
        && s.len() == 3
        && s.as_bytes()[1].is_ascii_digit())
        || (s.starts_with("r1") && s.ends_with('d') && s.len() == 4)
    {
        return Some(32);
    }
    // 16-bit
    if matches!(s, "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp") {
        return Some(16);
    }
    // 8-bit
    if matches!(
        s,
        "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh" | "sil" | "dil" | "bpl" | "spl"
    ) {
        return Some(8);
    }
    None
}

/// True when `s` is a decimal or `0x`-hex integer literal
/// the assembler will accept verbatim. Tolerates a leading
/// `-` for signed forms.
fn is_integer_literal(s: &str) -> bool {
    let s = s.trim();
    let s = s.strip_prefix('-').unwrap_or(s);
    if let Some(hex) = s.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// Register the x86 codec factory with [`ud_arch_codec::registry`].
///
/// One factory handles all bitnesses by inspecting `arch_name`.
/// Call once at process startup.
pub fn register() {
    ud_arch_codec::register(factory);
}

fn factory(arch_name: Option<&str>, _e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>> {
    match arch_name {
        Some("x86_64") => Some(Box::new(X86Codec(Bitness::Bits64))),
        Some("i386") => Some(Box::new(X86Codec(Bitness::Bits32))),
        Some("x86_16") => Some(Box::new(X86Codec(Bitness::Bits16))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_arch_codec::ArchCodec;

    /// `mov reg, reg` is the one form `assemble_intel`
    /// currently encodes; verify the codec wires through.
    #[test]
    fn encode_move_reg_reg() {
        let codec = X86Codec(Bitness::Bits64);
        let bytes = codec.encode_move("rax", "rbx").expect("encode");
        assert_eq!(bytes, vec![0x48, 0x89, 0xd8]);
    }

    /// Forms `assemble_intel` doesn't yet model (mov ↔ imm /
    /// mov ↔ memory / lea / etc.) return Unsupported so the
    /// byte-drop pass leaves the pinned bytes alone. This is
    /// the round-trip-safe default.
    #[test]
    fn encode_move_unsupported_forms_error() {
        let codec = X86Codec(Bitness::Bits64);
        assert!(codec.encode_move("eax", "0").is_err());
        assert!(codec.encode_move("var_8", "0").is_err());
    }
}

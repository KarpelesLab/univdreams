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

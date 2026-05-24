//! `ArchCodec` placeholder for AArch64.
//!
//! AArch64 has no encoder surface yet (the crate is decode-only at
//! v0), so every method returns [`ArchError::Unsupported`]. This
//! lets the framework compile and dispatch through aarch64 without
//! the encoder; the pinned-bytes fallback covers any Stmt that
//! would have asked for re-encoding. Filling out the encoders is a
//! per-method follow-up.

use ud_arch_codec::{ArchCodec, ArchError, EncodeHints};

/// Stateless aarch64 codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aarch64Codec;

impl ArchCodec for Aarch64Codec {
    fn name(&self) -> &'static str {
        "aarch64"
    }

    fn assemble_one(&self, _text: &str, _addr: u64) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "assemble_one",
        })
    }

    fn encode_jump(
        &self,
        _source_ip: u64,
        _target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "jump",
        })
    }

    fn encode_call(
        &self,
        _source_ip: u64,
        _target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "call",
        })
    }

    fn encode_cond_jump(
        &self,
        _cond_text: &str,
        _source_ip: u64,
        _target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "cond_jump",
        })
    }

    /// AArch64 has fixed 4-byte instructions; size is constant
    /// regardless of jump target.
    fn encoded_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        4
    }

    fn encoded_cond_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        4
    }

    fn encoded_call_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        4
    }
}

/// Register the aarch64 codec factory with the registry.
pub fn register() {
    ud_arch_codec::register(factory);
}

fn factory(arch_name: Option<&str>, _e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>> {
    if matches!(arch_name, Some("aarch64" | "arm64")) {
        Some(Box::new(Aarch64Codec))
    } else {
        None
    }
}

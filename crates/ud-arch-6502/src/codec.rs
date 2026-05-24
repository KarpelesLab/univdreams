//! `ArchCodec` placeholder for MOS 6502.
//!
//! The 6502 crate is decode-only at v0, so every encoder method
//! returns [`ArchError::Unsupported`]. Size queries return a
//! conservative `3` (the maximum 6502 instruction width) so size
//! predictions in size-stable lowering passes don't underestimate.

use ud_arch_codec::{ArchCodec, ArchError, EncodeHints};

/// Stateless 6502 codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct M6502Codec;

impl ArchCodec for M6502Codec {
    fn name(&self) -> &'static str {
        "6502"
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

    /// 6502 has variable-width instructions (1, 2, or 3 bytes);
    /// return the maximum so callers don't underestimate.
    fn encoded_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        3
    }

    fn encoded_cond_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        2
    }

    fn encoded_call_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        3
    }
}

/// Register the 6502 codec factory with the registry.
pub fn register() {
    ud_arch_codec::register(factory);
}

fn factory(arch_name: Option<&str>, _e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>> {
    if matches!(arch_name, Some("6502" | "mos6502")) {
        Some(Box::new(M6502Codec))
    } else {
        None
    }
}

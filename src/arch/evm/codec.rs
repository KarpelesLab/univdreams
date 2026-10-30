//! `ArchCodec` for EVM bytecode.
//!
//! Only `assemble_one` is real: EVM jumps are absolute and take their
//! target from the stack (`PUSH2 dest; JUMP`), so there is no
//! PC-relative branch encoding for the lower path to re-resolve. The
//! jump / call encoders return [`ArchError::Unsupported`] and the
//! decompiler keeps targets as plain `PUSHn` immediates.

use crate::arch::codec::{ArchCodec, ArchError, EncodeHints};

/// Stateless EVM codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct EvmCodec;

impl ArchCodec for EvmCodec {
    fn name(&self) -> &'static str {
        "evm"
    }

    fn assemble_one(&self, text: &str, _addr: u64) -> Result<Vec<u8>, ArchError> {
        super::assemble_one(text).map_err(|e| ArchError::Assemble(e.to_string()))
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

    /// `PUSH2 dest; JUMP` — the shape solc emits for code under 64 KiB.
    fn encoded_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        4
    }

    /// `PUSH2 dest; JUMPI`.
    fn encoded_cond_jump_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        4
    }

    /// Internal calls are jumps too (return address pushed first).
    fn encoded_call_size(&self, _source_ip: u64, _target: u64, _hints: EncodeHints) -> usize {
        4
    }
}

/// Register the EVM codec factory with the registry.
pub fn register() {
    crate::arch::codec::register(factory);
}

fn factory(arch_name: Option<&str>, _e_machine: Option<u64>) -> Option<Box<dyn ArchCodec>> {
    if matches!(arch_name, Some("evm")) {
        Some(Box::new(EvmCodec))
    } else {
        None
    }
}

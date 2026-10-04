//! Instruction-set backends: the shared [`codec`] interface and one module
//! per architecture.

pub mod aarch64;
pub mod bpf;
pub mod codec;
pub mod mos6502;
pub mod x86;

//! Shared IR types for univdreams.
//!
//! Per the architecture sketch, the IR is **arch-tagged**: each
//! architecture brings its own instruction vocabulary. This crate hosts
//! only the concepts that genuinely span architectures — function and
//! basic-block structure, control-flow terminators, and the
//! [`ArchInsn`] trait that lets per-arch instruction types plug in.
//!
//! The byte-identity contract for the IR layer:
//!
//! > For any [`Function`] built from real bytes by an arch's lifter,
//! > [`Function::emit_bytes`] returns exactly the input bytes.
//!
//! This is true by construction: [`emit_bytes`] concatenates each
//! instruction's preserved original bytes in address order. The CFG
//! structure is a *view* over a flat byte stream, not a transformation
//! of it.
//!
//! [`emit_bytes`]: Function::emit_bytes

#![allow(clippy::cast_possible_truncation)]

use ud_core::VAddr;

/// An architecture's per-instruction type, plugged into the shared IR.
///
/// The trait surface is deliberately tiny: an instruction must know its
/// virtual address and the bytes it occupied in the source binary.
/// Higher-level analyses query the arch-specific concrete type directly.
pub trait ArchInsn {
    /// Virtual address where this instruction lives.
    fn addr(&self) -> VAddr;

    /// Exact bytes the instruction occupied in the source. Used by
    /// [`Function::emit_bytes`] to defend round-trip byte identity.
    fn original_bytes(&self) -> &[u8];

    /// Length of the encoded instruction in bytes. Default impl uses
    /// `original_bytes().len()`; override only if your representation
    /// can differ between the two (e.g. a synthetic IR insn that
    /// doesn't have a byte form yet).
    fn len_bytes(&self) -> usize {
        self.original_bytes().len()
    }
}

/// How control flow leaves a basic block.
///
/// Calls are deliberately *not* terminators: the standard CFG convention
/// treats a `call` as a regular instruction whose semantics include
/// transferring control elsewhere and eventually returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminator {
    /// Reached only at the very end of a function whose body simply
    /// ran out of recorded bytes (e.g. `nop`s for alignment with no
    /// branch back). Rare in real code but possible.
    Fallthrough,

    /// Unconditional direct branch (`jmp rel32`, etc.) to a known target.
    UnconditionalBranch { target: VAddr },

    /// Conditional direct branch (`jcc`); has both a taken target and a
    /// fall-through edge to the next address.
    ConditionalBranch { taken: VAddr, fallthrough: VAddr },

    /// Return from function (`ret`, `iret`, etc.).
    Return,

    /// Indirect branch or call where the target is not a constant
    /// (`jmp rax`, `jmp [rip+...]`, `call rax`). Static analysis can't
    /// resolve these; downstream passes may attempt jump-table
    /// recovery.
    IndirectBranch,

    /// `ud2`, `int3` reaching here as a terminator, or any other
    /// instruction that surfaces as flow-control "exception" /
    /// "interrupt" / "unreachable".
    InvalidOrUnreachable,
}

/// A maximal straight-line sequence of instructions ending in a
/// [`Terminator`].
///
/// "Maximal" in the usual sense: the only entry to the block is at
/// `addr`, and every instruction except the last falls through to its
/// successor.
#[derive(Debug, Clone)]
pub struct BasicBlock<I> {
    pub addr: VAddr,
    pub insns: Vec<I>,
    pub terminator: Terminator,
}

impl<I: ArchInsn> BasicBlock<I> {
    /// Sum of `original_bytes` lengths across the block.
    #[must_use]
    pub fn size(&self) -> usize {
        self.insns.iter().map(ArchInsn::len_bytes).sum()
    }

    /// Address one past the last byte of the block.
    #[must_use]
    pub fn end_addr(&self) -> VAddr {
        VAddr(self.addr.0 + self.size() as u64)
    }
}

/// A function: a name, an entry address, and a sequence of basic blocks
/// in original layout (address) order.
///
/// `blocks[0]` is by convention the entry block, since blocks are stored
/// in address order and a function starts at its lowest address.
#[derive(Debug, Clone)]
pub struct Function<I> {
    pub addr: VAddr,
    pub name: String,
    pub blocks: Vec<BasicBlock<I>>,
}

impl<I: ArchInsn> Function<I> {
    /// Total size in bytes — sum across all blocks.
    #[must_use]
    pub fn size(&self) -> usize {
        self.blocks.iter().map(BasicBlock::size).sum()
    }

    /// Concatenate every instruction's preserved bytes in address order.
    /// For any function lifted from real bytes, this returns exactly the
    /// input bytes.
    #[must_use]
    pub fn emit_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        for block in &self.blocks {
            for insn in &block.insns {
                out.extend_from_slice(insn.original_bytes());
            }
        }
        out
    }

    /// Find the block whose address equals `addr`, if any.
    #[must_use]
    pub fn block_at(&self, addr: VAddr) -> Option<&BasicBlock<I>> {
        self.blocks.iter().find(|b| b.addr == addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic instruction type for testing the shared IR without
    /// pulling in an arch crate.
    #[derive(Debug, Clone)]
    struct DummyInsn {
        addr: u64,
        bytes: Vec<u8>,
    }

    impl ArchInsn for DummyInsn {
        fn addr(&self) -> VAddr {
            VAddr(self.addr)
        }
        fn original_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    fn insn(addr: u64, bytes: &[u8]) -> DummyInsn {
        DummyInsn {
            addr,
            bytes: bytes.to_vec(),
        }
    }

    fn function_one_block() -> Function<DummyInsn> {
        Function {
            addr: VAddr(0x1000),
            name: "single".into(),
            blocks: vec![BasicBlock {
                addr: VAddr(0x1000),
                insns: vec![insn(0x1000, &[0x90, 0x90]), insn(0x1002, &[0xc3])],
                terminator: Terminator::Return,
            }],
        }
    }

    #[test]
    fn emit_bytes_concatenates_in_block_order() {
        let f = function_one_block();
        assert_eq!(f.emit_bytes(), vec![0x90, 0x90, 0xc3]);
    }

    #[test]
    fn function_size_sums_block_sizes() {
        let f = function_one_block();
        assert_eq!(f.size(), 3);
    }

    #[test]
    fn block_end_addr_is_addr_plus_size() {
        let f = function_one_block();
        assert_eq!(f.blocks[0].end_addr(), VAddr(0x1003));
    }

    #[test]
    fn block_at_finds_blocks_by_address() {
        let f = Function::<DummyInsn> {
            addr: VAddr(0x1000),
            name: "two_blocks".into(),
            blocks: vec![
                BasicBlock {
                    addr: VAddr(0x1000),
                    insns: vec![insn(0x1000, &[0xeb, 0x02])],
                    terminator: Terminator::UnconditionalBranch {
                        target: VAddr(0x1004),
                    },
                },
                BasicBlock {
                    addr: VAddr(0x1004),
                    insns: vec![insn(0x1004, &[0xc3])],
                    terminator: Terminator::Return,
                },
            ],
        };
        assert!(f.block_at(VAddr(0x1004)).is_some());
        assert!(f.block_at(VAddr(0x1002)).is_none());
    }
}

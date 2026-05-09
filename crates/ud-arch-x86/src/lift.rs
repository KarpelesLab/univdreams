//! Lift a decoded x86 instruction stream into the shared IR.
//!
//! Standard CFG construction:
//!
//! 1. Identify *leaders* — instructions that begin a basic block. The
//!    first instruction is a leader; the target of any direct branch is
//!    a leader; the instruction immediately following any branch /
//!    return / unreachable is a leader.
//! 2. Each maximal run from one leader to the next forms a basic block.
//! 3. Classify the terminator at the end of each block from iced's
//!    [`FlowControl`] of the last instruction.
//!
//! Branch targets that fall outside the supplied instruction range
//! (typical for tail calls: `jmp other_func`) are recorded on the
//! terminator but do not produce a leader; they belong to a different
//! function.
//!
//! [`FlowControl`]: iced_x86::FlowControl

use std::collections::BTreeSet;

use iced_x86::FlowControl;
use ud_core::VAddr;
use ud_ir::{BasicBlock, Function, Terminator};

use crate::DecodedInsn;

/// Errors specific to the lifter.
#[derive(Debug, thiserror::Error)]
pub enum LiftError {
    #[error("cannot lift an empty instruction stream")]
    Empty,

    #[error(
        "instructions are not contiguous: instruction at 0x{prev_end:x} is followed by 0x{next:x}"
    )]
    NotContiguous { prev_end: u64, next: u64 },
}

/// Build a [`Function`] CFG from a contiguous stream of decoded x86
/// instructions starting at `entry_addr`.
///
/// `name` is the function's display name. `entry_addr` is the virtual
/// address of the first instruction; it must equal `insns[0].iced.ip()`.
pub fn lift_function(
    name: String,
    insns: &[DecodedInsn],
) -> Result<Function<DecodedInsn>, LiftError> {
    if insns.is_empty() {
        return Err(LiftError::Empty);
    }
    verify_contiguous(insns)?;

    let func_start = insns[0].iced.ip();
    let func_end_excl = insns
        .last()
        .map_or(func_start, |i| i.iced.ip() + i.iced.len() as u64);

    let leaders = collect_leaders(insns, func_start, func_end_excl);
    let blocks = partition_into_blocks(insns, &leaders);

    Ok(Function {
        addr: VAddr(func_start),
        name,
        blocks,
    })
}

fn verify_contiguous(insns: &[DecodedInsn]) -> Result<(), LiftError> {
    for pair in insns.windows(2) {
        let prev_end = pair[0].iced.ip() + pair[0].iced.len() as u64;
        let next = pair[1].iced.ip();
        if prev_end != next {
            return Err(LiftError::NotContiguous { prev_end, next });
        }
    }
    Ok(())
}

fn collect_leaders(insns: &[DecodedInsn], func_start: u64, func_end_excl: u64) -> BTreeSet<u64> {
    let mut leaders = BTreeSet::new();
    leaders.insert(func_start);

    for (i, insn) in insns.iter().enumerate() {
        let next_ip = insn.iced.next_ip();
        let in_range = |a: u64| a >= func_start && a < func_end_excl;

        match insn.iced.flow_control() {
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                let target = insn.iced.near_branch_target();
                if in_range(target) {
                    leaders.insert(target);
                }
                // Instruction after a branch starts a new block (the
                // fall-through edge for conditionals, or unreachable
                // code for unconditionals — either way it's a leader).
                if i + 1 < insns.len() && in_range(next_ip) {
                    leaders.insert(next_ip);
                }
            }
            FlowControl::Return
            | FlowControl::IndirectBranch
            | FlowControl::Exception
            | FlowControl::Interrupt
            | FlowControl::XbeginXabortXend => {
                if i + 1 < insns.len() && in_range(next_ip) {
                    leaders.insert(next_ip);
                }
            }
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                // Calls do not split blocks: control returns to the next
                // instruction, so the run continues uninterrupted.
            }
        }
    }
    leaders
}

fn partition_into_blocks(
    insns: &[DecodedInsn],
    leaders: &BTreeSet<u64>,
) -> Vec<BasicBlock<DecodedInsn>> {
    let mut blocks = Vec::new();
    let mut current_addr = insns[0].iced.ip();
    let mut current_insns: Vec<DecodedInsn> = Vec::new();

    for insn in insns {
        let ip = insn.iced.ip();
        if !current_insns.is_empty() && leaders.contains(&ip) {
            // Close out the previous block at this leader. The block's
            // last instruction was a fall-through into a new leader —
            // its terminator is therefore implicit Fallthrough.
            let last = current_insns.last().expect("non-empty");
            let terminator = classify_terminator(last);
            blocks.push(BasicBlock {
                addr: VAddr(current_addr),
                insns: std::mem::take(&mut current_insns),
                terminator,
            });
            current_addr = ip;
        }
        current_insns.push(insn.clone());
    }

    if !current_insns.is_empty() {
        let last = current_insns.last().expect("non-empty");
        let terminator = classify_terminator(last);
        blocks.push(BasicBlock {
            addr: VAddr(current_addr),
            insns: current_insns,
            terminator,
        });
    }

    blocks
}

fn classify_terminator(insn: &DecodedInsn) -> Terminator {
    match insn.iced.flow_control() {
        FlowControl::UnconditionalBranch => Terminator::UnconditionalBranch {
            target: VAddr(insn.iced.near_branch_target()),
        },
        FlowControl::ConditionalBranch => Terminator::ConditionalBranch {
            taken: VAddr(insn.iced.near_branch_target()),
            fallthrough: VAddr(insn.iced.next_ip()),
        },
        FlowControl::Return => Terminator::Return,
        FlowControl::IndirectBranch => Terminator::IndirectBranch,
        FlowControl::Exception | FlowControl::Interrupt | FlowControl::XbeginXabortXend => {
            Terminator::InvalidOrUnreachable
        }
        FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
            // The block was closed at a leader; the last instruction was
            // a non-branch that fell through. This shows up at function
            // boundaries that don't end in a branch (rare, but possible
            // with `nop` padding tails or tail-merged code).
            Terminator::Fallthrough
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, Bitness};

    fn lift(bytes: &[u8], rip: u64) -> Function<DecodedInsn> {
        let insns = decode(Bitness::Bits64, bytes, rip).expect("decode");
        lift_function("test".into(), &insns).expect("lift")
    }

    #[test]
    fn straight_line_function_is_one_block() {
        // endbr64; xor eax, eax; ret
        let bytes = [0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xc0, 0xc3];
        let f = lift(&bytes, 0x1000);
        assert_eq!(f.blocks.len(), 1);
        assert_eq!(f.blocks[0].terminator, Terminator::Return);
        assert_eq!(f.emit_bytes(), bytes);
    }

    #[test]
    fn conditional_branch_creates_two_blocks_via_taken_target() {
        // 0: 31 c0          xor eax, eax       ; sets ZF
        // 2: 74 01          je short +1 -> 0x05
        // 4: c3             ret                ; not-taken / fall-through
        // 5: 90             nop                ; taken target
        // 6: c3             ret
        let bytes = [0x31, 0xc0, 0x74, 0x01, 0xc3, 0x90, 0xc3];
        let f = lift(&bytes, 0x1000);
        // Three blocks expected: leader 0x1000 (entry), 0x1004 (fallthrough),
        // 0x1005 (taken).
        assert_eq!(f.blocks.len(), 3);
        assert_eq!(f.blocks[0].addr, VAddr(0x1000));
        assert_eq!(f.blocks[1].addr, VAddr(0x1004));
        assert_eq!(f.blocks[2].addr, VAddr(0x1005));
        assert!(matches!(
            f.blocks[0].terminator,
            Terminator::ConditionalBranch {
                taken: VAddr(0x1005),
                fallthrough: VAddr(0x1004),
            }
        ));
        assert_eq!(f.blocks[1].terminator, Terminator::Return);
        assert_eq!(f.blocks[2].terminator, Terminator::Return);
        assert_eq!(f.emit_bytes(), bytes);
    }

    #[test]
    fn calls_do_not_split_blocks() {
        // 0: e8 05 00 00 00       call +5 -> 0x0a
        // 5: 31 c0                xor eax, eax
        // 7: c3                   ret
        // 8: 90 90                nop nop
        // a: c3                   ret
        let bytes = [
            0xe8, 0x05, 0x00, 0x00, 0x00, // call +5
            0x31, 0xc0, // xor eax, eax
            0xc3, // ret
            0x90, 0x90, // nops
            0xc3, // ret
        ];
        let f = lift(&bytes, 0x1000);
        // The call does NOT terminate. The first ret does. Then another
        // block starts at the address after the ret.
        assert_eq!(f.blocks.len(), 2);
        assert_eq!(f.blocks[0].insns.len(), 3); // call, xor, ret
        assert_eq!(f.blocks[0].terminator, Terminator::Return);
        assert_eq!(f.blocks[1].terminator, Terminator::Return);
        assert_eq!(f.emit_bytes(), bytes);
    }

    #[test]
    fn empty_stream_errors() {
        assert!(matches!(
            lift_function("e".into(), &[]),
            Err(LiftError::Empty)
        ));
    }
}

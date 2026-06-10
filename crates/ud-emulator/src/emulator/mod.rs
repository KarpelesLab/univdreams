//! The 32-bit x86 software interpreter.
//!
//! Three submodules:
//!
//! * [`mmu`] — flat 4 GiB virtual memory with R/W/X-permissioned
//!   sparse pages.
//! * [`regs`] — register file (eax..ebp + esp + eip + EFLAGS).
//! * [`decode`] — i386 instruction decoder (REX-less; we run in
//!   32-bit protected mode equivalent).
//! * [`isa_int`] — i386 integer instruction executor + the
//!   primary [`Cpu`] type.
//!
//! The interpreter is a `match` over decoded operations; no JIT,
//! no host-CPU dependence. See `OxideAV/docs/winmf/winmf-emulator.md`
//! §"The emulator" for the design rationale.

pub mod aarch64;
pub mod decode;
pub mod isa_avx;
pub mod isa_fpu;
pub mod isa_int;
pub mod isa_mmx;
pub mod isa_sse;
pub mod long64;
pub mod mmu;
pub mod regs;

pub use isa_int::Cpu;
pub use mmu::{Mmu, Perm};
pub use regs::{Flags, Regs};

/// Reasons the interpreter halts other than reaching the
/// synthetic return sentinel.
///
/// Trap variants nest enough detail to debug a misbehaving codec
/// without losing the address of the offending instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trap {
    /// Tried to access an unmapped page.
    MemoryFault { addr: u32 },
    /// Page is mapped but read permission is not set.
    ReadProtectFault { addr: u32 },
    /// Page is mapped but write permission is not set.
    WriteProtectFault { addr: u32 },
    /// Tried to fetch an instruction byte from a non-executable
    /// page.
    ExecuteProtectFault { addr: u32 },
    /// Unknown / unimplemented opcode at `eip`.
    UndefinedOpcode { eip: u32, opcode: u32 },
    /// Privileged opcode (CR/DR access, IO, INT, HLT, far call,
    /// segment load, …) — cannot run inside the sandbox.
    PrivilegedOpcode { eip: u32, mnemonic: &'static str },
    /// A software interrupt (`INT n`) executed in 16-bit (Win16) mode.
    /// The run loop services known vectors in place (e.g. DOS
    /// `INT 21h`) and resumes; unhandled vectors surface as an error.
    /// `eip` is the address of the instruction after the `INT`.
    SoftwareInterrupt { num: u8, eip: u32 },
    /// A syscall-gate instruction executed: x86-64 `syscall` (0F 05) or
    /// AArch64 `SVC`. The Linux run loop reads the arch's syscall
    /// registers, services it, and resumes; `pc` already points past the
    /// gate instruction.
    Syscall { pc: u64 },
    /// Integer divide by zero.
    DivideByZero { eip: u32 },
    /// Codec called a Win32 function we have not stubbed.
    UnresolvedImport { dll: String, name: String },
    /// Instruction limit exceeded — guards against runaway
    /// loops.
    InstructionLimitExceeded { eip: u32, count: u64 },
    /// MMX opcode in the recognised opcode-map slots
    /// (`0F 60..6F`, `0F 70..7F`, `0F D0..FF`) that is decoded as
    /// MMX but not yet semantically implemented.
    ///
    /// Round 7 routes the MMX opcode space here; round 8 drains
    /// it opcode-by-opcode. The trap carries the full 2-byte
    /// opcode (`0F xx`) packed into `opcode`, the EIP of the
    /// `0F` byte, and a short SDM-derived `mnemonic_hint`
    /// (`"PADDB"`, `"MOVQ MMX"`, `"PXOR"`, …) so the trap log
    /// reads as a concrete to-do list.
    UnimplementedMmx {
        eip: u32,
        opcode: u32,
        mnemonic_hint: &'static str,
    },
}

impl core::fmt::Display for Trap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Trap::MemoryFault { addr } => {
                write!(f, "memory fault at {addr:#010x} (page unmapped)")
            }
            Trap::ReadProtectFault { addr } => {
                write!(f, "read-protect fault at {addr:#010x} (no R bit)")
            }
            Trap::WriteProtectFault { addr } => {
                write!(f, "write-protect fault at {addr:#010x} (no W bit)")
            }
            Trap::ExecuteProtectFault { addr } => {
                write!(f, "execute-protect fault at {addr:#010x} (no X bit)")
            }
            Trap::UndefinedOpcode { eip, opcode } => {
                write!(f, "undefined opcode {opcode:#x} at eip={eip:#010x}")
            }
            Trap::PrivilegedOpcode { eip, mnemonic } => {
                write!(f, "privileged opcode {mnemonic:?} at eip={eip:#010x}")
            }
            Trap::SoftwareInterrupt { num, eip } => {
                write!(f, "unhandled INT {num:#04x} at eip={eip:#010x}")
            }
            Trap::Syscall { pc } => write!(f, "unhandled syscall gate at pc={pc:#018x}"),
            Trap::DivideByZero { eip } => write!(f, "divide-by-zero at eip={eip:#010x}"),
            Trap::UnresolvedImport { dll, name } => {
                write!(f, "unresolved import {dll}!{name}")
            }
            Trap::InstructionLimitExceeded { eip, count } => write!(
                f,
                "instruction limit exceeded at eip={eip:#010x} after {count} instructions"
            ),
            Trap::UnimplementedMmx {
                eip,
                opcode,
                mnemonic_hint,
            } => write!(
                f,
                "unimplemented MMX opcode {opcode:#06x} ({mnemonic_hint}) at eip={eip:#010x}"
            ),
        }
    }
}

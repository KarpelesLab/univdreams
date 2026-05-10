//! Call-site analysis: identify direct `call` instructions and the
//! `mov` / `lea` arg-setup operations that immediately precede them.
//!
//! The analyzer walks a basic block forward maintaining per-register
//! state (the SysV-x64 integer arg registers — RDI/RSI/RDX/RCX/R8/R9
//! plus RAX for tracking call results). When it sees a direct
//! `call`, it snapshots the current arg-register values and emits a
//! [`CallSite`] covering the contiguous arg-setup-then-call window.
//!
//! Anything we can't model (a memory store, a non-trivial arithmetic
//! op, a conditional branch, an indirect call) clears the window and
//! the next call has to rebuild from scratch. This is conservative
//! by design: a folded `@call` directive must either be exact or not
//! lift at all, since the .ud language treats a folded directive's
//! pinned bytes as authoritative.

use std::collections::HashMap;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::DecodedInsn;

/// Per-arg value computed by the analyzer. The renderer (the
/// decompiler) turns this into a human-readable string using
/// per-binary context (`.rodata` strings, function names, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    /// A literal integer immediate (e.g. `mov edi, 8`).
    Const(i64),
    /// A rip-relative address load (`lea reg, [rip+disp]`). Likely a
    /// string in `.rodata` or a function pointer.
    Lea { addr: u64 },
    /// A rip-relative memory load (`mov reg, [rip+disp]`). Likely a
    /// global variable.
    GlobalLoad { addr: u64 },
    /// A stack-slot load (`mov reg, [rbp+disp]`).
    StackLoad { displacement: i64 },
    /// The result of the most-recent call in the same block.
    PrevCallResult,
}

/// One detected direct-call site, including the index range of the
/// instructions that should be folded into the resulting `@call`.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Absolute virtual address of the call target.
    pub call_target: u64,
    /// Arg values resolved from the SysV arg registers, in order.
    /// Length stops at the first arg register that has no resolved
    /// value (so a function we infer takes 2 args has `args.len() == 2`).
    pub args: Vec<ArgValue>,
    /// Index in the input slice of the first arg-setup instruction
    /// to fold into the `@call`.
    pub setup_start: usize,
    /// Index of the `call` instruction itself.
    pub call_idx: usize,
}

/// One recognised post-call result spill: the instruction(s) that
/// move the call's return value into a stack slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostCallSpill {
    /// Stack-slot displacement the result lands at (`[rbp+displacement]`).
    pub displacement: i64,
    /// Number of trailing instructions matched (1 or 2).
    pub insns_consumed: usize,
}

/// If the instructions starting at `after_idx` form a recognised
/// "spill the call's return value to a local stack slot" sequence,
/// return the displacement of that slot.
///
/// Recognised patterns:
///
/// * `mov [rbp+disp], rax`   — int/pointer return spill.
/// * `mov [rbp+disp], eax`   — 32-bit int return spill.
/// * `movq rax, xmm0; mov [rbp+disp], rax` — float/double return
///   rerouted through rax then stored.
#[must_use]
pub fn detect_post_call_spill(insns: &[DecodedInsn], after_idx: usize) -> Option<PostCallSpill> {
    let first = insns.get(after_idx)?;
    let m = first.iced.mnemonic();
    if m == Mnemonic::Movq && is_movq_rax_from_xmm0(&first.iced) {
        let second = insns.get(after_idx + 1)?;
        let disp = parse_rbp_store(&second.iced, &[Register::RAX])?;
        return Some(PostCallSpill {
            displacement: disp,
            insns_consumed: 2,
        });
    }
    if m == Mnemonic::Mov {
        let disp = parse_rbp_store(&first.iced, &[Register::RAX, Register::EAX])?;
        return Some(PostCallSpill {
            displacement: disp,
            insns_consumed: 1,
        });
    }
    None
}

fn is_movq_rax_from_xmm0(insn: &Instruction) -> bool {
    insn.op_count() == 2
        && insn.op0_kind() == OpKind::Register
        && insn.op0_register() == Register::RAX
        && insn.op1_kind() == OpKind::Register
        && insn.op1_register() == Register::XMM0
}

fn parse_rbp_store(insn: &Instruction, allowed_src: &[Register]) -> Option<i64> {
    if insn.op_count() != 2 {
        return None;
    }
    if insn.op0_kind() != OpKind::Memory
        || insn.memory_base() != Register::RBP
        || insn.memory_index() != Register::None
    {
        return None;
    }
    if insn.op1_kind() != OpKind::Register {
        return None;
    }
    if !allowed_src.contains(&insn.op1_register()) {
        return None;
    }
    #[allow(clippy::cast_possible_wrap)]
    Some(insn.memory_displacement64() as i64)
}

/// Walk `insns` forward, returning every direct call site whose
/// arg-setup we could resolve.
#[must_use]
pub fn identify_call_sites(insns: &[DecodedInsn]) -> Vec<CallSite> {
    let mut analyzer = Analyzer::default();
    let mut out = Vec::new();
    for (i, insn) in insns.iter().enumerate() {
        analyzer.step(i, &insn.iced, &mut out);
    }
    out
}

#[derive(Default)]
struct Analyzer {
    /// Currently-known values for arg registers (and RAX for call
    /// results). Cleared at each window boundary.
    regs: HashMap<Register, ArgValue>,
    /// Currently-known values written to the i386 cdecl stack-arg
    /// slots: `[esp]`, `[esp+4]`, `[esp+8]`, … Keyed by the offset
    /// from `esp`. Cleared after each call window.
    stack_args: HashMap<i32, ArgValue>,
    /// Index right after the previous call (or 0 at block start).
    /// Determines which instructions are foldable into the next call.
    setup_start: usize,
    /// Whether we've seen a call in this block already. RAX's
    /// `PrevCallResult` is only meaningful from that point on.
    saw_any_call: bool,
}

impl Analyzer {
    fn step(&mut self, idx: usize, insn: &Instruction, out: &mut Vec<CallSite>) {
        match insn.mnemonic() {
            Mnemonic::Call => self.handle_call(idx, insn, out),
            Mnemonic::Mov
            | Mnemonic::Movq
            | Mnemonic::Movd
            | Mnemonic::Movss
            | Mnemonic::Movsd
            | Mnemonic::Movaps
            | Mnemonic::Movapd => {
                if !self.handle_mov(insn) {
                    self.break_window(idx + 1);
                }
            }
            Mnemonic::Lea => {
                if !self.handle_lea(insn) {
                    self.break_window(idx + 1);
                }
            }
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 => {
                // Pure markers — leave the window intact.
            }
            _ => self.break_window(idx + 1),
        }
    }

    fn handle_call(&mut self, idx: usize, insn: &Instruction, out: &mut Vec<CallSite>) {
        // Direct calls only — indirect calls (`call rax`) lose their
        // target name, and arg-setup analysis would be misleading.
        if insn.flow_control() != FlowControl::Call {
            self.break_window(idx + 1);
            return;
        }
        let target = insn.near_branch_target();
        if target == 0 {
            self.break_window(idx + 1);
            return;
        }

        // SysV-x64 splits args by class: integers go into the GPR
        // sequence, doubles/floats into the XMM sequence. We can't
        // recover the original C-source interleaving without type
        // info, so we append all int args first then all float args
        // — wrong for `f(int, double, int, double)` but right for
        // every fixture today.
        let int_arg_regs = [
            Register::RDI,
            Register::RSI,
            Register::RDX,
            Register::RCX,
            Register::R8,
            Register::R9,
        ];
        let xmm_arg_regs = [
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            Register::XMM3,
            Register::XMM4,
            Register::XMM5,
            Register::XMM6,
            Register::XMM7,
        ];
        let mut args = Vec::new();
        for r in int_arg_regs {
            match self.regs.get(&full_reg(r)).cloned() {
                Some(v) => args.push(v),
                None => break,
            }
        }
        // i386 cdecl: when no integer arg registers were touched but
        // we saw `mov [esp+OFF], val` writes, fall back to the stack
        // sequence at offsets 0, 4, 8, … as the integer args.
        if args.is_empty() {
            let mut off = 0i32;
            while let Some(v) = self.stack_args.get(&off).cloned() {
                args.push(v);
                off += 4;
            }
        }
        for r in xmm_arg_regs {
            match self.regs.get(&full_reg(r)).cloned() {
                Some(v) => args.push(v),
                None => break,
            }
        }
        out.push(CallSite {
            call_target: target,
            args,
            setup_start: self.setup_start,
            call_idx: idx,
        });

        // After the call: arg registers are clobbered. The return
        // value lives in RAX for integer/pointer returns and in XMM0
        // for float/double returns; we don't know which, so both
        // get the `PrevCallResult` tag so downstream `mov reg, rax`
        // / `movq reg, xmm0` chains can pick it up. Stack arg slots
        // are also invalidated — cdecl callers leave the values on
        // the stack but reuse the slots for the next call's setup.
        self.regs.clear();
        self.regs.insert(Register::RAX, ArgValue::PrevCallResult);
        self.regs.insert(Register::XMM0, ArgValue::PrevCallResult);
        self.stack_args.clear();
        self.saw_any_call = true;
        self.setup_start = idx + 1;
    }

    fn handle_mov(&mut self, insn: &Instruction) -> bool {
        if insn.op_count() != 2 {
            return false;
        }
        // `mov [esp+OFF], src` — i386 cdecl stack-arg setup. Track
        // the value at that slot and keep the window open.
        if insn.op0_kind() == OpKind::Memory
            && insn.memory_base() == Register::ESP
            && insn.memory_index() == Register::None
        {
            let val = match insn.op1_kind() {
                OpKind::Register => match self.regs.get(&full_reg(insn.op1_register())).cloned() {
                    Some(v) => v,
                    None => return false,
                },
                OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => ArgValue::Const(read_signed_immediate(insn)),
                _ => return false,
            };
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let off = insn.memory_displacement64() as i32;
            self.stack_args.insert(off, val);
            return true;
        }
        if insn.op0_kind() != OpKind::Register {
            return false;
        }
        let dst = insn.op0_register();
        let value = match insn.op1_kind() {
            OpKind::Register => {
                let src = insn.op1_register();
                if let Some(v) = self.regs.get(&full_reg(src)) {
                    v.clone()
                } else if full_reg(src) == Register::RAX && self.saw_any_call {
                    ArgValue::PrevCallResult
                } else {
                    return false;
                }
            }
            OpKind::Memory => {
                if insn.memory_index() != Register::None {
                    return false;
                }
                match insn.memory_base() {
                    Register::RIP => ArgValue::GlobalLoad {
                        addr: insn.memory_displacement64(),
                    },
                    Register::RBP => ArgValue::StackLoad {
                        #[allow(clippy::cast_possible_wrap)]
                        displacement: insn.memory_displacement64() as i64,
                    },
                    _ => return false,
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => ArgValue::Const(read_signed_immediate(insn)),
            _ => return false,
        };
        self.regs.insert(full_reg(dst), value);
        true
    }

    fn handle_lea(&mut self, insn: &Instruction) -> bool {
        if insn.op_count() != 2 || insn.op0_kind() != OpKind::Register {
            return false;
        }
        if insn.op1_kind() != OpKind::Memory {
            return false;
        }
        if insn.memory_base() != Register::RIP || insn.memory_index() != Register::None {
            return false;
        }
        let dst = insn.op0_register();
        self.regs.insert(
            full_reg(dst),
            ArgValue::Lea {
                addr: insn.memory_displacement64(),
            },
        );
        true
    }

    fn break_window(&mut self, next_setup_start: usize) {
        // Anything we can't model invalidates pending arg setup —
        // the next call must start its window fresh. RAX's "prev
        // call result" tag survives, since later moves can still
        // recover it.
        let prev_rax = self.regs.remove(&Register::RAX);
        self.regs.clear();
        if let Some(rax) = prev_rax {
            self.regs.insert(Register::RAX, rax);
        }
        self.setup_start = next_setup_start;
    }
}

fn full_reg(reg: Register) -> Register {
    let full = reg.full_register();
    if full == Register::None {
        reg
    } else {
        full
    }
}

#[allow(clippy::cast_possible_wrap)]
fn read_signed_immediate(insn: &Instruction) -> i64 {
    match insn.op1_kind() {
        OpKind::Immediate8 => i64::from(insn.immediate8() as i8),
        OpKind::Immediate16 => i64::from(insn.immediate16() as i16),
        OpKind::Immediate32 => i64::from(insn.immediate32() as i32),
        OpKind::Immediate64 => insn.immediate64() as i64,
        OpKind::Immediate8to16 => i64::from(insn.immediate8to16()),
        OpKind::Immediate8to32 => i64::from(insn.immediate8to32()),
        OpKind::Immediate8to64 => insn.immediate8to64(),
        OpKind::Immediate32to64 => insn.immediate32to64(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, Bitness};

    #[test]
    fn lifts_direct_call_with_one_immediate_arg() {
        // mov edi, 8        ; bf 08 00 00 00
        // call <0x100A>     ; e8 00 00 00 00  (rel32 = 0)
        // Block at 0x1000; mov ends at 0x1005; call ends at 0x100a.
        let bytes = [0xbf, 0x08, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let sites = identify_call_sites(&insns);
        assert_eq!(sites.len(), 1);
        let cs = &sites[0];
        assert_eq!(cs.call_target, 0x100a);
        assert_eq!(cs.args, vec![ArgValue::Const(8)]);
        assert_eq!(cs.setup_start, 0);
        assert_eq!(cs.call_idx, 1);
    }

    #[test]
    fn lifts_lea_through_rax_to_rdi() {
        // lea rax, [rip+0x1000]  ; 48 8d 05 00 10 00 00
        // mov rdi, rax           ; 48 89 c7
        // call <near>            ; e8 00 00 00 00
        let bytes = [
            0x48, 0x8d, 0x05, 0x00, 0x10, 0x00, 0x00, // lea rax, [rip+0x1000]
            0x48, 0x89, 0xc7, // mov rdi, rax
            0xe8, 0x00, 0x00, 0x00, 0x00, // call rel32
        ];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let sites = identify_call_sites(&insns);
        assert_eq!(sites.len(), 1);
        // lea ip = 0x1000, length 7 → rip after = 0x1007 → target = 0x2007.
        assert_eq!(sites[0].args, vec![ArgValue::Lea { addr: 0x2007 }]);
    }

    #[test]
    fn second_call_reads_prev_result_through_rax() {
        // call f1            ; e8 00 00 00 00 (target=0x1005)
        // mov esi, eax       ; 89 c6 (← prev call result becomes arg-1 of next call)
        // mov edi, 1         ; bf 01 00 00 00
        // call f2            ; e8 00 00 00 00 (target=0x1011)
        let bytes = [
            0xe8, 0x00, 0x00, 0x00, 0x00, // call f1
            0x89, 0xc6, // mov esi, eax
            0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
            0xe8, 0x00, 0x00, 0x00, 0x00, // call f2
        ];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let sites = identify_call_sites(&insns);
        assert_eq!(sites.len(), 2);
        // First call has no args resolved.
        assert!(sites[0].args.is_empty());
        // Second call has arg0 = const 1, arg1 = prev result.
        assert_eq!(
            sites[1].args,
            vec![ArgValue::Const(1), ArgValue::PrevCallResult]
        );
    }

    #[test]
    fn lifts_xmm_arg_via_movsd_load() {
        // movsd xmm0, [rbp-0x10]  ; f2 0f 10 45 f0
        // call f                   ; e8 00 00 00 00
        let bytes = [0xf2, 0x0f, 0x10, 0x45, 0xf0, 0xe8, 0x00, 0x00, 0x00, 0x00];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let sites = identify_call_sites(&insns);
        assert_eq!(sites.len(), 1);
        assert_eq!(
            sites[0].args,
            vec![ArgValue::StackLoad {
                displacement: -0x10
            }]
        );
    }

    #[test]
    fn lifts_xmm_arg_via_movq_from_rax() {
        // mov rax, [rip+0x100]     ; 48 8b 05 00 01 00 00
        // movq xmm0, rax            ; 66 48 0f 6e c0
        // call f                    ; e8 00 00 00 00
        let bytes = [
            0x48, 0x8b, 0x05, 0x00, 0x01, 0x00, 0x00, // mov rax, [rip+0x100]
            0x66, 0x48, 0x0f, 0x6e, 0xc0, // movq xmm0, rax
            0xe8, 0x00, 0x00, 0x00, 0x00, // call rel32
        ];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let sites = identify_call_sites(&insns);
        assert_eq!(sites.len(), 1);
        // mov rax,[rip+0x100] resolves with rip-after = 0x1007 → 0x1107.
        assert_eq!(sites[0].args, vec![ArgValue::GlobalLoad { addr: 0x1107 }]);
    }

    #[test]
    fn detect_post_call_spill_recognizes_movq_then_mov() {
        // movq rax, xmm0           ; 66 48 0f 7e c0
        // mov [rbp-8], rax         ; 48 89 45 f8
        let bytes = [0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x48, 0x89, 0x45, 0xf8];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let spill = detect_post_call_spill(&insns, 0).expect("should match");
        assert_eq!(spill.displacement, -8);
        assert_eq!(spill.insns_consumed, 2);
    }

    #[test]
    fn detect_post_call_spill_recognizes_direct_mov_rax() {
        // mov [rbp-0x10], rax      ; 48 89 45 f0
        let bytes = [0x48, 0x89, 0x45, 0xf0];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let spill = detect_post_call_spill(&insns, 0).expect("should match");
        assert_eq!(spill.displacement, -0x10);
        assert_eq!(spill.insns_consumed, 1);
    }

    #[test]
    fn detect_post_call_spill_rejects_unrelated_mov() {
        // mov rdi, rax — register-to-register, no store.
        let bytes = [0x48, 0x89, 0xc7];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        assert!(detect_post_call_spill(&insns, 0).is_none());
    }

    #[test]
    fn unmodelled_op_breaks_arg_window() {
        // mov edi, 1                     ; bf 01 00 00 00
        // add dword ptr [rbp-4], 1       ; 83 45 fc 01  (memory write — we don't model)
        // call f                         ; e8 00 00 00 00
        let bytes = [
            0xbf, 0x01, 0x00, 0x00, 0x00, 0x83, 0x45, 0xfc, 0x01, 0xe8, 0x00, 0x00, 0x00, 0x00,
        ];
        let insns = decode(Bitness::Bits64, &bytes, 0x1000).unwrap();
        let sites = identify_call_sites(&insns);
        assert_eq!(sites.len(), 1);
        assert!(
            sites[0].args.is_empty(),
            "memory write should have invalidated edi: {:?}",
            sites[0].args
        );
        assert_eq!(sites[0].setup_start, 2); // starts after the unmodelled insn
    }
}

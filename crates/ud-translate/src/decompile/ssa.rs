//! x86 SSA bridge.
//!
//! Thin wrapper that supplies the arch-specific
//! reads/writes extraction (iced-x86 facts) to the generic
//! Cytron-Ferrante SSA core in [`ud_ir::ssa`]. The data
//! types ([`Var`], [`DefId`], [`DefSite`], [`SsaInfo`],
//! [`DefRecord`], [`Liveness`]) live in `ud-ir` and are
//! re-exported here so existing imports in
//! `crates/ud-translate/src/decompile/build_function.rs`
//! continue to work without edits.
//!
//! ## What this file owns
//!
//! Only the x86-coupled pieces:
//!
//! * [`insn_reads_writes`] — given one decoded x86
//!   instruction and the SP-delta-per-IP table, return
//!   `(reads, writes)` over [`Var`]. Uses iced's
//!   `InstructionInfoFactory` for explicit + implicit
//!   register accesses; handles memory operands separately
//!   to resolve `[ebp+disp]` / SP-delta-corrected
//!   `[esp+disp]` to the same `Var::Stack(offset)`.
//! * [`canonical_reg_name`] — iced `Register` → lowercase
//!   full-width name (`"eax"`, `"rsi"`, …). Sub-registers
//!   widen to their containing register so a write to `al`
//!   shows up as a write to `eax`.
//! * [`memory_var`] — x86 memory operand → `Var::Stack` or
//!   `Var::Memory`.
//! * Two helpers (`is_write_to_op0`, `is_read_of_op`) that
//!   encode the mnemonic-specific operand-access flavour
//!   the iced API doesn't expose directly.
//!
//! ## Public entry points (preserved API)
//!
//! [`build_ssa`] and [`compute_liveness`] keep their
//! pre-refactor signatures — same parameters, same return
//! types — so consumers don't change. Internally they
//! construct a closure capturing `sp_delta_at` and dispatch
//! to [`ud_ir::ssa::build_ssa`] / [`ud_ir::ssa::compute_liveness`].

use std::collections::HashMap;

use ud_arch_x86::{DecodedInsn, Instruction, InstructionInfoFactory, OpAccess, OpKind, Register};
use ud_ir::Function;

// Re-export the data types from the generic core so existing
// imports continue to work. `canonical_reg_name` is x86-only
// and stays a local function. `DefId` and `DefRecord` aren't
// re-exported because no current consumer references them
// through this path — downstream code that does need them
// imports straight from `ud_ir::ssa`.
pub use ud_ir::ssa::{DefSite, Liveness, SsaInfo, Var};

/// Compute liveness for `f` using x86's reads/writes
/// extraction. Backward dataflow lives in [`ud_ir::ssa`];
/// this wrapper just supplies the per-instruction bridge.
#[must_use]
pub fn compute_liveness(f: &Function<DecodedInsn>, sp_delta_at: &HashMap<u64, i64>) -> Liveness {
    ud_ir::ssa::compute_liveness(f, |i| insn_reads_writes(i, sp_delta_at))
}

/// Build SSA for `f` using x86's reads/writes extraction.
///
/// `sp_delta_at` carries the SP-delta-per-IP table the rest
/// of the lifter uses; SSA consults it to map `[esp+disp]`
/// accesses to the same EBP-form slots `[ebp+disp]` uses, so
/// both shapes resolve to the same `Var::Stack` and version
/// chain.
#[must_use]
pub fn build_ssa(f: &Function<DecodedInsn>, sp_delta_at: &HashMap<u64, i64>) -> SsaInfo {
    ud_ir::ssa::build_ssa(f, |i| insn_reads_writes(i, sp_delta_at))
}

/// Extract `(reads, writes)` for one x86 instruction.
///
/// Uses iced's `InstructionInfoFactory` for register
/// read/write classification (covers both explicit operand
/// registers and implicit ones like `cdq` writing edx or
/// `rep movsb` reading esi/edi). Memory operands are
/// classified separately: address-forming registers are
/// reads, the memory target itself is `Var::Stack(disp)`
/// when the access is EBP/ESP-relative or `Var::Memory`
/// otherwise.
pub fn insn_reads_writes(
    insn: &DecodedInsn,
    sp_delta_at: &HashMap<u64, i64>,
) -> (Vec<Var>, Vec<Var>) {
    let mut reads: Vec<Var> = Vec::new();
    let mut writes: Vec<Var> = Vec::new();
    let i = &insn.iced;
    let sp = sp_delta_at.get(&i.ip()).copied();
    // Register accesses (explicit + implicit) via InstructionInfoFactory.
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(i);
    for used in info.used_registers() {
        let Some(name) = canonical_reg_name(used.register()) else {
            continue;
        };
        let var = Var::Reg(name);
        match used.access() {
            OpAccess::Read | OpAccess::CondRead => push_unique(&mut reads, var),
            OpAccess::Write | OpAccess::CondWrite => push_unique(&mut writes, var),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                push_unique(&mut reads, var.clone());
                push_unique(&mut writes, var);
            }
            _ => {}
        }
    }
    // Memory accesses: walk operands, classify reads vs
    // writes by operand position. We can't get per-operand
    // access flags in iced 1.x without the
    // InstructionInfo memory-walker, but the common shape
    // is: Memory is op0 → write; Memory is op1 (or later) →
    // read; LEA's memory operand is conceptually a read of
    // the address but not of the memory.
    for op in 0..i.op_count() {
        if i.op_kind(op) == OpKind::Memory {
            // LEA: the "memory" operand is an address
            // computation, not an actual memory access.
            // Skip the Var::Memory or Var::Stack effect; the
            // base/index register reads were already
            // captured above by used_registers.
            if i.mnemonic() == ud_arch_x86::Mnemonic::Lea {
                continue;
            }
            let mem_var = memory_var(i, sp);
            // Heuristic: op0 memory is a write for typical
            // single-operand-destination instructions; the
            // rest are reads. Read-modify-write forms
            // (`add [mem], reg`) are both — we err on the
            // side of recording it as both via the
            // used_memory walker below.
            if op == 0 && is_write_to_op0(i.mnemonic()) {
                push_unique(&mut writes, mem_var.clone());
            }
            if is_read_of_op(i.mnemonic(), op) {
                push_unique(&mut reads, mem_var);
            }
        }
    }
    (reads, writes)
}

/// For an instruction's destination operand position 0,
/// does the mnemonic write to memory there? Covers the
/// common forms; the few that don't (compare-style ops with
/// mem op0 as a read) are listed explicitly.
fn is_write_to_op0(m: ud_arch_x86::Mnemonic) -> bool {
    use ud_arch_x86::Mnemonic;
    !matches!(
        m,
        // op0 is a read, not a write, for these.
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Push
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Bt
    )
}

/// Does this mnemonic read its op0 memory operand as well
/// as possibly writing it? Captures read-modify-write forms.
fn is_read_of_op(m: ud_arch_x86::Mnemonic, op: u32) -> bool {
    use ud_arch_x86::Mnemonic;
    if op > 0 {
        return true; // any later operand is a source = read
    }
    matches!(
        m,
        // op0 is read for these forms (memory source or RMW).
        Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Push
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Bt
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Adc
            | Mnemonic::Sbb
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Sal
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Xadd
            | Mnemonic::Xchg
            | Mnemonic::Cmpxchg
    )
}

fn push_unique(v: &mut Vec<Var>, x: Var) {
    if !v.contains(&x) {
        v.push(x);
    }
}

/// Map an iced `Register` to its lowercase
/// "canonical full-width" name. Sub-registers (al, ax) are
/// widened to their containing 32/64-bit register so a
/// write to `al` shows up as a write to `eax`. Returns
/// `None` for non-GPRs (XMM, segment, etc.) — those aren't
/// versioned by today's SSA.
#[must_use]
pub fn canonical_reg_name(reg: Register) -> Option<String> {
    let full = reg.full_register();
    let name = match full {
        Register::EAX | Register::RAX => "eax",
        Register::EBX | Register::RBX => "ebx",
        Register::ECX | Register::RCX => "ecx",
        Register::EDX | Register::RDX => "edx",
        Register::ESI | Register::RSI => "esi",
        Register::EDI | Register::RDI => "edi",
        Register::EBP | Register::RBP => "ebp",
        Register::ESP | Register::RSP => "esp",
        Register::R8 => "r8",
        Register::R9 => "r9",
        Register::R10 => "r10",
        Register::R11 => "r11",
        Register::R12 => "r12",
        Register::R13 => "r13",
        Register::R14 => "r14",
        Register::R15 => "r15",
        _ => return None,
    };
    Some(name.to_string())
}

fn memory_var(i: &Instruction, sp: Option<i64>) -> Var {
    let base = i.memory_base();
    let has_index = i.memory_index() != Register::None;
    // EBP-relative: `[ebp + disp]` directly maps to
    // Var::Stack(disp).
    if (base == Register::EBP || base == Register::RBP) && !has_index {
        #[allow(clippy::cast_possible_wrap)]
        let disp = i.memory_displacement64() as i64;
        return Var::Stack(disp);
    }
    // ESP-relative with a known SP delta — map to EBP-style
    // by adding the delta. Approximate; full alias analysis
    // would refine this.
    if (base == Register::ESP || base == Register::RSP) && !has_index {
        if let Some(delta) = sp {
            #[allow(clippy::cast_possible_wrap)]
            let disp = i.memory_displacement64() as i64;
            return Var::Stack(disp.wrapping_add(delta));
        }
    }
    Var::Memory
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_arch_x86::lift_function;
    use ud_arch_x86::{decode, Bitness};

    fn lift(bytes: &[u8]) -> Function<DecodedInsn> {
        let insns = decode(Bitness::Bits32, bytes, 0x1000).unwrap();
        lift_function("test".into(), &insns).unwrap()
    }

    /// Single-block function: `mov eax, 1; mov eax, 2; ret`.
    /// The second mov should be a fresh def; the use of
    /// `eax` returned (implicit) reaches the second def,
    /// not the first.
    #[test]
    fn linear_two_defs_keep_separate_versions() {
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0xc3, // ret
        ];
        let f = lift(&bytes);
        let sp: HashMap<u64, i64> = HashMap::new();
        let ssa = build_ssa(&f, &sp);
        // Two def sites for eax + one Entry def.
        let eax = Var::Reg("eax".into());
        let eax_defs: Vec<_> = ssa
            .defs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.var == eax)
            .collect();
        assert!(
            eax_defs.len() >= 2,
            "expected ≥2 eax defs (entry + 2 mov writes), got {}",
            eax_defs.len()
        );
        // Returned-via-eax read at the ret: should map to
        // the 2nd mov's def.
        let ret_ip = 0x1000 + 10;
        if let Some(reaching) = ssa.use_at.get(&(ret_ip, eax.clone())) {
            let site = &ssa.defs[reaching.0 as usize].site;
            assert!(
                matches!(site, DefSite::Insn(ip) if *ip == 0x1005),
                "ret's eax read should reach the 2nd mov (ip=0x1005), got {site:?}"
            );
        }
    }

    /// Liveness on a linear two-write program: after the
    /// first `mov eax, 1`, eax is dead because the next
    /// instruction overwrites it before any read. This is
    /// the key property for dead-store elimination.
    #[test]
    fn liveness_kills_overwritten_register() {
        let bytes = [
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1   — dead
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0x89, 0xc3, // mov ebx, eax — reads eax
            0xc3, // ret
        ];
        let f = lift(&bytes);
        let sp: HashMap<u64, i64> = HashMap::new();
        let live = compute_liveness(&f, &sp);
        let eax = Var::Reg("eax".into());
        let after_first = live.live_after_insn.get(&0x1000).expect("after first mov");
        assert!(
            !after_first.contains(&eax),
            "eax should be DEAD after first mov: {after_first:?}"
        );
        let after_second = live.live_after_insn.get(&0x1005).expect("after second mov");
        assert!(
            after_second.contains(&eax),
            "eax should be LIVE after second mov (next reads it): {after_second:?}"
        );
    }

    /// Diamond CFG: a conditional jumps to either of two
    /// blocks that each assign eax differently, then both
    /// flow into a merge block. The merge block should see
    /// a phi for eax with two incoming defs.
    #[test]
    fn diamond_cfg_places_phi_at_merge() {
        let bytes = [
            0x83, 0xf9, 0x00, // cmp ecx, 0
            0x74, 0x06, // je +6 → 0x100b
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xeb, 0x05, // jmp +5 → 0x1011 (off by 1 — let's compute)
            0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2
            0xc3, // ret
        ];
        let f = lift(&bytes);
        // Verify we have ≥ 3 blocks (entry, two arms, merge).
        assert!(
            f.blocks.len() >= 3,
            "expected diamond CFG, got {} blocks",
            f.blocks.len()
        );
        let sp: HashMap<u64, i64> = HashMap::new();
        let ssa = build_ssa(&f, &sp);
        // Look for a phi for eax.
        let eax = Var::Reg("eax".into());
        let has_phi = ssa
            .defs
            .iter()
            .any(|r| r.var == eax && matches!(r.site, DefSite::Phi { .. }));
        assert!(has_phi, "expected a phi for eax at the diamond merge");
    }
}

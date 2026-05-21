//! Function discovery from `call` targets.
//!
//! Stripped binaries (notably on-chain Solana programs that
//! only expose `entrypoint` + `custom_panic` in `.dynsym`) hide
//! every other function behind the dynamic linker's view. The
//! body is still there in `.text`; we just don't know where
//! each function starts.
//!
//! The trick: every `call <imm>` instruction whose `imm` is a
//! code-relative offset (as opposed to a syscall id / Murmur3
//! hash) names a function entry point. Harvest those targets
//! and synthesize `sub_<addr>` function entries; the rest of
//! the analysis pipeline treats them like any other discovered
//! function.
//!
//! v1 is BPF-specific because BPF is currently the only arch
//! that benefits — x86 has `.eh_frame` and `.symtab` doing most
//! of this work already, and the BPF call instruction has a
//! fixed format we can decode without falling into pun /
//! data confusion. The structure is generic enough that an
//! `Arch::CallTargetCollector` trait can land alongside L5a's
//! per-arch `Condition` hook when we need a second arch's
//! harvester.

use std::collections::HashMap;

use ud_arch_bpf::{call_target, decode, BpfVariant, InsnKind};
use ud_core::VAddr;
use ud_format::elf::{Elf64File, EM_BPF, EM_SBF, SHF_EXECINSTR};

use crate::function_map::{Function, FunctionSource};

/// Errors specific to call-site discovery.
#[derive(Debug, thiserror::Error)]
pub enum CallSiteError {
    #[error(transparent)]
    BpfDecode(ud_arch_bpf::Error),
}

/// Discover BPF / SBF function entries from local `call`
/// targets. Returns one `Function` per unique target address;
/// `syscall_calls` lists addresses already accounted for by
/// `bpf_relocs` so we don't re-emit syscall targets as local
/// functions.
///
/// Size is left at zero; the existing
/// `fill_in_sizes_from_neighbors` pass in `lib.rs` fills it
/// from the next discovered function's address (or the section
/// end).
///
/// Returns an empty vector for non-BPF e_machines so the
/// caller can call unconditionally.
#[allow(clippy::missing_errors_doc, clippy::implicit_hasher)]
pub fn discover_from_bpf_call_sites(
    elf: &Elf64File,
    syscall_calls: &HashMap<u64, String>,
) -> Result<Vec<Function>, CallSiteError> {
    if !matches!(elf.ehdr.e_machine, EM_BPF | EM_SBF) {
        return Ok(Vec::new());
    }
    let variant = if elf.ehdr.e_machine == EM_BPF {
        BpfVariant::Linux
    } else {
        BpfVariant::Sbfv1
    };

    // Gather every executable section's [start, end) — call
    // targets that fall outside any of these are bogus
    // (data refs, syscall hashes that happen to look like
    // small offsets) and should be ignored.
    let exec_ranges: Vec<(u64, u64)> = elf
        .sections()
        .filter(|(_, sh, _)| sh.sh_flags & SHF_EXECINSTR != 0 && sh.sh_size > 0)
        .map(|(_, sh, _)| (sh.sh_addr, sh.sh_addr.saturating_add(sh.sh_size)))
        .collect();

    let mut targets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    for (_, sh, data) in elf.sections() {
        if sh.sh_flags & SHF_EXECINSTR == 0 || sh.sh_size == 0 {
            continue;
        }
        // BPF slots are 8 bytes; reject misaligned sections
        // silently — the round-trip path will surface the
        // problem later if there is one.
        if data.len() % ud_arch_bpf::INSN_SIZE != 0 {
            continue;
        }
        let insns = decode(data, sh.sh_addr, variant).map_err(CallSiteError::BpfDecode)?;
        for insn in &insns {
            if insn.kind != InsnKind::Call {
                continue;
            }
            // Syscalls are excluded — those don't target local
            // function entries.
            if syscall_calls.contains_key(&insn.addr.0) {
                continue;
            }
            // Defensive: BPF syscalls on Linux use small
            // positive imm values that are helper IDs, not
            // offsets. We have no easy way to tell them apart
            // here without the reloc table, so fall back to
            // "target must land inside an executable section"
            // — that rejects most stray helper-id calls
            // because helper IDs are typically tiny (0..30)
            // and the resulting target lands in the first
            // hundred bytes of `.text`, which is usually
            // pre-function header bytes. False positives are
            // possible but cosmetic; layer 6's
            // discovery-confidence pass can prune.
            let target = call_target(insn);
            let in_text = exec_ranges
                .iter()
                .any(|&(start, end)| (start..end).contains(&target));
            if !in_text {
                continue;
            }
            // BPF instructions are slot-aligned; a target that
            // isn't 8-byte aligned is a decode error somewhere
            // upstream.
            if target % ud_arch_bpf::INSN_SIZE as u64 != 0 {
                continue;
            }
            targets.insert(target);
        }
    }

    Ok(targets
        .into_iter()
        .map(|addr| Function {
            addr: VAddr(addr),
            size: 0,
            name: format!("sub_{addr:x}"),
            sources: vec![FunctionSource::CallSite],
        })
        .collect())
}

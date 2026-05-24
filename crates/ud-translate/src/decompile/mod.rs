//! Decompile a parsed ELF into a `.ud` AST.
//!
//! The output of [`decompile`] is a [`ud_ast::UdFile`] in canonical
//! shape:
//!
//! * A `@module { … }` header pinned from the ELF header.
//! * A top-level `@section("name", 0x…) { … }` block per ELF section
//!   that has on-disk content (everything except NULL, NOBITS, and
//!   debug-info sections without a virtual address). Section bodies
//!   contain `fn` declarations for discovered functions and `@raw`
//!   blocks for everything between/around them — alignment padding,
//!   data section content, etc.
//! * `// note: …` comments at the top level for functions we know
//!   exist but couldn't locate bytes for (no recorded size, missing
//!   from any executable section).
//!
//! The byte-identity invariant the decompiler defends:
//!
//! > For every section emitted, concatenating the bytes of its items
//! > in source order reproduces the section's on-disk content exactly.
//!
//! This is the precondition for full source-level binary round-trip
//! once `phdr` / `shdr` metadata makes it into `@module` (next
//! iteration).
//!
//! [`decompile_to_text`] is the thin wrapper that calls
//! [`ud_ast::emit`] on the AST.

#![allow(clippy::cast_possible_truncation)]

mod aarch64;
mod args;
mod bpf;
mod bpf_args_ssa;
mod bpf_ssa;
mod build_function;
mod build_module;
mod data_lookup;
mod expr;
mod idioms;
pub mod macho;
mod patterns;
pub mod pe;
pub mod raw6502;
mod ssa;
mod stack_slots;
pub mod wasm;
mod wasm_disasm;

pub use data_lookup::DataLookup;
pub use macho::{decompile_macho, decompile_macho_to_text};
pub use pe::{decompile_pe, decompile_pe_to_text};
pub use raw6502::{decompile_raw_6502, decompile_raw_6502_to_text};
pub use wasm::{decompile_wasm, decompile_wasm_to_text};

use std::collections::HashMap;

use ud_analysis::{discover_functions, FunctionMap};
use ud_arch_x86::{decode, lift_function, Bitness};
use ud_ast::{Item, UdFile};
use ud_debug::DebugFunction;
use ud_format::elf::{
    Elf64File, ElfClass, Shdr64, EM_386, EM_AARCH64, EM_BPF, EM_SBF, EM_X86_64, SHF_EXECINSTR,
};

/// Which arch backend to drive for a given ELF.
#[derive(Debug, Clone, Copy)]
enum Arch {
    X86 { bitness: Bitness },
    Aarch64,
    Bpf { variant: ud_arch_bpf::BpfVariant },
}

/// Errors surfaced by the top-level entry point.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("only x86 ELF inputs are supported; got e_machine = {0}")]
    UnsupportedMachine(u16),

    #[error(transparent)]
    Analysis(#[from] ud_analysis::Error),

    #[error(transparent)]
    Decode(#[from] ud_arch_x86::Error),

    #[error(transparent)]
    Lift(#[from] ud_arch_x86::LiftError),

    #[error(transparent)]
    Debug(#[from] ud_debug::DebugError),

    #[error(transparent)]
    Aarch64Decode(ud_arch_aarch64::Error),

    #[error(transparent)]
    BpfDecode(ud_arch_bpf::Error),

    #[error(transparent)]
    BpfReloc(ud_analysis::bpf_relocs::BpfRelocError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Build the AST for `elf`. The structural form is the primary output
/// of decompilation; [`decompile_to_text`] is a thin convenience.
pub fn decompile(elf: &Elf64File) -> Result<UdFile> {
    let arch = match (elf.class, elf.ehdr.e_machine) {
        (ElfClass::Elf64, EM_X86_64) => Arch::X86 {
            bitness: Bitness::Bits64,
        },
        (ElfClass::Elf32, EM_386) => Arch::X86 {
            bitness: Bitness::Bits32,
        },
        (ElfClass::Elf64, EM_AARCH64) => Arch::Aarch64,
        // Linux eBPF — `e_machine = 247`. Always ELF64-LE
        // regardless of host endianness; SBF support below
        // covers the Solana-specific machine number.
        (ElfClass::Elf64, EM_BPF) => Arch::Bpf {
            variant: ud_arch_bpf::BpfVariant::Linux,
        },
        // Solana SBF — `e_machine = 263`. sBPFv1 vs sBPFv2 is
        // a runtime decision made by the loader from
        // `e_flags`; for the decompile path we default to
        // sBPFv1 since the encoding is shared and the variant
        // only changes a handful of mnemonics. A future pass
        // can sharpen this once a real sBPFv2 fixture lands.
        (ElfClass::Elf64, EM_SBF) => Arch::Bpf {
            variant: ud_arch_bpf::BpfVariant::Sbfv1,
        },
        _ => return Err(Error::UnsupportedMachine(elf.ehdr.e_machine)),
    };

    let module = build_module::build_module(elf);
    let map = discover_functions(elf)?;
    let debug_by_addr: HashMap<u64, DebugFunction> = ud_debug::read_debug_info(elf)?;

    // Build an address → name map once; passed to every build_function so
    // call sites can be annotated with target names.
    let name_at: HashMap<u64, String> = map.iter().map(|f| (f.addr.0, f.name.clone())).collect();

    // BPF / SBF only: build a `call <imm> → symbol name` map
    // from `.rel.dyn`. This is layer 1 of the BPF
    // decompile-quality push — `call 0xeca` becomes
    // `call sol_log_` for every relocation-resolved import.
    // Non-BPF arches don't carry these relocations; the map
    // stays empty and the rewrite path is a no-op.
    let call_site_names: HashMap<u64, String> = match arch {
        Arch::Bpf { .. } => {
            ud_analysis::bpf_relocs::build_call_site_names(elf).map_err(Error::BpfReloc)?
        }
        _ => HashMap::new(),
    };

    let mut items = Vec::new();

    // Top-level notes for functions we know about but can't body.
    for f in map.iter() {
        if f.size == 0 {
            items.push(Item::Comment(format!(
                "note: `{}` at 0x{:x} has no known size; not bodied",
                f.name, f.addr.0
            )));
        } else if !function_lives_in_a_section(elf, f.addr.0, f.size) {
            items.push(Item::Comment(format!(
                "note: `{}` at 0x{:x} not in any on-disk section; not bodied",
                f.name, f.addr.0
            )));
        }
    }

    // One @section block per ELF section worth emitting.
    for (idx, sh, data) in elf.sections() {
        if !section_is_emittable(sh) {
            continue;
        }
        let name = elf
            .section_name(idx)
            .map_or_else(|| format!("section{idx}"), str::to_string);
        let mut section_items = build_section_items(
            elf,
            sh,
            data,
            &map,
            &debug_by_addr,
            &name_at,
            &call_site_names,
            arch,
        )?;
        drop_redundant_function_addrs(sh.sh_addr, &mut section_items);
        items.push(Item::Section {
            name,
            addr: sh.sh_addr,
            items: section_items,
        });
    }

    // After every section is built, harvest the jump-table
    // metadata from `Stmt::Switch` instances and replace the
    // corresponding `@raw` byte run in `.rodata` (or any other
    // section that holds the table) with an `@jump_table`
    // directive. This is the symbolic form — editing a case
    // target re-encodes the table at lower time.
    let tables = collect_switch_tables(&items);
    replace_raw_with_jump_tables(&mut items, &tables);

    // Drop the byte list from every `@asm("text", [bytes])`
    // statement whose text re-assembles to those exact bytes —
    // we can regenerate them at lower time from the text alone.
    // This shrinks the .ud source toward "minimal bytes": only
    // forms the assembler doesn't yet cover keep their pinned
    // bytes.
    let bitness = if let Arch::X86 { bitness } = arch {
        Some(bitness)
    } else {
        None
    };
    if let Some(bitness) = bitness {
        drop_regenerable_asm_bytes(&mut items, bitness);
    }
    if matches!(arch, Arch::Bpf { .. }) {
        // Build an ad-hoc codec for the byte-drop pass —
        // mirrors what the compile-side does via
        // `compile::module::resolve_arch_codec`, but the
        // decompile pipeline doesn't yet have a parsed
        // `@module` to resolve through the registry. We
        // already classified the arch from `e_machine` above,
        // so construct the codec directly.
        let Arch::Bpf { variant } = arch else {
            unreachable!();
        };
        let codec = ud_arch_bpf::BpfCodec(variant);
        drop_regenerable_bytes(&mut items, &codec);
    }

    Ok(UdFile { module, items })
}

/// Generic byte-drop pass driven by an [`ud_arch_codec::ArchCodec`].
///
/// Walks every `Stmt::Asm` / `Stmt::IfBlock` / `Stmt::WhileBlock`
/// recursively, asks the codec to re-encode each one's
/// canonical text form, and clears the pinned bytes when the
/// codec reproduces them exactly. The byte-identity guard means
/// "drop only when the lower-time default reproduces these
/// bytes" — the same regen happens on both sides, so a passing
/// drop on this side guarantees round-trip.
///
/// Originally BPF-specific; the trait abstraction lets the same
/// loop service any fixed-width arch whose codec implements
/// `assemble_one`, `desymbolize`, `encode_cond_jump`, and
/// `encode_jump`. Arches without those methods return
/// `Unsupported` and the loop is a no-op for them.
#[allow(clippy::too_many_lines, clippy::items_after_statements)]
fn drop_regenerable_bytes(items: &mut [Item], arch: &dyn ud_arch_codec::ArchCodec) {
    // Probe the arch's fixed instruction width via a
    // self-relative jump-size query. BPF returns 8;
    // fixed-width arches return their natural width.
    let slot_size = arch.encoded_jump_size(0, 0, ud_arch_codec::EncodeHints::default()) as u64;

    /// Walk a slice of statements, threading the cursor IP
    /// so each @asm's address is known.
    fn visit_stmts(
        stmts: &mut [ud_ast::Stmt],
        ip: &mut u64,
        arch: &dyn ud_arch_codec::ArchCodec,
        slot_size: u64,
    ) {
        for stmt in stmts.iter_mut() {
            match stmt {
                ud_ast::Stmt::Asm { text, bytes } => {
                    let here = *ip;
                    if bytes.is_empty() {
                        *ip = ip.saturating_add(slot_size);
                        continue;
                    }
                    // Try the pure form first; symbolic forms
                    // (BPF's `call sub_<hex>`, `jeq …,
                    // label_<hex>`) need desymbolize first.
                    let mut dropped = false;
                    if let Ok(encoded) = arch.assemble_one(text, here) {
                        if encoded == *bytes {
                            bytes.clear();
                            dropped = true;
                        }
                    }
                    if !dropped {
                        let desym = arch.desymbolize(text, here);
                        if desym != *text {
                            if let Ok(encoded) = arch.assemble_one(&desym, here) {
                                if encoded == *bytes {
                                    bytes.clear();
                                }
                            }
                        }
                    }
                    *ip = ip.saturating_add(slot_size);
                }
                ud_ast::Stmt::IfBlock {
                    cond_text,
                    cond_bytes,
                    then_body,
                    then_tail_jmp,
                    else_body,
                } => {
                    // Cond_bytes: jcc skipping the then-body
                    // (and the tail ja) when cond_text is
                    // false. Target = past then_body + tail.
                    if !cond_bytes.is_empty() {
                        let cond_ip = *ip;
                        let then_body_size = build_function::lowered_body_size_at(
                            then_body,
                            cond_ip.saturating_add(cond_bytes.len() as u64),
                        );
                        let target = cond_ip
                            .saturating_add(slot_size)
                            .saturating_add(then_body_size)
                            .saturating_add(then_tail_jmp.len() as u64);
                        if let Ok(encoded) = arch.encode_cond_jump(
                            cond_text,
                            cond_ip,
                            target,
                            ud_arch_codec::EncodeHints::default(),
                        ) {
                            if encoded == *cond_bytes {
                                cond_bytes.clear();
                            }
                        }
                    }
                    *ip = ip.saturating_add(slot_size);
                    visit_stmts(then_body, ip, arch, slot_size);
                    // then_tail_jmp: unconditional `ja` over
                    // the else body.
                    if !then_tail_jmp.is_empty() {
                        let ttj_ip = *ip;
                        let else_size = build_function::lowered_body_size_at(
                            else_body,
                            ttj_ip.saturating_add(slot_size),
                        );
                        let target = ttj_ip.saturating_add(slot_size).saturating_add(else_size);
                        if let Ok(encoded) =
                            arch.encode_jump(ttj_ip, target, ud_arch_codec::EncodeHints::default())
                        {
                            if encoded == *then_tail_jmp {
                                then_tail_jmp.clear();
                            }
                        }
                        *ip = ip.saturating_add(slot_size);
                    }
                    visit_stmts(else_body, ip, arch, slot_size);
                }
                ud_ast::Stmt::WhileBlock {
                    cond_text,
                    entry_bytes,
                    body: wb,
                    tail_bytes,
                } => {
                    let entry_ip = *ip;
                    if !entry_bytes.is_empty() {
                        let body_size = build_function::lowered_body_size_at(
                            wb,
                            entry_ip.saturating_add(entry_bytes.len() as u64),
                        );
                        let target = entry_ip
                            .saturating_add(slot_size)
                            .saturating_add(body_size)
                            .saturating_add(tail_bytes.len() as u64);
                        if let Ok(encoded) = arch.encode_cond_jump(
                            cond_text,
                            entry_ip,
                            target,
                            ud_arch_codec::EncodeHints::default(),
                        ) {
                            if encoded == *entry_bytes {
                                entry_bytes.clear();
                            }
                        }
                    }
                    *ip = ip.saturating_add(slot_size);
                    visit_stmts(wb, ip, arch, slot_size);
                    if !tail_bytes.is_empty() {
                        let ja_ip = *ip;
                        // Back-edge: jump to entry_ip.
                        if let Ok(encoded) =
                            arch.encode_jump(ja_ip, entry_ip, ud_arch_codec::EncodeHints::default())
                        {
                            if encoded == *tail_bytes {
                                tail_bytes.clear();
                            }
                        }
                        *ip = ip.saturating_add(slot_size);
                    }
                }
                ud_ast::Stmt::IfBranch {
                    pre_body,
                    cond_bytes,
                    then_body,
                    else_body,
                    ..
                } => {
                    visit_stmts(pre_body, ip, arch, slot_size);
                    *ip = ip.saturating_add(cond_bytes.len() as u64);
                    visit_stmts(then_body, ip, arch, slot_size);
                    if let Some(eb) = else_body {
                        visit_stmts(eb, ip, arch, slot_size);
                    }
                }
                _ => {}
            }
        }
    }

    /// Recover the function's IP-space starting address.
    /// Order of preference:
    /// 1. `fd.addr` if set (`@addr(0x…)` survived the
    ///    `drop_redundant_function_addrs` pass).
    /// 2. Hex suffix of the name: `sub_<hex>` maps to the
    ///    address directly (this is the convention the
    ///    decompiler uses when no real symbol exists).
    /// 3. Zero — give up; the byte-drop won't fire for
    ///    address-dependent symbolic forms in this function.
    fn fn_base_addr(fd: &ud_ast::FnDecl) -> u64 {
        if let Some(a) = fd.addr {
            return a;
        }
        if let Some(rest) = fd.name.strip_prefix("sub_") {
            if let Ok(a) = u64::from_str_radix(rest, 16) {
                return a;
            }
        }
        0
    }

    /// Walk a section's items in order, threading a
    /// cursor through them so functions whose `@addr` was
    /// dropped (because their address equals the running
    /// cursor) still get their base IP recovered. Mirrors
    /// `drop_redundant_function_addrs` plus
    /// `build_function::lowered_body_size_at` — and
    /// matches exactly what the lower path does at
    /// recompile time.
    fn visit_section_items(
        section_addr: u64,
        items: &mut [Item],
        arch: &dyn ud_arch_codec::ArchCodec,
        slot_size: u64,
    ) {
        let mut cursor = section_addr;
        for item in items.iter_mut() {
            match item {
                Item::Function(fd) => {
                    let start = if let Some(a) = fd.addr {
                        a
                    } else if let Some(rest) = fd.name.strip_prefix("sub_") {
                        u64::from_str_radix(rest, 16).unwrap_or(cursor)
                    } else {
                        cursor
                    };
                    // CRITICAL: compute body_size BEFORE
                    // visit_stmts runs — visit_stmts drops
                    // bytes from @asm lines, which causes
                    // `lowered_body_size_at` to report 0
                    // for those (it sums `bytes.len()`).
                    let body_size = build_function::lowered_body_size_at(&fd.body, start);
                    let mut ip = start;
                    visit_stmts(&mut fd.body, &mut ip, arch, slot_size);
                    cursor = start.saturating_add(body_size);
                }
                Item::Raw { addr, bytes } => {
                    cursor = (*addr).saturating_add(bytes.len() as u64);
                }
                Item::Section { addr, items, .. } => {
                    visit_section_items(*addr, items, arch, slot_size);
                }
                _ => {}
            }
        }
    }

    for item in items.iter_mut() {
        match item {
            Item::Section { addr, items, .. } => {
                visit_section_items(*addr, items, arch, slot_size);
            }
            Item::Function(fd) => {
                let mut ip = fn_base_addr(fd);
                visit_stmts(&mut fd.body, &mut ip, arch, slot_size);
            }
            _ => {}
        }
    }
}

/// Walk every `Stmt::Asm` in the AST. For each, try to encode
/// `text` via the in-crate x86 assembler at the statement's
/// actual IP; if it succeeds and the encoded bytes equal the
/// pinned `bytes`, clear the byte list — lower will re-assemble
/// at the same IP and reproduce the same bytes.
///
/// The IP threading matters for RIP-relative encodings
/// (`jmp/call/push qword ptr [abs]` in 64-bit mode): the
/// emitted bytes carry `disp32 = target − (rip + insn_size)`,
/// so assembling at IP 0 would produce a different disp than
/// the original bytes at the real IP. Threading the cursor
/// through gives us both the regen path and the drop test
/// against the same fixed reference point.
#[allow(clippy::too_many_lines)]
fn drop_regenerable_asm_bytes(items: &mut [Item], bitness: ud_arch_x86::Bitness) {
    /// Return the encoded byte size of `stmt` so the cursor can
    /// step past it. For `Stmt::Asm`, the pinned bytes' length
    /// is the source of truth; for re-encoded forms the size is
    /// what our assembler would emit.
    fn asm_size(stmt: &ud_ast::Stmt, bitness: ud_arch_x86::Bitness, ip: u64) -> u64 {
        if let ud_ast::Stmt::Asm { text, bytes } = stmt {
            if !bytes.is_empty() {
                return bytes.len() as u64;
            }
            if let Ok(encoded) = ud_arch_x86::assemble_intel(bitness, text, ip) {
                return encoded.len() as u64;
            }
        }
        0
    }

    fn visit_stmts(stmts: &mut [ud_ast::Stmt], bitness: ud_arch_x86::Bitness, ip: &mut u64) {
        for stmt in stmts.iter_mut() {
            let here = *ip;
            match stmt {
                ud_ast::Stmt::Asm { text, bytes } => {
                    if bytes.is_empty() {
                        *ip = ip.saturating_add(asm_size(stmt, bitness, here));
                        continue;
                    }
                    if let Ok(encoded) = ud_arch_x86::assemble_intel(bitness, text, here) {
                        if encoded == *bytes {
                            bytes.clear();
                        }
                    }
                    *ip = ip.saturating_add(asm_size(stmt, bitness, here));
                }
                ud_ast::Stmt::IfBranch {
                    pre_body,
                    cond_bytes,
                    then_body,
                    else_body,
                    ..
                } => {
                    visit_stmts(pre_body, bitness, ip);
                    *ip = ip.saturating_add(cond_bytes.len() as u64);
                    visit_stmts(then_body, bitness, ip);
                    if let Some(eb) = else_body {
                        visit_stmts(eb, bitness, ip);
                    }
                }
                ud_ast::Stmt::Loop {
                    entry_jmp_bytes,
                    body,
                    tail_bytes,
                    ..
                } => {
                    if let Some(jmp) = entry_jmp_bytes {
                        *ip = ip.saturating_add(jmp.len() as u64);
                    }
                    visit_stmts(body, bitness, ip);
                    *ip = ip.saturating_add(tail_bytes.len() as u64);
                }
                other => {
                    // Conservative fallback: bump the cursor by
                    // any byte-bearing sub-field we know about.
                    // Inaccurate for some statement kinds but
                    // sufficient since RIP-relative forms only
                    // appear in `Stmt::Asm` today.
                    *ip = ip.saturating_add(stmt_min_size(other));
                }
            }
        }
    }

    fn auto_prologue_size(f: &ud_ast::FnDecl) -> u64 {
        let has_flag = f.attrs.iter().any(|a| {
            (a.key == "autogen_pro" || a.key == "autogen_pro_legacy")
                && matches!(a.value, ud_ast::AttrValue::Flag)
        });
        if !has_flag {
            return 0;
        }
        let profile = build_function::profile_inputs_from_fn(f);
        let cb = if profile.bits == 64 {
            ud_arch_x86::CodecBits::Bits64
        } else {
            ud_arch_x86::CodecBits::Bits32
        };
        let pro = ud_arch_x86::default_prologue(&profile);
        ud_arch_x86::encode_prologue(&pro, cb).len() as u64
    }

    fn auto_epilogue_size(f: &ud_ast::FnDecl) -> u64 {
        let has_flag = f.attrs.iter().any(|a| {
            (a.key == "autogen_pro" || a.key == "autogen_pro_legacy")
                && matches!(a.value, ud_ast::AttrValue::Flag)
        });
        if !has_flag {
            return 0;
        }
        let profile = build_function::profile_inputs_from_fn(f);
        let cb = if profile.bits == 64 {
            ud_arch_x86::CodecBits::Bits64
        } else {
            ud_arch_x86::CodecBits::Bits32
        };
        let epi = ud_arch_x86::default_epilogue(&profile);
        ud_arch_x86::encode_epilogue(&epi, cb).len() as u64
    }

    #[allow(clippy::enum_glob_use)]
    fn stmt_min_size(stmt: &ud_ast::Stmt) -> u64 {
        use ud_ast::Stmt::*;
        match stmt {
            Asm { bytes, .. }
            | Return { bytes, .. }
            | Prologue { bytes, .. }
            | Epilogue { bytes, .. }
            | Save { bytes, .. }
            | Restore { bytes, .. }
            | ReturnExpr { bytes, .. }
            | ArgSpill { bytes, .. }
            | LocalSet { bytes, .. }
            | LocalArith { bytes, .. }
            | LocalCompound { bytes, .. }
            | Move { bytes, .. }
            | Inc16 { bytes, .. }
            | SehInstall { bytes }
            | SehRestore { bytes } => bytes.len() as u64,
            Call {
                bytes,
                direct_target,
                ..
            } => bytes.len() as u64 + if direct_target.is_some() { 5 } else { 0 },
            Goto { wide, .. } => {
                if *wide {
                    5
                } else {
                    2
                }
            }
            IfGoto {
                cmp_bytes, wide, ..
            }
            | IfReturn {
                cmp_bytes, wide, ..
            } => cmp_bytes.len() as u64 + if *wide { 6 } else { 2 },
            _ => 0,
        }
    }

    fn visit_items(items: &mut [Item], bitness: ud_arch_x86::Bitness, section_cursor: u64) {
        let mut cursor = section_cursor;
        for item in items.iter_mut() {
            match item {
                Item::Function(f) => {
                    let fn_ip = f.addr.unwrap_or(cursor);
                    let mut ip = fn_ip;
                    // Account for the auto-generated prologue
                    // bytes the lower path will emit when
                    // `@autogen_pro` (or its legacy alias) is
                    // set — the first body statement's IP sits
                    // past those bytes.
                    ip = ip.saturating_add(auto_prologue_size(f));
                    visit_stmts(&mut f.body, bitness, &mut ip);
                    // The trailing autogen epilogue, when set,
                    // also lives in the function's bytes but
                    // emits after the body — for cursor
                    // tracking past the function, add it.
                    ip = ip.saturating_add(auto_epilogue_size(f));
                    cursor = ip;
                }
                Item::Section {
                    addr,
                    items: nested,
                    ..
                } => visit_items(nested, bitness, *addr),
                Item::Raw { addr, bytes } => {
                    cursor = (*addr).saturating_add(bytes.len() as u64);
                }
                Item::Strings { addr, strings } => {
                    cursor =
                        (*addr).saturating_add(strings.iter().map(|s| (s.len() + 1) as u64).sum());
                }
                Item::Notes { addr, .. } => {
                    cursor = *addr;
                }
                Item::JumpTable { addr, entries, .. } => {
                    cursor = (*addr).saturating_add((entries.len() as u64) * 4);
                }
                Item::Comment(_) => {}
            }
        }
    }
    visit_items(items, bitness, 0);
}

/// One switch-dispatch table harvested from a `Stmt::Switch`.
#[derive(Debug, Clone)]
struct SwitchTable {
    table_va: u64,
    dispatch: String,
    /// Case targets in source order — entry `[i]` is the address
    /// that case `i` dispatches to.
    cases: Vec<u64>,
}

fn collect_switch_tables(items: &[Item]) -> Vec<SwitchTable> {
    fn walk(items: &[Item], out: &mut Vec<SwitchTable>) {
        for item in items {
            match item {
                Item::Function(f) => collect_in_stmts(&f.body, out),
                Item::Section { items: nested, .. } => walk(nested, out),
                _ => {}
            }
        }
    }
    fn collect_in_stmts(stmts: &[ud_ast::Stmt], out: &mut Vec<SwitchTable>) {
        for s in stmts {
            match s {
                ud_ast::Stmt::Switch {
                    cases,
                    dispatch,
                    table_va,
                    ..
                } if *table_va != 0 && !cases.is_empty() => {
                    out.push(SwitchTable {
                        table_va: *table_va,
                        dispatch: dispatch.clone(),
                        cases: cases.clone(),
                    });
                }
                ud_ast::Stmt::IfBranch {
                    pre_body,
                    then_body,
                    else_body,
                    ..
                } => {
                    collect_in_stmts(pre_body, out);
                    collect_in_stmts(then_body, out);
                    if let Some(eb) = else_body {
                        collect_in_stmts(eb, out);
                    }
                }
                ud_ast::Stmt::Loop { body, .. } => collect_in_stmts(body, out),
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    walk(items, &mut out);
    out
}

/// Walk the section tree and, for every `@raw` block that fully
/// contains a known switch table's bytes, split it into:
///
/// ```text
/// @raw(<addr>, [prefix])
/// @jump_table(<table_va>, dispatch="…") { case_<i>: label_<target>; … }
/// @raw(<table_end>, [suffix])
/// ```
///
/// Zero-length prefix / suffix slices are omitted. Today the
/// known dispatch encodings (`gcc_pie_rel32`, `msvc_va32`) both
/// use 4-byte entries, so each table covers `4 * cases.len()`
/// bytes starting at `table_va`. Unknown dispatch kinds are
/// skipped (no replacement, no error).
fn replace_raw_with_jump_tables(items: &mut [Item], tables: &[SwitchTable]) {
    fn entry_size(dispatch: &str) -> Option<u64> {
        match dispatch {
            "gcc_pie_rel32" | "msvc_va32" => Some(4),
            _ => None,
        }
    }
    fn rewrite_section(section_items: &mut Vec<Item>, tables: &[SwitchTable]) {
        let mut i = 0;
        while i < section_items.len() {
            // Try each table; the first that fits splits this raw
            // block.
            let mut replacement: Option<(usize, Vec<Item>)> = None;
            if let Item::Raw { addr, bytes } = &section_items[i] {
                for t in tables {
                    let Some(esz) = entry_size(&t.dispatch) else {
                        continue;
                    };
                    let table_size = esz * (t.cases.len() as u64);
                    let raw_start = *addr;
                    let raw_end = raw_start.saturating_add(bytes.len() as u64);
                    let table_end = t.table_va.saturating_add(table_size);
                    if t.table_va < raw_start || table_end > raw_end {
                        continue;
                    }
                    // Slice the raw into prefix / table / suffix.
                    let prefix_len = (t.table_va - raw_start) as usize;
                    let table_len = table_size as usize;
                    let suffix_start = prefix_len + table_len;
                    let mut new_items: Vec<Item> = Vec::new();
                    if prefix_len > 0 {
                        new_items.push(Item::Raw {
                            addr: raw_start,
                            bytes: bytes[..prefix_len].to_vec(),
                        });
                    }
                    let entries = t
                        .cases
                        .iter()
                        .enumerate()
                        .map(|(idx, target)| ud_ast::JumpTableEntry {
                            case: idx as u64,
                            target: *target,
                        })
                        .collect();
                    new_items.push(Item::JumpTable {
                        addr: t.table_va,
                        dispatch: t.dispatch.clone(),
                        entries,
                    });
                    if suffix_start < bytes.len() {
                        new_items.push(Item::Raw {
                            addr: table_end,
                            bytes: bytes[suffix_start..].to_vec(),
                        });
                    }
                    replacement = Some((1, new_items));
                    break;
                }
            }
            if let Some((remove, mut new_items)) = replacement {
                section_items.remove(i);
                let added = new_items.len();
                for (off, it) in new_items.drain(..).enumerate() {
                    section_items.insert(i + off, it);
                }
                let _ = remove; // we always remove exactly one item
                i += added;
            } else {
                i += 1;
            }
        }
    }
    for item in items.iter_mut() {
        if let Item::Section { items: nested, .. } = item {
            rewrite_section(nested, tables);
        }
    }
}

/// Walk a section's items in declaration order and drop
/// `@addr(…)` from every `Function` whose address is exactly the
/// cumulative cursor — i.e., the function would fall in at the
/// expected position anyway. This removes noise from the
/// decompiled source: the addr-pinned shape is reserved for
/// items that diverge from the running cursor (functions
/// preceded by a deliberate alignment gap, or hand-edited
/// placements). On lower, items without an explicit addr take
/// the cumulative cursor automatically.
///
/// `Raw`, `Strings`, and `Notes` items keep their `addr` — those
/// are required by the AST today, and they're typically pinned
/// at section-relative offsets that matter for the binary's
/// data layout. We advance the cursor past them by recomputing
/// the on-disk byte size locally so subsequent function-addr
/// comparisons land at the right position.
fn drop_redundant_function_addrs(section_addr: u64, items: &mut [Item]) {
    let mut cursor = section_addr;
    for item in items.iter_mut() {
        match item {
            Item::Function(f) => {
                let body_size = build_function::lowered_body_size_at(&f.body, cursor);
                if f.addr == Some(cursor) {
                    f.addr = None;
                }
                cursor = cursor.saturating_add(body_size);
            }
            Item::Raw { addr, bytes } => {
                cursor = (*addr).saturating_add(bytes.len() as u64);
            }
            Item::Strings { addr, strings } => {
                cursor = (*addr).saturating_add(strings_byte_size(strings));
            }
            Item::Notes { addr, entries } => {
                cursor = (*addr).saturating_add(notes_byte_size(entries));
            }
            Item::JumpTable { addr, entries, .. } => {
                // Every supported dispatch encoding uses 4-byte
                // entries; case_count * 4 is the on-disk size.
                cursor = (*addr).saturating_add((entries.len() as u64) * 4);
            }
            Item::Comment(_) | Item::Section { .. } => {}
        }
    }
}

fn strings_byte_size(strings: &[String]) -> u64 {
    strings.iter().map(|s| (s.len() + 1) as u64).sum()
}

fn notes_byte_size(entries: &[ud_ast::NoteEntry]) -> u64 {
    let mut size: u64 = 0;
    for e in entries {
        size += 12; // Nhdr: name_size + desc_size + type
        let name_padded = ((e.name.len() + 1) + 3) & !3; // null-terminated, 4-aligned
        size += name_padded as u64;
        let desc_padded = (e.desc.len() + 3) & !3;
        size += desc_padded as u64;
    }
    size
}

/// Convenience: build the AST and pretty-print it to canonical text.
pub fn decompile_to_text(elf: &Elf64File) -> Result<String> {
    let ast = decompile(elf)?;
    Ok(ud_ast::emit(&ast))
}

/// Whether a section will be emitted as `@section`. Skips sections
/// without on-disk content (NULL, NOBITS, zero-size). Sections with
/// `sh_addr == 0` (debug info, `.comment`, `.symtab`, …) ARE emitted —
/// their items are addressed in [0, sh_size) since virtual addresses
/// don't apply, and the lower path matches them to shdrs by name.
fn section_is_emittable(sh: &Shdr64) -> bool {
    const SHT_NULL: u32 = 0;
    const SHT_NOBITS: u32 = 8;
    sh.sh_type != SHT_NULL && sh.sh_type != SHT_NOBITS && sh.sh_size > 0
}

fn function_lives_in_a_section(elf: &Elf64File, addr: u64, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let end = addr.saturating_add(size);
    for (_, sh, _) in elf.sections() {
        let sh_end = sh.sh_addr.saturating_add(sh.sh_size);
        if sh.sh_addr <= addr && end <= sh_end {
            return true;
        }
    }
    false
}

/// Decode an ELF `SHT_STRTAB` section as a list of null-terminated
/// strings. Returns `None` when any string contains non-UTF-8 bytes
/// or the section doesn't end on a terminator — in that case the
/// caller falls back to the opaque `@raw` form.
fn decode_strtab(data: &[u8]) -> Option<Vec<String>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    if *data.last().unwrap() != 0 {
        return None;
    }
    let mut out = Vec::new();
    for chunk in data.split(|&b| b == 0) {
        if chunk.is_empty() {
            out.push(String::new());
        } else {
            out.push(std::str::from_utf8(chunk).ok()?.to_string());
        }
    }
    // `split` on a trailing 0 produces a final empty chunk that
    // isn't a real entry — drop it so the encode round-trips.
    if out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    Some(out)
}

/// Decode an ELF `SHT_NOTE` section into a flat list of notes.
/// Returns `None` on any structural mismatch (truncated header,
/// non-UTF-8 name, padding that doesn't round-trip cleanly).
fn decode_notes(data: &[u8]) -> Option<Vec<ud_ast::NoteEntry>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if i + 12 > data.len() {
            return None;
        }
        let name_size = u32::from_le_bytes(data[i..i + 4].try_into().ok()?) as usize;
        let desc_size = u32::from_le_bytes(data[i + 4..i + 8].try_into().ok()?) as usize;
        let note_type = u32::from_le_bytes(data[i + 8..i + 12].try_into().ok()?);
        i += 12;
        if name_size == 0 || i + name_size > data.len() {
            return None;
        }
        // name_size includes the trailing NUL.
        let name_bytes = &data[i..i + name_size - 1];
        if data[i + name_size - 1] != 0 {
            return None;
        }
        let name = std::str::from_utf8(name_bytes).ok()?.to_string();
        i += name_size;
        // Pad to 4-byte boundary.
        while i % 4 != 0 {
            if i >= data.len() || data[i] != 0 {
                return None;
            }
            i += 1;
        }
        if i + desc_size > data.len() {
            return None;
        }
        let desc = data[i..i + desc_size].to_vec();
        i += desc_size;
        while i % 4 != 0 {
            if i >= data.len() || data[i] != 0 {
                return None;
            }
            i += 1;
        }
        out.push(ud_ast::NoteEntry {
            note_type,
            name,
            desc,
        });
    }
    Some(out)
}

/// Build the items inside one `@section` block: any functions whose
/// address range falls inside the section, plus `@raw` blocks for
/// every byte not covered by a function.
#[allow(clippy::too_many_arguments)]
fn build_section_items(
    elf: &Elf64File,
    sh: &Shdr64,
    data: &[u8],
    map: &FunctionMap,
    debug_by_addr: &HashMap<u64, DebugFunction>,
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
    arch: Arch,
) -> Result<Vec<Item>> {
    // Structured-form sections short-circuit before the
    // function-coverage walk: ELF string tables and note sections
    // have a well-defined byte layout we can faithfully decode and
    // re-emit. When the structured decode covers the whole section
    // cleanly, prefer it over `@raw`. Round-trip safety comes from
    // the lower-side encoder producing the same bytes.
    const SHT_STRTAB: u32 = 3;
    const SHT_NOTE: u32 = 7;
    let section_name = elf
        .shdrs
        .iter()
        .position(|sh2| std::ptr::eq(sh2, sh))
        .and_then(|idx| elf.section_name(idx))
        .unwrap_or("");
    // `.interp` is `SHT_PROGBITS` by sh_type but always contains a
    // single null-terminated path to the dynamic linker. Decoding it
    // as a one-entry `@strings` matches the lower-side encoder.
    let is_interp = section_name == ".interp";
    if sh.sh_type == SHT_STRTAB || is_interp {
        if let Some(strings) = decode_strtab(data) {
            return Ok(vec![Item::Strings {
                addr: sh.sh_addr,
                strings,
            }]);
        }
    }
    if sh.sh_type == SHT_NOTE {
        if let Some(entries) = decode_notes(data) {
            return Ok(vec![Item::Notes {
                addr: sh.sh_addr,
                entries,
            }]);
        }
    }

    let section_start = sh.sh_addr;
    let section_end = sh.sh_addr.saturating_add(sh.sh_size);

    // Functions whose entire range falls inside this section.
    // For relocatable object files (`.o`) multiple sections
    // share `sh_addr = 0`, so an address-range match alone
    // would pull `.text` functions into `.symtab` / `.strtab`
    // too. Filter on `SHF_EXECINSTR` first: data sections
    // never contain functions regardless of how their address
    // range overlaps.
    let is_exec = sh.sh_flags & SHF_EXECINSTR != 0;
    let mut funcs: Vec<_> = if is_exec {
        map.iter()
            .filter(|f| {
                f.size > 0
                    && f.addr.0 >= section_start
                    && f.addr.0.saturating_add(f.size) <= section_end
            })
            .collect()
    } else {
        Vec::new()
    };
    funcs.sort_by_key(|f| f.addr.0);

    let mut out = Vec::new();
    let mut cursor = section_start;

    for f in &funcs {
        // Gap before this function — usually padding bytes, but
        // for stripped BPF binaries (Solana programs without a
        // `.symtab`) the gap is the whole program. Lift it as
        // anonymous BPF code instead of `@raw` so the output is
        // actually readable.
        if cursor < f.addr.0 {
            let lo = (cursor - section_start) as usize;
            let hi = (f.addr.0 - section_start) as usize;
            emit_gap(
                &mut out,
                arch,
                is_exec,
                cursor,
                &data[lo..hi],
                name_at,
                call_site_names,
                elf,
            )?;
        }
        // The function itself.
        let lo = (f.addr.0 - section_start) as usize;
        let hi = lo + f.size as usize;
        let slice = &data[lo..hi];
        let fn_decl = match arch {
            Arch::X86 { bitness } => {
                let insns = decode(bitness, slice, f.addr.0)?;
                let lifted = lift_function(f.name.clone(), &insns)?;
                let debug = debug_by_addr.get(&f.addr.0);
                build_function::build_function(&lifted, debug, name_at, elf)
            }
            Arch::Aarch64 => {
                let insns =
                    ud_arch_aarch64::decode(slice, f.addr.0).map_err(Error::Aarch64Decode)?;
                let lifted = ud_arch_aarch64::lift_function(f.name.clone(), &insns);
                aarch64::build_function(&lifted, name_at)
            }
            Arch::Bpf { variant } => {
                let insns =
                    ud_arch_bpf::decode(slice, f.addr.0, variant).map_err(Error::BpfDecode)?;
                let lifted = ud_arch_bpf::lift_function(f.name.clone(), &insns);
                bpf::build_function(&lifted, name_at, call_site_names, variant, Some(elf))
            }
        };
        out.push(Item::Function(fn_decl));
        cursor = f.addr.0.saturating_add(f.size);
    }

    // Trailing gap to the section's end.
    if cursor < section_end {
        let lo = (cursor - section_start) as usize;
        emit_gap(
            &mut out,
            arch,
            is_exec,
            cursor,
            &data[lo..],
            name_at,
            call_site_names,
            elf,
        )?;
    }

    Ok(out)
}

/// Emit a section gap. For non-executable sections or non-BPF
/// arches, the gap is preserved as `@raw` bytes (the historical
/// behaviour). For executable BPF sections, the gap is lifted
/// as anonymous BPF code under a synthetic `fragment_<addr>`
/// function so stripped Solana programs surface as readable
/// instructions instead of one giant byte blob.
///
/// BPF is the only arch we lift gaps for because BPF `.text`
/// is guaranteed to contain instruction-aligned 8-byte slots
/// only. x86 `.text` may mix jump-table data with code, so
/// blanket-decoding a gap there can produce nonsense; aarch64
/// is the same concern at a smaller scale. The fix slot in
/// `discover_functions` for x86 / aarch64 is call-site /
/// landing-pad-style function discovery, which is its own
/// project.
#[allow(clippy::too_many_arguments)]
fn emit_gap(
    out: &mut Vec<Item>,
    arch: Arch,
    is_exec: bool,
    addr: u64,
    bytes: &[u8],
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
    elf: &Elf64File,
) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    if is_exec {
        if let Arch::Bpf { variant } = arch {
            // BPF slots are 8 bytes. If the gap doesn't align
            // to that, the leading misaligned bytes ride out as
            // `@raw` and the rest gets lifted. This usually
            // means the section has padding ahead of the first
            // instruction; rare on Solana programs but cheap
            // to defend against.
            let prefix_len = bytes.len() % ud_arch_bpf::INSN_SIZE;
            let (prefix, code) = bytes.split_at(prefix_len);
            if !prefix.is_empty() {
                out.push(Item::Raw {
                    addr,
                    bytes: prefix.to_vec(),
                });
            }
            let code_addr = addr + prefix_len as u64;
            if !code.is_empty() {
                let insns =
                    ud_arch_bpf::decode(code, code_addr, variant).map_err(Error::BpfDecode)?;
                let lifted = ud_arch_bpf::lift_function(format!("fragment_{code_addr:x}"), &insns);
                out.push(Item::Function(bpf::build_function(
                    &lifted,
                    name_at,
                    call_site_names,
                    variant,
                    Some(elf),
                )));
            }
            return Ok(());
        }
    }
    out.push(Item::Raw {
        addr,
        bytes: bytes.to_vec(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_ast::{FnDecl, Stmt};

    #[test]
    fn replace_raw_with_jump_table_splits_around_table_va() {
        // Synthetic section: a function with a Stmt::Switch
        // pointing at a `@raw` data block. The replacement
        // should split the raw into prefix + jump_table + suffix.
        let switch_stmt = Stmt::Switch {
            selector: "ecx".into(),
            cases: vec![0x117a, 0x1183, 0x118c],
            default_addr: 0x1200,
            dispatch: "gcc_pie_rel32".into(),
            table_va: 0x2008,
        };
        // .rodata starts at 0x2000 with 8 bytes of prefix,
        // 12 bytes of jump table (3 entries × 4 bytes), 4 bytes
        // of suffix.
        let raw_bytes = vec![
            // prefix (0x2000..0x2008)
            0x01, 0x00, 0x02, 0x00, 0x53, 0x75, 0x6e,
            0x00, // table (0x2008..0x2014) — bytes don't matter, will be replaced
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // suffix (0x2014..0x2018)
            0xde, 0xad, 0xbe, 0xef,
        ];
        let mut items = vec![Item::Section {
            name: ".text".into(),
            addr: 0x1000,
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1000),
                name: "f".into(),
                attrs: Vec::new(),
                signature: None,
                locals: Vec::new(),
                body: vec![switch_stmt],
            })],
        }];
        items.push(Item::Section {
            name: ".rodata".into(),
            addr: 0x2000,
            items: vec![Item::Raw {
                addr: 0x2000,
                bytes: raw_bytes,
            }],
        });
        let tables = collect_switch_tables(&items);
        assert_eq!(tables.len(), 1);
        replace_raw_with_jump_tables(&mut items, &tables);

        let Item::Section {
            items: ro_items, ..
        } = &items[1]
        else {
            panic!("expected .rodata section");
        };
        // Expect: [Raw(prefix 0x2000..0x2008), JumpTable(0x2008), Raw(suffix 0x2014..)]
        assert_eq!(ro_items.len(), 3);
        match &ro_items[0] {
            Item::Raw { addr, bytes } => {
                assert_eq!(*addr, 0x2000);
                assert_eq!(bytes.len(), 8);
            }
            other => panic!("expected Raw prefix, got {other:?}"),
        }
        match &ro_items[1] {
            Item::JumpTable {
                addr,
                dispatch,
                entries,
            } => {
                assert_eq!(*addr, 0x2008);
                assert_eq!(dispatch, "gcc_pie_rel32");
                assert_eq!(entries.len(), 3);
                assert_eq!(entries[0].target, 0x117a);
                assert_eq!(entries[2].target, 0x118c);
            }
            other => panic!("expected JumpTable, got {other:?}"),
        }
        match &ro_items[2] {
            Item::Raw { addr, bytes } => {
                assert_eq!(*addr, 0x2014);
                assert_eq!(bytes, &[0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("expected Raw suffix, got {other:?}"),
        }
    }

    #[test]
    fn replace_raw_with_jump_table_skips_unknown_dispatch() {
        let switch_stmt = Stmt::Switch {
            selector: "ecx".into(),
            cases: vec![0x100, 0x200],
            default_addr: 0x300,
            dispatch: "bogus-dispatch".into(),
            table_va: 0x2000,
        };
        let mut items = vec![
            Item::Section {
                name: ".text".into(),
                addr: 0x1000,
                items: vec![Item::Function(FnDecl {
                    addr: Some(0x1000),
                    name: "f".into(),
                    attrs: Vec::new(),
                    signature: None,
                    locals: Vec::new(),
                    body: vec![switch_stmt],
                })],
            },
            Item::Section {
                name: ".rodata".into(),
                addr: 0x2000,
                items: vec![Item::Raw {
                    addr: 0x2000,
                    bytes: vec![0u8; 8],
                }],
            },
        ];
        let tables = collect_switch_tables(&items);
        replace_raw_with_jump_tables(&mut items, &tables);
        // Unknown dispatch → no replacement → raw stays intact.
        let Item::Section {
            items: ro_items, ..
        } = &items[1]
        else {
            panic!()
        };
        assert!(matches!(&ro_items[0], Item::Raw { .. }));
    }
}

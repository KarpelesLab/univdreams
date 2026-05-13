//! Build the `FnDecl` AST node for a lifted function.

use std::collections::{HashMap, HashSet};

use ud_arch_x86::{
    arg_spill_index, detect_post_call_spill, direct_call_target, direct_lea_rip_target,
    direct_unconditional_branch_target, format_intel, identify_call_sites,
    try_lift_epilogue_pattern, try_lift_if_branch_head, try_lift_prologue_pattern,
    try_lift_return_pattern, try_lift_return_via_jmp, try_lift_value_block, ArgValue, CallSite,
    DecodedInsn, ExprRenderCtx, OpKind, Register,
};
use ud_ast::{FnDecl, LocalDecl, LocalKind, Signature, Stmt, Type};
use ud_debug::DebugFunction;
use ud_ir::{BasicBlock, Function, Terminator};

use crate::data_lookup::DataLookup;

/// Convert a lifted [`Function`] into the AST's [`FnDecl`].
///
/// Most blocks emit one [`Stmt::Asm`] per decoded instruction (Intel
/// syntax). When the function's CFG matches a recognised
/// `cmp/test + jcc + then-block + else-block` shape, those three
/// blocks are folded into a single [`Stmt::IfBranch`] with the
/// branches embedded as nested statements.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_function(
    f: &Function<DecodedInsn>,
    debug: Option<&DebugFunction>,
    name_at: &HashMap<u64, String>,
    data: &dyn DataLookup,
) -> FnDecl {
    let signature = debug.map(|d| Signature {
        params: d.params.clone(),
        return_type: d.return_type.clone(),
    });
    let slot_to_name = collect_slot_to_name(f, signature.as_ref());
    let lifts = compute_block_tail_lifts(f, signature.as_ref(), &slot_to_name, name_at);
    let groups = identify_if_else_groups(f);
    let loops = identify_loop_groups(f);

    // Build a per-IP SP-delta table once and share it with every
    // pattern via `EmitCtx` / `PatternCtx`. CFG-aware: the entry
    // delta of a jcc target comes from the predecessor's delta at
    // the jcc instruction, not from whatever block happened to
    // precede the target in source order.
    let sp_delta_at = compute_sp_delta_cfg(f);

    // Build SSA — the forwarding pass uses its per-IP write set
    // to invalidate only the registers each `@asm` instruction
    // actually wrote, instead of dropping the whole state on any
    // mnemonic we don't have a hand-written carve-out for.
    let ssa = crate::ssa::build_ssa(f, &sp_delta_at);
    let liveness = crate::ssa::compute_liveness(f, &sp_delta_at);
    let bitness = function_bitness(f);

    let mut body = Vec::new();
    let func_end = f.addr.0.saturating_add(f.size() as u64);
    let codec_bits = match bitness {
        ud_arch_x86::Bitness::Bits64 => ud_arch_x86::CodecBits::Bits64,
        _ => ud_arch_x86::CodecBits::Bits32,
    };
    let ctx = EmitCtx {
        fn_addr_start: f.addr.0,
        fn_addr_end: func_end,
        name_at,
        sp_delta_at: &sp_delta_at,
        signature: signature.as_ref(),
        data,
        codec_bits,
    };

    // Loops can fold the unconditional `jmp` from the block right
    // before the body into their `entry_jmp_bytes`. Track which
    // blocks need a trailing instruction truncated for that.
    let mut pre_jmp_truncate: HashMap<usize, usize> = HashMap::new();
    for lg in loops.iter().flatten() {
        if let Some(idx) = lg.pre_jmp_block_idx {
            pre_jmp_truncate.insert(idx, 1);
        }
    }

    emit_blocks_in_range(
        &mut body,
        f,
        0..f.blocks.len(),
        &loops,
        &groups,
        &lifts,
        &pre_jmp_truncate,
        &ctx,
        true,
    );

    // SSA-aware value forwarding: walks the body with a `RegState`
    // tracker, but uses SSA's per-IP write set to invalidate
    // exactly the registers each `@asm` line writes. Cleaner than
    // the old mnemonic-keyed heuristic — it answers correctly for
    // unrecognised instructions and stops over-invalidating across
    // every conditional branch.
    forward_propagate_registers(&mut body, &ssa, f.addr.0, bitness);

    // Algebraic simplification on every operand-text field.
    // Collapses the chains forward-propagation produces:
    // `((x - 1) - 1) - 1` → `x - 3`, `~(x | 0FFFFFFFFh)` → `0`,
    // `x ^ x` → `0`, etc. Iterates each expression to a fixpoint;
    // unparseable text is preserved verbatim.
    let bit_width = match bitness {
        ud_arch_x86::Bitness::Bits64 => crate::expr::BitWidth::Bits64,
        _ => crate::expr::BitWidth::Bits32,
    };
    simplify_body(&mut body, bit_width);

    // Resolve integer literals that point at strings in the data
    // sections. `1C24F920h` becomes `"Software\\Microsoft\\…"` —
    // the dereferenced content is what the reader cares about,
    // not the address. Idempotent: already-substituted strings
    // pass through.
    let string_lookup = |va: u64| -> Option<String> { lookup_string_at_va(data, va) };
    resolve_strings_in_body(&mut body, &string_lookup);

    // After forward-propagation, indirect calls routed through a
    // register (`mov ebx, [IAT_SLOT]; … ; call ebx`) have their
    // target name rewritten to `[IAT_SLOT]`. Resolve any such
    // `[ABSOLUTE_VA]` call targets back to import names from
    // `name_at` — the same map the call-site renderer consulted
    // pre-propagation for the memory-indirect form.
    resolve_indirect_call_names(&mut body, name_at);

    // Annotate every `@epilogue` / `@return` with a comment showing
    // the expression held in EAX/RAX at exit — the ABI's return
    // register. Lets the reader see what each exit path returns
    // without manually scanning back to find the last assignment.
    annotate_return_values(&mut body);

    // Replace LIFO-matched `@asm("push REG")` / `@asm("pop REG")`
    // pairs with `@save` / `@restore` directives. These are the
    // "lazy prologue" saves the compiler emits mid-function for
    // additional callee-saved registers the standard prologue
    // didn't reserve. Pinning the bytes on a directive instead of
    // an `@asm` line both visually de-noises the body and lets a
    // future reader pair the save with its restore at a glance.
    absorb_save_restore(&mut body);

    // Fold "compare/test then jcc-to-return-tail" patterns into
    // `@if_return` directives that render as `if (cond) return N;`.
    // The jcc bytes still appear at the early-exit position; the
    // actual return bytes remain at the original tail block. Only
    // the rendering changes — round-trip preserved.
    fold_early_returns(&mut body, f.addr.0, bitness);

    // Drop dead-register `Move` stmts: `eax = expr` whose dst
    // register is dead immediately afterwards (liveness says it's
    // not read before next overwrite). The bytes are not dropped
    // — they merge into the following stmt's `bytes` field so the
    // function's byte stream is unchanged. The visible source
    // shortens because the scratch-register-setup line goes away,
    // leaving the consumer (typically a call) to show the value
    // directly via forward-propagation's earlier substitution.
    fold_dead_register_moves(&mut body, &liveness, f.addr.0);

    // Detect MSVC SEH frame install/restore. `mov fs:[0], esp`
    // is the install (a new exception handler frame); the
    // matching `mov fs:[0], <var>` later is the restore.
    fold_seh_frame(&mut body);

    // Detect MSVC's switch-via-jump-table idiom: the
    // `cmp reg, MAX; ja default; jmp [TABLE + reg*4]` triple.
    // Reads `MAX+1` consecutive code-pointer entries from the
    // data section at TABLE, generates a `Stmt::Switch` with the
    // per-case target addresses. Bytes from both `@asm` lines
    // (the cmp+ja and the indirect jmp) are concatenated onto
    // the resulting Switch so round-trip is preserved.
    fold_switch_jump_tables(&mut body, f.addr.0, bitness, data);

    // Recognise common string-instruction idioms (`rep movs`,
    // `rep stos`, `repe cmps`, `repne scas`) and lift them to
    // synthetic calls — `memcpy(edi, esi, ecx)`, `memset(edi,
    // al, ecx)`, `memcmp(edi, esi, ecx)`, `strlen(edi)`. Bytes
    // stay pinned on the lifted stmt; only the rendering changes.
    recognise_string_idioms(&mut body);

    // Local structural lift: an `IfGoto(cond, L)` whose body
    // ends at a `Label(L)` in the same scope, with no other
    // gotos/labels in between, is the trivial "skip body when
    // cond" shape. Lift to `if (!cond) { body }` so the
    // structural form shows. Body bytes stay in place; only the
    // surrounding IfGoto becomes an IfBranch.
    fold_local_if_skip(&mut body, bitness);

    // Last-resort lift for the `@asm("jmp/jcc target")` lines
    // that earlier passes (if-else lifter, loop lifter, compound
    // conditions, early-return folding) didn't claim. Convert
    // them into `goto`/`if (cond) goto` plus `label_<hex>:` markers
    // so the remaining unstructured control flow reads as C-with-
    // labels rather than raw `@asm` jcc lines.
    fold_gotos_and_labels(&mut body, f.addr.0, bitness);

    let locals = discover_locals(f, &sp_delta_at);
    let mut attrs = detect_calling_convention_attrs(f, &ssa);
    // Drop the leading `@prologue` / trailing `@epilogue` when
    // their structured params match the auto-derived default for
    // this function's profile. Lower regenerates identical bytes
    // at emit time. When a function has neither prologue nor
    // epilogue and the default WOULD add one, mark it `naked` so
    // the parser/lower knows to skip auto-generation.
    let temp_decl = ud_ast::FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        attrs: attrs.clone(),
        signature: signature.clone(),
        locals: locals.clone(),
        body: body.clone(),
    };
    // Try two candidate profiles: with frame (MSVC /Oy-) and
    // without frame (omitted frame pointer). If the no-frame
    // variant matches, mark the fn with `#[noframe]` so the
    // parser regenerates the same prologue/epilogue.
    let base = profile_inputs_from_fn(&temp_decl);
    let mut profile_fp = base.clone();
    profile_fp.frame_required = true;
    let mut profile_nofp = base.clone();
    profile_nofp.frame_required = false;
    let try_match = |profile: &ud_arch_x86::ProfileInputs| -> (
        bool,
        bool,
        ud_arch_x86::StructuredPrologue,
        ud_arch_x86::StructuredEpilogue,
    ) {
        let dp = ud_arch_x86::default_prologue(profile);
        let de = ud_arch_x86::default_epilogue(profile);
        let pm = matches!(body.first(), Some(Stmt::Prologue { params: Some(p), .. })
            if p.saves == dp.saves
                && p.saves_after == dp.saves_after
                && p.frame == dp.frame
                && p.sub_esp == dp.sub_esp
                && p.cf_protect == dp.cf_protect);
        let em = matches!(body.last(), Some(Stmt::Epilogue { params: Some(e), .. })
            if e.saves == de.saves
                && e.leave == de.leave
                && e.pop_frame == de.pop_frame
                && e.add_esp == de.add_esp
                && e.ret_imm == de.ret_imm);
        (pm, em, dp, de)
    };
    let (pm_fp, em_fp, dp_fp, de_fp) = try_match(&profile_fp);
    let (pm_nofp, em_nofp, dp_nofp, de_nofp) = try_match(&profile_nofp);

    // Prefer the variant that matches BOTH ends; otherwise the
    // one that matches more sides; ties go to frame=true.
    let fp_score = u32::from(pm_fp) + u32::from(em_fp);
    let nofp_score = u32::from(pm_nofp) + u32::from(em_nofp);
    let use_nofp = nofp_score > fp_score;
    let (pro_matches, epi_matches, default_pro, default_epi) = if use_nofp {
        (pm_nofp, em_nofp, dp_nofp, de_nofp)
    } else {
        (pm_fp, em_fp, dp_fp, de_fp)
    };
    let mut dropped_any = false;
    // The default heuristic targets MSVC x86-32 prologue shapes
    // (callee-saved ebx/esi/edi, `push ebp; mov ebp, esp` frame
    // setup). For 64-bit functions the comparison is structurally
    // impossible — the registers don't match — so the comments it
    // would emit are misleading and the autogen marker would
    // round-trip wrong. Gate the whole block.
    let defaults_apply = !matches!(bitness, ud_arch_x86::Bitness::Bits64);
    if defaults_apply && pro_matches {
        body.remove(0);
        dropped_any = true;
    } else if let (
        true,
        Some(Stmt::Prologue {
            params: Some(p), ..
        }),
    ) = (defaults_apply, body.first())
    {
        // Non-matching prologue: prepend a brief comment showing
        // what the auto-derived default would have been, so a
        // reader can see at a glance why the explicit form is
        // needed. Comments lower to zero bytes; round-trip safe.
        //
        // Skip the comment when the actual params are just a
        // subset of the default's saves with everything else
        // equal — the prologue line itself shows the saves, so
        // the comment would just restate the default.
        let saves_is_subset = is_subset(&p.saves, &default_pro.saves)
            && is_subset(&p.saves_after, &default_pro.saves_after)
            && p.frame == default_pro.frame
            && p.sub_esp == default_pro.sub_esp
            && p.cf_protect == default_pro.cf_protect;
        if !saves_is_subset {
            if let Some(text) = describe_default_prologue(&default_pro) {
                body.insert(0, Stmt::Comment(format!("default: {text}")));
            }
        }
    }
    if defaults_apply && epi_matches {
        body.pop();
        dropped_any = true;
    } else if let (
        true,
        Some(Stmt::Epilogue {
            params: Some(e), ..
        }),
    ) = (defaults_apply, body.last())
    {
        let saves_is_subset = is_subset(&e.saves, &default_epi.saves)
            && e.leave == default_epi.leave
            && e.pop_frame == default_epi.pop_frame
            && e.add_esp == default_epi.add_esp
            && e.ret_imm == default_epi.ret_imm;
        if !saves_is_subset {
            if let Some(text) = describe_default_epilogue(&default_epi) {
                let last = body.len() - 1;
                body.insert(last, Stmt::Comment(format!("default: {text}")));
            }
        }
    }
    if dropped_any {
        // `#[autogen]` opts the function INTO lower-time defaults
        // regeneration. We add it only when we actually dropped a
        // matched prologue or epilogue, so functions that don't
        // round-trip through the codec (GCC, hand-written) stay
        // bare and lower emits their bytes verbatim.
        attrs.push(ud_ast::Attribute {
            key: "autogen".into(),
            value: ud_ast::AttrValue::Flag,
        });
    }
    if use_nofp && dropped_any {
        attrs.push(ud_ast::Attribute {
            key: "noframe".into(),
            value: ud_ast::AttrValue::Flag,
        });
    }

    // Thiscall / fastcall ECX rendering: when the calling
    // convention puts the `this` pointer in ECX, replace every
    // `ecx` reference with `this` in the rendered text and
    // every `[ecx+N]` access with `this->f_N`. The bytes still
    // execute the original code; only the operand text changes.
    let abi_is_thiscall = attrs.iter().any(|a| {
        a.key == "abi"
            && matches!(&a.value, ud_ast::AttrValue::String(s) if s == "thiscall" || s == "fastcall")
    });
    if abi_is_thiscall {
        rewrite_ecx_as_this(&mut body);
    }

    // Stack-slot rename: `[rbp-4]`, `dword ptr [rbp-4]`, `[ebp+8]`,
    // etc. in operand text → matching `var_N` / `arg_N` local name.
    // The local list already carries the names, so the body
    // matches; pure text rewrite, bytes untouched.
    let stack_map = build_stack_local_map(&locals);
    if !stack_map.is_empty() {
        rewrite_stack_refs(&mut body, &stack_map);
    }

    // Branch-target rename: iced's intel formatter renders jump
    // targets as `00000000000011E0h`-style full-width hex literals.
    // When the address matches a `label_<hex>` we emit elsewhere
    // in the same function, substitute. Pure text rewrite.
    let labels = collect_label_addrs(&body);
    if !labels.is_empty() {
        rewrite_label_refs(&mut body, &labels);
    }

    // Parameter-register rename: in SysV-x64 (the default for ELF
    // x86-64) the first six integer parameters are passed in
    // rdi/rsi/rdx/rcx/r8/r9 (plus xmm0-7 for floats). When the
    // signature names them, substitute each register read in the
    // body with the parameter name — but only while the register
    // is still believed to hold the entry value (Move-to-self,
    // Call clobbers, etc.). Round-trip safe: pure text rewrite.
    let param_regs = build_param_register_map(signature.as_ref(), &attrs, bitness);
    if !param_regs.is_empty() {
        rewrite_param_register_reads(&mut body, &param_regs);
    }

    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        attrs,
        signature,
        locals,
        body,
    }
}

/// Inspect the function's return instructions and entry-block
/// register reads to classify its calling convention. Returns an
/// `#[abi="..."]` attribute when classification succeeds, empty
/// otherwise.
///
/// Heuristics (x86 i386 conventions):
///
/// * `ret` with no immediate → caller cleans the stack → cdecl.
/// * `ret N` (callee cleans) + ECX read before being written →
///   thiscall (when EDX is NOT also read) or fastcall (when EDX
///   IS read).
/// * `ret N` without an early ECX read → stdcall.
///
/// 64-bit functions get an `#[abi="sysv"]` or `#[abi="win64"]`
/// attribute when the platform hints are clear; we default to
/// `sysv` for ELF inputs and `win64` for PE since the CLI passes
/// those through different decompile entry points already.
fn detect_calling_convention_attrs(
    f: &Function<DecodedInsn>,
    ssa: &crate::ssa::SsaInfo,
) -> Vec<ud_ast::Attribute> {
    use ud_arch_x86::{CodeSize, Mnemonic};
    let Some(first_insn) = f.blocks.first().and_then(|b| b.insns.first()) else {
        return Vec::new();
    };
    // 64-bit functions: defer ABI classification to a future
    // win64-vs-sysv detector. Don't tag anything for now.
    if first_insn.iced.code_size() == CodeSize::Code64 {
        return Vec::new();
    }

    // Find a `ret` (possibly `ret N`) in the function.
    let mut ret_imm: Option<u32> = None;
    for block in &f.blocks {
        for insn in &block.insns {
            if matches!(insn.iced.mnemonic(), Mnemonic::Ret | Mnemonic::Retf) {
                let imm = insn.iced.immediate16();
                ret_imm = Some(u32::from(imm));
                break;
            }
        }
        if ret_imm.is_some() {
            break;
        }
    }
    let Some(imm) = ret_imm else {
        return Vec::new();
    };

    if imm == 0 {
        return vec![ud_ast::Attribute {
            key: "abi".into(),
            value: ud_ast::AttrValue::String("cdecl".into()),
        }];
    }

    // Callee cleans the stack — distinguish fastcall / thiscall /
    // stdcall by whether ECX (and EDX) are read in the entry
    // block before being written.
    let ecx_read_early = reg_read_before_write(f, ssa, "ecx");
    let edx_read_early = reg_read_before_write(f, ssa, "edx");
    let kind = if ecx_read_early && edx_read_early {
        "fastcall"
    } else if ecx_read_early {
        "thiscall"
    } else {
        "stdcall"
    };
    vec![ud_ast::Attribute {
        key: "abi".into(),
        value: ud_ast::AttrValue::String(kind.into()),
    }]
}

/// Walk the entry block and report whether `reg` is read before
/// it gets written. Treats SSA's per-IP read/write info as
/// authoritative.
fn reg_read_before_write(f: &Function<DecodedInsn>, ssa: &crate::ssa::SsaInfo, reg: &str) -> bool {
    let Some(entry) = f.blocks.first() else {
        return false;
    };
    let var = crate::ssa::Var::Reg(reg.to_string());
    for insn in &entry.insns {
        let ip = insn.iced.ip();
        if ssa.use_at.contains_key(&(ip, var.clone())) {
            // The SSA use_at only records uses that have a
            // reaching def — for the entry block, that's only the
            // function-entry def when the register hasn't been
            // written yet. So a use_at hit at the entry block
            // before any write means "read on entry".
            if let Some(def) = ssa.use_at.get(&(ip, var.clone())) {
                if matches!(
                    ssa.defs.get(def.0 as usize).map(|r| &r.site),
                    Some(crate::ssa::DefSite::Entry)
                ) {
                    return true;
                }
            }
        }
        if ssa.def_at.contains_key(&(ip, var.clone())) {
            return false;
        }
    }
    false
}

/// Compute SP delta at every instruction in `f`, propagating through
/// the CFG so jcc-only successors get the delta from their jcc
/// predecessor (not from whatever block sits next to them in source
/// order). Each block sees a single entry delta — well-structured
/// code keeps that consistent across all predecessors; when
/// predecessors disagree we take the first one we visit and accept
/// the small inaccuracy at merge points rather than refusing to
/// rename anything.
fn compute_sp_delta_cfg(f: &Function<DecodedInsn>) -> HashMap<u64, i64> {
    use ud_arch_x86::sp_change_for;
    let mut out: HashMap<u64, i64> = HashMap::new();
    if f.blocks.is_empty() {
        return out;
    }
    let addr_to_idx: HashMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr.0, i))
        .collect();
    let mut block_entry: HashMap<usize, i64> = HashMap::new();
    block_entry.insert(0, 0);
    let mut queue: Vec<usize> = vec![0];
    while let Some(idx) = queue.pop() {
        let block = &f.blocks[idx];
        let mut delta = block_entry[&idx];
        for insn in &block.insns {
            out.insert(insn.iced.ip(), delta);
            delta = delta.saturating_add(sp_change_for(&insn.iced));
        }
        let mut successors: Vec<usize> = Vec::new();
        match &block.terminator {
            Terminator::Fallthrough => {
                if idx + 1 < f.blocks.len() {
                    successors.push(idx + 1);
                }
            }
            Terminator::ConditionalBranch { taken, .. } => {
                if idx + 1 < f.blocks.len() {
                    successors.push(idx + 1);
                }
                if let Some(&t) = addr_to_idx.get(&taken.0) {
                    successors.push(t);
                }
            }
            Terminator::UnconditionalBranch { target } => {
                if let Some(&t) = addr_to_idx.get(&target.0) {
                    successors.push(t);
                }
            }
            Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable => {}
        }
        for succ in successors {
            if let std::collections::hash_map::Entry::Vacant(e) = block_entry.entry(succ) {
                e.insert(delta);
                queue.push(succ);
            }
        }
    }
    // Fallback: any block not reached via CFG (dead code, orphans)
    // still gets a recorded delta of 0 for every instruction so the
    // pattern lookup never panics.
    for (idx, block) in f.blocks.iter().enumerate() {
        if !block_entry.contains_key(&idx) {
            for insn in &block.insns {
                out.entry(insn.iced.ip()).or_insert(0);
            }
        }
    }
    out
}

/// Tracked expression for each GPR. The map is consulted on every
/// register *read* and updated on every register *write*. Values
/// are the source-language expressions the register currently
/// holds — so the substituted output reads as the computation the
/// programmer wrote, before the compiler threaded everything
/// through a scratch register.
#[derive(Default, Clone)]
struct RegState {
    values: std::collections::HashMap<String, String>,
}

impl RegState {
    fn write(&mut self, reg: &str, value: String) {
        self.values.insert(reg.to_string(), value);
    }

    fn invalidate(&mut self, reg: &str) {
        self.values.remove(reg);
    }

    fn invalidate_all(&mut self) {
        self.values.clear();
    }

    fn substitute(&self, text: &str) -> String {
        let mut result = text.to_string();
        // Substitute longest-name first so `eax` (a substring of
        // imaginary `eaxle`) can't accidentally match inside a
        // longer identifier — the word-boundary check inside
        // `replace_register_word` already guards this, but the
        // ordering is a small safety belt.
        let mut names: Vec<&String> = self.values.keys().collect();
        names.sort_by_key(|n| std::cmp::Reverse(n.len()));
        for reg in names {
            let val = &self.values[reg];
            result = replace_register_word(&result, reg, val);
        }
        result
    }
}

/// Intersect two register states: the result contains only entries
/// for registers that both inputs agree on (same key, same value).
/// Used at if-branch merge points so a value untouched by both arms
/// remains tracked, while a register reassigned to different values
/// in the two arms is dropped.
fn merge_states(a: &RegState, b: &RegState) -> RegState {
    let mut out = RegState::default();
    for (reg, val) in &a.values {
        if b.values.get(reg) == Some(val) {
            out.values.insert(reg.clone(), val.clone());
        }
    }
    out
}

/// Replace word-boundary, top-level (not inside `[…]`) occurrences
/// of `reg` in `text` with `value`. Substitution happens only
/// outside bracketed memory expressions because `[reg+disp]` reads
/// the *value* in `reg` as a pointer — substituting in a value
/// expression like `arg_8` (which itself is a slot, not a pointer)
/// would silently change the access target. The word-boundary
/// check stops the renamer from rewriting `eax` inside identifier
/// `eax_v2` (none of our names actually have such a prefix today,
/// but it's the right invariant to enforce).
///
/// Values that contain operator characters get parenthesised so
/// the substituted form re-parses with the same precedence as the
/// original (`x = eax + 1` with `eax = a + b` becomes
/// `x = (a + b) + 1`, not the ambiguous `a + b + 1`).
fn replace_register_word(text: &str, reg: &str, value: &str) -> String {
    // Char-aware scan so multi-byte UTF-8 sequences (string literals
    // from `.rodata` pulled into call args by the lifter, ellipsis
    // characters in those literals, etc.) don't slice mid-codepoint.
    let chars: Vec<char> = text.chars().collect();
    let reg_chars: Vec<char> = reg.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut depth: i32 = 0;
    // Incrementally tracked: are we currently inside a `"…"`
    // string literal? Reading the entire `out` buffer for each
    // char position would be O(n²); single-pass tracking is O(n).
    let mut in_quote = false;
    let mut prev_was_escape = false;
    while i < chars.len() {
        let c = chars[i];
        if !in_quote {
            if c == '[' {
                depth += 1;
            } else if c == ']' {
                depth -= 1;
            }
        }
        let head_matches =
            i + reg_chars.len() <= chars.len() && chars[i..i + reg_chars.len()] == reg_chars[..];
        let prefix_ok = i == 0 || !is_ident_char(chars[i - 1]);
        let suffix_ok = !head_matches
            || i + reg_chars.len() == chars.len()
            || !is_ident_char(chars[i + reg_chars.len()]);
        let matches_here = depth == 0 && !in_quote && head_matches && prefix_ok && suffix_ok;
        if matches_here {
            let needs_parens = value.contains(' ');
            if needs_parens {
                out.push('(');
                out.push_str(value);
                out.push(')');
            } else {
                out.push_str(value);
            }
            i += reg_chars.len();
            prev_was_escape = false;
            continue;
        }
        // Update string-state tracker AFTER deciding whether to
        // substitute at this char so the opening `"` doesn't get
        // counted as already-inside-string.
        prev_was_escape = if c == '"' && !prev_was_escape {
            in_quote = !in_quote;
            false
        } else {
            c == '\\' && in_quote && !prev_was_escape
        };
        out.push(c);
        i += 1;
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Run SSA-aware value forwarding over a block of statements.
///
/// Walks each stmt with a `RegState` that tracks the last expression
/// each register held; substitutes register references in operand
/// text with that expression. The forwarding is informed by the
/// pre-built SSA's per-IP write set: for every `@asm` boundary we
/// invalidate exactly the registers the underlying instructions
/// actually wrote, rather than the historical "control flow → drop
/// everything" approximation.
///
/// `base_ip` is the function entry's run-time address; the walker
/// maintains a byte cursor relative to it so it can decode each
/// stmt's bytes at the right IP and consult SSA. `bitness` decides
/// 32- vs 64-bit decoding.
///
/// The bytes pinned on each stmt are untouched. Only the rendered
/// text changes.
fn forward_propagate_registers(
    stmts: &mut [Stmt],
    ssa: &crate::ssa::SsaInfo,
    base_ip: u64,
    bitness: ud_arch_x86::Bitness,
) {
    let writes_at = build_writes_at(ssa);
    let mut state = RegState::default();
    let mut cursor = base_ip;
    forward_propagate_in_seq(stmts, &mut state, &writes_at, &mut cursor, bitness);
}

/// Pre-build the "writes at IP" map from SSA's `def_at`: for each
/// instruction, the list of variables it defines. Used by
/// `asm_state_effect` to invalidate just those registers rather
/// than the entire state.
fn build_writes_at(ssa: &crate::ssa::SsaInfo) -> HashMap<u64, Vec<crate::ssa::Var>> {
    let mut out: HashMap<u64, Vec<crate::ssa::Var>> = HashMap::new();
    for (ip, var) in ssa.def_at.keys() {
        out.entry(*ip).or_default().push(var.clone());
    }
    out
}

fn forward_propagate_in_seq(
    stmts: &mut [Stmt],
    state: &mut RegState,
    writes_at: &HashMap<u64, Vec<crate::ssa::Var>>,
    cursor: &mut u64,
    bitness: ud_arch_x86::Bitness,
) {
    for stmt in stmts.iter_mut() {
        propagate_one_stmt(stmt, state, writes_at, cursor, bitness);
    }
}

#[allow(clippy::too_many_lines)]
fn propagate_one_stmt(
    stmt: &mut Stmt,
    state: &mut RegState,
    writes_at: &HashMap<u64, Vec<crate::ssa::Var>>,
    cursor: &mut u64,
    bitness: ud_arch_x86::Bitness,
) {
    match stmt {
        Stmt::Move { dst, src, bytes } => {
            let new_src = state.substitute(src);
            if &new_src == dst {
                if is_gpr_name(dst) {
                    state.invalidate(dst);
                }
            } else {
                src.clone_from(&new_src);
                if is_gpr_name(dst) {
                    state.write(dst, new_src);
                } else {
                    *dst = state.substitute(dst);
                }
            }
            *cursor += bytes.len() as u64;
        }
        Stmt::Call { name, args, bytes } => {
            for a in args.iter_mut() {
                *a = state.substitute(a);
            }
            *name = state.substitute(name);
            for reg in CALLER_SAVED {
                state.invalidate(reg);
            }
            *cursor += bytes.len() as u64;
        }
        Stmt::IfBranch {
            cond_text,
            attrs,
            cond_bytes,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            *cond_text = state.substitute(cond_text);
            // head_bytes attribute lives in cond_bytes byte-order
            // BEFORE pre_body and cond_bytes. See lower_stmts_into.
            if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                *cursor += hb.len() as u64;
            }
            forward_propagate_in_seq(pre_body, state, writes_at, cursor, bitness);
            *cursor += cond_bytes.len() as u64;
            let snapshot = state.clone();
            forward_propagate_in_seq(then_body, state, writes_at, cursor, bitness);
            let after_then = state.clone();
            let after_else = if let Some(eb) = else_body {
                *state = snapshot.clone();
                forward_propagate_in_seq(eb, state, writes_at, cursor, bitness);
                state.clone()
            } else {
                snapshot
            };
            *state = merge_states(&after_then, &after_else);
        }
        Stmt::Loop {
            cond_text,
            entry_jmp_bytes,
            tail_bytes,
            body,
            ..
        } => {
            *cond_text = state.substitute(cond_text);
            if let Some(jmp) = entry_jmp_bytes {
                *cursor += jmp.len() as u64;
            }
            state.invalidate_all();
            forward_propagate_in_seq(body, state, writes_at, cursor, bitness);
            *cursor += tail_bytes.len() as u64;
            state.invalidate_all();
        }
        Stmt::Asm { text: _, bytes } => {
            // Use SSA-recorded writes for the underlying
            // instructions rather than mnemonic-based heuristics.
            // Decode the bytes at the cursor IP and walk each
            // instruction; aggregate its written variables from
            // `writes_at`. Then selectively invalidate those.
            let stmt_start = *cursor;
            let mut clobbered: HashSet<String> = HashSet::new();
            let mut has_call = false;
            if let Ok(insns) = ud_arch_x86::decode(bitness, bytes, stmt_start) {
                for insn in &insns {
                    let mnemonic = insn.iced.mnemonic();
                    if matches!(mnemonic, ud_arch_x86::Mnemonic::Call) {
                        has_call = true;
                    }
                    if let Some(vars) = writes_at.get(&insn.iced.ip()) {
                        for v in vars {
                            if let crate::ssa::Var::Reg(name) = v {
                                clobbered.insert(name.clone());
                            }
                        }
                    }
                }
            }
            if has_call {
                for reg in CALLER_SAVED {
                    state.invalidate(reg);
                }
            }
            for reg in &clobbered {
                state.invalidate(reg);
            }
            *cursor += bytes.len() as u64;
        }
        Stmt::ReturnExpr { text, bytes } => {
            *text = state.substitute(text);
            state.invalidate_all();
            *cursor += bytes.len() as u64;
        }
        Stmt::Prologue { bytes, .. }
        | Stmt::Epilogue { bytes, .. }
        | Stmt::Return { bytes, .. }
        | Stmt::ArgSpill { bytes, .. }
        | Stmt::LocalSet { bytes, .. }
        | Stmt::LocalArith { bytes, .. }
        | Stmt::LocalCompound { bytes, .. }
        | Stmt::Inc16 { bytes, .. } => {
            state.invalidate_all();
            *cursor += bytes.len() as u64;
        }
        Stmt::Save { reg, bytes } | Stmt::Restore { reg, bytes } => {
            if is_gpr_name(reg) {
                state.invalidate(reg);
            }
            *cursor += bytes.len() as u64;
        }
        Stmt::IfReturn { bytes, .. }
        | Stmt::Goto { bytes, .. }
        | Stmt::IfGoto { bytes, .. }
        | Stmt::Switch { bytes, .. } => {
            // cmp/test/jcc/jmp don't touch GPRs — state preserved.
            *cursor += bytes.len() as u64;
        }
        Stmt::SehInstall { bytes } | Stmt::SehRestore { bytes } => {
            // FS:[0] writes don't affect GPR tracking, but the
            // install includes a push that does pre/post adjust
            // esp — be conservative and drop everything.
            state.invalidate_all();
            *cursor += bytes.len() as u64;
        }
        Stmt::Label { .. } | Stmt::Comment(_) => {}
    }
}

/// Recursively walk `body` and resolve hex literals that point
/// at string data. Mirrors [`simplify_body`]'s shape but uses
/// [`crate::expr::resolve_strings_in_text`] for the rewrite.
fn resolve_strings_in_body(stmts: &mut [Stmt], lookup: &dyn Fn(u64) -> Option<String>) {
    for stmt in stmts.iter_mut() {
        resolve_strings_in_stmt(stmt, lookup);
    }
}

fn resolve_strings_in_stmt(stmt: &mut Stmt, lookup: &dyn Fn(u64) -> Option<String>) {
    match stmt {
        Stmt::Move { dst, src, .. } => {
            *dst = crate::expr::resolve_strings_in_text(dst, lookup);
            *src = crate::expr::resolve_strings_in_text(src, lookup);
        }
        Stmt::Call { args, name, .. } => {
            *name = crate::expr::resolve_strings_in_text(name, lookup);
            for a in args.iter_mut() {
                *a = crate::expr::resolve_strings_in_text(a, lookup);
            }
        }
        Stmt::IfBranch {
            cond_text,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            *cond_text = crate::expr::resolve_strings_in_text(cond_text, lookup);
            resolve_strings_in_body(pre_body, lookup);
            resolve_strings_in_body(then_body, lookup);
            if let Some(eb) = else_body {
                resolve_strings_in_body(eb, lookup);
            }
        }
        Stmt::Loop {
            cond_text, body, ..
        } => {
            *cond_text = crate::expr::resolve_strings_in_text(cond_text, lookup);
            resolve_strings_in_body(body, lookup);
        }
        Stmt::ReturnExpr { text, .. } => {
            *text = crate::expr::resolve_strings_in_text(text, lookup);
        }
        Stmt::IfReturn {
            cond_text,
            value_text,
            ..
        } => {
            *cond_text = crate::expr::resolve_strings_in_text(cond_text, lookup);
            *value_text = crate::expr::resolve_strings_in_text(value_text, lookup);
        }
        _ => {}
    }
}

/// Try to read a NUL-terminated ASCII or UTF-8 string at `va`. The
/// VA goes through the format-agnostic [`DataLookup`] so this works
/// for both PE (mapped VA) and ELF (vaddr). Returns `None` for any
/// of:
///
/// * VA is implausibly small (typical small integer literals like
///   stack-frame offsets or array indices live here; treating them
///   as pointers produces spurious "strings").
/// * VA not in any data section.
/// * Section is code-only (we don't quote-render text-section bytes
///   as strings, even though they could happen to look like text).
/// * Bytes don't form a printable string of length ≥ 4 with a NUL
///   terminator within 1024 bytes.
fn lookup_string_at_va(data: &dyn DataLookup, va: u64) -> Option<String> {
    // Plausibility floor: real string-data lives above the first
    // page on every platform we target. Sub-0x1000 hits are almost
    // always stack-frame offsets that happened to share a numeric
    // value with a section-relative address.
    if va < 0x1000 {
        return None;
    }
    let (section_name, section_data, offset) = data.section_at(va)?;
    // Reject code sections so we don't substitute function entries
    // (which `call` operands also use) for "string" text just
    // because the bytes happen to be printable.
    if section_name == ".text"
        || section_name == ".init"
        || section_name == ".fini"
        || section_name.starts_with(".text.")
    {
        return None;
    }
    let slice = section_data.get(offset..)?;
    let max_len = slice.len().min(1024);
    let nul = slice[..max_len].iter().position(|&b| b == 0)?;
    if nul < 4 {
        return None;
    }
    let text_bytes = &slice[..nul];
    // Accept only when every byte is printable ASCII or a small
    // set of harmless whitespace. UTF-8 is rejected here for now;
    // wide-string handling lives in a future pass.
    if !text_bytes
        .iter()
        .all(|&b| matches!(b, 0x20..=0x7e | b'\n' | b'\r' | b'\t'))
    {
        return None;
    }
    std::str::from_utf8(text_bytes).ok().map(str::to_string)
}

/// Walk every `Stmt` in `body` and run the algebraic simplifier
/// on its operand-text fields. Recurses into `IfBranch` /
/// `Loop` arms.
fn simplify_body(stmts: &mut [Stmt], width: crate::expr::BitWidth) {
    for stmt in stmts.iter_mut() {
        simplify_stmt(stmt, width);
    }
}

fn simplify_stmt(stmt: &mut Stmt, width: crate::expr::BitWidth) {
    match stmt {
        Stmt::Move { dst, src, .. } => {
            *dst = crate::expr::simplify_text(dst, width);
            *src = crate::expr::simplify_text(src, width);
        }
        Stmt::Call { args, name, .. } => {
            *name = crate::expr::simplify_text(name, width);
            for a in args.iter_mut() {
                *a = crate::expr::simplify_text(a, width);
            }
        }
        Stmt::IfBranch {
            cond_text,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            *cond_text = crate::expr::simplify_text(cond_text, width);
            simplify_body(pre_body, width);
            simplify_body(then_body, width);
            if let Some(eb) = else_body {
                simplify_body(eb, width);
            }
        }
        Stmt::Loop {
            cond_text, body, ..
        } => {
            *cond_text = crate::expr::simplify_text(cond_text, width);
            simplify_body(body, width);
        }
        Stmt::ReturnExpr { text, .. } => {
            *text = crate::expr::simplify_text(text, width);
        }
        _ => {}
    }
}

/// Distill a `FnDecl` into the inputs the prologue/epilogue
/// default-computer needs: which callee-saved registers the
/// function uses, whether it reserves stack space, how many
/// stack-passed arguments it has, and what ABI it follows.
///
/// Same algorithm runs at decompile time (after we've built
/// the body) and at lower time (after the parser has read the
/// source); as long as both sides see the same `FnDecl`,
/// they compute the same default, and the @prologue / @epilogue
/// can be safely omitted from source.
fn profile_inputs_from_fn(f: &ud_ast::FnDecl) -> ud_arch_x86::ProfileInputs {
    let abi = f
        .attrs
        .iter()
        .find_map(|a| match (&a.key, &a.value) {
            (k, ud_ast::AttrValue::String(s)) if k == "abi" => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let noframe = f
        .attrs
        .iter()
        .any(|a| a.key == "noframe" && matches!(a.value, ud_ast::AttrValue::Flag));
    let mut uses_ebx = false;
    let mut uses_esi = false;
    let mut uses_edi = false;
    let mut max_neg_off: u32 = 0;
    let mut stack_arg_count: u32 = 0;
    for local in &f.locals {
        match local.kind {
            ud_ast::LocalKind::Register => match local.name.as_str() {
                "ebx" => uses_ebx = true,
                "esi" => uses_esi = true,
                "edi" => uses_edi = true,
                _ => {}
            },
            ud_ast::LocalKind::Stack => {
                if let Some(rest) = local.name.strip_prefix("var_") {
                    if let Ok(n) = u32::from_str_radix(rest, 16) {
                        if n > max_neg_off {
                            max_neg_off = n;
                        }
                    }
                } else if let Some(rest) = local.name.strip_prefix("arg_") {
                    if u32::from_str_radix(rest, 16).is_ok() {
                        stack_arg_count += 1;
                    }
                }
            }
        }
    }
    // MSVC /Oy- default keeps a frame pointer in nearly every
    // function. `#[noframe]` is the per-fn opt-out marker that the
    // decompiler sets when the no-frame variant of the default
    // matches the observed bytes.
    let frame_required = !noframe;
    // Canonical MSVC x86 save order: ebx → esi → edi.
    let mut saves_used: Vec<String> = Vec::new();
    if uses_ebx {
        saves_used.push("ebx".into());
    }
    if uses_esi {
        saves_used.push("esi".into());
    }
    if uses_edi {
        saves_used.push("edi".into());
    }
    ud_arch_x86::ProfileInputs {
        saves_used,
        frame_required,
        sub_esp: max_neg_off,
        cf_protect: false,
        stack_arg_count,
        abi,
    }
}

/// Is every element of `small` also in `large` (order-preserving
/// not required)? Used to decide whether an actual prologue's
/// `saves` list is a subset of the default-derived `saves`, in
/// which case the explanatory comment would just restate what
/// the explicit prologue already shows.
fn is_subset(small: &[String], large: &[String]) -> bool {
    small.iter().all(|s| large.contains(s))
}

/// Render the default prologue as a one-line summary suitable
/// for an inline `// default: …` comment. Returns `None` when
/// the default is fully empty — in that case the actual prologue
/// must be reading some signal we don't capture in `ProfileInputs`,
/// and the bare comment would be uninformative.
fn describe_default_prologue(p: &ud_arch_x86::StructuredPrologue) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if !p.saves.is_empty() {
        parts.push(format!("saves: [{}]", p.saves.join(", ")));
    }
    if p.frame {
        parts.push("frame".into());
    }
    if p.sub_esp > 0 {
        parts.push(format!("sub: {:#x}", p.sub_esp));
    }
    if !p.saves_after.is_empty() {
        parts.push(format!("saves_after: [{}]", p.saves_after.join(", ")));
    }
    if p.cf_protect {
        parts.push("cf_protect".into());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Pair to [`describe_default_prologue`] for the trailing epilogue.
fn describe_default_epilogue(e: &ud_arch_x86::StructuredEpilogue) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if !e.saves.is_empty() {
        parts.push(format!("saves: [{}]", e.saves.join(", ")));
    }
    if e.leave {
        parts.push("leave".into());
    } else if e.pop_frame {
        parts.push("pop_frame".into());
    }
    if e.add_esp > 0 {
        parts.push(format!("add: {:#x}", e.add_esp));
    }
    if e.ret_imm > 0 {
        parts.push(format!("ret: {:#x}", e.ret_imm));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Try to decode a prologue's bytes via the canonical codec.
/// Returns `Some(params)` only when the codec's encode-back
/// produces exactly the same bytes — i.e., the structured form
/// is a faithful representation of the bytes. Returns `None` for
/// handwritten / non-canonical prologues so the emitter falls
/// back to the opaque byte list. The bit-width is currently
/// fixed to 32-bit; expand the call site when the structured
/// form is wired in for x86-64.
fn decode_prologue_params(
    bytes: &[u8],
    bits: ud_arch_x86::CodecBits,
) -> Option<ud_ast::PrologueParams> {
    let p = ud_arch_x86::prologue_roundtrips(bytes, bits)?;
    Some(ud_ast::PrologueParams {
        saves: p.saves,
        saves_after: p.saves_after,
        frame: p.frame,
        sub_esp: p.sub_esp,
        cf_protect: p.cf_protect,
        frame_alt: p.frame_alt_encoding,
    })
}

/// Mirror of [`decode_prologue_params`] for epilogues.
fn decode_epilogue_params(
    bytes: &[u8],
    bits: ud_arch_x86::CodecBits,
) -> Option<ud_ast::EpilogueParams> {
    let e = ud_arch_x86::epilogue_roundtrips(bytes, bits)?;
    Some(ud_ast::EpilogueParams {
        saves: e.saves,
        leave: e.leave,
        pop_frame: e.pop_frame,
        add_esp: e.add_esp,
        ret_imm: e.ret_imm,
    })
}

/// Infer 32- vs 64-bit decoding from the function's first
/// instruction. iced records the `code_size` on every decoded
/// instruction; reading it back lets the SSA-aware propagation
/// decode pinned bytes without the caller having to thread
/// bitness through (and it stays right for the rare per-function
/// mixed-mode binary).
fn function_bitness(f: &Function<DecodedInsn>) -> ud_arch_x86::Bitness {
    use ud_arch_x86::{Bitness, CodeSize};
    let first = f.blocks.first().and_then(|b| b.insns.first());
    match first.map(|i| i.iced.code_size()) {
        Some(CodeSize::Code16) => Bitness::Bits16,
        Some(CodeSize::Code64) => Bitness::Bits64,
        _ => Bitness::Bits32,
    }
}

/// Read the `head_bytes` attribute off an `IfBranch`'s attrs, if
/// present. Mirrors the same lookup the lower path performs to
/// determine the byte position of `pre_body`.
fn ud_ast_head_bytes_attr(attrs: &[ud_ast::Attribute]) -> Option<&[u8]> {
    for a in attrs {
        if a.key == "head_bytes" {
            if let ud_ast::AttrValue::ByteList(b) = &a.value {
                return Some(b.as_slice());
            }
        }
    }
    None
}

/// Lower-case GPR names that participate in value forwarding.
/// Restricted to general-purpose registers — segment, MMX, XMM,
/// x87 registers don't get the same treatment because their use
/// patterns are different and substitution would mostly produce
/// noise.
fn is_gpr_name(s: &str) -> bool {
    matches!(
        s,
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    )
}

const CALLER_SAVED: &[&str] = &[
    "eax", "ecx", "edx", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
];

/// At an Epilogue/Return position `i` with a known returned
/// expression `expr`, rewrite the most recent `eax/rax = <expr>`
/// Move into a `Stmt::ReturnExpr` (renders as `return <expr>;`).
/// Falls back to inserting a `// returns <expr>` comment when the
/// preceding Move can't be cleanly identified (side-effecting
/// stmt in between, or value flowed in through a Call's return).
///
/// Returns the number of statements inserted before `i` so the
/// caller can advance its cursor accordingly.
fn fold_or_annotate_return(stmts: &mut Vec<Stmt>, i: usize, expr: &str) -> usize {
    for k in (0..i).rev() {
        match &stmts[k] {
            Stmt::Move { dst, src, bytes } if (dst == "eax" || dst == "rax") && src == expr => {
                let new_stmt = Stmt::ReturnExpr {
                    text: src.clone(),
                    bytes: bytes.clone(),
                };
                stmts[k] = new_stmt;
                return 0;
            }
            Stmt::Call { .. }
            | Stmt::Asm { .. }
            | Stmt::Move { .. }
            | Stmt::IfBranch { .. }
            | Stmt::Loop { .. }
            | Stmt::Switch { .. } => break,
            _ => {}
        }
    }
    let comment = Stmt::Comment(format!("returns {expr}"));
    stmts.insert(i, comment);
    1
}

/// Walk the function body and insert a `// returns <expr>` comment
/// before every `@epilogue` / `@return` that has a tracked EAX/RAX
/// expression at exit. Same `RegState` machinery as forward
/// propagation, but the only output is a comment annotation — no
/// stmts are rewritten.
fn annotate_return_values(stmts: &mut Vec<Stmt>) {
    let mut state = RegState::default();
    annotate_in_seq(stmts, &mut state);
}

fn annotate_in_seq(stmts: &mut Vec<Stmt>, state: &mut RegState) {
    let mut i = 0;
    while i < stmts.len() {
        // Peek at the stmt's effect; for an epilogue / return, peek
        // at the state first so the comment captures pre-epilogue
        // values.
        match &mut stmts[i] {
            Stmt::Epilogue { .. } | Stmt::Return { .. } | Stmt::ReturnExpr { .. } => {
                let ret = state
                    .values
                    .get("eax")
                    .or_else(|| state.values.get("rax"))
                    .cloned();
                state.invalidate_all();
                if let Some(expr) = ret {
                    if expr != "eax" && expr != "rax" {
                        let added = fold_or_annotate_return(stmts, i, &expr);
                        i += added;
                    }
                }
                i += 1;
                continue;
            }
            Stmt::Move { dst, src, .. } => {
                if is_gpr_name(dst) {
                    state.write(dst, src.clone());
                } else {
                    // Memory dst — register state preserved.
                }
            }
            Stmt::Call { .. } => {
                // Caller-saved regs get clobbered, including EAX.
                for r in CALLER_SAVED {
                    state.invalidate(r);
                }
            }
            Stmt::Asm { text, .. } => {
                let text_owned = text.clone();
                asm_state_effect(&text_owned, state);
            }
            Stmt::IfBranch {
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                annotate_in_seq(pre_body, state);
                let snapshot = state.clone();
                annotate_in_seq(then_body, state);
                if let Some(eb) = else_body {
                    *state = snapshot;
                    annotate_in_seq(eb, state);
                }
                state.invalidate_all();
            }
            Stmt::Loop { body, .. } => {
                state.invalidate_all();
                annotate_in_seq(body, state);
                state.invalidate_all();
            }
            Stmt::Prologue { .. }
            | Stmt::ArgSpill { .. }
            | Stmt::LocalSet { .. }
            | Stmt::LocalArith { .. }
            | Stmt::LocalCompound { .. }
            | Stmt::Inc16 { .. } => {
                state.invalidate_all();
            }
            Stmt::Save { reg, .. } | Stmt::Restore { reg, .. } => {
                if is_gpr_name(reg) {
                    state.invalidate(reg);
                }
            }
            Stmt::IfReturn { .. }
            | Stmt::Goto { .. }
            | Stmt::IfGoto { .. }
            | Stmt::Switch { .. }
            | Stmt::SehInstall { .. }
            | Stmt::SehRestore { .. }
            | Stmt::Label { .. }
            | Stmt::Comment(_) => {
                // cmp/test/jcc don't touch GPRs, comments are
                // metadata — both leave state alone.
            }
        }
        i += 1;
    }
}

/// LIFO-pair `@asm("push REG")` / `@asm("pop REG")` lines in a
/// function body and replace them with `@save("REG")` /
/// `@restore("REG")` directives. The pinned bytes carry through
/// verbatim, so round-trip is preserved — only the rendering
/// changes from a generic `@asm` line to a directive whose intent
/// (extend the prologue's save set for the duration of a region)
/// is obvious at a glance.
///
/// Pairing is per-execution-scope: an `IfBranch`'s `pre_body`
/// counts as continuation of the surrounding scope (its bytes
/// execute sequentially between cmp and jcc), while `then_body` /
/// `else_body` / loop bodies start fresh scopes — a push in one
/// branch never pairs with a pop in a sibling branch even though
/// both might balance the stack at runtime, because that would
/// conflate distinct save lifetimes.
/// Resolve `Stmt::Call` targets whose `name` field, after
/// forward-propagation, is an absolute-VA memory reference of the
/// shape `[1C201030h]`. Looks the VA up in `name_at` and, when
/// found, replaces the name with the resolved label. Misses (a
/// register-indirect through a non-IAT pointer, an unresolved
/// address) keep the original text — the bytes are pinned either
/// way, so this is purely a rendering improvement.
fn resolve_indirect_call_names(stmts: &mut [Stmt], name_at: &HashMap<u64, String>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Call { name, .. } => {
                if let Some(resolved) = resolve_absolute_indirect(name, name_at) {
                    *name = resolved;
                }
            }
            Stmt::IfBranch {
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                resolve_indirect_call_names(pre_body, name_at);
                resolve_indirect_call_names(then_body, name_at);
                if let Some(eb) = else_body {
                    resolve_indirect_call_names(eb, name_at);
                }
            }
            Stmt::Loop { body, .. } => {
                resolve_indirect_call_names(body, name_at);
            }
            _ => {}
        }
    }
}

/// Parse a call-target string of the form `[ABS_HEX]` and look up
/// the address in `name_at`. Returns `None` for any other shape
/// (register names, `[reg+disp]`, already-resolved names).
fn resolve_absolute_indirect(text: &str, name_at: &HashMap<u64, String>) -> Option<String> {
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    if inner.contains('+') || inner.contains('-') || inner.contains('*') {
        return None;
    }
    let hex = if let Some(s) = inner.strip_suffix('h') {
        s
    } else {
        inner
            .strip_prefix("0x")
            .or_else(|| inner.strip_prefix("0X"))?
    };
    let va = u64::from_str_radix(hex, 16).ok()?;
    name_at.get(&va).cloned()
}

/// Fold `@asm("cmp/test X,Y; jcc TARGET")` lines whose `jcc`
/// target is a return-shaped block elsewhere in the function
/// into `@if_return` directives. The original bytes are pinned
/// on the new directive; round-trip is preserved because the
/// total byte sequence of the body doesn't change.
///
/// A block is "return-shaped" when, walking from its starting IP
/// in lower order, we find at most a few register-init stmts
/// (`eax = LIT`, `xor eax, eax`) followed by either `@return` or
/// `@epilogue`. The return-value text comes from any
/// `// returns <expr>` comment the annotator already inserted
/// before the epilogue, falling back to the constant the init
/// stmts produced.
fn fold_early_returns(stmts: &mut [Stmt], base_ip: u64, bitness: ud_arch_x86::Bitness) {
    let returns_at = collect_return_targets(stmts, base_ip);
    let mut cursor = base_ip;
    fold_early_returns_in_seq(stmts, &mut cursor, &returns_at, bitness);
}

fn fold_early_returns_in_seq(
    stmts: &mut [Stmt],
    cursor: &mut u64,
    returns_at: &HashMap<u64, String>,
    bitness: ud_arch_x86::Bitness,
) {
    let mut i = 0;
    while i < stmts.len() {
        let stmt_start = *cursor;
        let advance = stmt_total_bytes(&stmts[i]);
        let mut replaced = false;
        if let Stmt::Asm { text, bytes } = &stmts[i] {
            if let Some(rewrite) =
                try_fold_to_if_return(text, bytes, stmt_start, returns_at, bitness)
            {
                stmts[i] = rewrite;
                replaced = true;
            }
        }
        // Recurse into nested arms regardless of replacement (the
        // replacement is itself a single stmt with cond_bytes).
        if !replaced {
            match &mut stmts[i] {
                Stmt::IfBranch {
                    attrs,
                    cond_bytes,
                    pre_body,
                    then_body,
                    else_body,
                    ..
                } => {
                    let mut sub = *cursor;
                    if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                        sub += hb.len() as u64;
                    }
                    fold_early_returns_in_seq(pre_body, &mut sub, returns_at, bitness);
                    sub += cond_bytes.len() as u64;
                    fold_early_returns_in_seq(then_body, &mut sub, returns_at, bitness);
                    if let Some(eb) = else_body {
                        fold_early_returns_in_seq(eb, &mut sub, returns_at, bitness);
                    }
                    let _ = sub;
                }
                Stmt::Loop {
                    entry_jmp_bytes,
                    body,
                    tail_bytes,
                    ..
                } => {
                    let mut sub = *cursor;
                    if let Some(jmp) = entry_jmp_bytes {
                        sub += jmp.len() as u64;
                    }
                    fold_early_returns_in_seq(body, &mut sub, returns_at, bitness);
                    sub += tail_bytes.len() as u64;
                    let _ = sub;
                }
                _ => {}
            }
        }
        *cursor += advance as u64;
        i += 1;
    }
}

/// Try to recognise `text` as `cmp/test ARGS; jcc TARGET` shape
/// and, when `TARGET` is a known return-shape IP, return a
/// replacement `Stmt::IfReturn` carrying the same bytes.
fn try_fold_to_if_return(
    text: &str,
    bytes: &[u8],
    stmt_start: u64,
    returns_at: &HashMap<u64, String>,
    bitness: ud_arch_x86::Bitness,
) -> Option<Stmt> {
    use ud_arch_x86::{FlowControl, Mnemonic};
    // Cheap text gate so we don't decode every `@asm` line.
    if !(text.starts_with("cmp ") || text.starts_with("test ")) {
        return None;
    }
    if !text.contains("; j") {
        return None;
    }
    let insns = ud_arch_x86::decode(bitness, bytes, stmt_start).ok()?;
    if insns.len() != 2 {
        return None;
    }
    let cmp = &insns[0];
    let jcc = &insns[1];
    if !matches!(cmp.iced.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
        return None;
    }
    if jcc.iced.flow_control() != FlowControl::ConditionalBranch {
        return None;
    }
    let target = jcc.iced.near_branch_target();
    if target == 0 {
        return None;
    }
    let value_text = returns_at.get(&target)?.clone();
    // The jcc-taken condition is the *positive* form: when it
    // fires, control transfers to the early-return block. The
    // existing `render_cond_source` returns the body-side
    // (inverted) form, so we invert it back here.
    let body_form = ud_arch_x86::render_cond_source(&cmp.iced, &jcc.iced);
    let cond_text = invert_relational_cond(&body_form);
    Some(Stmt::IfReturn {
        cond_text,
        value_text,
        bytes: bytes.to_vec(),
    })
}

/// Walk the body in lower-order, identifying every IP that's the
/// start of a "return-shaped" stmt sequence: a chain of small
/// register-init stmts terminating in `@return` or `@epilogue`.
/// Returns a map keyed by the chain's starting IP whose value is
/// the textual form of the return value (e.g. `"0"`, `"-100"`,
/// `"eax"` — the same form the existing `// returns N` comment
/// uses).
fn collect_return_targets(stmts: &[Stmt], base_ip: u64) -> HashMap<u64, String> {
    let mut out: HashMap<u64, String> = HashMap::new();
    let mut cursor = base_ip;
    collect_return_targets_in_seq(stmts, &mut cursor, &mut out);
    out
}

fn collect_return_targets_in_seq(stmts: &[Stmt], cursor: &mut u64, out: &mut HashMap<u64, String>) {
    let mut i = 0;
    while i < stmts.len() {
        let chunk_start = *cursor;
        // Try to identify a return-shape starting here. We allow
        // up to 4 register-init stmts (mov / xor) before the
        // `// returns N` comment + `@epilogue` / `@return`.
        let mut j = i;
        let mut value: Option<String> = None;
        let mut steps = 0;
        loop {
            if j >= stmts.len() {
                break;
            }
            match &stmts[j] {
                Stmt::Move { dst, src, .. } if is_gpr_name(dst) => {
                    if dst == "eax" || dst == "rax" {
                        value = Some(src.clone());
                    }
                    j += 1;
                    steps += 1;
                    if steps > 4 {
                        break;
                    }
                }
                Stmt::Comment(text) => {
                    if let Some(v) = text.strip_prefix("returns ") {
                        value = Some(v.to_string());
                    }
                    j += 1;
                }
                Stmt::Epilogue { .. } | Stmt::Return { .. } => {
                    let v = value.unwrap_or_default();
                    out.insert(chunk_start, v);
                    break;
                }
                _ => break,
            }
        }
        // Advance the outer cursor by the first stmt's bytes — we
        // re-evaluate from `i+1` to catch overlapping shapes too
        // (rare, but harmless).
        let first_bytes = stmt_total_bytes(&stmts[i]);
        *cursor += first_bytes as u64;
        // Recurse into nested bodies.
        match &stmts[i] {
            Stmt::IfBranch {
                attrs,
                cond_bytes,
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                // Reset and walk the sub-bodies with their own
                // cursor anchored at the position of this stmt's
                // start.
                let mut sub = chunk_start;
                if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                    sub += hb.len() as u64;
                }
                collect_return_targets_in_seq(pre_body, &mut sub, out);
                sub += cond_bytes.len() as u64;
                collect_return_targets_in_seq(then_body, &mut sub, out);
                if let Some(eb) = else_body {
                    collect_return_targets_in_seq(eb, &mut sub, out);
                }
            }
            Stmt::Loop {
                entry_jmp_bytes,
                body,
                ..
            } => {
                let mut sub = chunk_start;
                if let Some(jmp) = entry_jmp_bytes {
                    sub += jmp.len() as u64;
                }
                collect_return_targets_in_seq(body, &mut sub, out);
            }
            _ => {}
        }
        i += 1;
    }
}

/// Total bytes a `Stmt` contributes to the function's byte
/// stream. Matches `lower_stmts_into`'s walk order, including
/// nested `IfBranch` head/cond/arm bytes and `Loop`
/// entry/body/tail.
fn stmt_total_bytes(stmt: &Stmt) -> usize {
    match stmt {
        Stmt::Asm { bytes, .. }
        | Stmt::Return { bytes, .. }
        | Stmt::Prologue { bytes, .. }
        | Stmt::Epilogue { bytes, .. }
        | Stmt::Save { bytes, .. }
        | Stmt::Restore { bytes, .. }
        | Stmt::IfReturn { bytes, .. }
        | Stmt::Goto { bytes, .. }
        | Stmt::IfGoto { bytes, .. }
        | Stmt::Switch { bytes, .. }
        | Stmt::ReturnExpr { bytes, .. }
        | Stmt::ArgSpill { bytes, .. }
        | Stmt::Call { bytes, .. }
        | Stmt::LocalSet { bytes, .. }
        | Stmt::LocalArith { bytes, .. }
        | Stmt::LocalCompound { bytes, .. }
        | Stmt::Move { bytes, .. }
        | Stmt::Inc16 { bytes, .. }
        | Stmt::SehInstall { bytes }
        | Stmt::SehRestore { bytes } => bytes.len(),
        Stmt::IfBranch {
            attrs,
            cond_bytes,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            let mut n = cond_bytes.len();
            if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                n += hb.len();
            }
            n += stmts_total_bytes(pre_body);
            n += stmts_total_bytes(then_body);
            if let Some(eb) = else_body {
                n += stmts_total_bytes(eb);
            }
            n
        }
        Stmt::Loop {
            entry_jmp_bytes,
            body,
            tail_bytes,
            ..
        } => {
            let mut n = 0;
            if let Some(jmp) = entry_jmp_bytes {
                n += jmp.len();
            }
            n += stmts_total_bytes(body);
            n += tail_bytes.len();
            n
        }
        Stmt::Label { .. } | Stmt::Comment(_) => 0,
    }
}

fn stmts_total_bytes(stmts: &[Stmt]) -> usize {
    stmts.iter().map(stmt_total_bytes).sum()
}

/// Drop `Move { dst: REG, … }` stmts whose dst register is dead
/// after the move per [`crate::ssa::Liveness`]. The deleted
/// stmt's bytes are merged into the *following* stmt's `bytes`
/// field so the function's total byte sequence is unchanged —
/// round-trip is preserved by construction.
///
/// Only fires when the dst is a tracked GPR (registers
/// participating in liveness analysis). Memory destinations,
/// register-pair forms, and non-GPR fields are left alone.
fn fold_dead_register_moves(stmts: &mut Vec<Stmt>, liveness: &crate::ssa::Liveness, base_ip: u64) {
    let mut cursor = base_ip;
    let mut i = 0;
    while i < stmts.len() {
        let stmt_start = cursor;
        let stmt_len = stmt_total_bytes(&stmts[i]);
        let mut deleted = false;
        if let Stmt::Move { dst, bytes, .. } = &stmts[i] {
            if is_gpr_name(dst) && !bytes.is_empty() {
                let last_insn_ip = stmt_start;
                let var = crate::ssa::Var::Reg(dst.clone());
                let dead_after = liveness
                    .live_after_insn
                    .get(&last_insn_ip)
                    .is_some_and(|live| !live.contains(&var));
                // Even if the register stays live for one more
                // instruction, fold when the next stmt's render
                // text doesn't reference it at top level — that
                // means forward-propagation already inlined the
                // value at the use site, so the intermediate
                // line is purely redundant in the visible source.
                let forwarded = stmts.get(i + 1).is_some_and(|next| {
                    !stmt_has_top_level_register_read(next, dst)
                        && stmt_bytes_field_ro(next).is_some()
                });
                if dead_after || forwarded {
                    let prefix = match &stmts[i] {
                        Stmt::Move { bytes, .. } => bytes.clone(),
                        _ => unreachable!(),
                    };
                    if let Some(next_bytes) = stmts.get_mut(i + 1).and_then(stmt_bytes_field_mut) {
                        let mut merged = Vec::with_capacity(prefix.len() + next_bytes.len());
                        merged.extend_from_slice(&prefix);
                        merged.extend_from_slice(next_bytes);
                        *next_bytes = merged;
                        stmts.remove(i);
                        deleted = true;
                    }
                }
            }
        }
        if !deleted {
            // Nested-stmt cursor management is involved and the
            // dominant dead-store wins are at the top level;
            // skip recursion for now — top-level alone already
            // catches the bulk of the redundant scratch-Move
            // setups.
            cursor += stmt_len as u64;
            i += 1;
        }
        // When `deleted`, cursor stays put because we shifted the
        // bytes onto stmts[i] (which is the former stmts[i+1]).
    }
}

/// Does `stmt`'s rendered text reference `reg` as a top-level
/// (i.e., not inside a `[…]` address calculation) word-boundary
/// use? Used by dead-store folding to ask "would the reader still
/// see the register name in this stmt's output?". A `false`
/// answer means forward-propagation has already substituted the
/// value at the use site, so the producing move is redundant
/// for display purposes.
fn stmt_has_top_level_register_read(stmt: &Stmt, reg: &str) -> bool {
    let needle = reg.as_bytes();
    let mut found = false;
    let mut visit = |text: &str| {
        if found {
            return;
        }
        if text_has_top_level_reg(text, needle) {
            found = true;
        }
    };
    match stmt {
        Stmt::Move { dst, src, .. } => {
            visit(dst);
            visit(src);
        }
        Stmt::Call { name, args, .. } => {
            visit(name);
            for a in args {
                visit(a);
            }
        }
        Stmt::IfBranch { cond_text, .. }
        | Stmt::Loop { cond_text, .. }
        | Stmt::IfGoto { cond_text, .. } => visit(cond_text),
        Stmt::IfReturn {
            cond_text,
            value_text,
            ..
        } => {
            visit(cond_text);
            visit(value_text);
        }
        Stmt::ReturnExpr { text, .. } => visit(text),
        _ => {}
    }
    found
}

/// Scan `text` for a bare-word occurrence of `needle` outside
/// any `[…]` bracketed subexpression and outside quoted strings.
/// Mirrors the register-substitution scanner the forward-prop
/// pass uses so the two stay consistent.
fn text_has_top_level_reg(text: &str, needle: &[u8]) -> bool {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut prev_escape = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if !prev_escape && c == b'"' {
                in_string = false;
            }
            prev_escape = !prev_escape && c == b'\\';
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_string = true;
            }
            b'[' | b'(' => depth += 1,
            b']' | b')' => depth = depth.saturating_sub(1),
            _ if depth == 0
                && i + needle.len() <= bytes.len()
                && &bytes[i..i + needle.len()] == needle =>
            {
                let prev_alnum = i > 0 && is_ident_byte(bytes[i - 1]);
                let next_alnum =
                    i + needle.len() < bytes.len() && is_ident_byte(bytes[i + needle.len()]);
                if !prev_alnum && !next_alnum {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Read-only access to the bytes field — mirror of
/// [`stmt_bytes_field_mut`] for the dead-store fold's predicate.
fn stmt_bytes_field_ro(stmt: &Stmt) -> Option<&Vec<u8>> {
    match stmt {
        Stmt::Asm { bytes, .. }
        | Stmt::Return { bytes, .. }
        | Stmt::Prologue { bytes, .. }
        | Stmt::Epilogue { bytes, .. }
        | Stmt::Save { bytes, .. }
        | Stmt::Restore { bytes, .. }
        | Stmt::IfReturn { bytes, .. }
        | Stmt::Goto { bytes, .. }
        | Stmt::IfGoto { bytes, .. }
        | Stmt::Switch { bytes, .. }
        | Stmt::ReturnExpr { bytes, .. }
        | Stmt::ArgSpill { bytes, .. }
        | Stmt::Call { bytes, .. }
        | Stmt::LocalSet { bytes, .. }
        | Stmt::LocalArith { bytes, .. }
        | Stmt::LocalCompound { bytes, .. }
        | Stmt::Move { bytes, .. }
        | Stmt::Inc16 { bytes, .. }
        | Stmt::SehInstall { bytes }
        | Stmt::SehRestore { bytes } => Some(bytes),
        Stmt::IfBranch { .. } | Stmt::Loop { .. } | Stmt::Label { .. } | Stmt::Comment(_) => None,
    }
}

/// Return a mutable reference to the `bytes: Vec<u8>` field of a
/// stmt that has one. Returns `None` for stmts that don't carry
/// bytes (Comment, Label, IfBranch, Loop — those have child
/// bytes rather than a single field) so the caller skips them.
fn stmt_bytes_field_mut(stmt: &mut Stmt) -> Option<&mut Vec<u8>> {
    match stmt {
        Stmt::Asm { bytes, .. }
        | Stmt::Return { bytes, .. }
        | Stmt::Prologue { bytes, .. }
        | Stmt::Epilogue { bytes, .. }
        | Stmt::Save { bytes, .. }
        | Stmt::Restore { bytes, .. }
        | Stmt::IfReturn { bytes, .. }
        | Stmt::Goto { bytes, .. }
        | Stmt::IfGoto { bytes, .. }
        | Stmt::Switch { bytes, .. }
        | Stmt::ReturnExpr { bytes, .. }
        | Stmt::ArgSpill { bytes, .. }
        | Stmt::Call { bytes, .. }
        | Stmt::LocalSet { bytes, .. }
        | Stmt::LocalArith { bytes, .. }
        | Stmt::LocalCompound { bytes, .. }
        | Stmt::Move { bytes, .. }
        | Stmt::Inc16 { bytes, .. }
        | Stmt::SehInstall { bytes }
        | Stmt::SehRestore { bytes } => Some(bytes),
        Stmt::IfBranch { .. } | Stmt::Loop { .. } | Stmt::Label { .. } | Stmt::Comment(_) => None,
    }
}

/// Walk the body and rewrite `ecx` references to `this` (the
/// thiscall convention puts the receiver in ECX) and `[ecx+N]`
/// accesses to `this->f_N`. Targets the rendered text only; the
/// pinned bytes are untouched, so round-trip is preserved.
fn rewrite_ecx_as_this(stmts: &mut [Stmt]) {
    for stmt in stmts.iter_mut() {
        rewrite_ecx_in_stmt(stmt);
    }
}

fn rewrite_ecx_in_stmt(stmt: &mut Stmt) {
    fn apply(text: &mut String) {
        let new_text = apply_this_rewrite(text);
        if new_text != *text {
            *text = new_text;
        }
    }
    match stmt {
        Stmt::Move { dst, src, .. } => {
            apply(dst);
            apply(src);
        }
        Stmt::Call { name, args, .. } => {
            apply(name);
            for a in args.iter_mut() {
                apply(a);
            }
        }
        Stmt::IfBranch {
            cond_text,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            apply(cond_text);
            rewrite_ecx_as_this(pre_body);
            rewrite_ecx_as_this(then_body);
            if let Some(eb) = else_body {
                rewrite_ecx_as_this(eb);
            }
        }
        Stmt::Loop {
            cond_text, body, ..
        } => {
            apply(cond_text);
            rewrite_ecx_as_this(body);
        }
        Stmt::ReturnExpr { text, .. } => apply(text),
        Stmt::IfReturn {
            cond_text,
            value_text,
            ..
        } => {
            apply(cond_text);
            apply(value_text);
        }
        Stmt::IfGoto { cond_text, .. } => apply(cond_text),
        _ => {}
    }
}

/// Map each parameter to the canonical entry register it occupies
/// under the function's ABI, when the param is integer-typed and
/// the ABI passes the first few integer args in registers.
///
/// Returns `(reg_name → param_name)` pairs covering every form of
/// the register the body might mention (e.g. `edi`/`rdi`/`di`).
/// Empty for non-register ABIs (cdecl/stdcall) or for functions
/// with no typed signature.
fn build_param_register_map(
    sig: Option<&Signature>,
    attrs: &[ud_ast::Attribute],
    bitness: ud_arch_x86::Bitness,
) -> Vec<(String, String)> {
    let Some(sig) = sig else {
        return Vec::new();
    };
    let abi = attrs.iter().find_map(|a| match (&a.key, &a.value) {
        (k, ud_ast::AttrValue::String(s)) if k == "abi" => Some(s.as_str()),
        _ => None,
    });
    // x86-64: SysV (rdi/rsi/rdx/rcx/r8/r9) vs Windows (rcx/rdx/r8/r9).
    // x86-32 cdecl/stdcall: stack-only, no register params.
    let regs64_sysv = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    let regs64_win = ["rcx", "rdx", "r8", "r9"];
    let is_ms = matches!(abi, Some("ms" | "win" | "microsoft"));
    let convention: &[&str] = match (bitness, is_ms) {
        (ud_arch_x86::Bitness::Bits64, true) => &regs64_win,
        (ud_arch_x86::Bitness::Bits64, false) => &regs64_sysv,
        _ => return Vec::new(),
    };
    let mut out: Vec<(String, String)> = Vec::new();
    let mut int_idx = 0usize;
    for p in &sig.params {
        if p.name.is_empty() {
            int_idx += 1;
            continue;
        }
        if int_idx >= convention.len() {
            break;
        }
        if !param_is_integer_like(&p.ty) {
            continue;
        }
        let reg64 = convention[int_idx];
        // Register the param under every common name the body
        // might use for that register.
        for view in register_views(reg64) {
            out.push(((*view).to_string(), p.name.clone()));
        }
        int_idx += 1;
    }
    out
}

fn param_is_integer_like(ty: &ud_ast::Type) -> bool {
    matches!(
        ty,
        ud_ast::Type::I8
            | ud_ast::Type::I16
            | ud_ast::Type::I32
            | ud_ast::Type::I64
            | ud_ast::Type::U8
            | ud_ast::Type::U16
            | ud_ast::Type::U32
            | ud_ast::Type::U64
            | ud_ast::Type::Bool
            | ud_ast::Type::Char
            | ud_ast::Type::Pointer(_)
            | ud_ast::Type::Unknown
    )
}

/// Return every register name the body might reference for a given
/// 64-bit register. e.g. `rdi` → `["rdi", "edi", "di", "dil"]`.
fn register_views(reg64: &str) -> &'static [&'static str] {
    match reg64 {
        "rdi" => &["rdi", "edi", "di", "dil"],
        "rsi" => &["rsi", "esi", "si", "sil"],
        "rdx" => &["rdx", "edx", "dx", "dl"],
        "rcx" => &["rcx", "ecx", "cx", "cl"],
        "r8" => &["r8", "r8d", "r8w", "r8b"],
        "r9" => &["r9", "r9d", "r9w", "r9b"],
        _ => &[],
    }
}

/// Walk the body and substitute reads of param-holding registers
/// with the parameter name. Maintains a set of registers still
/// believed to hold their entry value; removes a register when the
/// body writes to it, and clears all caller-saved on a Call.
fn rewrite_param_register_reads(stmts: &mut [Stmt], param_regs: &[(String, String)]) {
    let mut live: std::collections::HashMap<String, String> = param_regs.iter().cloned().collect();
    rewrite_param_in_seq(stmts, &mut live);
}

fn rewrite_param_in_seq(stmts: &mut [Stmt], live: &mut std::collections::HashMap<String, String>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Move { dst, src, .. } => {
                *src = substitute_word_tokens(src, live);
                // Writing to a register kills its entry-value
                // tracking. Cover all width-views so a write to
                // `edi` also invalidates `rdi`/`di`/`dil`.
                let invalidated = views_invalidated_by(dst);
                for v in invalidated {
                    live.remove(*v);
                }
            }
            Stmt::Call { name, args, .. } => {
                *name = substitute_word_tokens(name, live);
                for a in args.iter_mut() {
                    *a = substitute_word_tokens(a, live);
                }
                // Caller-saved registers get clobbered: in
                // SysV-x64 that's rdi/rsi/rdx/rcx/r8/r9/r10/r11
                // (and xmm0-15). Keep it simple: invalidate any
                // live register since we can't tell the callee's
                // calling convention here.
                live.clear();
            }
            Stmt::Asm { text, .. } | Stmt::ReturnExpr { text, .. } => {
                *text = substitute_word_tokens(text, live);
            }
            Stmt::IfBranch {
                cond_text,
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                *cond_text = substitute_word_tokens(cond_text, live);
                rewrite_param_in_seq(pre_body, live);
                let mut then_live = live.clone();
                rewrite_param_in_seq(then_body, &mut then_live);
                if let Some(eb) = else_body {
                    let mut else_live = live.clone();
                    rewrite_param_in_seq(eb, &mut else_live);
                }
                // Conservative: assume both arms could have
                // clobbered everything.
                live.clear();
            }
            Stmt::Loop {
                cond_text, body, ..
            } => {
                *cond_text = substitute_word_tokens(cond_text, live);
                rewrite_param_in_seq(body, live);
                live.clear();
            }
            Stmt::IfReturn {
                cond_text,
                value_text,
                ..
            } => {
                *cond_text = substitute_word_tokens(cond_text, live);
                *value_text = substitute_word_tokens(value_text, live);
            }
            Stmt::IfGoto { cond_text, .. } => {
                *cond_text = substitute_word_tokens(cond_text, live);
            }
            _ => {}
        }
    }
}

/// Conservative set of register-view names invalidated by writing
/// `dst`. Treats `edi` as a write to the full rdi family.
fn views_invalidated_by(dst: &str) -> &'static [&'static str] {
    match dst {
        "rdi" | "edi" | "di" | "dil" => &["rdi", "edi", "di", "dil"],
        "rsi" | "esi" | "si" | "sil" => &["rsi", "esi", "si", "sil"],
        "rdx" | "edx" | "dx" | "dl" => &["rdx", "edx", "dx", "dl"],
        "rcx" | "ecx" | "cx" | "cl" => &["rcx", "ecx", "cx", "cl"],
        "r8" | "r8d" | "r8w" | "r8b" => &["r8", "r8d", "r8w", "r8b"],
        "r9" | "r9d" | "r9w" | "r9b" => &["r9", "r9d", "r9w", "r9b"],
        _ => &[],
    }
}

/// Replace whole-word occurrences of any key in `subs` with its
/// associated value. Skips matches inside quoted strings and
/// matches that aren't on word boundaries (so `rdi` doesn't
/// substitute inside `rdival`). Char-based iteration so embedded
/// UTF-8 in string payloads passes through unchanged.
fn substitute_word_tokens(text: &str, subs: &std::collections::HashMap<String, String>) -> String {
    if subs.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut iter = text.char_indices().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some((i, c)) = iter.next() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push('"');
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            // Find the end of this identifier.
            let start = i;
            let mut end = i + c.len_utf8();
            while let Some(&(j, nc)) = iter.peek() {
                if nc.is_ascii_alphanumeric() || nc == '_' {
                    end = j + nc.len_utf8();
                    iter.next();
                } else {
                    break;
                }
            }
            let word = &text[start..end];
            // Reject matches preceded by `.` or `'` (member access
            // / quote-bracketed ids).
            let prev = text[..start].chars().last();
            let word_boundary_ok = prev.map_or(true, |p| !p.is_ascii_alphanumeric() && p != '_');
            if word_boundary_ok {
                if let Some(replacement) = subs.get(word) {
                    out.push_str(replacement);
                    continue;
                }
            }
            out.push_str(word);
            continue;
        }
        out.push(c);
    }
    out
}

/// Walk the body collecting every address that has a
/// `Stmt::Label { addr }` somewhere — those are the addresses
/// the `label_<hex>:` markers refer to and are the legitimate
/// targets a branch-target rewrite can substitute for.
fn collect_label_addrs(stmts: &[Stmt]) -> std::collections::HashSet<u64> {
    use std::collections::HashSet;
    let mut out: HashSet<u64> = HashSet::new();
    walk_collect_labels(stmts, &mut out);
    out
}

fn walk_collect_labels(stmts: &[Stmt], out: &mut std::collections::HashSet<u64>) {
    for s in stmts {
        match s {
            Stmt::Label { addr } => {
                out.insert(*addr);
            }
            Stmt::IfBranch {
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                walk_collect_labels(pre_body, out);
                walk_collect_labels(then_body, out);
                if let Some(eb) = else_body {
                    walk_collect_labels(eb, out);
                }
            }
            Stmt::Loop { body, .. } => walk_collect_labels(body, out),
            _ => {}
        }
    }
}

/// Replace `00000000000011E0h`-style full-width hex address
/// literals in `@asm` text with the matching `label_<hex>` name
/// when the address is known. Only touches Asm text — bytes and
/// other stmt kinds stay verbatim.
fn rewrite_label_refs(stmts: &mut [Stmt], labels: &std::collections::HashSet<u64>) {
    for stmt in stmts.iter_mut() {
        rewrite_label_refs_in_stmt(stmt, labels);
    }
}

fn rewrite_label_refs_in_stmt(stmt: &mut Stmt, labels: &std::collections::HashSet<u64>) {
    match stmt {
        Stmt::Asm { text, .. } => {
            let new_text = rewrite_label_refs_in_text(text, labels);
            if new_text != *text {
                *text = new_text;
            }
        }
        Stmt::IfBranch {
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            rewrite_label_refs(pre_body, labels);
            rewrite_label_refs(then_body, labels);
            if let Some(eb) = else_body {
                rewrite_label_refs(eb, labels);
            }
        }
        Stmt::Loop { body, .. } => rewrite_label_refs(body, labels),
        _ => {}
    }
}

fn rewrite_label_refs_in_text(text: &str, labels: &std::collections::HashSet<u64>) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    let mut iter = text.char_indices().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some((i, c)) = iter.next() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push('"');
            continue;
        }
        // A hex literal in iced's intel formatter takes the shape
        // `[0-9a-fA-F]+h` and is always preceded by a non-alphanumeric
        // char (operand boundary).
        if c.is_ascii_hexdigit() {
            let prev = text[..i].chars().last();
            let boundary_ok = prev.map_or(true, |p| !p.is_ascii_alphanumeric() && p != '_');
            if boundary_ok {
                let start = i;
                let mut end = i + c.len_utf8();
                while let Some(&(j, nc)) = iter.peek() {
                    if nc.is_ascii_hexdigit() {
                        end = j + nc.len_utf8();
                        iter.next();
                    } else {
                        break;
                    }
                }
                // Must be followed by `h` to be a hex literal.
                if let Some(&(j, 'h')) = iter.peek() {
                    let hex = &text[start..end];
                    if let Ok(addr) = u64::from_str_radix(hex, 16) {
                        if labels.contains(&addr) {
                            iter.next(); // consume the `h`
                            let _ = j;
                            let _ = write!(out, "label_{addr:x}");
                            continue;
                        }
                    }
                }
                // Not a label hit: emit the digit run verbatim.
                out.push_str(&text[start..end]);
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Build a `(offset → name)` map of the function's stack locals
/// for the stack-slot rewrite pass. Negative offsets (the
/// `var_<hex>` decls) and positive offsets (the `arg_<hex>`
/// decls) are pulled in; non-stack locals are ignored.
fn build_stack_local_map(locals: &[ud_ast::LocalDecl]) -> Vec<(i64, String)> {
    let mut out: Vec<(i64, String)> = Vec::new();
    for l in locals {
        if !matches!(l.kind, ud_ast::LocalKind::Stack) {
            continue;
        }
        if let Some(rest) = l.name.strip_prefix("var_") {
            if let Ok(n) = i64::from_str_radix(rest, 16) {
                out.push((-n, l.name.clone()));
            }
        } else if let Some(rest) = l.name.strip_prefix("arg_") {
            if let Ok(n) = i64::from_str_radix(rest, 16) {
                out.push((n, l.name.clone()));
            }
        }
    }
    out
}

/// Walk every text field in `stmts` and substitute `[rbp±N]` /
/// `[ebp±N]` / size-prefixed forms with the matching local name.
/// Pure text rewrite — bytes are untouched, round-trip is safe.
fn rewrite_stack_refs(stmts: &mut [Stmt], map: &[(i64, String)]) {
    for stmt in stmts.iter_mut() {
        rewrite_stack_refs_in_stmt(stmt, map);
    }
}

fn rewrite_stack_refs_in_stmt(stmt: &mut Stmt, map: &[(i64, String)]) {
    fn apply(text: &mut String, map: &[(i64, String)]) {
        let new_text = rewrite_stack_refs_in_text(text, map);
        if new_text != *text {
            *text = new_text;
        }
    }
    match stmt {
        Stmt::Move { dst, src, .. } => {
            apply(dst, map);
            apply(src, map);
        }
        Stmt::Call { name, args, .. } => {
            apply(name, map);
            for a in args.iter_mut() {
                apply(a, map);
            }
        }
        Stmt::Asm { text, .. } | Stmt::ReturnExpr { text, .. } => apply(text, map),
        Stmt::IfBranch {
            cond_text,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            apply(cond_text, map);
            rewrite_stack_refs(pre_body, map);
            rewrite_stack_refs(then_body, map);
            if let Some(eb) = else_body {
                rewrite_stack_refs(eb, map);
            }
        }
        Stmt::Loop {
            cond_text, body, ..
        } => {
            apply(cond_text, map);
            rewrite_stack_refs(body, map);
        }
        Stmt::IfReturn {
            cond_text,
            value_text,
            ..
        } => {
            apply(cond_text, map);
            apply(value_text, map);
        }
        Stmt::IfGoto { cond_text, .. } => apply(cond_text, map),
        _ => {}
    }
}

/// One pass over `text` replacing `[rbp±N]` (with optional size
/// prefix and `0x`/decimal offsets) with the matching local
/// name. Operates outside quoted strings to avoid corrupting
/// `@asm("…")` payloads that happen to mention `[rbp-4]` in
/// some embedded context.
fn rewrite_stack_refs_in_text(text: &str, map: &[(i64, String)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut iter = text.char_indices().peekable();
    let mut in_string = false;
    let mut escape = false;
    while let Some((i, c)) = iter.next() {
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push('"');
            continue;
        }
        // Only attempt the substitution when the char could start
        // one of the patterns (`[`, or a size prefix's leading
        // letter). Char-based iteration avoids UTF-8 slicing
        // panics on `@asm("…")` string-literal payloads that can
        // contain multibyte chars like `…`.
        if matches!(c, '[' | 'd' | 'q' | 'w' | 'b' | 'x' | 't') {
            if let Some((name, consumed)) = try_match_stack_ref(&text[i..], map) {
                out.push_str(name);
                // Advance `iter` past the consumed range so the
                // outer loop continues from the new position.
                let target = i + consumed;
                while iter.peek().is_some_and(|&(j, _)| j < target) {
                    iter.next();
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// At `text`'s start, try to match `[<size> ptr ]?[(r|e)bp(\s*[+-]\s*(0x[0-9a-f]+|[0-9]+))?]`.
/// Returns the matching local name + bytes consumed.
fn try_match_stack_ref<'a>(text: &str, map: &'a [(i64, String)]) -> Option<(&'a String, usize)> {
    let lc_full = text.to_ascii_lowercase();
    let bytes = lc_full.as_bytes();
    let mut i = 0;
    // Optional size prefix.
    for prefix in &[
        "xmmword ptr ",
        "qword ptr ",
        "dword ptr ",
        "word ptr ",
        "byte ptr ",
        "tbyte ptr ",
    ] {
        if lc_full[i..].starts_with(prefix) {
            i += prefix.len();
            break;
        }
    }
    if !lc_full[i..].starts_with("[rbp") && !lc_full[i..].starts_with("[ebp") {
        return None;
    }
    i += 4; // past `[rbp` / `[ebp`
            // Skip whitespace.
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    // Bare `[rbp]` → offset 0.
    if i < bytes.len() && bytes[i] == b']' {
        let name = map.iter().find(|(off, _)| *off == 0).map(|(_, n)| n)?;
        return Some((name, i + 1));
    }
    let sign: i64 = match bytes.get(i) {
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return None,
    };
    i += 1;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    let num_start = i;
    let value: i64 = if lc_full[i..].starts_with("0x") {
        i += 2;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i == num_start + 2 {
            return None;
        }
        i64::from_str_radix(&lc_full[num_start + 2..i], 16).ok()?
    } else {
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i == num_start {
            return None;
        }
        // Intel hex suffix (`18h`): if the digit run is followed
        // by `h` and contains at least one hex letter OR the run
        // is followed by `h]`, treat as hex. Otherwise decimal.
        if bytes.get(i) == Some(&b'h') {
            let v = i64::from_str_radix(&lc_full[num_start..i], 16).ok()?;
            i += 1; // consume the `h`
            v
        } else {
            // Decimal fallback. Require pure decimal digits, since
            // we accepted hex digits above for the `h`-suffix case.
            if lc_full[num_start..i].bytes().all(|b| b.is_ascii_digit()) {
                lc_full[num_start..i].parse::<i64>().ok()?
            } else {
                return None;
            }
        }
    };
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if bytes.get(i) != Some(&b']') {
        return None;
    }
    i += 1;
    let offset = sign * value;
    let name = map.iter().find(|(off, _)| *off == offset).map(|(_, n)| n)?;
    Some((name, i))
}

/// Substitute occurrences of `ecx` (at word boundaries, outside
/// quoted strings) with `this`, and `[ecx + N]` with `this->f_N`.
/// Both substitutions are conservative — they only fire when the
/// surrounding text shape clearly maps to the rewrite.
fn apply_this_rewrite(text: &str) -> String {
    // First: replace `[ecx]` and `[ecx + N]` / `[ecx+N]` with
    // the structured-field form. We scan for `[ecx` at word
    // boundaries; the bracketed sub-expression is then rewritten
    // up to the matching `]`.
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // `[ecx` — must be at the start of a bracketed expression.
        if i + 4 <= bytes.len() && &bytes[i..i + 4] == b"[ecx" {
            // Find the matching `]`.
            let mut depth = 1;
            let mut j = i + 4;
            while j < bytes.len() {
                match bytes[j] {
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if j < bytes.len() && depth == 0 {
                let inner = std::str::from_utf8(&bytes[i + 1..j]).unwrap_or("");
                if let Some(field) = parse_ecx_field(inner) {
                    out.push_str(&field);
                    i = j + 1;
                    continue;
                }
            }
        }
        // `ecx` at word boundaries outside strings → `this`.
        if word_at(bytes, i, b"ecx") {
            out.push_str("this");
            i += 3;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn word_at(bytes: &[u8], i: usize, word: &[u8]) -> bool {
    if i + word.len() > bytes.len() {
        return false;
    }
    if &bytes[i..i + word.len()] != word {
        return false;
    }
    let prev_is_ident = i > 0 && is_ident_byte(bytes[i - 1]);
    let next_is_ident = i + word.len() < bytes.len() && is_ident_byte(bytes[i + word.len()]);
    !prev_is_ident && !next_is_ident
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Recognise the inside of a `[ecx…]` bracketed expression and
/// turn it into a struct-field reference. Recognised shapes:
///
/// * `ecx` alone → `this->f_0`
/// * `ecx + N`, `ecx + 0xN`, `ecx + Nh` → `this->f_<N>`
/// * `ecx - N` → `this->f_minus_<N>` (rare; negative offsets
///   normally don't appear off `this`, but we render rather than
///   bail so the rewrite stays predictable)
fn parse_ecx_field(inner: &str) -> Option<String> {
    let s = inner.trim();
    if s == "ecx" {
        return Some("this->f_0".to_string());
    }
    let rest = s.strip_prefix("ecx")?;
    let rest = rest.trim();
    let sign = if let Some(r) = rest.strip_prefix('+') {
        ("", r)
    } else if let Some(r) = rest.strip_prefix('-') {
        ("minus_", r)
    } else {
        return None;
    };
    let raw = sign.1.trim();
    let parsed = parse_simple_uint(raw)?;
    Some(format!("this->f_{}{:x}", sign.0, parsed))
}

fn parse_simple_uint(s: &str) -> Option<u64> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        return u64::from_str_radix(rest, 16).ok();
    }
    s.parse::<u64>().ok()
}

/// Detect MSVC's Structured Exception Handling frame install /
/// restore pattern and lift the `Stmt::Move`s that touch `fs:[0]`
/// into dedicated `Stmt::SehInstall` / `Stmt::SehRestore`
/// directives. The bytes are unchanged; only the rendering shifts
/// from a low-level `fs:[0] = esp` assignment to a clearly-named
/// SEH marker so the reader knows the function uses __try/__except.
fn fold_seh_frame(stmts: &mut [Stmt]) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Move { dst, src, bytes } if dst == "fs:[0]" => {
                let bytes = std::mem::take(bytes);
                if src == "esp" {
                    *stmt = Stmt::SehInstall { bytes };
                } else {
                    *stmt = Stmt::SehRestore { bytes };
                }
            }
            Stmt::IfBranch {
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                fold_seh_frame(pre_body);
                fold_seh_frame(then_body);
                if let Some(eb) = else_body {
                    fold_seh_frame(eb);
                }
            }
            Stmt::Loop { body, .. } => fold_seh_frame(body),
            _ => {}
        }
    }
}

/// Detect and lift MSVC's switch-via-jump-table idiom. The
/// compiler emits a three-instruction triple for `switch(reg)`:
///
/// ```text
/// cmp reg, MAX       ; bounds check
/// ja  default        ; out-of-range branch
/// jmp [TABLE+reg*4]  ; indirect dispatch via jump table
/// ```
///
/// The first two end up as a single `@asm("cmp reg,MAX; ja …")`
/// statement (the `cmp_jcc` pattern merges them); the third is
/// its own `@asm("jmp …")` line. We pair adjacent matches,
/// read `MAX+1` consecutive 32-bit code-pointer entries from the
/// data section at TABLE, and produce a `Stmt::Switch`. Both
/// `@asm` Stmts' bytes are concatenated onto the new directive
/// so round-trip is preserved.
fn fold_switch_jump_tables(
    stmts: &mut Vec<Stmt>,
    base_ip: u64,
    bitness: ud_arch_x86::Bitness,
    data: &dyn DataLookup,
) {
    let mut cursor = base_ip;
    let mut i = 0;
    while i < stmts.len() {
        let cmp_start = cursor;
        let cmp_bytes_len = stmt_total_bytes(&stmts[i]) as u64;
        // Find the next byte-bearing stmt past zero-byte
        // intermediates (comments, labels). The cmp+ja text was
        // emitted between block boundaries, so the indirect jmp
        // may sit a few comment lines later.
        let mut j = i + 1;
        let mut between_bytes: u64 = 0;
        while j < stmts.len() {
            let len = stmt_total_bytes(&stmts[j]);
            if len > 0 {
                break;
            }
            between_bytes += len as u64;
            j += 1;
        }
        let _ = between_bytes; // always 0 since we skipped only zero-byte stmts
        if let Some(jmp_idx) = (j < stmts.len()).then_some(j) {
            let jmp_start = cursor + cmp_bytes_len;
            if let Some(switch_stmt) = try_switch_pair(
                &stmts[i],
                &stmts[jmp_idx],
                cmp_start,
                jmp_start,
                bitness,
                data,
            ) {
                stmts[i] = switch_stmt;
                // Remove everything between i+1 and jmp_idx
                // (inclusive of jmp_idx).
                for _ in i + 1..=jmp_idx {
                    stmts.remove(i + 1);
                }
                cursor += stmt_total_bytes(&stmts[i]) as u64;
                i += 1;
                continue;
            }
        }
        cursor += cmp_bytes_len;
        i += 1;
    }
}

/// Try to recognise an adjacent (cmp+ja, jmp[table+reg*4]) pair
/// and build a `Stmt::Switch` from it. Returns `None` for any
/// mismatch.
fn try_switch_pair(
    a: &Stmt,
    b: &Stmt,
    a_ip: u64,
    b_ip: u64,
    bitness: ud_arch_x86::Bitness,
    data: &dyn DataLookup,
) -> Option<Stmt> {
    use ud_arch_x86::{FlowControl, Mnemonic};
    let (a_text, a_bytes) = match a {
        Stmt::Asm { text, bytes } => (text.as_str(), bytes.as_slice()),
        _ => return None,
    };
    let (b_text, b_bytes) = match b {
        Stmt::Asm { text, bytes } => (text.as_str(), bytes.as_slice()),
        _ => return None,
    };
    // Both must look like the canonical Intel form we expect.
    if !(a_text.starts_with("cmp ") && a_text.contains(';') && a_text.contains("ja ")) {
        return None;
    }
    if !b_text.starts_with("jmp ") {
        return None;
    }
    // Decode the cmp+ja Stmt. It may have leading flag-preserving
    // instructions (lea / mov) that dead-store folding merged in;
    // the cmp+ja pair we care about is at the end.
    let a_insns = ud_arch_x86::decode(bitness, a_bytes, a_ip).ok()?;
    if a_insns.len() < 2 {
        return None;
    }
    let cmp_insn = a_insns.iter().rev().nth(1)?;
    let ja_insn = a_insns.last()?;
    if cmp_insn.iced.mnemonic() != Mnemonic::Cmp {
        return None;
    }
    if ja_insn.iced.mnemonic() != Mnemonic::Ja {
        return None;
    }
    // Selector register is the first cmp operand; MAX is the
    // immediate the cmp compares against.
    let selector_reg = crate::ssa::canonical_reg_name(cmp_insn.iced.op0_register())?;
    let max_val = u64::from(cmp_insn.iced.immediate32());
    let default_addr = ja_insn.iced.near_branch_target();
    if default_addr == 0 {
        return None;
    }
    // Decode the indirect jmp; need its memory base + scale +
    // displacement to locate the jump-table data.
    let b_insns = ud_arch_x86::decode(bitness, b_bytes, b_ip).ok()?;
    if b_insns.len() != 1 {
        return None;
    }
    let jmp = &b_insns[0];
    if jmp.iced.flow_control() != FlowControl::IndirectBranch {
        return None;
    }
    // Expect `jmp [base + index*scale + disp]`. The scale must be 4
    // for a u32 jump table; the disp is the table VA.
    if jmp.iced.memory_index_scale() != 4 {
        return None;
    }
    if jmp.iced.op_count() != 1 || jmp.iced.op_kind(0) != ud_arch_x86::OpKind::Memory {
        return None;
    }
    let table_va = jmp.iced.memory_displacement64();
    let case_count = max_val.checked_add(1)?;
    if case_count > 4096 {
        return None;
    }
    // Read MAX+1 dword pointers from the data section.
    let (_, sec_data, off) = data.section_at(table_va)?;
    let bytes_needed = case_count.checked_mul(4)? as usize;
    let slice = sec_data.get(off..off.checked_add(bytes_needed)?)?;
    // Jump-table entries are absolute VAs on PE32 (loader stamps
    // them in via relocations). Convert each to the RVA form
    // the rest of the pipeline uses for labels so the rendered
    // `case N: goto label_<rva>;` lines reference the labels we
    // actually insert in the function body.
    let image_base = data.image_base();
    let mut cases: Vec<u64> = Vec::with_capacity(case_count as usize);
    for i in 0..case_count as usize {
        let raw = &slice[i * 4..i * 4 + 4];
        let absolute = u64::from(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]));
        let rva = absolute.saturating_sub(image_base);
        cases.push(rva);
    }
    let mut bytes = Vec::with_capacity(a_bytes.len() + b_bytes.len());
    bytes.extend_from_slice(a_bytes);
    bytes.extend_from_slice(b_bytes);
    let _ = selector_reg.clone();
    Some(Stmt::Switch {
        selector: selector_reg,
        cases,
        default_addr,
        bytes,
    })
}

/// Walk every `Stmt::Asm` and rewrite the small set of x86
/// string-instruction idioms into synthetic `Stmt::Call`s that
/// read like the C library function they implement:
///
/// * `rep movsb [edi], [esi]` → `memcpy(edi, esi, ecx)`
/// * `rep movsd [edi], [esi]` → `memcpy_d(edi, esi, ecx)`
///   (the `_d` reminder that ecx counts dwords, not bytes)
/// * `rep stosb [edi]` → `memset(edi, al, ecx)`
/// * `rep stosd [edi]` → `memset_d(edi, eax, ecx)`
/// * `repe cmpsb [esi], [edi]` → `memcmp(esi, edi, ecx)`
/// * `repne scasb [edi]` → `strlen_aux(edi, eax, ecx)`
///
/// Bytes stay pinned on the new `Call`; the byte stream is
/// unchanged. The rendering shift makes the function read at the
/// C-library level (the compiler's intent) rather than the
/// x86-instruction level (the encoding).
fn recognise_string_idioms(stmts: &mut [Stmt]) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Asm { text, bytes } => {
                if let Some((name, args)) = string_idiom_lift(text) {
                    *stmt = Stmt::Call {
                        name: name.into(),
                        args: args.into_iter().map(str::to_string).collect(),
                        bytes: std::mem::take(bytes),
                    };
                }
            }
            Stmt::IfBranch {
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                recognise_string_idioms(pre_body);
                recognise_string_idioms(then_body);
                if let Some(eb) = else_body {
                    recognise_string_idioms(eb);
                }
            }
            Stmt::Loop { body, .. } => {
                recognise_string_idioms(body);
            }
            _ => {}
        }
    }
}

/// Map an `@asm` text to a `(call_name, args)` pair when it
/// matches one of the recognised string-instruction idioms.
/// Returns `None` for any other text.
fn string_idiom_lift(text: &str) -> Option<(&'static str, Vec<&'static str>)> {
    // Canonical Intel forms produced by iced; we match the
    // operand string verbatim so order/spacing stays predictable.
    Some(match text {
        "rep movsb [edi],[esi]" => ("memcpy", vec!["edi", "esi", "ecx"]),
        "rep movsd [edi],[esi]" => ("memcpy_d", vec!["edi", "esi", "ecx"]),
        "rep movsw [edi],[esi]" => ("memcpy_w", vec!["edi", "esi", "ecx"]),
        "rep movsq [rdi],[rsi]" => ("memcpy_q", vec!["rdi", "rsi", "rcx"]),
        "rep stosb [edi]" => ("memset", vec!["edi", "al", "ecx"]),
        "rep stosd [edi]" => ("memset_d", vec!["edi", "eax", "ecx"]),
        "rep stosw [edi]" => ("memset_w", vec!["edi", "ax", "ecx"]),
        "rep stosq [rdi]" => ("memset_q", vec!["rdi", "rax", "rcx"]),
        "repe cmpsb [esi],[edi]" => ("memcmp", vec!["esi", "edi", "ecx"]),
        "repe cmpsd [esi],[edi]" => ("memcmp_d", vec!["esi", "edi", "ecx"]),
        "repne scasb [edi]" => ("strlen_aux", vec!["edi", "al", "ecx"]),
        "repne scasd [edi]" => ("scan_d", vec!["edi", "eax", "ecx"]),
        _ => return None,
    })
}

/// Local structural-recovery pass: convert
/// `IfGoto(cond, L); …body…; Label(L)` triples into an
/// `IfBranch` with `cond_text = invert(cond)` and the body as
/// `then_body`. Only fires when the body is a single-entry
/// single-exit region (no other labels, no escaping gotos),
/// since restructuring around extra entries/exits would change
/// the semantic meaning of `goto L` references elsewhere.
///
/// Round-trip: the IfBranch's bytes are `cond_bytes` (the
/// original cmp+jcc) + the body's bytes — identical to the
/// pre-lift layout. The `Label(L)` stays after the IfBranch
/// (zero bytes) so any subsequent code that gotos into L still
/// finds its target.
#[allow(clippy::match_same_arms)]
fn fold_local_if_skip(stmts: &mut Vec<Stmt>, _bitness: ud_arch_x86::Bitness) {
    let mut i = 0;
    while i < stmts.len() {
        let Stmt::IfGoto {
            target_addr: skip_to,
            ..
        } = &stmts[i]
        else {
            i += 1;
            continue;
        };
        let skip_to = *skip_to;
        // Find a `Label(skip_to)` at the same level, with no
        // other labels or gotos pointing outside the body in
        // between.
        let mut body_end: Option<usize> = None;
        for (j, s) in stmts.iter().enumerate().skip(i + 1) {
            // Stop when we reach our target label, or any other
            // boundary that would make the body's CFG escape the
            // simple skip pattern.
            let stop = match s {
                Stmt::Label { addr } if *addr == skip_to => true,
                Stmt::Label { .. } => true,
                Stmt::Goto { target_addr, .. } => *target_addr != skip_to,
                Stmt::IfGoto { target_addr, .. } => *target_addr != skip_to,
                Stmt::Switch { .. } | Stmt::IfReturn { .. } => true,
                _ => false,
            };
            if stop {
                if matches!(s, Stmt::Label { addr } if *addr == skip_to) {
                    body_end = Some(j);
                }
                break;
            }
        }
        let Some(end_idx) = body_end else {
            i += 1;
            continue;
        };
        if end_idx == i + 1 {
            // Empty body — not worth restructuring.
            i += 1;
            continue;
        }
        // Pull the IfGoto out, gather the body, build the IfBranch.
        let (cond_text_inverted, cond_bytes) = match stmts.remove(i) {
            Stmt::IfGoto {
                cond_text, bytes, ..
            } => (invert_relational_cond(&cond_text), bytes),
            _ => unreachable!(),
        };
        // After removing the IfGoto, body indices i..end_idx-1
        // (end_idx shifted by 1).
        let body_count = end_idx - i - 1;
        let body: Vec<Stmt> = stmts.drain(i..i + body_count).collect();
        stmts.insert(
            i,
            Stmt::IfBranch {
                cond_text: cond_text_inverted,
                cond_bytes,
                attrs: Vec::new(),
                pre_body: Vec::new(),
                then_body: body,
                else_body: None,
            },
        );
        i += 1;
    }
}

/// Convert remaining `@asm("jmp …")` / `@asm("cmp/test …; jcc …")`
/// statements into `Stmt::Goto` / `Stmt::IfGoto`, and insert
/// `Stmt::Label` markers at the (function-local) target
/// addresses. Bytes are pinned on the new directives so round-
/// trip stays exact; only the surface form changes.
///
/// This is the unconditional fallback for the structural lifters:
/// anything they couldn't fold into an `IfBranch`, `Loop`,
/// `IfReturn`, etc. ends up here as named goto + label.
fn fold_gotos_and_labels(stmts: &mut Vec<Stmt>, base_ip: u64, bitness: ud_arch_x86::Bitness) {
    let func_end = base_ip + stmts_total_bytes(stmts) as u64;
    // Pass 1: walk the body, decode each `@asm` candidate, collect
    // (path, target_addr, kind, cond_text) tuples for the ones we
    // can fold.
    let mut targets: HashSet<u64> = HashSet::new();
    collect_goto_targets(stmts, base_ip, bitness, base_ip, func_end, &mut targets);
    // Pass 2: rewrite matching `@asm` Stmts in place.
    let mut cursor = base_ip;
    rewrite_gotos_in_seq(stmts, &mut cursor, base_ip, func_end, bitness);
    // Pass 3: insert `Stmt::Label { addr }` at every block start
    // that's referenced by a goto / if-goto. Walk in lower order,
    // tracking the cursor; when the cursor matches a target we
    // haven't placed a label for yet, splice in a Label before the
    // next stmt.
    insert_labels_at_targets(stmts, base_ip, &targets);
}

/// Walk the body in lower-order, finding every `@asm` Stmt that
/// looks like an unconditional or conditional jump to a target
/// within the function. Stores each such target's address in
/// `out`.
fn collect_goto_targets(
    stmts: &[Stmt],
    cursor_start: u64,
    bitness: ud_arch_x86::Bitness,
    fn_start: u64,
    fn_end: u64,
    out: &mut HashSet<u64>,
) {
    let mut cursor = cursor_start;
    for stmt in stmts {
        match stmt {
            Stmt::Asm { bytes, .. } => {
                if let Some(target) = jump_target_of(bytes, cursor, bitness) {
                    if target >= fn_start && target < fn_end {
                        out.insert(target);
                    }
                }
                cursor += bytes.len() as u64;
            }
            Stmt::Switch {
                cases,
                default_addr,
                bytes,
                ..
            } => {
                for &c in cases {
                    if c >= fn_start && c < fn_end {
                        out.insert(c);
                    }
                }
                if *default_addr >= fn_start && *default_addr < fn_end {
                    out.insert(*default_addr);
                }
                cursor += bytes.len() as u64;
            }
            Stmt::Goto { target_addr, bytes }
            | Stmt::IfGoto {
                target_addr, bytes, ..
            } => {
                if *target_addr >= fn_start && *target_addr < fn_end {
                    out.insert(*target_addr);
                }
                cursor += bytes.len() as u64;
            }
            Stmt::IfBranch {
                attrs,
                cond_bytes,
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                let mut sub = cursor;
                if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                    sub += hb.len() as u64;
                }
                collect_goto_targets(pre_body, sub, bitness, fn_start, fn_end, out);
                sub += stmts_total_bytes(pre_body) as u64 + cond_bytes.len() as u64;
                collect_goto_targets(then_body, sub, bitness, fn_start, fn_end, out);
                if let Some(eb) = else_body {
                    sub += stmts_total_bytes(then_body) as u64;
                    collect_goto_targets(eb, sub, bitness, fn_start, fn_end, out);
                }
                cursor += stmt_total_bytes(stmt) as u64;
            }
            Stmt::Loop {
                entry_jmp_bytes,
                body,
                ..
            } => {
                let mut sub = cursor;
                if let Some(jmp) = entry_jmp_bytes {
                    sub += jmp.len() as u64;
                }
                collect_goto_targets(body, sub, bitness, fn_start, fn_end, out);
                cursor += stmt_total_bytes(stmt) as u64;
            }
            _ => {
                cursor += stmt_total_bytes(stmt) as u64;
            }
        }
    }
}

/// Decode `bytes` at `ip` and report the jump target if the bytes
/// decode to a single direct branch (`jmp rel`, `jcc rel`, or a
/// `cmp/test + jcc` pair where the jcc is the second instruction).
/// Returns `None` for indirect jumps, calls, or anything else.
fn jump_target_of(bytes: &[u8], ip: u64, bitness: ud_arch_x86::Bitness) -> Option<u64> {
    use ud_arch_x86::FlowControl;
    let insns = ud_arch_x86::decode(bitness, bytes, ip).ok()?;
    if insns.is_empty() {
        return None;
    }
    // The branch is the *last* decoded instruction (the leading
    // ones are cmp/test/etc that set flags).
    let last = insns.last()?;
    let flow = last.iced.flow_control();
    if !matches!(
        flow,
        FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
    ) {
        return None;
    }
    let target = last.iced.near_branch_target();
    if target == 0 {
        return None;
    }
    Some(target)
}

/// Pass 2 of the goto/label fold: walk the body, when we find an
/// `@asm` Stmt whose bytes decode to a direct branch with a
/// function-local target, rewrite it as `Goto` (unconditional) or
/// `IfGoto` (conditional).
fn rewrite_gotos_in_seq(
    stmts: &mut [Stmt],
    cursor: &mut u64,
    fn_start: u64,
    fn_end: u64,
    bitness: ud_arch_x86::Bitness,
) {
    for stmt in stmts.iter_mut() {
        let stmt_start = *cursor;
        let advance = stmt_total_bytes(stmt) as u64;
        let mut replaced = false;
        if let Stmt::Asm { text: _, bytes } = stmt {
            if let Some(target) = jump_target_of(bytes, stmt_start, bitness) {
                if target >= fn_start && target < fn_end {
                    let bytes_owned = bytes.clone();
                    let new_stmt = make_goto_stmt(&bytes_owned, stmt_start, target, bitness);
                    if let Some(s) = new_stmt {
                        *stmt = s;
                        replaced = true;
                    }
                }
            }
        }
        if !replaced {
            match stmt {
                Stmt::IfBranch {
                    attrs,
                    cond_bytes,
                    pre_body,
                    then_body,
                    else_body,
                    ..
                } => {
                    let mut sub = *cursor;
                    if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                        sub += hb.len() as u64;
                    }
                    rewrite_gotos_in_seq(pre_body, &mut sub, fn_start, fn_end, bitness);
                    sub += cond_bytes.len() as u64;
                    rewrite_gotos_in_seq(then_body, &mut sub, fn_start, fn_end, bitness);
                    if let Some(eb) = else_body {
                        rewrite_gotos_in_seq(eb, &mut sub, fn_start, fn_end, bitness);
                    }
                }
                Stmt::Loop {
                    entry_jmp_bytes,
                    body,
                    ..
                } => {
                    let mut sub = *cursor;
                    if let Some(jmp) = entry_jmp_bytes {
                        sub += jmp.len() as u64;
                    }
                    rewrite_gotos_in_seq(body, &mut sub, fn_start, fn_end, bitness);
                }
                _ => {}
            }
        }
        *cursor += advance;
    }
}

/// Build a `Goto` or `IfGoto` for the @asm-bytes/IP that target a
/// known location. Returns `None` if decoding fails.
fn make_goto_stmt(
    bytes: &[u8],
    ip: u64,
    target_addr: u64,
    bitness: ud_arch_x86::Bitness,
) -> Option<Stmt> {
    use ud_arch_x86::{FlowControl, Mnemonic};
    let insns = ud_arch_x86::decode(bitness, bytes, ip).ok()?;
    let last = insns.last()?;
    match last.iced.flow_control() {
        FlowControl::UnconditionalBranch => {
            // Pure `jmp` — but if there are insns before, we'd
            // mis-classify (e.g., setcc + jmp). Limit to single-
            // instruction shape.
            if insns.len() != 1 {
                return None;
            }
            Some(Stmt::Goto {
                target_addr,
                bytes: bytes.to_vec(),
            })
        }
        FlowControl::ConditionalBranch => {
            let cond_text = if insns.len() == 1 {
                // Bare jcc — render against the flags only ("flags
                // set elsewhere"). Iced gives us the mnemonic; map
                // to a readable form via inverted body_operator.
                jcc_mnemonic_to_text(last.iced.mnemonic())?
            } else if insns.len() == 2 {
                let cmp = &insns[0];
                if !matches!(cmp.iced.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
                    return None;
                }
                let body_form = ud_arch_x86::render_cond_source(&cmp.iced, &last.iced);
                invert_relational_cond(&body_form)
            } else {
                return None;
            };
            Some(Stmt::IfGoto {
                cond_text,
                target_addr,
                bytes: bytes.to_vec(),
            })
        }
        _ => None,
    }
}

/// Render a bare jcc's positive condition. Used when the `@asm`
/// has only the jcc instruction (the cmp/test was folded into a
/// previous stmt or happened across a block boundary). Reads
/// like `flags.zero`, `flags.signed_lt`, etc. — a clear textual
/// hint that the flags were set elsewhere.
fn jcc_mnemonic_to_text(m: ud_arch_x86::Mnemonic) -> Option<String> {
    use ud_arch_x86::Mnemonic;
    let s = match m {
        Mnemonic::Je => "flags.zero",
        Mnemonic::Jne => "!flags.zero",
        Mnemonic::Jl => "flags.signed_lt",
        Mnemonic::Jle => "flags.signed_le",
        Mnemonic::Jg => "flags.signed_gt",
        Mnemonic::Jge => "flags.signed_ge",
        Mnemonic::Jb => "flags.below",
        Mnemonic::Jbe => "flags.below_or_eq",
        Mnemonic::Ja => "flags.above",
        Mnemonic::Jae => "flags.above_or_eq",
        Mnemonic::Js => "flags.sign",
        Mnemonic::Jns => "!flags.sign",
        Mnemonic::Jp => "flags.parity",
        Mnemonic::Jnp => "!flags.parity",
        Mnemonic::Jo => "flags.overflow",
        Mnemonic::Jno => "!flags.overflow",
        _ => return None,
    };
    Some(s.to_string())
}

/// Pass 3 of the goto/label fold: walk the body and insert
/// `Stmt::Label { addr }` markers immediately before any stmt
/// whose IP equals one of the recorded target addresses. Idempotent
/// for the entry IP (we don't add a label at function start since
/// nothing can jump to it from within).
fn insert_labels_at_targets(stmts: &mut Vec<Stmt>, base_ip: u64, targets: &HashSet<u64>) {
    insert_labels_in_seq(stmts, base_ip, targets);
}

fn insert_labels_in_seq(stmts: &mut Vec<Stmt>, base_ip: u64, targets: &HashSet<u64>) -> u64 {
    let mut cursor = base_ip;
    let mut i = 0;
    let mut labeled_at: HashSet<u64> = HashSet::new();
    while i < stmts.len() {
        let stmt_start = cursor;
        // Skip past zero-byte stmts already at this IP that
        // already represent the label (or unrelated metadata).
        if matches!(&stmts[i], Stmt::Label { addr } if *addr == stmt_start) {
            labeled_at.insert(stmt_start);
        }
        if stmt_start != base_ip
            && targets.contains(&stmt_start)
            && !labeled_at.contains(&stmt_start)
        {
            stmts.insert(i, Stmt::Label { addr: stmt_start });
            labeled_at.insert(stmt_start);
            i += 1;
        }
        // Recurse into nested bodies so labels can land inside
        // structured arms too.
        let mut sub_handled = false;
        match &mut stmts[i] {
            Stmt::IfBranch {
                attrs,
                cond_bytes,
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                let mut sub = stmt_start;
                if let Some(hb) = ud_ast_head_bytes_attr(attrs) {
                    sub += hb.len() as u64;
                }
                let after_pre = insert_labels_in_seq(pre_body, sub, targets);
                let after_cond = after_pre + cond_bytes.len() as u64;
                let after_then = insert_labels_in_seq(then_body, after_cond, targets);
                if let Some(eb) = else_body {
                    insert_labels_in_seq(eb, after_then, targets);
                }
                sub_handled = true;
            }
            Stmt::Loop {
                entry_jmp_bytes,
                body,
                ..
            } => {
                let mut sub = stmt_start;
                if let Some(jmp) = entry_jmp_bytes {
                    sub += jmp.len() as u64;
                }
                insert_labels_in_seq(body, sub, targets);
                sub_handled = true;
            }
            _ => {}
        }
        let _ = sub_handled;
        cursor += stmt_total_bytes(&stmts[i]) as u64;
        i += 1;
    }
    cursor
}

fn absorb_save_restore(stmts: &mut [Stmt]) {
    // Phase 1: walk the scope (inlining pre_body), numbering each
    // push/pop candidate by DFS order so we can pair them up.
    let mut counter: u32 = 0;
    let mut events: Vec<(u32, SaveKind, String)> = Vec::new();
    scan_scope(stmts, &mut counter, &mut events);

    // Phase 2: LIFO match. Each push waits on the stack for a
    // same-register pop; mismatches close the chain (the push
    // never gets transformed).
    let mut stack: Vec<(u32, String)> = Vec::new();
    let mut transforms: HashMap<u32, SaveKind> = HashMap::new();
    for (mark, kind, reg) in events {
        match kind {
            SaveKind::Push => stack.push((mark, reg)),
            SaveKind::Pop => {
                if let Some(top) = stack.last() {
                    if top.1 == reg {
                        let (push_mark, _) = stack.pop().unwrap();
                        transforms.insert(push_mark, SaveKind::Push);
                        transforms.insert(mark, SaveKind::Pop);
                    }
                }
            }
        }
    }

    // Phase 3: re-walk the scope and apply transforms.
    let mut counter: u32 = 0;
    apply_scope(stmts, &mut counter, &transforms);

    // Phase 4: recurse into sub-scopes (then_body / else_body /
    // loop body). Each runs as an independent scope.
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::IfBranch {
                then_body,
                else_body,
                ..
            } => {
                absorb_save_restore(then_body);
                if let Some(eb) = else_body {
                    absorb_save_restore(eb);
                }
            }
            Stmt::Loop { body, .. } => {
                absorb_save_restore(body);
            }
            _ => {}
        }
    }
}

#[derive(Copy, Clone)]
enum SaveKind {
    Push,
    Pop,
}

/// Phase-1 walker: numbers callee-saved push/pop sites in DFS
/// order, inlining any `IfBranch::pre_body` it encounters since
/// those execute sequentially with the surrounding scope.
fn scan_scope(stmts: &[Stmt], counter: &mut u32, out: &mut Vec<(u32, SaveKind, String)>) {
    for stmt in stmts {
        match stmt {
            Stmt::Asm { text, .. } => {
                if let Some(reg) = parse_callee_save_push(text) {
                    out.push((*counter, SaveKind::Push, reg));
                    *counter += 1;
                } else if let Some(reg) = parse_callee_save_pop(text) {
                    out.push((*counter, SaveKind::Pop, reg));
                    *counter += 1;
                }
            }
            Stmt::IfBranch { pre_body, .. } => {
                scan_scope(pre_body, counter, out);
            }
            _ => {}
        }
    }
}

/// Phase-3 walker: visits sites in the same DFS order as
/// [`scan_scope`] and rewrites those whose marker is in the
/// transforms map.
fn apply_scope(stmts: &mut [Stmt], counter: &mut u32, transforms: &HashMap<u32, SaveKind>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Asm { text, bytes } => {
                let push_reg = parse_callee_save_push(text);
                let pop_reg = parse_callee_save_pop(text);
                if push_reg.is_some() || pop_reg.is_some() {
                    let mark = *counter;
                    *counter += 1;
                    if let Some(action) = transforms.get(&mark) {
                        match action {
                            SaveKind::Push => {
                                if let Some(reg) = push_reg {
                                    let bytes = std::mem::take(bytes);
                                    *stmt = Stmt::Save { reg, bytes };
                                }
                            }
                            SaveKind::Pop => {
                                if let Some(reg) = pop_reg {
                                    let bytes = std::mem::take(bytes);
                                    *stmt = Stmt::Restore { reg, bytes };
                                }
                            }
                        }
                    }
                }
            }
            Stmt::IfBranch { pre_body, .. } => {
                apply_scope(pre_body, counter, transforms);
            }
            _ => {}
        }
    }
}

/// Match an `@asm` text against a bare `push REG` of a callee-saved
/// register and return the register name. Anything else (including
/// `push imm`, `push [mem]`, or a multi-instruction `push REG; …`
/// line) returns `None`.
fn parse_callee_save_push(text: &str) -> Option<String> {
    let stripped = text.strip_prefix("push ")?;
    if stripped.contains(',') || stripped.contains(';') || stripped.contains('[') {
        return None;
    }
    let reg = stripped.trim();
    if is_callee_saved_reg(reg) {
        Some(reg.to_string())
    } else {
        None
    }
}

/// Match an `@asm` text against a bare `pop REG` of a callee-saved
/// register and return the register name.
fn parse_callee_save_pop(text: &str) -> Option<String> {
    let stripped = text.strip_prefix("pop ")?;
    if stripped.contains(',') || stripped.contains(';') || stripped.contains('[') {
        return None;
    }
    let reg = stripped.trim();
    if is_callee_saved_reg(reg) {
        Some(reg.to_string())
    } else {
        None
    }
}

/// Callee-saved register names across the cdecl / sysv / win64 ABIs
/// we encounter in practice. Permissive on purpose: the round-trip
/// property holds regardless, and pairing a non-callee-saved push
/// with its matching pop is still a valid save/restore region —
/// just one the calling convention wouldn't normally generate.
fn is_callee_saved_reg(reg: &str) -> bool {
    matches!(
        reg,
        "ebx"
            | "esi"
            | "edi"
            | "ebp"
            | "rbx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    )
}

/// Approximate the GPR-state effect of an `@asm` line by looking at
/// its mnemonic prefix. The output is the canonical Intel form that
/// `format_intel` produces, so a static lookup table is enough.
///
/// We err toward conservatism — anything that might write a GPR we
/// don't recognise drops the whole state. Recognised "safe-reads"
/// (push, cmp, test, jcc, jmp, …) leave the state untouched; pop /
/// inc / dec / shifts / arithmetic / etc. invalidate just their
/// destination register; everything else is a full reset.
fn asm_state_effect(text: &str, state: &mut RegState) {
    let head = text.split_whitespace().next().unwrap_or("");
    // Mnemonics that change control flow are *block boundaries* for
    // our purposes. Even when they don't write a GPR, the next stmt
    // could be reached via a back-edge or other path where our
    // tracked values don't hold — reset state to be safe.
    let is_branch = matches!(
        head,
        "jmp"
            | "ret"
            | "je"
            | "jne"
            | "jl"
            | "jle"
            | "jg"
            | "jge"
            | "jb"
            | "jbe"
            | "ja"
            | "jae"
            | "js"
            | "jns"
            | "jo"
            | "jno"
            | "jp"
            | "jnp"
            | "jc"
            | "jnc"
            | "jecxz"
            | "jcxz"
            | "jrcxz"
    ) || text.contains("; j")
        || text.contains("; ret");
    if is_branch {
        state.invalidate_all();
        return;
    }
    // `call` clobbers caller-saved registers (eax/ecx/edx + the x64
    // sysv adds rsi/rdi/r8-r11) but leaves callee-saved alone. Same
    // treatment as `Stmt::Call`. Without this carve-out, a register
    // loaded with an IAT slot and used as a repeated indirect-call
    // target — `edi = [IAT]; @asm("call edi"); … ; @asm("call edi")`
    // — would lose its tracked value after the first call, so the
    // second site fails to render as the import name.
    if head == "call" {
        for reg in CALLER_SAVED {
            state.invalidate(reg);
        }
        return;
    }
    // Pure flag-setters and no-effect-on-GPRs.
    let is_pure_read = matches!(
        head,
        "push" | "cmp" | "test" | "nop" | "cdq" | "cwd" | "rep" | "repe" | "repne" | "leave"
    );
    if is_pure_read {
        return;
    }
    // Forms whose destination is a single register operand: just
    // that register's state needs to drop. Parse the destination by
    // taking the first operand after the mnemonic.
    let modifies_single_dst = matches!(
        head,
        "pop"
            | "inc"
            | "dec"
            | "neg"
            | "not"
            | "shl"
            | "shr"
            | "sar"
            | "rol"
            | "ror"
            | "sal"
            | "rcl"
            | "rcr"
    );
    if modifies_single_dst {
        if let Some(rest) = text.split_once(' ').map(|(_, r)| r) {
            // First operand ends at the first comma (or end).
            let first = rest.split(',').next().unwrap_or("").trim();
            if is_gpr_name(first) {
                state.invalidate(first);
                return;
            }
        }
    }
    state.invalidate_all();
}

/// Walk every instruction in `f` and discover the stack slots and
/// registers it touches. Returns one `LocalDecl` per unique slot /
/// register, sorted by:
///
/// * stack slots first, ordered by offset (negative `var_*` then
///   positive `arg_*`, both ascending — matches the order the
///   compiler would emit them in source),
/// * register decls after the stack block, in canonical x86 order
///   (eax, ecx, edx, ebx, esp, ebp, esi, edi, then the 64-bit
///   extras and the 8-/16-bit aliases).
///
/// Sizes come from the widest access seen at each slot / register;
/// `mov al, [ebp-4]` then `mov dword ptr [ebp-4], …` makes
/// `var_4: u32` (the dword form wins).
#[allow(clippy::too_many_lines)]
fn discover_locals(f: &Function<DecodedInsn>, sp_table: &HashMap<u64, i64>) -> Vec<LocalDecl> {
    use std::collections::BTreeMap;

    // Stack slots keyed by *conventional* offset (the EBP-relative
    // form: `arg_8` lives at +8). The size is the max access width
    // seen at the slot; the bool tracks whether ANY access used a
    // signed `MemorySize::Int*` (treating it as `iN` instead of `uN`).
    let mut stack: BTreeMap<i64, (u32, bool)> = BTreeMap::new();
    // Stack slots that show up as a memory-base register in any
    // `[slot+disp]` access — they're pointers to something.
    let mut stack_pointer_slots: HashSet<i64> = HashSet::new();
    // Registers keyed by canonical full-width name. Same max-size
    // rule.
    let mut regs: BTreeMap<String, u32> = BTreeMap::new();
    let mut reg_signed: HashSet<String> = HashSet::new();
    // Track first-seen order for stable register-decl ordering.
    let mut reg_order: Vec<String> = Vec::new();

    for block in &f.blocks {
        for insn in &block.insns {
            let ip = insn.iced.ip();
            for op_idx in 0..insn.iced.op_count() {
                match insn.iced.op_kind(op_idx) {
                    OpKind::Memory
                        if insn.iced.memory_index() == Register::None
                            && matches!(
                                insn.iced.memory_base(),
                                Register::EBP | Register::ESP | Register::RBP | Register::RSP
                            ) =>
                    {
                        let base = insn.iced.memory_base();
                        // `memory_displacement64()` returns the
                        // sign-extended-then-cast-to-u64 raw
                        // displacement; the helper picks the right
                        // sign interpretation for the addressing
                        // mode (32-bit vs 64-bit) so negative offsets
                        // come out as negative i64 instead of large
                        // positive values.
                        let disp = ud_arch_x86::signed_memory_displacement(&insn.iced);
                        // Convention: positive offsets in `arg_X`
                        // start at 8 (first arg). For SP-relative
                        // accesses, normalise via the SP delta:
                        // `entry_ESP + (stable - 4)` is the actual
                        // address, so `stable = sp_delta + disp + 4`.
                        let stable = match base {
                            Register::EBP | Register::RBP => disp,
                            Register::ESP | Register::RSP => {
                                let delta = sp_table.get(&ip).copied().unwrap_or(0);
                                delta + disp + 4
                            }
                            _ => continue,
                        };
                        if stable == 0 || stable == 4 {
                            // Saved EBP / return addr — internal.
                            continue;
                        }
                        let size = memory_size_bytes(insn.iced.memory_size());
                        let signed = is_signed_memory_size(insn.iced.memory_size());
                        if size > 0 {
                            stack
                                .entry(stable)
                                .and_modify(|(s, sg)| {
                                    *s = (*s).max(size);
                                    *sg = *sg || signed;
                                })
                                .or_insert((size, signed));
                        }
                    }
                    OpKind::Register => {
                        let reg = insn.iced.op_register(op_idx);
                        if let Some(name) = canonical_register_name(reg) {
                            let size = register_size_bytes(reg);
                            if size > 0 {
                                regs.entry(name.clone())
                                    .and_modify(|s| *s = (*s).max(size))
                                    .or_insert_with(|| {
                                        reg_order.push(name.clone());
                                        size
                                    });
                            }
                            // Sign-aware ops: idiv/imul/sar/cdq treat
                            // their inputs as signed. Track these so
                            // the register's decl reads as `iN`.
                            if uses_register_as_signed(&insn.iced, reg) {
                                reg_signed.insert(name);
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Track stack slots whose value gets used as a memory
            // base (i.e., the slot acts as a pointer). The slot
            // itself was loaded into a register prior; iced exposes
            // base/index regs of memory operands but not their
            // origin slot — so the heuristic here is conservative
            // (only the EBP/ESP cases are recorded; far-base
            // pointer chains aren't traced).
            for op_idx in 0..insn.iced.op_count() {
                if insn.iced.op_kind(op_idx) == OpKind::Memory {
                    let base = insn.iced.memory_base();
                    if !matches!(
                        base,
                        Register::EBP
                            | Register::ESP
                            | Register::RBP
                            | Register::RSP
                            | Register::None
                    ) {
                        let _ = stack_pointer_slots.insert(0); // placeholder
                    }
                }
            }
        }
    }
    let _ = stack_pointer_slots;

    let mut out: Vec<LocalDecl> = Vec::with_capacity(stack.len() + regs.len());
    for (disp, (size, signed)) in &stack {
        let name = if *disp >= 0 {
            #[allow(clippy::cast_sign_loss)]
            let d = *disp as u64;
            format!("arg_{d:x}")
        } else {
            #[allow(clippy::cast_sign_loss)]
            let d = (-disp) as u64;
            format!("var_{d:x}")
        };
        out.push(LocalDecl {
            name,
            ty: bytes_to_type_signed(*size, *signed),
            kind: LocalKind::Stack,
        });
    }
    for name in &reg_order {
        // ebp/esp/rbp/rsp are part of the call frame setup. They're
        // implicit in every function and add visual noise without
        // carrying semantic information for the reader. Skip them
        // from the locals list. Round-trip safe: the lower path's
        // profile_inputs heuristic only consults ebx/esi/edi for
        // saves anyway.
        if matches!(name.as_str(), "ebp" | "esp" | "rbp" | "rsp") {
            continue;
        }
        let size = regs[name];
        let signed = reg_signed.contains(name);
        out.push(LocalDecl {
            name: name.clone(),
            ty: bytes_to_type_signed(size, signed),
            kind: LocalKind::Register,
        });
    }
    out
}

/// Is `size` one of the iced `MemorySize::Int*` variants (versus
/// the `UInt*` or `Float*` ones)? Used to seed signed-vs-unsigned
/// type inference for stack slots.
fn is_signed_memory_size(size: ud_arch_x86::MemorySize) -> bool {
    use ud_arch_x86::MemorySize;
    matches!(
        size,
        MemorySize::Int8 | MemorySize::Int16 | MemorySize::Int32 | MemorySize::Int64
    )
}

/// Does this instruction treat `reg` as signed? Recognises
/// `idiv`/`imul`/`sar`/`cdq`/`cwde`/`cbw` and signed-jcc-
/// preceding shapes. Conservative — returns `true` only when the
/// signed interpretation is unambiguous; the caller defaults to
/// unsigned for anything else.
fn uses_register_as_signed(insn: &ud_arch_x86::Instruction, reg: Register) -> bool {
    use ud_arch_x86::Mnemonic;
    let signed_op = matches!(
        insn.mnemonic(),
        Mnemonic::Idiv
            | Mnemonic::Imul
            | Mnemonic::Sar
            | Mnemonic::Cdq
            | Mnemonic::Cwde
            | Mnemonic::Cbw
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Cdqe
    );
    if !signed_op {
        return false;
    }
    // For `idiv`/`imul`, the implicit edx:eax pair is signed.
    // For `sar`/`movsx*`, the named operand is signed.
    let touched = (0..insn.op_count())
        .any(|i| insn.op_kind(i) == ud_arch_x86::OpKind::Register && insn.op_register(i) == reg);
    if !touched && matches!(insn.mnemonic(), Mnemonic::Idiv | Mnemonic::Imul) {
        // Treat eax/edx as touched for implicit-operand forms.
        return matches!(
            reg,
            Register::EAX
                | Register::EDX
                | Register::RAX
                | Register::RDX
                | Register::AX
                | Register::DX
        );
    }
    touched
}

/// Like [`bytes_to_type`], but picks the signed variant
/// (`I8`/`I16`/`I32`/`I64`) when `signed` is true.
fn bytes_to_type_signed(bytes: u32, signed: bool) -> Type {
    match (bytes, signed) {
        (1, true) => Type::I8,
        (2, true) => Type::I16,
        (4, true) => Type::I32,
        (8, true) => Type::I64,
        _ => bytes_to_type(bytes),
    }
}

/// Map an `iced::MemorySize` to its access width in bytes. Returns
/// `0` for vector / x87 / "unknown" sizes the source language
/// doesn't have a primitive type for — those slots just don't
/// declare (they're still readable in the body via raw `@asm`).
fn memory_size_bytes(size: ud_arch_x86::MemorySize) -> u32 {
    use ud_arch_x86::MemorySize;
    match size {
        MemorySize::UInt8 | MemorySize::Int8 => 1,
        MemorySize::UInt16 | MemorySize::Int16 => 2,
        MemorySize::UInt32 | MemorySize::Int32 | MemorySize::Float32 => 4,
        MemorySize::UInt64 | MemorySize::Int64 | MemorySize::Float64 => 8,
        _ => 0,
    }
}

/// Lower-case canonical name for a register operand. Maps the 8-bit
/// halves, 16-bit halves, and 32-bit forms back to their 32-bit
/// container (`al`/`ah`/`ax` / `eax` all alias `eax`). Returns
/// `None` for non-GPR registers (segment, XMM, MMX, …) that don't
/// participate in the high-level variable naming.
fn canonical_register_name(reg: Register) -> Option<String> {
    use Register::{
        EAX, EBP, EBX, ECX, EDI, EDX, ESI, ESP, R10, R10D, R11, R11D, R12, R12D, R13, R13D, R14,
        R14D, R15, R15D, R8, R8D, R9, R9D, RAX, RBP, RBX, RCX, RDI, RDX, RSI, RSP,
    };
    let full = match reg {
        // 8-bit / 16-bit / 32-bit halves of the eight legacy GPRs
        // all canonicalise to their 32-bit names. The decompiler's
        // operand text already uses `eax` for the full register and
        // `al` only when the instruction is byte-wide — but for the
        // declaration block we want one decl per logical register.
        Register::AL | Register::AH | Register::AX | EAX | RAX => "eax",
        Register::CL | Register::CH | Register::CX | ECX | RCX => "ecx",
        Register::DL | Register::DH | Register::DX | EDX | RDX => "edx",
        Register::BL | Register::BH | Register::BX | EBX | RBX => "ebx",
        Register::SPL | Register::SP | ESP | RSP => "esp",
        Register::BPL | Register::BP | EBP | RBP => "ebp",
        Register::SIL | Register::SI | ESI | RSI => "esi",
        Register::DIL | Register::DI | EDI | RDI => "edi",
        // x86-64 extras.
        Register::R8L | Register::R8W | R8D | R8 => "r8",
        Register::R9L | Register::R9W | R9D | R9 => "r9",
        Register::R10L | Register::R10W | R10D | R10 => "r10",
        Register::R11L | Register::R11W | R11D | R11 => "r11",
        Register::R12L | Register::R12W | R12D | R12 => "r12",
        Register::R13L | Register::R13W | R13D | R13 => "r13",
        Register::R14L | Register::R14W | R14D | R14 => "r14",
        Register::R15L | Register::R15W | R15D | R15 => "r15",
        _ => return None,
    };
    Some(full.to_string())
}

fn register_size_bytes(reg: Register) -> u32 {
    let info = reg.info();
    // `RegisterInfo::size()` returns the natural width in bytes.
    info.size().try_into().unwrap_or(0)
}

fn bytes_to_type(bytes: u32) -> Type {
    match bytes {
        1 => Type::U8,
        2 => Type::U16,
        4 => Type::U32,
        8 => Type::U64,
        _ => Type::Unknown,
    }
}

/// Emit a contiguous slice of basic blocks into `out`. Handles loops,
/// nested if-else groups (constrained to fit within `range`), and bare
/// blocks with a unified dispatch.
///
/// When `is_top_level` is true, the first block of the range gets the
/// `is_first` flag (so its prologue lifts) and subsequent blocks emit a
/// `// block: 0x…` boundary comment. Inside an `@if_branch` arm
/// (`is_top_level == false`), the first block omits its boundary
/// comment because the structural directive already conveys "this is
/// where the arm starts"; the arm's last block also suppresses its
/// terminator comment since the structural join makes it implicit.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn emit_blocks_in_range(
    out: &mut Vec<Stmt>,
    f: &Function<DecodedInsn>,
    range: std::ops::Range<usize>,
    loops: &[Option<LoopGroup>],
    groups: &[Option<IfElseGroup>],
    lifts: &[Option<BlockTailLift>],
    pre_jmp_truncate: &HashMap<usize, usize>,
    ctx: &EmitCtx<'_>,
    is_top_level: bool,
) {
    let range_start = range.start;
    let range_end = range.end;
    let mut i = range_start;
    while i < range_end {
        let is_first_of_range = i == range_start;
        if let Some(lg) = loops.get(i).and_then(Option::as_ref) {
            // Loops fold body blocks (`i..lg.tail_idx`) plus the
            // tail block; the whole span must fit within the
            // surrounding range. Body blocks are emitted recursively
            // so nested if-else / inner loops inside the body get
            // their own structural lifts.
            if lg.tail_idx < range_end {
                let mut body_stmts = Vec::new();
                emit_blocks_in_range(
                    &mut body_stmts,
                    f,
                    i..lg.tail_idx,
                    loops,
                    groups,
                    lifts,
                    pre_jmp_truncate,
                    ctx,
                    false,
                );
                // The tail block carries the loop's bottom-test plus
                // any work that happens between the body and the
                // test (counter increments, end-of-iteration mutates,
                // etc.). Emit everything *before* the trailing
                // cmp/test+jcc as additional body stmts, and reserve
                // only the cmp+jcc bytes for `tail_bytes`. Without
                // this split the tail-work would be invisible from
                // the source even though it's executing every iter.
                let tail_block = &f.blocks[lg.tail_idx];
                let head = try_lift_if_branch_head(&tail_block.insns);
                let head_consumed = head
                    .as_ref()
                    .map_or(0, |h| h.insns_consumed.min(tail_block.insns.len()));
                let pre_test_count = tail_block.insns.len() - head_consumed;
                let tail_bytes: Vec<u8> = tail_block.insns[pre_test_count..]
                    .iter()
                    .flat_map(|insn| insn.original_bytes.iter().copied())
                    .collect();
                if pre_test_count > 0 {
                    // Synthesise a single-block view of the tail's
                    // pre-test instructions and run the normal block
                    // emitter on it. The cloned block is purely a
                    // vehicle for `emit_block_stmts`'s lifts; the
                    // bytes still come from `f.blocks[lg.tail_idx]`'s
                    // pre-test slice via `tail_block.insns[..pre_test_count]`.
                    let mut tail_view = tail_block.clone();
                    tail_view.insns.truncate(pre_test_count);
                    tail_view.terminator = ud_ir::Terminator::Fallthrough;
                    emit_block_stmts(
                        &mut body_stmts,
                        &tail_view,
                        BlockEmitConfig {
                            is_first: false,
                            emit_block_comment: false,
                            truncate_trailing: 0,
                            emit_terminator_comment: false,
                        },
                        None,
                        ctx,
                    );
                }
                let entry_jmp_bytes = lg.pre_jmp_block_idx.and_then(|pre_idx| {
                    f.blocks[pre_idx]
                        .insns
                        .last()
                        .map(|insn| insn.original_bytes.clone())
                });
                out.push(Stmt::Loop {
                    cond_text: lg.cond_text.clone(),
                    entry_jmp_bytes,
                    tail_bytes,
                    body: body_stmts,
                });
                i = lg.tail_idx + 1;
                continue;
            }
        }

        if let Some(group) = groups.get(i).and_then(Option::as_ref) {
            // Only consume the group when its claimed range fits
            // entirely within the surrounding range — that's how
            // nested if-else inside an arm gets handled correctly.
            if group.end_idx() <= range_end {
                let block = &f.blocks[i];
                let block_len = block.insns.len();
                // Separated cmp/jcc — the cmp lives `pre_body_count`
                // insns earlier than the jcc, with flag-preserving
                // insns in between. We need to:
                //   * skip emitting the cmp (its bytes ride on the
                //     `head_bytes` attribute),
                //   * route the intervening insns into the IfBranch's
                //     `pre_body` instead of the block's main output.
                let separated = group.head_consumed == 1 && group.pre_body_count > 0;
                let head_trim = if separated {
                    group.head_consumed + group.pre_body_count + 1
                } else {
                    group.head_consumed
                };
                emit_block_stmts(
                    out,
                    block,
                    BlockEmitConfig {
                        is_first: is_first_of_range && is_top_level,
                        emit_block_comment: !is_first_of_range || is_top_level && i > 0,
                        truncate_trailing: head_trim,
                        emit_terminator_comment: false,
                    },
                    lifts[i].as_ref(),
                    ctx,
                );
                // For separated shape, run a second emission pass on
                // just the intervening slice (between cmp and jcc) so
                // they appear inside the IfBranch's `pre_body`.
                let mut pre_body_stmts = group.pre_body.clone();
                if separated {
                    let intervening_start = block_len - group.head_consumed - group.pre_body_count;
                    let intervening_end = block_len - group.head_consumed;
                    let mut intervening_view = block.clone();
                    intervening_view.insns =
                        block.insns[intervening_start..intervening_end].to_vec();
                    intervening_view.terminator = ud_ir::Terminator::Fallthrough;
                    emit_block_stmts(
                        &mut pre_body_stmts,
                        &intervening_view,
                        BlockEmitConfig {
                            is_first: false,
                            emit_block_comment: false,
                            truncate_trailing: 0,
                            emit_terminator_comment: false,
                        },
                        None,
                        ctx,
                    );
                }
                let mut then_body = Vec::new();
                emit_blocks_in_range(
                    &mut then_body,
                    f,
                    group.then_range.clone(),
                    loops,
                    groups,
                    lifts,
                    pre_jmp_truncate,
                    ctx,
                    false,
                );
                let else_body = group.else_range.clone().map(|er| {
                    let mut v = Vec::new();
                    emit_blocks_in_range(
                        &mut v,
                        f,
                        er,
                        loops,
                        groups,
                        lifts,
                        pre_jmp_truncate,
                        ctx,
                        false,
                    );
                    v
                });
                out.push(Stmt::IfBranch {
                    cond_text: group.cond_text.clone(),
                    cond_bytes: group.cond_bytes.clone(),
                    attrs: group.attrs.clone(),
                    pre_body: pre_body_stmts,
                    then_body,
                    else_body,
                });
                i = group.end_idx();
                continue;
            }
        }

        // Plain block emission. Within an arm, the first block omits
        // its `// block:` comment and the last block omits the
        // terminator comment.
        let is_last_of_range = i + 1 == range_end;
        let truncate_trailing = pre_jmp_truncate.get(&i).copied().unwrap_or(0);
        let emit_term_default = truncate_trailing == 0;
        let emit_block_comment = if is_top_level {
            i > 0
        } else {
            !is_first_of_range
        };
        let emit_term = if is_top_level {
            emit_term_default
        } else {
            !is_last_of_range && emit_term_default
        };
        emit_block_stmts(
            out,
            &f.blocks[i],
            BlockEmitConfig {
                is_first: is_first_of_range && is_top_level,
                emit_block_comment,
                truncate_trailing,
                emit_terminator_comment: emit_term,
            },
            lifts[i].as_ref(),
            ctx,
        );
        i += 1;
    }
}

/// Per-block emission knobs.
#[derive(Clone, Copy)]
struct BlockEmitConfig {
    /// True for the function's entry block; enables prologue lifting.
    is_first: bool,
    /// Emit a leading `// block: 0x…` comment.
    emit_block_comment: bool,
    /// How many trailing instructions to skip — consumed by an outer
    /// structural directive (e.g. an enclosing `Stmt::IfBranch`'s
    /// `cmp+jcc` head).
    truncate_trailing: usize,
    /// Emit a `// -> …` comment describing the block's terminator
    /// when no other lift consumed it. Suppressed inside `IfBranch`
    /// arms — the structural directive already conveys flow.
    emit_terminator_comment: bool,
}

/// Read-only context passed through emission.
struct EmitCtx<'a> {
    fn_addr_start: u64,
    fn_addr_end: u64,
    name_at: &'a HashMap<u64, String>,
    /// SP delta at every instruction in the function, keyed by IP.
    /// Patterns rendering `[esp+disp]` operands look themselves up
    /// here to normalise into the `arg_X`/`var_X` naming.
    sp_delta_at: &'a HashMap<u64, i64>,
    signature: Option<&'a Signature>,
    data: &'a dyn DataLookup,
    /// Bit width for the prologue/epilogue codec — derived from the
    /// function's first instruction. Drives the 32-bit vs 64-bit
    /// encoding choice in `decode_prologue_params` and friends.
    codec_bits: ud_arch_x86::CodecBits,
}

/// Emit one block's worth of statements into `out`.
///
/// Order: optional `// block: 0x…` header, optional prologue lift on
/// the first block, per-instruction `@asm` lines (with call-target /
/// arg-spill annotations), then either the trailing-tail lift
/// (`Stmt::Return` / `Stmt::Epilogue`) or a terminator comment.
#[allow(clippy::too_many_lines)]
fn emit_block_stmts(
    out: &mut Vec<Stmt>,
    block: &BasicBlock<DecodedInsn>,
    cfg: BlockEmitConfig,
    lift: Option<&BlockTailLift>,
    ctx: &EmitCtx<'_>,
) {
    // `// block: 0x…` boundary markers used to be emitted at every
    // basic-block transition. They're redundant in structured
    // output: `label_<hex>:` markers already flag goto targets, and
    // structural directives (if/else/loop/switch) make boundaries
    // visible by code shape. Skip them to reduce visual noise.
    let _ = cfg.emit_block_comment;

    let prologue_consumed = if cfg.is_first {
        if let Some(lifted) = try_lift_prologue_pattern(&block.insns) {
            let bytes: Vec<u8> = block.insns[..lifted.insns_consumed]
                .iter()
                .flat_map(|insn| insn.original_bytes.iter().copied())
                .collect();
            let params = decode_prologue_params(&bytes, ctx.codec_bits);
            out.push(Stmt::Prologue {
                kind: lifted.kind.to_string(),
                params,
                bytes,
            });
            lifted.insns_consumed
        } else {
            0
        }
    } else {
        0
    };

    let tail_consumed = match lift {
        Some(
            BlockTailLift::Return { insns_consumed, .. }
            | BlockTailLift::Epilogue { insns_consumed, .. }
            | BlockTailLift::ReturnExpr { insns_consumed, .. },
        ) => *insns_consumed,
        None => 0,
    };
    let asm_count = block
        .insns
        .len()
        .saturating_sub(tail_consumed + cfg.truncate_trailing);

    // Pre-pass: identify direct-call sites in this block so we can
    // fold their arg-setup + call into a single `@call` directive.
    // We only consider sites whose `call_idx` falls within the
    // emitted-as-asm range — anything past `asm_count` belongs to a
    // tail lift (`@return_expr` etc.) that already owns those bytes.
    let call_sites = identify_call_sites(&block.insns);
    let mut call_at: HashMap<usize, &CallSite> = HashMap::new();
    let mut consumed_by_call: HashSet<usize> = HashSet::new();
    let mut call_end_idx: HashMap<usize, usize> = HashMap::new();
    let mut post_call_spill: HashMap<usize, i64> = HashMap::new();
    for (site_idx, site) in call_sites.iter().enumerate() {
        if site.call_idx >= asm_count {
            continue;
        }
        let setup_start = site.setup_start.max(prologue_consumed);
        if setup_start > site.call_idx {
            continue;
        }
        call_at.insert(site.call_idx, site);
        for i in setup_start..site.call_idx {
            consumed_by_call.insert(i);
        }
        // Try to fold the post-call result-spill into this call's
        // bytes. Skip when the spill instructions would overlap the
        // next call's setup window — those belong to the next call.
        let mut end_idx = site.call_idx;
        if let Some(spill) = detect_post_call_spill(&block.insns, site.call_idx + 1) {
            let spill_end = site.call_idx + spill.insns_consumed;
            let next_setup_start = call_sites
                .get(site_idx + 1)
                .map_or(usize::MAX, |s| s.setup_start);
            if spill_end < next_setup_start && spill_end < asm_count {
                for i in (site.call_idx + 1)..=spill_end {
                    consumed_by_call.insert(i);
                }
                post_call_spill.insert(site.call_idx, spill.displacement);
                end_idx = spill_end;
            }
        }
        call_end_idx.insert(site.call_idx, end_idx);
    }

    // Run the pattern catalog once for this block. Pattern matches
    // claim their instruction ranges first; the inline pattern chain
    // below picks up whatever survives.
    let pattern_ctx = crate::patterns::PatternCtx {
        fn_addr_start: ctx.fn_addr_start,
        fn_addr_end: ctx.fn_addr_end,
        name_at: ctx.name_at,
        sp_delta_at: ctx.sp_delta_at,
    };
    let pattern_matches = crate::patterns::apply_patterns(&pattern_ctx, &block.insns);

    let mut global_idx = prologue_consumed;
    while global_idx < asm_count {
        let insn = &block.insns[global_idx];
        if consumed_by_call.contains(&global_idx) {
            global_idx += 1;
            continue;
        }
        if let Some(m) = pattern_matches.get(&global_idx) {
            for stmt in &m.stmts {
                out.push(stmt.clone());
            }
            global_idx += m.consumed;
            continue;
        }
        if let Some(site) = call_at.get(&global_idx) {
            let setup_start = site.setup_start.max(prologue_consumed);
            let end_idx = *call_end_idx.get(&site.call_idx).unwrap_or(&site.call_idx);
            let spill_disp = post_call_spill.get(&site.call_idx).copied();
            let mut bytes = Vec::new();
            for j in setup_start..=end_idx {
                bytes.extend_from_slice(&block.insns[j].original_bytes);
            }
            let name = ctx
                .name_at
                .get(&site.call_target)
                .cloned()
                .unwrap_or_else(|| format!("sub_{:x}", site.call_target));
            let args = site
                .args
                .iter()
                .map(|a| render_arg_value(a, ctx))
                .collect::<Vec<_>>();
            out.push(Stmt::Call { name, args, bytes });
            if let Some(disp) = spill_disp {
                let dest = if disp < 0 {
                    format!("[rbp-0x{:x}]", disp.unsigned_abs())
                } else {
                    format!("[rbp+0x{disp:x}]")
                };
                out.push(Stmt::Comment(format!("result -> {dest}")));
            }
            global_idx += 1;
            continue;
        }

        // Lift `mov [rbp+disp], REG_arg` into `@arg_spill(N, [bytes])`
        // when the function has a parameter at that arg index. The
        // directive subsumes both the `@asm` and the
        // `// arg N: name (type)` comment that the v0 decompiler used
        // to emit as separate statements.
        if let Some(arg_index) = arg_spill_lift_index(insn, ctx.signature) {
            out.push(Stmt::ArgSpill {
                arg_index,
                bytes: insn.original_bytes.clone(),
            });
            global_idx += 1;
            continue;
        }
        // Multi-instruction compound stack-slot op:
        // `[rbp+dst] op= [rbp+src]`. The window must stay within
        // the current asm range, must not cross a call boundary,
        // and none of its instructions may already be consumed.
        if let Some(consumed) = try_lift_local_compound(
            block,
            global_idx,
            asm_count,
            &consumed_by_call,
            &call_at,
            out,
        ) {
            global_idx += consumed;
            continue;
        }
        // Lift `mov [rbp+disp], IMM` (local being initialised or
        // assigned a literal) into a structured `@local_set`.
        if let Some((slot, value)) = ud_arch_x86::match_local_set_immediate(&insn.iced) {
            out.push(Stmt::LocalSet {
                slot,
                value,
                bytes: insn.original_bytes.clone(),
            });
            global_idx += 1;
            continue;
        }
        // Lift `add/sub dword ptr [rbp+disp], IMM` into
        // `@local_arith`. Catches loop-counter increments/decrements
        // and accumulator updates.
        if let Some((slot, op, value)) = ud_arch_x86::match_local_arith_immediate(&insn.iced) {
            out.push(Stmt::LocalArith {
                slot,
                op: op.to_string(),
                value,
                bytes: insn.original_bytes.clone(),
            });
            global_idx += 1;
            continue;
        }
        out.push(Stmt::asm(
            format_intel(&insn.iced),
            insn.original_bytes.clone(),
        ));
        if let Some(annotation) =
            call_annotation(insn, ctx.fn_addr_start, ctx.fn_addr_end, ctx.name_at)
        {
            out.push(Stmt::Comment(annotation));
        }
        if let Some(annotation) = lea_target_annotation(insn, ctx.data, ctx.name_at) {
            out.push(Stmt::Comment(annotation));
        }
        global_idx += 1;
    }

    if cfg.truncate_trailing > 0 {
        // Trailing instructions are owned by the outer structural
        // directive (e.g. IfBranch); the caller emits them.
        return;
    }

    if let Some(lift) = lift {
        let lifted_bytes: Vec<u8> = block.insns[asm_count..]
            .iter()
            .flat_map(|insn| insn.original_bytes.iter().copied())
            .collect();
        match lift {
            BlockTailLift::Return { value, .. } => {
                out.push(Stmt::Return {
                    value: *value,
                    bytes: lifted_bytes,
                });
            }
            BlockTailLift::Epilogue { kind, .. } => {
                let params = decode_epilogue_params(&lifted_bytes, ctx.codec_bits);
                out.push(Stmt::Epilogue {
                    kind: (*kind).to_string(),
                    params,
                    bytes: lifted_bytes,
                });
            }
            BlockTailLift::ReturnExpr { text, .. } => {
                out.push(Stmt::ReturnExpr {
                    text: text.clone(),
                    bytes: lifted_bytes,
                });
            }
        }
        return;
    }

    // The `// -> 0xN` / `// -> { taken, fallthrough }` annotations
    // were useful when conditional and unconditional jumps were the
    // primary form on the page — the comment said where the jump
    // led so the reader didn't have to decode the rel8/rel32. Now
    // that those bytes lift to `@asm("jcc Xh", …)` / `@asm("jmp Xh",
    // …)` (or get folded into an `if`/`@loop`), the target is
    // already in the source text and the comment is just clutter.
    let _ = cfg.emit_terminator_comment;
}

/// One block's trailing-instruction lift decision.
enum BlockTailLift {
    /// The block ends with a recognised return-with-literal pattern;
    /// fold those instructions into a `Stmt::Return`.
    Return { insns_consumed: usize, value: u64 },
    /// The block ends with a recognised epilogue (`leave; ret` /
    /// `pop rbp; ret`); fold into a `Stmt::Epilogue`. Only ever set
    /// for the function's last block, and only when no `Return` lift
    /// matched.
    Epilogue {
        insns_consumed: usize,
        kind: &'static str,
    },
    /// The whole block models into a value-producing expression that
    /// lands in EAX/RAX, and the block falls through to a recognised
    /// epilogue. The lift consumes every instruction in the block;
    /// `Stmt::ReturnExpr` carries the rendered text.
    ReturnExpr { insns_consumed: usize, text: String },
}

/// Per-block: which trailing instructions become a `Stmt::Return`,
/// `Stmt::Epilogue`, or `Stmt::ReturnExpr`?
///
/// Order of preference for non-tail blocks:
///
/// 1. `try_lift_return_via_jmp` — recognised `mov eax, IMM; jmp epilogue`
///    pattern. Folds into `Stmt::Return` with a literal value.
/// 2. `try_lift_value_block` — entire block models cleanly into a
///    value expression AND falls through directly to a recognised
///    epilogue tail. Folds the whole block into `Stmt::ReturnExpr`.
///
/// The tail block is unchanged — it tries `try_lift_return_pattern`
/// then `try_lift_epilogue_pattern`.
fn compute_block_tail_lifts(
    f: &Function<DecodedInsn>,
    signature: Option<&Signature>,
    slot_to_name: &HashMap<i64, String>,
    name_at: &HashMap<u64, String>,
) -> Vec<Option<BlockTailLift>> {
    let mut out: Vec<Option<BlockTailLift>> = (0..f.blocks.len()).map(|_| None).collect();
    let Some(last_idx) = f.blocks.len().checked_sub(1) else {
        return out;
    };
    let epilogue_addr = f.blocks[last_idx].addr.0;

    // Allow return-value lifting even without DWARF: i386 / x86-64
    // both return integers in EAX/RAX by ABI convention, and the
    // return patterns (`mov eax, IMM; epilogue` / value-into-eax +
    // epilogue) match without needing the source-language return
    // type. When a signature is present, still gate on it so we
    // don't try to lift a function returning a struct as an
    // integer.
    let return_lift_allowed = match signature {
        Some(s) => return_type_is_integer_like(&s.return_type),
        None => true,
    };

    let tail_is_epilogue = try_lift_epilogue_pattern(&f.blocks[last_idx].insns).is_some();

    for (i, block) in f.blocks.iter().enumerate() {
        if i == last_idx {
            if return_lift_allowed {
                if let Some(lifted) = try_lift_return_pattern(&block.insns) {
                    out[i] = Some(BlockTailLift::Return {
                        insns_consumed: lifted.insns_consumed,
                        value: lifted.value,
                    });
                    continue;
                }
            }
            // Try lifting the tail block as "value computation +
            // epilogue" → @return_expr. The leading insns
            // (everything before leave/pop+ret) must model into an
            // EAX-bearing expression; the trailing 2 must be a
            // recognised epilogue. Folds patterns like
            // `mov eax, [rbp-8]; leave; ret` into one directive.
            if return_lift_allowed {
                if let Some(epi) = try_lift_epilogue_pattern(&block.insns) {
                    let split = block.insns.len() - epi.insns_consumed;
                    if split > 0 {
                        let leading = &block.insns[..split];
                        if let Some(value) = try_lift_value_block(leading, name_at) {
                            let render_ctx = ExprRenderCtx {
                                slot_to_name,
                                name_at,
                            };
                            out[i] = Some(BlockTailLift::ReturnExpr {
                                insns_consumed: block.insns.len(),
                                text: value.expr.render(&render_ctx),
                            });
                            continue;
                        }
                    }
                }
            }
            if let Some(lifted) = try_lift_epilogue_pattern(&block.insns) {
                out[i] = Some(BlockTailLift::Epilogue {
                    insns_consumed: lifted.insns_consumed,
                    kind: lifted.kind,
                });
            }
            continue;
        }

        if return_lift_allowed {
            if let Some(lifted) = try_lift_return_via_jmp(&block.insns, epilogue_addr) {
                out[i] = Some(BlockTailLift::Return {
                    insns_consumed: lifted.insns_consumed,
                    value: lifted.value,
                });
                continue;
            }
        }

        // Any return-terminated block can carry an epilogue lift —
        // not just the function's last block. Windows i386 routines
        // typically have multiple `pop edi; pop esi; pop ebp; pop ebx;
        // ret 0Ch` exit points, one per arm of a switch.
        if matches!(block.terminator, Terminator::Return) {
            if let Some(lifted) = try_lift_epilogue_pattern(&block.insns) {
                out[i] = Some(BlockTailLift::Epilogue {
                    insns_consumed: lifted.insns_consumed,
                    kind: lifted.kind,
                });
                continue;
            }
        }

        // ReturnExpr: this block falls through directly to the
        // function's tail block, which itself is a recognised
        // epilogue. The block's instructions all model into an
        // expression that lives in EAX at fall-through.
        if return_lift_allowed && tail_is_epilogue {
            if let Terminator::Fallthrough = block.terminator {
                if i + 1 == last_idx {
                    if let Some(lifted) = try_lift_value_block(&block.insns, name_at) {
                        let render_ctx = ExprRenderCtx {
                            slot_to_name,
                            name_at,
                        };
                        out[i] = Some(BlockTailLift::ReturnExpr {
                            insns_consumed: lifted.insns_consumed,
                            text: lifted.expr.render(&render_ctx),
                        });
                    }
                }
            }
        }
    }
    out
}

/// One detected `cmp/test + jcc + then-arm [+ else-arm]` group whose
/// conditional block sits at a particular index in `f.blocks`.
///
/// Both arms can span multiple basic blocks. The arm ranges are
/// half-open block-index intervals.
/// One detected back-edge loop. The body block's stmts go inside the
/// `@loop` directive; the tail block's full bytes become
/// `tail_bytes`.
struct LoopGroup {
    /// Block index of the tail — `body_idx + 1` in v0.
    tail_idx: usize,
    cond_text: String,
    /// When the block immediately preceding the body ends with an
    /// unconditional `jmp` to the tail's address (the gcc -O0
    /// "skip body on first iteration" idiom), that block's index is
    /// recorded here. The pre-block's emission then truncates one
    /// trailing instruction; those bytes go into the `@loop`'s
    /// `entry_jmp_bytes`.
    pre_jmp_block_idx: Option<usize>,
}

/// Per-block: is this the body's first block of a recognised loop?
///
/// Detects test-at-bottom do-while shapes — the dominant lowering for
/// `while`/`for` once the compiler hoists the entry check. The body
/// can be either a single Fallthrough-terminated block or a
/// multi-block run that ends with a back-edge from a tail block:
///
/// * Tail block (C) terminates with
///   `ConditionalBranch { taken == B.addr, .. }` (the back-edge).
/// * Tail block's last two instructions are a `cmp/test + jcc` pair,
///   so [`try_lift_if_branch_head`] gives us a cond text.
/// * Body span (B..C) — every block strictly before C falls through.
///   With B == C-1 (the previous shape) the run is one block; for
///   multi-block bodies the run accumulates upstream until the
///   fall-through chain breaks.
fn identify_loop_groups(f: &Function<DecodedInsn>) -> Vec<Option<LoopGroup>> {
    let mut out: Vec<Option<LoopGroup>> = (0..f.blocks.len()).map(|_| None).collect();
    if f.blocks.len() < 2 {
        return out;
    }
    let addr_to_idx: HashMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr.0, i))
        .collect();
    for (tail_idx, tail) in f.blocks.iter().enumerate() {
        let Terminator::ConditionalBranch { taken, .. } = tail.terminator else {
            continue;
        };
        let Some(&body_first_idx) = addr_to_idx.get(&taken.0) else {
            continue;
        };
        if body_first_idx >= tail_idx {
            // Forward branch (not a loop back-edge).
            continue;
        }
        // Every block in body_first_idx..tail_idx must fall through.
        let body_span_clean = (body_first_idx..tail_idx)
            .all(|j| matches!(f.blocks[j].terminator, Terminator::Fallthrough));
        if !body_span_clean {
            continue;
        }
        let Some(head) = try_lift_if_branch_head(&tail.insns) else {
            continue;
        };
        // Pre-jmp folding: the block immediately before the body
        // ends with `jmp tail.addr`. The pre-block must end with
        // an unconditional branch to the tail's address (the "skip
        // body on first iteration" idiom).
        let pre_jmp_block_idx = body_first_idx.checked_sub(1).and_then(|pre_idx| {
            let pre = &f.blocks[pre_idx];
            match pre.terminator {
                Terminator::UnconditionalBranch { target } if target == tail.addr => pre
                    .insns
                    .last()
                    .and_then(|insn| direct_unconditional_branch_target(&insn.iced))
                    .filter(|&target| target == tail.addr.0)
                    .map(|_| pre_idx),
                _ => None,
            }
        });
        out[body_first_idx] = Some(LoopGroup {
            tail_idx,
            cond_text: head.cond_text,
            pre_jmp_block_idx,
        });
    }
    out
}

struct IfElseGroup {
    /// Number of trailing instructions in the conditional block that
    /// the IfBranch head consumes. Two for an adjacent `cmp/test + jcc`
    /// (the canonical shape); one when the cmp/test is separated from
    /// the jcc by flag-preserving insns — those intervening insns
    /// emit as `pre_body` and the cmp's bytes ride along on the
    /// `head_bytes` attribute.
    head_consumed: usize,
    /// Number of instructions from the back of the conditional
    /// block that should be hoisted into the `IfBranch::pre_body`
    /// (the intervening insns between cmp/test and jcc). Always 0
    /// for the adjacent shape.
    pre_body_count: usize,
    /// Extra blocks (immediately following `a_idx`) that the lifted
    /// IfBranch absorbs into its `cond_bytes` rather than emitting
    /// as part of `then_range`. Used by the compound-OR detection:
    /// `if (A) goto T; if (B) goto T; …` folds the second `if`'s
    /// cmp/jcc into the head bytes, eliminating the standalone
    /// `cmp; jcc` line and joining the two conditions with `&&`.
    /// Always 0 for the simple single-comparison shape.
    //
    // The emission loop doesn't need to consult this field
    // directly — `then_range.start` already skips past the
    // absorbed blocks, and `end_idx()` covers the rest of the
    // consumed span. The field is kept for diagnostics and to
    // make the compound shape explicit in the data model.
    #[allow(dead_code)]
    absorbed_blocks: usize,
    cond_text: String,
    cond_bytes: Vec<u8>,
    /// Attributes attached to the lifted `Stmt::IfBranch`. Empty for
    /// the adjacent shape; carries `head_bytes` when the cmp/test was
    /// separated from the jcc.
    attrs: Vec<ud_ast::Attribute>,
    /// Statements lifted from the intervening insns between cmp/test
    /// and jcc. Same semantics as `pre_body_count` but expressed as
    /// the actual AST stmts the IfBranch will own.
    pre_body: Vec<Stmt>,
    /// Block-index range of the fallthrough (`@then`) arm. Always
    /// non-empty; starts at `a_idx + 1 + absorbed_blocks`.
    then_range: std::ops::Range<usize>,
    /// Block-index range of the taken (`@else`) arm. `None` for
    /// if-only patterns where the fallthrough arm falls through into
    /// the would-be-else block (which is then the post-if join, owned
    /// by the outer iteration).
    else_range: Option<std::ops::Range<usize>>,
}

impl IfElseGroup {
    /// One past the last block index this group owns. Takes the
    /// max across both arms because compound-OR shapes can have
    /// then- and else-ranges in either order — the simple `if X
    /// else Y` form always has else after then, but the
    /// compound's then can be the later region.
    fn end_idx(&self) -> usize {
        let then_end = self.then_range.end;
        match &self.else_range {
            Some(r) => r.end.max(then_end),
            None => then_end,
        }
    }
}

/// Per-block: is this block the head of a recognised if/else group?
///
/// v0 detection rules:
///
/// * The block ends with [`Terminator::ConditionalBranch`].
/// * The trailing two instructions match [`try_lift_if_branch_head`]
///   — a `cmp/test` followed by a direct `jcc`.
/// * The block immediately after in memory is at the conditional
///   branch's fallthrough address — start of the `@then` arm.
/// * The "then" arm is a maximal contiguous run of fall-through
///   blocks ending just before the jcc's taken-target block, OR
///   ending in a single non-fallthrough exit (`jmp join_addr` /
///   `Return` / `IndirectBranch` / `InvalidOrUnreachable`).
/// * For if-with-else: the `@else` arm starts at the jcc's
///   taken-target block and runs as a similar contiguous run ending
///   at the join.
/// * For if-only: the "then" arm falls through into the jcc target —
///   that target is then the post-if join, not a separate `else` arm.
///
/// Nested if-else inside an arm is detected by recording a group at
/// every block whose shape fits — the emission loop is responsible
/// for picking the outermost group whose end fits in the surrounding
/// range and recursing into its arms.
fn identify_if_else_groups(f: &Function<DecodedInsn>) -> Vec<Option<IfElseGroup>> {
    let mut groups: Vec<Option<IfElseGroup>> = (0..f.blocks.len()).map(|_| None).collect();
    if f.blocks.len() < 2 {
        return groups;
    }

    // addr → block-index map for jumping to jcc / join targets.
    let addr_to_idx: HashMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr.0, i))
        .collect();

    for (a_idx, slot) in groups.iter_mut().enumerate() {
        if let Some(group) = try_detect_if_else_at(f, a_idx, &addr_to_idx) {
            *slot = Some(group);
        }
    }

    groups
}

/// Try to recognise an if/else group whose conditional block is at
/// `a_idx`. Returns `None` when the shape doesn't fit one of the
/// supported patterns described on [`identify_if_else_groups`].
fn try_detect_if_else_at(
    f: &Function<DecodedInsn>,
    a_idx: usize,
    addr_to_idx: &HashMap<u64, usize>,
) -> Option<IfElseGroup> {
    let a = &f.blocks[a_idx];
    let Terminator::ConditionalBranch { taken, fallthrough } = a.terminator else {
        return None;
    };
    let head = try_lift_if_branch_head(&a.insns)?;
    if head.jcc_target != taken.0 {
        return None;
    }

    let f_idx = a_idx + 1;
    if f.blocks.get(f_idx).map(|b| b.addr.0) != Some(fallthrough.0) {
        return None;
    }
    let &t_idx = addr_to_idx.get(&taken.0)?;
    if t_idx <= f_idx {
        return None;
    }

    // Walk the "then" arm: blocks `f_idx..t_idx`. Every block except
    // the last must fall through; the last either falls through (=
    // if-only) or has a clean exit (= if-with-else).
    if !is_clean_fallthrough_run(f, f_idx..t_idx - 1) {
        return None;
    }
    let then_last = &f.blocks[t_idx - 1];

    let then_exit_join = match then_last.terminator {
        // If the then-arm falls into t_idx OR exits the function
        // early (return / indirect tailcall / unreachable), the
        // implicit join sits at the jcc-taken block t_idx — that's
        // the if-only shape, no `@else` arm needed.
        Terminator::Fallthrough
        | Terminator::Return
        | Terminator::IndirectBranch
        | Terminator::InvalidOrUnreachable => {
            let (attrs, pre_body, pre_body_count) = build_if_head_extras(&head, a);
            return Some(IfElseGroup {
                head_consumed: head.insns_consumed,
                pre_body_count,
                absorbed_blocks: 0,
                cond_text: head.cond_text,
                cond_bytes: head.cond_bytes,
                attrs,
                pre_body,
                then_range: f_idx..t_idx,
                else_range: None,
            });
        }
        Terminator::UnconditionalBranch { target } => Some(target.0),
        Terminator::ConditionalBranch {
            taken: inner_taken, ..
        } => {
            // Compound OR / AND: the then-arm is a single pure
            // cmp/test+jcc block whose jcc-taken target is the
            // same as the outer's, or whose fallthrough target is.
            // Both shapes collapse to a single IfBranch joined by
            // `&&` (in body-runs-on-fallthrough convention).
            if let Some(group) =
                try_detect_compound(f, a, &head, f_idx, t_idx, then_last, inner_taken.0, taken.0)
            {
                return Some(group);
            }
            return None;
        }
    };

    // Walk the "else" arm: blocks `t_idx..join_idx`. Same rule:
    // non-last blocks fall through; the last either falls through
    // to the join address or jumps directly to it.
    let join_idx = match then_exit_join {
        Some(j) => *addr_to_idx.get(&j)?,
        None => f.blocks.len(),
    };
    if join_idx <= t_idx {
        return None;
    }
    if !is_clean_fallthrough_run(f, t_idx..join_idx - 1) {
        return None;
    }
    let else_last = &f.blocks[join_idx - 1];
    let else_meets_join = match (then_exit_join, &else_last.terminator) {
        // Then-arm exits the function and the else-arm runs to the
        // function's tail. Accept any tail terminator.
        (None, _) if join_idx == f.blocks.len() => true,
        (Some(j), Terminator::Fallthrough) => f.blocks.get(join_idx).is_some_and(|b| b.addr.0 == j),
        (Some(j), Terminator::UnconditionalBranch { target }) => target.0 == j,
        (
            Some(_),
            Terminator::Return | Terminator::IndirectBranch | Terminator::InvalidOrUnreachable,
        ) => true,
        _ => false,
    };
    if !else_meets_join {
        return None;
    }

    let (attrs, pre_body, pre_body_count) = build_if_head_extras(&head, a);
    Some(IfElseGroup {
        head_consumed: head.insns_consumed,
        pre_body_count,
        absorbed_blocks: 0,
        cond_text: head.cond_text,
        cond_bytes: head.cond_bytes,
        attrs,
        pre_body,
        then_range: f_idx..t_idx,
        else_range: Some(t_idx..join_idx),
    })
}

/// Invert a relational condition for compound rendering. Recognises
/// the operators produced by [`render_cond_source`] (==, !=, `<`, `<=`,
/// `>`, `>=`, `<u`, `<=u`, `>u`, `>=u`) and returns the complement
/// form; falls back to `!(text)` for anything else so the wrapping
/// at least conveys logical negation.
fn invert_relational_cond(text: &str) -> String {
    const PAIRS: &[(&str, &str)] = &[
        // Longest operators first so the splitter doesn't catch
        // `<` as part of `<=u`.
        (" <=u ", " >u "),
        (" >=u ", " <u "),
        (" <u ", " >=u "),
        (" >u ", " <=u "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" == ", " != "),
        (" != ", " == "),
        (" < ", " >= "),
        (" > ", " <= "),
    ];
    for (op, inverse) in PAIRS {
        if let Some(idx) = text.find(op) {
            let lhs = &text[..idx];
            let rhs = &text[idx + op.len()..];
            return format!("{lhs}{inverse}{rhs}");
        }
    }
    format!("!({text})")
}

/// Try to recognise a compound-condition `if` where the outer if's
/// then-arm is itself a single pure cmp/test+jcc block whose jump
/// target lines up with the outer.
///
/// Two shapes recognised, both folded into a single
/// `IfBranch` whose cond_text joins the two body texts with `&&`:
///
/// 1. **Both ifs go to the same target** (`if (A || B) goto T`):
///    `inner_taken == outer_taken`. After both fall through,
///    control reaches `inner_fallthrough` — that's the body of the
///    compound. T sits as the implicit else.
///
/// 2. **Inner-fallthrough = outer-taken** (`if (A || !B) goto T`,
///    the mixed je/jne switch-dispatch idiom from MSVC i386):
///    `inner_fallthrough == outer_taken`. Body of the compound is
///    then `inner_taken` — the path reached only when A fails AND
///    B takes its jcc. Combined cond_text: `A_body && !B_body`.
#[allow(clippy::too_many_arguments)]
fn try_detect_compound(
    f: &Function<DecodedInsn>,
    _a: &BasicBlock<DecodedInsn>,
    head: &ud_arch_x86::LiftedIfBranchHead,
    f_idx: usize,
    t_idx: usize,
    inner: &BasicBlock<DecodedInsn>,
    inner_taken: u64,
    outer_taken: u64,
) -> Option<IfElseGroup> {
    // Outer must be the adjacent cmp/jcc shape (insns_consumed == 2).
    // Separated forms have an attr+pre_body to preserve and don't
    // combine cleanly.
    if head.insns_consumed != 2 {
        return None;
    }
    // Inner block must be purely a cmp/test+jcc — no other side
    // effects to fold in.
    if inner.insns.len() != 2 {
        return None;
    }
    let inner_head = ud_arch_x86::try_lift_if_branch_head(&inner.insns)?;
    if inner_head.insns_consumed != 2 {
        return None;
    }
    let inner_fall = match inner.terminator {
        Terminator::ConditionalBranch { fallthrough, .. } => fallthrough.0,
        _ => return None,
    };
    let addr_to_idx: HashMap<u64, usize> = f
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.addr.0, i))
        .collect();

    let (cond_text, then_range, else_range) = if inner_taken == outer_taken {
        // Shape 1: A.taken == B.taken == T. After both fall through,
        // body sits at `inner_fall` (post_compound). To preserve
        // the original byte layout (A.cmp+jcc, B.cmp+jcc,
        // post_compound, T_arm), then-arm must be post_compound
        // (it comes first in bytes) and else-arm must be T_arm.
        // cond_text uses the body-on-fallthrough form:
        // `A_body && B_body` (both jccs fall through).
        let post_idx = *addr_to_idx.get(&inner_fall)?;
        if t_idx <= post_idx {
            return None;
        }
        if !is_clean_fallthrough_run(f, post_idx..t_idx - 1) {
            return None;
        }
        let cond = format!("{} && {}", head.cond_text, inner_head.cond_text);
        (cond, post_idx..t_idx, Some(t_idx..f.blocks.len()))
    } else if inner_fall == outer_taken {
        // Shape 2: A.taken == B.fallthrough == T. Byte order is
        // A.cmp+jcc, B.cmp+jcc, T_arm, E_arm — T comes before E.
        // For round-trip the then-arm must hold T (which lowers
        // first) and else-arm must hold E. The cond expresses "T
        // path is taken": `A.cond_taken || NOT B.cond_taken`
        // = inverted-A-body OR B-body (since B's body_op is the
        // !B.cond_taken direction).
        let e_idx = *addr_to_idx.get(&inner_taken)?;
        if e_idx <= t_idx {
            return None;
        }
        let a_taken = invert_relational_cond(&head.cond_text);
        let cond = format!("{} || {}", a_taken, inner_head.cond_text);
        (cond, t_idx..e_idx, Some(e_idx..f.blocks.len()))
    } else {
        return None;
    };

    let mut cond_bytes = Vec::with_capacity(head.cond_bytes.len() + inner_head.cond_bytes.len());
    cond_bytes.extend_from_slice(&head.cond_bytes);
    cond_bytes.extend_from_slice(&inner_head.cond_bytes);

    let _ = f_idx;
    Some(IfElseGroup {
        head_consumed: head.insns_consumed,
        pre_body_count: 0,
        absorbed_blocks: 1,
        cond_text,
        cond_bytes,
        attrs: Vec::new(),
        pre_body: Vec::new(),
        then_range,
        else_range,
    })
}

/// Compute the IfBranch's `attrs` / `pre_body` / `pre_body_count`
/// from a lifted if-head and the conditional block it lives in.
///
/// * **Adjacent shape** (`head.insns_consumed == 2`): no extras —
///   the cmp+jcc both live in `cond_bytes`, nothing to hoist.
/// * **Separated shape** (`head.insns_consumed == 1`): the jcc is
///   the trailing insn; the cmp/test is the last *flag-modifying*
///   instruction earlier in the block, and the insns between them
///   are flag-preserving. The cmp's bytes go into a
///   `head_bytes=[…]` attribute and the intervening insns become
///   `pre_body` stmts via [`emit_block_stmts`] later on.
fn build_if_head_extras(
    head: &ud_arch_x86::LiftedIfBranchHead,
    block: &BasicBlock<DecodedInsn>,
) -> (Vec<ud_ast::Attribute>, Vec<Stmt>, usize) {
    if head.insns_consumed >= 2 {
        return (Vec::new(), Vec::new(), 0);
    }
    // Walk backward from the jcc (at the block tail) over flag-
    // preserving insns until we hit the cmp/test. Same predicate as
    // try_lift_if_branch_head — keep them in sync so the two
    // analyses never disagree about which insns are intervening.
    let jcc_idx = block.insns.len().saturating_sub(1);
    let mut cmp_idx: Option<usize> = None;
    for i in (0..jcc_idx).rev() {
        let ins = &block.insns[i];
        let m = ins.iced.mnemonic();
        if matches!(m, ud_arch_x86::Mnemonic::Cmp | ud_arch_x86::Mnemonic::Test) {
            cmp_idx = Some(i);
            break;
        }
        if ins.iced.rflags_modified() != 0 {
            return (Vec::new(), Vec::new(), 0);
        }
    }
    let Some(cmp_idx) = cmp_idx else {
        return (Vec::new(), Vec::new(), 0);
    };
    let head_bytes = block.insns[cmp_idx].original_bytes.clone();
    let attrs = vec![ud_ast::Attribute {
        key: "head_bytes".into(),
        value: ud_ast::AttrValue::ByteList(head_bytes),
    }];
    let pre_body_count = jcc_idx - cmp_idx - 1;
    (attrs, Vec::new(), pre_body_count)
}

/// Every block index in `range` must have `Terminator::Fallthrough`.
/// An empty range trivially satisfies this.
fn is_clean_fallthrough_run(f: &Function<DecodedInsn>, range: std::ops::Range<usize>) -> bool {
    range
        .into_iter()
        .all(|i| matches!(f.blocks[i].terminator, Terminator::Fallthrough))
}

/// Walk the entry block looking for arg-spill instructions
/// (`mov [rbp+disp], REG_arg`); record `disp -> param_name` for every
/// match where the function has a named parameter at that arg index.
///
/// The map is consumed by [`try_lift_value_block`] via [`ExprRenderCtx`]
/// so that loads from `[rbp-4]` render as the parameter name (e.g.
/// `v`) instead of the raw memory operand.
fn collect_slot_to_name(
    f: &Function<DecodedInsn>,
    signature: Option<&Signature>,
) -> HashMap<i64, String> {
    let mut out = HashMap::new();
    let Some(sig) = signature else {
        return out;
    };
    let Some(entry) = f.blocks.first() else {
        return out;
    };
    for insn in &entry.insns {
        let Some(idx) = arg_spill_index(&insn.iced) else {
            continue;
        };
        let Some(param) = sig.params.get(idx as usize) else {
            continue;
        };
        if param.name.is_empty() {
            continue;
        }
        // arg-spill validates the destination is `[rbp/ebp+disp]`,
        // so the memory operand is meaningful. Use the
        // addressing-aware helper so 32-bit `[ebp-0x20]` doesn't
        // come back as a positive-looking 0xffffffe0.
        let disp = ud_arch_x86::signed_memory_displacement(&insn.iced);
        out.insert(disp, param.name.clone());
    }
    out
}

fn return_type_is_integer_like(t: &Type) -> bool {
    matches!(
        t,
        Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::Bool
            | Type::Char
    )
}

/// Decide what (if anything) to comment after an instruction based on
/// its flow control:
///
/// * Direct `call` to a known function → `// -> <name>`.
/// * Direct `jmp` to a known function *outside* the current function's
///   address range → `// tail-call -> <name>` (a real tail call to
///   another function, not a same-function branch).
/// * Anything else (returns, conditionals, indirect calls / branches,
///   normal moves) → no annotation.
fn call_annotation(
    insn: &DecodedInsn,
    fn_start: u64,
    fn_end: u64,
    name_at: &HashMap<u64, String>,
) -> Option<String> {
    if let Some(target) = direct_call_target(&insn.iced) {
        if let Some(name) = name_at.get(&target) {
            return Some(format!("-> {name}"));
        }
    }
    if let Some(target) = direct_unconditional_branch_target(&insn.iced) {
        let outside_function = target < fn_start || target >= fn_end;
        if outside_function {
            if let Some(name) = name_at.get(&target) {
                return Some(format!("tail-call -> {name}"));
            }
        }
    }
    None
}

/// Render an [`ArgValue`] into a human-readable string for the
/// `@call(name, [args], [bytes])` directive.
///
/// This is intentionally low-fidelity — the strings are
/// informational; the pinned bytes on the `Stmt::Call` are
/// authoritative for round-trip. Renderings prioritise readability
/// over preserving operand semantics: a `lea` to a function address
/// renders as `&function`, a `lea` to a `.rodata` C-string renders
/// as the string literal itself.
fn render_arg_value(value: &ArgValue, ctx: &EmitCtx<'_>) -> String {
    match value {
        // A "Const" arg may actually be an absolute address into a
        // data section — e.g. i386 cdecl pushes a string's address
        // as `mov [esp], IMM` where IMM is the .rdata offset. Try
        // to resolve as a string first, fall back to decimal.
        ArgValue::Const(n) if *n > 0 => {
            #[allow(clippy::cast_sign_loss)]
            let addr = *n as u64;
            if let Some(name) = ctx.name_at.get(&addr) {
                return format!("&{name}");
            }
            if let Some((section_name, data, off)) = ctx.data.section_at(addr) {
                if is_string_data_section(section_name) {
                    if let Some(s) = read_cstring_at(data, off) {
                        // Return the raw string content — the emitter
                        // owns the quoting policy (auto-wraps any arg
                        // whose unquoted form would be ambiguous). Using
                        // `{:?}` here pre-wraps with quotes and the
                        // emitter then re-quotes, producing the
                        // `"\"Hello\""` double-quoting bug.
                        return shorten_for_display(s);
                    }
                }
            }
            n.to_string()
        }
        ArgValue::Const(n) => n.to_string(),
        ArgValue::Lea { addr } => {
            if let Some(name) = ctx.name_at.get(addr) {
                return format!("&{name}");
            }
            if let Some((section_name, data, off)) = ctx.data.section_at(*addr) {
                if is_string_data_section(section_name) {
                    if let Some(s) = read_cstring_at(data, off) {
                        return shorten_for_display(s);
                    }
                }
            }
            // Drop the `{section_name} @ 0x{addr:x}` form: it contains
            // a space and `@`, which the emit layer would auto-quote
            // and the reader would mistake for a string literal. The
            // bare `&0x{addr:x}` round-trips cleanly and the per-line
            // annotation comment carries the section context.
            format!("&0x{addr:x}")
        }
        ArgValue::GlobalLoad { addr } => {
            if let Some(name) = ctx.name_at.get(addr) {
                return format!("*{name}");
            }
            format!("*0x{addr:x}")
        }
        ArgValue::StackLoad { displacement } => {
            if *displacement < 0 {
                format!("[rbp-0x{:x}]", displacement.unsigned_abs())
            } else {
                format!("[rbp+0x{displacement:x}]")
            }
        }
        ArgValue::PrevCallResult => "result".into(),
    }
}

/// If `insn` is a `lea reg, [rip+disp]` whose target lives in a
/// recognisable data section, return a comment string surfacing
/// what's at that address. Goal: turn the cryptic
/// `lea rax, [2015h]` into a navigable hint like
/// `// = .rodata @ 0x2015 ("Hello from test2.c!")`.
///
/// Resolution rules:
///
/// * If the target address belongs to a known function (in `name_at`),
///   render as `// = &<function_name>` — typical for "load the
///   address of a function and indirect-call it" idioms.
/// * Else if the target falls inside a section whose name we
///   recognise as read-only data (`.rodata`, `.data.rel.ro`,
///   `.eh_frame`, `.eh_frame_hdr`), and the bytes there are a valid
///   NUL-terminated UTF-8 C-string of length ≥ 1, render as
///   `// = .rodata @ 0xADDR ("string")`.
/// * Else if the target is just inside *some* section, render as
///   `// = .secname @ 0xADDR`.
/// * Otherwise return None — the lea probably loads computed state we
///   can't surface with a single string.
fn lea_target_annotation(
    insn: &DecodedInsn,
    data: &dyn DataLookup,
    name_at: &HashMap<u64, String>,
) -> Option<String> {
    let addr = direct_lea_rip_target(&insn.iced)?;
    if let Some(name) = name_at.get(&addr) {
        return Some(format!("= &{name}"));
    }
    let (section_name, section_data, sec_offset) = data.section_at(addr)?;
    if is_string_data_section(section_name) {
        if let Some(text) = read_cstring_at(section_data, sec_offset) {
            return Some(format!(
                "= {section_name} @ 0x{addr:x} ({:?})",
                shorten_for_display(text)
            ));
        }
    }
    if section_name.is_empty() {
        return Some(format!("= 0x{addr:x}"));
    }
    Some(format!("= {section_name} @ 0x{addr:x}"))
}

fn is_string_data_section(name: &str) -> bool {
    matches!(
        name,
        // ELF (gcc/clang on Linux/BSD).
        ".rodata"
            | ".rodata.str1.1"
            | ".rodata.str1.8"
            | ".data.rel.ro"
            | ".data.rel.ro.local"
        // PE/COFF (mingw, MSVC).
            | ".rdata"
            | ".rdata$zzz"
    )
}

/// Read a NUL-terminated UTF-8 string at `offset` in `data`. Returns
/// `None` for empty strings, missing NUL terminators, or non-UTF-8
/// content (typical of pointer/relocation tables that happen to live
/// in `.data.rel.ro`).
fn read_cstring_at(data: &[u8], offset: usize) -> Option<&str> {
    let tail = data.get(offset..)?;
    let nul = tail.iter().position(|&b| b == 0)?;
    if nul == 0 {
        return None;
    }
    std::str::from_utf8(&tail[..nul]).ok()
}

/// Truncate strings longer than 60 chars in the lea-annotation
/// comment. Long strings get a trailing `…`.
fn shorten_for_display(s: &str) -> String {
    const MAX_CHARS: usize = 60;
    if s.chars().count() <= MAX_CHARS {
        return s.to_string();
    }
    let truncated: String = s.chars().take(MAX_CHARS).collect();
    format!("{truncated}…")
}

/// If `insn` is a mov of a SysV-x64 argument register to a stack slot
/// AND the function has a (named) parameter at that argument's index,
/// return the index — the caller emits a `Stmt::ArgSpill`.
///
/// The unnamed-parameter case still falls through to `@asm`, since
/// without a name the spill carries no extra semantic information
/// over the raw instruction.
fn arg_spill_lift_index(insn: &DecodedInsn, signature: Option<&Signature>) -> Option<u32> {
    let idx = arg_spill_index(&insn.iced)?;
    let sig = signature?;
    let param = sig.params.get(idx as usize)?;
    if param.name.is_empty() {
        return None;
    }
    Some(idx)
}

/// Try to fold an instruction window starting at `start` into a
/// single `Stmt::LocalCompound`. Returns the number of instructions
/// consumed on success.
fn try_lift_local_compound(
    block: &BasicBlock<DecodedInsn>,
    start: usize,
    asm_count: usize,
    consumed_by_call: &HashSet<usize>,
    call_at: &HashMap<usize, &CallSite>,
    out: &mut Vec<Stmt>,
) -> Option<usize> {
    let max_window = (asm_count - start).min(3);
    if max_window < 2 {
        return None;
    }
    for k in start..start + max_window {
        if consumed_by_call.contains(&k) || call_at.contains_key(&k) {
            return None;
        }
    }
    let window: Vec<_> = block.insns[start..start + max_window]
        .iter()
        .map(|i| i.iced)
        .collect();
    let (consumed, dst, op, src) = ud_arch_x86::match_local_compound(&window)?;
    let mut bytes = Vec::new();
    for j in start..start + consumed {
        bytes.extend_from_slice(&block.insns[j].original_bytes);
    }
    out.push(Stmt::LocalCompound {
        dst,
        op: op.to_string(),
        src,
        bytes,
    });
    Some(consumed)
}

//! BPF function-body builder.
//!
//! Mirrors `decompile/aarch64.rs`: each decoded instruction
//! emits one `@asm` line whose text comes from
//! [`ud_arch_bpf::format_insn`] and whose pinned bytes are the
//! 8 raw encoding bytes. Round-trip is guaranteed by the byte
//! list — editing the text does not regenerate bytes (no BPF
//! assembler in v1).
//!
//! Direct calls and unconditional jumps within the function
//! get the usual `// -> name` annotations when their target is
//! a known function or symbol.
//!
//! For `call <imm>` instructions whose address appears in the
//! relocation-derived name map (`call_site_names`), the
//! rendered text has its `0x<hex>` operand replaced by the
//! imported symbol name (e.g. `call sol_log_` instead of
//! `call 0xeca`). The pinned bytes are unchanged — the rewrite
//! is purely textual, so editing the text doesn't change the
//! recompiled bytes.
//!
//! Each call also gets a function-call-style comment beneath
//! it (`// → sub_X(arg_0, arg_1)` / `// → sol_log_("Hello", 13)`)
//! built from the per-block value tracker's snapshot of r1..r5
//! at the call site. The tracker knows about immediates,
//! register copies, frame-pointer arithmetic, lddw-resolved
//! string literals, and stack-slot loads.
//!
//! LDDW (load 64-bit immediate) is rendered as a pair of
//! `@asm` lines — one for the `lddw` slot itself plus a
//! continuation slot whose text reads `<lddw-cont 0x…>`. Both
//! slots carry their raw bytes, so the 16-byte instruction
//! round-trips intact.

use std::collections::HashMap;

use ud_arch_bpf::{call_target, format_insn, jump_target, BpfVariant, DecodedInsn, InsnKind};
use ud_ast::{FnDecl, Stmt};
use ud_ir::Function;

use super::args::infer_bpf_signature;
use super::data_lookup::DataLookup;
use super::idioms::solana_syscall_signature;
use super::stack_slots::rewrite_slots;

/// Name of the BPF frame-pointer register. Hard-coded by the
/// ISA — there is no other choice on any BPF variant.
const BPF_FP: &str = "r10";

/// Build a `FnDecl` from a lifted BPF function.
///
/// `name_at` maps function entry addresses → names (for jump
/// / fall-through call annotations). `call_site_names` maps
/// `call <imm>` instruction addresses → imported symbol names
/// (typically syscalls resolved through `.rel.dyn`).
#[must_use]
pub fn build_function(
    f: &Function<DecodedInsn>,
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
    variant: BpfVariant,
    data: Option<&dyn DataLookup>,
) -> FnDecl {
    // Layer-4 pre-pass: collect every jump target *inside*
    // this function. A target outside the function's address
    // range is a cross-function tail-call and stays as
    // numeric offset / comment annotation; only intra-function
    // jumps get `label_<addr>:` markers.
    let fn_start = f.addr.0;
    let fn_end = fn_start.saturating_add(f.size() as u64);
    let mut intra_targets: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for block in &f.blocks {
        for insn in &block.insns {
            if matches!(
                insn.kind,
                InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32
            ) {
                let t = jump_target(insn);
                if (fn_start..fn_end).contains(&t) {
                    intra_targets.insert(t);
                }
            }
        }
    }

    // Pre-compute the signature once so the value tracker
    // can seed r1..r5 with `arg_0..` at function entry.
    let signature = infer_bpf_signature(f);
    let arity = signature.as_ref().map_or(0, |s| s.params.len() as u8);

    // Layer-6c+ pre-pass: track per-register values across
    // each linear instruction sequence so we can annotate
    // call sites with their actual argument values (r1..r5)
    // resolved to immediates, copies, or pointer-to-local
    // forms. The state is invalidated at labels (basic-block
    // boundaries) and after every call.
    let mut tracker = RegTracker::new_at_entry(arity);
    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            // Emit a `label_<addr>:` marker before every
            // instruction that's a known jump target.
            if intra_targets.contains(&insn.addr.0) {
                body.push(Stmt::Label { addr: insn.addr.0 });
                // A label marks a join point — values flowing
                // in may come from either the fall-through or
                // the jump, so we can't trust the tracked
                // state. Reset to "unknown".
                tracker.reset();
            }
            // Snapshot the call args BEFORE the instruction
            // applies its own state effects, so a `call`'s
            // args are the *incoming* values of r1..r5.
            let call_args = if matches!(insn.kind, InsnKind::Call) {
                Some(tracker.snapshot_call_args())
            } else {
                None
            };
            let text = render_text(
                insn,
                variant,
                name_at,
                call_site_names,
                &intra_targets,
                data,
            );
            body.push(Stmt::asm(text, insn.bytes.to_vec()));
            if let Some(annotation) = call_or_branch_annotation(insn, name_at, &intra_targets) {
                body.push(Stmt::Comment(annotation));
            }
            // Layer-6c / 6c+: format the call site as a
            // function-call-style comment. For recognised
            // syscalls we know the arity, so we render only
            // that many args. For unknown / local calls we
            // fall back to the generic `args: r1=…` form.
            if matches!(insn.kind, InsnKind::Call) {
                if let Some(args) = call_args {
                    let callee_name = call_site_names.get(&insn.addr.0).cloned();
                    let line = if let Some(name) = callee_name {
                        // Syscall: use the SDK signature
                        // (already showing types) plus the
                        // resolved values.
                        let sig = solana_syscall_signature(&name);
                        let arity = sig.map_or(5, syscall_arity);
                        if let Some(sig_str) = sig {
                            body.push(Stmt::Comment(sig_str.to_string()));
                        }
                        format_call_invocation(&name, arity, &args)
                    } else if let Some(callee) = name_at.get(&call_target(insn)) {
                        // Local call to a known function. We
                        // don't know its arity without a
                        // second pass; render all five slots
                        // that have resolved values.
                        format_call_invocation(callee, 5, &args)
                    } else {
                        render_call_args(&args).unwrap_or_default()
                    };
                    if !line.is_empty() {
                        body.push(Stmt::Comment(line));
                    }
                }
            }
            // Apply this instruction's effect on the tracker
            // *after* snapshotting (so the next insn sees the
            // new state).
            tracker.apply(insn, data);
        }
    }
    // Layer-5a: detect forward `jcc -> body -> label` patterns
    // and wrap them in `Stmt::IfBlock`. Bytes are preserved
    // because the jcc bytes ride in `cond_bytes` and the body
    // statements keep their own pinned `@asm` bytes.
    let body = wrap_if_blocks(body, f, &intra_targets);
    // (signature was computed up-front so the L6c+ tracker
    // could seed r1..r5; reuse it here.)
    FnDecl {
        addr: Some(f.addr.0),
        name: f.name.clone(),
        attrs: Vec::new(),
        locals: Vec::new(),
        signature,
        body,
    }
}

/// Walk the flat body and wrap forward `jcc → body → label`
/// patterns in `Stmt::IfBlock`. The body is conservative:
///   * jcc at addr X targets Y > X
///   * the body Stmt::Asm lines in [X+8, Y) have no jumps
///     outside that range (intra-function or otherwise)
///   * no label inside (X, Y) is the target of a jump from
///     outside that range (defended by `intra_targets`
///     bookkeeping plus the within-range jump check)
///
/// When the conditions don't all hold, the jcc stays a plain
/// `@asm` line and the body stays flat — this layer is purely
/// additive and never breaks round-trip.
fn wrap_if_blocks(
    body: Vec<Stmt>,
    f: &Function<DecodedInsn>,
    intra_targets: &std::collections::BTreeSet<u64>,
) -> Vec<Stmt> {
    let _ = intra_targets;
    // Pre-compute every Stmt::Asm jcc target by instruction
    // address so we can sweep the body in one pass.
    let mut jcc_by_addr: HashMap<u64, (u64, Vec<u8>, String, String)> = HashMap::new();
    for block in &f.blocks {
        for insn in &block.insns {
            if !matches!(insn.kind, InsnKind::JmpCond | InsnKind::JmpCond32) {
                continue;
            }
            let target = jump_target(insn);
            if target <= insn.addr.0 {
                // Backwards jcc — that's a loop tail, not an
                // if-then. Layer-5b's loop detector covers it.
                continue;
            }
            // Render the inverted condition: the body executes
            // when the jcc would *not* take the branch.
            let cond = invert_bpf_cond(insn);
            // The visible operand of the jcc that the
            // structural lift consumes ends with the label
            // reference; keep the rest as a tag for the
            // rendered `if (...)` body.
            jcc_by_addr.insert(
                insn.addr.0,
                (target, insn.bytes.to_vec(), cond, String::new()),
            );
        }
    }

    wrap_if_blocks_in_seq(body, &jcc_by_addr)
}

#[allow(clippy::needless_pass_by_value)]
fn wrap_if_blocks_in_seq(
    body: Vec<Stmt>,
    jcc_by_addr: &HashMap<u64, (u64, Vec<u8>, String, String)>,
) -> Vec<Stmt> {
    // Pre-index Label positions for fast target lookup.
    let mut label_pos: HashMap<u64, usize> = HashMap::new();
    for (i, s) in body.iter().enumerate() {
        if let Stmt::Label { addr } = s {
            label_pos.insert(*addr, i);
        }
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        // The pattern we're looking for: an @asm whose insn
        // address starts a known forward jcc, and whose target
        // label exists later in the body, and the body
        // statements in between have no jumps escaping the
        // [jcc_addr, target) range.
        if let Stmt::Asm { bytes, .. } = &body[i] {
            if bytes.len() == 8 {
                let insn_addr = peek_insn_addr(&body, i);
                if let Some(jcc) = insn_addr.and_then(|a| jcc_by_addr.get(&a)) {
                    let target = jcc.0;
                    if let Some(&label_idx) = label_pos.get(&target) {
                        if label_idx > i {
                            let inner = &body[i + 1..label_idx];
                            // Try while-loop shape first: the
                            // jcc must be the FIRST statement
                            // after an entry label, and the
                            // last `@asm` of the body must be
                            // `ja label_<entry>`.
                            if let Some((body_stmts, tail_bytes)) =
                                try_match_while(inner, insn_addr.unwrap(), &out)
                            {
                                let body_recursed = wrap_if_blocks_in_seq(body_stmts, jcc_by_addr);
                                out.push(Stmt::WhileBlock {
                                    cond_text: jcc.2.clone(),
                                    entry_bytes: jcc.1.clone(),
                                    tail_bytes,
                                    body: body_recursed,
                                });
                                i = label_idx;
                                continue;
                            }
                            // First: try the if-then-else
                            // shape. The "then" arm's tail
                            // `ja label_DONE` would violate
                            // strict self-containment, so we
                            // need to factor it out before the
                            // self-containment check.
                            if let Some((then_body, tail, else_body, advance)) = try_split_then_else(
                                inner,
                                target,
                                &label_pos,
                                &body,
                                label_idx,
                                insn_addr.unwrap(),
                                jcc_by_addr,
                            ) {
                                out.push(Stmt::IfBlock {
                                    cond_text: jcc.2.clone(),
                                    cond_bytes: jcc.1.clone(),
                                    then_body,
                                    then_tail_jmp: tail,
                                    else_body,
                                });
                                i = advance;
                                continue;
                            }
                            // Otherwise: simple if-then.
                            if region_is_self_contained(inner, insn_addr.unwrap(), target) {
                                let inner_owned: Vec<Stmt> = inner.to_vec();
                                let then_body = wrap_if_blocks_in_seq(inner_owned, jcc_by_addr);
                                out.push(Stmt::IfBlock {
                                    cond_text: jcc.2.clone(),
                                    cond_bytes: jcc.1.clone(),
                                    then_body,
                                    then_tail_jmp: Vec::new(),
                                    else_body: Vec::new(),
                                });
                                i = label_idx;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        out.push(body[i].clone());
        i += 1;
    }
    out
}

/// Detect a top-checked while-loop: the jcc we're considering
/// is preceded by a label (the loop entry), and the inner
/// body ends with `ja label_<entry>`. The jcc's target is the
/// loop's exit; the body executes when the jcc would *not*
/// take (inverted condition, same as if-then). Returns the
/// body stmts (without the trailing ja) plus the ja's bytes.
fn try_match_while(
    inner: &[Stmt],
    jcc_addr: u64,
    out_so_far: &[Stmt],
) -> Option<(Vec<Stmt>, Vec<u8>)> {
    let _ = jcc_addr;
    // Last @asm in inner must be `ja label_<target>` where
    // target is some label that *appears in `out_so_far`* —
    // i.e., we've already emitted the loop entry label. This
    // is the back-edge that defines a loop.
    let last_idx = inner.iter().rposition(|s| matches!(s, Stmt::Asm { .. }))?;
    let Stmt::Asm { text, bytes } = &inner[last_idx] else {
        return None;
    };
    let label_hex = text.strip_prefix("ja label_")?;
    let ja_target = u64::from_str_radix(label_hex, 16).ok()?;
    // Search out_so_far for a Label with addr == ja_target.
    let mut found = false;
    for s in out_so_far.iter().rev() {
        if let Stmt::Label { addr } = s {
            if *addr == ja_target {
                found = true;
                break;
            }
        }
    }
    if !found {
        return None;
    }
    let body_stmts: Vec<Stmt> = inner[..last_idx].to_vec();
    Some((body_stmts, bytes.clone()))
}

/// `(then_body, then_tail_jmp_bytes, else_body, advance_to_idx)`
/// — the four pieces an if-then-else needs.
type ThenElseSplit = (Vec<Stmt>, Vec<u8>, Vec<Stmt>, usize);

/// Detect an if-then-else: the inner body ends with
/// `ja label_DONE` where DONE > target, and the run from
/// `target` to `DONE` is a self-contained else arm. Returns
/// `(then_body, tail_jmp, else_body, advance_to_idx)` on
/// success.
#[allow(clippy::too_many_arguments)]
fn try_split_then_else(
    inner: &[Stmt],
    target: u64,
    label_pos: &HashMap<u64, usize>,
    full_body: &[Stmt],
    label_idx: usize,
    jcc_addr: u64,
    jcc_by_addr: &HashMap<u64, (u64, Vec<u8>, String, String)>,
) -> Option<ThenElseSplit> {
    // Find the last @asm in `inner` — the candidate tail jmp.
    let last_asm_idx = inner.iter().rposition(|s| matches!(s, Stmt::Asm { .. }))?;
    let Stmt::Asm { text, bytes } = &inner[last_asm_idx] else {
        return None;
    };
    let label_hex = text.strip_prefix("ja label_")?;
    let done_addr = u64::from_str_radix(label_hex, 16).ok()?;
    if done_addr <= target {
        return None;
    }
    let &done_idx = label_pos.get(&done_addr)?;
    if done_idx <= label_idx {
        return None;
    }
    // The then arm is everything up to (but not including)
    // the tail-jmp. Verify it's self-contained over
    // [jcc_addr, target) ignoring the tail-jmp itself.
    if !region_is_self_contained(&inner[..last_asm_idx], jcc_addr, target) {
        return None;
    }
    // The else arm is the run between target's label and
    // done_addr's label.
    let else_slice = &full_body[label_idx..done_idx];
    if !region_is_self_contained(else_slice, target, done_addr) {
        return None;
    }
    let tail_jmp = bytes.clone();
    let then_inner: Vec<Stmt> = inner[..last_asm_idx].to_vec();
    let then_body = wrap_if_blocks_in_seq(then_inner, jcc_by_addr);
    let else_body = wrap_if_blocks_in_seq(else_slice.to_vec(), jcc_by_addr);
    Some((then_body, tail_jmp, else_body, done_idx))
}

/// The pinned `@asm` bytes for a BPF slot are exactly 8 bytes;
/// reading the first byte's opcode + offset (le16 at bytes 2-3)
/// would let us recompute the slot address, but the caller
/// already knows it from the prior loop. We just track it by
/// scanning labels backward for context — simpler is to use
/// the stmt's neighbour info passed in via the per-function
/// build, but `wrap_if_blocks_in_seq` runs over a flat list.
///
/// For simplicity, we re-derive the slot's instruction address
/// by looking *forward*: every `Stmt::Asm` carries its 8 bytes
/// and a preceding `Stmt::Label` carries the slot's address.
/// We snapshot the running cursor when first entering the body
/// to make this exact, but here we cheat: peek the previous
/// `Stmt::Label` (within a small window) or fall back to
/// `None`. Layer-5a's wrap is conservative — when in doubt,
/// stay unwrapped.
fn peek_insn_addr(body: &[Stmt], idx: usize) -> Option<u64> {
    // Walk back from `idx` looking for the most recent label.
    // Each Stmt::Asm advances the cursor by its byte len, and
    // every BPF slot is 8 bytes — so we count Asms between
    // here and the last label.
    let mut asms_seen = 0u64;
    for j in (0..idx).rev() {
        match &body[j] {
            Stmt::Asm { .. } => asms_seen += 1,
            Stmt::Label { addr } => return Some(addr + asms_seen * 8),
            _ => {}
        }
    }
    None
}

/// Inverted condition text for a BPF jcc — the body of an
/// if-then executes when the jcc would NOT jump. Maps each
/// jcc mnemonic to its complement: `jeq` → `!=`, `jne` → `==`,
/// `jgt` → `<=`, etc.
#[allow(clippy::cast_sign_loss)]
fn invert_bpf_cond(insn: &DecodedInsn) -> String {
    let op = insn.opcode >> 4;
    let dst = format!("r{}", insn.dst);
    let is_reg_src = (insn.opcode & 0x08) != 0;
    let rhs = if is_reg_src {
        format!("r{}", insn.src)
    } else {
        format!("0x{:x}", insn.imm as u32)
    };
    let cmp = match op {
        0x1 => "!=",                                   // jeq
        0x2 | 0x6 => "<=",                             // jgt / jsgt
        0x3 | 0x7 => "<",                              // jge / jsge
        0x4 => return format!("({dst} & {rhs}) == 0"), // jset
        0x5 => "==",                                   // jne
        0xa | 0xc => ">=",                             // jlt / jslt
        0xb | 0xd => ">",                              // jle / jsle
        _ => "?",
    };
    format!("{dst} {cmp} {rhs}")
}

/// True when every jump statement inside `region` targets an
/// address within `[fn_start, target)` (i.e. stays inside the
/// candidate if-then body). Skips the textual label_<addr>
/// scan by parsing the operand directly.
fn region_is_self_contained(region: &[Stmt], jcc_addr: u64, target: u64) -> bool {
    for s in region {
        if let Stmt::Asm { text, .. } = s {
            for tok in text.split_whitespace() {
                if let Some(rest) = tok.strip_prefix("label_") {
                    let hex = rest.trim_end_matches(',');
                    if let Ok(t) = u64::from_str_radix(hex, 16) {
                        if t < jcc_addr || t >= target {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

/// Format an instruction with name-aware substitution.
///
/// Two cases for `call`:
///   1. Relocation map names the *call site* (syscall import).
///      Render as `call <symbol>`.
///   2. Otherwise, compute the local call target. If it lands
///      on a known function (layer-2 `sub_<addr>` or anything
///      else), render as `call <fn_name>`.
///
/// The pinned bytes never change; only the text does.
fn render_text(
    insn: &DecodedInsn,
    variant: BpfVariant,
    name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
    intra_targets: &std::collections::BTreeSet<u64>,
    data: Option<&dyn DataLookup>,
) -> String {
    if matches!(insn.kind, InsnKind::Call) {
        if let Some(name) = call_site_names.get(&insn.addr.0) {
            return format!("call {name}");
        }
        let target = call_target(insn);
        if let Some(name) = name_at.get(&target) {
            return format!("call {name}");
        }
    }
    // Layer 6c+: for `lddw r, imm64` whose imm64 lands in a
    // readable section with printable string content (typical
    // pattern for sol_log_ message pointers), surface the
    // string as the operand.
    if matches!(insn.kind, InsnKind::Lddw) {
        if let (Some(imm), Some(lookup)) = (insn.imm64, data) {
            if let Some(s) = read_inline_string(lookup, imm) {
                return format!("lddw r{}, {s}", insn.dst);
            }
        }
    }
    // Layer-4: rewrite the relative-offset operand of intra-
    // function jumps to a `label_<addr>` reference. The trailing
    // `, +0xN` is replaced with `, label_<target_hex>`. Calls
    // already get name substitution above; jumps to other
    // functions stay as offsets and pick up a `// -> name`
    // comment via `call_or_branch_annotation`.
    let mut text = rewrite_slots(&format_insn(insn, variant), BPF_FP);
    if matches!(
        insn.kind,
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32
    ) {
        let target = jump_target(insn);
        if intra_targets.contains(&target) {
            text = rewrite_branch_offset(&text, target);
        }
    }
    text
}

/// Replace the trailing relative offset of a jump (`+0xN` or
/// `-0xN`) with `label_<target_hex>`. Keeps the rest of the
/// line unchanged so unconditional `ja` and conditional
/// `jeq r1, 0x0, +0x2` forms both work — the offset is always
/// the last token before end-of-line.
fn rewrite_branch_offset(text: &str, target: u64) -> String {
    let label_ref = format!("label_{target:x}");
    if let Some((head, _)) = text.rsplit_once(", +0x") {
        return format!("{head}, {label_ref}");
    }
    if let Some((head, _)) = text.rsplit_once(", -0x") {
        return format!("{head}, {label_ref}");
    }
    // Unconditional jump (`ja +0xN`): no comma.
    if let Some((head, _)) = text.rsplit_once(" +0x") {
        return format!("{head} {label_ref}");
    }
    if let Some((head, _)) = text.rsplit_once(" -0x") {
        return format!("{head} {label_ref}");
    }
    text.to_string()
}

/// Annotate jumps whose target is a known function — i.e.
/// cross-function tail-calls. Intra-function jumps now point
/// at named labels and need no comment.
fn call_or_branch_annotation(
    insn: &DecodedInsn,
    name_at: &HashMap<u64, String>,
    intra_targets: &std::collections::BTreeSet<u64>,
) -> Option<String> {
    match insn.kind {
        InsnKind::Jmp | InsnKind::JmpCond | InsnKind::JmpCond32 => {
            let target = jump_target(insn);
            if intra_targets.contains(&target) {
                // Already labelled — no extra comment needed.
                return None;
            }
            name_at.get(&target).map(|n| format!("-> {n}"))
        }
        _ => None,
    }
}

// ============================================================
// Register-value tracker (layer 6c+).
// ============================================================

/// Linear-flow register-value tracker. Updates a per-register
/// `Option<String>` map as instructions execute; resets on
/// labels (basic-block boundaries) and clobbers r1..r5 + sets
/// r0 to `<return>` on calls.
///
/// Values are rendered as human-readable strings (`"0x10"`,
/// `"r10"`, `"&local_8"`, `"[local_38]"`). The tracker
/// understands the patterns BPF emits at call setup —
/// immediates, register copies, frame-pointer arithmetic, and
/// loads from stack — which covers most argument-prep
/// sequences without needing a full value-flow analysis.
struct RegTracker {
    /// One entry per r0..r10 (index 0..10). `None` means
    /// "unknown / clobbered".
    state: [Option<String>; 11],
}

impl RegTracker {
    /// Construct with the entry state: r10 always holds the
    /// frame pointer, and r1..r(arity) hold the function's
    /// arguments (named `arg_0`..`arg_<arity-1>` to match the
    /// signature `infer_bpf_signature` produces).
    fn new_at_entry(arity: u8) -> Self {
        let mut state: [Option<String>; 11] = Default::default();
        state[10] = Some("r10".into());
        for i in 0..arity.min(5) {
            state[(i + 1) as usize] = Some(format!("arg_{i}"));
        }
        Self { state }
    }

    /// Clear all register values — used at labels (CFG join
    /// points) where the incoming value could come from any
    /// predecessor. r10 stays set since the frame pointer is
    /// invariant across the function body.
    fn reset(&mut self) {
        for (i, s) in self.state.iter_mut().enumerate() {
            if i == 10 {
                continue;
            }
            *s = None;
        }
    }

    /// Snapshot the current values of r1..r5 (the BPF arg
    /// registers). Returned as a fixed-size array of optional
    /// strings — none for "unknown".
    fn snapshot_call_args(&self) -> [Option<String>; 5] {
        [
            self.state[1].clone(),
            self.state[2].clone(),
            self.state[3].clone(),
            self.state[4].clone(),
            self.state[5].clone(),
        ]
    }

    /// Update the tracker by interpreting `insn`'s effect.
    /// If `data` is provided and a lddw's imm64 resolves to a
    /// printable string via the `DataLookup`, the register is
    /// set to the string literal so subsequent call-arg
    /// snapshots show the string instead of a raw address.
    #[allow(clippy::match_same_arms)]
    fn apply(&mut self, insn: &DecodedInsn, data: Option<&dyn DataLookup>) {
        let class = insn.opcode & 0x07;
        let op_nibble = insn.opcode >> 4;
        let is_reg_src = (insn.opcode & 0x08) != 0;
        let dst = insn.dst as usize;
        let src = insn.src as usize;
        if dst > 10 {
            return;
        }
        match class {
            // BPF_LD (LDDW + legacy packet loads).
            0x00 => {
                if insn.opcode == 0x18 {
                    let imm = insn.imm64.unwrap_or(0);
                    // If the imm64 resolves to a string
                    // literal via DataLookup, store the
                    // literal (`"..."`) — the call-arg
                    // annotation reads better as
                    // `r1="Hello, world!"` than `r1=0x52b20`.
                    let val = data
                        .and_then(|d| read_inline_string(d, imm))
                        .unwrap_or_else(|| format!("0x{imm:x}"));
                    self.state[dst] = Some(val);
                } else {
                    self.state[dst] = None;
                }
            }
            // BPF_LDX (register-indexed loads): track loads
            // from `[r10 ± offset]` as `[local_N]` / `[arg_N]`.
            0x01 => {
                if src == 10 {
                    self.state[dst] = Some(render_stack_ref(insn.offset, false));
                } else {
                    self.state[dst] = None;
                }
            }
            // Stores don't change register values. (Two
            // opcode classes; same effect.)
            0x02 | 0x03 => { /* no-op */ }
            // ALU32 / ALU64 — the interesting cases are MOV
            // (immediate or register copy) and ADD on a known
            // base.
            0x04 | 0x07 => {
                #[allow(clippy::cast_sign_loss)]
                match op_nibble {
                    // MOV
                    0xb => {
                        self.state[dst] = if is_reg_src {
                            self.state[src].clone()
                        } else {
                            Some(format!("0x{:x}", insn.imm as u32))
                        };
                    }
                    // ADD
                    0x0 => {
                        if is_reg_src {
                            self.state[dst] = None;
                        } else {
                            // Add immediate. If dst is a known
                            // pointer-to-r10, fold the offset
                            // into the stack-slot name.
                            let folded = self.state[dst]
                                .as_deref()
                                .and_then(|s| fold_stack_add(s, insn.imm));
                            self.state[dst] = folded;
                        }
                    }
                    // Everything else (NEG, ARSH, END, …):
                    // invalidate dst.
                    _ => {
                        self.state[dst] = None;
                    }
                }
            }
            // BPF_JMP — only CALL has a register effect.
            0x05 => {
                if matches!(insn.kind, InsnKind::Call | InsnKind::CallReg) {
                    // r0 = return; r1..r5 clobbered.
                    self.state[0] = Some("<return>".into());
                    for r in 1..=5 {
                        self.state[r] = None;
                    }
                }
                // EXIT / jumps / etc. don't change reg values.
            }
            // BPF_JMP32 — same idea, no register write.
            0x06 => {}
            _ => {}
        }
    }
}

/// Format a `[r10 + offset]` reference as a stack-slot name.
/// When `take_addr` is true, render as `&local_N` (or
/// `&arg_N`); otherwise as `[local_N]`.
fn render_stack_ref(offset: i16, take_addr: bool) -> String {
    let prefix = if take_addr { "&" } else { "[" };
    let suffix = if take_addr { "" } else { "]" };
    if offset >= 0 {
        format!("{prefix}arg_{offset:x}{suffix}")
    } else {
        let abs = u32::from(offset.unsigned_abs());
        format!("{prefix}local_{abs:x}{suffix}")
    }
}

/// When a register holds `"r10"` (or a pointer-to-r10 form
/// like `"&local_8"`), adjust the offset by `delta` and return
/// the new symbolic name. Returns `None` when the base isn't
/// a recognisable frame-pointer form.
fn fold_stack_add(base: &str, delta: i32) -> Option<String> {
    if base == "r10" {
        // Pointer-to-r10 after adding `delta`. Convention:
        // negative delta → local; non-negative → arg.
        if delta < 0 {
            return Some(format!("&local_{:x}", delta.unsigned_abs()));
        }
        return Some(format!("&arg_{delta:x}"));
    }
    if let Some(rest) = base.strip_prefix("&local_") {
        let cur = i64::from_str_radix(rest, 16).ok()?;
        let new = -cur + i64::from(delta);
        if new <= 0 {
            return Some(format!("&local_{:x}", new.unsigned_abs()));
        }
        return Some(format!("&arg_{new:x}"));
    }
    if let Some(rest) = base.strip_prefix("&arg_") {
        let cur = i64::from_str_radix(rest, 16).ok()?;
        let new = cur + i64::from(delta);
        if new < 0 {
            return Some(format!("&local_{:x}", new.unsigned_abs()));
        }
        return Some(format!("&arg_{new:x}"));
    }
    None
}

/// Try to surface a string literal at `vaddr` via the supplied
/// data lookup. Returns a quoted, escaped Rust-style literal
/// (e.g. `"Hello, world!"`).
///
/// Two cases are handled:
///   1. **Direct**: `vaddr` lands in a section whose bytes at
///      that offset are printable ASCII. Read up to ~96 bytes
///      or to a NUL / non-printable byte and quote it.
///   2. **Slice descriptor**: `vaddr` lands in a section like
///      `.data.rel.ro` that holds 16-byte `{ ptr: u64, len: u64 }`
///      slice descriptors. Read both, range-check the length,
///      follow `ptr` to recover the bytes, and quote.
fn read_inline_string(lookup: &dyn DataLookup, vaddr: u64) -> Option<String> {
    if let Some(s) = read_string_direct(lookup, vaddr, 96) {
        return Some(s);
    }
    read_string_via_slice_descriptor(lookup, vaddr)
}

fn read_string_direct(lookup: &dyn DataLookup, vaddr: u64, max_len: usize) -> Option<String> {
    let (_section, bytes, offset) = lookup.section_at(vaddr)?;
    let tail = bytes.get(offset..)?;
    let mut end = 0;
    for (i, &b) in tail.iter().take(max_len).enumerate() {
        if b == 0 {
            end = i;
            break;
        }
        if !(b == b'\t' || b == b'\n' || (0x20..0x7f).contains(&b)) {
            end = i;
            break;
        }
        end = i + 1;
    }
    if end < 4 {
        return None;
    }
    let s = std::str::from_utf8(&tail[..end]).ok()?;
    Some(format!("{s:?}"))
}

fn read_string_via_slice_descriptor(lookup: &dyn DataLookup, vaddr: u64) -> Option<String> {
    let (_section, bytes, offset) = lookup.section_at(vaddr)?;
    let descriptor = bytes.get(offset..offset + 16)?;
    // Solana SBF stores R_BPF_64_RELATIVE pointers with the
    // static vaddr in the **upper 32 bits** of an 8-byte slot
    // (low 32 stay zero on disk; the loader resolves them at
    // runtime by adding the program's load base). For static
    // analysis we just take the upper u32 as the vaddr —
    // that's what the string will end up referencing once
    // the program is loaded.
    let ptr = u64::from(u32::from_le_bytes(descriptor[4..8].try_into().ok()?));
    let len = u64::from_le_bytes(descriptor[8..16].try_into().ok()?);
    if len == 0 || len > 1024 || ptr == 0 {
        return None;
    }
    let (_section2, ptr_bytes, ptr_offset) = lookup.section_at(ptr)?;
    let slice = ptr_bytes.get(ptr_offset..ptr_offset + len as usize)?;
    let s = std::str::from_utf8(slice).ok()?;
    // Must be mostly printable.
    if s.chars()
        .any(|c| (c as u32) < 0x20 && c != '\t' && c != '\n')
    {
        return None;
    }
    Some(format!("{s:?}"))
}

/// Render a call's resolved r1..r5 values as a single comment.
/// Returns `None` when every slot is unknown — the comment
/// would be empty noise.
/// Format a call as `name(arg_0, arg_1, …)` using the
/// tracker-resolved register values. Trailing unknowns are
/// trimmed; if every slot is unknown we omit the args list
/// entirely (the bare name is enough). The `arity` cap
/// reflects how many arguments the callee actually takes —
/// for known syscalls it's the SDK signature, for unknown
/// callees it's the conservative "up to 5".
fn format_call_invocation(name: &str, arity: usize, args: &[Option<String>; 5]) -> String {
    let n = arity.min(5);
    let mut parts = Vec::new();
    for slot in args.iter().take(n) {
        match slot {
            Some(v) => parts.push(v.clone()),
            None => parts.push("?".into()),
        }
    }
    // Drop trailing "?" placeholders so a syscall with only
    // the first arg known doesn't render as `(value, ?, ?, ?, ?)`.
    while let Some(last) = parts.last() {
        if last == "?" {
            parts.pop();
        } else {
            break;
        }
    }
    if parts.is_empty() {
        format!("→ {name}()")
    } else {
        format!("→ {name}({})", parts.join(", "))
    }
}

/// Count the parentheses-bounded arguments in a syscall
/// signature like `"sol_log_(msg: *const u8, len: u64)"`.
/// Returns the comma count + 1 inside the outermost parens,
/// or 5 (conservative) when parsing fails.
fn syscall_arity(sig: &str) -> usize {
    let Some(open) = sig.find('(') else { return 5 };
    let Some(close) = sig.rfind(')') else {
        return 5;
    };
    if close <= open + 1 {
        return 0;
    }
    let inner = &sig[open + 1..close];
    // Strip any return-type tail (the `-> X` only appears
    // *after* the closing paren, so it shouldn't be here).
    inner.split(',').count()
}

fn render_call_args(args: &[Option<String>; 5]) -> Option<String> {
    let mut parts = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a {
            parts.push(format!("r{}={v}", i + 1));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("args: {}", parts.join(", ")))
    }
}

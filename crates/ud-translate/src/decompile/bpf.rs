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

    let mut body = Vec::new();
    for block in &f.blocks {
        for insn in &block.insns {
            // Emit a `label_<addr>:` marker before every
            // instruction that's a known jump target.
            if intra_targets.contains(&insn.addr.0) {
                body.push(Stmt::Label { addr: insn.addr.0 });
            }
            let text = render_text(insn, variant, name_at, call_site_names, &intra_targets);
            body.push(Stmt::asm(text, insn.bytes.to_vec()));
            if let Some(annotation) = call_or_branch_annotation(insn, name_at, &intra_targets) {
                body.push(Stmt::Comment(annotation));
            }
        }
    }
    // Layer-5a: detect forward `jcc -> body -> label` patterns
    // and wrap them in `Stmt::IfBlock`. Bytes are preserved
    // because the jcc bytes ride in `cond_bytes` and the body
    // statements keep their own pinned `@asm` bytes.
    let body = wrap_if_blocks(body, f, &intra_targets);
    // Layer-6b: infer arity + return type from per-register
    // read-before-write analysis. Renders as a Rust-shaped
    // signature on the FnDecl; the AST emit / parse path
    // already round-trips signatures, so this is pure addition
    // with no round-trip impact.
    let signature = infer_bpf_signature(f);
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
                            if region_is_self_contained(inner, insn_addr.unwrap(), target) {
                                // Recursively wrap nested
                                // if-blocks inside this region
                                // first.
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

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
use super::idioms::{
    annotate_handler_banners, annotate_pda_verify, solana_function_summary,
    solana_semantic_comment, solana_syscall_signature,
};
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
#[allow(clippy::too_many_lines)]
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

    // L6a-arc: build SSA + IP→insn index up-front so the
    // post-label call-arg fallback can chase reaching defs
    // when the per-block tracker comes up empty. Cost is
    // sub-millisecond on every function we've measured.
    let ssa = super::bpf_ssa::build_bpf_ssa(f);
    let insns_by_addr = super::bpf_args_ssa::index_by_addr(f);

    // Layer-6c+ pre-pass: track per-register values across
    // each linear instruction sequence so we can annotate
    // call sites with their actual argument values (r1..r5)
    // resolved to immediates, copies, or pointer-to-local
    // forms. The state is invalidated at labels (basic-block
    // boundaries) and after every call.
    let mut tracker = RegTracker::new_at_entry(arity);
    let mut body = Vec::new();
    for block in &f.blocks {
        let mut idx = 0;
        while idx < block.insns.len() {
            let insn = &block.insns[idx];
            // LDDW lift consumes the next slot too — peek
            // ahead for an LddwSecondHalf companion so the
            // emitted `Stmt::Move` covers all 16 bytes.
            let mut consumed_extra = 0usize;
            let lddw_pair_bytes: Option<Vec<u8>> = if matches!(insn.kind, InsnKind::Lddw) {
                block
                    .insns
                    .get(idx + 1)
                    .filter(|next| matches!(next.kind, InsnKind::LddwSecondHalf))
                    .map(|next| {
                        let mut b = Vec::with_capacity(16);
                        b.extend_from_slice(&insn.bytes);
                        b.extend_from_slice(&next.bytes);
                        consumed_extra = 1;
                        b
                    })
            } else {
                None
            };
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
            //
            // For any slot the per-block tracker couldn't
            // resolve (typically because a label reset wiped
            // the state), fall back to SSA-driven reaching-
            // def resolution. Strictly additive: tracker's
            // answer wins when it has one.
            let call_args = if matches!(insn.kind, InsnKind::Call) {
                let mut args = tracker.snapshot_call_args();
                for (slot, arg) in args.iter_mut().enumerate() {
                    if arg.is_none() {
                        *arg = super::bpf_args_ssa::resolve_arg(
                            &ssa,
                            &insns_by_addr,
                            insn.addr.0,
                            slot,
                            data,
                        );
                    }
                }
                Some(args)
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
            // Lift recognized instruction shapes into semantic
            // Stmt variants. Falls back to `Stmt::Asm` for any
            // shape the codec can't (yet) regenerate. Round-trip
            // is preserved either way: bytes ride along on the
            // chosen variant and the byte-drop pass clears them
            // only when the codec reproduces them.
            let lifted_to_call = if matches!(insn.kind, InsnKind::Call) {
                if let Some(args) = call_args.as_ref() {
                    let lifted = lift_call_stmt(insn, &text, args, name_at, call_site_names);
                    if let Some(stmt) = lifted {
                        body.push(stmt);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            if !lifted_to_call {
                if let Some(lifted) = lift_semantic_stmt(insn, &text, lddw_pair_bytes.as_deref()) {
                    body.push(lifted);
                } else {
                    body.push(Stmt::asm(text, insn.bytes.to_vec()));
                    // If we peeked a LddwSecondHalf to make a
                    // 16-byte Move but the lift declined, emit
                    // the continuation as its own Asm so its
                    // bytes survive.
                    if let Some(cont) = block.insns.get(idx + 1) {
                        if consumed_extra > 0 {
                            let cont_text = render_text(
                                cont,
                                variant,
                                name_at,
                                call_site_names,
                                &intra_targets,
                                data,
                            );
                            body.push(Stmt::asm(cont_text, cont.bytes.to_vec()));
                        }
                    }
                }
            }
            if let Some(annotation) = call_or_branch_annotation(insn, name_at, &intra_targets) {
                body.push(Stmt::Comment(annotation));
            }
            // Layer-6c / 6c+: at the call site, surface the
            // SDK signature + Solana-semantic annotations as
            // auditor comments. The bare `→ name(args)`
            // recap that used to live here is now redundant
            // (the lifted `Stmt::Call` renders the same info
            // directly) — emit it only when we couldn't lift.
            if matches!(insn.kind, InsnKind::Call) {
                if let Some(args) = call_args {
                    let callee_name = call_site_names.get(&insn.addr.0).cloned();
                    if let Some(name) = &callee_name {
                        let sig = solana_syscall_signature(name);
                        if let Some(sig_str) = sig {
                            body.push(Stmt::Comment(sig_str.to_string()));
                        }
                        if let Some(semantic) = solana_semantic_comment(name, &args) {
                            body.push(Stmt::Comment(semantic));
                        }
                    }
                    if !lifted_to_call {
                        let line = if let Some(name) = callee_name {
                            let sig = solana_syscall_signature(&name);
                            let arity = sig.map_or(5, syscall_arity);
                            format_call_invocation(&name, arity, &args)
                        } else if let Some(callee) = name_at.get(&call_target(insn)) {
                            format_call_invocation(callee, 5, &args)
                        } else {
                            render_call_args(&args).unwrap_or_default()
                        };
                        if !line.is_empty() {
                            body.push(Stmt::Comment(line));
                        }
                    }
                }
            }
            // Apply this instruction's effect on the tracker
            // *after* snapshotting (so the next insn sees the
            // new state). When LDDW consumed its
            // continuation, apply the continuation's effect
            // too (no-op for the tracker but keeps state
            // consistent with the linear instruction stream).
            tracker.apply(insn, data);
            if consumed_extra > 0 {
                if let Some(cont) = block.insns.get(idx + 1) {
                    tracker.apply(cont, data);
                }
            }
            idx += 1 + consumed_extra;
        }
    }
    // Layer-5a: detect forward `jcc -> body -> label` patterns
    // and wrap them in `Stmt::IfBlock`. Bytes are preserved
    // because the jcc bytes ride in `cond_bytes` and the body
    // statements keep their own pinned `@asm` bytes.
    let mut body = wrap_if_blocks(body, f, &intra_targets);
    // L6c-Solana: insert "PDA verification check" annotations
    // where a `sol_try_find_program_address` is followed shortly
    // by a 32-byte `sol_memcmp_`. Round-trip-neutral comments.
    annotate_pda_verify(&mut body);
    // L6c-Solana: insert per-handler `=== handler: <name> ===`
    // banners above every detected instruction-handler marker
    // (lddw of an "Instruction: <name>…" literal, or a
    // `→ sol_log_(…)` comment carrying one). Lets auditors
    // navigate a giant inlined dispatcher by handler name.
    annotate_handler_banners(&mut body);
    // L6c-Solana: prepend a one-line "function-summary" comment
    // listing the security-relevant syscalls reachable from this
    // function (cpi, pda-derive, sysvar, return-data, …).
    // Auditors can grep `function-summary: .*cpi` to enumerate
    // every CPI-bearing function in the dump.
    if let Some(summary) = solana_function_summary(&body) {
        body.insert(0, Stmt::Comment(summary));
    }
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

/// Recognise instruction shapes that the BPF arch codec can
/// re-encode from semantic fields, returning the lifted Stmt
/// for emission in place of `Stmt::Asm`. Returning `None` keeps
/// the @asm fallback so anything the codec can't reproduce
/// stays pinned-bytes (the round-trip-safe default).
///
/// `lddw_pair_bytes` is `Some(16)` when the caller paired a
/// `Lddw` insn with its `LddwSecondHalf` continuation so the
/// emitted `Stmt::Move` covers both slots; otherwise `None`.
fn lift_semantic_stmt(
    insn: &DecodedInsn,
    text: &str,
    lddw_pair_bytes: Option<&[u8]>,
) -> Option<Stmt> {
    // exit → Stmt::Return
    if insn.opcode == 0x95 {
        return Some(Stmt::Return {
            value: 0,
            bytes: insn.bytes.to_vec(),
        });
    }

    // mov64 reg, reg/imm → Stmt::Move
    if matches!(insn.opcode, 0xb7 | 0xbf) {
        let after = text.strip_prefix("mov64 ")?;
        let (dst, src) = after.split_once(", ")?;
        return Some(Stmt::Move {
            dst: dst.trim().to_string(),
            src: src.trim().to_string(),
            bytes: insn.bytes.to_vec(),
        });
    }

    // ldx / stx → Stmt::Move with sized memory operand.
    // BPF Load class = 0x01, Store class = 0x03 (STX);
    // size bits live in opcode bits 3..4 (0x18 / 0x00 / 0x08 / 0x10).
    let class = insn.opcode & 0x07;
    if matches!(insn.kind, InsnKind::Load) && class == 0x01 {
        return lift_load(insn, text);
    }
    if matches!(insn.kind, InsnKind::Store) && class == 0x03 {
        return lift_store(insn, text);
    }

    // lddw rN, imm64 → Stmt::Move covering both slots.
    if matches!(insn.kind, InsnKind::Lddw) {
        return lift_lddw(insn, text, lddw_pair_bytes);
    }

    // 64-bit ALU ops → Stmt::RegArith.
    // ALU64 class = 0x07. op nibble lives in high nibble of opcode.
    if matches!(insn.kind, InsnKind::Alu64) && (insn.opcode & 0x07) == 0x07 {
        return lift_alu64(insn);
    }

    None
}

/// Lift `add64 / sub64 / mul64 / lsh64 / rsh64 / or64 / and64
/// / xor64 / div64 / mod64` (the byte-drop-friendly subset) to
/// `Stmt::RegArith`. `arsh64` / `neg64` keep their `@asm`
/// rendering because the canonical `>>=` / unary-minus syntax
/// would lose the arsh-vs-rsh distinction (need an attribute
/// marker first).
fn lift_alu64(insn: &DecodedInsn) -> Option<Stmt> {
    let op_nibble = insn.opcode >> 4;
    let op = match op_nibble {
        0x0 => "+=",
        0x1 => "-=",
        0x2 => "*=",
        0x3 => "/=",
        0x4 => "|=",
        0x5 => "&=",
        0x6 => "<<=",
        0x7 => ">>=",
        0x9 => "%=",
        0xa => "^=",
        _ => return None, // 0x8 neg, 0xb mov (handled elsewhere),
                          // 0xc arsh — defer with marker.
    };
    let dst = format!("r{}", insn.dst);
    let src = if (insn.opcode & 0x08) != 0 {
        format!("r{}", insn.src)
    } else {
        #[allow(clippy::cast_sign_loss)]
        let imm_u32 = insn.imm as u32;
        format!("0x{imm_u32:x}")
    };
    Some(Stmt::RegArith {
        dst,
        op: op.into(),
        src,
        bytes: insn.bytes.to_vec(),
    })
}

/// Lift `ldx{b,h,w,dw} rN, [rM ± off]` into
/// `Stmt::Move { dst: "rN", src: "[rM ± off]:uNN", bytes }`.
fn lift_load(insn: &DecodedInsn, text: &str) -> Option<Stmt> {
    // Strip the `ldx` prefix and the size letter to find the
    // rendered operands.
    let rest = text.strip_prefix("ldx")?;
    // rest starts with size letter ("b", "h", "w", or "dw"),
    // then space, then "rN, [...]".
    let (size_letter, after) = split_size_letter(rest)?;
    let (dst, mem) = after.trim_start().split_once(", ")?;
    let mem = mem.trim();
    // Append the `:uNN` suffix only when the size differs
    // from the default `:u64` (dw). Keeps the canonical form
    // suffix-free for the common case.
    let src = if size_letter == "dw" {
        mem.to_string()
    } else {
        format!("{mem}:u{}", bits_for_size_letter(size_letter))
    };
    Some(Stmt::Move {
        dst: dst.trim().to_string(),
        src,
        bytes: insn.bytes.to_vec(),
    })
}

/// Lift `stx{b,h,w,dw} [rM ± off], rN` into
/// `Stmt::Move { dst: "[rM ± off]:uNN", src: "rN", bytes }`.
fn lift_store(insn: &DecodedInsn, text: &str) -> Option<Stmt> {
    let rest = text.strip_prefix("stx")?;
    let (size_letter, after) = split_size_letter(rest)?;
    let (mem, src) = after.trim_start().split_once(", ")?;
    let mem = mem.trim();
    let dst = if size_letter == "dw" {
        mem.to_string()
    } else {
        format!("{mem}:u{}", bits_for_size_letter(size_letter))
    };
    Some(Stmt::Move {
        dst,
        src: src.trim().to_string(),
        bytes: insn.bytes.to_vec(),
    })
}

/// Lift `lddw rN, 0x<imm>` into a 16-byte `Stmt::Move`.
/// Returns `None` for the string-resolved form
/// (`lddw rN, "literal" @0xADDR`) — that surface keeps its
/// audit-friendly `@asm` rendering until the codec learns
/// to round-trip string literals.
fn lift_lddw(_insn: &DecodedInsn, text: &str, pair_bytes: Option<&[u8]>) -> Option<Stmt> {
    // Need the full 16-byte pair; reject orphan LDDWs (no
    // continuation peeked).
    let bytes = pair_bytes?.to_vec();
    if bytes.len() != 16 {
        return None;
    }
    let rest = text.strip_prefix("lddw ")?;
    let (dst, rhs) = rest.split_once(", ")?;
    let rhs = rhs.trim();
    // Reject the string-resolved form for now.
    if rhs.starts_with('"') || rhs.contains(" @0x") {
        return None;
    }
    // `:u64` suffix tells `encode_move` to pick LDDW over
    // `mov64 reg, imm32`.
    let src = format!("{rhs}:u64");
    Some(Stmt::Move {
        dst: dst.trim().to_string(),
        src,
        bytes,
    })
}

/// Split a leading size letter (`b` / `h` / `w` / `dw`) off
/// the front of a string, returning the letter and the rest.
fn split_size_letter(s: &str) -> Option<(&str, &str)> {
    if let Some(after) = s.strip_prefix("dw") {
        return Some(("dw", after));
    }
    let b = s.as_bytes();
    if !b.is_empty() && matches!(b[0], b'b' | b'h' | b'w') {
        return Some((&s[..1], &s[1..]));
    }
    None
}

fn bits_for_size_letter(letter: &str) -> u32 {
    match letter {
        "b" => 8,
        "h" => 16,
        "w" => 32,
        _ => 64, // "dw" or unrecognised — default to 64 (BPF `dw`).
    }
}

/// Recognise a call-site that the codec + lower path can
/// regenerate as `Stmt::Call` rather than `@asm("call ...")`.
///
/// Returns `Some(Stmt::Call)` when the call has a resolved
/// textual name (either a syscall via the relocation map or a
/// known intra-program function via `name_at`); falls back to
/// `None` for hash-only / register-indirect / unknown calls so
/// they keep their `@asm` rendering.
///
/// The args slot array is collapsed to a `Vec<String>` with
/// `"?"` for unresolved slots and trailing unresolved slots
/// trimmed (mirrors `format_call_invocation`'s output shape).
fn lift_call_stmt(
    insn: &DecodedInsn,
    text: &str,
    call_args: &[Option<String>; 5],
    _name_at: &HashMap<u64, String>,
    call_site_names: &HashMap<u64, String>,
) -> Option<Stmt> {
    // Parse `call <name>` or `call_local <name>` shapes.
    let (mnem_prefix, rest) = if let Some(r) = text.strip_prefix("call_local ") {
        ("call_local", r)
    } else {
        ("call", text.strip_prefix("call ")?)
    };
    let _ = mnem_prefix;
    let name = rest.trim();
    // Hash-only fallback (`call 0xeca`) means the symbol
    // resolver didn't map it — keep as @asm so the audit
    // signal isn't lost.
    if name.starts_with("0x") || name.is_empty() {
        return None;
    }

    // Direct-target classification:
    //
    // - If the call site is registered as a syscall in
    //   `call_site_names` (relocation-derived imports like
    //   `sol_log_`, `abort`, etc.), `direct_target` is None
    //   — the imm carries a relocation hash the codec can't
    //   reproduce from `(source_ip, target)` alone, so the
    //   pinned bytes are the source of truth.
    // - Otherwise opcode-driven:
    //   - 0x8d (Linux call_local) → intra-program target.
    //   - 0x85 src=1 (Solana sBPF intra-program) → target.
    //   - 0x85 src=0 (Linux helper) → no target.
    let src_nibble = (insn.bytes[1] >> 4) & 0x0f;
    let direct_target = if call_site_names.contains_key(&insn.addr.0) {
        None
    } else {
        match (insn.opcode, src_nibble) {
            (0x8d, _) | (0x85, 1) => Some(call_target(insn)),
            _ => None,
        }
    };

    // Pick arity from the syscall signature (if known) or
    // default to 5 for local calls.
    let arity = if let Some(callee) = call_site_names.get(&insn.addr.0) {
        super::idioms::solana_syscall_signature(callee).map_or(5, syscall_arity)
    } else {
        // Local call to a known function or unknown callee: we
        // don't have an arity signature, so render up to 5
        // slots (matches the comment-rendering convention).
        5
    };
    let args = call_args_vec(call_args, arity);

    Some(Stmt::Call {
        name: name.to_string(),
        args,
        bytes: insn.bytes.to_vec(),
        direct_target,
    })
}

/// Collapse the tracker's `[Option<String>; 5]` slot array
/// into a `Vec<String>` ready for `Stmt::Call.args`. Trailing
/// unresolved slots are trimmed; interior `None` becomes `"_"`
/// (underscore — lexes as an ident so the parser round-trips,
/// reads like Rust's "ignore" placeholder).
fn call_args_vec(args: &[Option<String>; 5], arity: usize) -> Vec<String> {
    let n = arity.min(5);
    let mut parts: Vec<String> = args
        .iter()
        .take(n)
        .map(|s| s.clone().unwrap_or_else(|| "_".into()))
        .collect();
    while parts.last().is_some_and(|s| s == "_") {
        parts.pop();
    }
    parts
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
    let last_idx = inner.iter().rposition(is_byte_bearing_stmt)?;
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
    // The candidate tail jmp must be the LAST byte-bearing
    // stmt in `inner` — anything after it would be unreachable
    // code that the wrap silently drops, breaking round-trip
    // (the lifted Move/Return variants make this a real risk
    // because they look just like Asm to the size tracker).
    // Trailing zero-byte Labels are fine.
    let last_byte_idx = inner.iter().rposition(is_byte_bearing_stmt)?;
    let Stmt::Asm { text, bytes } = &inner[last_byte_idx] else {
        return None;
    };
    let last_asm_idx = last_byte_idx;
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
/// True when `stmt` occupies one or more BPF slots in the
/// lowered binary. Asm, Move (lifted from mov64), Return
/// (lifted from exit), and Call (lifted from call /
/// call_local) all qualify. Labels are zero-byte markers
/// and don't.
fn is_byte_bearing_stmt(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Asm { .. }
            | Stmt::Move { .. }
            | Stmt::Return { .. }
            | Stmt::Call { .. }
            | Stmt::RegArith { .. }
    )
}

fn peek_insn_addr(body: &[Stmt], idx: usize) -> Option<u64> {
    // Walk back from `idx` looking for the most recent label.
    // Each single-slot BPF stmt advances the cursor by 8 bytes.
    // Today that's Asm + the lifter-produced Return / Move /
    // Call variants. Adding more lifts means adding more arms.
    let mut slots_seen = 0u64;
    for j in (0..idx).rev() {
        match &body[j] {
            Stmt::Asm { bytes, .. }
            | Stmt::Return { bytes, .. }
            | Stmt::Call { bytes, .. }
            | Stmt::RegArith { bytes, .. } => {
                // 8 bytes = 1 slot for every single-slot BPF
                // stmt class; LDDW Move is the only multi-slot
                // case and lives in the Move arm below.
                slots_seen += bytes.len().max(8) as u64 / 8;
            }
            Stmt::Move { bytes, .. } => {
                // LDDW Move is 16 bytes (2 slots); regular
                // Move is 8 bytes (1 slot). Use bytes.len()
                // when present, else assume 1 slot.
                if bytes.is_empty() {
                    slots_seen += 1;
                } else {
                    slots_seen += (bytes.len() as u64) / 8;
                }
            }
            Stmt::Label { addr } => return Some(addr + slots_seen * 8),
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
        // BPF-to-BPF intra-program calls have two encodings:
        // Solana sBPF uses opcode 0x85 + src=1; the Linux
        // BPF-to-BPF convention uses opcode 0x8d. We
        // surface the distinction in the rendered text by
        // using a `call` vs `call_local` mnemonic so the
        // byte-drop pass and the lower path can recover the
        // exact original encoding from the text alone (no
        // hidden bytes, no out-of-band hint).
        let call_mnem = if insn.opcode == 0x8d {
            "call_local"
        } else {
            "call"
        };
        if let Some(name) = call_site_names.get(&insn.addr.0) {
            return format!("{call_mnem} {name}");
        }
        let target = call_target(insn);
        if let Some(name) = name_at.get(&target) {
            return format!("{call_mnem} {name}");
        }
    }
    // Layer 6c+: for `lddw r, imm64` whose imm64 lands in
    // a readable section with printable string content
    // (typical pattern for sol_log_ message pointers),
    // surface the string as the operand. We also append the
    // original `@0x<imm>` so the lower path can recover the
    // exact rodata address from the text alone — the same
    // literal may live at multiple addresses in rodata
    // (overlapping suffixes), so a string→address table
    // can't disambiguate, but a per-call-site annotation
    // can.
    if matches!(insn.kind, InsnKind::Lddw) {
        if let (Some(imm), Some(lookup)) = (insn.imm64, data) {
            if let Some(s) = read_inline_string(lookup, imm) {
                return format!("lddw r{}, {s} @0x{imm:x}", insn.dst);
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
pub(super) fn read_inline_string(lookup: &dyn DataLookup, vaddr: u64) -> Option<String> {
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

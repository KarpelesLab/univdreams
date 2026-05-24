//! Lower a parsed `.ud` AST to bytes.
//!
//! v0 scope: per-function byte concatenation. Each [`Stmt::Asm`] in
//! the body must carry pinned `bytes`; the lowerer concatenates them
//! in source order and returns the result. Empty `bytes` is a hard
//! error — there's no text assembler online yet, so an `@asm("text")`
//! without bytes is not yet recompilable.
//!
//! Future expansion:
//!
//! * When a text assembler is wired in, empty `bytes` becomes "the
//!   assembler will fill in", and a non-empty `bytes` field becomes a
//!   verification hint (assemble `text`, assert it equals `bytes`).
//! * Sectioning and inter-function padding are not yet represented in
//!   the source language; once `@raw` and `@pad` directives land, the
//!   top-level `lower_to_bytes` will produce a complete binary image.

use ud_arch_codec::{ArchCodec, ArchError, EncodeHints, SwitchSpec};
use ud_ast::{AttrValue, Attribute, FnDecl, Item, Stmt, UdFile};

/// Read the `head_bytes` attribute off an `IfBranch`. Returns `None`
/// when the attribute is missing (the adjacent-cmp case) or holds an
/// inappropriate value type — the lower path treats both as "no head
/// bytes". A separately-validated parser is responsible for rejecting
/// malformed inputs.
fn head_bytes_attr(attrs: &[Attribute]) -> Option<&[u8]> {
    attrs.iter().find_map(|a| {
        if a.key != "head_bytes" {
            return None;
        }
        match &a.value {
            AttrValue::ByteList(b) => Some(b.as_slice()),
            _ => None,
        }
    })
}

/// One function lowered to bytes.
#[derive(Debug, Clone)]
pub struct LoweredFunction {
    pub name: String,
    pub addr: Option<u64>,
    pub bytes: Vec<u8>,
}

/// Errors specific to the lower path.
#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    #[error(
        "function `{fn_name}` has an `@asm` statement without pinned bytes \
         at body index {stmt_index} (text = {text:?})"
    )]
    MissingBytes {
        fn_name: String,
        stmt_index: usize,
        text: String,
    },

    #[error(
        "function `{fn_name}` body index {stmt_index}: re-assembly of \
         `@asm({text:?})` failed: {message}"
    )]
    AsmAssembleFailed {
        fn_name: String,
        stmt_index: usize,
        text: String,
        message: String,
    },

    #[error(
        "section `{section}` has a gap: item at 0x{item_addr:x} but cursor was at 0x{cursor:x}"
    )]
    SectionGap {
        section: String,
        cursor: u64,
        item_addr: u64,
    },

    #[error(
        "section `{section}` has overlapping items: cursor at 0x{cursor:x}, next item at 0x{item_addr:x}"
    )]
    SectionOverlap {
        section: String,
        cursor: u64,
        item_addr: u64,
    },

    #[error("section `{section}` contains a nested section, which is not supported")]
    NestedSection { section: String },

    #[error(
        "function `{fn_name}` body index {stmt_index}: switch dispatch \
         {dispatch:?} is not a supported encoding (expected \"msvc-jmp-table\")"
    )]
    UnsupportedSwitchDispatch {
        fn_name: String,
        stmt_index: usize,
        dispatch: String,
    },

    #[error(
        "function `{fn_name}` body index {stmt_index}: switch dispatch \
         needs the enclosing function's `@addr` set so the `ja rel32` \
         can be computed against the case targets"
    )]
    SwitchNeedsAddress { fn_name: String, stmt_index: usize },

    #[error(
        "function `{fn_name}` body index {stmt_index}: goto needs the \
         enclosing function's `@addr` set so the `jmp rel32` can be \
         computed against the target label"
    )]
    GotoNeedsAddress { fn_name: String, stmt_index: usize },

    #[error(
        "function `{fn_name}` body index {stmt_index}: goto encode \
         failed: {source}"
    )]
    GotoEncode {
        fn_name: String,
        stmt_index: usize,
        source: ud_arch_x86::JumpEncodeError,
    },

    #[error(
        "function `{fn_name}` body index {stmt_index}: switch dispatch \
         encode failed: {source}"
    )]
    SwitchEncode {
        fn_name: String,
        stmt_index: usize,
        source: ud_arch_x86::SwitchEncodeError,
    },

    #[error("function `{fn_name}` has no @addr; cannot place it inside a section")]
    FunctionWithoutAddr { fn_name: String },

    #[error("unknown jump_table dispatch `{dispatch}` (expected `gcc_pie_rel32` or `msvc_va32`)")]
    UnknownJumpTableDispatch { dispatch: String },

    #[error(
        "function `{fn_name}` body index {stmt_index}: arch codec failed to encode \
         {operation}: {message}"
    )]
    ArchEncode {
        fn_name: String,
        stmt_index: usize,
        operation: &'static str,
        message: String,
    },
}

/// Lower one [`FnDecl`] to its byte sequence.
///
/// When the function's body lacks a leading `Stmt::Prologue` or
/// trailing `Stmt::Epilogue` AND the function is not flagged
/// `#[naked]`, the compiler-profile defaults are auto-generated
/// and their bytes prepended / appended at lower time. This
/// matches the rendering side: the emitter omits @prologue /
/// @epilogue when their structured params equal the auto-default
/// for the function's profile.
pub fn lower_function_bytes(f: &FnDecl, arch: &dyn ArchCodec) -> Result<Vec<u8>, LowerError> {
    lower_function_bytes_at(f, f.addr, arch)
}

/// Same as [`lower_function_bytes`] but with an explicit
/// "IP-space" address override. Callers that store something
/// other than the function's IP in `FnDecl.addr` (notably the PE
/// pipeline, which uses file offsets) pass the function's true
/// virtual address here so `Stmt::Switch` (and any other
/// PC-relative encoders) compute correctly.
pub fn lower_function_bytes_at(
    f: &FnDecl,
    ip_base: Option<u64>,
    arch: &dyn ArchCodec,
) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::new();
    let has_prologue = matches!(f.body.first(), Some(Stmt::Prologue { .. }));
    let has_epilogue = matches!(f.body.last(), Some(Stmt::Epilogue { .. }));
    // Per-side opt-in: the decompiler sets `#[autogen_pro]` /
    // `#[autogen_epi]` for each side it dropped (a function may
    // drop just the prologue, just the epilogue, or both — PLT
    // entries are prologue-only, tail-call wrappers are
    // epilogue-only).  Without the relevant marker, lower emits
    // the body verbatim — no bytes get injected into GCC or
    // hand-written functions that lack the codec round-trip.
    let autogen_pro = f
        .attrs
        .iter()
        .any(|a| a.key == "autogen_pro" && matches!(a.value, ud_ast::AttrValue::Flag));
    let autogen_epi = f
        .attrs
        .iter()
        .any(|a| a.key == "autogen_epi" && matches!(a.value, ud_ast::AttrValue::Flag));
    // Backward-compat: an older `#[autogen]` flag means BOTH.
    let autogen_legacy = f
        .attrs
        .iter()
        .any(|a| a.key == "autogen" && matches!(a.value, ud_ast::AttrValue::Flag));
    let regen_pro = autogen_pro || autogen_legacy;
    let regen_epi = autogen_epi || autogen_legacy;
    if !has_prologue && regen_pro {
        let prefix = auto_prologue_bytes(f);
        out.extend_from_slice(&prefix);
    }
    // `func_ip` is the function's IP-space address (RVA on PE,
    // VA on ELF/Mach-O). Statements that re-encode rel32 jumps —
    // currently `Stmt::Switch`'s dispatch — compute their `ja`
    // offsets as `func_ip + out.len()`, so the auto-emitted
    // prologue's bytes (already in `out`) naturally shift the
    // body cursor.
    lower_stmts_into(&f.name, ip_base, &f.body, &mut out, arch)?;
    if !has_epilogue && regen_epi {
        let suffix = auto_epilogue_bytes(f);
        out.extend_from_slice(&suffix);
    }
    Ok(out)
}

/// Compute the default prologue's bytes for a function with
/// no explicit `@prologue`. Mirrors what the decompiler dropped
/// from the body — same inputs, same algorithm, same bytes.
fn auto_prologue_bytes(f: &FnDecl) -> Vec<u8> {
    let profile = profile_inputs_from_fn(f);
    let cb = codec_bits(profile.bits);
    let prologue = ud_arch_x86::default_prologue(&profile);
    ud_arch_x86::encode_prologue(&prologue, cb)
}

/// Pair to [`auto_prologue_bytes`].
fn auto_epilogue_bytes(f: &FnDecl) -> Vec<u8> {
    let profile = profile_inputs_from_fn(f);
    let cb = codec_bits(profile.bits);
    let epilogue = ud_arch_x86::default_epilogue(&profile);
    ud_arch_x86::encode_epilogue(&epilogue, cb)
}

fn codec_bits(bits: u32) -> ud_arch_x86::CodecBits {
    if bits == 64 {
        ud_arch_x86::CodecBits::Bits64
    } else {
        ud_arch_x86::CodecBits::Bits32
    }
}

/// Distill a `FnDecl` into the inputs the prologue/epilogue
/// default-computer needs. Mirrors the decompile-side helper
/// in `ud_decompile::build_function::profile_inputs_from_fn` —
/// same algorithm both sides so the defaults match.
fn profile_inputs_from_fn(f: &FnDecl) -> ud_arch_x86::ProfileInputs {
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
    let cf = f
        .attrs
        .iter()
        .any(|a| a.key == "cf" && matches!(a.value, ud_ast::AttrValue::Flag));
    // 64-bit functions carry `#[bits=64]`; absent → 32-bit.
    let bits = f
        .attrs
        .iter()
        .find_map(|a| match (&a.key, &a.value) {
            (k, ud_ast::AttrValue::Int(n)) if k == "bits" => Some(*n as u32),
            _ => None,
        })
        .unwrap_or(32);
    let mut touched_regs: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut max_neg_off: u32 = 0;
    let mut stack_arg_count: u32 = 0;
    for local in &f.locals {
        match local.kind {
            ud_ast::LocalKind::Register => {
                touched_regs.insert(local.name.as_str());
            }
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
    let body_has_call = body_contains_call(&f.body);
    let frame_required = !noframe;
    // Callee-saved register set varies by ABI/bitness — see the
    // mirror in `ud_decompile::build_function::profile_inputs_from_fn`.
    let saves_order: &[&str] = if bits == 64 {
        &["rbx", "r12", "r13", "r14", "r15"]
    } else {
        &["ebx", "esi", "edi"]
    };
    let mut saves_used: Vec<String> = Vec::new();
    for r in saves_order {
        if reg_views_intersect(&touched_regs, r) {
            saves_used.push((*r).to_string());
        }
    }
    // `sub_esp` stays as the raw max-negative-offset; the
    // bit-width formula lives in `default_prologue`.
    ud_arch_x86::ProfileInputs {
        saves_used,
        frame_required,
        sub_esp: max_neg_off,
        cf_protect: cf,
        stack_arg_count,
        abi,
        bits,
        frame_alt: bits == 64,
        body_has_call,
    }
}

fn body_contains_call(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| match s {
        Stmt::Call { name, .. } => !name.starts_with("tail_"),
        Stmt::IfBranch {
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            body_contains_call(pre_body)
                || body_contains_call(then_body)
                || else_body.as_deref().is_some_and(body_contains_call)
        }
        Stmt::Loop { body, .. } => body_contains_call(body),
        Stmt::Asm { text, .. } => text.contains("call "),
        _ => false,
    })
}

fn reg_views_intersect(touched: &std::collections::HashSet<&str>, reg64: &str) -> bool {
    let views: &[&str] = match reg64 {
        "rbx" => &["rbx", "ebx", "bx", "bl", "bh"],
        "r12" => &["r12", "r12d", "r12w", "r12b"],
        "r13" => &["r13", "r13d", "r13w", "r13b"],
        "r14" => &["r14", "r14d", "r14w", "r14b"],
        "r15" => &["r15", "r15d", "r15w", "r15b"],
        "ebx" => &["ebx", "bx", "bl", "bh"],
        "esi" => &["esi", "si", "sil"],
        "edi" => &["edi", "di", "dil"],
        _ => return false,
    };
    views.iter().any(|v| touched.contains(*v))
}

/// Recursive worker: lower a flat statement list into `out`,
/// recursing into nested arms (e.g. `Stmt::IfBranch`).
///
/// Path-tracking note: errors carry the function name. We intentionally
/// don't track stmt-index paths through nested arms — the body indices
/// in errors refer to the outermost iteration order, which is enough
/// to find the bad statement in practice.
#[allow(clippy::too_many_lines)]
/// Length the `then_tail_jmp` field will occupy in the
/// emitted bytes. Empty when both the pinned field is
/// empty and there's no else-body to jump over (the BPF
/// lifter omits the `ja` in that case).
fn then_tail_jmp_len(then_tail_jmp: &[u8], else_body: &[Stmt]) -> u64 {
    if !then_tail_jmp.is_empty() {
        then_tail_jmp.len() as u64
    } else if else_body.is_empty() {
        0
    } else {
        8 // a single BPF `ja` slot
    }
}

/// Length of the `tail_bytes` field. Always 8 if present
/// in the source OR regenerated; empty when explicitly
/// elided (rare for BPF).
fn tail_bytes_len(tail_bytes: &[u8]) -> u64 {
    if tail_bytes.is_empty() {
        8
    } else {
        tail_bytes.len() as u64
    }
}

#[allow(clippy::too_many_lines)]
fn lower_stmts_into(
    fn_name: &str,
    base_addr: Option<u64>,
    stmts: &[Stmt],
    out: &mut Vec<u8>,
    arch: &dyn ArchCodec,
) -> Result<(), LowerError> {
    for (i, stmt) in stmts.iter().enumerate() {
        match stmt {
            Stmt::Asm { text, bytes } => {
                if bytes.is_empty() {
                    // Bytes were dropped at decompile time
                    // because the canonical text re-assembles to
                    // them exactly. Ask the arch codec to
                    // re-encode; if the raw text fails, retry
                    // after a desymbolise pass (BPF's
                    // label_<hex> / sub_<hex> resolver, identity
                    // on other arches).
                    let ip = base_addr.map_or(0, |a| a.saturating_add(out.len() as u64));
                    let encoded = arch.assemble_one(text, ip).or_else(|first_err| {
                        let desym = arch.desymbolize(text, ip);
                        if desym == *text {
                            Err(first_err)
                        } else {
                            arch.assemble_one(&desym, ip)
                        }
                    });
                    let encoded = encoded.map_err(|e| LowerError::AsmAssembleFailed {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        text: text.clone(),
                        message: e.to_string(),
                    })?;
                    out.extend_from_slice(&encoded);
                } else {
                    out.extend_from_slice(bytes);
                }
            }
            Stmt::Switch {
                selector,
                cases,
                default_addr,
                dispatch,
                table_va,
            } => {
                let func_addr = base_addr.ok_or_else(|| LowerError::SwitchNeedsAddress {
                    fn_name: fn_name.to_string(),
                    stmt_index: i,
                })?;
                let cmp_ip = func_addr.checked_add(out.len() as u64).ok_or_else(|| {
                    LowerError::SwitchNeedsAddress {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                    }
                })?;
                let spec = SwitchSpec {
                    selector,
                    cases,
                    default_addr: *default_addr,
                    dispatch,
                    table_va: *table_va,
                    cmp_ip,
                };
                let bytes = arch.encode_switch_dispatch(&spec).map_err(|e| match e {
                    ArchError::Unsupported { .. } => LowerError::UnsupportedSwitchDispatch {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        dispatch: dispatch.clone(),
                    },
                    other => LowerError::ArchEncode {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        operation: "switch_dispatch",
                        message: other.to_string(),
                    },
                })?;
                out.extend_from_slice(&bytes);
            }
            Stmt::Goto { target_addr, wide } => {
                let func_addr = base_addr.ok_or_else(|| LowerError::GotoNeedsAddress {
                    fn_name: fn_name.to_string(),
                    stmt_index: i,
                })?;
                let source_ip = func_addr.checked_add(out.len() as u64).ok_or_else(|| {
                    LowerError::GotoNeedsAddress {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                    }
                })?;
                let bytes = arch
                    .encode_jump(source_ip, *target_addr, EncodeHints::wide(*wide))
                    .map_err(|e| LowerError::ArchEncode {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        operation: "jump",
                        message: e.to_string(),
                    })?;
                out.extend_from_slice(&bytes);
            }
            Stmt::IfGoto {
                target_addr,
                cmp_bytes,
                cond_code,
                wide,
                ..
            } => {
                let func_addr = base_addr.ok_or_else(|| LowerError::GotoNeedsAddress {
                    fn_name: fn_name.to_string(),
                    stmt_index: i,
                })?;
                out.extend_from_slice(cmp_bytes);
                let jcc_ip = func_addr.checked_add(out.len() as u64).ok_or_else(|| {
                    LowerError::GotoNeedsAddress {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                    }
                })?;
                let jcc = arch
                    .encode_cond_jump_with_code(
                        *cond_code,
                        jcc_ip,
                        *target_addr,
                        EncodeHints::wide(*wide),
                    )
                    .map_err(|e| LowerError::ArchEncode {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        operation: "cond_jump_with_code",
                        message: e.to_string(),
                    })?;
                out.extend_from_slice(&jcc);
            }
            Stmt::IfReturn {
                target_addr,
                cmp_bytes,
                cond_code,
                wide,
                ..
            } => {
                let func_addr = base_addr.ok_or_else(|| LowerError::GotoNeedsAddress {
                    fn_name: fn_name.to_string(),
                    stmt_index: i,
                })?;
                out.extend_from_slice(cmp_bytes);
                let jcc_ip = func_addr.checked_add(out.len() as u64).ok_or_else(|| {
                    LowerError::GotoNeedsAddress {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                    }
                })?;
                let jcc = arch
                    .encode_cond_jump_with_code(
                        *cond_code,
                        jcc_ip,
                        *target_addr,
                        EncodeHints::wide(*wide),
                    )
                    .map_err(|e| LowerError::ArchEncode {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        operation: "cond_jump_with_code",
                        message: e.to_string(),
                    })?;
                out.extend_from_slice(&jcc);
            }
            Stmt::Call {
                bytes,
                direct_target,
                ..
            } => {
                out.extend_from_slice(bytes);
                if let Some(target) = direct_target {
                    let func_addr = base_addr.ok_or_else(|| LowerError::GotoNeedsAddress {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                    })?;
                    let call_ip = func_addr.checked_add(out.len() as u64).ok_or_else(|| {
                        LowerError::GotoNeedsAddress {
                            fn_name: fn_name.to_string(),
                            stmt_index: i,
                        }
                    })?;
                    let call_bytes = arch
                        .encode_call(call_ip, *target, EncodeHints::default())
                        .map_err(|e| LowerError::ArchEncode {
                            fn_name: fn_name.to_string(),
                            stmt_index: i,
                            operation: "call",
                            message: e.to_string(),
                        })?;
                    out.extend_from_slice(&call_bytes);
                }
            }
            Stmt::Move { dst, src, bytes } => {
                if bytes.is_empty() {
                    // Bytes dropped at decompile time — ask the
                    // codec to re-emit.
                    let encoded =
                        arch.encode_move(dst, src)
                            .map_err(|e| LowerError::ArchEncode {
                                fn_name: fn_name.to_string(),
                                stmt_index: i,
                                operation: "move",
                                message: e.to_string(),
                            })?;
                    out.extend_from_slice(&encoded);
                } else {
                    out.extend_from_slice(bytes);
                }
            }
            Stmt::Return { value, bytes } => {
                if bytes.is_empty() {
                    let encoded =
                        arch.encode_return(Some(*value))
                            .map_err(|e| LowerError::ArchEncode {
                                fn_name: fn_name.to_string(),
                                stmt_index: i,
                                operation: "return",
                                message: e.to_string(),
                            })?;
                    out.extend_from_slice(&encoded);
                } else {
                    out.extend_from_slice(bytes);
                }
            }
            Stmt::Prologue { bytes, .. }
            | Stmt::Epilogue { bytes, .. }
            | Stmt::Save { bytes, .. }
            | Stmt::Restore { bytes, .. }
            | Stmt::SehInstall { bytes }
            | Stmt::SehRestore { bytes }
            | Stmt::ReturnExpr { bytes, .. }
            | Stmt::ArgSpill { bytes, .. }
            | Stmt::LocalSet { bytes, .. }
            | Stmt::LocalArith { bytes, .. }
            | Stmt::LocalCompound { bytes, .. }
            | Stmt::Inc16 { bytes, .. } => {
                out.extend_from_slice(bytes);
            }
            // Combined with Comment below — both zero-byte.
            #[allow(clippy::match_same_arms)]
            Stmt::Label { .. } => {}
            Stmt::IfBranch {
                cond_bytes,
                attrs,
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                // Byte layout (separated cmp/jcc case):
                //   head_bytes  ← #[head_bytes=…] attribute (cmp/test)
                //   pre_body    ← intervening flag-preserving insns
                //   cond_bytes  ← the jcc itself
                //   then_body
                //   else_body
                // For the adjacent (canonical) case `head_bytes` is
                // absent and `pre_body` is empty, so this collapses to
                // the historical `cond_bytes; then_body; else_body`.
                if let Some(head_bytes) = head_bytes_attr(attrs) {
                    out.extend_from_slice(head_bytes);
                }
                lower_stmts_into(fn_name, base_addr, pre_body, out, arch)?;
                out.extend_from_slice(cond_bytes);
                lower_stmts_into(fn_name, base_addr, then_body, out, arch)?;
                if let Some(else_body) = else_body {
                    lower_stmts_into(fn_name, base_addr, else_body, out, arch)?;
                }
            }
            Stmt::Loop {
                entry_jmp_bytes,
                tail_bytes,
                body,
                ..
            } => {
                if let Some(jmp_bytes) = entry_jmp_bytes {
                    out.extend_from_slice(jmp_bytes);
                }
                lower_stmts_into(fn_name, base_addr, body, out, arch)?;
                out.extend_from_slice(tail_bytes);
            }
            Stmt::IfBlock {
                cond_text,
                cond_bytes,
                then_body,
                then_tail_jmp,
                else_body,
            } => {
                // Effective cond_bytes length: 8 when we'll
                // regenerate, else the pinned length.
                let cond_len = if cond_bytes.is_empty() {
                    8
                } else {
                    cond_bytes.len()
                };
                // Lower bodies to scratch buffers so we know
                // their sizes before emitting the jcc / ja
                // that frame them. The scratch lower must see
                // the *real* base_addr for the start of each
                // body — otherwise nested PC-relative encodings
                // (call_local, jcc, etc.) get the wrong IP.
                let ifblock_ip = base_addr.map_or(0, |a| a.saturating_add(out.len() as u64));
                let then_base = base_addr.map(|a| {
                    a.saturating_add(out.len() as u64)
                        .saturating_add(cond_len as u64)
                });
                let mut then_buf = Vec::new();
                lower_stmts_into(fn_name, then_base, then_body, &mut then_buf, arch)?;
                let then_tail_size = then_tail_jmp_len(then_tail_jmp, else_body);
                let else_base = base_addr.map(|a| {
                    a.saturating_add(out.len() as u64)
                        .saturating_add(cond_len as u64)
                        .saturating_add(then_buf.len() as u64)
                        .saturating_add(then_tail_size)
                });
                let mut else_buf = Vec::new();
                lower_stmts_into(fn_name, else_base, else_body, &mut else_buf, arch)?;
                // Resolve cond_bytes (regenerate when empty).
                let cb = if cond_bytes.is_empty() {
                    let then_tail_size = then_tail_jmp_len(then_tail_jmp, else_body);
                    let cond_target =
                        ifblock_ip + cond_len as u64 + then_buf.len() as u64 + then_tail_size;
                    arch.encode_cond_jump(
                        cond_text,
                        ifblock_ip,
                        cond_target,
                        EncodeHints::default(),
                    )
                    .map_err(|e| LowerError::AsmAssembleFailed {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        text: format!("ifblock({cond_text})"),
                        message: e.to_string(),
                    })?
                } else {
                    cond_bytes.clone()
                };
                out.extend_from_slice(&cb);
                out.extend_from_slice(&then_buf);
                let ttj = if then_tail_jmp.is_empty() {
                    if else_body.is_empty() {
                        Vec::new()
                    } else {
                        // Emit a `ja` over the else body.
                        let ttj_ip = base_addr.map_or(0, |a| a.saturating_add(out.len() as u64));
                        let jmp_size =
                            arch.encoded_jump_size(ttj_ip, ttj_ip, EncodeHints::default()) as u64;
                        let jmp_target = ttj_ip + jmp_size + else_buf.len() as u64;
                        arch.encode_jump(ttj_ip, jmp_target, EncodeHints::default())
                            .map_err(|e| LowerError::AsmAssembleFailed {
                                fn_name: fn_name.to_string(),
                                stmt_index: i,
                                text: format!("ifblock({cond_text}) tail"),
                                message: e.to_string(),
                            })?
                    }
                } else {
                    then_tail_jmp.clone()
                };
                out.extend_from_slice(&ttj);
                out.extend_from_slice(&else_buf);
            }
            Stmt::WhileBlock {
                cond_text,
                entry_bytes,
                tail_bytes,
                body,
            } => {
                let entry_ip = base_addr.map_or(0, |a| a.saturating_add(out.len() as u64));
                let entry_len = if entry_bytes.is_empty() {
                    8
                } else {
                    entry_bytes.len()
                };
                // Lower body to scratch so we know its size.
                // Scratch base_addr = real position the body
                // will occupy = base + out.len() + entry_len.
                let body_base = base_addr.map(|a| {
                    a.saturating_add(out.len() as u64)
                        .saturating_add(entry_len as u64)
                });
                let mut body_buf = Vec::new();
                lower_stmts_into(fn_name, body_base, body, &mut body_buf, arch)?;
                let eb = if entry_bytes.is_empty() {
                    let tail_size = tail_bytes_len(tail_bytes);
                    let cond_target =
                        entry_ip + entry_len as u64 + body_buf.len() as u64 + tail_size;
                    arch.encode_cond_jump(cond_text, entry_ip, cond_target, EncodeHints::default())
                        .map_err(|e| LowerError::AsmAssembleFailed {
                            fn_name: fn_name.to_string(),
                            stmt_index: i,
                            text: format!("whileblock({cond_text})"),
                            message: e.to_string(),
                        })?
                } else {
                    entry_bytes.clone()
                };
                out.extend_from_slice(&eb);
                out.extend_from_slice(&body_buf);
                let tb = if tail_bytes.is_empty() {
                    // `ja` back to entry_ip from the current cursor.
                    let ja_ip = base_addr.map_or(0, |a| a.saturating_add(out.len() as u64));
                    arch.encode_jump(ja_ip, entry_ip, EncodeHints::default())
                        .map_err(|e| LowerError::AsmAssembleFailed {
                            fn_name: fn_name.to_string(),
                            stmt_index: i,
                            text: format!("whileblock({cond_text}) tail"),
                            message: e.to_string(),
                        })?
                } else {
                    tail_bytes.clone()
                };
                out.extend_from_slice(&tb);
            }
            Stmt::Comment(_) => {}
        }
    }
    Ok(())
}

/// Lower every function in the file to bytes.
///
/// Walks both top-level items and items nested inside `@section`
/// blocks. Returns one [`LoweredFunction`] per [`Item::Function`] in
/// source order. Non-function items are skipped silently.
pub fn lower_functions(
    file: &UdFile,
    arch: &dyn ArchCodec,
) -> Result<Vec<LoweredFunction>, LowerError> {
    let mut out = Vec::new();
    walk_functions(&file.items, None, &mut out, arch)?;
    Ok(out)
}

/// Walk every `Function` in `items`, lowering each to bytes. The
/// `section_cursor` tracks the cumulative byte position within
/// the enclosing `@section` block (in IP space), so functions
/// without an explicit `@addr` can still resolve PC-relative
/// references — their effective IP is the cumulative cursor.
/// Top-level functions (no enclosing section) keep the original
/// behavior: the cursor is `None` and PC-relative regen falls
/// back to `f.addr`.
fn walk_functions(
    items: &[Item],
    section_cursor: Option<u64>,
    out: &mut Vec<LoweredFunction>,
    arch: &dyn ArchCodec,
) -> Result<(), LowerError> {
    let mut cursor = section_cursor;
    for item in items {
        match item {
            Item::Function(f) => {
                let ip = match (f.addr, cursor) {
                    (Some(a), _) => Some(a),
                    (None, Some(c)) => Some(c),
                    (None, None) => None,
                };
                let bytes = lower_function_bytes_at(f, ip, arch)?;
                if let Some(c) = cursor.as_mut() {
                    let placement = f.addr.unwrap_or(*c);
                    *c = placement.saturating_add(bytes.len() as u64);
                }
                out.push(LoweredFunction {
                    name: f.name.clone(),
                    addr: f.addr.or(ip),
                    bytes,
                });
            }
            Item::Section {
                addr,
                items: nested,
                ..
            } => walk_functions(nested, Some(*addr), out, arch)?,
            Item::Raw { addr, bytes } => {
                if let Some(c) = cursor.as_mut() {
                    *c = (*addr).saturating_add(bytes.len() as u64);
                }
            }
            Item::Strings { addr, strings } => {
                if let Some(c) = cursor.as_mut() {
                    *c = (*addr).saturating_add(lower_strings_bytes(strings).len() as u64);
                }
            }
            Item::Notes { addr, entries } => {
                if let Some(c) = cursor.as_mut() {
                    *c = (*addr).saturating_add(lower_notes_bytes(entries).len() as u64);
                }
            }
            Item::JumpTable {
                addr,
                dispatch,
                entries,
            } => {
                if let Some(c) = cursor.as_mut() {
                    let bytes = lower_jump_table_bytes(*addr, dispatch, entries)?;
                    *c = (*addr).saturating_add(bytes.len() as u64);
                }
            }
            Item::Comment(_) => {}
        }
    }
    Ok(())
}

/// Pack a string list into the byte layout of an ELF `SHT_STRTAB`
/// section: each entry's UTF-8 bytes followed by a single 0x00
/// terminator. The first entry is conventionally empty, which lowers
/// to a single zero byte.
fn lower_strings_bytes(strings: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in strings {
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    out
}

/// Pack a note-entry list into the byte layout of an ELF `SHT_NOTE`
/// section: per entry an `Elf64_Nhdr` (3× little-endian `u32`:
/// `name_size`, `desc_size`, `type`) followed by the name (with a
/// trailing NUL, padded to a 4-byte boundary) and the descriptor
/// (padded to a 4-byte boundary).
fn lower_notes_bytes(entries: &[ud_ast::NoteEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let name_bytes = e.name.as_bytes();
        // Note: name_size in the header counts the trailing NUL.
        let name_size = u32::try_from(name_bytes.len() + 1).unwrap_or(0);
        let desc_size = u32::try_from(e.desc.len()).unwrap_or(0);
        out.extend_from_slice(&name_size.to_le_bytes());
        out.extend_from_slice(&desc_size.to_le_bytes());
        out.extend_from_slice(&e.note_type.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&e.desc);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

/// Encode an [`Item::JumpTable`] to its on-disk bytes. The
/// dispatch tag selects the entry encoding:
///
/// * `"gcc_pie_rel32"` — 4-byte signed little-endian
///   `target - table_base`, written in case-index order. Matches
///   GCC's PIE switch dispatch.
/// * `"msvc_va32"` — 4-byte little-endian absolute VA of the
///   target. Matches MSVC's `jmp [base + idx*4]` dispatch.
///
/// The case index range is taken as `0..entries.len()`; sparse
/// tables (cases that aren't 0..N) are not supported at lower
/// time — the source must spell out gaps with `default:` arms
/// or an `@raw` fallback.
#[allow(clippy::cast_possible_wrap)]
fn lower_jump_table_bytes(
    addr: u64,
    dispatch: &str,
    entries: &[ud_ast::JumpTableEntry],
) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::with_capacity(entries.len() * 4);
    match dispatch {
        "gcc_pie_rel32" => {
            for e in entries {
                let off = e.target.wrapping_sub(addr) as i64 as i32;
                out.extend_from_slice(&off.to_le_bytes());
            }
        }
        "msvc_va32" => {
            for e in entries {
                let va = u32::try_from(e.target & 0xffff_ffff).unwrap_or(0);
                out.extend_from_slice(&va.to_le_bytes());
            }
        }
        other => {
            return Err(LowerError::UnknownJumpTableDispatch {
                dispatch: other.to_string(),
            });
        }
    }
    Ok(out)
}

/// One section lowered to its on-disk bytes.
#[derive(Debug, Clone)]
pub struct LoweredSection {
    pub name: String,
    pub addr: u64,
    pub bytes: Vec<u8>,
}

/// Lower the contents of an `@section` to its byte sequence.
///
/// Walks the section's items in source order, requiring contiguity:
/// the first item starts at `section.addr`, and each subsequent item
/// starts exactly where the previous one ended. Gaps and overlaps are
/// hard errors.
///
/// Nested sections are rejected — the decompiler doesn't produce them
/// and the runtime semantics aren't yet defined.
pub fn lower_section_bytes(
    name: &str,
    section_addr: u64,
    items: &[Item],
    arch: &dyn ArchCodec,
) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::new();
    let mut cursor = section_addr;

    for item in items {
        // Lower each item to its bytes; for `Function` items we
        // also want the function's true `addr` in IP space (its
        // `f.addr`) so we can detect edit-induced shifts. Items
        // that declare an explicit `addr` get checked against
        // the cumulative cursor; items without an explicit addr
        // (today: `Item::Comment` only — every byte-bearing
        // variant carries an addr) just append.
        let (explicit_addr, item_bytes) = match item {
            Item::Comment(_) => continue,
            Item::Raw { addr, bytes } => (Some(*addr), bytes.clone()),
            Item::Strings { addr, strings } => (Some(*addr), lower_strings_bytes(strings)),
            Item::Notes { addr, entries } => (Some(*addr), lower_notes_bytes(entries)),
            Item::JumpTable {
                addr,
                dispatch,
                entries,
            } => (
                Some(*addr),
                lower_jump_table_bytes(*addr, dispatch, entries)?,
            ),
            Item::Function(f) => {
                let bytes = lower_function_bytes_at(f, Some(cursor), arch)?;
                (f.addr, bytes)
            }
            Item::Section { name: nested, .. } => {
                return Err(LowerError::NestedSection {
                    section: nested.clone(),
                });
            }
        };

        if let Some(item_addr) = explicit_addr {
            if item_addr < cursor {
                return Err(LowerError::SectionOverlap {
                    section: name.to_string(),
                    cursor,
                    item_addr,
                });
            }
            if item_addr > cursor {
                // A gap declared by the source: zero-pad so the
                // declared `addr` lands at the right offset. This
                // handles `.text` alignment padding between
                // functions without forcing the source to spell
                // out an `@raw(addr, [0x00; N])` block.
                let gap = (item_addr - cursor) as usize;
                out.resize(out.len() + gap, 0);
                cursor = item_addr;
            }
        }
        out.extend_from_slice(&item_bytes);
        cursor = cursor.saturating_add(item_bytes.len() as u64);
    }

    Ok(out)
}

/// Lower every `@section` block in `file` to its bytes. Returns one
/// [`LoweredSection`] per top-level section, in source order.
pub fn lower_sections(
    file: &UdFile,
    arch: &dyn ArchCodec,
) -> Result<Vec<LoweredSection>, LowerError> {
    let mut out = Vec::new();
    for item in &file.items {
        if let Item::Section { name, addr, items } = item {
            let bytes = lower_section_bytes(name, *addr, items, arch)?;
            out.push(LoweredSection {
                name: name.clone(),
                addr: *addr,
                bytes,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_arch_x86::X86Codec;
    use ud_ast::{FnDecl, Module, Stmt};

    fn empty_module() -> Module {
        Module { fields: vec![] }
    }

    /// Default codec used by tests — historically every test in
    /// this file lowered x86_64 fixtures, so X86Codec::BITS64 is
    /// the right default.
    fn arch() -> X86Codec {
        X86Codec::BITS64
    }

    #[test]
    fn lower_function_with_pinned_bytes_concatenates() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![
                Stmt::asm("endbr64", vec![0xf3, 0x0f, 0x1e, 0xfa]),
                Stmt::asm("ret", vec![0xc3]),
            ],
        };
        let bytes = lower_function_bytes(&f, &arch()).unwrap();
        assert_eq!(bytes, vec![0xf3, 0x0f, 0x1e, 0xfa, 0xc3]);
    }

    #[test]
    fn lower_if_branch_concatenates_cond_then_else() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![Stmt::IfBranch {
                cond_text: "cmp eax,0; je".into(),
                cond_bytes: vec![0x83, 0xf8, 0x00, 0x74, 0x01],
                attrs: Vec::new(),
                pre_body: Vec::new(),
                then_body: vec![Stmt::asm("ret", vec![0xc3])],
                else_body: Some(vec![Stmt::asm("nop", vec![0x90])]),
            }],
        };
        let bytes = lower_function_bytes(&f, &arch()).unwrap();
        // cond_bytes + then bytes + else bytes
        assert_eq!(bytes, vec![0x83, 0xf8, 0x00, 0x74, 0x01, 0xc3, 0x90]);
    }

    #[test]
    fn lower_if_branch_without_else_omits_else_bytes() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![Stmt::IfBranch {
                cond_text: "test rax,rax; je".into(),
                cond_bytes: vec![0x48, 0x85, 0xc0, 0x74, 0x02],
                attrs: Vec::new(),
                pre_body: Vec::new(),
                then_body: vec![Stmt::asm("call rax", vec![0xff, 0xd0])],
                else_body: None,
            }],
        };
        let bytes = lower_function_bytes(&f, &arch()).unwrap();
        // Only cond_bytes + then bytes; no else bytes.
        assert_eq!(bytes, vec![0x48, 0x85, 0xc0, 0x74, 0x02, 0xff, 0xd0]);
    }

    #[test]
    fn lower_function_skips_comments() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![
                Stmt::asm("ret", vec![0xc3]),
                Stmt::Comment("block: 0x1001".into()),
            ],
        };
        assert_eq!(lower_function_bytes(&f, &arch()).unwrap(), vec![0xc3]);
    }

    #[test]
    fn lower_function_reassembles_bytesless_asm() {
        // `@asm("ret")` without a pinned byte list now re-encodes
        // via the in-crate x86 assembler at lower time. `ret`
        // is a zero-operand mnemonic the assembler covers, so
        // the rebuilt function emits `0xc3`.
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![Stmt::asm_text("ret")],
        };
        assert_eq!(lower_function_bytes(&f, &arch()).unwrap(), vec![0xc3]);
    }

    #[test]
    fn lower_function_errors_on_unassemblable_bytesless_asm() {
        // A mnemonic the assembler doesn't yet support and no
        // pinned bytes is a hard error — otherwise the lower
        // would silently produce a zero-byte stand-in.
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![Stmt::asm_text("completely-fake-insn")],
        };
        let err = lower_function_bytes(&f, &arch()).unwrap_err();
        assert!(
            matches!(err, LowerError::AsmAssembleFailed { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn lower_section_concatenates_contiguous_items() {
        let items = vec![
            Item::Function(FnDecl {
                addr: Some(0x1000),
                name: "f".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![Stmt::asm("ret", vec![0xc3])],
            }),
            Item::Raw {
                addr: 0x1001,
                bytes: vec![0x90, 0x90],
            },
        ];
        let bytes = lower_section_bytes(".text", 0x1000, &items, &arch()).unwrap();
        assert_eq!(bytes, vec![0xc3, 0x90, 0x90]);
    }

    #[test]
    fn lower_section_zero_fills_gap() {
        // Items separated by a gap of declared addresses get
        // zero-padded so the second item lands at its declared
        // addr — supports section alignment without forcing the
        // source to spell out an `@raw` zero-fill block.
        let items = vec![
            Item::Function(FnDecl {
                addr: Some(0x1000),
                name: "f".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![Stmt::asm("ret", vec![0xc3])],
            }),
            Item::Raw {
                addr: 0x1010, // 15-byte zero gap from 0x1001 to 0x1010
                bytes: vec![0x90],
            },
        ];
        let bytes = lower_section_bytes(".text", 0x1000, &items, &arch()).unwrap();
        let mut expected = vec![0xc3];
        expected.extend(std::iter::repeat(0u8).take(15));
        expected.push(0x90);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn lower_section_detects_overlap() {
        let items = vec![
            Item::Raw {
                addr: 0x1000,
                bytes: vec![0xaa, 0xbb, 0xcc],
            },
            Item::Raw {
                addr: 0x1001, // overlaps with previous (which ended at 0x1003)
                bytes: vec![0xdd],
            },
        ];
        let err = lower_section_bytes(".text", 0x1000, &items, &arch()).unwrap_err();
        assert!(matches!(err, LowerError::SectionOverlap { .. }));
    }

    #[test]
    fn lower_section_skips_nested_comments() {
        let items = vec![
            Item::Comment("preamble".into()),
            Item::Raw {
                addr: 0x1000,
                bytes: vec![0xaa],
            },
        ];
        let bytes = lower_section_bytes(".x", 0x1000, &items, &arch()).unwrap();
        assert_eq!(bytes, vec![0xaa]);
    }

    #[test]
    fn lower_jump_table_gcc_pie_rel32_encodes_signed_offsets() {
        // Table at 0x2020 dispatches to:
        //   case 0 → 0x117a   (offset -0xea6, low bytes 5a f1 ff ff)
        //   case 1 → 0x1183   (offset -0xe9d, low bytes 63 f1 ff ff)
        let bytes = lower_jump_table_bytes(
            0x2020,
            "gcc_pie_rel32",
            &[
                ud_ast::JumpTableEntry {
                    case: 0,
                    target: 0x117a,
                },
                ud_ast::JumpTableEntry {
                    case: 1,
                    target: 0x1183,
                },
            ],
        )
        .unwrap();
        assert_eq!(bytes, vec![0x5a, 0xf1, 0xff, 0xff, 0x63, 0xf1, 0xff, 0xff]);
    }

    #[test]
    fn lower_jump_table_msvc_va32_encodes_absolute_va() {
        let bytes = lower_jump_table_bytes(
            0x40_2000,
            "msvc_va32",
            &[
                ud_ast::JumpTableEntry {
                    case: 0,
                    target: 0x40_117a,
                },
                ud_ast::JumpTableEntry {
                    case: 1,
                    target: 0x40_1183,
                },
            ],
        )
        .unwrap();
        assert_eq!(bytes, vec![0x7a, 0x11, 0x40, 0x00, 0x83, 0x11, 0x40, 0x00]);
    }

    #[test]
    fn lower_jump_table_unknown_dispatch_errors() {
        let err = lower_jump_table_bytes(0x2020, "bogus", &[]).unwrap_err();
        assert!(matches!(err, LowerError::UnknownJumpTableDispatch { .. }));
    }

    #[test]
    fn lower_functions_returns_one_entry_per_function() {
        let file = UdFile {
            module: empty_module(),
            items: vec![
                Item::Function(FnDecl {
                    addr: Some(0x1000),
                    name: "a".into(),
                    attrs: Vec::new(),
                    locals: Vec::new(),
                    signature: None,
                    body: vec![Stmt::asm("ret", vec![0xc3])],
                }),
                Item::Comment("note: skip me".into()),
                Item::Function(FnDecl {
                    addr: Some(0x2000),
                    name: "b".into(),
                    attrs: Vec::new(),
                    locals: Vec::new(),
                    signature: None,
                    body: vec![Stmt::asm("ret", vec![0xc3])],
                }),
            ],
        };
        let lowered = lower_functions(&file, &arch()).unwrap();
        assert_eq!(lowered.len(), 2);
        assert_eq!(lowered[0].name, "a");
        assert_eq!(lowered[0].addr, Some(0x1000));
        assert_eq!(lowered[0].bytes, vec![0xc3]);
        assert_eq!(lowered[1].name, "b");
    }
}

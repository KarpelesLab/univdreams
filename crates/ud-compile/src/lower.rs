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

    #[error("function `{fn_name}` has no @addr; cannot place it inside a section")]
    FunctionWithoutAddr { fn_name: String },
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
pub fn lower_function_bytes(f: &FnDecl) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::new();
    let has_prologue = matches!(f.body.first(), Some(Stmt::Prologue { .. }));
    let has_epilogue = matches!(f.body.last(), Some(Stmt::Epilogue { .. }));
    // `#[autogen]` is the explicit opt-IN: the decompiler set it
    // when it dropped a matched-default prologue/epilogue. Without
    // this marker, lower emits the body verbatim — no MSVC-style
    // bytes get injected into GCC or hand-written functions.
    let autogen = f
        .attrs
        .iter()
        .any(|a| a.key == "autogen" && matches!(a.value, ud_ast::AttrValue::Flag));
    if !has_prologue && autogen {
        let prefix = auto_prologue_bytes(f);
        out.extend_from_slice(&prefix);
    }
    lower_stmts_into(&f.name, &f.body, &mut out)?;
    if !has_epilogue && autogen {
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
    let prologue = ud_arch_x86::default_prologue(&profile);
    ud_arch_x86::encode_prologue(&prologue, ud_arch_x86::CodecBits::Bits32)
}

/// Pair to [`auto_prologue_bytes`].
fn auto_epilogue_bytes(f: &FnDecl) -> Vec<u8> {
    let profile = profile_inputs_from_fn(f);
    let epilogue = ud_arch_x86::default_epilogue(&profile);
    ud_arch_x86::encode_epilogue(&epilogue, ud_arch_x86::CodecBits::Bits32)
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
    // `#[noframe]` opts the function out of MSVC /Oy- default
    // (frame pointer always). The decompiler emits this when the
    // no-frame variant of the default prologue/epilogue matches.
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
    // function. The opt-out is the `#[noframe]` flag, which the
    // decompiler emits when the no-frame default variant matched
    // the observed prologue/epilogue. (Whether to auto-inject at
    // all is gated by `#[autogen]` upstream in `lower_function_bytes`.)
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

/// Recursive worker: lower a flat statement list into `out`,
/// recursing into nested arms (e.g. `Stmt::IfBranch`).
///
/// Path-tracking note: errors carry the function name. We intentionally
/// don't track stmt-index paths through nested arms — the body indices
/// in errors refer to the outermost iteration order, which is enough
/// to find the bad statement in practice.
fn lower_stmts_into(fn_name: &str, stmts: &[Stmt], out: &mut Vec<u8>) -> Result<(), LowerError> {
    for (i, stmt) in stmts.iter().enumerate() {
        match stmt {
            Stmt::Asm { text, bytes } => {
                if bytes.is_empty() {
                    return Err(LowerError::MissingBytes {
                        fn_name: fn_name.to_string(),
                        stmt_index: i,
                        text: text.clone(),
                    });
                }
                out.extend_from_slice(bytes);
            }
            Stmt::Return { bytes, .. }
            | Stmt::Prologue { bytes, .. }
            | Stmt::Epilogue { bytes, .. }
            | Stmt::Save { bytes, .. }
            | Stmt::Restore { bytes, .. }
            | Stmt::IfReturn { bytes, .. }
            | Stmt::Goto { bytes, .. }
            | Stmt::IfGoto { bytes, .. }
            | Stmt::Switch { bytes, .. }
            | Stmt::SehInstall { bytes }
            | Stmt::SehRestore { bytes }
            | Stmt::ReturnExpr { bytes, .. }
            | Stmt::ArgSpill { bytes, .. }
            | Stmt::Call { bytes, .. }
            | Stmt::LocalSet { bytes, .. }
            | Stmt::LocalArith { bytes, .. }
            | Stmt::LocalCompound { bytes, .. }
            | Stmt::Move { bytes, .. }
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
                lower_stmts_into(fn_name, pre_body, out)?;
                out.extend_from_slice(cond_bytes);
                lower_stmts_into(fn_name, then_body, out)?;
                if let Some(else_body) = else_body {
                    lower_stmts_into(fn_name, else_body, out)?;
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
                lower_stmts_into(fn_name, body, out)?;
                out.extend_from_slice(tail_bytes);
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
pub fn lower_functions(file: &UdFile) -> Result<Vec<LoweredFunction>, LowerError> {
    let mut out = Vec::new();
    walk_functions(&file.items, &mut out)?;
    Ok(out)
}

fn walk_functions(items: &[Item], out: &mut Vec<LoweredFunction>) -> Result<(), LowerError> {
    for item in items {
        match item {
            Item::Function(f) => {
                out.push(LoweredFunction {
                    name: f.name.clone(),
                    addr: f.addr,
                    bytes: lower_function_bytes(f)?,
                });
            }
            Item::Section { items: nested, .. } => walk_functions(nested, out)?,
            Item::Comment(_) | Item::Raw { .. } => {}
        }
    }
    Ok(())
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
) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::new();
    let mut cursor = section_addr;

    for item in items {
        let (item_addr, item_bytes) = match item {
            Item::Comment(_) => continue,
            Item::Raw { addr, bytes } => (*addr, bytes.clone()),
            Item::Function(f) => {
                let addr = f.addr.ok_or_else(|| LowerError::FunctionWithoutAddr {
                    fn_name: f.name.clone(),
                })?;
                (addr, lower_function_bytes(f)?)
            }
            Item::Section { name: nested, .. } => {
                return Err(LowerError::NestedSection {
                    section: nested.clone(),
                });
            }
        };

        if item_addr < cursor {
            return Err(LowerError::SectionOverlap {
                section: name.to_string(),
                cursor,
                item_addr,
            });
        }
        if item_addr > cursor {
            return Err(LowerError::SectionGap {
                section: name.to_string(),
                cursor,
                item_addr,
            });
        }
        out.extend_from_slice(&item_bytes);
        cursor = cursor.saturating_add(item_bytes.len() as u64);
    }

    Ok(out)
}

/// Lower every `@section` block in `file` to its bytes. Returns one
/// [`LoweredSection`] per top-level section, in source order.
pub fn lower_sections(file: &UdFile) -> Result<Vec<LoweredSection>, LowerError> {
    let mut out = Vec::new();
    for item in &file.items {
        if let Item::Section { name, addr, items } = item {
            let bytes = lower_section_bytes(name, *addr, items)?;
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
    use ud_ast::{FnDecl, Module, Stmt};

    fn empty_module() -> Module {
        Module { fields: vec![] }
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
        let bytes = lower_function_bytes(&f).unwrap();
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
        let bytes = lower_function_bytes(&f).unwrap();
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
        let bytes = lower_function_bytes(&f).unwrap();
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
        assert_eq!(lower_function_bytes(&f).unwrap(), vec![0xc3]);
    }

    #[test]
    fn lower_function_without_bytes_errors() {
        let f = FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: vec![Stmt::asm_text("ret")],
        };
        let err = lower_function_bytes(&f).unwrap_err();
        let LowerError::MissingBytes {
            fn_name,
            stmt_index,
            text,
        } = err
        else {
            panic!("expected MissingBytes")
        };
        assert_eq!(fn_name, "f");
        assert_eq!(stmt_index, 0);
        assert_eq!(text, "ret");
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
        let bytes = lower_section_bytes(".text", 0x1000, &items).unwrap();
        assert_eq!(bytes, vec![0xc3, 0x90, 0x90]);
    }

    #[test]
    fn lower_section_detects_gap() {
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
                addr: 0x1010, // gap from 0x1001 to 0x1010
                bytes: vec![0x90],
            },
        ];
        let err = lower_section_bytes(".text", 0x1000, &items).unwrap_err();
        assert!(matches!(err, LowerError::SectionGap { .. }));
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
        let err = lower_section_bytes(".text", 0x1000, &items).unwrap_err();
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
        let bytes = lower_section_bytes(".x", 0x1000, &items).unwrap();
        assert_eq!(bytes, vec![0xaa]);
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
        let lowered = lower_functions(&file).unwrap();
        assert_eq!(lowered.len(), 2);
        assert_eq!(lowered[0].name, "a");
        assert_eq!(lowered[0].addr, Some(0x1000));
        assert_eq!(lowered[0].bytes, vec![0xc3]);
        assert_eq!(lowered[1].name, "b");
    }
}

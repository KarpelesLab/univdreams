//! Pre-lower verification: walk the AST and report `@asm` lines whose
//! text disagrees with their pinned bytes.
//!
//! Today this is the cleanest signal we have that someone edited a
//! `.ud` file: the lower path uses pinned bytes as ground truth, so a
//! divergence between text and bytes means lowering will produce
//! something that doesn't match what the source *says*.
//!
//! A stricter "would the edited text re-encode to the same length"
//! check needs a text assembler, which we don't yet ship. For now the
//! verification is "does the user's text agree with the canonical
//! form iced would produce for these bytes."

use ud_arch_x86::{verify_intel_text, Bitness, VerifyAsm};
use ud_ast::{Item, Stmt, UdFile, Value};

/// One verification finding. Emitted to stderr by the CLI; collected
/// for programmatic use elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmWarning {
    /// `text` and the canonical form for `bytes` differ. The lower
    /// path will use `bytes`; the user's `text` is informational.
    Divergence {
        location: AsmLocation,
        text: String,
        canonical: String,
    },
    /// `bytes` couldn't be decoded as a single x86 instruction.
    /// Suggests the bytes were tampered with.
    Undecodable { location: AsmLocation, text: String },
    /// `bytes` decoded to multiple instructions. One `@asm` per
    /// instruction is the convention; this signals the bytes belong
    /// in separate `@asm` lines.
    MultipleInsns {
        location: AsmLocation,
        text: String,
        count: usize,
    },
}

/// Where in the AST the warning fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmLocation {
    /// Containing function name, if any.
    pub function: Option<String>,
    /// Containing section name, if any.
    pub section: Option<String>,
    /// 0-based statement index inside the function body.
    pub stmt_index: usize,
}

/// Walk every `Stmt::Asm` in `file` and verify text/byte consistency.
///
/// Currently x86_64-only: returns an empty vector for files whose
/// `@module.arch` field isn't `"x86_64"`. `@asm` lines without pinned
/// bytes are skipped (no bytes → nothing to verify against).
#[must_use]
pub fn verify_asm(file: &UdFile) -> Vec<AsmWarning> {
    if !arch_is_x86_64(&file.module.fields) {
        return Vec::new();
    }
    let mut out = Vec::new();
    walk(&file.items, None, &mut out);
    out
}

fn arch_is_x86_64(fields: &[ud_ast::Field]) -> bool {
    fields
        .iter()
        .any(|f| f.name == "arch" && matches!(&f.value, Value::String(s) if s == "x86_64"))
}

fn walk(items: &[Item], section: Option<&str>, out: &mut Vec<AsmWarning>) {
    for item in items {
        match item {
            Item::Function(f) => verify_fn_body(f, section, out),
            Item::Section { name, items, .. } => walk(items, Some(name.as_str()), out),
            Item::Comment(_)
            | Item::Raw { .. }
            | Item::Strings { .. }
            | Item::Notes { .. }
            | Item::JumpTable { .. } => {}
        }
    }
}

fn verify_fn_body(f: &ud_ast::FnDecl, section: Option<&str>, out: &mut Vec<AsmWarning>) {
    let base_addr = f.addr.unwrap_or(0);
    let mut cursor = base_addr;
    verify_stmts(f, section, &f.body, &mut cursor, out);
}

#[allow(clippy::too_many_lines)]
fn verify_stmts(
    f: &ud_ast::FnDecl,
    section: Option<&str>,
    stmts: &[Stmt],
    cursor: &mut u64,
    out: &mut Vec<AsmWarning>,
) {
    for (i, stmt) in stmts.iter().enumerate() {
        match stmt {
            Stmt::Asm { text, bytes } => {
                if bytes.is_empty() {
                    continue;
                }
                let location = AsmLocation {
                    function: Some(f.name.clone()),
                    section: section.map(str::to_string),
                    stmt_index: i,
                };
                match verify_intel_text(Bitness::Bits64, text, bytes, *cursor) {
                    VerifyAsm::Match => {}
                    VerifyAsm::Diverged { canonical } => {
                        out.push(AsmWarning::Divergence {
                            location,
                            text: text.clone(),
                            canonical,
                        });
                    }
                    VerifyAsm::Undecodable => {
                        out.push(AsmWarning::Undecodable {
                            location,
                            text: text.clone(),
                        });
                    }
                    VerifyAsm::MultipleInsns { count } => {
                        out.push(AsmWarning::MultipleInsns {
                            location,
                            text: text.clone(),
                            count,
                        });
                    }
                }
                *cursor = cursor.saturating_add(bytes.len() as u64);
            }
            // @return / @prologue / @epilogue are structurally multi-
            // instruction groups with their own pinned bytes; advance
            // the cursor by the byte count so subsequent @asm RIPs
            // stay correct.
            Stmt::Return { bytes, .. }
            | Stmt::Prologue { bytes, .. }
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
            | Stmt::Move { bytes, .. }
            | Stmt::Inc16 { bytes, .. }
            | Stmt::RegArith { bytes, .. } => {
                *cursor = cursor.saturating_add(bytes.len() as u64);
            }
            Stmt::Call {
                bytes,
                direct_target,
                ..
            } => {
                let mut size = bytes.len() as u64;
                if direct_target.is_some() {
                    size += 5;
                }
                *cursor = cursor.saturating_add(size);
            }
            Stmt::Goto { target_addr, wide } => {
                let size = ud_arch_x86::encoded_jmp_size(*cursor, *target_addr, *wide) as u64;
                *cursor = cursor.saturating_add(size);
            }
            Stmt::IfGoto {
                target_addr,
                cmp_bytes,
                wide,
                ..
            }
            | Stmt::IfReturn {
                target_addr,
                cmp_bytes,
                wide,
                ..
            } => {
                let jcc_ip = cursor.saturating_add(cmp_bytes.len() as u64);
                let size = (cmp_bytes.len() as u64)
                    + ud_arch_x86::encoded_jcc_size(jcc_ip, *target_addr, *wide) as u64;
                *cursor = cursor.saturating_add(size);
            }
            Stmt::Switch {
                cases, dispatch, ..
            } => {
                // Match the `switch_encoded_size` formula used on
                // the decompile side: cmp(3|6) + ja(6) + jmp(7).
                let max_value = u32::try_from(cases.len().saturating_sub(1)).unwrap_or(u32::MAX);
                let cmp: u64 = if dispatch == "msvc-jmp-table" && max_value <= 0x7f {
                    3
                } else {
                    6
                };
                *cursor = cursor.saturating_add(cmp + 6 + 7);
            }
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
                if let Some(hb) = attrs.iter().find_map(|a| match (a.key.as_str(), &a.value) {
                    ("head_bytes", ud_ast::AttrValue::ByteList(b)) => Some(b.as_slice()),
                    _ => None,
                }) {
                    *cursor = cursor.saturating_add(hb.len() as u64);
                }
                verify_stmts(f, section, pre_body, cursor, out);
                *cursor = cursor.saturating_add(cond_bytes.len() as u64);
                verify_stmts(f, section, then_body, cursor, out);
                if let Some(else_body) = else_body {
                    verify_stmts(f, section, else_body, cursor, out);
                }
            }
            Stmt::Loop {
                entry_jmp_bytes,
                tail_bytes,
                body,
                ..
            } => {
                if let Some(jmp) = entry_jmp_bytes {
                    *cursor = cursor.saturating_add(jmp.len() as u64);
                }
                verify_stmts(f, section, body, cursor, out);
                *cursor = cursor.saturating_add(tail_bytes.len() as u64);
            }
            Stmt::IfBlock {
                cond_bytes,
                then_body,
                then_tail_jmp,
                else_body,
                ..
            } => {
                *cursor = cursor.saturating_add(cond_bytes.len() as u64);
                verify_stmts(f, section, then_body, cursor, out);
                *cursor = cursor.saturating_add(then_tail_jmp.len() as u64);
                verify_stmts(f, section, else_body, cursor, out);
            }
            Stmt::WhileBlock {
                entry_bytes,
                tail_bytes,
                body,
                ..
            } => {
                *cursor = cursor.saturating_add(entry_bytes.len() as u64);
                verify_stmts(f, section, body, cursor, out);
                *cursor = cursor.saturating_add(tail_bytes.len() as u64);
            }
            Stmt::Comment(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ud_ast::{Field, FnDecl, Module, Stmt, UdFile, Value};

    fn x86_module() -> Module {
        Module {
            fields: vec![Field {
                name: "arch".into(),
                value: Value::String("x86_64".into()),
            }],
        }
    }

    fn fn_with(stmts: Vec<Stmt>) -> Item {
        Item::Function(FnDecl {
            addr: Some(0x1000),
            name: "f".into(),
            attrs: Vec::new(),
            locals: Vec::new(),
            signature: None,
            body: stmts,
        })
    }

    #[test]
    fn no_warnings_when_text_matches_bytes() {
        let file = UdFile {
            module: x86_module(),
            items: vec![fn_with(vec![Stmt::asm("ret", vec![0xc3])])],
        };
        assert!(verify_asm(&file).is_empty());
    }

    #[test]
    fn warns_on_divergence() {
        let file = UdFile {
            module: x86_module(),
            items: vec![fn_with(vec![Stmt::asm("nop", vec![0xc3])])],
        };
        let warnings = verify_asm(&file);
        assert_eq!(warnings.len(), 1);
        match &warnings[0] {
            AsmWarning::Divergence { canonical, .. } => assert_eq!(canonical, "ret"),
            other => panic!("expected Divergence, got {other:?}"),
        }
    }

    #[test]
    fn warns_on_undecodable_bytes() {
        let file = UdFile {
            module: x86_module(),
            items: vec![fn_with(vec![Stmt::asm("ret", vec![0x06])])],
        };
        let warnings = verify_asm(&file);
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0], AsmWarning::Undecodable { .. }));
    }

    #[test]
    fn warns_on_multi_insn_byte_block() {
        let file = UdFile {
            module: x86_module(),
            items: vec![fn_with(vec![Stmt::asm("ret", vec![0xc3, 0xc3])])],
        };
        let warnings = verify_asm(&file);
        assert!(matches!(
            warnings.as_slice(),
            [AsmWarning::MultipleInsns { count: 2, .. }]
        ));
    }

    #[test]
    fn skips_asm_without_pinned_bytes() {
        let file = UdFile {
            module: x86_module(),
            items: vec![fn_with(vec![Stmt::asm_text("ret")])],
        };
        assert!(verify_asm(&file).is_empty());
    }

    #[test]
    fn skips_when_arch_is_not_x86_64() {
        let mut module = x86_module();
        module.fields[0].value = Value::String("arm64".into());
        let file = UdFile {
            module,
            items: vec![fn_with(vec![Stmt::asm("nop", vec![0xc3])])],
        };
        assert!(verify_asm(&file).is_empty());
    }

    #[test]
    fn walks_into_sections() {
        let file = UdFile {
            module: x86_module(),
            items: vec![Item::Section {
                name: ".text".into(),
                addr: 0x1000,
                items: vec![fn_with(vec![Stmt::asm("nop", vec![0xc3])])],
            }],
        };
        let warnings = verify_asm(&file);
        assert_eq!(warnings.len(), 1);
        if let AsmWarning::Divergence { location, .. } = &warnings[0] {
            assert_eq!(location.section.as_deref(), Some(".text"));
            assert_eq!(location.function.as_deref(), Some("f"));
        } else {
            panic!()
        }
    }
}

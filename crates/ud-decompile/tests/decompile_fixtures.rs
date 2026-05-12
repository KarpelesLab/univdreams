//! Decompile each x86_64 ELF fixture to a `.ud` AST and check shape
//! against expected facts. Tests assert on the structured AST when
//! possible (more robust than substring matches on text), and on the
//! emitted text when the test is specifically about formatting.

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};

use ud_ast::{Item, Stmt, Type, UdFile, Value};
use ud_format_elf::{is_elf64_le, Elf64File, EM_X86_64};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn ast_for(path: &Path) -> Option<UdFile> {
    let bytes = std::fs::read(path).ok()?;
    if !is_elf64_le(&bytes) {
        return None;
    }
    let elf = Elf64File::parse(&bytes).ok()?;
    if elf.ehdr.e_machine != EM_X86_64 {
        return None;
    }
    Some(ud_decompile::decompile(&elf).expect("decompile"))
}

fn function_names(ast: &UdFile) -> Vec<&str> {
    let mut out = Vec::new();
    walk_functions(&ast.items, &mut out);
    out
}

fn walk_functions<'a>(items: &'a [Item], out: &mut Vec<&'a str>) {
    for item in items {
        match item {
            Item::Function(f) => out.push(f.name.as_str()),
            Item::Section { items, .. } => walk_functions(items, out),
            _ => {}
        }
    }
}

#[test]
fn hello_fixture_module_header_is_canonical() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(ast) = ast_for(&path) else {
        eprintln!("note: {} unavailable; skipping", path.display());
        return;
    };

    // Field names appear in canonical order; values are well-typed.
    let names: Vec<&str> = ast.module.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["arch", "abi", "format", "bits", "endian", "type", "entry", "build"]
    );

    // arch/abi/format/endian are strings; bits/type/entry are ints; build is a block.
    assert_eq!(ast.module.fields[0].value, Value::String("x86_64".into()));
    assert_eq!(ast.module.fields[1].value, Value::String("sysv".into()));
    assert_eq!(ast.module.fields[3].value, Value::Int(64));
    assert!(matches!(ast.module.fields[7].value, Value::Block(_)));
}

#[test]
fn hello_fixture_includes_main_and_start() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(ast) = ast_for(&path) else {
        return;
    };
    let names = function_names(&ast);
    for required in &[
        "_start",
        "main",
        "_init",
        "_fini",
        "deregister_tm_clones",
        "register_tm_clones",
        "__do_global_dtors_aux",
        "frame_dummy",
    ] {
        assert!(
            names.contains(required),
            "expected `{required}` in {names:?}"
        );
    }
}

#[test]
fn sqrt_fixture_emits_user_functions() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(ast) = ast_for(&path) else {
        return;
    };
    let names = function_names(&ast);
    for required in &["main", "do_fac", "test_sqrt"] {
        assert!(names.contains(required), "missing `{required}`");
    }
}

/// Determinism: the AST is the same across two runs for the same input.
#[test]
fn output_is_deterministic() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(a) = ast_for(&path) else { return };
    let b = ast_for(&path).unwrap();
    assert_eq!(a, b, "decompile is non-deterministic");
}

/// The asm-statement count across all functions equals the lifted
/// instruction count from the same fixtures. Catches silent drops in
/// either direction.
#[test]
fn asm_count_matches_lifted_instruction_count() {
    let path = workspace_root().join("testdata/hello-gcc13-O0");
    let Some(ast) = ast_for(&path) else { return };

    let asm_count = count_asm_stmts(&ast.items);

    // Re-lift via discovery + decode and total the instruction count.
    let bytes = std::fs::read(&path).expect("read");
    let elf = Elf64File::parse(&bytes).expect("parse");
    let map = ud_analysis::discover_functions(&elf).expect("discover");
    let mut expected = 0usize;
    for f in map.iter() {
        if f.size == 0 {
            continue;
        }
        let Some(slice) = slice_function_bytes(&elf, f.addr.0, f.size) else {
            continue;
        };
        let insns =
            ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, slice, f.addr.0).expect("decode");
        expected += insns.len();
    }

    assert_eq!(
        asm_count, expected,
        "Stmt::Asm count {asm_count} differs from lifted total {expected}"
    );
}

/// DWARF integration: functions whose source signature lives in
/// `.debug_info` get typed parameters and a typed return on the
/// emitted `fn` line. Confirmed against the `do_fac(int) -> int`
/// signature in sqrt.c.
#[test]
fn dwarf_supplies_function_signatures() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(ast) = ast_for(&path) else { return };
    let do_fac = find_function(&ast, "do_fac").expect("do_fac present");
    let sig = do_fac.signature.as_ref().expect("do_fac has a signature");
    assert_eq!(sig.return_type, Type::I32);
    assert_eq!(sig.params.len(), 1);
    assert_eq!(sig.params[0].ty, Type::I32);
}

fn find_function<'a>(ast: &'a UdFile, name: &str) -> Option<&'a ud_ast::FnDecl> {
    fn search<'a>(items: &'a [Item], name: &str) -> Option<&'a ud_ast::FnDecl> {
        for item in items {
            match item {
                Item::Function(f) if f.name == name => return Some(f),
                Item::Section { items, .. } => {
                    if let Some(f) = search(items, name) {
                        return Some(f);
                    }
                }
                _ => {}
            }
        }
        None
    }
    search(&ast.items, name)
}

/// Source-level round-trip: take the canonical text the decompiler
/// emits, parse it back, and verify the resulting AST is structurally
/// equal to the AST we started from. This is the strongest property
/// the .ud language layer can defend right now.
#[test]
fn parse_of_decompile_to_text_equals_decompile() {
    let path = workspace_root().join("testdata/sqrt-gcc13-O0");
    let Some(ast) = ast_for(&path) else { return };
    let text = ud_ast::emit(&ast);
    let reparsed = ud_compile::parse(&text).expect("parse decompile output");
    assert_eq!(
        reparsed, ast,
        "parse(decompile_to_text(elf)) != decompile(elf)"
    );
}

/// Total number of instructions represented in the AST. Counts each
/// `Stmt::Asm` as one; for any directive that pins multi-instruction
/// bytes (`Stmt::Return`, `Stmt::Prologue`, `Stmt::Epilogue`,
/// `Stmt::IfBranch`'s cond head), decodes the bytes to count the real
/// instruction total. Recurses into IfBranch arms.
fn count_asm_stmts(items: &[Item]) -> usize {
    let mut n = 0;
    for item in items {
        match item {
            Item::Function(f) => n += count_stmts(&f.body),
            Item::Section { items, .. } => n += count_asm_stmts(items),
            _ => {}
        }
    }
    n
}

fn count_stmts(stmts: &[Stmt]) -> usize {
    let mut n = 0;
    for stmt in stmts {
        match stmt {
            Stmt::Asm { bytes, .. } => {
                // Some `@asm` lines combine multiple x86 instructions
                // — e.g. the `cmp_jcc` pattern folds an adjacent
                // `cmp/test + jcc` pair into one line — so count the
                // actual instruction encodings rather than stmts.
                if bytes.is_empty() {
                    n += 1;
                } else {
                    let insns =
                        ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, bytes, 0)
                            .expect("decode asm bytes");
                    n += insns.len();
                }
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
            | Stmt::Call { bytes, .. } => {
                let insns = ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, bytes, 0)
                    .expect("decode lifted-block bytes");
                n += insns.len();
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
                // Separated cmp/jcc lifts route the cmp's bytes
                // through the `head_bytes` attribute — count those
                // too so the total still matches the original insn
                // count.
                for a in attrs {
                    if a.key == "head_bytes" {
                        if let ud_ast::AttrValue::ByteList(b) = &a.value {
                            let insns = ud_arch_x86::decode(
                                ud_arch_x86::Bitness::Bits64,
                                b,
                                0,
                            )
                            .expect("decode head_bytes attribute");
                            n += insns.len();
                        }
                    }
                }
                n += count_stmts(pre_body);
                let insns = ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, cond_bytes, 0)
                    .expect("decode if-branch cond bytes");
                n += insns.len();
                n += count_stmts(then_body);
                if let Some(else_body) = else_body {
                    n += count_stmts(else_body);
                }
            }
            Stmt::Loop {
                entry_jmp_bytes,
                tail_bytes,
                body,
                ..
            } => {
                if let Some(jmp) = entry_jmp_bytes {
                    let insns = ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, jmp, 0)
                        .expect("decode loop entry jmp");
                    n += insns.len();
                }
                let insns = ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, tail_bytes, 0)
                    .expect("decode loop tail bytes");
                n += insns.len();
                n += count_stmts(body);
            }
            Stmt::LocalSet { bytes, .. }
            | Stmt::LocalArith { bytes, .. }
            | Stmt::LocalCompound { bytes, .. }
            | Stmt::Move { bytes, .. }
            | Stmt::Inc16 { bytes, .. } => {
                let insns = ud_arch_x86::decode(ud_arch_x86::Bitness::Bits64, bytes, 0)
                    .expect("decode local-op bytes");
                n += insns.len();
            }
            Stmt::Comment(_) => {}
        }
    }
    n
}

fn slice_function_bytes(elf: &Elf64File, addr: u64, size: u64) -> Option<&[u8]> {
    if size == 0 {
        return None;
    }
    for (_, sh, data) in elf.sections() {
        let sh_end = sh.sh_addr.saturating_add(sh.sh_size);
        if sh.sh_addr <= addr && addr.saturating_add(size) <= sh_end {
            let offset = (addr - sh.sh_addr) as usize;
            let slice_end = offset + size as usize;
            if slice_end <= data.len() {
                return Some(&data[offset..slice_end]);
            }
        }
    }
    None
}

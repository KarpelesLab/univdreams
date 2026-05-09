//! Canonical pretty-printer.
//!
//! The output is the source of truth for what `.ud` looks like. Any
//! valid AST emits in exactly one canonical shape; the parser will
//! accept that shape (and a handful of trivial whitespace variations)
//! and reproduce it on re-emit. So `emit(parse(canonical)) == canonical`
//! is a hard invariant the test suite defends.
//!
//! Indentation: 4 spaces per level. Top-level blocks have a blank line
//! between them.

use std::fmt::Write as _;

use crate::types::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};

/// Format an entire AST as canonical `.ud` text. Trailing newline is
/// included; the file always ends in `\n`.
#[must_use]
pub fn emit(file: &UdFile) -> String {
    let mut out = String::new();
    emit_module(&mut out, &file.module);
    for item in &file.items {
        out.push('\n');
        emit_item(&mut out, item);
    }
    out
}

fn emit_module(out: &mut String, module: &Module) {
    writeln!(out, "@module {{").unwrap();
    for f in &module.fields {
        emit_field(out, f, 1);
    }
    writeln!(out, "}}").unwrap();
}

fn emit_item(out: &mut String, item: &Item) {
    emit_item_indented(out, item, 0);
}

fn emit_item_indented(out: &mut String, item: &Item, depth: usize) {
    let indent = " ".repeat(depth * 4);
    match item {
        Item::Comment(text) => writeln!(out, "{indent}// {text}").unwrap(),
        Item::Function(f) => emit_fn_indented(out, f, depth),
        Item::Raw { addr, bytes } => emit_raw(out, *addr, bytes, depth),
        Item::Section { name, addr, items } => emit_section(out, name, *addr, items, depth),
    }
}

fn emit_raw(out: &mut String, addr: u64, bytes: &[u8], depth: usize) {
    let indent = " ".repeat(depth * 4);
    write!(out, "{indent}@raw(0x{addr:x}, [").unwrap();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write!(out, "0x{b:02x}").unwrap();
    }
    writeln!(out, "])").unwrap();
}

fn emit_section(out: &mut String, name: &str, addr: u64, items: &[Item], depth: usize) {
    let indent = " ".repeat(depth * 4);
    writeln!(
        out,
        "{indent}@section({}, 0x{addr:x}) {{",
        quote_string(name)
    )
    .unwrap();
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_item_indented(out, item, depth + 1);
    }
    writeln!(out, "{indent}}}").unwrap();
}

fn emit_fn_indented(out: &mut String, f: &FnDecl, depth: usize) {
    let indent = " ".repeat(depth * 4);
    let body_indent = " ".repeat((depth + 1) * 4);
    if let Some(addr) = f.addr {
        writeln!(out, "{indent}@addr(0x{addr:x})").unwrap();
    }
    writeln!(out, "{indent}fn {}() {{", f.name).unwrap();
    for stmt in &f.body {
        match stmt {
            Stmt::Asm { text, bytes } if bytes.is_empty() => {
                writeln!(out, "{body_indent}@asm({})", quote_string(text)).unwrap();
            }
            Stmt::Asm { text, bytes } => {
                write!(out, "{body_indent}@asm({}, [", quote_string(text)).unwrap();
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write!(out, "0x{b:02x}").unwrap();
                }
                writeln!(out, "])").unwrap();
            }
            Stmt::Comment(text) => {
                writeln!(out, "{body_indent}// {text}").unwrap();
            }
        }
    }
    writeln!(out, "{indent}}}").unwrap();
}

fn emit_field(out: &mut String, f: &Field, depth: usize) {
    let indent = " ".repeat(depth * 4);
    write!(out, "{indent}{}: ", f.name).unwrap();
    emit_value(out, &f.value, depth);
    writeln!(out, ",").unwrap();
}

fn emit_value(out: &mut String, v: &Value, depth: usize) {
    match v {
        Value::String(s) => out.push_str(&quote_string(s)),
        Value::Int(n) => write!(out, "0x{n:x}").unwrap(),
        Value::List(items) => emit_list(out, items, depth),
        Value::Block(fields) => emit_block(out, fields, depth),
    }
}

fn emit_list(out: &mut String, items: &[Value], depth: usize) {
    out.push('[');
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        emit_value(out, v, depth);
    }
    out.push(']');
}

fn emit_block(out: &mut String, fields: &[Field], depth: usize) {
    out.push('{');
    out.push('\n');
    for f in fields {
        emit_field(out, f, depth + 1);
    }
    let close_indent = " ".repeat(depth * 4);
    out.push_str(&close_indent);
    out.push('}');
}

/// Quote a string for `.ud` output: surround in `"…"`, escape backslash
/// and double-quote.
fn quote_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_module() -> Module {
        Module { fields: vec![] }
    }

    #[test]
    fn empty_file_emits_just_module_header() {
        let f = UdFile {
            module: empty_module(),
            items: vec![],
        };
        assert_eq!(emit(&f), "@module {\n}\n");
    }

    #[test]
    fn module_fields_indent_with_four_spaces() {
        let f = UdFile {
            module: Module {
                fields: vec![
                    Field {
                        name: "arch".into(),
                        value: Value::String("x86_64".into()),
                    },
                    Field {
                        name: "bits".into(),
                        value: Value::Int(64),
                    },
                ],
            },
            items: vec![],
        };
        let out = emit(&f);
        assert!(out.contains("    arch: \"x86_64\","));
        assert!(out.contains("    bits: 0x40,"));
    }

    #[test]
    fn nested_blocks_indent_correctly() {
        let f = UdFile {
            module: Module {
                fields: vec![Field {
                    name: "build".into(),
                    value: Value::Block(vec![Field {
                        name: "e_flags".into(),
                        value: Value::Int(0),
                    }]),
                }],
            },
            items: vec![],
        };
        let out = emit(&f);
        assert!(
            out.contains("    build: {\n        e_flags: 0x0,\n    },\n"),
            "actual: {out:?}"
        );
    }

    #[test]
    fn list_values_inline_on_one_line() {
        let f = UdFile {
            module: Module {
                fields: vec![Field {
                    name: "ident".into(),
                    value: Value::List(vec![Value::Int(0x7f), Value::Int(0x45)]),
                }],
            },
            items: vec![],
        };
        let out = emit(&f);
        assert!(out.contains("    ident: [0x7f, 0x45],"));
    }

    #[test]
    fn function_with_asm_lines_text_only() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1080),
                name: "_start".into(),
                body: vec![
                    Stmt::asm_text("endbr64"),
                    Stmt::Comment("block: 0x1084".into()),
                    Stmt::asm_text("ret"),
                ],
            })],
        };
        let out = emit(&f);
        assert!(out.contains("@addr(0x1080)\nfn _start() {\n"));
        assert!(out.contains("    @asm(\"endbr64\")\n"));
        assert!(out.contains("    // block: 0x1084\n"));
        assert!(out.contains("    @asm(\"ret\")\n"));
    }

    #[test]
    fn function_with_asm_lines_and_pinned_bytes() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1080),
                name: "f".into(),
                body: vec![
                    Stmt::asm("endbr64", vec![0xf3, 0x0f, 0x1e, 0xfa]),
                    Stmt::asm("ret", vec![0xc3]),
                ],
            })],
        };
        let out = emit(&f);
        assert!(out.contains("    @asm(\"endbr64\", [0xf3, 0x0f, 0x1e, 0xfa])\n"));
        assert!(out.contains("    @asm(\"ret\", [0xc3])\n"));
    }

    #[test]
    fn raw_item_emits_addr_and_byte_list() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Raw {
                addr: 0x10c0,
                bytes: vec![0xcc, 0xcc, 0xcc],
            }],
        };
        let out = emit(&f);
        assert!(out.contains("@raw(0x10c0, [0xcc, 0xcc, 0xcc])\n"));
    }

    #[test]
    fn section_wraps_nested_items_with_indentation() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Section {
                name: ".text".into(),
                addr: 0x1000,
                items: vec![
                    Item::Function(FnDecl {
                        addr: Some(0x1000),
                        name: "f".into(),
                        body: vec![Stmt::asm("ret", vec![0xc3])],
                    }),
                    Item::Raw {
                        addr: 0x1001,
                        bytes: vec![0x90, 0x90],
                    },
                ],
            }],
        };
        let out = emit(&f);
        assert!(out.contains("@section(\".text\", 0x1000) {\n"));
        assert!(out.contains("    @addr(0x1000)\n"));
        assert!(out.contains("    fn f() {\n"));
        assert!(out.contains("        @asm(\"ret\", [0xc3])\n"));
        assert!(out.contains("    @raw(0x1001, [0x90, 0x90])\n"));
    }

    #[test]
    fn quote_string_escapes_quote_and_backslash() {
        assert_eq!(quote_string("a"), r#""a""#);
        assert_eq!(quote_string(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_string(r"\n"), r#""\\n""#);
    }
}

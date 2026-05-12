//! Source-level round-trip property tests.
//!
//! These defend the contract:
//!
//! > * `parse(emit(ast))` is structurally equal to `ast`.
//! > * `emit(parse(canonical_text))` is byte-equal to `canonical_text`.

use ud_ast::{emit, Field, FnDecl, Item, Module, Stmt, UdFile, Value};
use ud_compile::parse;

fn sample_ast() -> UdFile {
    UdFile {
        module: Module {
            fields: vec![
                Field {
                    name: "arch".into(),
                    value: Value::String("x86_64".into()),
                },
                Field {
                    name: "abi".into(),
                    value: Value::String("sysv".into()),
                },
                Field {
                    name: "bits".into(),
                    value: Value::Int(64),
                },
                Field {
                    name: "build".into(),
                    value: Value::Block(vec![
                        Field {
                            name: "e_flags".into(),
                            value: Value::Int(0),
                        },
                        Field {
                            name: "e_ident".into(),
                            value: Value::List(vec![Value::Int(0x7f), Value::Int(0x45)]),
                        },
                    ]),
                },
            ],
        },
        items: vec![
            Item::Comment("note: handcrafted".into()),
            Item::Function(FnDecl {
                addr: Some(0x1080),
                name: "_start".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![
                    Stmt::asm("endbr64", vec![0xf3, 0x0f, 0x1e, 0xfa]),
                    Stmt::Comment("block: 0x1084".into()),
                    Stmt::asm("xor rax, rax", vec![0x48, 0x31, 0xc0]),
                    Stmt::asm("ret", vec![0xc3]),
                ],
            }),
            Item::Function(FnDecl {
                addr: Some(0x1100),
                name: "main".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![Stmt::asm("ret", vec![0xc3])],
            }),
        ],
    }
}

#[test]
fn parse_of_emit_equals_ast() {
    let ast = sample_ast();
    let text = emit(&ast);
    let reparsed = parse(&text).expect("parse emitted text");
    assert_eq!(
        reparsed, ast,
        "parse(emit(ast)) was not structurally equal to ast"
    );
}

#[test]
fn emit_of_parse_is_idempotent() {
    let ast = sample_ast();
    let text = emit(&ast);
    let reparsed = parse(&text).expect("parse");
    let reemitted = emit(&reparsed);
    assert_eq!(
        reemitted, text,
        "emit(parse(canonical)) diverged from canonical"
    );
}

/// Negative test: malformed input is rejected with a position.
#[test]
fn missing_closing_brace_errors_with_line() {
    let src = "@module {\n    arch: \"x86_64\",\n";
    let err = parse(src).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("line"),
        "expected error message to mention a line, got {msg:?}"
    );
}

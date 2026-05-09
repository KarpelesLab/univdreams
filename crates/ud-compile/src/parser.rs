//! Recursive-descent parser for `.ud`.
//!
//! Expects the canonical-form output of [`ud_ast::emit`] plus minor
//! whitespace variations. Errors carry a 1-indexed line/column.

use ud_ast::{Field, FnDecl, Item, Module, Stmt, UdFile, Value};

use crate::lexer::{tokenize, LexError, Token, TokenKind};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    Lex(#[from] LexError),

    #[error("expected {expected} at line {line}, col {col}, got {got}")]
    Expected {
        expected: String,
        got: String,
        line: u32,
        col: u32,
    },

    #[error("unknown directive `@{name}` at line {line}, col {col}")]
    UnknownDirective { name: String, line: u32, col: u32 },

    #[error("unexpected end of input")]
    UnexpectedEof,
}

/// Parse `input` into an AST. Returns the first error encountered.
pub fn parse(input: &str) -> Result<UdFile, ParseError> {
    let tokens = tokenize(input)?;
    let mut p = Parser::new(tokens);
    p.parse_file()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn bump(&mut self) -> Token {
        let tok = self.tokens[self.pos].clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn eat_kind(&mut self, kind: &TokenKind) -> bool {
        if &self.peek().kind == kind {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: &TokenKind, label: &str) -> Result<(), ParseError> {
        let tok = self.peek().clone();
        if &tok.kind == kind {
            self.bump();
            Ok(())
        } else {
            Err(ParseError::Expected {
                expected: label.to_string(),
                got: describe(&tok.kind),
                line: tok.line,
                col: tok.col,
            })
        }
    }

    fn expect_ident(&mut self, label: &str) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        if let TokenKind::Ident(name) = &tok.kind {
            let name = name.clone();
            self.bump();
            Ok(name)
        } else {
            Err(ParseError::Expected {
                expected: label.to_string(),
                got: describe(&tok.kind),
                line: tok.line,
                col: tok.col,
            })
        }
    }

    fn expect_string(&mut self, label: &str) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        if let TokenKind::String(s) = &tok.kind {
            let s = s.clone();
            self.bump();
            Ok(s)
        } else {
            Err(ParseError::Expected {
                expected: label.to_string(),
                got: describe(&tok.kind),
                line: tok.line,
                col: tok.col,
            })
        }
    }

    fn expect_int(&mut self, label: &str) -> Result<u64, ParseError> {
        let tok = self.peek().clone();
        if let TokenKind::Int(n) = &tok.kind {
            let n = *n;
            self.bump();
            Ok(n)
        } else {
            Err(ParseError::Expected {
                expected: label.to_string(),
                got: describe(&tok.kind),
                line: tok.line,
                col: tok.col,
            })
        }
    }

    fn parse_file(&mut self) -> Result<UdFile, ParseError> {
        let module = self.parse_module()?;
        let mut items = Vec::new();
        while self.peek().kind != TokenKind::Eof {
            items.push(self.parse_item()?);
        }
        Ok(UdFile { module, items })
    }

    fn parse_module(&mut self) -> Result<Module, ParseError> {
        // Skip any stray top-level comments before the module header.
        while let TokenKind::Comment(_) = self.peek().kind {
            self.bump();
        }
        self.expect(&TokenKind::At, "`@module`")?;
        let name_tok = self.peek().clone();
        let name = self.expect_ident("`module` after `@`")?;
        if name != "module" {
            return Err(ParseError::Expected {
                expected: "`module`".to_string(),
                got: format!("`{name}`"),
                line: name_tok.line,
                col: name_tok.col,
            });
        }
        self.expect(&TokenKind::LBrace, "`{` after `@module`")?;
        let fields = self.parse_field_list()?;
        self.expect(&TokenKind::RBrace, "`}` to close `@module`")?;
        Ok(Module { fields })
    }

    fn parse_field_list(&mut self) -> Result<Vec<Field>, ParseError> {
        let mut out = Vec::new();
        while !matches!(self.peek().kind, TokenKind::RBrace | TokenKind::Eof) {
            let name = self.expect_ident("field name")?;
            self.expect(&TokenKind::Colon, "`:` after field name")?;
            let value = self.parse_value()?;
            self.expect(&TokenKind::Comma, "`,` after field value")?;
            out.push(Field { name, value });
        }
        Ok(out)
    }

    /// Parse `[byte, byte, …]` where each byte is an integer in 0..=255.
    /// Used by `@asm("text", [bytes])` and (future) `@raw([bytes])`.
    fn parse_byte_list(&mut self) -> Result<Vec<u8>, ParseError> {
        let bracket = self.peek().clone();
        self.expect(&TokenKind::LBracket, "`[` to open byte list")?;
        let mut out = Vec::new();
        if self.peek().kind != TokenKind::RBracket {
            loop {
                let tok = self.peek().clone();
                let n = self.expect_int("byte value (0..=255)")?;
                if n > 0xff {
                    return Err(ParseError::Expected {
                        expected: "byte value (0..=255)".into(),
                        got: format!("integer 0x{n:x}"),
                        line: tok.line,
                        col: tok.col,
                    });
                }
                out.push(n as u8);
                if !self.eat_kind(&TokenKind::Comma) {
                    break;
                }
                if self.peek().kind == TokenKind::RBracket {
                    break;
                }
            }
        }
        self.expect(&TokenKind::RBracket, "`]` to close byte list")?;
        let _ = bracket; // kept for potential future use in error messages
        Ok(out)
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::String(s) => {
                let s = s.clone();
                self.bump();
                Ok(Value::String(s))
            }
            TokenKind::Int(n) => {
                let n = *n;
                self.bump();
                Ok(Value::Int(n))
            }
            TokenKind::LBracket => {
                self.bump();
                let mut items = Vec::new();
                if self.peek().kind != TokenKind::RBracket {
                    items.push(self.parse_value()?);
                    while self.eat_kind(&TokenKind::Comma) {
                        if self.peek().kind == TokenKind::RBracket {
                            break;
                        }
                        items.push(self.parse_value()?);
                    }
                }
                self.expect(&TokenKind::RBracket, "`]` to close list")?;
                Ok(Value::List(items))
            }
            TokenKind::LBrace => {
                self.bump();
                let fields = self.parse_field_list()?;
                self.expect(&TokenKind::RBrace, "`}` to close block")?;
                Ok(Value::Block(fields))
            }
            other => Err(ParseError::Expected {
                expected: "a value (string, int, list, or block)".into(),
                got: describe(other),
                line: tok.line,
                col: tok.col,
            }),
        }
    }

    fn parse_item(&mut self) -> Result<Item, ParseError> {
        match self.peek().kind.clone() {
            TokenKind::Comment(text) => {
                self.bump();
                Ok(Item::Comment(text))
            }
            TokenKind::At => self.parse_at_directive(),
            TokenKind::Ident(ref name) if name == "fn" => self.parse_fn(None),
            other => Err(ParseError::Expected {
                expected: "a top-level item (`@addr`, `@raw`, `@section`, `fn`, or `// comment`)"
                    .into(),
                got: describe(&other),
                line: self.peek().line,
                col: self.peek().col,
            }),
        }
    }

    fn parse_at_directive(&mut self) -> Result<Item, ParseError> {
        self.expect(&TokenKind::At, "`@`")?;
        let dir_tok = self.peek().clone();
        let name = self.expect_ident("directive name")?;
        match name.as_str() {
            "addr" => {
                self.expect(&TokenKind::LParen, "`(` after `@addr`")?;
                let addr = self.expect_int("an integer address")?;
                self.expect(&TokenKind::RParen, "`)` to close `@addr`")?;
                self.parse_fn(Some(addr))
            }
            "raw" => {
                self.expect(&TokenKind::LParen, "`(` after `@raw`")?;
                let addr = self.expect_int("an integer address")?;
                self.expect(&TokenKind::Comma, "`,` after `@raw` address")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@raw`")?;
                Ok(Item::Raw { addr, bytes })
            }
            "section" => {
                self.expect(&TokenKind::LParen, "`(` after `@section`")?;
                let section_name = self.expect_string("section name")?;
                self.expect(&TokenKind::Comma, "`,` after section name")?;
                let addr = self.expect_int("section start address")?;
                self.expect(&TokenKind::RParen, "`)` to close `@section`")?;
                self.expect(&TokenKind::LBrace, "`{` to open section body")?;
                let mut items = Vec::new();
                while !matches!(self.peek().kind, TokenKind::RBrace | TokenKind::Eof) {
                    items.push(self.parse_item()?);
                }
                self.expect(&TokenKind::RBrace, "`}` to close section body")?;
                Ok(Item::Section {
                    name: section_name,
                    addr,
                    items,
                })
            }
            other => Err(ParseError::UnknownDirective {
                name: other.to_string(),
                line: dir_tok.line,
                col: dir_tok.col,
            }),
        }
    }

    fn parse_fn(&mut self, addr: Option<u64>) -> Result<Item, ParseError> {
        let kw_tok = self.peek().clone();
        let kw = self.expect_ident("`fn`")?;
        if kw != "fn" {
            return Err(ParseError::Expected {
                expected: "`fn`".into(),
                got: format!("`{kw}`"),
                line: kw_tok.line,
                col: kw_tok.col,
            });
        }
        let name = self.expect_ident("function name")?;
        self.expect(&TokenKind::LParen, "`(` after function name")?;
        // v0: no parameters.
        self.expect(&TokenKind::RParen, "`)` after parameter list")?;
        self.expect(&TokenKind::LBrace, "`{` to open function body")?;

        let mut body = Vec::new();
        loop {
            match self.peek().kind.clone() {
                TokenKind::RBrace => {
                    self.bump();
                    break;
                }
                TokenKind::Eof => return Err(ParseError::UnexpectedEof),
                TokenKind::Comment(text) => {
                    self.bump();
                    body.push(Stmt::Comment(text));
                }
                TokenKind::At => {
                    self.bump();
                    let dir_tok = self.peek().clone();
                    let dir_name = self.expect_ident("statement directive name")?;
                    match dir_name.as_str() {
                        "asm" => {
                            self.expect(&TokenKind::LParen, "`(` after `@asm`")?;
                            let text = self.expect_string("asm string")?;
                            let bytes = if self.eat_kind(&TokenKind::Comma) {
                                self.parse_byte_list()?
                            } else {
                                Vec::new()
                            };
                            self.expect(&TokenKind::RParen, "`)` to close `@asm`")?;
                            body.push(Stmt::Asm { text, bytes });
                        }
                        other => {
                            return Err(ParseError::UnknownDirective {
                                name: other.to_string(),
                                line: dir_tok.line,
                                col: dir_tok.col,
                            });
                        }
                    }
                }
                other => {
                    return Err(ParseError::Expected {
                        expected: "`@asm`, `// comment`, or `}`".into(),
                        got: describe(&other),
                        line: self.peek().line,
                        col: self.peek().col,
                    });
                }
            }
        }

        Ok(Item::Function(FnDecl { addr, name, body }))
    }
}

fn describe(kind: &TokenKind) -> String {
    match kind {
        TokenKind::LBrace => "`{`".into(),
        TokenKind::RBrace => "`}`".into(),
        TokenKind::LParen => "`(`".into(),
        TokenKind::RParen => "`)`".into(),
        TokenKind::LBracket => "`[`".into(),
        TokenKind::RBracket => "`]`".into(),
        TokenKind::Comma => "`,`".into(),
        TokenKind::Colon => "`:`".into(),
        TokenKind::At => "`@`".into(),
        TokenKind::Ident(n) => format!("identifier `{n}`"),
        TokenKind::String(_) => "a string literal".into(),
        TokenKind::Int(n) => format!("integer 0x{n:x}"),
        TokenKind::Comment(_) => "a comment".into(),
        TokenKind::Eof => "end of input".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_module() {
        let f = parse("@module {}\n").unwrap();
        assert!(f.module.fields.is_empty());
        assert!(f.items.is_empty());
    }

    #[test]
    fn module_with_fields() {
        let src = r#"@module {
    arch: "x86_64",
    bits: 64,
}
"#;
        let f = parse(src).unwrap();
        assert_eq!(f.module.fields.len(), 2);
        assert_eq!(f.module.fields[0].name, "arch");
        assert_eq!(f.module.fields[0].value, Value::String("x86_64".into()));
        assert_eq!(f.module.fields[1].value, Value::Int(64));
    }

    #[test]
    fn nested_block_value() {
        let src = r"@module {
    build: {
        e_flags: 0x0,
    },
}
";
        let f = parse(src).unwrap();
        let Value::Block(inner) = &f.module.fields[0].value else {
            panic!("expected nested block");
        };
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].name, "e_flags");
    }

    #[test]
    fn list_value_with_trailing_comma_optional() {
        let f = parse("@module { ident: [0x7f, 0x45], }\n").unwrap();
        let Value::List(items) = &f.module.fields[0].value else {
            panic!("expected list");
        };
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn function_with_addr_and_asm() {
        let src = r#"@module {}

@addr(0x1080)
fn _start() {
    @asm("endbr64")
    @asm("ret")
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!("expected function");
        };
        assert_eq!(fn_.addr, Some(0x1080));
        assert_eq!(fn_.name, "_start");
        assert_eq!(fn_.body.len(), 2);
        assert_eq!(fn_.body[0], Stmt::asm_text("endbr64"));
    }

    #[test]
    fn comments_at_top_level_become_items() {
        let f = parse("@module {}\n\n// note: hi\n").unwrap();
        assert_eq!(f.items.len(), 1);
        assert_eq!(f.items[0], Item::Comment("note: hi".into()));
    }

    #[test]
    fn comments_inside_function_body() {
        let src = r#"@module {}

fn f() {
    @asm("a")
    // block: 0x100
    @asm("b")
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        assert_eq!(fn_.body.len(), 3);
        assert_eq!(fn_.body[1], Stmt::Comment("block: 0x100".into()));
    }

    #[test]
    fn asm_with_pinned_bytes() {
        let src = r#"@module {}

fn f() {
    @asm("endbr64", [0xf3, 0x0f, 0x1e, 0xfa])
    @asm("ret", [0xc3])
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        assert_eq!(
            fn_.body[0],
            Stmt::asm("endbr64", vec![0xf3, 0x0f, 0x1e, 0xfa])
        );
        assert_eq!(fn_.body[1], Stmt::asm("ret", vec![0xc3]));
    }

    #[test]
    fn asm_byte_outside_range_is_rejected() {
        let src = r#"@module {}

fn f() {
    @asm("?", [0x100])
}
"#;
        let err = parse(src).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("byte value"),
            "expected byte-range error, got: {msg}"
        );
    }

    #[test]
    fn raw_item_at_top_level() {
        let src = "@module {}\n\n@raw(0x10c0, [0xcc, 0xcc, 0xcc])\n";
        let f = parse(src).unwrap();
        assert_eq!(
            f.items[0],
            Item::Raw {
                addr: 0x10c0,
                bytes: vec![0xcc, 0xcc, 0xcc],
            }
        );
    }

    #[test]
    fn section_with_nested_items() {
        let src = r#"@module {}

@section(".text", 0x1000) {
    @addr(0x1000)
    fn f() {
        @asm("ret", [0xc3])
    }

    @raw(0x1001, [0x90])
}
"#;
        let f = parse(src).unwrap();
        let Item::Section { name, addr, items } = &f.items[0] else {
            panic!("expected Section");
        };
        assert_eq!(name, ".text");
        assert_eq!(*addr, 0x1000);
        assert_eq!(items.len(), 2);
        assert!(matches!(items[0], Item::Function(_)));
        assert!(matches!(items[1], Item::Raw { .. }));
    }

    #[test]
    fn unknown_directive_reports_position() {
        let err = parse("@module {}\n\n@bogus(42)\nfn f() {}\n").unwrap_err();
        match err {
            ParseError::UnknownDirective { name, line, .. } => {
                assert_eq!(name, "bogus");
                assert_eq!(line, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

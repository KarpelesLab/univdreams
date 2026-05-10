//! Recursive-descent parser for `.ud`.
//!
//! Expects the canonical-form output of [`ud_ast::emit`] plus minor
//! whitespace variations. Errors carry a 1-indexed line/column.

use ud_ast::{Field, FnDecl, Item, Module, Param, Signature, Stmt, Type, UdFile, Value};

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

    /// Parse `name: type, name: type, …` (no parentheses; consumes
    /// up to but not including the closing `)`).
    fn parse_param_list(&mut self) -> Result<Vec<Param>, ParseError> {
        let mut out = Vec::new();
        loop {
            let name = self.expect_ident("parameter name")?;
            self.expect(&TokenKind::Colon, "`:` after parameter name")?;
            let ty = self.parse_type()?;
            out.push(Param { name, ty });
            if !self.eat_kind(&TokenKind::Comma) {
                break;
            }
            if self.peek().kind == TokenKind::RParen {
                break;
            }
        }
        Ok(out)
    }

    /// Parse a type token-sequence: a primitive name or `ptr<T>`.
    fn parse_type(&mut self) -> Result<Type, ParseError> {
        let tok = self.peek().clone();
        let name = self.expect_ident("type name")?;
        match name.as_str() {
            "void" => Ok(Type::Void),
            "i8" => Ok(Type::I8),
            "i16" => Ok(Type::I16),
            "i32" => Ok(Type::I32),
            "i64" => Ok(Type::I64),
            "u8" => Ok(Type::U8),
            "u16" => Ok(Type::U16),
            "u32" => Ok(Type::U32),
            "u64" => Ok(Type::U64),
            "f32" => Ok(Type::F32),
            "f64" => Ok(Type::F64),
            "bool" => Ok(Type::Bool),
            "char" => Ok(Type::Char),
            "unknown" => Ok(Type::Unknown),
            "ptr" => {
                self.expect(&TokenKind::Lt, "`<` after `ptr`")?;
                let inner = self.parse_type()?;
                self.expect(&TokenKind::Gt, "`>` to close `ptr<…>`")?;
                Ok(Type::Pointer(Box::new(inner)))
            }
            other => Err(ParseError::Expected {
                expected: "a type (void, iN, uN, fN, bool, char, ptr<…>, unknown)".into(),
                got: format!("identifier `{other}`"),
                line: tok.line,
                col: tok.col,
            }),
        }
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

        // Parameter list: empty `(...)` means no signature; non-empty
        // means typed.
        let params = if self.peek().kind == TokenKind::RParen {
            None
        } else {
            Some(self.parse_param_list()?)
        };
        self.expect(&TokenKind::RParen, "`)` after parameter list")?;

        // Optional `-> type` for the return type.
        let return_type = if self.eat_kind(&TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };

        let signature = match (params, return_type) {
            (None, None) => None,
            (Some(p), Some(r)) => Some(Signature {
                params: p,
                return_type: r,
            }),
            (Some(p), None) => Some(Signature {
                params: p,
                return_type: Type::Void,
            }),
            (None, Some(r)) => Some(Signature {
                params: Vec::new(),
                return_type: r,
            }),
        };

        self.expect(&TokenKind::LBrace, "`{` to open function body")?;
        let body = self.parse_stmt_list_until_rbrace()?;
        self.expect(&TokenKind::RBrace, "`}` to close function body")?;

        Ok(Item::Function(FnDecl {
            addr,
            name,
            signature,
            body,
        }))
    }

    /// Parse a sequence of statements until a `}` is the next token
    /// (or end of input). Does NOT consume the `}` — caller does.
    fn parse_stmt_list_until_rbrace(&mut self) -> Result<Vec<Stmt>, ParseError> {
        let mut body = Vec::new();
        loop {
            match self.peek().kind.clone() {
                TokenKind::RBrace => break,
                TokenKind::Eof => return Err(ParseError::UnexpectedEof),
                TokenKind::Comment(text) => {
                    self.bump();
                    body.push(Stmt::Comment(text));
                }
                TokenKind::At => {
                    self.bump();
                    let dir_tok = self.peek().clone();
                    let dir_name = self.expect_ident("statement directive name")?;
                    let stmt = self.parse_stmt_at_directive(&dir_name, &dir_tok)?;
                    body.push(stmt);
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
        Ok(body)
    }

    /// Dispatch on the directive name after a leading `@` inside a
    /// statement context (function body or if-branch arm).
    #[allow(clippy::too_many_lines)]
    fn parse_stmt_at_directive(
        &mut self,
        dir_name: &str,
        dir_tok: &Token,
    ) -> Result<Stmt, ParseError> {
        match dir_name {
            "asm" => {
                self.expect(&TokenKind::LParen, "`(` after `@asm`")?;
                let text = self.expect_string("asm string")?;
                let bytes = if self.eat_kind(&TokenKind::Comma) {
                    self.parse_byte_list()?
                } else {
                    Vec::new()
                };
                self.expect(&TokenKind::RParen, "`)` to close `@asm`")?;
                Ok(Stmt::Asm { text, bytes })
            }
            "return" => {
                self.expect(&TokenKind::LParen, "`(` after `@return`")?;
                let value = self.expect_int("return value (integer literal)")?;
                self.expect(&TokenKind::Comma, "`,` after return value")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@return`")?;
                Ok(Stmt::Return { value, bytes })
            }
            "prologue" => {
                self.expect(&TokenKind::LParen, "`(` after `@prologue`")?;
                let kind = self.expect_string("prologue kind string")?;
                self.expect(&TokenKind::Comma, "`,` after prologue kind")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@prologue`")?;
                Ok(Stmt::Prologue { kind, bytes })
            }
            "epilogue" => {
                self.expect(&TokenKind::LParen, "`(` after `@epilogue`")?;
                let kind = self.expect_string("epilogue kind string")?;
                self.expect(&TokenKind::Comma, "`,` after epilogue kind")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@epilogue`")?;
                Ok(Stmt::Epilogue { kind, bytes })
            }
            "return_expr" => {
                self.expect(&TokenKind::LParen, "`(` after `@return_expr`")?;
                let text = self.expect_string("return-expr text")?;
                self.expect(&TokenKind::Comma, "`,` after return-expr text")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@return_expr`")?;
                Ok(Stmt::ReturnExpr { text, bytes })
            }
            "call" => {
                self.expect(&TokenKind::LParen, "`(` after `@call`")?;
                let name = self.expect_string("call target name")?;
                self.expect(&TokenKind::Comma, "`,` after `@call` name")?;
                self.expect(&TokenKind::LBracket, "`[` to open arg list")?;
                let mut args = Vec::new();
                if self.peek().kind != TokenKind::RBracket {
                    args.push(self.expect_string("arg expression string")?);
                    while self.eat_kind(&TokenKind::Comma) {
                        if self.peek().kind == TokenKind::RBracket {
                            break;
                        }
                        args.push(self.expect_string("arg expression string")?);
                    }
                }
                self.expect(&TokenKind::RBracket, "`]` to close arg list")?;
                self.expect(&TokenKind::Comma, "`,` after `@call` args")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@call`")?;
                Ok(Stmt::Call { name, args, bytes })
            }
            "arg_spill" => {
                self.expect(&TokenKind::LParen, "`(` after `@arg_spill`")?;
                let idx = self.expect_int("argument index")?;
                if idx > u64::from(u32::MAX) {
                    return Err(ParseError::Expected {
                        expected: "argument index in 0..=u32::MAX".into(),
                        got: format!("integer 0x{idx:x}"),
                        line: dir_tok.line,
                        col: dir_tok.col,
                    });
                }
                self.expect(&TokenKind::Comma, "`,` after argument index")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@arg_spill`")?;
                #[allow(clippy::cast_possible_truncation)]
                let arg_index = idx as u32;
                Ok(Stmt::ArgSpill { arg_index, bytes })
            }
            "if_branch" => self.parse_if_branch_directive(dir_tok),
            "loop" => self.parse_loop_directive(),
            "local_set" => {
                self.expect(&TokenKind::LParen, "`(` after `@local_set`")?;
                #[allow(clippy::cast_possible_wrap)]
                let slot = self.expect_int("local-set slot displacement")? as i64;
                self.expect(&TokenKind::Comma, "`,` after `@local_set` slot")?;
                #[allow(clippy::cast_possible_wrap)]
                let value = self.expect_int("local-set immediate value")? as i64;
                self.expect(&TokenKind::Comma, "`,` after `@local_set` value")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@local_set`")?;
                Ok(Stmt::LocalSet { slot, value, bytes })
            }
            "local_arith" => {
                self.expect(&TokenKind::LParen, "`(` after `@local_arith`")?;
                #[allow(clippy::cast_possible_wrap)]
                let slot = self.expect_int("local-arith slot displacement")? as i64;
                self.expect(&TokenKind::Comma, "`,` after `@local_arith` slot")?;
                let op = self.expect_string("local-arith op string (e.g. \"+=\")")?;
                self.expect(&TokenKind::Comma, "`,` after `@local_arith` op")?;
                #[allow(clippy::cast_possible_wrap)]
                let value = self.expect_int("local-arith immediate value")? as i64;
                self.expect(&TokenKind::Comma, "`,` after `@local_arith` value")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@local_arith`")?;
                Ok(Stmt::LocalArith {
                    slot,
                    op,
                    value,
                    bytes,
                })
            }
            "local_compound" => {
                self.expect(&TokenKind::LParen, "`(` after `@local_compound`")?;
                #[allow(clippy::cast_possible_wrap)]
                let dst = self.expect_int("local-compound dst displacement")? as i64;
                self.expect(&TokenKind::Comma, "`,` after `@local_compound` dst")?;
                let op = self.expect_string("local-compound op string (e.g. \"+=\")")?;
                self.expect(&TokenKind::Comma, "`,` after `@local_compound` op")?;
                #[allow(clippy::cast_possible_wrap)]
                let src = self.expect_int("local-compound src displacement")? as i64;
                self.expect(&TokenKind::Comma, "`,` after `@local_compound` src")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@local_compound`")?;
                Ok(Stmt::LocalCompound {
                    dst,
                    op,
                    src,
                    bytes,
                })
            }
            other => Err(ParseError::UnknownDirective {
                name: other.to_string(),
                line: dir_tok.line,
                col: dir_tok.col,
            }),
        }
    }

    /// Parse `@loop([entry_jmp=[bytes],] "cond", [tail bytes]) { …body… }`.
    fn parse_loop_directive(&mut self) -> Result<Stmt, ParseError> {
        self.expect(&TokenKind::LParen, "`(` after `@loop`")?;
        // Optional `entry_jmp=[bytes],` prefix.
        let entry_jmp_bytes = if matches!(&self.peek().kind, TokenKind::Ident(name) if name == "entry_jmp")
        {
            self.bump();
            self.expect(&TokenKind::Eq, "`=` after `entry_jmp`")?;
            let bytes = self.parse_byte_list()?;
            self.expect(&TokenKind::Comma, "`,` after `entry_jmp` bytes")?;
            Some(bytes)
        } else {
            None
        };
        let cond_text = self.expect_string("loop cond text")?;
        self.expect(&TokenKind::Comma, "`,` after loop cond text")?;
        let tail_bytes = self.parse_byte_list()?;
        self.expect(&TokenKind::RParen, "`)` to close `@loop` head")?;
        self.expect(&TokenKind::LBrace, "`{` to open `@loop` body")?;
        let body = self.parse_stmt_list_until_rbrace()?;
        self.expect(&TokenKind::RBrace, "`}` to close `@loop` body")?;
        Ok(Stmt::Loop {
            cond_text,
            entry_jmp_bytes,
            tail_bytes,
            body,
        })
    }

    /// Parse `@if_branch("cond", [bytes]) { @then { … } [@else { … }] }`
    /// after the `@if_branch` directive name has already been consumed.
    /// `@then` is required; `@else` is optional. The arms may appear
    /// in either order.
    fn parse_if_branch_directive(&mut self, dir_tok: &Token) -> Result<Stmt, ParseError> {
        self.expect(&TokenKind::LParen, "`(` after `@if_branch`")?;
        let cond_text = self.expect_string("if-branch cond text")?;
        self.expect(&TokenKind::Comma, "`,` after if-branch cond text")?;
        let cond_bytes = self.parse_byte_list()?;
        self.expect(&TokenKind::RParen, "`)` to close `@if_branch` head")?;
        self.expect(&TokenKind::LBrace, "`{` to open `@if_branch` body")?;

        let mut then_body: Option<Vec<Stmt>> = None;
        let mut else_body: Option<Vec<Stmt>> = None;

        loop {
            match self.peek().kind.clone() {
                TokenKind::RBrace => {
                    self.bump();
                    break;
                }
                TokenKind::Eof => return Err(ParseError::UnexpectedEof),
                TokenKind::Comment(_) => {
                    self.bump(); // tolerate comments between arms; they're not retained
                }
                TokenKind::At => {
                    self.bump();
                    let arm_tok = self.peek().clone();
                    let arm_name = self.expect_ident("`then` or `else` after `@`")?;
                    match arm_name.as_str() {
                        "then" => {
                            if then_body.is_some() {
                                return Err(ParseError::Expected {
                                    expected: "exactly one `@then` arm".into(),
                                    got: "duplicate `@then`".into(),
                                    line: arm_tok.line,
                                    col: arm_tok.col,
                                });
                            }
                            self.expect(&TokenKind::LBrace, "`{` to open `@then` arm")?;
                            let body = self.parse_stmt_list_until_rbrace()?;
                            self.expect(&TokenKind::RBrace, "`}` to close `@then` arm")?;
                            then_body = Some(body);
                        }
                        "else" => {
                            if else_body.is_some() {
                                return Err(ParseError::Expected {
                                    expected: "exactly one `@else` arm".into(),
                                    got: "duplicate `@else`".into(),
                                    line: arm_tok.line,
                                    col: arm_tok.col,
                                });
                            }
                            self.expect(&TokenKind::LBrace, "`{` to open `@else` arm")?;
                            let body = self.parse_stmt_list_until_rbrace()?;
                            self.expect(&TokenKind::RBrace, "`}` to close `@else` arm")?;
                            else_body = Some(body);
                        }
                        other => {
                            return Err(ParseError::UnknownDirective {
                                name: other.to_string(),
                                line: arm_tok.line,
                                col: arm_tok.col,
                            });
                        }
                    }
                }
                other => {
                    return Err(ParseError::Expected {
                        expected: "`@then`, `@else`, or `}`".into(),
                        got: describe(&other),
                        line: self.peek().line,
                        col: self.peek().col,
                    });
                }
            }
        }

        let then_body = then_body.ok_or_else(|| ParseError::Expected {
            expected: "`@then` arm inside `@if_branch`".into(),
            got: "missing `@then` arm".into(),
            line: dir_tok.line,
            col: dir_tok.col,
        })?;

        Ok(Stmt::IfBranch {
            cond_text,
            cond_bytes,
            then_body,
            else_body,
        })
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
        TokenKind::Arrow => "`->`".into(),
        TokenKind::Lt => "`<`".into(),
        TokenKind::Gt => "`>`".into(),
        TokenKind::Eq => "`=`".into(),
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
    fn function_with_typed_signature() {
        let src = "@module {}\n\nfn main(argc: i32, argv: ptr<ptr<u8>>) -> i32 {\n}\n";
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        let sig = fn_.signature.as_ref().unwrap();
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0].name, "argc");
        assert_eq!(sig.params[0].ty, Type::I32);
        assert_eq!(sig.params[1].name, "argv");
        assert_eq!(
            sig.params[1].ty,
            Type::Pointer(Box::new(Type::Pointer(Box::new(Type::U8))))
        );
        assert_eq!(sig.return_type, Type::I32);
    }

    #[test]
    fn function_without_signature() {
        let src = "@module {}\n\nfn _init() {\n}\n";
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        assert!(fn_.signature.is_none());
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
    fn if_branch_else_body_round_trips_via_some() {
        let src = r#"@module {}

fn f() {
    @if_branch("c", [0x90]) {
        @then { @asm("ret", [0xc3]) }
        @else { @asm("nop", [0x90]) }
    }
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        let Stmt::IfBranch { else_body, .. } = &fn_.body[0] else {
            panic!()
        };
        assert!(else_body.is_some());
    }

    #[test]
    fn if_branch_with_then_and_else_arms() {
        let src = r#"@module {}

fn f() {
    @if_branch("cmp [rbp-4],1; jne", [0x83, 0x7d, 0xfc, 0x01, 0x75, 0x07]) {
        @then {
            @asm("ret", [0xc3])
        }
        @else {
            @asm("nop", [0x90])
        }
    }
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        assert_eq!(fn_.body.len(), 1);
        let Stmt::IfBranch {
            cond_text,
            cond_bytes,
            then_body,
            else_body,
        } = &fn_.body[0]
        else {
            panic!("expected IfBranch, got {:?}", fn_.body[0]);
        };
        assert_eq!(cond_text, "cmp [rbp-4],1; jne");
        assert_eq!(cond_bytes, &vec![0x83, 0x7d, 0xfc, 0x01, 0x75, 0x07]);
        assert_eq!(then_body.len(), 1);
        let else_body = else_body.as_ref().expect("else arm");
        assert_eq!(else_body.len(), 1);
        assert_eq!(then_body[0], Stmt::asm("ret", vec![0xc3]));
        assert_eq!(else_body[0], Stmt::asm("nop", vec![0x90]));
    }

    #[test]
    fn if_branch_arms_can_be_in_either_order() {
        let src = r#"@module {}

fn f() {
    @if_branch("test eax,eax; je", [0x85, 0xc0, 0x74, 0x01]) {
        @else { @asm("nop", [0x90]) }
        @then { @asm("ret", [0xc3]) }
    }
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        let Stmt::IfBranch {
            then_body,
            else_body,
            ..
        } = &fn_.body[0]
        else {
            panic!()
        };
        assert_eq!(then_body[0], Stmt::asm("ret", vec![0xc3]));
        let else_body = else_body.as_ref().expect("else arm");
        assert_eq!(else_body[0], Stmt::asm("nop", vec![0x90]));
    }

    #[test]
    fn if_branch_without_else_arm_is_accepted() {
        let src = r#"@module {}

fn f() {
    @if_branch("test rax,rax; je short 0x1016", [0x48, 0x85, 0xc0, 0x74, 0x02]) {
        @then { @asm("call rax", [0xff, 0xd0]) }
    }
}
"#;
        let f = parse(src).unwrap();
        let Item::Function(fn_) = &f.items[0] else {
            panic!()
        };
        let Stmt::IfBranch {
            then_body,
            else_body,
            ..
        } = &fn_.body[0]
        else {
            panic!("expected IfBranch")
        };
        assert_eq!(then_body[0], Stmt::asm("call rax", vec![0xff, 0xd0]));
        assert!(else_body.is_none());
    }

    #[test]
    fn if_branch_missing_then_arm_errors() {
        let src = r#"@module {}

fn f() {
    @if_branch("c", [0x90]) {
        @else { @asm("nop", [0x90]) }
    }
}
"#;
        let err = parse(src).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("@then"),
            "expected `@then` mention in error, got: {msg}"
        );
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

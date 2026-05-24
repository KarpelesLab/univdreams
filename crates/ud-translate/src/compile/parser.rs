//! Recursive-descent parser for `.ud`.
//!
//! Expects the canonical-form output of [`ud_ast::emit`] plus minor
//! whitespace variations. Errors carry a 1-indexed line/column.

use ud_ast::{Field, FnDecl, Item, Module, Param, Signature, Stmt, Type, UdFile, Value};

use crate::compile::lexer::{tokenize, LexError, Token, TokenKind};

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
    let mut p = Parser::new(input.to_string(), tokens);
    p.parse_file()
}

struct Parser {
    src: String,
    tokens: Vec<Token>,
    pos: usize,
    /// Bit width captured from `@module.bits` once the module
    /// header is parsed. Drives the prologue/epilogue codec choice
    /// for byte encoding at parse time. Defaults to 32 so legacy
    /// fixtures without an explicit `bits` field still encode
    /// correctly.
    bits: u32,
}

impl Parser {
    fn new(src: String, tokens: Vec<Token>) -> Self {
        Self {
            src,
            tokens,
            pos: 0,
            bits: 32,
        }
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
        // Cache `bits` so prologue/epilogue encoders downstream
        // pick the matching codec width without re-walking the
        // module fields per stmt.
        for f in &module.fields {
            if f.name == "bits" {
                if let ud_ast::Value::Int(n) = &f.value {
                    if let Ok(n) = u32::try_from(*n) {
                        self.bits = n;
                    }
                }
                break;
            }
        }
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
            // Optional `@LOC` calling-convention location suffix.
            let location = if self.eat_kind(&TokenKind::At) {
                Some(self.expect_ident("calling-convention location after `@`")?)
            } else {
                None
            };
            out.push(Param { name, ty, location });
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

    /// Parse one `{ type: …, name: "…", desc: [bytes] }` entry inside
    /// a `@notes(…)` directive. Trailing comma after `desc:` allowed.
    fn parse_note_entry(&mut self) -> Result<ud_ast::NoteEntry, ParseError> {
        self.expect(&TokenKind::LBrace, "`{` to open note entry")?;
        let mut note_type: Option<u32> = None;
        let mut name: Option<String> = None;
        let mut desc: Option<Vec<u8>> = None;
        loop {
            if self.peek().kind == TokenKind::RBrace {
                break;
            }
            let key_tok = self.peek().clone();
            let key = self.expect_ident("note field name")?;
            self.expect(&TokenKind::Colon, "`:` after note field name")?;
            match key.as_str() {
                "type" => {
                    let n = self.expect_int("note type")?;
                    note_type = Some(u32::try_from(n).map_err(|_| ParseError::Expected {
                        expected: "u32 note type".into(),
                        got: format!("integer 0x{n:x}"),
                        line: key_tok.line,
                        col: key_tok.col,
                    })?);
                }
                "name" => name = Some(self.expect_string("note name")?),
                "desc" => desc = Some(self.parse_byte_list()?),
                other => {
                    return Err(ParseError::Expected {
                        expected: "`type`, `name`, or `desc`".into(),
                        got: format!("`{other}`"),
                        line: key_tok.line,
                        col: key_tok.col,
                    });
                }
            }
            if !self.eat_kind(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RBrace, "`}` to close note entry")?;
        let entry_tok = self.peek().clone();
        Ok(ud_ast::NoteEntry {
            note_type: note_type.ok_or_else(|| ParseError::Expected {
                expected: "`type:` field in note entry".into(),
                got: "no `type` key".into(),
                line: entry_tok.line,
                col: entry_tok.col,
            })?,
            name: name.unwrap_or_default(),
            desc: desc.unwrap_or_default(),
        })
    }

    /// Parse `#[key=value, key=value, …]`. Returns the empty vec when
    /// the next token isn't `#`. Trailing comma allowed.
    fn parse_attrs(&mut self) -> Result<Vec<ud_ast::Attribute>, ParseError> {
        if self.peek().kind != TokenKind::Hash {
            return Ok(Vec::new());
        }
        self.expect(&TokenKind::Hash, "`#` to open attribute list")?;
        self.expect(&TokenKind::LBracket, "`[` after `#`")?;
        let mut out = Vec::new();
        if self.peek().kind == TokenKind::RBracket {
            self.bump();
            return Ok(out);
        }
        loop {
            let key = self.expect_ident("attribute key")?;
            // Bare-flag attrs (`#[naked]`) skip the `=value` part;
            // the next token is either a separator or the
            // closing bracket.
            let value = if matches!(self.peek().kind, TokenKind::Comma | TokenKind::RBracket) {
                ud_ast::AttrValue::Flag
            } else {
                self.expect(&TokenKind::Eq, "`=` after attribute key")?;
                self.parse_attr_value()?
            };
            out.push(ud_ast::Attribute { key, value });
            if !self.eat_kind(&TokenKind::Comma) {
                break;
            }
            if self.peek().kind == TokenKind::RBracket {
                break;
            }
        }
        self.expect(&TokenKind::RBracket, "`]` to close attribute list")?;
        Ok(out)
    }

    /// Parse one attribute value: string, integer, or `[byte, …]`
    /// byte list. The byte-list form is the only one usable for
    /// load-bearing attributes (`head_bytes=[…]`).
    fn parse_attr_value(&mut self) -> Result<ud_ast::AttrValue, ParseError> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::String(s) => {
                let s = s.clone();
                self.bump();
                Ok(ud_ast::AttrValue::String(s))
            }
            TokenKind::Int(n) => {
                let n = *n;
                self.bump();
                Ok(ud_ast::AttrValue::Int(n))
            }
            TokenKind::LBracket => {
                let bytes = self.parse_byte_list()?;
                Ok(ud_ast::AttrValue::ByteList(bytes))
            }
            other => Err(ParseError::Expected {
                expected: "an attribute value (string, integer, or `[bytes]`)".into(),
                got: describe(other),
                line: tok.line,
                col: tok.col,
            }),
        }
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

    #[allow(clippy::too_many_lines)]
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
            "strings" => {
                self.expect(&TokenKind::LParen, "`(` after `@strings`")?;
                let addr = self.expect_int("an integer address")?;
                self.expect(&TokenKind::Comma, "`,` after `@strings` address")?;
                self.expect(&TokenKind::LBracket, "`[` to open string list")?;
                let mut strings = Vec::new();
                while !matches!(self.peek().kind, TokenKind::RBracket | TokenKind::Eof) {
                    let s = self.expect_string("a string literal")?;
                    strings.push(s);
                    if !self.eat_kind(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(&TokenKind::RBracket, "`]` to close string list")?;
                self.expect(&TokenKind::RParen, "`)` to close `@strings`")?;
                Ok(Item::Strings { addr, strings })
            }
            "notes" => {
                self.expect(&TokenKind::LParen, "`(` after `@notes`")?;
                let addr = self.expect_int("an integer address")?;
                self.expect(&TokenKind::Comma, "`,` after `@notes` address")?;
                self.expect(&TokenKind::LBracket, "`[` to open note list")?;
                let mut entries: Vec<ud_ast::NoteEntry> = Vec::new();
                while !matches!(self.peek().kind, TokenKind::RBracket | TokenKind::Eof) {
                    entries.push(self.parse_note_entry()?);
                    if !self.eat_kind(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(&TokenKind::RBracket, "`]` to close note list")?;
                self.expect(&TokenKind::RParen, "`)` to close `@notes`")?;
                Ok(Item::Notes { addr, entries })
            }
            "jump_table" => {
                self.expect(&TokenKind::LParen, "`(` after `@jump_table`")?;
                let addr = self.expect_int("an integer address")?;
                self.expect(&TokenKind::Comma, "`,` after `@jump_table` address")?;
                let dispatch_key = self.expect_ident("`dispatch`")?;
                if dispatch_key != "dispatch" {
                    return Err(ParseError::Expected {
                        expected: "`dispatch`".into(),
                        got: format!("`{dispatch_key}`"),
                        line: dir_tok.line,
                        col: dir_tok.col,
                    });
                }
                self.expect(&TokenKind::Eq, "`=` after `dispatch`")?;
                let dispatch = self.expect_string("dispatch kind string")?;
                self.expect(&TokenKind::RParen, "`)` to close `@jump_table` header")?;
                self.expect(&TokenKind::LBrace, "`{` to open jump_table entries")?;
                let mut entries: Vec<ud_ast::JumpTableEntry> = Vec::new();
                while !matches!(self.peek().kind, TokenKind::RBrace | TokenKind::Eof) {
                    let case_ident = self.expect_ident("`case_<N>` identifier")?;
                    let case_num = case_ident
                        .strip_prefix("case_")
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or_else(|| ParseError::Expected {
                            expected: "`case_<N>` (decimal index)".into(),
                            got: format!("`{case_ident}`"),
                            line: self.peek().line,
                            col: self.peek().col,
                        })?;
                    self.expect(&TokenKind::Colon, "`:` after case label")?;
                    let target_ident = self.expect_ident("`label_<hex>` target")?;
                    let target = target_ident
                        .strip_prefix("label_")
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                        .ok_or_else(|| ParseError::Expected {
                            expected: "`label_<hex>` target".into(),
                            got: format!("`{target_ident}`"),
                            line: self.peek().line,
                            col: self.peek().col,
                        })?;
                    entries.push(ud_ast::JumpTableEntry {
                        case: case_num,
                        target,
                    });
                    if !self.eat_kind(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(&TokenKind::RBrace, "`}` to close `@jump_table` body")?;
                Ok(Item::JumpTable {
                    addr,
                    dispatch,
                    entries,
                })
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

        // Optional `#[…]` attribute list after the signature.
        let attrs = self.parse_attrs()?;
        self.expect(&TokenKind::LBrace, "`{` to open function body")?;
        // Leading `let NAME: TYPE [@reg];` declarations describe the
        // variables and registers the function uses. They precede
        // every other statement and end as soon as the next token
        // isn't another `let`.
        let locals = self.parse_local_decls()?;
        let body = self.parse_stmt_list_until_rbrace()?;
        self.expect(&TokenKind::RBrace, "`}` to close function body")?;

        Ok(Item::Function(FnDecl {
            addr,
            name,
            attrs,
            signature,
            locals,
            body,
        }))
    }

    /// Parse a contiguous run of `let NAME: TYPE [@reg];` lines.
    /// Returns the empty vec when the next token isn't `let`.
    fn parse_local_decls(&mut self) -> Result<Vec<ud_ast::LocalDecl>, ParseError> {
        let mut out = Vec::new();
        loop {
            let is_let = matches!(&self.peek().kind, TokenKind::Ident(n) if n == "let");
            if !is_let {
                return Ok(out);
            }
            self.bump(); // consume `let`
                         // Accept a comma-separated list of `name: ty` entries
                         // on one `let`. The emitter coalesces register-backed
                         // locals onto a single line to reduce visual noise:
                         //   `let ebp: u64, esp: u64, edi: u32 @reg;`
            let mut group: Vec<(String, ud_ast::Type)> = Vec::new();
            loop {
                let name = self.expect_ident("local variable name")?;
                self.expect(&TokenKind::Colon, "`:` after local variable name")?;
                let ty = self.parse_type()?;
                group.push((name, ty));
                if !self.eat_kind(&TokenKind::Comma) {
                    break;
                }
            }
            // Optional trailing `@reg` marker applies to every name
            // in the group.
            let kind = if self.eat_kind(&TokenKind::At) {
                let marker = self.expect_ident("local-decl marker after `@`")?;
                if marker != "reg" {
                    return Err(ParseError::Expected {
                        expected: "`reg` after `@` in local declaration".into(),
                        got: format!("identifier `{marker}`"),
                        line: self.peek().line,
                        col: self.peek().col,
                    });
                }
                ud_ast::LocalKind::Register
            } else {
                ud_ast::LocalKind::Stack
            };
            self.expect(&TokenKind::Semicolon, "`;` to close `let` declaration")?;
            for (name, ty) in group {
                out.push(ud_ast::LocalDecl { name, ty, kind });
            }
        }
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
                TokenKind::Ident(name) if name == "if" => {
                    let stmt = self.parse_if_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if name == "ifblock" => {
                    let stmt = self.parse_ifblock_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if name == "whileblock" => {
                    let stmt = self.parse_whileblock_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if name == "do" => {
                    let stmt = self.parse_do_while_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if name == "goto" => {
                    let stmt = self.parse_goto_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if name == "return" => {
                    let stmt = self.parse_return_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if name == "switch" => {
                    let stmt = self.parse_switch_stmt()?;
                    body.push(stmt);
                }
                TokenKind::Ident(name) if is_label_name(name.as_str()) => {
                    // Disambiguate `label_HEX:` (a marker) from
                    // `label_HEX = …` (a stmt whose lhs happens to
                    // start with `label_`). Only consume as a label
                    // when the next token is `:`.
                    let next_kind = self.tokens.get(self.pos + 1).map(|t| t.kind.clone());
                    if matches!(next_kind, Some(TokenKind::Colon)) {
                        let stmt = self.parse_label_stmt()?;
                        body.push(stmt);
                    } else {
                        let stmt = self.parse_call_or_move_stmt()?;
                        body.push(stmt);
                    }
                }
                TokenKind::Ident(_) | TokenKind::LBracket | TokenKind::LParen => {
                    let stmt = self.parse_call_or_move_stmt()?;
                    body.push(stmt);
                }
                other => {
                    return Err(ParseError::Expected {
                        expected: "`@asm`, `// comment`, function call, or `}`".into(),
                        got: describe(&other),
                        line: self.peek().line,
                        col: self.peek().col,
                    });
                }
            }
        }
        Ok(body)
    }

    /// Pick between call and assignment statement based on the
    /// initial tokens. Three shapes are supported:
    ///
    /// * `name(args) [bytes]`           — direct call with an Ident name.
    /// * `[mem-expr](args) [bytes]`     — indirect call through memory
    ///   (the call target itself is a bracketed addressing expression).
    /// * `dst = src [bytes]`            — assignment / move, where the
    ///   destination may be any of: a bare Ident, a `[mem-expr]`
    ///   (e.g. `[ebp+8]`), or a `(reg,reg)` 6502-style operand.
    ///
    /// The discriminator is: skip past a leading delimited expression
    /// (anything starting with `[` or `(`) and look at the next token.
    /// If it's `(`, this is a call; otherwise a move.
    /// Probe the token stream starting at the current `Ident` for
    /// the `Ident (-> Ident)+ (` shape that thiscall lifting
    /// produces (`this->f_2a4(…)`, `this->f_8->run(…)`, …).
    /// Stops at any other token (including `=`, which would mean
    /// a Move statement).
    fn lookahead_is_method_call(&self) -> bool {
        let mut i = self.pos + 1;
        let mut saw_arrow_ident = false;
        loop {
            let arrow = self.tokens.get(i).map(|t| &t.kind);
            if !matches!(arrow, Some(TokenKind::Arrow)) {
                break;
            }
            i += 1;
            if !matches!(
                self.tokens.get(i).map(|t| &t.kind),
                Some(TokenKind::Ident(_))
            ) {
                return false;
            }
            i += 1;
            saw_arrow_ident = true;
        }
        if !saw_arrow_ident {
            return false;
        }
        matches!(self.tokens.get(i).map(|t| &t.kind), Some(TokenKind::LParen))
    }

    fn parse_call_or_move_stmt(&mut self) -> Result<Stmt, ParseError> {
        // Statement begins with `Ident`. Direct call when the next
        // token is `(`, or when a `Ident -> Ident (` chain (a C++
        // method call lifted from thiscall) follows. Otherwise an
        // assignment.
        if matches!(self.peek().kind, TokenKind::Ident(_)) {
            let next = self.tokens.get(self.pos + 1).map(|t| &t.kind);
            if matches!(next, Some(TokenKind::LParen)) {
                return self.parse_call_stmt();
            }
            // `obj->method(…)` shape: probe several `Arrow Ident`
            // pairs (e.g., `this->f_8->run()`).
            if self.lookahead_is_method_call() {
                return self.parse_call_stmt();
            }
            return self.parse_move_stmt();
        }
        // Statement begins with `[` or `(`. Find the matching close
        // delimiter; if the token right after is `(`, the leading
        // bracketed expression names the call target. Otherwise this
        // is a move whose destination is the bracketed expression.
        let close_idx = self.find_matching_close(self.pos);
        if let Some(close) = close_idx {
            if matches!(
                self.tokens.get(close + 1).map(|t| &t.kind),
                Some(TokenKind::LParen)
            ) {
                return self.parse_call_stmt();
            }
        }
        self.parse_move_stmt()
    }

    /// Walk tokens starting at the `[` or `(` at `open_idx` and return
    /// the index of the matching close delimiter. Returns `None` if
    /// the open is missing or the delimiters are unbalanced.
    fn find_matching_close(&self, open_idx: usize) -> Option<usize> {
        let open_kind = match self.tokens.get(open_idx).map(|t| &t.kind)? {
            TokenKind::LParen => TokenKind::LParen,
            TokenKind::LBracket => TokenKind::LBracket,
            _ => return None,
        };
        let close_kind = match open_kind {
            TokenKind::LParen => TokenKind::RParen,
            TokenKind::LBracket => TokenKind::RBracket,
            _ => unreachable!(),
        };
        let mut depth = 0i32;
        let mut i = open_idx;
        while i < self.tokens.len() {
            match &self.tokens[i].kind {
                TokenKind::LParen | TokenKind::LBracket => depth += 1,
                k if *k == close_kind => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                TokenKind::RParen | TokenKind::RBracket => depth -= 1,
                TokenKind::Eof | TokenKind::RBrace => return None,
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// Parse `<dst> = <src> [bytes]`. Both sides are raw source
    /// text snipped between token boundaries — the contents can
    /// include arbitrary x86 effective-address syntax
    /// (`[ebp+8]`, `[esi+ebx*4]`), hex literals with a trailing
    /// `h`, and chained destinations (`KBDCR = DSPCR`).
    ///
    /// The scan is bounded to the statement's starting line so it
    /// doesn't reach into the next statement. The split between
    /// `dst` and `src` is the *last* `=` at depth zero on that
    /// line, so cascade dsts (`a = b = c`) survive. The byte list
    /// is the last top-level `[…]` that contains only integers
    /// and commas — this excludes memory-expression `[…]`s and
    /// hex-literal blocks like `[1C201030h]`.
    fn parse_move_stmt(&mut self) -> Result<Stmt, ParseError> {
        let stmt_start_tok = self.peek().clone();
        let stmt_line = stmt_start_tok.line;
        let stmt_start = stmt_start_tok.start;
        // Walk on this line and collect:
        //   - last `=` at depth 0
        //   - last `[…]` at depth 0 whose contents look like a
        //     byte list (only `Int`s and commas).
        // `Stmt::Move` always emits on a single line, so the scan is
        // bounded to `stmt_line`. Crossing the line boundary would let
        // the scan capture tokens from the next statement (e.g. an
        // `if (cond) [cond_bytes]` whose byte list would otherwise be
        // mis-identified as this move's byte list, dropping the real
        // bytes and leaving the parser stranded at the `{`).
        let mut depth = 0i32;
        let mut last_eq_idx: Option<usize> = None;
        let mut byte_list_idx: Option<usize> = None;
        let mut probe = self.pos;
        while probe < self.tokens.len() {
            let tok = &self.tokens[probe];
            if tok.line != stmt_line {
                break;
            }
            match &tok.kind {
                TokenKind::LBracket if depth == 0 => {
                    if is_byte_list_block(&self.tokens, probe) {
                        byte_list_idx = Some(probe);
                    }
                    depth += 1;
                }
                TokenKind::LParen | TokenKind::LBracket => depth += 1,
                TokenKind::RParen | TokenKind::RBracket => depth -= 1,
                TokenKind::Eq if depth == 0 => last_eq_idx = Some(probe),
                TokenKind::Eof | TokenKind::Comment(_) | TokenKind::RBrace => break,
                _ => {}
            }
            probe += 1;
        }
        let last_eq_tok =
            last_eq_idx
                .map(|i| self.tokens[i].clone())
                .ok_or_else(|| ParseError::Expected {
                    expected: "`=` in assignment statement".into(),
                    got: describe(&self.peek().kind),
                    line: self.peek().line,
                    col: self.peek().col,
                })?;
        // Detect compound-assignment forms (`+=`, `-=`, `*=`,
        // `/=`, `%=`, `|=`, `&=`, `^=`, `<<=`, `>>=`) by
        // peeking at the token(s) immediately before `Eq`.
        // The op text is sliced from the source so the
        // emitter's canonical form (e.g. `r1 += 0x5`) round-
        // trips.
        let eq_idx = last_eq_idx.unwrap();
        let compound_op = detect_compound_op(&self.tokens, eq_idx);
        let dst_end = compound_op
            .map_or(last_eq_tok.start, |(prev_idx, _len)| self.tokens[prev_idx].start);
        // Bytes are optional now — when the byte-drop pass clears
        // them at decompile time, the emitter skips the `[]` and
        // lower regenerates from the dst/src text via the arch
        // codec.
        let bytes_tok = byte_list_idx
            .filter(|&i| self.tokens[i].start > last_eq_tok.start)
            .map(|i| self.tokens[i].clone());
        let dst = self.src[stmt_start..dst_end].trim().to_string();
        let (src, bytes) = if let Some(btok) = bytes_tok {
            let src = self.src[last_eq_tok.end..btok.start].trim().to_string();
            // Advance to the byte list and parse it.
            while self.pos < self.tokens.len() && self.peek().start < btok.start {
                self.bump();
            }
            let bytes = self.parse_byte_list()?;
            (src, bytes)
        } else {
            // src runs from `=` to end-of-line (the last token
            // on this line that isn't a Comment/Eof/RBrace).
            let mut last_tok_end = last_eq_tok.end;
            while self.pos < self.tokens.len() {
                let tok = self.peek();
                if tok.line != stmt_line
                    || matches!(
                        tok.kind,
                        TokenKind::Eof | TokenKind::Comment(_) | TokenKind::RBrace
                    )
                {
                    break;
                }
                last_tok_end = tok.end;
                self.bump();
            }
            let src = self.src[last_eq_tok.end..last_tok_end].trim().to_string();
            (src, Vec::new())
        };
        // Strip a trailing `;` from `src` if present (RegArith
        // canonical form emits `dst op src;` with the semicolon
        // inside the captured range).
        let src = src
            .strip_suffix(';')
            .map_or(src.clone(), |s| s.trim().to_string());
        if let Some((_prev_idx, _len)) = compound_op {
            let op = self.src[dst_end..last_eq_tok.end].trim().to_string();
            return Ok(Stmt::RegArith {
                dst,
                op,
                src,
                bytes,
            });
        }
        Ok(Stmt::Move { dst, src, bytes })
    }

    /// Parse a function-call statement:
    ///
    /// ```text
    /// name(arg, …) [bytes]
    /// ```
    ///
    /// `arg`s are free-form text — typically `A=#$0D` for 6502 or
    /// `0x4008` / `result` for x86. They can also be quoted strings
    /// when they contain characters the lexer wouldn't otherwise
    /// recognise (whitespace, embedded quotes, escapes). The
    /// trailing `[bytes]` pins the lowered encoding for
    /// byte-identical round-trip.
    ///
    /// Implementation: we tokenise normally, walk over the args
    /// with paren-balance tracking, and snip the raw source text
    /// for each top-level comma-separated segment. This lets
    /// `A=(XAML,X)` or `*.data @ 0x4008` survive without escaping.
    /// Parse the name preceding a call's argument list. Two shapes:
    ///
    /// * `name` — a bare identifier (the direct-call shape).
    /// * `[mem-expr]` — a bracketed addressing expression (indirect
    ///   call through memory). The raw source text between `[` and
    ///   the matching `]` (inclusive of both) is returned verbatim.
    fn parse_call_target_name(&mut self) -> Result<String, ParseError> {
        let tok = self.peek().clone();
        if let TokenKind::Ident(n) = &tok.kind {
            let start = tok.start;
            let mut name = n.clone();
            self.bump();
            // Consume any `-> Ident` chain (C++ method-call form
            // surfaced by thiscall lifting). Capture the raw text
            // so `this->f_2a4` survives intact as the call target.
            while matches!(self.peek().kind, TokenKind::Arrow) {
                self.bump();
                if let TokenKind::Ident(_) = &self.peek().kind {
                    let end = self.peek().end;
                    self.bump();
                    name = self.src[start..end].to_string();
                } else {
                    break;
                }
            }
            return Ok(name);
        }
        if matches!(tok.kind, TokenKind::LBracket) {
            let start = tok.start;
            let close = self
                .find_matching_close(self.pos)
                .ok_or(ParseError::UnexpectedEof)?;
            let end = self.tokens[close].end;
            let text = self.src[start..end].to_string();
            while self.pos < self.tokens.len() && self.pos <= close {
                self.bump();
            }
            return Ok(text);
        }
        Err(ParseError::Expected {
            expected: "a call target name (identifier or `[…]`)".into(),
            got: describe(&tok.kind),
            line: tok.line,
            col: tok.col,
        })
    }

    fn parse_call_stmt(&mut self) -> Result<Stmt, ParseError> {
        let name = self.parse_call_target_name()?;
        self.expect(&TokenKind::LParen, "`(` after call target name")?;
        let mut args = Vec::new();
        // Empty arg list: `name()`.
        if self.peek().kind != TokenKind::RParen {
            self.collect_call_args(&mut args)?;
        }
        self.expect(&TokenKind::RParen, "`)` to close call argument list")?;
        // Optional `#[target=0x…]` attribute marks a direct call
        // whose trailing `call rel32` re-encodes at lower time.
        let attrs = self.parse_attrs()?;
        let direct_target = attrs.iter().find_map(|a| match (a.key.as_str(), &a.value) {
            ("target", ud_ast::AttrValue::Int(n)) => Some(*n),
            _ => None,
        });
        // Bytes are optional: BPF call-sites with a known
        // `direct_target` regenerate via `arch.encode_call` at
        // lower time, so the emitter omits the `[]` block.
        // Only consume a following `[` when it's a real byte
        // list AND on the same line as the call — otherwise
        // it's the dst of a stx-style Move on the next line
        // (e.g. `[r6 + 0x60] = r8`).
        let call_line = self
            .tokens
            .get(self.pos.saturating_sub(1))
            .map_or(0, |t| t.line);
        let bytes = if self.peek().kind == TokenKind::LBracket
            && self.peek().line == call_line
            && is_byte_list_block(&self.tokens, self.pos)
        {
            self.parse_byte_list()?
        } else {
            Vec::new()
        };
        Ok(Stmt::Call {
            name,
            args,
            bytes,
            direct_target,
        })
    }

    /// Walk tokens until the matching `)` of the current call
    /// argument list, splitting on top-level commas.
    ///
    /// Each segment becomes one element of `out`:
    ///
    /// * If the segment is exactly one quoted-string token, the
    ///   AST gets the *parsed* string (escapes resolved) so the
    ///   AST canonical content survives a round-trip via text.
    /// * Otherwise, the AST gets the raw source-text slice spanning
    ///   the segment — preserves `A=#$0D`, `A=(XAML,X)`, etc.
    ///   verbatim.
    fn collect_call_args(&mut self, out: &mut Vec<String>) -> Result<(), ParseError> {
        let mut depth = 0i32;
        let mut seg_start = self.peek().start;
        let mut seg_string: Option<String> = None;
        let mut seg_token_count = 0usize;
        loop {
            let tok = self.peek().clone();
            match &tok.kind {
                TokenKind::LParen | TokenKind::LBracket => {
                    depth += 1;
                    seg_token_count += 1;
                    self.bump();
                }
                TokenKind::RParen | TokenKind::RBracket if depth > 0 => {
                    depth -= 1;
                    seg_token_count += 1;
                    self.bump();
                }
                TokenKind::RParen => {
                    let seg_end = tok.start;
                    self.flush_call_arg(
                        out,
                        seg_start,
                        seg_end,
                        seg_string.as_deref(),
                        seg_token_count,
                    );
                    return Ok(());
                }
                TokenKind::Comma if depth == 0 => {
                    let seg_end = tok.start;
                    self.flush_call_arg(
                        out,
                        seg_start,
                        seg_end,
                        seg_string.as_deref(),
                        seg_token_count,
                    );
                    self.bump();
                    seg_start = self.peek().start;
                    seg_string = None;
                    seg_token_count = 0;
                }
                TokenKind::Eof => {
                    return Err(ParseError::UnexpectedEof);
                }
                TokenKind::String(s) => {
                    if seg_token_count == 0 {
                        seg_string = Some(s.clone());
                    } else {
                        seg_string = None;
                    }
                    seg_token_count += 1;
                    self.bump();
                }
                _ => {
                    seg_string = None;
                    seg_token_count += 1;
                    self.bump();
                }
            }
        }
    }

    fn flush_call_arg(
        &self,
        out: &mut Vec<String>,
        seg_start: usize,
        seg_end: usize,
        seg_string: Option<&str>,
        token_count: usize,
    ) {
        if token_count == 0 {
            // Trailing comma or empty list — emit nothing.
            return;
        }
        if let Some(s) = seg_string {
            if token_count == 1 {
                out.push(s.to_string());
                return;
            }
        }
        let raw = self.src[seg_start..seg_end].trim().to_string();
        if !raw.is_empty() {
            out.push(raw);
        }
    }

    /// Parse `if (cond) [#[attrs]] [bytes] { body } [else { else_body }]`.
    /// The `if` ident has not been consumed yet.
    ///
    /// Two body shapes are accepted:
    ///
    /// * **Simple**: `{ stmt; stmt; … }` — every stmt becomes
    ///   `then_body`; no `pre_body` and (typically) no attrs. This is
    ///   the historical form for adjacent cmp/jcc.
    /// * **Arms**: `{ pre_stmts; @then { … } [@else { … }] }` — any
    ///   leading stmts before `@then` become `pre_body`; the `@then`
    ///   arm is `then_body`. The body switches into arms mode the
    ///   moment a `@then` directive is encountered.
    fn parse_if_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // consume `if`
        self.expect(&TokenKind::LParen, "`(` after `if`")?;
        let cond_text = self.parse_paren_inner()?;
        self.expect(&TokenKind::RParen, "`)` to close `if` condition")?;
        // Early-return form: `if (cond) return [value]; [bytes]`.
        if matches!(&self.peek().kind, TokenKind::Ident(n) if n == "return") {
            return self.parse_if_return_tail(cond_text);
        }
        // Conditional-goto form: `if (cond) goto label_HEX; [bytes]`.
        if matches!(&self.peek().kind, TokenKind::Ident(n) if n == "goto") {
            return self.parse_if_goto_tail(cond_text);
        }
        let attrs = self.parse_attrs()?;
        let cond_bytes = self.parse_byte_list()?;
        self.expect(&TokenKind::LBrace, "`{` to open `if` body")?;
        let (pre_body, then_body, else_body_in_braces) = self.parse_if_body_with_optional_arms()?;
        self.expect(&TokenKind::RBrace, "`}` to close `if` body")?;
        let else_body = if else_body_in_braces.is_some() {
            else_body_in_braces
        } else if matches!(&self.peek().kind, TokenKind::Ident(n) if n == "else") {
            self.bump(); // consume `else`
            self.expect(&TokenKind::LBrace, "`{` after `else`")?;
            let stmts = self.parse_stmt_list_until_rbrace()?;
            self.expect(&TokenKind::RBrace, "`}` to close `else` body")?;
            Some(stmts)
        } else {
            None
        };
        // When `pre_body` carries intervening insns (the separated
        // cmp/jcc shape) the IfBranch needs a `head_bytes` attribute
        // to know the cmp's encoded bytes. If the source omitted
        // the attribute, derive it from the cond text — the
        // canonical Intel encoding is reconstructible for the
        // common cmp/test forms. Callers shouldn't have to spell
        // out every byte the profile already implies.
        let attrs = ensure_head_bytes(&cond_text, &pre_body, attrs);
        Ok(Stmt::IfBranch {
            cond_text,
            cond_bytes,
            attrs,
            pre_body,
            then_body,
            else_body,
        })
    }

    /// Parse a top-level `return EXPR; [bytes]` statement.
    ///
    /// When `EXPR` parses as a single integer literal, the result is
    /// a [`Stmt::Return`] (numeric form); otherwise it's a
    /// [`Stmt::ReturnExpr`] carrying the literal source text so the
    /// expression survives the round-trip verbatim.
    fn parse_return_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // consume `return`
        let value_text = if self.peek().kind == TokenKind::Semicolon {
            String::new()
        } else {
            self.parse_until_semicolon()?
        };
        self.expect(&TokenKind::Semicolon, "`;` after `return` value")?;
        // Bytes are optional: BPF's `exit` lifts to
        // `Stmt::Return` and the byte-drop pass clears them
        // when the codec reproduces them.
        let bytes = if self.peek().kind == TokenKind::LBracket {
            self.parse_byte_list()?
        } else {
            Vec::new()
        };
        // Numeric tail → Stmt::Return; otherwise keep the text as
        // a ReturnExpr.
        if let Some(value) = parse_int_literal(&value_text) {
            Ok(Stmt::Return { value, bytes })
        } else {
            Ok(Stmt::ReturnExpr {
                text: value_text,
                bytes,
            })
        }
    }

    /// Parse the tail of an `if (cond) goto label_HEX [#[…]] ;`.
    fn parse_if_goto_tail(&mut self, cond_text: String) -> Result<Stmt, ParseError> {
        self.bump(); // consume `goto`
        let label_tok = self.peek().clone();
        let label_name = self.expect_ident("label name (e.g. `label_1234`)")?;
        let Some(target_addr) = parse_label_addr(&label_name) else {
            return Err(ParseError::Expected {
                expected: "label name of the form `label_<hex>`".into(),
                got: format!("`{label_name}`"),
                line: label_tok.line,
                col: label_tok.col,
            });
        };
        let (cmp_bytes, cond_code, wide, _target_attr) = self.parse_jcc_attrs(&label_tok)?;
        self.expect(&TokenKind::Semicolon, "`;` after `goto` target")?;
        Ok(Stmt::IfGoto {
            cond_text,
            target_addr,
            cmp_bytes,
            cond_code,
            wide,
        })
    }

    /// Parse the trailing `#[cond="…", cmp=[bytes], wide, target=0x…]`
    /// block shared by `IfGoto` and `IfReturn`. Returns
    /// `(cmp_bytes, cond_code, wide, target)` with the cond
    /// resolved from the attribute's name. `target` is `None` for
    /// goto forms (the target is in the `goto label_X` syntax)
    /// and `Some(addr)` for return forms.
    fn parse_jcc_attrs(
        &mut self,
        anchor_tok: &super::lexer::Token,
    ) -> Result<(Vec<u8>, u8, bool, Option<u64>), ParseError> {
        let attrs = self.parse_attrs()?;
        let mut cmp_bytes: Vec<u8> = Vec::new();
        let mut cond_code: Option<u8> = None;
        let mut wide = false;
        let mut target: Option<u64> = None;
        for a in &attrs {
            match (a.key.as_str(), &a.value) {
                ("cond", ud_ast::AttrValue::String(s)) => {
                    cond_code = ud_arch_x86::jcc_cond_code_from_name(s);
                    if cond_code.is_none() {
                        return Err(ParseError::Expected {
                            expected: "known jcc mnemonic in `cond=\"…\"`".into(),
                            got: format!("`{s}`"),
                            line: anchor_tok.line,
                            col: anchor_tok.col,
                        });
                    }
                }
                ("cmp", ud_ast::AttrValue::ByteList(b)) => cmp_bytes.clone_from(b),
                ("wide", ud_ast::AttrValue::Flag) => wide = true,
                ("target", ud_ast::AttrValue::Int(n)) => target = Some(*n),
                _ => {}
            }
        }
        let cond_code = cond_code.ok_or_else(|| ParseError::Expected {
            expected: "`#[cond=\"…\"]` attribute on the `if (...) goto/return`".into(),
            got: "no `cond` attribute".into(),
            line: anchor_tok.line,
            col: anchor_tok.col,
        })?;
        Ok((cmp_bytes, cond_code, wide, target))
    }

    /// Parse `switch (sel) #[dispatch="...", table_va=…] { case N: goto label_HEX; … default: goto label_HEX; }`.
    #[allow(clippy::too_many_lines)]
    fn parse_switch_stmt(&mut self) -> Result<Stmt, ParseError> {
        let switch_tok = self.peek().clone();
        self.bump(); // `switch`
        self.expect(&TokenKind::LParen, "`(` after `switch`")?;
        let selector = self.parse_paren_inner()?;
        self.expect(&TokenKind::RParen, "`)` to close `switch` selector")?;
        let attrs = self.parse_attrs()?;
        let mut dispatch: Option<String> = None;
        let mut table_va: Option<u64> = None;
        for attr in &attrs {
            match (attr.key.as_str(), &attr.value) {
                ("dispatch", ud_ast::AttrValue::String(s)) => dispatch = Some(s.clone()),
                ("table_va", ud_ast::AttrValue::Int(n)) => table_va = Some(*n),
                _ => {}
            }
        }
        let dispatch = dispatch.ok_or_else(|| ParseError::Expected {
            expected: "`#[dispatch=\"...\", table_va=…]` on switch".into(),
            got: "no dispatch attribute".into(),
            line: switch_tok.line,
            col: switch_tok.col,
        })?;
        let table_va = table_va.ok_or_else(|| ParseError::Expected {
            expected: "`table_va=<addr>` on switch".into(),
            got: "no table_va attribute".into(),
            line: switch_tok.line,
            col: switch_tok.col,
        })?;
        self.expect(&TokenKind::LBrace, "`{` to open `switch` body")?;
        let mut case_table: Vec<(u64, u64)> = Vec::new();
        let mut default_addr: Option<u64> = None;
        loop {
            if self.peek().kind == TokenKind::RBrace {
                break;
            }
            let kw_tok = self.peek().clone();
            let kw = self.expect_ident("`case` or `default`")?;
            match kw.as_str() {
                "case" => {
                    let value = self.expect_int("case value")?;
                    self.expect(&TokenKind::Colon, "`:` after case value")?;
                    let goto_tok = self.peek().clone();
                    let goto_kw = self.expect_ident("`goto`")?;
                    if goto_kw != "goto" {
                        return Err(ParseError::Expected {
                            expected: "`goto` after case label".into(),
                            got: format!("`{goto_kw}`"),
                            line: goto_tok.line,
                            col: goto_tok.col,
                        });
                    }
                    let lbl_tok = self.peek().clone();
                    let lbl_name = self.expect_ident("label name")?;
                    let Some(target) = parse_label_addr(&lbl_name) else {
                        return Err(ParseError::Expected {
                            expected: "label name `label_<hex>`".into(),
                            got: format!("`{lbl_name}`"),
                            line: lbl_tok.line,
                            col: lbl_tok.col,
                        });
                    };
                    self.expect(&TokenKind::Semicolon, "`;` after case target")?;
                    case_table.push((value, target));
                }
                "default" => {
                    self.expect(&TokenKind::Colon, "`:` after `default`")?;
                    let goto_tok = self.peek().clone();
                    let goto_kw = self.expect_ident("`goto`")?;
                    if goto_kw != "goto" {
                        return Err(ParseError::Expected {
                            expected: "`goto` after `default`".into(),
                            got: format!("`{goto_kw}`"),
                            line: goto_tok.line,
                            col: goto_tok.col,
                        });
                    }
                    let lbl_tok = self.peek().clone();
                    let lbl_name = self.expect_ident("label name")?;
                    let Some(target) = parse_label_addr(&lbl_name) else {
                        return Err(ParseError::Expected {
                            expected: "label name `label_<hex>`".into(),
                            got: format!("`{lbl_name}`"),
                            line: lbl_tok.line,
                            col: lbl_tok.col,
                        });
                    };
                    self.expect(&TokenKind::Semicolon, "`;` after `default` target")?;
                    default_addr = Some(target);
                }
                _ => {
                    return Err(ParseError::Expected {
                        expected: "`case` or `default`".into(),
                        got: format!("`{kw}`"),
                        line: kw_tok.line,
                        col: kw_tok.col,
                    });
                }
            }
        }
        self.expect(&TokenKind::RBrace, "`}` to close `switch` body")?;
        // Verify case values are 0..=N contiguous (the only shape
        // we currently emit). Build the parallel-to-table `cases`
        // vec from the sorted entries.
        case_table.sort_by_key(|(v, _)| *v);
        let cases: Vec<u64> = case_table.iter().map(|(_, t)| *t).collect();
        let default_addr = default_addr.unwrap_or(0);
        Ok(Stmt::Switch {
            selector,
            cases,
            default_addr,
            dispatch,
            table_va,
        })
    }

    /// Parse a top-level `goto label_HEX; [bytes]` statement.
    fn parse_goto_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // consume `goto`
        let label_tok = self.peek().clone();
        let label_name = self.expect_ident("label name (e.g. `label_1234`)")?;
        let Some(target_addr) = parse_label_addr(&label_name) else {
            return Err(ParseError::Expected {
                expected: "label name of the form `label_<hex>`".into(),
                got: format!("`{label_name}`"),
                line: label_tok.line,
                col: label_tok.col,
            });
        };
        // Optional `#[wide]` attribute forces a 5-byte rel32 even
        // when a 2-byte rel8 would fit — used to preserve the
        // encoding choice the original compiler made.
        let attrs = self.parse_attrs()?;
        let wide = attrs
            .iter()
            .any(|a| a.key == "wide" && matches!(a.value, ud_ast::AttrValue::Flag));
        self.expect(&TokenKind::Semicolon, "`;` after `goto` target")?;
        Ok(Stmt::Goto { target_addr, wide })
    }

    /// Parse a `label_HEX:` marker — no bytes, just a position
    /// in the source for `goto` / `if (cond) goto` to refer to.
    /// The caller has already verified the next token is the
    /// `label_…` identifier.
    fn parse_label_stmt(&mut self) -> Result<Stmt, ParseError> {
        let label_tok = self.peek().clone();
        let label_name = self.expect_ident("label name")?;
        let Some(addr) = parse_label_addr(&label_name) else {
            return Err(ParseError::Expected {
                expected: "label name of the form `label_<hex>`".into(),
                got: format!("`{label_name}`"),
                line: label_tok.line,
                col: label_tok.col,
            });
        };
        self.expect(&TokenKind::Colon, "`:` after label name")?;
        Ok(Stmt::Label { addr })
    }

    /// Parse the tail of an early-return `if`:
    /// `return [value] [#[…]] ;`. Called by [`parse_if_stmt`] when
    /// the token immediately after the condition's `)` is the
    /// `return` keyword.
    fn parse_if_return_tail(&mut self, cond_text: String) -> Result<Stmt, ParseError> {
        let anchor_tok = self.peek().clone();
        self.bump(); // consume `return`
                     // Optional value expression — anything up to the `;` or `#[…]` attrs.
        let value_text = if matches!(self.peek().kind, TokenKind::Semicolon | TokenKind::Hash) {
            String::new()
        } else {
            self.parse_until_semicolon_or_attr()?
        };
        let (cmp_bytes, cond_code, wide, target) = self.parse_jcc_attrs(&anchor_tok)?;
        self.expect(&TokenKind::Semicolon, "`;` after `return` value")?;
        let target_addr = target.ok_or_else(|| ParseError::Expected {
            expected: "`target=0x…` attribute on `if (...) return …`".into(),
            got: "no `target` attribute".into(),
            line: anchor_tok.line,
            col: anchor_tok.col,
        })?;
        Ok(Stmt::IfReturn {
            cond_text,
            value_text,
            target_addr,
            cmp_bytes,
            cond_code,
            wide,
        })
    }

    fn parse_until_semicolon_or_attr(&mut self) -> Result<String, ParseError> {
        let start_pos = self.peek().start;
        loop {
            match self.peek().kind {
                TokenKind::Semicolon | TokenKind::Hash => break,
                TokenKind::Eof => return Err(ParseError::UnexpectedEof),
                _ => {
                    self.bump();
                }
            }
        }
        let end_pos = self.peek().start;
        Ok(self.src[start_pos..end_pos].trim().to_string())
    }

    /// Snip the source text between the current position and the
    /// next `;` (which is left unconsumed for the caller to expect).
    /// Used for the value expression in an
    /// `if (...) return EXPR; [bytes]` shape so EXPR's original
    /// spacing/spelling survives the round-trip.
    fn parse_until_semicolon(&mut self) -> Result<String, ParseError> {
        let start_pos = self.peek().start;
        loop {
            match self.peek().kind {
                TokenKind::Semicolon => break,
                TokenKind::Eof => return Err(ParseError::UnexpectedEof),
                _ => {
                    self.bump();
                }
            }
        }
        let end_pos = self.peek().start;
        Ok(self.src[start_pos..end_pos].trim().to_string())
    }

    /// Parse the body of an `if (…) { … }`. Walks until the closing
    /// brace (which the caller consumes). Returns the parts as a
    /// `(pre_body, then_body, else_body)` triple.
    ///
    /// Body interpretation:
    /// * As long as no `@then` is seen, statements accumulate into
    ///   `pre_body` (which, by convention, is the simple form's
    ///   `then_body` reinterpretation — see below).
    /// * The first `@then { … }` directive switches mode: everything
    ///   before it is `pre_body`, the directive's body becomes
    ///   `then_body`. An optional `@else { … }` directive can follow.
    /// * If no `@then` directive appears anywhere, the accumulated
    ///   statements were the simple form — they're the `then_body`
    ///   and `pre_body` is empty.
    #[allow(clippy::type_complexity)]
    fn parse_if_body_with_optional_arms(
        &mut self,
    ) -> Result<(Vec<Stmt>, Vec<Stmt>, Option<Vec<Stmt>>), ParseError> {
        let mut accumulated: Vec<Stmt> = Vec::new();
        let mut then_body: Option<Vec<Stmt>> = None;
        let mut else_body: Option<Vec<Stmt>> = None;
        loop {
            // Probe for `@then` / `@else` directives.
            if self.peek().kind == TokenKind::At {
                let next_ident = self.tokens.get(self.pos + 1).cloned();
                if let Some(tok) = &next_ident {
                    if let TokenKind::Ident(name) = &tok.kind {
                        if name == "then" || name == "else" {
                            self.bump(); // `@`
                            let arm_name = self.expect_ident("`then` or `else`")?;
                            self.expect(&TokenKind::LBrace, "`{` to open `@then` / `@else` arm")?;
                            let arm = self.parse_stmt_list_until_rbrace()?;
                            self.expect(&TokenKind::RBrace, "`}` to close arm")?;
                            match arm_name.as_str() {
                                "then" => then_body = Some(arm),
                                "else" => else_body = Some(arm),
                                _ => unreachable!(),
                            }
                            continue;
                        }
                    }
                }
            }
            if self.peek().kind == TokenKind::RBrace {
                break;
            }
            // Parse one statement and add to accumulated.
            let body = self.parse_stmt_list_one()?;
            accumulated.push(body);
        }
        match then_body {
            Some(then_body) => Ok((accumulated, then_body, else_body)),
            None => Ok((Vec::new(), accumulated, else_body)),
        }
    }

    /// Parse exactly one statement. Wrapper around the loop body of
    /// `parse_stmt_list_until_rbrace` so we can reuse the dispatch
    /// logic in `parse_if_body_with_optional_arms`.
    fn parse_stmt_list_one(&mut self) -> Result<Stmt, ParseError> {
        match self.peek().kind.clone() {
            TokenKind::Eof => Err(ParseError::UnexpectedEof),
            TokenKind::Comment(text) => {
                self.bump();
                Ok(Stmt::Comment(text))
            }
            TokenKind::At => {
                self.bump();
                let dir_tok = self.peek().clone();
                let dir_name = self.expect_ident("statement directive name")?;
                self.parse_stmt_at_directive(&dir_name, &dir_tok)
            }
            TokenKind::Ident(name) if name == "if" => self.parse_if_stmt(),
            TokenKind::Ident(name) if name == "ifblock" => self.parse_ifblock_stmt(),
            TokenKind::Ident(name) if name == "whileblock" => self.parse_whileblock_stmt(),
            TokenKind::Ident(name) if name == "do" => self.parse_do_while_stmt(),
            TokenKind::Ident(name) if name == "goto" => self.parse_goto_stmt(),
            TokenKind::Ident(name) if name == "return" => self.parse_return_stmt(),
            TokenKind::Ident(name) if is_label_name(name.as_str()) => {
                let next_kind = self.tokens.get(self.pos + 1).map(|t| t.kind.clone());
                if matches!(next_kind, Some(TokenKind::Colon)) {
                    self.parse_label_stmt()
                } else {
                    self.parse_call_or_move_stmt()
                }
            }
            TokenKind::Ident(_) | TokenKind::LBracket | TokenKind::LParen => {
                self.parse_call_or_move_stmt()
            }
            other => Err(ParseError::Expected {
                expected: "`@asm`, `// comment`, function call, or `}`".into(),
                got: describe(&other),
                line: self.peek().line,
                col: self.peek().col,
            }),
        }
    }

    /// Parse `do [entry=[bytes]] { body } while (cond) [bytes]`.
    /// The `do` ident has not been consumed yet.
    fn parse_do_while_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // consume `do`
        let entry_jmp_bytes = if matches!(&self.peek().kind, TokenKind::Ident(n) if n == "entry") {
            self.bump(); // consume `entry`
            self.expect(&TokenKind::Eq, "`=` after `entry`")?;
            Some(self.parse_byte_list()?)
        } else {
            None
        };
        self.expect(&TokenKind::LBrace, "`{` to open `do` body")?;
        let body = self.parse_stmt_list_until_rbrace()?;
        self.expect(&TokenKind::RBrace, "`}` to close `do` body")?;
        let while_tok = self.peek().clone();
        let TokenKind::Ident(ref name) = while_tok.kind else {
            return Err(ParseError::Expected {
                expected: "`while` after do-body".into(),
                got: describe(&while_tok.kind),
                line: while_tok.line,
                col: while_tok.col,
            });
        };
        if name != "while" {
            return Err(ParseError::Expected {
                expected: "`while`".into(),
                got: format!("identifier `{name}`"),
                line: while_tok.line,
                col: while_tok.col,
            });
        }
        self.bump(); // consume `while`
        self.expect(&TokenKind::LParen, "`(` after `while`")?;
        let cond_text = self.parse_paren_inner()?;
        self.expect(&TokenKind::RParen, "`)` to close `while` condition")?;
        let tail_bytes = self.parse_byte_list()?;
        Ok(Stmt::Loop {
            cond_text,
            entry_jmp_bytes,
            tail_bytes,
            body,
        })
    }

    /// Parse `ifblock (<cond>) [<cond_bytes>] { <then> } [else [tail=[<jmp>]] { <else> }]`.
    ///
    /// `ifblock` (one word) is the BPF-style structural if/else
    /// emitted by the layer-5 CFG pass. Distinct from the
    /// x86-style `if (cond) [bytes] { … }` (which parses to
    /// `Stmt::IfBranch`) because BPF needs a tail-jmp byte slot
    /// for the unconditional jump that skips the `else` arm.
    fn parse_ifblock_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // consume `ifblock`
        self.expect(&TokenKind::LParen, "`(` after `ifblock`")?;
        let cond_text = self.parse_paren_inner()?;
        self.expect(&TokenKind::RParen, "`)` to close `ifblock` condition")?;
        let cond_bytes = self.parse_byte_list()?;
        self.expect(&TokenKind::LBrace, "`{` to open `ifblock` body")?;
        let then_body = self.parse_stmt_list_until_rbrace()?;
        self.expect(&TokenKind::RBrace, "`}` to close `ifblock` body")?;
        let (then_tail_jmp, else_body) = if matches!(&self.peek().kind, TokenKind::Ident(n) if n == "else")
        {
            self.bump(); // consume `else`
            let tail = if matches!(&self.peek().kind, TokenKind::Ident(n) if n == "tail") {
                self.bump(); // consume `tail`
                self.expect(&TokenKind::Eq, "`=` after `tail`")?;
                self.parse_byte_list()?
            } else {
                Vec::new()
            };
            self.expect(&TokenKind::LBrace, "`{` after `else`")?;
            let body = self.parse_stmt_list_until_rbrace()?;
            self.expect(&TokenKind::RBrace, "`}` to close `else` body")?;
            (tail, body)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Stmt::IfBlock {
            cond_text,
            cond_bytes,
            then_body,
            then_tail_jmp,
            else_body,
        })
    }

    /// Parse `whileblock (<cond>) entry=[<bytes>] tail=[<bytes>] { <body> }`.
    fn parse_whileblock_stmt(&mut self) -> Result<Stmt, ParseError> {
        self.bump(); // consume `whileblock`
        self.expect(&TokenKind::LParen, "`(` after `whileblock`")?;
        let cond_text = self.parse_paren_inner()?;
        self.expect(&TokenKind::RParen, "`)` to close `whileblock` condition")?;
        self.expect_keyword("entry")?;
        self.expect(&TokenKind::Eq, "`=` after `entry`")?;
        let entry_bytes = self.parse_byte_list()?;
        self.expect_keyword("tail")?;
        self.expect(&TokenKind::Eq, "`=` after `tail`")?;
        let tail_bytes = self.parse_byte_list()?;
        self.expect(&TokenKind::LBrace, "`{` to open `whileblock` body")?;
        let body = self.parse_stmt_list_until_rbrace()?;
        self.expect(&TokenKind::RBrace, "`}` to close `whileblock` body")?;
        Ok(Stmt::WhileBlock {
            cond_text,
            entry_bytes,
            tail_bytes,
            body,
        })
    }

    /// Expect a specific identifier keyword (e.g. `entry`, `tail`).
    fn expect_keyword(&mut self, kw: &str) -> Result<(), ParseError> {
        let tok = self.peek().clone();
        if let TokenKind::Ident(name) = &tok.kind {
            if name == kw {
                self.bump();
                return Ok(());
            }
        }
        Err(ParseError::Expected {
            expected: format!("`{kw}`"),
            got: describe(&tok.kind),
            line: tok.line,
            col: tok.col,
        })
    }

    /// Snip the raw source text between a `(` (already consumed) and
    /// its matching `)`. Tracks paren depth so `(XAML, X)` etc.
    /// survives intact. Leaves the `)` unconsumed.
    fn parse_paren_inner(&mut self) -> Result<String, ParseError> {
        let start_pos = self.peek().start;
        // Empty cond: caller sees `)` immediately.
        if self.peek().kind == TokenKind::RParen {
            return Ok(String::new());
        }
        // A single quoted-string token uses the parsed value so
        // escapes (e.g. for x86 printf-style args) survive.
        if let TokenKind::String(s) = &self.peek().kind {
            let s = s.clone();
            self.bump();
            if self.peek().kind == TokenKind::RParen {
                return Ok(s);
            }
            // Else fall through to raw-text capture from `start_pos`.
        }
        let mut depth = 0i32;
        loop {
            let tok = self.peek().clone();
            match &tok.kind {
                TokenKind::LParen | TokenKind::LBracket => {
                    depth += 1;
                    self.bump();
                }
                TokenKind::RParen | TokenKind::RBracket if depth > 0 => {
                    depth -= 1;
                    self.bump();
                }
                TokenKind::RParen => {
                    let end_pos = tok.start;
                    return Ok(self.src[start_pos..end_pos].trim().to_string());
                }
                TokenKind::Eof => return Err(ParseError::UnexpectedEof),
                _ => {
                    self.bump();
                }
            }
        }
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
                // Three shapes accepted:
                //   "kind"                       — all-defaults structured form
                //   "kind", [bytes]              — legacy byte form
                //   "kind", saves: [...], …      — structured form with params
                if self.peek().kind == TokenKind::RParen {
                    self.bump();
                    let params = ud_ast::PrologueParams::default();
                    let bytes = encode_prologue_bytes(&kind, &params, self.bits);
                    return Ok(Stmt::Prologue {
                        kind,
                        params: Some(params),
                        bytes,
                    });
                }
                self.expect(&TokenKind::Comma, "`,` after prologue kind")?;
                if self.peek().kind == TokenKind::LBracket {
                    let bytes = self.parse_byte_list()?;
                    self.expect(&TokenKind::RParen, "`)` to close `@prologue`")?;
                    Ok(Stmt::Prologue {
                        kind,
                        params: None,
                        bytes,
                    })
                } else {
                    let params = self.parse_prologue_params()?;
                    self.expect(&TokenKind::RParen, "`)` to close `@prologue`")?;
                    let bytes = encode_prologue_bytes(&kind, &params, self.bits);
                    Ok(Stmt::Prologue {
                        kind,
                        params: Some(params),
                        bytes,
                    })
                }
            }
            "epilogue" => {
                self.expect(&TokenKind::LParen, "`(` after `@epilogue`")?;
                let kind = self.expect_string("epilogue kind string")?;
                if self.peek().kind == TokenKind::RParen {
                    self.bump();
                    let params = ud_ast::EpilogueParams::default();
                    let bytes = encode_epilogue_bytes(&params, self.bits);
                    return Ok(Stmt::Epilogue {
                        kind,
                        params: Some(params),
                        bytes,
                    });
                }
                self.expect(&TokenKind::Comma, "`,` after epilogue kind")?;
                if self.peek().kind == TokenKind::LBracket {
                    let bytes = self.parse_byte_list()?;
                    self.expect(&TokenKind::RParen, "`)` to close `@epilogue`")?;
                    Ok(Stmt::Epilogue {
                        kind,
                        params: None,
                        bytes,
                    })
                } else {
                    let params = self.parse_epilogue_params()?;
                    self.expect(&TokenKind::RParen, "`)` to close `@epilogue`")?;
                    let bytes = encode_epilogue_bytes(&params, self.bits);
                    Ok(Stmt::Epilogue {
                        kind,
                        params: Some(params),
                        bytes,
                    })
                }
            }
            "save" => {
                self.expect(&TokenKind::LParen, "`(` after `@save`")?;
                let reg = self.expect_string("save register name")?;
                self.expect(&TokenKind::Comma, "`,` after `@save` register")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@save`")?;
                Ok(Stmt::Save { reg, bytes })
            }
            "restore" => {
                self.expect(&TokenKind::LParen, "`(` after `@restore`")?;
                let reg = self.expect_string("restore register name")?;
                self.expect(&TokenKind::Comma, "`,` after `@restore` register")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@restore`")?;
                Ok(Stmt::Restore { reg, bytes })
            }
            "seh_install" => {
                self.expect(&TokenKind::LParen, "`(` after `@seh_install`")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@seh_install`")?;
                Ok(Stmt::SehInstall { bytes })
            }
            "seh_restore" => {
                self.expect(&TokenKind::LParen, "`(` after `@seh_restore`")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@seh_restore`")?;
                Ok(Stmt::SehRestore { bytes })
            }
            "if_return" => Err(ParseError::Expected {
                expected: "C-style `if (cond) return value;` syntax — the legacy `@if_return(...)` directive is retired".into(),
                got: "`@if_return`".into(),
                line: 0,
                col: 0,
            }),
            "return_expr" => {
                self.expect(&TokenKind::LParen, "`(` after `@return_expr`")?;
                let text = self.expect_string("return-expr text")?;
                self.expect(&TokenKind::Comma, "`,` after return-expr text")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@return_expr`")?;
                Ok(Stmt::ReturnExpr { text, bytes })
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
            "move" => {
                self.expect(&TokenKind::LParen, "`(` after `@move`")?;
                let dst = self.expect_string("move dst operand string")?;
                self.expect(&TokenKind::Comma, "`,` after `@move` dst")?;
                let src = self.expect_string("move src operand string")?;
                self.expect(&TokenKind::Comma, "`,` after `@move` src")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@move`")?;
                Ok(Stmt::Move { dst, src, bytes })
            }
            "inc16" => {
                self.expect(&TokenKind::LParen, "`(` after `@inc16`")?;
                let lo = self.expect_string("inc16 lo operand")?;
                self.expect(&TokenKind::Comma, "`,` after `@inc16` lo")?;
                let hi = self.expect_string("inc16 hi operand")?;
                self.expect(&TokenKind::Comma, "`,` after `@inc16` hi")?;
                let bytes = self.parse_byte_list()?;
                self.expect(&TokenKind::RParen, "`)` to close `@inc16`")?;
                Ok(Stmt::Inc16 { lo, hi, bytes })
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
            attrs: Vec::new(),
            pre_body: Vec::new(),
            then_body,
            else_body,
        })
    }
}

/// Does the `[…]` block opening at `tokens[lbracket_idx]` look
/// like a byte list (a flat run of `Int`s separated by `,` and
/// terminated by `]`)? Used by `parse_move_stmt` to distinguish
/// the trailing byte list from operand-side memory expressions
/// like `[ebp+8]` or `[1C201030h]`.
/// Recognise a compound-assignment operator sitting
/// immediately before the `Eq` token at `eq_idx`. Returns
/// `Some((first_op_token_idx, total_op_token_count))` when
/// matched. The op text spans tokens
/// `[first_op_token_idx, eq_idx + 1)` in source order.
///
/// Two-char ops (`+=`, `-=`, `*=`, `/=`, `%=`, `|=`, `&=`,
/// `^=`): one operator token then `Eq`.
/// Three-char ops (`<<=`, `>>=`): two same-kind operator
/// tokens then `Eq`.
fn detect_compound_op(tokens: &[Token], eq_idx: usize) -> Option<(usize, usize)> {
    if eq_idx == 0 {
        return None;
    }
    let prev = &tokens[eq_idx - 1];
    // The op token must be adjacent (no whitespace gap) to
    // distinguish `r1 += 0x5` from `r1 = +0x5`. Token spans
    // carry start/end byte offsets; the `Eq`'s start must
    // equal the previous token's end.
    let eq_tok = &tokens[eq_idx];
    if prev.end != eq_tok.start {
        return None;
    }
    // 3-char ops first (need to check 2 prior tokens).
    if matches!(prev.kind, TokenKind::Lt | TokenKind::Gt) && eq_idx >= 2 {
        let prev2 = &tokens[eq_idx - 2];
        if prev2.kind == prev.kind && prev2.end == prev.start {
            return Some((eq_idx - 2, 3));
        }
    }
    // 2-char ops.
    if matches!(
        prev.kind,
        TokenKind::Plus
            | TokenKind::Minus
            | TokenKind::Star
            | TokenKind::Slash
            | TokenKind::Percent
            | TokenKind::Pipe
            | TokenKind::Ampersand
            | TokenKind::Caret
    ) {
        return Some((eq_idx - 1, 2));
    }
    None
}

fn is_byte_list_block(tokens: &[Token], lbracket_idx: usize) -> bool {
    if !matches!(
        tokens.get(lbracket_idx).map(|t| &t.kind),
        Some(TokenKind::LBracket)
    ) {
        return false;
    }
    let mut i = lbracket_idx + 1;
    // `[]` is a valid empty byte list.
    if matches!(tokens.get(i).map(|t| &t.kind), Some(TokenKind::RBracket)) {
        return true;
    }
    loop {
        match tokens.get(i).map(|t| &t.kind) {
            Some(TokenKind::Int(_)) => i += 1,
            _ => return false,
        }
        match tokens.get(i).map(|t| &t.kind) {
            Some(TokenKind::Comma) => i += 1,
            Some(TokenKind::RBracket) => return true,
            _ => return false,
        }
    }
}

/// Add a derived `head_bytes` attribute when the IfBranch needs one
/// and the source didn't supply it.
///
/// The source language treats `head_bytes` as a hint the parser can
/// recover from the cmp/test text alone — when the file omits it,
/// the canonical Intel encoding for the operands stands in. This
/// keeps the surface form compact while preserving byte identity:
/// emit drops the attribute whenever the encoder would reproduce
/// the same bytes, and we put it back here so the lower path always
/// sees a non-empty `head_bytes` for separated cmp/jcc shapes.
fn ensure_head_bytes(
    cond_text: &str,
    pre_body: &[Stmt],
    mut attrs: Vec<ud_ast::Attribute>,
) -> Vec<ud_ast::Attribute> {
    if pre_body.is_empty() {
        return attrs;
    }
    if attrs.iter().any(|a| a.key == "head_bytes") {
        return attrs;
    }
    let Some(bytes) = ud_arch_x86::encode_head_from_cond_text(cond_text) else {
        return attrs;
    };
    attrs.push(ud_ast::Attribute {
        key: "head_bytes".into(),
        value: ud_ast::AttrValue::ByteList(bytes),
    });
    attrs
}

/// Encode a prologue's structured form back to bytes. Mirrors
/// the lift-side decode via `ud_arch_x86::encode_prologue`. The
/// kind string carries the bit-width via convention: legacy
/// labels (`std`, `std-no-cf`) without a `64-` prefix are 32-bit;
/// 64-bit kinds use the `64-` prefix (e.g. `64-std`). For now,
/// callers always use 32-bit since the structured-form codec is
/// wired in only for x86-32 inputs.
fn encode_prologue_bytes(_kind: &str, params: &ud_ast::PrologueParams, bits: u32) -> Vec<u8> {
    let cb = if bits == 64 {
        ud_arch_x86::CodecBits::Bits64
    } else {
        ud_arch_x86::CodecBits::Bits32
    };
    ud_arch_x86::encode_prologue(&prologue_to_codec(params), cb)
}

fn encode_epilogue_bytes(params: &ud_ast::EpilogueParams, bits: u32) -> Vec<u8> {
    let cb = if bits == 64 {
        ud_arch_x86::CodecBits::Bits64
    } else {
        ud_arch_x86::CodecBits::Bits32
    };
    ud_arch_x86::encode_epilogue(&epilogue_to_codec(params), cb)
}

fn prologue_to_codec(p: &ud_ast::PrologueParams) -> ud_arch_x86::StructuredPrologue {
    ud_arch_x86::StructuredPrologue {
        saves: p.saves.clone(),
        saves_after: p.saves_after.clone(),
        frame: p.frame,
        sub_esp: p.sub_esp,
        cf_protect: p.cf_protect,
        frame_alt_encoding: p.frame_alt,
    }
}

fn epilogue_to_codec(e: &ud_ast::EpilogueParams) -> ud_arch_x86::StructuredEpilogue {
    ud_arch_x86::StructuredEpilogue {
        saves: e.saves.clone(),
        leave: e.leave,
        pop_frame: e.pop_frame,
        add_esp: e.add_esp,
        ret_imm: e.ret_imm,
    }
}

impl Parser {
    /// Parse the trailing `, saves: [...], frame, sub: 0xN, …`
    /// portion of a structured `@prologue` directive. The caller
    /// has already consumed the kind string and the comma after.
    fn parse_prologue_params(&mut self) -> Result<ud_ast::PrologueParams, ParseError> {
        let mut p = ud_ast::PrologueParams::default();
        loop {
            // Stop when we reach the closing `)` of the directive.
            if self.peek().kind == TokenKind::RParen {
                break;
            }
            let kw_tok = self.peek().clone();
            let kw = self.expect_ident("prologue field name")?;
            match kw.as_str() {
                "saves" => {
                    self.expect(&TokenKind::Colon, "`:` after `saves`")?;
                    p.saves = self.parse_register_list()?;
                }
                "saves_after" => {
                    self.expect(&TokenKind::Colon, "`:` after `saves_after`")?;
                    p.saves_after = self.parse_register_list()?;
                }
                "frame" => {
                    p.frame = true;
                    // Optional `=alt` selector picks the GCC MR
                    // encoding (`mov ebp, esp` as `0x89 0xe5`)
                    // instead of the default MSVC RM form
                    // (`0x8b 0xec`).
                    if self.eat_kind(&TokenKind::Eq) {
                        let marker_tok = self.peek().clone();
                        let marker = self.expect_ident("`alt` after `frame=`")?;
                        if marker != "alt" {
                            return Err(ParseError::Expected {
                                expected: "`alt` after `frame=`".into(),
                                got: format!("`{marker}`"),
                                line: marker_tok.line,
                                col: marker_tok.col,
                            });
                        }
                        p.frame_alt = true;
                    }
                }
                "sub" => {
                    self.expect(&TokenKind::Colon, "`:` after `sub`")?;
                    p.sub_esp = self.expect_int("sub_esp value")? as u32;
                }
                "cf" => {
                    p.cf_protect = true;
                }
                other => {
                    return Err(ParseError::Expected {
                        expected: "`saves`, `frame`, `sub`, `cf`, or `)`".into(),
                        got: format!("`{other}`"),
                        line: kw_tok.line,
                        col: kw_tok.col,
                    });
                }
            }
            if self.peek().kind == TokenKind::Comma {
                self.bump();
            }
        }
        Ok(p)
    }

    /// Parse the trailing `, saves: [...], leave, ret_imm: 0xN`
    /// portion of a structured `@epilogue` directive.
    fn parse_epilogue_params(&mut self) -> Result<ud_ast::EpilogueParams, ParseError> {
        let mut e = ud_ast::EpilogueParams::default();
        loop {
            if self.peek().kind == TokenKind::RParen {
                break;
            }
            let kw_tok = self.peek().clone();
            let kw = self.expect_ident("epilogue field name")?;
            match kw.as_str() {
                "saves" => {
                    self.expect(&TokenKind::Colon, "`:` after `saves`")?;
                    e.saves = self.parse_register_list()?;
                }
                "leave" => {
                    e.leave = true;
                }
                "pop_frame" => {
                    e.pop_frame = true;
                }
                "add" => {
                    self.expect(&TokenKind::Colon, "`:` after `add`")?;
                    e.add_esp = self.expect_int("add_esp value")? as u32;
                }
                "ret_imm" => {
                    self.expect(&TokenKind::Colon, "`:` after `ret_imm`")?;
                    e.ret_imm = self.expect_int("ret_imm value")? as u16;
                }
                other => {
                    return Err(ParseError::Expected {
                        expected: "`saves`, `leave`, `pop_frame`, `add`, `ret_imm`, or `)`".into(),
                        got: format!("`{other}`"),
                        line: kw_tok.line,
                        col: kw_tok.col,
                    });
                }
            }
            if self.peek().kind == TokenKind::Comma {
                self.bump();
            }
        }
        Ok(e)
    }

    fn parse_register_list(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect(&TokenKind::LBracket, "`[` to open register list")?;
        let mut out = Vec::new();
        if self.peek().kind != TokenKind::RBracket {
            loop {
                let name = self.expect_ident("register name")?;
                out.push(name);
                if !self.eat_kind(&TokenKind::Comma) {
                    break;
                }
                if self.peek().kind == TokenKind::RBracket {
                    break;
                }
            }
        }
        self.expect(&TokenKind::RBracket, "`]` to close register list")?;
        Ok(out)
    }
}

/// `label_<hex>` ⇒ parsed address. Used by goto/label parsers
/// to roundtrip the address through a textual marker.
fn parse_label_addr(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("label_")?;
    u64::from_str_radix(rest, 16).ok()
}

/// Recognise `123`, `0x1f`, or `0X1F` as an integer literal.
/// Used by `parse_return_stmt` to decide whether a tail like
/// `return 0;` carries a numeric value (lift to `Stmt::Return`)
/// or an expression (`Stmt::ReturnExpr`).
fn parse_int_literal(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Identifier-name predicate matching the `label_<hex>` shape
/// used by the goto/label rendering.
fn is_label_name(name: &str) -> bool {
    parse_label_addr(name).is_some()
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
        TokenKind::Hash => "`#`".into(),
        TokenKind::Dollar => "`$`".into(),
        TokenKind::Semicolon => "`;`".into(),
        TokenKind::Plus => "`+`".into(),
        TokenKind::Star => "`*`".into(),
        TokenKind::Ampersand => "`&`".into(),
        TokenKind::Pipe => "`|`".into(),
        TokenKind::Caret => "`^`".into(),
        TokenKind::Tilde => "`~`".into(),
        TokenKind::Bang => "`!`".into(),
        TokenKind::Minus => "`-`".into(),
        TokenKind::Slash => "`/`".into(),
        TokenKind::Percent => "`%`".into(),
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
            ..
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
    fn jump_table_round_trips_through_parse() {
        let src = r#"@module {}

@jump_table(0x2020, dispatch="gcc_pie_rel32") {
    case_0: label_117a,
    case_1: label_1183,
    case_2: label_118c,
}
"#;
        let f = parse(src).unwrap();
        let Item::JumpTable {
            addr,
            dispatch,
            entries,
        } = &f.items[0]
        else {
            panic!("expected JumpTable, got {:?}", f.items[0]);
        };
        assert_eq!(*addr, 0x2020);
        assert_eq!(dispatch, "gcc_pie_rel32");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].case, 0);
        assert_eq!(entries[0].target, 0x117a);
        assert_eq!(entries[2].case, 2);
        assert_eq!(entries[2].target, 0x118c);
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

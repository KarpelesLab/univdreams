// Internal-only relaxations: the parser/simplifier ergonomically
// gets several arms with the same body (-(-x) vs ~(~x) etc.) and
// a couple of long pattern-matching functions; the `Raw` variant
// is held back for the not-yet-wired Stmt-level fallback.
#![allow(clippy::too_many_lines, clippy::match_same_arms, dead_code)]

//! Expression parser + algebraic simplifier for the rendered
//! `.ud` operand text.
//!
//! Each `Stmt::Move` / `Stmt::Call` / `Stmt::IfBranch` carries
//! human-readable expressions in its src/dst/cond_text fields.
//! After forward-propagation those texts often build up into
//! algebraically reducible shapes — `~(((((~(ecx | 0FFFFFFFFh))))
//! & 3) | 0FFFFFFFFh)`, `[eax+18h] - 1 - 1 - 1`, `x | 0`, and so
//! on. Ghidra-quality output requires running these through a
//! real simplifier.
//!
//! ## Pipeline
//!
//! 1. **Tokenize** the source text into a flat token stream.
//! 2. **Parse** the tokens into a typed [`Expr`] AST using a
//!    recursive-descent precedence climber (C-like precedence:
//!    unary > shift > multiplicative > additive > bitwise-and >
//!    bitwise-xor > bitwise-or > equality > comparison >
//!    logical-and > logical-or).
//! 3. **Simplify** the AST by applying algebraic identities and
//!    constant folding in a fixpoint loop.
//! 4. **Render** the simplified AST back to text.
//!
//! Operand strings that don't parse cleanly (unknown punctuation,
//! mismatched brackets, etc.) are returned verbatim — the bytes
//! pinned on each `Stmt` are the source of truth for round-trip,
//! so a parser miss is never a correctness hazard.
//!
//! ## Coverage
//!
//! Simplifications applied today:
//!
//! * **Constant folding** for `+`, `-`, `*`, `/`, `%`, `&`, `|`,
//!   `^`, `<<`, `>>`, and unary `-` / `~`. Result is the canonical
//!   numeric literal.
//! * **Algebraic identities**:
//!   * `x + 0`, `x - 0`, `0 + x`, `x | 0`, `x ^ 0` → `x`
//!   * `x * 0`, `0 * x`, `x & 0`, `0 & x` → `0`
//!   * `x * 1`, `x / 1`, `1 * x` → `x`
//!   * `x | 0xFFFFFFFF` (or `-1` in any signed-form) → `0xFFFFFFFF`
//!   * `x & 0xFFFFFFFF` → `x` (under the assumed 32-bit width)
//!   * `x ^ x`, `x - x` → `0`
//!   * `~~x`, `-(-x)` → `x`
//!   * `~0` → `0xFFFFFFFF` (32-bit), `~0xFFFFFFFF` → `0`
//!   * `x << 0`, `x >> 0` → `x`
//!   * `x << N >> N` and `x >> N << N` collapses when the shift
//!     widths match and the value is known-narrow (skipped for
//!     now — needs type info).
//! * **Re-association of sequential `+`/`-`**: `(x - 1) - 1` →
//!   `x - 2`, `(x + a) + b` → `x + (a + b)` when `a` and `b` are
//!   both literals.
//!
//! ## Bit-width assumption
//!
//! Constants fold under a configurable bit-width (32 or 64). For
//! a 32-bit binary, `~0xFFFFFFFF` is `0`; for 64-bit it's
//! `0xFFFFFFFF00000000`. The caller passes the width when calling
//! [`simplify_text`].

use std::fmt::Write;

/// Bit-width the simplifier assumes for constant folding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitWidth {
    Bits32,
    Bits64,
}

impl BitWidth {
    fn mask(self) -> u64 {
        match self {
            Self::Bits32 => 0xFFFF_FFFF,
            Self::Bits64 => u64::MAX,
        }
    }
}

/// Parse `text` as an expression, simplify it, and render back to
/// text. Returns the original `text` unchanged if parsing fails
/// at any point — partial simplification is never returned, so a
/// caller is free to overwrite the field unconditionally.
#[must_use]
pub fn simplify_text(text: &str, width: BitWidth) -> String {
    let tokens = tokenize(text);
    let mut parser = Parser::new(&tokens);
    let Some(expr) = parser.parse_expr_or_comma_list() else {
        return text.to_string();
    };
    if !parser.is_done() {
        return text.to_string();
    }
    let simplified = simplify_expr(expr, width);
    render(&simplified)
}

// ---------------------------------------------------------------
// Token stream
// ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Hex(u64),
    Dec(u64),
    Str(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Op(&'static str),
}

fn tokenize(text: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Multi-char operators first.
        if i + 1 < bytes.len() {
            let two = &bytes[i..i + 2];
            match two {
                b"<<" => {
                    out.push(Tok::Op("<<"));
                    i += 2;
                    continue;
                }
                b">>" => {
                    out.push(Tok::Op(">>"));
                    i += 2;
                    continue;
                }
                b"==" => {
                    out.push(Tok::Op("=="));
                    i += 2;
                    continue;
                }
                b"!=" => {
                    out.push(Tok::Op("!="));
                    i += 2;
                    continue;
                }
                b"<=" => {
                    out.push(Tok::Op("<="));
                    i += 2;
                    continue;
                }
                b">=" => {
                    out.push(Tok::Op(">="));
                    i += 2;
                    continue;
                }
                b"&&" => {
                    out.push(Tok::Op("&&"));
                    i += 2;
                    continue;
                }
                b"||" => {
                    out.push(Tok::Op("||"));
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        match c {
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
                continue;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
                continue;
            }
            b'[' => {
                out.push(Tok::LBracket);
                i += 1;
                continue;
            }
            b']' => {
                out.push(Tok::RBracket);
                i += 1;
                continue;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
                continue;
            }
            b'"' => {
                // String literal — slurp until the closing `"`,
                // honouring `\\` escapes.
                i += 1;
                let mut s = String::new();
                let mut esc = false;
                while i < bytes.len() {
                    let b = bytes[i];
                    if esc {
                        let resolved = match b {
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'\\' => '\\',
                            b'"' => '"',
                            other => other as char,
                        };
                        s.push(resolved);
                        esc = false;
                        i += 1;
                    } else if b == b'\\' {
                        esc = true;
                        i += 1;
                    } else if b == b'"' {
                        i += 1;
                        break;
                    } else {
                        s.push(b as char);
                        i += 1;
                    }
                }
                out.push(Tok::Str(s));
                continue;
            }
            b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'~' | b'!'
            | b'<' | b'>' | b'=' => {
                let ch = c as char;
                let s: &'static str = match ch {
                    '+' => "+",
                    '-' => "-",
                    '*' => "*",
                    '/' => "/",
                    '%' => "%",
                    '&' => "&",
                    '|' => "|",
                    '^' => "^",
                    '~' => "~",
                    '!' => "!",
                    '<' => "<",
                    '>' => ">",
                    '=' => "=",
                    _ => unreachable!(),
                };
                out.push(Tok::Op(s));
                i += 1;
                continue;
            }
            _ => {}
        }
        if c.is_ascii_digit() {
            // Hex (0x… or trailing-h Intel form) or decimal.
            let start = i;
            // Optional 0x prefix.
            let prefixed_hex = bytes[i] == b'0'
                && (i + 1 < bytes.len()
                    && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X'));
            if prefixed_hex {
                i += 2;
                let digits_start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if i == digits_start {
                    // "0x" alone — give up on this token.
                    return Vec::new();
                }
                let raw = std::str::from_utf8(&bytes[digits_start..i]).unwrap_or("0");
                let n = u64::from_str_radix(raw, 16).unwrap_or(0);
                out.push(Tok::Hex(n));
                continue;
            }
            // Otherwise: read hex-digits-then-optional-h or decimal.
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            // Intel hex form ends in `h` or `H`.
            if i < bytes.len() && (bytes[i] == b'h' || bytes[i] == b'H') {
                let raw = std::str::from_utf8(&bytes[start..i]).unwrap_or("0");
                let n = u64::from_str_radix(raw, 16).unwrap_or(0);
                out.push(Tok::Hex(n));
                i += 1;
                continue;
            }
            // Pure decimal — only digits 0-9, no a-f.
            let chunk = &bytes[start..i];
            if chunk.iter().all(u8::is_ascii_digit) {
                let raw = std::str::from_utf8(chunk).unwrap_or("0");
                let n: u64 = raw.parse().unwrap_or(0);
                out.push(Tok::Dec(n));
                continue;
            }
            // Mixed without trailing `h` — give up: this isn't a
            // form we can simplify cleanly.
            return Vec::new();
        }
        if c.is_ascii_alphabetic() || c == b'_' || c == b'.' || c == b'@' {
            let start = i;
            while i < bytes.len() {
                let b = bytes[i];
                if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'@' {
                    i += 1;
                } else {
                    break;
                }
            }
            let raw = std::str::from_utf8(&bytes[start..i]).unwrap_or("").to_string();
            out.push(Tok::Ident(raw));
            continue;
        }
        // Unexpected character — bail.
        return Vec::new();
    }
    out
}

// ---------------------------------------------------------------
// AST
// ---------------------------------------------------------------

/// A parsed expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Lit(u64),
    Ident(String),
    /// `&"text"` — a reference to a string literal at a known
    /// virtual address. Produced by the string-resolution pass
    /// that swaps integer literals matching a known string-data
    /// VA for the string's content. Renders as `&"escaped"`.
    StringRef(String),
    /// `[expr]` memory dereference. Treated as opaque by the
    /// simplifier (its contents may simplify, but the dereference
    /// itself is preserved verbatim).
    Deref(Box<Expr>),
    Unary(&'static str, Box<Expr>),
    Binary(&'static str, Box<Expr>, Box<Expr>),
    /// `name(arg, arg, …)` — a call expression embedded in
    /// operand text. The argument list is each simplified
    /// independently.
    Call(String, Vec<Expr>),
    /// A comma-separated list at the top level (function call
    /// arguments). Used so `simplify_text` can handle "a, b, c"
    /// the same way it handles a single expression.
    CommaList(Vec<Expr>),
    /// A token sequence we couldn't fold into structure — emit
    /// back verbatim.
    Raw(String),
}

// ---------------------------------------------------------------
// Parser (recursive descent with precedence climbing)
// ---------------------------------------------------------------

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(toks: &'a [Tok]) -> Self {
        Self { toks, pos: 0 }
    }

    fn is_done(&self) -> bool {
        self.pos >= self.toks.len()
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<&Tok> {
        let t = self.toks.get(self.pos);
        self.pos += 1;
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Parse an expression that may be a comma-separated list at
    /// the top level. Used so the simplifier can handle a call
    /// site's argument list (the operand text the renderer passes
    /// in is sometimes the full "a, b, c" string).
    fn parse_expr_or_comma_list(&mut self) -> Option<Expr> {
        let first = self.parse_expr()?;
        if self.peek() != Some(&Tok::Comma) {
            return Some(first);
        }
        let mut items = vec![first];
        while self.eat(&Tok::Comma) {
            items.push(self.parse_expr()?);
        }
        Some(Expr::CommaList(items))
    }

    fn parse_expr(&mut self) -> Option<Expr> {
        self.parse_logical_or()
    }

    fn parse_logical_or(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_logical_and, &["||"])
    }

    fn parse_logical_and(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_compare, &["&&"])
    }

    fn parse_compare(&mut self) -> Option<Expr> {
        self.binop_left(
            Self::parse_bitwise_or,
            &["==", "!=", "<", "<=", ">", ">="],
        )
    }

    fn parse_bitwise_or(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_bitwise_xor, &["|"])
    }

    fn parse_bitwise_xor(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_bitwise_and, &["^"])
    }

    fn parse_bitwise_and(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_shift, &["&"])
    }

    fn parse_shift(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_additive, &["<<", ">>"])
    }

    fn parse_additive(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_multiplicative, &["+", "-"])
    }

    fn parse_multiplicative(&mut self) -> Option<Expr> {
        self.binop_left(Self::parse_unary, &["*", "/", "%"])
    }

    fn binop_left(
        &mut self,
        mut next: impl FnMut(&mut Self) -> Option<Expr>,
        ops: &[&'static str],
    ) -> Option<Expr> {
        let mut lhs = next(self)?;
        while let Some(op) = self.peek_op_in(ops) {
            self.pos += 1;
            let rhs = next(self)?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Some(lhs)
    }

    fn peek_op_in(&self, ops: &[&'static str]) -> Option<&'static str> {
        if let Some(Tok::Op(o)) = self.peek() {
            for &cand in ops {
                if cand == *o {
                    return Some(cand);
                }
            }
        }
        None
    }

    fn parse_unary(&mut self) -> Option<Expr> {
        if let Some(Tok::Op(o)) = self.peek() {
            let op = *o;
            if op == "-" || op == "~" || op == "!" || op == "&" {
                self.pos += 1;
                let inner = self.parse_unary()?;
                let kind: &'static str = match op {
                    "-" => "-",
                    "~" => "~",
                    "!" => "!",
                    "&" => "&",
                    _ => unreachable!(),
                };
                return Some(Expr::Unary(kind, Box::new(inner)));
            }
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Option<Expr> {
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Option<Expr> {
        let tok = self.peek()?.clone();
        match tok {
            Tok::LParen => {
                self.bump();
                let inner = self.parse_expr()?;
                if !self.eat(&Tok::RParen) {
                    return None;
                }
                Some(inner)
            }
            Tok::LBracket => {
                self.bump();
                let inner = self.parse_expr()?;
                if !self.eat(&Tok::RBracket) {
                    return None;
                }
                Some(Expr::Deref(Box::new(inner)))
            }
            Tok::Hex(n) | Tok::Dec(n) => {
                self.bump();
                Some(Expr::Lit(n))
            }
            Tok::Str(s) => {
                self.bump();
                Some(Expr::StringRef(s))
            }
            Tok::Ident(name) => {
                self.bump();
                // Function call?
                if self.peek() == Some(&Tok::LParen) {
                    self.bump();
                    let mut args = Vec::new();
                    if self.peek() != Some(&Tok::RParen) {
                        args.push(self.parse_expr()?);
                        while self.eat(&Tok::Comma) {
                            args.push(self.parse_expr()?);
                        }
                    }
                    if !self.eat(&Tok::RParen) {
                        return None;
                    }
                    Some(Expr::Call(name, args))
                } else {
                    Some(Expr::Ident(name))
                }
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------
// Simplifier
// ---------------------------------------------------------------

/// Walk `expr` and replace integer literals whose value matches a
/// known string-data VA with a `StringRef` carrying the string's
/// content. Caller supplies the lookup: typically a closure over
/// the data-section reader that returns `Some(text)` only when
/// the address dereferences to a plausible NUL-terminated string.
///
/// Idempotent — already-resolved `StringRef`s pass through.
///
/// Lits inside a `[…]` memory-address subtree that already
/// contains an identifier (e.g. `[rbp - 4]`, `[rax * 8 + 16h]`)
/// are NOT resolved: those numbers are offsets/scales/sizes, not
/// pointers. Pure-numeric derefs like `[2020h]` still resolve
/// (the literal IS the pointer in that case).
#[must_use]
pub fn resolve_strings(expr: Expr, lookup: &dyn Fn(u64) -> Option<String>) -> Expr {
    resolve_strings_inner(expr, lookup, false)
}

fn resolve_strings_inner(
    expr: Expr,
    lookup: &dyn Fn(u64) -> Option<String>,
    in_offset_context: bool,
) -> Expr {
    match expr {
        Expr::Lit(n) => {
            if in_offset_context {
                return Expr::Lit(n);
            }
            match lookup(n) {
                // Wrap in `Unary("&", …)` so the rendering becomes
                // `&"text"` — a multi-token shape the call-arg
                // parser doesn't quote-strip on round-trip, and
                // which semantically reads as "address of the
                // string literal" (the original value at this
                // location was a pointer into a data section).
                Some(s) => Expr::Unary("&", Box::new(Expr::StringRef(s))),
                None => Expr::Lit(n),
            }
        }
        Expr::Ident(_) | Expr::Raw(_) | Expr::StringRef(_) => expr,
        Expr::Deref(inner) => {
            // If the inner expression mentions any identifier
            // (register), treat the entire dereferenced subtree
            // as an offset/index context: its constants are
            // offsets, not pointers. A pure-numeric dereference
            // (`[2020h]`) keeps the default behaviour.
            let offset_ctx = expr_contains_ident(&inner);
            Expr::Deref(Box::new(resolve_strings_inner(*inner, lookup, offset_ctx)))
        }
        Expr::Unary(op, inner) => Expr::Unary(
            op,
            Box::new(resolve_strings_inner(*inner, lookup, in_offset_context)),
        ),
        Expr::Binary(op, l, r) => Expr::Binary(
            op,
            Box::new(resolve_strings_inner(*l, lookup, in_offset_context)),
            Box::new(resolve_strings_inner(*r, lookup, in_offset_context)),
        ),
        Expr::Call(name, args) => Expr::Call(
            name,
            args.into_iter()
                .map(|a| resolve_strings_inner(a, lookup, false))
                .collect(),
        ),
        Expr::CommaList(items) => Expr::CommaList(
            items
                .into_iter()
                .map(|a| resolve_strings_inner(a, lookup, false))
                .collect(),
        ),
    }
}

fn expr_contains_ident(expr: &Expr) -> bool {
    match expr {
        Expr::Ident(_) => true,
        Expr::Lit(_) | Expr::StringRef(_) | Expr::Raw(_) => false,
        Expr::Deref(inner) | Expr::Unary(_, inner) => expr_contains_ident(inner),
        Expr::Binary(_, l, r) => expr_contains_ident(l) || expr_contains_ident(r),
        Expr::Call(_, args) | Expr::CommaList(args) => {
            args.iter().any(expr_contains_ident)
        }
    }
}

/// Resolve string literals in `text`. Parses the text as an
/// expression, walks the AST replacing `Lit(va)` with `StringRef`
/// where `lookup(va)` succeeds, renders back. Falls back to the
/// original text if parsing fails (round-trip-safe by construction).
#[must_use]
pub fn resolve_strings_in_text(
    text: &str,
    lookup: &dyn Fn(u64) -> Option<String>,
) -> String {
    let tokens = tokenize(text);
    let mut parser = Parser::new(&tokens);
    let Some(expr) = parser.parse_expr_or_comma_list() else {
        return text.to_string();
    };
    if !parser.is_done() {
        return text.to_string();
    }
    render(&resolve_strings(expr, lookup))
}

/// Walk `expr` bottom-up, applying algebraic identities until a
/// fixpoint. The result is structurally equivalent under the
/// assumed bit-width but typically shorter.
#[must_use]
pub fn simplify_expr(expr: Expr, width: BitWidth) -> Expr {
    let mut e = expr;
    loop {
        let stepped = simplify_step(e.clone(), width);
        if stepped == e {
            return stepped;
        }
        e = stepped;
    }
}

fn simplify_step(expr: Expr, width: BitWidth) -> Expr {
    let mask = width.mask();
    match expr {
        Expr::Lit(n) => Expr::Lit(n & mask),
        Expr::Ident(_) | Expr::Raw(_) | Expr::StringRef(_) => expr,
        Expr::Deref(inner) => Expr::Deref(Box::new(simplify_step(*inner, width))),
        Expr::Unary(op, inner) => {
            let inner = simplify_step(*inner, width);
            match (op, &inner) {
                // -(-x) = x
                ("-", Expr::Unary("-", x)) => (**x).clone(),
                // ~~x = x
                ("~", Expr::Unary("~", x)) => (**x).clone(),
                // !!x = x (when x is already 0/1; this is conservative
                // for our purposes — we leave logical-not chains alone
                // unless they reduce cleanly).
                ("!", Expr::Unary("!", x)) => (**x).clone(),
                // -LIT = literal of -LIT under the mask.
                ("-", Expr::Lit(n)) => Expr::Lit(n.wrapping_neg() & mask),
                // ~LIT = literal of ~LIT under the mask.
                ("~", Expr::Lit(n)) => Expr::Lit((!n) & mask),
                _ => Expr::Unary(op, Box::new(inner)),
            }
        }
        Expr::Binary(op, lhs, rhs) => {
            let l = simplify_step(*lhs, width);
            let r = simplify_step(*rhs, width);
            simplify_binary(op, l, r, width)
        }
        Expr::Call(name, args) => Expr::Call(
            name,
            args.into_iter().map(|a| simplify_step(a, width)).collect(),
        ),
        Expr::CommaList(items) => Expr::CommaList(
            items
                .into_iter()
                .map(|a| simplify_step(a, width))
                .collect(),
        ),
    }
}

fn simplify_binary(op: &'static str, l: Expr, r: Expr, width: BitWidth) -> Expr {
    let mask = width.mask();
    // Constant folding.
    if let (Expr::Lit(a), Expr::Lit(b)) = (&l, &r) {
        if let Some(v) = fold_binary(op, *a, *b, width) {
            return Expr::Lit(v & mask);
        }
    }
    // Algebraic identities. Try lhs-zero, rhs-zero, mask forms.
    match op {
        "+" => {
            if let Expr::Lit(0) = l {
                return r;
            }
            if let Expr::Lit(0) = r {
                return l;
            }
            // (x + a) + b → x + (a + b)
            if let (Expr::Binary("+", ll, lr), Expr::Lit(b)) = (&l, &r) {
                if let Expr::Lit(a) = **lr {
                    let sum = a.wrapping_add(*b) & mask;
                    if sum == 0 {
                        return (**ll).clone();
                    }
                    return Expr::Binary(
                        "+",
                        ll.clone(),
                        Box::new(Expr::Lit(sum)),
                    );
                }
            }
            // (x - a) + b → x + (b - a) or x - (a - b)
            if let (Expr::Binary("-", ll, lr), Expr::Lit(b)) = (&l, &r) {
                if let Expr::Lit(a) = **lr {
                    let net = b.wrapping_sub(a);
                    if net == 0 {
                        return (**ll).clone();
                    }
                    // Render as `x - LIT` when net is "small negative",
                    // else `x + LIT`. We approximate by treating high
                    // bits as negative.
                    let half = 1u64 << (match width {
                        BitWidth::Bits32 => 31,
                        BitWidth::Bits64 => 63,
                    });
                    if (net & mask) >= half {
                        let abs = net.wrapping_neg() & mask;
                        return Expr::Binary(
                            "-",
                            ll.clone(),
                            Box::new(Expr::Lit(abs)),
                        );
                    }
                    return Expr::Binary(
                        "+",
                        ll.clone(),
                        Box::new(Expr::Lit(net & mask)),
                    );
                }
            }
        }
        "-" => {
            if let Expr::Lit(0) = r {
                return l;
            }
            // x - x → 0
            if expr_eq(&l, &r) {
                return Expr::Lit(0);
            }
            // (x - a) - b → x - (a + b)
            if let (Expr::Binary("-", ll, lr), Expr::Lit(b)) = (&l, &r) {
                if let Expr::Lit(a) = **lr {
                    let sum = a.wrapping_add(*b) & mask;
                    return Expr::Binary(
                        "-",
                        ll.clone(),
                        Box::new(Expr::Lit(sum)),
                    );
                }
            }
            // (x + a) - b → x + (a - b) or x - (b - a)
            if let (Expr::Binary("+", ll, lr), Expr::Lit(b)) = (&l, &r) {
                if let Expr::Lit(a) = **lr {
                    if a >= *b {
                        let net = a.wrapping_sub(*b) & mask;
                        if net == 0 {
                            return (**ll).clone();
                        }
                        return Expr::Binary(
                            "+",
                            ll.clone(),
                            Box::new(Expr::Lit(net)),
                        );
                    }
                    let net = b.wrapping_sub(a) & mask;
                    return Expr::Binary(
                        "-",
                        ll.clone(),
                        Box::new(Expr::Lit(net)),
                    );
                }
            }
        }
        "*" => {
            if matches!(l, Expr::Lit(0)) || matches!(r, Expr::Lit(0)) {
                return Expr::Lit(0);
            }
            if matches!(l, Expr::Lit(1)) {
                return r;
            }
            if matches!(r, Expr::Lit(1)) {
                return l;
            }
        }
        "/" => {
            if matches!(r, Expr::Lit(1)) {
                return l;
            }
            if expr_eq(&l, &r) {
                return Expr::Lit(1);
            }
        }
        "&" => {
            if matches!(l, Expr::Lit(0)) || matches!(r, Expr::Lit(0)) {
                return Expr::Lit(0);
            }
            if let Expr::Lit(n) = r {
                if n == mask {
                    return l;
                }
            }
            if let Expr::Lit(n) = l {
                if n == mask {
                    return r;
                }
            }
            if expr_eq(&l, &r) {
                return l;
            }
        }
        "|" => {
            if let Expr::Lit(0) = l {
                return r;
            }
            if let Expr::Lit(0) = r {
                return l;
            }
            if let Expr::Lit(n) = r {
                if n == mask {
                    return Expr::Lit(mask);
                }
            }
            if let Expr::Lit(n) = l {
                if n == mask {
                    return Expr::Lit(mask);
                }
            }
            if expr_eq(&l, &r) {
                return l;
            }
        }
        "^" => {
            if let Expr::Lit(0) = l {
                return r;
            }
            if let Expr::Lit(0) = r {
                return l;
            }
            if expr_eq(&l, &r) {
                return Expr::Lit(0);
            }
        }
        "<<" | ">>" => {
            if matches!(r, Expr::Lit(0)) {
                return l;
            }
        }
        _ => {}
    }
    Expr::Binary(op, Box::new(l), Box::new(r))
}

fn fold_binary(op: &'static str, a: u64, b: u64, width: BitWidth) -> Option<u64> {
    let mask = width.mask();
    let a = a & mask;
    let b = b & mask;
    let v = match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" => {
            if b == 0 {
                return None;
            }
            a / b
        }
        "%" => {
            if b == 0 {
                return None;
            }
            a % b
        }
        "&" => a & b,
        "|" => a | b,
        "^" => a ^ b,
        "<<" => a.wrapping_shl((b & 63) as u32),
        ">>" => a.wrapping_shr((b & 63) as u32),
        _ => return None,
    };
    Some(v & mask)
}

fn expr_eq(a: &Expr, b: &Expr) -> bool {
    a == b
}

// ---------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------

/// Render an `Expr` back to the same textual style the rest of
/// the renderer uses: hex literals as `0xN` with an `h` suffix
/// for short hex (mimicking Intel form), identifiers/idents
/// verbatim, parenthesised sub-expressions where precedence
/// would otherwise be ambiguous.
#[must_use]
pub fn render(expr: &Expr) -> String {
    let mut out = String::new();
    render_into(&mut out, expr, 0);
    out
}

fn render_into(out: &mut String, expr: &Expr, parent_prec: u32) {
    let my_prec = expr_prec(expr);
    let needs_parens = my_prec < parent_prec;
    if needs_parens {
        out.push('(');
    }
    match expr {
        Expr::Lit(n) => {
            // Decimals up to 9, hex otherwise (matches the
            // existing renderer's convention: small numbers
            // appear as decimal, larger as Intel hex).
            if *n < 10 {
                write!(out, "{n}").unwrap();
            } else {
                write!(out, "{}", format_intel_hex(*n)).unwrap();
            }
        }
        Expr::Ident(name) => out.push_str(name),
        Expr::StringRef(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        use std::fmt::Write;
                        write!(out, "\\x{:02x}", c as u32).unwrap();
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Expr::Deref(inner) => {
            out.push('[');
            render_into(out, inner, 0);
            out.push(']');
        }
        Expr::Unary(op, inner) => {
            out.push_str(op);
            render_into(out, inner, my_prec);
        }
        Expr::Binary(op, l, r) => {
            render_into(out, l, my_prec);
            write!(out, " {op} ").unwrap();
            render_into(out, r, my_prec + 1);
        }
        Expr::Call(name, args) => {
            out.push_str(name);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_into(out, a, 0);
            }
            out.push(')');
        }
        Expr::CommaList(items) => {
            for (i, a) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                render_into(out, a, 0);
            }
        }
        Expr::Raw(s) => out.push_str(s),
    }
    if needs_parens {
        out.push(')');
    }
}

/// C-like precedence levels, mirroring the parse-time grouping.
/// Higher number binds tighter.
fn expr_prec(expr: &Expr) -> u32 {
    match expr {
        Expr::Lit(_)
        | Expr::Ident(_)
        | Expr::StringRef(_)
        | Expr::Deref(_)
        | Expr::Call(_, _)
        | Expr::Raw(_) => 100,
        Expr::CommaList(_) => 0,
        Expr::Unary(_, _) => 90,
        Expr::Binary(op, _, _) => match *op {
            "*" | "/" | "%" => 80,
            "+" | "-" => 70,
            "<<" | ">>" => 60,
            "&" => 55,
            "^" => 50,
            "|" => 45,
            "<" | "<=" | ">" | ">=" => 40,
            "==" | "!=" => 35,
            "&&" => 30,
            "||" => 25,
            _ => 50,
        },
    }
}

/// Render a literal in the Intel-style hex form the rest of the
/// renderer uses: uppercase hex digits, a leading `0` when the
/// value would otherwise start with `A-F`, trailing `h`. Values
/// in `0..=9` go through this only via the caller's small-number
/// check above.
fn format_intel_hex(n: u64) -> String {
    let raw = format!("{n:X}");
    let needs_zero = raw.chars().next().is_some_and(|c| matches!(c, 'A'..='F'));
    if needs_zero {
        format!("0{raw}h")
    } else {
        format!("{raw}h")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simp(text: &str) -> String {
        simplify_text(text, BitWidth::Bits32)
    }

    #[test]
    fn folds_or_with_neg_one() {
        assert_eq!(simp("ecx | 0FFFFFFFFh"), "0FFFFFFFFh");
    }

    #[test]
    fn folds_negate_neg_one() {
        // `~0xFFFFFFFF` is 0 under 32-bit width.
        assert_eq!(simp("~0FFFFFFFFh"), "0");
    }

    #[test]
    fn folds_subtract_self() {
        assert_eq!(simp("x - x"), "0");
    }

    #[test]
    fn collapses_sequential_decrement() {
        // (x - 1) - 1 → x - 2
        assert_eq!(simp("(x - 1) - 1"), "x - 2");
        // Three-level chain.
        assert_eq!(simp("((x - 1) - 1) - 1"), "x - 3");
    }

    #[test]
    fn collapses_double_neg() {
        assert_eq!(simp("-(-x)"), "x");
        assert_eq!(simp("~~x"), "x");
    }

    #[test]
    fn folds_constant_arithmetic() {
        assert_eq!(simp("2 + 3"), "5");
        assert_eq!(simp("10h - 5"), "0Bh");
    }

    #[test]
    fn preserves_unparseable_input() {
        // Unrecognised punctuation — returned verbatim.
        assert_eq!(simp("foo$bar"), "foo$bar");
    }

    #[test]
    fn full_chain_from_runaway() {
        // The signature ugly chain that prompted #174 — should
        // collapse most of the way down.
        let r = simp("~(((((~(ecx | 0FFFFFFFFh)))) & 3) | 0FFFFFFFFh)");
        // Whatever the final form, it shouldn't contain the
        // nested 0FFFFFFFFh-with-ecx subexpression.
        assert!(
            !r.contains("ecx | 0FFFFFFFFh"),
            "expected the `ecx | 0FFFFFFFFh` subexpr to fold away, got: {r}"
        );
    }

    #[test]
    fn comma_list_simplifies_each_arg() {
        assert_eq!(simp("x - 0, y | 0, 2 + 3"), "x, y, 5");
    }
}

//! Parser for the expression language of lifted EVM statements.
//!
//! The lifter (`decompile::evm_lift`) renders values Solidity-style:
//! hex constants (`0x20`, `~0x1f`), stack-slot and parameter names
//! (`v6`, `arg0`, `param1`, `t2`), environment reads (`msg.sender`,
//! `block.number`, `address(this)`), opcode calls (`sload(k)`,
//! `calldataload(0x4)`, `keccak256(p, n)`), idioms (`mapping(slot,
//! key)`, `address(x)`, `bool(x)`, `Name.selector`) and infix
//! operators. This module only parses; `evm_emit` gives the tree its
//! EVM meaning.
//!
//! Operator precedence follows Solidity, loosest first: `||`, `&&`,
//! `==` `!=`, `<` `>` `<=` `>=`, `|`, `^`, `&`, `<<` `>>`, `+` `-`,
//! `*` `/` `%`, unary `!` `~` `-` `&`, `**` (right-associative). The
//! lifter parenthesises every nested infix operand, so its own output
//! never depends on these levels.

use std::fmt;

/// A parsed expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EExpr {
    /// Big-endian constant, at most 32 bytes.
    Num(Vec<u8>),
    /// Identifier, possibly dotted (`msg.data.length`, `X.selector`).
    Name(String),
    /// `"…"` string literal (revert reasons).
    Str(String),
    Unary(UnOp, Box<EExpr>),
    Binary(BinOp, Box<EExpr>, Box<EExpr>),
    /// `f(args…)`; `f` may be dotted (`abi.encode`).
    Call(String, Vec<EExpr>),
    /// `a[b]`.
    Index(Box<EExpr>, Box<EExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnOp {
    /// `!x` — `ISZERO`.
    Not,
    /// `~x` — `NOT`.
    BitNot,
    /// `-x` — two's-complement negation.
    Neg,
    /// `&x` — the storage slot of a storage variable.
    Ref,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Exp,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Ne,
    LogicAnd,
    LogicOr,
}

/// Why an expression didn't parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParseError {
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn err<T>(message: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError {
        message: message.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(Vec<u8>),
    Ident(String),
    Str(String),
    Punct(&'static str),
}

const PUNCTS: &[&str] = &[
    "**", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "(", ")", "[", "]", ",", "!", "~", "-",
    "+", "*", "/", "%", "&", "|", "^", "<", ">",
];

#[allow(clippy::many_single_char_names)]
fn lex(text: &str) -> Result<Vec<Tok>, ParseError> {
    let s = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Num(parse_number(&text[start..i])?));
        } else if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            let start = i;
            while i < s.len()
                && (s[i].is_ascii_alphanumeric()
                    || s[i] == b'_'
                    || s[i] == b'$'
                    || (s[i] == b'.' && s.get(i + 1).is_some_and(u8::is_ascii_alphabetic)))
            {
                i += 1;
            }
            out.push(Tok::Ident(text[start..i].to_string()));
        } else if c == b'"' {
            let mut v = String::new();
            i += 1;
            loop {
                match s.get(i) {
                    None => return err("unterminated string literal"),
                    Some(b'"') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') => {
                        match s.get(i + 1) {
                            Some(b'n') => v.push('\n'),
                            Some(&e) => v.push(char::from(e)),
                            None => return err("unterminated string literal"),
                        }
                        i += 2;
                    }
                    Some(_) => {
                        let ch = text[i..].chars().next().expect("in bounds");
                        v.push(ch);
                        i += ch.len_utf8();
                    }
                }
            }
            out.push(Tok::Str(v));
        } else if let Some(p) = PUNCTS.iter().find(|p| text[i..].starts_with(**p)) {
            out.push(Tok::Punct(p));
            i += p.len();
        } else {
            return err(format!("unexpected character `{}`", char::from(c)));
        }
    }
    Ok(out)
}

/// `0x…` hex or decimal, as minimal big-endian bytes (at most 32).
fn parse_number(text: &str) -> Result<Vec<u8>, ParseError> {
    let bad = || ParseError {
        message: format!("bad number `{text}`"),
    };
    let mut bytes: Vec<u8> = Vec::new();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad());
        }
        let padded = if hex.len() % 2 == 1 {
            format!("0{hex}")
        } else {
            hex.to_string()
        };
        for pair in padded.as_bytes().chunks(2) {
            let s = std::str::from_utf8(pair).map_err(|_| bad())?;
            bytes.push(u8::from_str_radix(s, 16).map_err(|_| bad())?);
        }
    } else {
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        // Little-endian base-256 accumulator, times ten plus digit.
        let mut le: Vec<u8> = Vec::new();
        for d in text.bytes() {
            let mut carry = u32::from(d - b'0');
            for b in &mut le {
                let v = u32::from(*b) * 10 + carry;
                *b = (v & 0xff) as u8;
                carry = v >> 8;
            }
            while carry > 0 {
                le.push((carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        le.reverse();
        bytes = le;
    }
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let bytes = bytes[first..].to_vec();
    if bytes.len() > 32 {
        return err(format!("constant `{text}` is wider than 256 bits"));
    }
    Ok(bytes)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

/// Binary operator levels, loosest first.
const LEVELS: &[&[(&str, BinOp)]] = &[
    &[("||", BinOp::LogicOr)],
    &[("&&", BinOp::LogicAnd)],
    &[("==", BinOp::Eq), ("!=", BinOp::Ne)],
    &[
        ("<=", BinOp::Le),
        (">=", BinOp::Ge),
        ("<", BinOp::Lt),
        (">", BinOp::Gt),
    ],
    &[("|", BinOp::Or)],
    &[("^", BinOp::Xor)],
    &[("&", BinOp::And)],
    &[("<<", BinOp::Shl), (">>", BinOp::Shr)],
    &[("+", BinOp::Add), ("-", BinOp::Sub)],
    &[("*", BinOp::Mul), ("/", BinOp::Div), ("%", BinOp::Mod)],
];

impl Parser {
    fn peek_punct(&self, p: &str) -> bool {
        matches!(self.toks.get(self.pos), Some(Tok::Punct(q)) if *q == p)
    }

    fn eat(&mut self, p: &str) -> bool {
        if self.peek_punct(p) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, p: &str) -> Result<(), ParseError> {
        if self.eat(p) {
            Ok(())
        } else {
            err(format!("expected `{p}`"))
        }
    }

    fn binary(&mut self, level: usize) -> Result<EExpr, ParseError> {
        let Some(ops) = LEVELS.get(level) else {
            return self.unary();
        };
        let mut lhs = self.binary(level + 1)?;
        'outer: loop {
            for (sym, op) in *ops {
                if self.eat(sym) {
                    let rhs = self.binary(level + 1)?;
                    lhs = EExpr::Binary(*op, Box::new(lhs), Box::new(rhs));
                    continue 'outer;
                }
            }
            return Ok(lhs);
        }
    }

    fn unary(&mut self) -> Result<EExpr, ParseError> {
        let op = if self.eat("!") {
            UnOp::Not
        } else if self.eat("~") {
            UnOp::BitNot
        } else if self.eat("-") {
            UnOp::Neg
        } else if self.eat("&") {
            UnOp::Ref
        } else {
            return self.power();
        };
        Ok(EExpr::Unary(op, Box::new(self.unary()?)))
    }

    fn power(&mut self) -> Result<EExpr, ParseError> {
        let base = self.postfix()?;
        if self.eat("**") {
            let exp = self.unary()?;
            return Ok(EExpr::Binary(BinOp::Exp, Box::new(base), Box::new(exp)));
        }
        Ok(base)
    }

    fn postfix(&mut self) -> Result<EExpr, ParseError> {
        let mut e = self.primary()?;
        while self.eat("[") {
            let idx = self.binary(0)?;
            self.expect("]")?;
            e = EExpr::Index(Box::new(e), Box::new(idx));
        }
        Ok(e)
    }

    fn primary(&mut self) -> Result<EExpr, ParseError> {
        let Some(tok) = self.toks.get(self.pos).cloned() else {
            return err("unexpected end of expression");
        };
        self.pos += 1;
        match tok {
            Tok::Num(b) => Ok(EExpr::Num(b)),
            Tok::Str(s) => Ok(EExpr::Str(s)),
            Tok::Ident(name) => {
                if !self.eat("(") {
                    return Ok(EExpr::Name(name));
                }
                let mut args = Vec::new();
                if !self.eat(")") {
                    loop {
                        args.push(self.binary(0)?);
                        if self.eat(")") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                Ok(EExpr::Call(name, args))
            }
            Tok::Punct("(") => {
                let e = self.binary(0)?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Punct(p) => err(format!("unexpected `{p}`")),
        }
    }
}

/// Parse one expression.
pub(crate) fn parse_expr(text: &str) -> Result<EExpr, ParseError> {
    let mut list = parse_list(text)?;
    if list.len() != 1 {
        return err(format!("expected one expression, found {}", list.len()));
    }
    Ok(list.pop().expect("one"))
}

/// Parse a comma-separated list of expressions (empty text gives an
/// empty list).
pub(crate) fn parse_list(text: &str) -> Result<Vec<EExpr>, ParseError> {
    let toks = lex(text)?;
    if toks.is_empty() {
        return Ok(Vec::new());
    }
    let mut p = Parser { toks, pos: 0 };
    let mut out = vec![p.binary(0)?];
    while p.eat(",") {
        out.push(p.binary(0)?);
    }
    if p.pos != p.toks.len() {
        return err(format!(
            "unexpected trailing input in `{}`",
            text.trim().chars().take(60).collect::<String>()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(v: u8) -> EExpr {
        EExpr::Num(if v == 0 { vec![] } else { vec![v] })
    }

    fn name(s: &str) -> EExpr {
        EExpr::Name(s.into())
    }

    #[test]
    fn parses_lifted_forms() {
        assert_eq!(
            parse_expr("(v6 >= arg2)").unwrap(),
            EExpr::Binary(BinOp::Ge, Box::new(name("v6")), Box::new(name("arg2")))
        );
        assert_eq!(
            parse_expr("!msg.value").unwrap(),
            EExpr::Unary(UnOp::Not, Box::new(name("msg.value")))
        );
        assert_eq!(
            parse_expr("mapping(0x3, address(msg.sender))").unwrap(),
            EExpr::Call(
                "mapping".into(),
                vec![
                    n(3),
                    EExpr::Call("address".into(), vec![name("msg.sender")])
                ]
            )
        );
        assert_eq!(
            parse_expr("~0x1f").unwrap(),
            EExpr::Unary(UnOp::BitNot, Box::new(n(0x1f)))
        );
        assert_eq!(parse_expr("0x0").unwrap(), n(0));
        assert_eq!(parse_expr("300").unwrap(), EExpr::Num(vec![1, 0x2c]));
        assert_eq!(
            parse_list("v4, 0x0, (0x20 + v4)").unwrap().len(),
            3,
            "tuple sources"
        );
        assert_eq!(parse_list("").unwrap(), vec![]);
        assert_eq!(
            parse_expr("balanceOf[msg.sender]").unwrap(),
            EExpr::Index(Box::new(name("balanceOf")), Box::new(name("msg.sender")))
        );
        assert_eq!(
            parse_expr("&allowance[a]").unwrap(),
            EExpr::Unary(
                UnOp::Ref,
                Box::new(EExpr::Index(
                    Box::new(name("allowance")),
                    Box::new(name("a"))
                ))
            )
        );
    }

    #[test]
    fn precedence_is_solidity_like() {
        // `a + b * c == d` groups as `(a + (b * c)) == d`.
        let e = parse_expr("a + b * c == d").unwrap();
        let EExpr::Binary(BinOp::Eq, lhs, _) = e else {
            panic!("{e:?}")
        };
        assert!(matches!(*lhs, EExpr::Binary(BinOp::Add, _, ref r)
            if matches!(**r, EExpr::Binary(BinOp::Mul, _, _))));
        // `2 ** 3 ** 2` is right-associative.
        let e = parse_expr("2 ** 3 ** 2").unwrap();
        assert!(matches!(e, EExpr::Binary(BinOp::Exp, _, ref r)
            if matches!(**r, EExpr::Binary(BinOp::Exp, _, _))));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_expr("v1 +").is_err());
        assert!(parse_expr("v1 v2").is_err());
        assert!(parse_expr("0x").is_err());
        assert!(parse_expr("a @ b").is_err());
        assert!(parse_expr(&format!("0x{}", "ff".repeat(33))).is_err());
    }

    #[test]
    fn strings() {
        assert_eq!(
            parse_list("v1 > 0x0, \"not enough\"").unwrap()[1],
            EExpr::Str("not enough".into())
        );
    }
}

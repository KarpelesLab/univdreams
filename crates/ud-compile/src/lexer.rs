//! Lexer for `.ud`.
//!
//! Produces a stream of [`Token`] values, each with a 1-indexed line
//! and column for diagnostics. Whitespace is skipped; comments are
//! emitted as their own tokens so the parser can preserve them in the
//! AST when they appear at significant positions (top level, function
//! body) and reject them in the middle of expressions.

use std::iter::Peekable;
use std::str::CharIndices;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `,`
    Comma,
    /// `:`
    Colon,
    /// `@`
    At,
    /// `->` (return-type arrow)
    Arrow,
    /// `<` (type-parameter open)
    Lt,
    /// `>` (type-parameter close)
    Gt,
    /// `=` (used in named directive arguments like `entry_jmp=[bytes]`).
    Eq,
    /// `#` — the 6502 immediate-operand sigil that appears in call
    /// arg text like `A=#$0D`. Not interpreted by the parser; only
    /// recognised so the lexer doesn't reject these characters in
    /// the source.
    Hash,
    /// `$` — the 6502 hex-literal sigil that appears in call arg
    /// text like `A=$D012` or `A=#$0D`. Also a "skip me" token.
    Dollar,
    /// `;` — appears inside if/while cond text as an instruction
    /// separator (`CMP X; BNE tgt`). Lexer-recognised so the
    /// raw-text-capture parser can snip the inner text.
    Semicolon,
    /// An identifier or keyword.
    Ident(String),
    /// A double-quoted string literal (already unescaped).
    String(String),
    /// An integer literal (always parsed as u64).
    Int(u64),
    /// A `// …` line comment, with the leading `//` and any leading
    /// whitespace inside stripped — `// hello` becomes `Comment("hello")`.
    Comment(String),
    /// End of input.
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub line: u32,
    pub col: u32,
    /// Byte offset of this token's first character in the input
    /// string. Combined with `end` it lets the parser snip raw text
    /// out of the source — used by the call-statement parser to
    /// preserve the exact unquoted argument text the user wrote.
    pub start: usize,
    /// Byte offset just past this token's last character.
    pub end: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum LexError {
    #[error("unexpected character {ch:?} at line {line}, col {col}")]
    UnexpectedChar { ch: char, line: u32, col: u32 },
    #[error("unterminated string literal starting at line {line}, col {col}")]
    UnterminatedString { line: u32, col: u32 },
    #[error("invalid escape `\\{ch}` in string at line {line}, col {col}")]
    InvalidEscape { ch: char, line: u32, col: u32 },
    #[error("invalid number {text:?} at line {line}, col {col}: {reason}")]
    InvalidNumber {
        text: String,
        line: u32,
        col: u32,
        reason: String,
    },
}

/// Tokenize `input` into a stream of tokens, skipping whitespace.
/// The final token is always `Eof`.
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    let mut lexer = Lexer::new(input);
    let mut out = Vec::new();
    loop {
        let tok = lexer.next_token()?;
        let is_eof = tok.kind == TokenKind::Eof;
        out.push(tok);
        if is_eof {
            return Ok(out);
        }
    }
}

struct Lexer<'a> {
    src: &'a str,
    iter: Peekable<CharIndices<'a>>,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            iter: src.char_indices().peekable(),
            line: 1,
            col: 1,
        }
    }

    fn bump(&mut self) -> Option<(usize, char)> {
        let next = self.iter.next();
        if let Some((_, ch)) = next {
            if ch == '\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
        }
        next
    }

    fn peek_char(&mut self) -> Option<char> {
        self.iter.peek().map(|&(_, c)| c)
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek_char() {
            if c.is_whitespace() {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_whitespace();
        let line = self.line;
        let col = self.col;
        let Some((start, ch)) = self.bump() else {
            let eof_pos = self.src.len();
            return Ok(Token {
                kind: TokenKind::Eof,
                line,
                col,
                start: eof_pos,
                end: eof_pos,
            });
        };
        let kind = match ch {
            '{' => TokenKind::LBrace,
            '}' => TokenKind::RBrace,
            '(' => TokenKind::LParen,
            ')' => TokenKind::RParen,
            '[' => TokenKind::LBracket,
            ']' => TokenKind::RBracket,
            ',' => TokenKind::Comma,
            ':' => TokenKind::Colon,
            '@' => TokenKind::At,
            '-' if self.peek_char() == Some('>') => {
                self.bump(); // consume '>'
                TokenKind::Arrow
            }
            '<' => TokenKind::Lt,
            '>' => TokenKind::Gt,
            '=' => TokenKind::Eq,
            '#' => TokenKind::Hash,
            '$' => TokenKind::Dollar,
            ';' => TokenKind::Semicolon,
            '/' if self.peek_char() == Some('/') => {
                self.bump(); // consume the second '/'
                self.read_line_comment()
            }
            '"' => self.read_string(line, col)?,
            '-' if self.peek_char().is_some_and(|c| c.is_ascii_digit()) => {
                self.read_number(start, line, col)?
            }
            c if c.is_ascii_digit() => self.read_number(start, line, col)?,
            c if is_ident_start(c) => self.read_ident(start),
            other => {
                return Err(LexError::UnexpectedChar {
                    ch: other,
                    line,
                    col,
                });
            }
        };
        let end = self.current_byte_pos();
        Ok(Token {
            kind,
            line,
            col,
            start,
            end,
        })
    }

    /// Byte position of the next character to be consumed, or
    /// `src.len()` at EOF.
    fn current_byte_pos(&mut self) -> usize {
        self.iter.peek().map_or(self.src.len(), |&(p, _)| p)
    }

    fn read_line_comment(&mut self) -> TokenKind {
        let mut text = String::new();
        while let Some(c) = self.peek_char() {
            if c == '\n' {
                break;
            }
            self.bump();
            text.push(c);
        }
        TokenKind::Comment(text.trim_start().to_string())
    }

    fn read_string(&mut self, line: u32, col: u32) -> Result<TokenKind, LexError> {
        let mut text = String::new();
        loop {
            let Some((_, ch)) = self.bump() else {
                return Err(LexError::UnterminatedString { line, col });
            };
            match ch {
                '"' => return Ok(TokenKind::String(text)),
                '\\' => {
                    let escape_line = self.line;
                    let escape_col = self.col;
                    let Some((_, esc)) = self.bump() else {
                        return Err(LexError::UnterminatedString { line, col });
                    };
                    match esc {
                        '"' => text.push('"'),
                        '\\' => text.push('\\'),
                        'n' => text.push('\n'),
                        't' => text.push('\t'),
                        'r' => text.push('\r'),
                        '0' => text.push('\0'),
                        other => {
                            return Err(LexError::InvalidEscape {
                                ch: other,
                                line: escape_line,
                                col: escape_col,
                            });
                        }
                    }
                }
                other => text.push(other),
            }
        }
    }

    fn read_number(&mut self, start: usize, line: u32, col: u32) -> Result<TokenKind, LexError> {
        // We've already consumed the first character at `start`,
        // which is either an ASCII digit or a `-` followed by a
        // digit. Read the rest of the number in either case.
        let first = self.src.as_bytes()[start] as char;
        let negative = first == '-';
        let mut end = start + first.len_utf8();
        // Skip past the leading `-` so radix detection sees the
        // first digit.
        let radix_start = if negative {
            // The `-` was consumed before calling read_number; now
            // the first actual digit is the next char waiting.
            end
        } else {
            start
        };
        let radix_first = self.src.as_bytes()[radix_start] as char;
        if negative {
            // Consume the digit at `radix_start` (we know it's a digit).
            self.bump();
            end += radix_first.len_utf8();
        }
        let radix = if radix_first == '0' && matches!(self.peek_char(), Some('x' | 'X')) {
            self.bump(); // consume the 'x'
            end += 1;
            16
        } else {
            10
        };
        while let Some(c) = self.peek_char() {
            if c == '_' || c.is_digit(radix) {
                self.bump();
                end += c.len_utf8();
            } else {
                break;
            }
        }
        let text = &self.src[start..end];
        let trimmed = text.replace('_', "");
        // Strip the leading `-` and the optional `0x` prefix.
        let body = if negative {
            if radix == 16 {
                &trimmed[3..] // skip "-0x"
            } else {
                &trimmed[1..] // skip "-"
            }
        } else if radix == 16 {
            &trimmed[2..]
        } else {
            &trimmed
        };
        let parsed = u64::from_str_radix(body, radix);
        match parsed {
            Ok(n) => {
                let value = if negative {
                    // Two's-complement negation; the parser stores
                    // the bit pattern, callers that want signed
                    // semantics cast back to i64.
                    n.wrapping_neg()
                } else {
                    n
                };
                Ok(TokenKind::Int(value))
            }
            Err(e) => Err(LexError::InvalidNumber {
                text: text.to_string(),
                line,
                col,
                reason: e.to_string(),
            }),
        }
    }

    fn read_ident(&mut self, start: usize) -> TokenKind {
        let mut end = start + 1;
        while let Some(c) = self.peek_char() {
            if is_ident_continue(c) {
                self.bump();
                end += c.len_utf8();
            } else {
                break;
            }
        }
        TokenKind::Ident(self.src[start..end].to_string())
    }
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

/// Identifier continuation chars. `.` is permitted because gcc's
/// i386 PC-thunk helpers have names like `__x86.get_pc_thunk.bx`,
/// and our function-name field stores them verbatim. The leading
/// character is still restricted (no identifier starts with `.`),
/// which keeps `// foo.bar` from being lexed as an ident.
fn is_ident_continue(c: char) -> bool {
    c == '_' || c == '.' || c.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(input: &str) -> Vec<TokenKind> {
        tokenize(input)
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn punctuation_and_eof() {
        assert_eq!(
            kinds("{ } ( ) [ ] , : @"),
            vec![
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::Comma,
                TokenKind::Colon,
                TokenKind::At,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn idents_and_keywords_are_just_idents() {
        assert_eq!(
            kinds("fn _start main"),
            vec![
                TokenKind::Ident("fn".into()),
                TokenKind::Ident("_start".into()),
                TokenKind::Ident("main".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn integers_decimal_and_hex() {
        assert_eq!(
            kinds("0 42 0x1f 0xFF 1_000 0xff_ff"),
            vec![
                TokenKind::Int(0),
                TokenKind::Int(42),
                TokenKind::Int(0x1f),
                TokenKind::Int(0xff),
                TokenKind::Int(1_000),
                TokenKind::Int(0xffff),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_with_escapes() {
        assert_eq!(
            kinds(r#""hello" "say \"hi\"" "\\n""#),
            vec![
                TokenKind::String("hello".into()),
                TokenKind::String(r#"say "hi""#.into()),
                TokenKind::String(r"\n".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn line_comments_strip_leading_whitespace() {
        assert_eq!(
            kinds("// hello\n// world"),
            vec![
                TokenKind::Comment("hello".into()),
                TokenKind::Comment("world".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn unterminated_string_errors_with_position() {
        let err = tokenize("\"unterminated").unwrap_err();
        assert!(matches!(
            err,
            LexError::UnterminatedString { line: 1, col: 1 }
        ));
    }
}

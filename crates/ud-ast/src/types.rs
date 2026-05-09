//! AST types for `.ud`.

/// A complete `.ud` file: a `@module { … }` header followed by zero
/// or more top-level items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdFile {
    pub module: Module,
    pub items: Vec<Item>,
}

/// The `@module { … }` block at the top of every file.
///
/// `fields` is an ordered list — order is significant for round-trip
/// (the pretty-printer emits in this order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub fields: Vec<Field>,
}

/// One `name: value` entry inside a `@module` or nested block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub value: Value,
}

/// A value that can appear on the right-hand side of a `Field`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A double-quoted string. Storage is the unescaped form.
    String(String),
    /// An integer literal. Always emitted in hex with the `0x` prefix
    /// for now (decimal also accepted on parse).
    Int(u64),
    /// A bracketed list of values: `[v1, v2, …]`.
    List(Vec<Value>),
    /// A nested block: `{ name: value, … }`.
    Block(Vec<Field>),
}

/// A top-level item between the module header and end of file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Free-floating `// …` line. Preserved on emit so structural
    /// notes the decompiler emitted survive parse → re-emit.
    Comment(String),
    /// A function declaration.
    Function(FnDecl),
}

/// A function declaration.
///
/// v0 has no parameters or return type yet — the body is a sequence of
/// `@asm("…")` directives and comments. Future iterations expand the
/// surface to typed parameters, return types, and structured statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnDecl {
    /// Optional `@addr(0x…)` directive preceding `fn`. Required for
    /// functions whose name doesn't encode the address (i.e. anything
    /// not matching `sub_<hex>`); the decompiler emits it always for
    /// clarity.
    pub addr: Option<u64>,
    pub name: String,
    pub body: Vec<Stmt>,
}

/// A statement inside a function body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    /// `@asm("text")` or `@asm("text", [bytes])` — an instruction.
    ///
    /// `text` is the human-readable assembly. `bytes` pins the exact
    /// encoded bytes; when non-empty, it's the ground truth for
    /// recompilation and the assembler's job is to verify that
    /// assembling `text` produces matching bytes (with directive-pinned
    /// encoding choices, when those land).
    ///
    /// `bytes` may be empty: a future assembler will then derive them
    /// from the text alone. v0 always populates `bytes` because we
    /// don't yet ship a text assembler that produces byte-identical
    /// output for non-canonical encodings.
    Asm { text: String, bytes: Vec<u8> },

    /// `// …` line. Used by the decompiler to surface block boundaries
    /// and direct-branch targets without committing to a structural
    /// syntax for them yet.
    Comment(String),
}

impl Stmt {
    /// Construct an [`Stmt::Asm`] with both text and pinned bytes.
    #[must_use]
    pub fn asm(text: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::Asm {
            text: text.into(),
            bytes,
        }
    }

    /// Construct an [`Stmt::Asm`] with text only (no bytes pinned).
    /// Useful in tests; not used by the v0 decompiler.
    #[must_use]
    pub fn asm_text(text: impl Into<String>) -> Self {
        Self::Asm {
            text: text.into(),
            bytes: Vec::new(),
        }
    }
}

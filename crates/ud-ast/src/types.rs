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

/// An item in the file: at the top level, or nested inside an
/// [`Item::Section`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// Free-floating `// …` line. Preserved on emit so structural
    /// notes survive parse → re-emit.
    Comment(String),

    /// A function declaration.
    Function(FnDecl),

    /// `@raw(0x…, [bytes])` — pin a slice of bytes at a virtual address.
    /// Used by the decompiler to fill the gaps between functions
    /// (alignment padding) and to capture the content of non-executable
    /// sections (`.rodata`, `.data`, etc.).
    Raw { addr: u64, bytes: Vec<u8> },

    /// `@section("name", 0x…) { items… }` — group items under an ELF
    /// section. The section's start address must equal the first
    /// nested item's address; items are required to cover the section
    /// contiguously (no gaps) for [`lower`](crate) to succeed.
    Section {
        name: String,
        addr: u64,
        items: Vec<Item>,
    },
}

/// A function declaration.
///
/// `signature` carries typed parameters and return type when known
/// (e.g. recovered from DWARF). When absent, the function emits as
/// `fn name() { … }` and behaves as untyped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnDecl {
    /// Optional `@addr(0x…)` directive preceding `fn`. Required for
    /// functions whose name doesn't encode the address (i.e. anything
    /// not matching `sub_<hex>`); the decompiler emits it always for
    /// clarity.
    pub addr: Option<u64>,
    pub name: String,
    /// Typed parameters and return type, when known.
    pub signature: Option<Signature>,
    pub body: Vec<Stmt>,
}

/// A function signature: parameter list + return type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub params: Vec<Param>,
    pub return_type: Type,
}

/// One typed parameter in a function signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: Type,
}

/// A type expressible in `.ud` source.
///
/// v0 covers C-like primitives plus single-level pointer wrapping.
/// Anything we can't recover (composite types, qualifiers, function
/// pointers) lands as [`Type::Unknown`], which the parser still
/// accepts so the round-trip closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Void,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    Bool,
    Char,
    /// `ptr<T>` — pointer to `T`.
    Pointer(Box<Type>),
    /// A type the source language can't yet express. Round-trips
    /// verbatim as the literal token `unknown`.
    Unknown,
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

    /// `@return(value, [bytes])` — a recognised return-with-literal
    /// pattern at the tail of a function. Lifted from sequences like
    /// `mov eax, N; [pop rbp;] ret` or `xor eax, eax; [pop rbp;] ret`.
    /// `bytes` carries every encoded byte of those instructions
    /// concatenated, so the lower path just emits the bytes.
    Return { value: u64, bytes: Vec<u8> },

    /// `@prologue("kind", [bytes])` — a recognised function prologue,
    /// typically `endbr64; push rbp; mov rbp, rsp; sub rsp, IMM` or
    /// a close variant. `kind` is a descriptive label
    /// (`"std"` / `"std-no-cf"` / `"std-noframe"`); `bytes` carries
    /// every encoded byte for round-trip.
    Prologue { kind: String, bytes: Vec<u8> },

    /// `@epilogue("kind", [bytes])` — a recognised function epilogue,
    /// typically `leave; ret` or `pop rbp; ret`. Used at the tail of
    /// the last block when no [`Stmt::Return`] consumed those bytes
    /// (e.g. the return value was computed in an earlier block).
    Epilogue { kind: String, bytes: Vec<u8> },

    /// `@return_expr("text", [bytes])` — a recognised
    /// "compute-a-value-and-fall-through-to-the-epilogue" block whose
    /// contents have been lifted into a single human-readable
    /// expression. The expression text is informational; the pinned
    /// bytes are the lower path's source of truth, so the original
    /// instruction stream re-emits exactly even if the expression is
    /// edited.
    ReturnExpr { text: String, bytes: Vec<u8> },

    /// `@arg_spill(N, [bytes])` — a recognised SysV-x64 argument
    /// spill: `mov [rbp+disp], REG_N` where `REG_N` is the integer or
    /// XMM register holding argument `N` at function entry. The slot
    /// displacement is recoverable from the pinned bytes, so it
    /// doesn't appear in the directive shape.
    ArgSpill { arg_index: u32, bytes: Vec<u8> },

    /// `@call("name", [args], [bytes])` — a recognised direct-call
    /// site whose preceding `mov reg, …` / `lea reg, …` instructions
    /// have been folded into the args list. Each arg is a
    /// human-readable rendering (string literal, integer constant,
    /// global address, `&function` reference, or `result` for a
    /// previous call's return value); the pinned bytes cover both
    /// the arg-setup instructions and the call itself, so the lower
    /// path emits the original instruction sequence verbatim.
    Call {
        name: String,
        args: Vec<String>,
        bytes: Vec<u8>,
    },

    /// A structured `cmp/test + jcc` head plus its branches:
    ///
    /// ```text
    /// @if_branch("cond text", [cond bytes]) {
    ///     @then { …fallthrough body… }
    ///     @else { …taken body… }   // optional
    /// }
    /// ```
    ///
    /// `else_body == None` means the source-language `if` has no
    /// `else` clause — the jcc-taken side jumps directly to whatever
    /// code follows the `@if_branch` in source order. With `Some`,
    /// both arms are real branches that converge somewhere later.
    ///
    /// Bytes layout, exactly preserved on lower: `cond_bytes` then
    /// bytes of `then_body`, then bytes of `else_body` if present.
    IfBranch {
        cond_text: String,
        cond_bytes: Vec<u8>,
        then_body: Vec<Stmt>,
        else_body: Option<Vec<Stmt>>,
    },

    /// `@local_set(slot, value, [bytes])` — a recognised
    /// `mov dword/qword ptr [rbp+disp], IMM` (or analogous on i386
    /// `[ebp+disp]`) where the destination is a stack-frame local.
    /// Lifts the common "initialise a local with a literal" pattern.
    /// `slot` is the signed displacement from the frame pointer
    /// (e.g. `-8` for `[rbp-8]`); `value` is the immediate, signed.
    LocalSet {
        slot: i64,
        value: i64,
        bytes: Vec<u8>,
    },

    /// `@local_arith(slot, op, value, [bytes])` — a recognised
    /// `add/sub dword/qword ptr [rbp+disp], IMM` pattern. Lifts
    /// the loop-counter / accumulator-update idiom.
    /// `op` is the arithmetic operation (`"+="` or `"-="`); `value`
    /// is the immediate, signed.
    LocalArith {
        slot: i64,
        op: String,
        value: i64,
        bytes: Vec<u8>,
    },

    /// `@local_compound(dst, op, src, [bytes])` — a multi-instruction
    /// pattern of the shape `[rbp+dst] op= [rbp+src]`. Either:
    ///
    /// * 2-insn form: `mov reg, [rbp+src]; <op> [rbp+dst], reg`
    ///   for ops with a memory-destination form (add, sub, and, or, xor),
    /// * 3-insn form: `mov reg, [rbp+dst]; <op> reg, [rbp+src];
    ///   mov [rbp+dst], reg` for ops without one (imul).
    ///
    /// The pinned `bytes` cover the whole sequence; the lower path
    /// re-emits them verbatim.
    LocalCompound {
        dst: i64,
        op: String,
        src: i64,
        bytes: Vec<u8>,
    },

    /// `@move("dst", "src", [bytes])` — an arch-agnostic
    /// "dst := src" data move whose lowering is pinned by `bytes`.
    /// The 6502 decompiler emits this for `LDA src; STA dst` pairs;
    /// the `dst` and `src` strings are operand text from the
    /// instruction stream (e.g. `"IN,Y"` and `"KBD"`).
    ///
    /// Round-trip: the source-language text is purely informational,
    /// `bytes` is what the lower path emits.
    Move {
        dst: String,
        src: String,
        bytes: Vec<u8>,
    },

    /// A structured loop with the test at the bottom. Canonical
    /// gcc -O0 shape:
    ///
    /// ```text
    /// @loop(entry_jmp=[bytes], "cond text", [tail bytes]) {
    ///     …body stmts…
    /// }
    /// ```
    ///
    /// Lifted from a CFG triple where:
    ///
    /// * a body block falls through to a tail block,
    /// * the tail block ends with a conditional branch whose
    ///   `taken` target is the body block (i.e. a back-edge),
    ///
    /// `entry_jmp_bytes` is the pre-header `jmp` that enters the
    /// loop at the tail (gcc's "skip body on first iteration" idiom).
    /// When detected, those bytes are folded into the directive so
    /// no `@asm` line is left behind for them.
    ///
    /// Lower-path byte order: `entry_jmp_bytes` (if any) → `body`
    /// bytes → `tail_bytes`. The `@loop` itself contributes nothing
    /// before `entry_jmp_bytes` — its placement in the function body
    /// determines where the bytes land.
    Loop {
        cond_text: String,
        entry_jmp_bytes: Option<Vec<u8>>,
        tail_bytes: Vec<u8>,
        body: Vec<Stmt>,
    },
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

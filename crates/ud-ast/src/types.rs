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

/// A `#[key=value]` annotation. Attributes live on structural
/// elements (functions, conditionals, …) and carry metadata that is
/// either:
///
/// * **Informational**: hints for the reader / downstream tooling
///   (`#[compiler="msvc15"]`, `#[abi="stdcall"]`) — they don't change
///   the lower-path output.
/// * **Load-bearing**: bytes / decisions that the lower path
///   consumes (`#[head_bytes=[…]]` on a separated cmp/jcc `if`, so
///   the cmp bytes land at the right offset relative to the
///   intervening statements).
///
/// Round-trip rule: attributes round-trip verbatim. The `@module`
/// header's optional `defaults: { … }` block can shadow any attribute
/// here; the emitter omits an attribute when it equals the module
/// default, the parser supplies the default when an attribute is
/// missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub key: String,
    pub value: AttrValue,
}

/// Right-hand side of an attribute. Kept small on purpose — every
/// new variant has to round-trip through emit + parse + lower.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    /// `"…"` — quoted string.
    String(String),
    /// `0x…` or decimal integer.
    Int(u64),
    /// `[0x01, 0x02, …]` — used by `head_bytes` and friends.
    ByteList(Vec<u8>),
    /// Bare flag, e.g. `#[naked]` — no `=value` part. Renders
    /// as just the key name; parses from any attribute that
    /// omits the `=` sign.
    Flag,
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

    /// `@strings(0x…, ["a", "b", …])` — a packed null-terminated
    /// string table. Lowers to each entry's UTF-8 bytes followed by
    /// a single 0x00 terminator, in order. Used for ELF `SHT_STRTAB`
    /// sections (`.dynstr`, `.strtab`, `.shstrtab`) and for any
    /// well-known single-string sections like `.interp` (which is
    /// emitted as a one-entry list).
    Strings { addr: u64, strings: Vec<String> },

    /// `@notes(0x…, [{ type: …, name: "…", desc: [bytes] }, …])` — an
    /// ELF note section. Each entry has a 12-byte `Elf64_Nhdr`
    /// header (name_size, desc_size, type), a name padded to a 4-byte
    /// boundary, and a desc padded to a 4-byte boundary. Used for
    /// `SHT_NOTE` sections (`.note.gnu.property`, `.note.ABI-tag`,
    /// `.note.gnu.build-id`, …).
    Notes { addr: u64, entries: Vec<NoteEntry> },

    /// `@section("name", 0x…) { items… }` — group items under an ELF
    /// section. The section's start address must equal the first
    /// nested item's address; items are required to cover the section
    /// contiguously (no gaps) for [`lower`](crate) to succeed.
    Section {
        name: String,
        addr: u64,
        items: Vec<Item>,
    },

    /// `@jump_table(0x…, dispatch="…") { case_0: label_<addr>; … }` —
    /// a structured switch jump table. Each entry names a case index
    /// and the address it dispatches to; the `dispatch` string tags
    /// the encoding kind (e.g. `"gcc_pie_rel32"`, `"msvc_va32"`) so
    /// lower knows whether to emit 4-byte signed offsets relative to
    /// the table base, absolute 32-bit VAs, or some other layout.
    /// Replaces the `@raw` byte run a jump table would otherwise
    /// occupy in `.rodata`, recovering the symbolic intent of the
    /// dispatch.
    JumpTable {
        addr: u64,
        dispatch: String,
        entries: Vec<JumpTableEntry>,
    },
}

/// One entry inside an [`Item::JumpTable`] block: a case index and
/// the address it dispatches to. The case ordering is the encoded
/// table order — entries lower in source-text order render at
/// `(addr + i * entry_size)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTableEntry {
    /// Case index — `0`, `1`, … for dense tables; sparse tables
    /// preserve gaps via case numbers that aren't strictly
    /// contiguous (rare in practice — most compilers normalise to
    /// a dense table with a `default` arm).
    pub case: u64,
    /// Target address the case dispatches to. Renders as
    /// `label_<addr:x>` in source text — the same label name a
    /// `Stmt::Goto` would produce.
    pub target: u64,
}

/// One entry inside an [`Item::Notes`] block. Mirrors the structure
/// of an ELF note (`Elf64_Nhdr` + name + desc, each padded to a
/// 4-byte boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteEntry {
    /// Note type (`NT_GNU_PROPERTY_TYPE_0`, `NT_GNU_BUILD_ID`, …).
    pub note_type: u32,
    /// Owner string (`"GNU"` for GNU notes, etc.). Encoded with a
    /// trailing NUL byte then padded to a 4-byte boundary.
    pub name: String,
    /// Descriptor bytes — opaque payload, padded to a 4-byte
    /// boundary on emit.
    pub desc: Vec<u8>,
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
    /// `#[…]` attributes attached to the `fn` keyword. Carry per-
    /// function profile info (`abi`, `cc`, `saves`, …); module-level
    /// `defaults` in the `@module` header can shadow these.
    pub attrs: Vec<Attribute>,
    /// Typed parameters and return type, when known.
    pub signature: Option<Signature>,
    /// Variable / register declarations at the top of the function
    /// body. Stack slots discovered from `[ebp±N]` accesses get a
    /// `Stack` decl; registers the function touches get a `Register`
    /// decl. Purely informational today (the prologue's pinned bytes
    /// already encode the actual stack allocation); future work can
    /// use the size hints to drive lowering of a re-allocated frame.
    pub locals: Vec<LocalDecl>,
    pub body: Vec<Stmt>,
}

/// One `let name: type;` entry at the head of a function body.
///
/// Kinds:
/// * **Stack** — `let var_4: u32;` — backed by a stack slot at
///   `[ebp-4]` (the name carries the offset as its hex suffix).
/// * **Register** — `let eax: u32 @reg;` — backed by a CPU
///   register; the name is the canonical x86 register mnemonic.
///
/// The type captures the largest access size seen at the slot /
/// register in the function. Multiple-width accesses (`mov al,
/// [ebp-1]; mov dword ptr [ebp-4], …`) pick the widest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDecl {
    pub name: String,
    pub ty: Type,
    pub kind: LocalKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalKind {
    Stack,
    Register,
}

/// A function signature: parameter list + return type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub params: Vec<Param>,
    pub return_type: Type,
}

/// One typed parameter in a function signature.
///
/// `location` carries the calling-convention slot the value is
/// passed in — for the 6502 backend this is a register name like
/// `"A"` / `"X"` / `"Y"`. When `Some`, the parameter renders as
/// `name: ty @LOC`. When `None`, just `name: ty`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub ty: Type,
    pub location: Option<String>,
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

/// Structured breakdown of a function prologue. Lets the source
/// language carry semantic information (which registers got
/// saved, whether a frame was set up, how much stack the function
/// reserves, whether CET protection is on) instead of an opaque
/// byte blob.
///
/// Used by the emitter to render
/// `@prologue(saves: [ebx, esi, edi], frame, sub: 0x40)` style
/// directives that drop the byte list because the parser can
/// regenerate identical bytes via the arch's prologue codec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrologueParams {
    /// Callee-saved registers pushed before the frame setup, in
    /// push order. Lowercase canonical names (`"ebx"`, `"esi"`,
    /// `"r12"`, …).
    pub saves: Vec<String>,
    /// Callee-saved registers pushed AFTER the frame setup
    /// (MSVC i386 idiom). Same naming.
    pub saves_after: Vec<String>,
    /// True when the prologue includes `push ebp; mov ebp, esp`
    /// (or the 64-bit variant).
    pub frame: bool,
    /// Stack reservation in bytes (`sub esp, IMM`). Zero when
    /// the function has no stack locals beyond saves.
    pub sub_esp: u32,
    /// True when the prologue starts with `endbr32` / `endbr64`
    /// (Intel CET indirect-branch landing pad).
    pub cf_protect: bool,
    /// Frame-setup encoding selector: `false` for the MSVC RM
    /// form (`mov ebp, esp` as `0x8b 0xec`), `true` for the GCC
    /// MR form (`0x89 0xe5`). Only meaningful when `frame` is
    /// true; the codec uses it to re-emit byte-identical
    /// instructions for either compiler.
    pub frame_alt: bool,
}

/// Structured breakdown of a function epilogue. Mirrors
/// [`PrologueParams`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpilogueParams {
    /// Callee-saved registers popped, in pop order (typically
    /// the reverse of the prologue's push order).
    pub saves: Vec<String>,
    /// True when the epilogue uses `leave` (atomic
    /// `mov esp, ebp; pop ebp`).
    pub leave: bool,
    /// True when the epilogue pops the frame pointer with an
    /// explicit `pop ebp` (after the named saves).
    pub pop_frame: bool,
    /// Stack adjustment via `add esp, IMM` before `ret`. Zero
    /// when absent.
    pub add_esp: u32,
    /// Immediate operand of `ret` (callee-cleanup amount).
    /// Zero for cdecl.
    pub ret_imm: u16,
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
    ///
    /// `params` carries the structured breakdown (saves list,
    /// frame flag, sub_esp value, cf_protect) when the prologue's
    /// bytes round-trip through the canonical codec. Lets the
    /// emitter render `@prologue(saves: [ebx, esi, edi], frame,
    /// sub: 0x40)` without the byte list. Empty for handwritten
    /// or non-canonical prologues where bytes are the source of
    /// truth.
    Prologue {
        kind: String,
        params: Option<PrologueParams>,
        bytes: Vec<u8>,
    },

    /// `@epilogue("kind", [bytes])` — a recognised function epilogue,
    /// typically `leave; ret` or `pop rbp; ret`. Used at the tail of
    /// the last block when no [`Stmt::Return`] consumed those bytes
    /// (e.g. the return value was computed in an earlier block).
    Epilogue {
        kind: String,
        params: Option<EpilogueParams>,
        bytes: Vec<u8>,
    },

    /// `@save("REG", [bytes])` — a mid-function callee-saved register
    /// save. Pairs LIFO with a matching [`Stmt::Restore`] elsewhere in
    /// the body; together they bracket a region where the function
    /// borrows an extra register the prologue didn't reserve. Bytes
    /// are exactly the `push REG` encoding.
    Save { reg: String, bytes: Vec<u8> },

    /// `@restore("REG", [bytes])` — the matching restore for a prior
    /// [`Stmt::Save`]. Bytes are exactly the `pop REG` encoding.
    Restore { reg: String, bytes: Vec<u8> },

    /// `@if_return("cond", "value", [bytes])` — an early-return
    /// pattern: a `test/cmp + jcc` whose taken target is a
    /// return-shaped block elsewhere in the function. The bytes
    /// are the original cmp/test + jcc encoding; the actual return
    /// happens at the target block (whose bytes remain in place).
    /// Renders as `if (cond) return value;` to convey the intent
    /// even though the jcc semantically transfers control to a
    /// shared cleanup tail.
    ///
    /// `value` is the literal/expression the target block returns,
    /// when statically known; empty when the target's return value
    /// can't be folded.
    ///
    /// Same shape as `IfGoto`: the jcc tail re-encodes from
    /// the target's *implicit* address (the return-block's
    /// position, captured at decompile time via the cmp-bytes
    /// length + jcc rel resolution). `cmp_bytes` stays pinned
    /// until the text assembler.
    IfReturn {
        cond_text: String,
        value_text: String,
        target_addr: u64,
        cmp_bytes: Vec<u8>,
        cond_code: u8,
        wide: bool,
    },

    /// `label_XXXX:` — a zero-byte marker for a jump target. The
    /// `addr` is the run-time virtual address the label represents
    /// (rendered as `label_<hex>`). Labels carry no bytes; they
    /// occupy a position in the source so a [`Stmt::Goto`] or
    /// [`Stmt::IfGoto`] elsewhere in the function can point at
    /// them by name. Round-trip neutral.
    Label { addr: u64 },

    /// `goto label_XXXX;` (or `goto label_XXXX #[wide];`) — an
    /// unconditional `jmp` to a label somewhere in the function
    /// body. No pinned bytes: the lower path picks the encoding
    /// from `target_addr`, the cursor position, and the `wide`
    /// flag:
    ///
    /// * `wide=false` and the displacement fits in `i8`:
    ///   `jmp rel8` (2 bytes).
    /// * otherwise: `jmp rel32` (5 bytes).
    ///
    /// The `wide` flag captures encoding choices the compiler
    /// made that don't follow the "always shortest" rule —
    /// occasional, but real (some MSVC paths emit `jmp rel32`
    /// even when `jmp rel8` would fit). Editing the function so
    /// a label moves auto-promotes `wide=false` → `wide=true`
    /// when the displacement no longer fits in `i8`.
    Goto { target_addr: u64, wide: bool },

    /// `if (cond) goto label_XXXX;` — a conditional jump folded
    /// from `cmp/test …; jcc …`. The jcc tail is no longer
    /// pinned in source: the lower path re-encodes
    /// `jcc rel8/rel32` from `target_addr`, `cond_code`, and
    /// `wide`. `cmp_bytes` carries the cmp/test prefix (empty
    /// when the source is a bare flag check); it stays pinned
    /// until the text-assembler can re-encode it from
    /// `cond_text`.
    ///
    /// Editing a label so its position changes flows through to
    /// the rebuilt binary. Editing `cmp_bytes` and `cond_text`
    /// without keeping them consistent is the user's job until
    /// the assembler lands.
    IfGoto {
        cond_text: String,
        target_addr: u64,
        cmp_bytes: Vec<u8>,
        cond_code: u8,
        wide: bool,
    },

    /// `switch (selector) #[dispatch="…", table_va=…] { case N: goto … }`
    /// — a structured switch whose dispatch bytes are *not* pinned
    /// to the source. The lower path regenerates `cmp REG,MAX; ja
    /// DEFAULT; jmp dword ptr [REG*4+TABLE_VA]` from the structured
    /// fields, validating that the case/default/selector data
    /// re-encodes to a correct dispatch sequence.
    ///
    /// `dispatch` names the encoding shape (currently only
    /// `"msvc-jmp-table"` is recognised). `table_va` is the
    /// absolute address of the jump-table data the indirect jmp
    /// reads — the table contents themselves still ride in a
    /// `@raw` block under the appropriate data section.
    ///
    /// Editing the source is the whole point: adding a case here,
    /// changing `default_addr`, or renaming the selector all flow
    /// through to the rebuilt binary via the lower-side encoder,
    /// without any pinned bytes to silently invalidate.
    Switch {
        selector: String,
        cases: Vec<u64>,
        default_addr: u64,
        dispatch: String,
        table_va: u64,
    },

    /// `@seh_install([bytes])` — MSVC's Structured Exception
    /// Handling frame install: `mov fs:[0], esp` after pushing
    /// the handler-frame fields. Bytes are exactly the
    /// `mov fs:[0], esp` encoding (7 bytes on x86-32).
    SehInstall { bytes: Vec<u8> },

    /// `@seh_restore([bytes])` — pops the SEH chain back to the
    /// previously installed handler. Bytes encode
    /// `mov reg, [ebp-N]; mov fs:[0], reg` (or similar pop
    /// sequence). Pairs LIFO with a prior `Stmt::SehInstall`.
    SehRestore { bytes: Vec<u8> },

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
    /// `name(args)` — a function call (direct or indirect).
    ///
    /// `bytes` pins the arg-setup prefix (pushes, movs, etc.).
    /// For **indirect** calls (`call dword ptr [imm]` etc.) the
    /// call instruction itself rides at the end of `bytes`
    /// because we don't yet re-encode arbitrary memory operands.
    ///
    /// For **direct** calls (`call rel32`) the trailing 5 bytes
    /// are stripped from `bytes` and `direct_target` carries the
    /// callee's IP. The lower path encodes `call rel32` against
    /// the current cursor + `direct_target`, so editing a
    /// function's position automatically re-resolves every
    /// caller's relative offset.
    Call {
        name: String,
        args: Vec<String>,
        bytes: Vec<u8>,
        direct_target: Option<u64>,
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
    /// Bytes layout, exactly preserved on lower (in source order):
    ///
    /// * `attrs["head_bytes"]` if present (the cmp/test bytes that
    ///   live *before* the intervening insns the compiler reordered
    ///   between the comparison and the conditional branch),
    /// * `pre_body` statement bytes (the "intervening" insns
    ///   between cmp and jcc — empty for the adjacent-cmp case),
    /// * `cond_bytes` (the jcc when there's `head_bytes`; the full
    ///   cmp+jcc when there isn't),
    /// * `then_body` statement bytes,
    /// * `else_body` statement bytes if present.
    IfBranch {
        cond_text: String,
        cond_bytes: Vec<u8>,
        /// Free-form metadata. Recognised keys today: `head_bytes`
        /// (load-bearing — see byte layout above).
        attrs: Vec<Attribute>,
        /// Statements that fall between the cmp/test and the jcc in
        /// the original instruction stream. Empty for adjacent cmp +
        /// jcc (the common case) — the field exists for the
        /// separated-by-flag-preserving-insns case.
        pre_body: Vec<Stmt>,
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

    /// `@inc16("lo", "hi", [bytes])` — a 16-bit increment composed
    /// of `INC lo; BNE +2; INC hi` (with the `BNE` skipping the
    /// high-byte INC unless the low byte just rolled over). The
    /// canonical 6502 idiom for advancing a 16-bit pointer.
    Inc16 {
        lo: String,
        hi: String,
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

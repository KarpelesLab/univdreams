//! Arch-codec trait + open registry.
//!
//! The `univdreams` decompile/compile pipeline is arch-agnostic at
//! its boundaries — the lower path takes a parsed `.ud` source and
//! emits bytes; the decompile path takes a binary and emits `.ud`
//! source. Between those boundaries, every instruction-shaped
//! decision belongs to a specific architecture.
//!
//! This crate defines the shared shape: [`ArchCodec`] is the trait
//! every arch backend implements; [`registry`] is the open registry
//! consumers (CLI, wasm) populate at process start. The lower path
//! resolves a codec from the parsed `@module` block, then asks it to
//! encode each statement that carries semantic fields the codec can
//! re-emit (jumps, calls, moves, returns). Anything the codec
//! doesn't model returns [`ArchError::Unsupported`] and the pinned
//! `bytes` field on the statement is the fallback.
//!
//! ## Layering
//!
//! This crate intentionally has **no dependency on `ud-ast`** — it
//! takes raw `(arch, e_machine)` pairs at the registry boundary
//! and leaves the marshaling from a parsed `ud_ast::Module` to the
//! caller (`ud-translate`). That break is what keeps the dependency
//! graph acyclic: `ud-ast` depends on `ud-arch-x86` for emitter
//! helpers, and the arch crates depend on `ud-arch-codec`, so
//! `ud-arch-codec` cannot also depend on `ud-ast`.
//!
//! Prologue/epilogue parameters (which today live in `ud-ast`)
//! flow through the lower path as arch-specific types, not through
//! the trait. A follow-up commit will introduce a shared
//! representation here once we settle on a cross-arch shape.

#![allow(clippy::module_name_repetitions)]

pub mod registry;

pub use registry::{for_arch, register, CodecFactory};

/// Errors raised by [`ArchCodec`] implementations.
///
/// `Unsupported` is the soft-fail signal — it means "this arch
/// doesn't model this operation, please fall back to pinned
/// bytes." Other variants are hard failures the caller surfaces to
/// the user.
#[derive(Debug, thiserror::Error)]
pub enum ArchError {
    /// Returned when an arch is asked to encode something its
    /// codec doesn't model. The caller (decompile-time byte-drop
    /// pass, compile-time lower path) treats this as
    /// "leave the pinned bytes alone."
    #[error("arch {arch} does not support {operation}")]
    Unsupported {
        arch: &'static str,
        operation: &'static str,
    },

    /// The text the codec was asked to assemble didn't parse.
    #[error("assembly failed: {0}")]
    Assemble(String),

    /// An operand (typically a jump/call displacement) didn't fit
    /// the arch's encoding range.
    #[error("operand out of range: {0}")]
    OutOfRange(String),

    /// No registered codec factory claimed this arch.
    #[error(
        "no codec registered for arch = {arch:?}, e_machine = {e_machine:?}; \
         did you call <arch_crate>::register() at startup?"
    )]
    UnknownArch {
        arch: Option<String>,
        e_machine: Option<u64>,
    },

    /// Catch-all for arch-specific encoder failures that don't fit
    /// the structured variants. Use sparingly.
    #[error("{0}")]
    Other(String),
}

/// Per-call encoding hints that arches interpret in their own
/// convention. Today the only hint is `wide` (x86's short-vs-rel32
/// toggle); fixed-width arches (BPF, AArch64) ignore it.
///
/// Kept as a plain struct rather than per-method args so the trait
/// can grow new hints without breaking every impl.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncodeHints {
    /// Force a wide-form encoding. On x86 this means "use rel32
    /// even when rel8 would fit"; on BPF this is ignored (slot
    /// offsets are always one slot wide). `None` = arch picks.
    pub wide: Option<bool>,
    /// BPF call-convention hint for `encode_call`: `Some(true)`
    /// requests `call_local` (opcode 0x8d, Linux eBPF style),
    /// `Some(false)` requests `call_internal` (opcode 0x85
    /// src=1, Solana sBPF style), `None` defers to the codec's
    /// default. Lifters that have the original opcode (e.g.
    /// the byte-drop pass with pinned bytes) set this so the
    /// regen matches the original encoding exactly. Ignored by
    /// non-BPF arches.
    pub bpf_call_local: Option<bool>,
}

impl EncodeHints {
    /// Convenience: hints with `wide` set.
    #[must_use]
    pub const fn wide(wide: bool) -> Self {
        Self {
            wide: Some(wide),
            bpf_call_local: None,
        }
    }

    /// Resolve `wide` with a default for arches that need a bool.
    /// Most callers don't care about the default; BPF ignores wide
    /// entirely, x86 falls back to "pick shortest."
    #[must_use]
    pub fn wide_or(self, default: bool) -> bool {
        self.wide.unwrap_or(default)
    }
}

/// Structured switch-dispatch spec, passed to
/// [`ArchCodec::encode_switch_dispatch`]. Holds everything the x86
/// MSVC encoder needs; arches that don't model jump-table dispatch
/// return `Unsupported`.
#[derive(Debug, Clone, Copy)]
pub struct SwitchSpec<'a> {
    /// Register name (e.g. `"ecx"`) holding the case selector.
    pub selector: &'a str,
    /// The case-target addresses, in case-index order.
    pub cases: &'a [u64],
    /// Target for out-of-range selectors.
    pub default_addr: u64,
    /// Dispatch shape identifier — `"msvc-jmp-table"` today.
    /// Implementations match on this and return Unsupported for
    /// shapes they don't recognise.
    pub dispatch: &'a str,
    /// Absolute virtual address where the jump-table data lives.
    pub table_va: u64,
    /// Absolute address of the dispatch's first instruction.
    pub cmp_ip: u64,
}

/// The shared interface every arch backend implements.
///
/// Methods come in three classes:
///
/// * **Always-supported**: every arch must implement (`name`,
///   `assemble_one`, `encode_jump`, `encode_call`,
///   `encode_cond_jump`, the three size queries). Trait users can
///   call these unconditionally.
/// * **Optional with `Unsupported` default**: methods that not
///   every arch needs (`encode_switch_dispatch`, `encode_move`,
///   `encode_arith`, `encode_return`,
///   `encode_cond_jump_with_code`). Default impl returns
///   `ArchError::Unsupported`. The decompile-side byte-drop pass
///   and compile-side lower path both treat `Unsupported` as
///   "leave the pinned bytes alone."
/// * **Optional with passthrough default**: `desymbolize`, which
///   maps `label_<hex>` / `sub_<hex>` operands to numeric form.
///   BPF overrides; default is identity.
///
/// Implementations must be `Sync + Send` so they can be stored
/// behind a `Box<dyn ArchCodec>` and shared across threads.
pub trait ArchCodec: Sync + Send + std::fmt::Debug {
    /// Short stable identifier used in error messages and
    /// `ArchError::Unsupported.arch`. Recommended forms:
    /// `"x86-64"`, `"x86-32"`, `"bpf-linux"`, `"bpf-sbf-v1"`,
    /// `"bpf-sbf-v2"`, `"aarch64"`, `"6502"`.
    fn name(&self) -> &'static str;

    // ---------------------------------------------------------------
    // Assembly: text → bytes for a single instruction.
    // ---------------------------------------------------------------

    /// Assemble one instruction's text into bytes at `addr`.
    ///
    /// `addr` matters only for arches whose instructions encode
    /// the IP or whose symbolic operands need cursor context. Pass
    /// `0` when you don't have a real address (e.g. unit tests).
    fn assemble_one(&self, text: &str, addr: u64) -> Result<Vec<u8>, ArchError>;

    /// Resolve symbolic operands in `text` against `addr`. The
    /// default is identity — arches with named-target operands
    /// (BPF's `label_<hex>` / `sub_<hex>`) override to substitute
    /// numeric forms the assembler accepts.
    fn desymbolize(&self, text: &str, _addr: u64) -> String {
        text.to_string()
    }

    // ---------------------------------------------------------------
    // Control flow: jumps, calls, conditional branches.
    // ---------------------------------------------------------------

    /// Encode an unconditional jump from `source_ip` to `target`.
    fn encode_jump(
        &self,
        source_ip: u64,
        target: u64,
        hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError>;

    /// Encode a direct call from `source_ip` to `target`.
    fn encode_call(
        &self,
        source_ip: u64,
        target: u64,
        hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError>;

    /// Encode a conditional jump driven by a BPF-style text
    /// condition.
    ///
    /// `cond_text` reads as "when this is true, the body runs"
    /// (e.g. `"r0 != 0x0"`). The implementation typically inverts
    /// internally to pick the underlying jcc that *skips* the
    /// body. `target` is the address the jcc jumps to when the
    /// condition is false (i.e. past the body).
    ///
    /// Used by `Stmt::IfBlock` / `Stmt::WhileBlock` regen. Arches
    /// whose `If*` Stmts carry a numeric cond_code instead use
    /// [`Self::encode_cond_jump_with_code`].
    fn encode_cond_jump(
        &self,
        cond_text: &str,
        source_ip: u64,
        target: u64,
        hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError>;

    /// Encode a conditional jump driven by an x86-style numeric
    /// cond_code (the low nibble of the jcc opcode).
    ///
    /// Used by `Stmt::IfGoto` / `Stmt::IfReturn` regen. Default
    /// returns `Unsupported`.
    fn encode_cond_jump_with_code(
        &self,
        _cond_code: u8,
        _source_ip: u64,
        _target: u64,
        _hints: EncodeHints,
    ) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "cond_jump_with_code",
        })
    }

    /// Encode a jump-table dispatch. Default `Unsupported`.
    fn encode_switch_dispatch(&self, _spec: &SwitchSpec) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "switch_dispatch",
        })
    }

    // ---------------------------------------------------------------
    // Size queries: predict the encoded byte length without
    // actually emitting bytes. Used by the lower path to compute
    // downstream offsets before laying out the surrounding region.
    // ---------------------------------------------------------------

    /// Predicted size of `encode_jump`'s output.
    fn encoded_jump_size(&self, source_ip: u64, target: u64, hints: EncodeHints) -> usize;
    /// Predicted size of `encode_cond_jump` (text-driven).
    fn encoded_cond_jump_size(&self, source_ip: u64, target: u64, hints: EncodeHints) -> usize;
    /// Predicted size of `encode_call`'s output.
    fn encoded_call_size(&self, source_ip: u64, target: u64, hints: EncodeHints) -> usize;

    /// Whether a `Stmt::Call`'s pinned `bytes` already
    /// contains the call instruction itself (return true), or
    /// `bytes` is just the arg-setup prefix and `encode_call`
    /// regenerates the trailing call (return false).
    ///
    /// - x86 strips the trailing 5 bytes of `call rel32` and
    ///   regenerates them at lower time so an edit that moves
    ///   the function auto-resolves the new rel32. Returns
    ///   `false` (the default).
    /// - BPF has no separate "prefix" — the call IS the
    ///   single 8-byte instruction. Returns `true`.
    ///
    /// Used by the lower path's `Stmt::Call` arm to decide
    /// whether to append `encode_call` output after the
    /// pinned bytes.
    fn direct_call_bytes_contain_call(&self) -> bool {
        false
    }

    // ---------------------------------------------------------------
    // Data movement (lifted forms — register/memory operands as
    // text). The strings follow the arch's textual convention; the
    // codec parses them and emits the corresponding instruction.
    // ---------------------------------------------------------------

    /// Encode `dst = src` as a single instruction. Default
    /// `Unsupported`.
    ///
    /// Both `dst` and `src` follow the arch's text convention:
    /// BPF accepts `"r6"`, `"0x5"`, `"[r5 - 0xff8]"`, etc.; x86
    /// would accept `"rax"`, `"0x5"`, `"qword ptr [rbp-8]"`, etc.
    /// Implementations return `Unsupported` for any shape they
    /// don't model.
    fn encode_move(&self, _dst: &str, _src: &str) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "move",
        })
    }

    /// Encode `dst op= src` (e.g. `"r6", "+=", "r1"`). Default
    /// `Unsupported`.
    fn encode_arith(&self, _dst: &str, _op: &str, _src: &str) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "arith",
        })
    }

    /// Encode a function return. `value` carries a known literal
    /// (e.g. x86's `xor eax, eax; ret` collapses to "ret returning
    /// 0"); arches that ignore it (BPF `exit` returns r0
    /// implicitly) discard the field. Default `Unsupported`.
    fn encode_return(&self, _value: Option<u64>) -> Result<Vec<u8>, ArchError> {
        Err(ArchError::Unsupported {
            arch: self.name(),
            operation: "return",
        })
    }
}

//! Stack-code generation for edited EVM statements.
//!
//! Values are [`Sym`]bolic: an item that was on the stack when the
//! statement started (`Slot(k)`, `k` = depth from the top), a
//! constant, a code address resolved at layout time, or an operation
//! over those. An [`Emitter`] tracks what every stack item holds as it
//! generates code, so producing a value that is already on the stack
//! is a `DUPn`, and [`Emitter::materialize`] can rearrange the top of
//! the stack into any layout whose items it can compute — which is how
//! an edited statement keeps the stack its unedited successors expect.
//!
//! Code comes out as [`Piece`]s: instruction bytes, label definitions
//! and `PUSHn` of a label, so jumps resolve once the whole contract is
//! laid out again.

use std::fmt;

use super::evm_expr::{BinOp, EExpr, UnOp};
use crate::arch::evm::{OPCODE_TABLE, opcode_by_name};

pub(crate) const STOP: u8 = 0x00;
const ADD: u8 = 0x01;
const MUL: u8 = 0x02;
const SUB: u8 = 0x03;
const DIV: u8 = 0x04;
const MOD: u8 = 0x06;
const EXP: u8 = 0x0a;
const LT: u8 = 0x10;
const GT: u8 = 0x11;
const EQ: u8 = 0x14;
pub(crate) const ISZERO: u8 = 0x15;
const AND: u8 = 0x16;
const OR: u8 = 0x17;
const XOR: u8 = 0x18;
const NOT: u8 = 0x19;
const SHL: u8 = 0x1b;
const SHR: u8 = 0x1c;
const KECCAK256: u8 = 0x20;
const ADDRESS: u8 = 0x30;
const CALLDATALOAD: u8 = 0x35;
const MLOAD: u8 = 0x51;
const SLOAD: u8 = 0x54;
pub(crate) const MSTORE: u8 = 0x52;
const POP: u8 = 0x50;
pub(crate) const JUMP: u8 = 0x56;
pub(crate) const JUMPI: u8 = 0x57;
pub(crate) const JUMPDEST: u8 = 0x5b;
const PUSH0: u8 = 0x5f;
const RETURN: u8 = 0xf3;
const REVERT: u8 = 0xfd;
pub(crate) const INVALID: u8 = 0xfe;

/// `Error(string)` selector.
const ERROR_SELECTOR: u32 = 0x08c3_79a0;
/// `Panic(uint256)` selector.
const PANIC_SELECTOR: u32 = 0x4e48_7b71;

/// A code location the final layout resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Target {
    /// An offset in the original contract: a `JUMPDEST`, or a byte of
    /// a data region.
    Orig(u64),
    /// A label made for generated code.
    Fresh(u32),
    /// The end of the laid-out code: its size.
    End,
}

/// One unit of laid-out code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Piece {
    /// Instruction bytes with no code references.
    Bytes(Vec<u8>),
    /// Defines a label at the current position.
    Label(Target),
    /// `PUSH<width>` of a label's final offset. `fixed` pushes were
    /// also used as plain numbers: the layout refuses to move them.
    Push {
        width: u8,
        target: Target,
        fixed: bool,
    },
    /// A data region; `orig` is its original offset and `orig_len` its
    /// original size (an embedded contract an edit resized differs).
    Data {
        orig: u64,
        orig_len: u64,
        bytes: Vec<u8>,
    },
    /// The original instruction at this offset starts here.
    Mark(u64),
}

/// A symbolic stack value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Sym {
    /// The item `k` deep (0 = top) when the statement started.
    Slot(usize),
    /// Minimal big-endian constant.
    Const(Vec<u8>),
    /// A code / data offset, pushed with the given width.
    Label(Target, u8),
    /// Opcode applied to operands in pop order (`args[0]` on top).
    Op(u8, Vec<Sym>),
    /// `keccak256` of `key ‖ slot` (Vyper: `slot ‖ key`) through scratch
    /// memory: `(slot, key)`.
    Mapping(Box<Sym>, Box<Sym>),
    /// A result that can't be recomputed (a state read the replaced
    /// code made, or an opcode with effects); distinct per id.
    Opaque(usize),
}

impl Sym {
    pub(crate) fn konst(v: u64) -> Self {
        let b = v.to_be_bytes();
        let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        Sym::Const(b[first..].to_vec())
    }

    fn is_boolean(&self) -> bool {
        matches!(self, Sym::Op(LT | GT | EQ | ISZERO | 0x12 | 0x13, _))
    }
}

/// Generation options, from what the original contract already uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Opts {
    /// `PUSH0` is available (Shanghai+).
    pub push0: bool,
    /// `SHL` / `SHR` are available (Constantinople+).
    pub shifts: bool,
    /// Vyper layout: mapping slots hash `slot ‖ key`, not `key ‖ slot`.
    pub vyper: bool,
}

/// Why code couldn't be generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmitError(pub String);

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail<T>(msg: impl Into<String>) -> Result<T, EmitError> {
    Err(EmitError(msg.into()))
}

// ---------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------

/// Environment reads the lifter renders by name.
fn env_opcode(name: &str) -> Option<u8> {
    Some(match name {
        "this" => ADDRESS,
        "tx.origin" => 0x32,
        "msg.sender" => 0x33,
        "msg.value" => 0x34,
        "msg.data.length" => 0x36,
        "tx.gasprice" => 0x3a,
        "block.coinbase" => 0x41,
        "block.timestamp" => 0x42,
        "block.number" => 0x43,
        "block.prevrandao" | "block.difficulty" => 0x44,
        "block.gaslimit" => 0x45,
        "block.chainid" => 0x46,
        "block.basefee" => 0x48,
        "block.blobbasefee" => 0x4a,
        _ => return None,
    })
}

/// Opcodes callable by name in an expression: value-producing and
/// free of side effects (calls and creates are statements).
fn callable_opcode(name: &str) -> Option<u8> {
    let op = match name {
        "gasleft" => 0x5a,
        "keccak256" => KECCAK256,
        _ => opcode_by_name(name)?,
    };
    let info = &OPCODE_TABLE[op as usize];
    let effectful = matches!(op, 0xf0..=0xff | 0x58 | 0x5f..=0x9f);
    (info.pushes == 1 && info.imm_len == 0 && !effectful).then_some(op)
}

fn shl(value: Sym, shift: Sym, opts: Opts) -> Sym {
    if opts.shifts {
        Sym::Op(SHL, vec![shift, value])
    } else {
        Sym::Op(MUL, vec![value, Sym::Op(EXP, vec![Sym::konst(2), shift])])
    }
}

fn shr(value: Sym, shift: Sym, opts: Opts) -> Sym {
    if opts.shifts {
        Sym::Op(SHR, vec![shift, value])
    } else {
        Sym::Op(DIV, vec![value, Sym::Op(EXP, vec![Sym::konst(2), shift])])
    }
}

fn boolean(x: Sym) -> Sym {
    if x.is_boolean() {
        x
    } else {
        Sym::Op(ISZERO, vec![Sym::Op(ISZERO, vec![x])])
    }
}

/// `!x`, folding a double negation.
pub(crate) fn negate(x: Sym) -> Sym {
    match x {
        Sym::Op(ISZERO, mut a) if a[0].is_boolean() => a.pop().expect("one operand"),
        other => Sym::Op(ISZERO, vec![other]),
    }
}

/// The storage slot a place expression names: a storage variable
/// (`owner`), possibly indexed (`allowance[a][b]`). `None` when `e`
/// isn't a place.
pub(crate) fn lower_place(
    e: &EExpr,
    names: &dyn Fn(&str) -> Option<Sym>,
    opts: Opts,
) -> Result<Option<Sym>, EmitError> {
    Ok(match e {
        EExpr::Name(n) => names(&format!("&{n}")),
        EExpr::Index(base, key) => match lower_place(base, names, opts)? {
            Some(slot) => Some(Sym::Mapping(
                Box::new(slot),
                Box::new(lower_expr(key, names, opts)?),
            )),
            None => None,
        },
        _ => None,
    })
}

/// Lower a parsed expression. `names` resolves identifiers that
/// aren't environment reads: stack slots, parameters and storage
/// variables, whose root slot `names("&name")` gives.
#[allow(clippy::too_many_lines)]
pub(crate) fn lower_expr(
    e: &EExpr,
    names: &dyn Fn(&str) -> Option<Sym>,
    opts: Opts,
) -> Result<Sym, EmitError> {
    let rec = |x: &EExpr| lower_expr(x, names, opts);
    Ok(match e {
        EExpr::Num(b) => Sym::Const(b.clone()),
        EExpr::Str(s) => return fail(format!("string \"{s}\" is not a value")),
        EExpr::Name(n) => {
            if n == "msg.sig" {
                let word = Sym::Op(CALLDATALOAD, vec![Sym::konst(0)]);
                return Ok(shr(word, Sym::konst(224), opts));
            }
            if let Some(op) = env_opcode(n) {
                return Ok(Sym::Op(op, vec![]));
            }
            if let Some(fname) = n.strip_suffix(".selector") {
                return match crate::signatures::evm::selectors_named(fname).as_slice() {
                    [sel] => {
                        let mut word = sel.to_be_bytes().to_vec();
                        word.extend([0u8; 28]);
                        Ok(Sym::Const(word))
                    }
                    [] => fail(format!("unknown function `{fname}` in `{n}`")),
                    _ => fail(format!("`{fname}` is overloaded; write the selector")),
                };
            }
            if let Some(s) = names(n) {
                return Ok(s);
            }
            if let Some(hex) = n.strip_prefix("L_")
                && let Ok(addr) = u64::from_str_radix(hex, 16)
            {
                return Ok(Sym::Label(Target::Orig(addr), 2));
            }
            if let Some(slot) = names(&format!("&{n}")) {
                return Ok(Sym::Op(SLOAD, vec![slot]));
            }
            return fail(format!(
                "`{n}` isn't on the stack here (only names live at this statement can be used)"
            ));
        }
        EExpr::Unary(UnOp::Ref, x) => {
            return lower_place(x, names, opts)?.map_or_else(
                || fail("`&` applies to storage variables (`&balanceOf[k]`)"),
                Ok,
            );
        }
        EExpr::Unary(op, x) => {
            let x = rec(x)?;
            match op {
                UnOp::Not => negate(x),
                UnOp::BitNot => Sym::Op(NOT, vec![x]),
                UnOp::Neg => Sym::Op(SUB, vec![Sym::konst(0), x]),
                UnOp::Ref => unreachable!("handled above"),
            }
        }
        EExpr::Binary(op, a, b) => {
            let (a, b) = (rec(a)?, rec(b)?);
            let bin = |code: u8, a: Sym, b: Sym| Sym::Op(code, vec![a, b]);
            match op {
                BinOp::Add => bin(ADD, a, b),
                BinOp::Sub => bin(SUB, a, b),
                BinOp::Mul => bin(MUL, a, b),
                BinOp::Div => bin(DIV, a, b),
                BinOp::Mod => bin(MOD, a, b),
                BinOp::Exp => bin(EXP, a, b),
                BinOp::And => bin(AND, a, b),
                BinOp::Or => bin(OR, a, b),
                BinOp::Xor => bin(XOR, a, b),
                BinOp::Shl => shl(a, b, opts),
                BinOp::Shr => shr(a, b, opts),
                BinOp::Lt => bin(LT, a, b),
                BinOp::Gt => bin(GT, a, b),
                BinOp::Le => negate(bin(GT, a, b)),
                BinOp::Ge => negate(bin(LT, a, b)),
                BinOp::Eq => bin(EQ, a, b),
                BinOp::Ne => negate(bin(EQ, a, b)),
                BinOp::LogicAnd => bin(AND, boolean(a), boolean(b)),
                BinOp::LogicOr => boolean(bin(OR, a, b)),
            }
        }
        EExpr::Call(name, args) => {
            let arity = |n: usize| -> Result<(), EmitError> {
                if args.len() == n {
                    Ok(())
                } else {
                    fail(format!(
                        "`{name}` takes {n} argument(s), got {}",
                        args.len()
                    ))
                }
            };
            match name.as_str() {
                "address" if args == &[EExpr::Name("this".into())] => Sym::Op(ADDRESS, vec![]),
                "address" => {
                    arity(1)?;
                    Sym::Op(AND, vec![rec(&args[0])?, Sym::Const(vec![0xff; 20])])
                }
                "bool" => {
                    arity(1)?;
                    boolean(rec(&args[0])?)
                }
                "mapping" => {
                    arity(2)?;
                    Sym::Mapping(Box::new(rec(&args[0])?), Box::new(rec(&args[1])?))
                }
                _ => {
                    let Some(op) = callable_opcode(name) else {
                        return fail(format!(
                            "`{name}(…)` can't be compiled from text (internal calls, external calls and unknown functions keep their bytes)"
                        ));
                    };
                    arity(OPCODE_TABLE[op as usize].pops.into())?;
                    let args: Result<Vec<Sym>, EmitError> = args.iter().map(rec).collect();
                    Sym::Op(op, args?)
                }
            }
        }
        EExpr::Index(..) => match lower_place(e, names, opts)? {
            Some(slot) => Sym::Op(SLOAD, vec![slot]),
            None => {
                return fail(
                    "only storage variables can be indexed; write `sload(mapping(slot, k))`",
                );
            }
        },
    })
}

// ---------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------

/// Generates code while modelling the stack.
pub(crate) struct Emitter<'f> {
    pub pieces: Vec<Piece>,
    /// Bottom → top.
    model: Vec<Sym>,
    opts: Opts,
    fresh: &'f mut u32,
    opaque: usize,
}

impl<'f> Emitter<'f> {
    /// An emitter whose stack starts as `Slot(depth-1) … Slot(0)`.
    pub(crate) fn new(opts: Opts, fresh: &'f mut u32, depth: usize) -> Self {
        Self {
            pieces: Vec::new(),
            model: (0..depth).rev().map(Sym::Slot).collect(),
            opts,
            fresh,
            opaque: usize::MAX / 2,
        }
    }

    /// Reset the top items to `items` (bottom first): the stack as it
    /// was at a jump into the code that follows.
    pub(crate) fn reset_top(&mut self, items: &[Sym]) -> Result<(), EmitError> {
        let Some(start) = self.model.len().checked_sub(items.len()) else {
            return fail("stack underflow in generated code");
        };
        self.model.truncate(start);
        self.model.extend_from_slice(items);
        Ok(())
    }

    /// Where control merges, items that differ from `before` (bottom
    /// first) hold one of several values: model them as unknown.
    pub(crate) fn forget_changes(&mut self, before: &[Sym]) -> Result<(), EmitError> {
        let Some(start) = self.model.len().checked_sub(before.len()) else {
            return fail("stack underflow in generated code");
        };
        for (i, b) in before.iter().enumerate() {
            if self.model[start + i] != *b {
                self.opaque += 1;
                self.model[start + i] = Sym::Opaque(self.opaque);
            }
        }
        Ok(())
    }

    /// Whether `s` is on the modelled stack or needs no stack item.
    pub(crate) fn holds(&self, s: &Sym) -> bool {
        fn free(s: &Sym) -> bool {
            match s {
                Sym::Const(_) | Sym::Label(..) => true,
                Sym::Op(_, a) => a.iter().all(free),
                Sym::Mapping(a, b) => free(a) && free(b),
                Sym::Slot(_) | Sym::Opaque(_) => false,
            }
        }
        free(s) || self.model.contains(s)
    }

    /// After a `JUMP` into an internal function: it took the top
    /// `consumed` items (its frame) and left `results` (bottom first).
    pub(crate) fn returned(&mut self, consumed: usize, results: &[Sym]) -> Result<(), EmitError> {
        let Some(start) = self.model.len().checked_sub(consumed) else {
            return fail("stack underflow in generated code");
        };
        self.model.truncate(start);
        self.model.extend_from_slice(results);
        Ok(())
    }

    /// A value distinct from every other.
    pub(crate) fn fresh_opaque(&mut self) -> Sym {
        self.opaque += 1;
        Sym::Opaque(self.opaque)
    }

    /// The top `n` modelled items, bottom first.
    pub(crate) fn top(&self, n: usize) -> Result<Vec<Sym>, EmitError> {
        let Some(start) = self.model.len().checked_sub(n) else {
            return fail("statement reaches deeper into the stack than modelled");
        };
        Ok(self.model[start..].to_vec())
    }

    pub(crate) fn fresh_label(&mut self) -> Target {
        *self.fresh += 1;
        Target::Fresh(*self.fresh)
    }

    fn byte(&mut self, b: u8) {
        if let Some(Piece::Bytes(v)) = self.pieces.last_mut() {
            v.push(b);
        } else {
            self.pieces.push(Piece::Bytes(vec![b]));
        }
    }

    /// Define `t` here, as a `JUMPDEST`.
    pub(crate) fn place(&mut self, t: Target) {
        self.pieces.push(Piece::Label(t));
        self.byte(JUMPDEST);
    }

    /// Emit `opcode` (no immediate), updating the model; a pushed
    /// result is `result`, or an opaque value.
    pub(crate) fn op(&mut self, opcode: u8, result: Option<Sym>) -> Result<(), EmitError> {
        let info = &OPCODE_TABLE[opcode as usize];
        let pops = usize::from(info.pops);
        if self.model.len() < pops {
            return fail("stack underflow in generated code");
        }
        self.model.truncate(self.model.len() - pops);
        if info.pushes == 1 {
            let r = result.unwrap_or_else(|| {
                self.opaque += 1;
                Sym::Opaque(self.opaque)
            });
            self.model.push(r);
        }
        self.byte(opcode);
        Ok(())
    }

    pub(crate) fn push_const(&mut self, bytes: &[u8]) {
        let first = bytes.iter().position(|&x| x != 0).unwrap_or(bytes.len());
        let b = &bytes[first..];
        if b.is_empty() && self.opts.push0 {
            self.byte(PUSH0);
        } else {
            let b: &[u8] = if b.is_empty() { &[0] } else { b };
            self.byte(0x5f + b.len() as u8);
            for &x in b {
                self.byte(x);
            }
        }
        self.model.push(Sym::Const(b.to_vec()));
    }

    pub(crate) fn push_label(&mut self, target: Target, width: u8) {
        self.pieces.push(Piece::Push {
            width,
            target,
            fixed: false,
        });
        self.model.push(Sym::Label(target, width));
    }

    /// Depth from the top of the nearest item equal to `s`.
    fn find(&self, s: &Sym) -> Option<usize> {
        self.model.iter().rev().position(|x| x == s)
    }

    fn dup(&mut self, depth: usize) -> Result<(), EmitError> {
        if depth >= 16 {
            return fail("value is more than 16 items deep in the stack");
        }
        let v = self.model[self.model.len() - 1 - depth].clone();
        self.byte(0x80 + depth as u8);
        self.model.push(v);
        Ok(())
    }

    fn swap(&mut self, n: usize) -> Result<(), EmitError> {
        if !(1..=16).contains(&n) || n >= self.model.len() {
            return fail("stack rearrangement reaches more than 16 items deep");
        }
        let len = self.model.len();
        self.model.swap(len - 1, len - 1 - n);
        self.byte(0x8f + n as u8);
        Ok(())
    }

    /// Push the value of `s`.
    pub(crate) fn value(&mut self, s: &Sym) -> Result<(), EmitError> {
        if let Some(d) = self.find(s)
            && d < 16
        {
            return self.dup(d);
        }
        match s {
            Sym::Slot(_) => {
                fail("a value the statement needs is no longer on the stack (consumed or too deep)")
            }
            Sym::Opaque(_) => fail(
                "the replaced code leaves a state-read result on the stack that the edit can't recompute",
            ),
            Sym::Const(b) => {
                self.push_const(b);
                Ok(())
            }
            Sym::Label(t, w) => {
                self.push_label(*t, *w);
                Ok(())
            }
            Sym::Op(op, args) => {
                for a in args.iter().rev() {
                    self.value(a)?;
                }
                self.op(*op, Some(s.clone()))
            }
            Sym::Mapping(slot, key) => {
                let (lo, hi) = if self.opts.vyper {
                    (slot, key)
                } else {
                    (key, slot)
                };
                // Both halves first: either may itself hash through
                // the same scratch words.
                self.value(hi)?;
                self.value(lo)?;
                self.push_const(&[]);
                self.op(MSTORE, None)?;
                self.push_const(&[0x20]);
                self.op(MSTORE, None)?;
                self.push_const(&[0x40]);
                self.push_const(&[]);
                self.op(KECCAK256, Some(s.clone()))
            }
        }
    }

    /// Replace the top `consumed` items with `goal` (bottom first).
    pub(crate) fn materialize(&mut self, consumed: usize, goal: &[Sym]) -> Result<(), EmitError> {
        let Some(base) = self.model.len().checked_sub(consumed) else {
            return fail("statement reaches deeper into the stack than modelled");
        };
        // Items that stay where they are.
        let mut keep = 0;
        while keep < consumed && keep < goal.len() && self.model[base + keep] == goal[keep] {
            keep += 1;
        }
        let garbage = consumed - keep;
        let fresh = &goal[keep..];
        for g in fresh {
            self.value(g)?;
        }
        // Sort the region (garbage, then the fresh items) into place:
        // `tags[i]` is the goal index of the item at region slot `i`.
        let m = fresh.len();
        let mut tags: Vec<Option<usize>> =
            (0..garbage).map(|_| None).chain((0..m).map(Some)).collect();
        loop {
            let h = tags.len();
            if h == m && tags.iter().enumerate().all(|(i, t)| *t == Some(i)) {
                break;
            }
            match tags[h - 1] {
                None => {
                    self.op(POP, None)?;
                    tags.pop();
                }
                Some(j) if j != h - 1 => {
                    self.swap(h - 1 - j)?;
                    tags.swap(h - 1, j);
                }
                Some(_) => {
                    let i = (0..h)
                        .find(|&i| tags[i] != Some(i))
                        .expect("unsorted region has a misplaced slot");
                    self.swap(h - 1 - i)?;
                    tags.swap(h - 1, i);
                }
            }
        }
        Ok(())
    }

    /// `JUMPI` to `target` when `cond`, after laying out `goal` below
    /// it (see [`Self::materialize`]).
    pub(crate) fn cond_jump(
        &mut self,
        consumed: usize,
        goal: &[Sym],
        cond: Sym,
        target: Target,
        width: u8,
    ) -> Result<(), EmitError> {
        let mut g = goal.to_vec();
        g.push(cond);
        self.materialize(consumed, &g)?;
        self.push_label(target, width);
        self.op(JUMPI, None)
    }

    /// `mstore(offset, value)`.
    pub(crate) fn mstore(&mut self, offset: &Sym, value: &Sym) -> Result<(), EmitError> {
        self.value(value)?;
        self.value(offset)?;
        self.op(MSTORE, None)
    }

    /// Store `words` at `0x0, 0x20, …` and halt with `opcode`
    /// (`RETURN` / `REVERT`) over them.
    pub(crate) fn halt_words(&mut self, words: &[Sym], opcode: u8) -> Result<(), EmitError> {
        // Evaluate everything before memory is touched.
        for w in words {
            self.value(w)?;
        }
        for k in (0..words.len()).rev() {
            self.value(&Sym::konst(32 * k as u64))?;
            self.op(MSTORE, None)?;
        }
        self.halt_mem(&Sym::konst(0), &Sym::konst(32 * words.len() as u64), opcode)
    }

    /// `RETURN` / `REVERT` of `memory[offset .. offset + len]`.
    pub(crate) fn halt_mem(
        &mut self,
        offset: &Sym,
        len: &Sym,
        opcode: u8,
    ) -> Result<(), EmitError> {
        self.value(len)?;
        self.value(offset)?;
        self.op(opcode, None)
    }

    pub(crate) fn ret(&mut self, words: &[Sym]) -> Result<(), EmitError> {
        self.halt_words(words, RETURN)
    }

    /// `revert(0, 0)`.
    pub(crate) fn revert_empty(&mut self) -> Result<(), EmitError> {
        self.halt_mem(&Sym::konst(0), &Sym::konst(0), REVERT)
    }

    /// `revert(Error(reason))`, the ABI encoding of a string reason.
    pub(crate) fn revert_reason(&mut self, reason: &str) -> Result<(), EmitError> {
        let data = reason.as_bytes();
        let mut sel = ERROR_SELECTOR.to_be_bytes().to_vec();
        sel.extend([0u8; 28]);
        self.mstore(&Sym::konst(0), &Sym::Const(sel))?;
        self.mstore(&Sym::konst(4), &Sym::konst(0x20))?;
        self.mstore(&Sym::konst(0x24), &Sym::konst(data.len() as u64))?;
        for (k, chunk) in data.chunks(32).enumerate() {
            let mut word = chunk.to_vec();
            word.resize(32, 0);
            self.mstore(&Sym::konst(0x44 + 32 * k as u64), &Sym::Const(word))?;
        }
        let len = 0x44 + 32 * data.len().div_ceil(32) as u64;
        self.halt_mem(&Sym::konst(0), &Sym::konst(len), REVERT)
    }

    /// `revert(Panic(code))`.
    pub(crate) fn revert_panic(&mut self, code: &Sym) -> Result<(), EmitError> {
        let mut sel = PANIC_SELECTOR.to_be_bytes().to_vec();
        sel.extend([0u8; 28]);
        self.value(code)?;
        self.mstore(&Sym::konst(0), &Sym::Const(sel))?;
        self.push_const(&[4]);
        self.op(MSTORE, None)?;
        self.halt_mem(&Sym::konst(0), &Sym::konst(0x24), REVERT)
    }

    /// `LOGn` of `data` words (written at the free-memory pointer,
    /// which isn't bumped — as solc does) with `topics`.
    pub(crate) fn log(&mut self, topics: &[Sym], data: &[Sym]) -> Result<(), EmitError> {
        let fmp = Sym::Op(MLOAD, vec![Sym::konst(0x40)]);
        for (k, w) in data.iter().enumerate() {
            let at = if k == 0 {
                fmp.clone()
            } else {
                Sym::Op(ADD, vec![Sym::konst(32 * k as u64), fmp.clone()])
            };
            self.mstore(&at, w)?;
        }
        for t in topics.iter().rev() {
            self.value(t)?;
        }
        self.value(&Sym::konst(32 * data.len() as u64))?;
        self.value(&fmp)?;
        self.op(0xa0 + topics.len() as u8, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translate::compile::evm_expr::parse_expr;

    const OPTS: Opts = Opts {
        push0: true,
        shifts: true,
        vyper: false,
    };

    fn bytes(pieces: &[Piece]) -> Vec<u8> {
        pieces
            .iter()
            .flat_map(|p| match p {
                Piece::Bytes(b) => b.clone(),
                _ => panic!("unexpected {p:?}"),
            })
            .collect()
    }

    #[test]
    fn dups_live_slots_and_folds_comparisons() {
        let mut fresh = 0;
        let mut em = Emitter::new(OPTS, &mut fresh, 4);
        let names = |n: &str| (n == "v1").then_some(Sym::Slot(1));
        let e = lower_expr(&parse_expr("v1 >= 0x5").unwrap(), &names, OPTS).unwrap();
        em.value(&e).unwrap();
        // PUSH1 5; DUP3; LT; ISZERO
        assert_eq!(bytes(&em.pieces), [0x60, 0x05, 0x82, 0x10, 0x15]);
    }

    #[test]
    fn materialize_drops_and_reorders() {
        let mut fresh = 0;
        let mut em = Emitter::new(OPTS, &mut fresh, 4);
        // [s3 s2 s1 s0] → [s3 s0 s1]
        em.materialize(3, &[Sym::Slot(0), Sym::Slot(1)]).unwrap();
        assert_eq!(
            em.top(3).unwrap(),
            [Sym::Slot(3), Sym::Slot(0), Sym::Slot(1)]
        );
        let mut em = Emitter::new(OPTS, &mut fresh, 3);
        em.materialize(2, &[]).unwrap();
        assert_eq!(bytes(&em.pieces), [POP, POP]);
    }

    #[test]
    fn unknown_names_and_calls_fail() {
        let names = |_: &str| None;
        assert!(lower_expr(&parse_expr("v9 + 1").unwrap(), &names, OPTS).is_err());
        assert!(lower_expr(&parse_expr("sub_0440(1)").unwrap(), &names, OPTS).is_err());
        assert!(lower_expr(&parse_expr("call(1,2,3,4,5,6,7)").unwrap(), &names, OPTS).is_err());
        assert!(lower_expr(&parse_expr("sload(1, 2)").unwrap(), &names, OPTS).is_err());
        // Storage variables come through `names("&x")`.
        let storage = |n: &str| (n == "&owner").then(|| Sym::konst(5));
        assert_eq!(
            lower_expr(&parse_expr("owner").unwrap(), &storage, OPTS).unwrap(),
            Sym::Op(SLOAD, vec![Sym::konst(5)])
        );
        assert_eq!(
            lower_expr(&parse_expr("&owner[0x1]").unwrap(), &storage, OPTS).unwrap(),
            Sym::Mapping(Box::new(Sym::konst(5)), Box::new(Sym::konst(1)))
        );
        assert!(lower_expr(&parse_expr("x[1]").unwrap(), &storage, OPTS).is_err());
    }
}

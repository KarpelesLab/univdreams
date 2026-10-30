//! Lift EVM basic blocks into statement-level `.ud`.
//!
//! Each block is executed over a symbolic stack:
//!
//! * pure operations fold into expressions (`msg.sig == 0xa9059cbb`,
//!   `arg0 + 0x20`);
//! * reads of mutable state (`sload`, `mload`, `call`, `gasleft()`, …)
//!   are bound to a stack-slot variable on the spot (`v5 = sload(v2)`),
//!   so later stores can't reorder them in the reader's eyes;
//! * side effects become calls (`sstore(k, v)`, `log3(…)`,
//!   `revert(0x0, 0x0)`), internal calls become `v4 = sub_0440(arg0)`,
//!   and internal returns `return v4;`;
//! * values a block leaves on the stack are written back to their
//!   slot names (`v3 = v3 + 0x1`), so blocks read like code over
//!   variables.
//!
//! Stack slots are named per frame (see [`super::evm_cfg`]): in an
//! internal function slot 0 is `ret`, then `arg0..`, then `vN`; in
//! the root frame every slot is `vN`. Blocks with no consistent depth
//! fall back to `sN`, the Nth item from the top at block entry.
//!
//! Each block hands what it knows about its exit stack to successors
//! whose predecessors all agree: constants, ABI parameters and
//! `msg.*` values read in place of their slot names, and internal
//! calls return what the callee's summary (from an earlier analysis
//! pass) says — via-IR's ABI-decoder helpers return parameters, and a
//! public getter's accessor returns the storage it names.
//!
//! External calls fold the ABI encoding of their input — a selector
//! and static words stored at the free-memory pointer (or Vyper's
//! fixed buffers) — into `t.call(IERC20.transfer(a, n))`, and into the
//! high-level `IERC20(t).transfer(a, n)` once the check that re-raises
//! a failure is folded in too. A block ending in a guard that falls
//! into a failure block, when its continuation (next in the slice)
//! makes a call, is lifted together with that continuation, so solc's
//! setup / `extcodesize` check / call read as one statement.
//!
//! A forward `JUMPI` whose fall-through run of blocks is entered only
//! from that `JUMPI` becomes `if (!cond) { … }`; any other jump stays
//! explicit as `jump(L_xxxx)`.
//!
//! Every statement pins the bytes of the instructions it stands for,
//! in order, so lowering an unedited file reproduces the code exactly.
//! The lowerer re-lifts those bytes to spot edited statements and
//! compiles them from their text (`compile::evm_edit`), using the
//! stack-slot names recorded in a [`LiftTrace`].

// Stack depths and positions are bounded by the EVM's 1024-item
// limit, so the usize/i64 conversions between them can't wrap.
#![allow(clippy::cast_possible_wrap)]

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use crate::arch::evm::{DecodedInsn, OPCODE_TABLE};
use crate::ast::Stmt;
use crate::signatures::evm::event_by_topic;
use crate::translate::decompile::evm_cfg::{BlockDepth, Cfg, FrameId, JumpRole, Term};

/// DUPs of expressions at least this large bind a variable instead of
/// duplicating the text.
const DUP_INLINE_MAX_NODES: usize = 2;

/// Operation standing for a value analysis can't follow (an entry slot
/// no predecessor told us about). Never rendered.
const UNKNOWN: &str = "?";

/// Wraps a value an internal call returned, known from the callee's
/// summary: analysis sees through it, but the text keeps naming the
/// variable the call assigned.
const RESULT: &str = "result";

/// A free-memory-pointer value in resolved form, `mptr(id)`: reads of
/// `mload(0x40)` with no `mstore(0x40, …)` between them share an id,
/// so buffers built at the pointer can be followed across statements
/// (and blocks, through the stack values blocks hand on). Never
/// rendered.
const MPTR: &str = "mptr";

/// Resolved values larger than this are treated as [`UNKNOWN`].
const RESOLVE_MAX_NODES: usize = 48;
/// Stack items a [`LiftTrace`] snapshot names (DUP16 / SWAP16 reach
/// plus one).
const TRACE_DEPTH: usize = 17;

/// Names of one stack item at an instruction boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotNames {
    /// The variable the item holds (`v6`, `arg1`, `param0`, `t2`,
    /// `L_00b7`), if it is a plain variable rather than a pending
    /// expression.
    pub var: Option<String>,
    /// The name of the frame position the item sits in, as used for
    /// slot write-backs (`v4, v8 = …`).
    pub slot: Option<String>,
}

/// Stack names the lifter saw, for compiling edited statements back
/// against the same slots. Snapshots list items top first.
#[derive(Debug, Default)]
pub(crate) struct LiftTrace {
    /// Before each lifted instruction, by instruction index.
    pub before: HashMap<usize, Vec<SlotNames>>,
    /// After the last instruction of a block that falls through, keyed
    /// by the index one past it.
    pub fall_end: HashMap<usize, Vec<SlotNames>>,
    /// The storage-variable names the text uses.
    pub storage: StorageNames,
    /// Names of each external function's ABI head words, by entry.
    pub params: HashMap<u64, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    /// Big-endian bytes of a pushed constant.
    Const(Vec<u8>),
    Var(String),
    /// Operation with operands in EVM pop order (`args[0]` was on
    /// top). Zero-operand ops are environment reads.
    Op(&'static str, Vec<Expr>),
}

impl Expr {
    fn nodes(&self) -> usize {
        match self {
            Expr::Op(_, args) => 1 + args.iter().map(Expr::nodes).sum::<usize>(),
            _ => 1,
        }
    }

    fn mentions(&self, name: &str) -> bool {
        match self {
            Expr::Var(v) => v == name,
            Expr::Op(_, args) => args.iter().any(|a| a.mentions(name)),
            Expr::Const(_) => false,
        }
    }

    fn count(&self, name: &str) -> usize {
        match self {
            Expr::Var(v) => usize::from(v == name),
            Expr::Op(_, args) => args.iter().map(|a| a.count(name)).sum(),
            Expr::Const(_) => 0,
        }
    }

    fn substitute(&self, name: &str, with: &Expr) -> Expr {
        match self {
            Expr::Var(v) if v == name => with.clone(),
            Expr::Op(op, args) => simplify(Expr::Op(
                op,
                args.iter().map(|a| a.substitute(name, with)).collect(),
            )),
            other => other.clone(),
        }
    }

    fn const_value(&self) -> Option<u64> {
        let Expr::Const(b) = self else { return None };
        let significant: Vec<u8> = b.iter().copied().skip_while(|&x| x == 0).collect();
        (significant.len() <= 8).then(|| {
            significant
                .iter()
                .fold(0u64, |a, &x| (a << 8) | u64::from(x))
        })
    }

    fn is_const_bytes(&self, pred: impl Fn(&[u8]) -> bool) -> bool {
        matches!(self, Expr::Const(b) if pred(strip(b)))
    }
}

fn strip(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[first..]
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

fn infix_symbol(op: &str) -> Option<&'static str> {
    Some(match op {
        "add" => "+",
        "sub" => "-",
        "mul" => "*",
        "div" => "/",
        "mod" => "%",
        "exp" => "**",
        "and" => "&",
        "or" => "|",
        "xor" => "^",
        "shl" => "<<",
        "shr" => ">>",
        "lt" => "<",
        "gt" => ">",
        "eq" => "==",
        "ne" => "!=",
        "le" => "<=",
        "ge" => ">=",
        _ => return None,
    })
}

/// Rewrite well-known compiler idioms into their source-level form.
fn simplify(e: Expr) -> Expr {
    let Expr::Op(op, args) = e else { return e };
    let args: Vec<Expr> = args.into_iter().map(simplify).collect();
    let is_calldata0 = |x: &Expr| matches!(x, Expr::Op("calldataload", a) if a.len() == 1 && a[0].const_value() == Some(0));
    // A low-bytes mask, also as solc ≥0.8 computes it: `(1 << n) - 1`.
    let is_mask = |x: &Expr, bytes: usize| {
        x.is_const_bytes(|b| b.len() == bytes && b.iter().all(|&v| v == 0xff))
            || matches!(x, Expr::Op("sub", ab) if ab.len() == 2
                && ab[1].const_value() == Some(1)
                && matches!(&ab[0], Expr::Op("shl", sh) if sh.len() == 2
                    && sh[0].const_value() == Some(8 * bytes as u64)
                    && sh[1].const_value() == Some(1)))
    };
    match (op, args.as_slice()) {
        // Selector extraction: `shr(224, calldataload(0))`, or the
        // pre-Constantinople `div(calldataload(0), 2**224)`.
        ("shr", [s, x]) if s.const_value() == Some(224) && is_calldata0(x) => {
            Expr::Op("msg.sig", vec![])
        }
        ("div", [x, d])
            if is_calldata0(x)
                && d.is_const_bytes(|b| {
                    b.len() == 29 && b[0] == 1 && b[1..].iter().all(|&v| v == 0)
                }) =>
        {
            Expr::Op("msg.sig", vec![])
        }
        ("and", [a, b]) if is_mask(b, 4) && matches!(a, Expr::Op("msg.sig", _)) => a.clone(),
        ("and", [a, b]) if is_mask(a, 4) && matches!(b, Expr::Op("msg.sig", _)) => b.clone(),
        // `x + ~(n-1)` is `x - n` in two's complement.
        ("add", [x, Expr::Const(c)] | [Expr::Const(c), x])
            if inverted_small(c).is_some_and(|inv| inv < u64::MAX) =>
        {
            let n = inverted_small(c).unwrap() + 1;
            Expr::Op(
                "sub",
                vec![x.clone(), Expr::Const(n.to_be_bytes().to_vec())],
            )
        }
        ("and", [a, b]) if is_mask(b, 20) || is_mask(a, 20) => {
            let x = if is_mask(b, 20) { a } else { b };
            if matches!(x, Expr::Op("address", _)) {
                x.clone()
            } else {
                Expr::Op("address", vec![x.clone()])
            }
        }
        // Double negation normalises to a boolean; already-boolean
        // operands need no wrapper.
        ("iszero", [Expr::Op("iszero", inner)]) => {
            let x = &inner[0];
            if is_boolean(x) {
                x.clone()
            } else {
                Expr::Op("bool", vec![x.clone()])
            }
        }
        ("iszero", [Expr::Op(cmp, ab)]) if ab.len() == 2 && inverse_cmp(cmp).is_some() => {
            simplify(Expr::Op(inverse_cmp(cmp).unwrap(), ab.clone()))
        }
        ("iszero", [Expr::Op("bool", x)]) => Expr::Op("iszero", x.clone()),
        // Constants read better on the right of a comparison.
        (_, [a, b])
            if mirror_cmp(op).is_some()
                && matches!(a, Expr::Const(_))
                && !matches!(b, Expr::Const(_)) =>
        {
            Expr::Op(mirror_cmp(op).unwrap(), vec![b.clone(), a.clone()])
        }
        _ => fold(op, &args).unwrap_or(Expr::Op(op, args)),
    }
}

fn is_boolean(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Op(
            "bool" | "iszero" | "eq" | "ne" | "lt" | "gt" | "le" | "ge" | "slt" | "sgt",
            _
        )
    )
}

/// Constant-fold an operation on two small constants.
fn fold(op: &str, args: &[Expr]) -> Option<Expr> {
    let [a, b] = args else { return None };
    let (a, b) = (u128::from(a.const_value()?), u128::from(b.const_value()?));
    let r = match op {
        "add" => a.checked_add(b)?,
        "sub" => a.checked_sub(b)?,
        "mul" => a.checked_mul(b)?,
        "div" => a.checked_div(b)?,
        "mod" => a.checked_rem(b)?,
        "and" => a & b,
        "or" => a | b,
        "xor" => a ^ b,
        "shl" if a < 64 => b.checked_shl(u32::try_from(a).ok()?)?,
        "shr" if a < 128 => b >> a,
        "exp" => a.checked_pow(u32::try_from(b).ok()?)?,
        _ => return None,
    };
    let r = u64::try_from(r).ok()?;
    Some(Expr::Const(r.to_be_bytes().to_vec()))
}

/// `!c` for a 256-bit constant whose complement is small: masks such
/// as `0xff…e0` (`~0x1f`) and negative numbers (`0xff…fc` = `~0x3`).
fn inverted_small(b: &[u8]) -> Option<u64> {
    let b = strip(b);
    if b.len() != 32 || b[..24].iter().any(|&x| x != 0xff) {
        return None;
    }
    Some(!u64::from_be_bytes(b[24..].try_into().ok()?))
}

fn hex_const(b: &[u8]) -> String {
    if let Some(inv) = inverted_small(b) {
        return format!("~0x{inv:x}");
    }
    let b = strip(b);
    if b.is_empty() {
        return "0x0".into();
    }
    // `selector << 224`, how 4-byte selectors are put in place for
    // revert payloads and external calls.
    if b.len() >= 29 && b[b.len() - 28..].iter().all(|&x| x == 0) {
        let mut sel = [0u8; 4];
        sel[4 - (b.len() - 28)..].copy_from_slice(&b[..b.len() - 28]);
        let sel = u32::from_be_bytes(sel);
        // A known selector reads as Solidity's left-aligned `bytes4`.
        if let Some(name) =
            crate::signatures::evm::function_by_selector(sel).and_then(|sig| sig.split('(').next())
        {
            return format!("{name}.selector");
        }
        return format!("(0x{sel:08x} << 0xe0)");
    }
    // Selector-sized values keep their leading zero nibble so they
    // read as the 8-digit selectors they usually are.
    if b.len() == 4 {
        return format!("0x{:08x}", u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    }
    let mut s = String::from("0x");
    for (i, x) in b.iter().enumerate() {
        if i == 0 {
            let _ = write!(s, "{x:x}");
        } else {
            let _ = write!(s, "{x:02x}");
        }
    }
    s
}

fn is_infix(e: &Expr) -> bool {
    matches!(e, Expr::Op(op, args) if args.len() == 2 && infix_symbol(op).is_some())
}

fn render_raw(e: &Expr) -> String {
    match e {
        Expr::Const(b) => hex_const(b),
        Expr::Var(v) => v.clone(),
        Expr::Op(op, args) if args.is_empty() => {
            if op.contains('.') || op.contains('(') {
                (*op).to_string()
            } else {
                format!("{op}()")
            }
        }
        Expr::Op(op, args) if args.len() == 2 && infix_symbol(op).is_some() => {
            let sym = infix_symbol(op).unwrap();
            // EVM shifts take the shift amount first.
            let (l, r) = if matches!(*op, "shl" | "shr") {
                (&args[1], &args[0])
            } else {
                (&args[0], &args[1])
            };
            format!("{} {sym} {}", render_child(l), render_child(r))
        }
        // Named storage: `balanceOf[k]`, and the slot of one as
        // `&balanceOf[k]`.
        Expr::Op("index", args) if args.len() == 2 => {
            format!("{}[{}]", render_child(&args[0]), render_raw(&args[1]))
        }
        Expr::Op("slot", args) if args.len() == 1 => format!("&{}", render_child(&args[0])),
        Expr::Op("iszero", args) if args.len() == 1 => format!("!{}", render_child(&args[0])),
        Expr::Op("not", args) if args.len() == 1 => format!("~{}", render_child(&args[0])),
        Expr::Op(op, args) => {
            let parts: Vec<String> = args.iter().map(render_raw).collect();
            format!("{op}({})", parts.join(", "))
        }
    }
}

fn render_child(e: &Expr) -> String {
    if is_infix(e) {
        format!("({})", render_raw(e))
    } else {
        render_raw(e)
    }
}

/// Top-level rendering (conditions).
fn render(e: &Expr) -> String {
    render_raw(&name_storage(simplify(e.clone())))
}

/// Rendering for a call argument or tuple element: no bare spaces at
/// the top level, so infix expressions get parentheses.
fn render_arg(e: &Expr) -> String {
    render_child(&name_storage(simplify(e.clone())))
}

/// Rendering for the right-hand side of an assignment: comparisons
/// are parenthesised so their `=` can't be mistaken for the
/// assignment's.
fn render_rhs(e: &Expr) -> String {
    let s = name_storage(simplify(e.clone()));
    match &s {
        Expr::Op(op, args) if args.len() == 2 && matches!(*op, "eq" | "ne" | "le" | "ge") => {
            format!("({})", render_raw(&s))
        }
        _ => render_raw(&s),
    }
}

// ---------------------------------------------------------------------
// Storage-variable names
// ---------------------------------------------------------------------

/// Storage slot (big-endian, leading zeros stripped) → the name of
/// the state variable that lives there.
pub(crate) type StorageNames = HashMap<Vec<u8>, String>;

thread_local! {
    /// Names in effect while [`lift_ranges`] renders its final pass.
    /// Rendering is spread over free functions; a scoped thread-local
    /// spares them all from taking the table as a parameter.
    static STORAGE_NAMES: RefCell<StorageNames> = RefCell::new(HashMap::new());
}

/// Installs a storage-name table for rendering until dropped.
struct StorageScope;

impl StorageScope {
    fn enter(names: StorageNames) -> Self {
        STORAGE_NAMES.with(|s| *s.borrow_mut() = names);
        StorageScope
    }
}

impl Drop for StorageScope {
    fn drop(&mut self) {
        STORAGE_NAMES.with(|s| s.borrow_mut().clear());
    }
}

/// `slot` as a named storage location — `totalSupply`,
/// `allowance[a][b]` — when its root slot has a name.
fn storage_ref(slot: &Expr, names: &StorageNames) -> Option<Expr> {
    match slot {
        Expr::Const(b) => names.get(strip(b)).map(|n| Expr::Var(n.clone())),
        Expr::Op("mapping", a) if a.len() == 2 => Some(Expr::Op(
            "index",
            vec![storage_ref(&a[0], names)?, name_storage_in(&a[1], names)],
        )),
        _ => None,
    }
}

fn name_storage_in(e: &Expr, names: &StorageNames) -> Expr {
    match e {
        Expr::Op("sload", a) if a.len() == 1 => storage_ref(&a[0], names)
            .unwrap_or_else(|| Expr::Op("sload", vec![name_storage_in(&a[0], names)])),
        Expr::Op("mapping", _) if storage_ref(e, names).is_some() => {
            Expr::Op("slot", vec![storage_ref(e, names).expect("checked")])
        }
        Expr::Op(op, a) => Expr::Op(op, a.iter().map(|x| name_storage_in(x, names)).collect()),
        other => other.clone(),
    }
}

/// Rewrite reads of named storage (`sload(mapping(0x3, k))` →
/// `balanceOf[k]`) and slot computations (`&balanceOf[k]`).
fn name_storage(e: Expr) -> Expr {
    STORAGE_NAMES.with(|s| {
        let names = s.borrow();
        if names.is_empty() {
            e
        } else {
            name_storage_in(&e, &names)
        }
    })
}

/// The named location an `sstore` to `slot` writes, if any.
fn storage_lvalue(slot: &Expr) -> Option<Expr> {
    STORAGE_NAMES.with(|s| storage_ref(&simplify(slot.clone()), &s.borrow()))
}

/// `e` as `(base, offset)`: a constant (empty base) or a variable /
/// free-memory-pointer read plus a constant. Bound variables are
/// looked through, so `v5 = 0x20 + v3` resolves against `v3`.
fn lin(e: &Expr, bindings: &HashMap<String, Expr>, depth: u8) -> Option<(String, u64)> {
    if depth > 8 {
        return None;
    }
    match e {
        Expr::Const(_) => Some((String::new(), e.const_value()?)),
        Expr::Var(n) => match bindings.get(n) {
            Some(Expr::Op("fmp", k)) => Some((format!("fmp{}", k[0].const_value()?), 0)),
            Some(b) => lin(b, bindings, depth + 1).or_else(|| Some((n.clone(), 0))),
            None => Some((n.clone(), 0)),
        },
        Expr::Op("add", ab) if ab.len() == 2 => {
            let (b1, o1) = lin(&ab[0], bindings, depth + 1)?;
            let (b2, o2) = lin(&ab[1], bindings, depth + 1)?;
            let base = match (b1.is_empty(), b2.is_empty()) {
                (_, true) => b1,
                (true, false) => b2,
                (false, false) => return None,
            };
            Some((base, o1.checked_add(o2)?))
        }
        Expr::Op(..) => None,
    }
}

/// `e` (a resolved value) as a base plus a constant offset: `(None,
/// c)` for a constant, `(Some(base), c)` for `base + c`, where `base`
/// is any other value analysis can follow. `(b + x) - (b + y)` is the
/// constant `x - y`.
fn rlin(e: &Expr) -> Option<(Option<Expr>, u64)> {
    match e {
        Expr::Const(_) => Some((None, e.const_value()?)),
        Expr::Op(RESULT, a) if a.len() == 1 => rlin(&a[0]),
        Expr::Op("add", ab) if ab.len() == 2 => {
            let (b1, o1) = rlin(&ab[0])?;
            let (b2, o2) = rlin(&ab[1])?;
            let ((base, None) | (None, base)) = (b1, b2) else {
                return None;
            };
            Some((base, o1.checked_add(o2)?))
        }
        Expr::Op("sub", ab) if ab.len() == 2 => {
            let (b1, o1) = rlin(&ab[0])?;
            let (b2, o2) = rlin(&ab[1])?;
            match (b1, b2) {
                (b, None) => Some((b, o1.checked_sub(o2)?)),
                (Some(x), Some(y)) if x == y => Some((None, o1.checked_sub(o2)?)),
                _ => None,
            }
        }
        _ if mentions_op(e, UNKNOWN) => None,
        _ => Some((Some(e.clone()), 0)),
    }
}

/// `e` with its free-memory-pointer reads of epoch `epoch` (`fmp(k)`
/// bindings) as `mload(0x40)`; `None` if it reads an older pointer.
fn replace_fmp(e: &Expr, epoch: &Expr) -> Option<Expr> {
    Some(match e {
        Expr::Op("fmp", k) => {
            if k.first() != Some(epoch) {
                return None;
            }
            Expr::Op("mload", vec![Expr::Const(vec![0x40])])
        }
        Expr::Op(op, args) => Expr::Op(
            op,
            args.iter()
                .map(|a| replace_fmp(a, epoch))
                .collect::<Option<_>>()?,
        ),
        other => other.clone(),
    })
}

/// The 4 bytes at byte `rel` of a resolved 32-byte word.
fn word_bytes4(e: &Expr, rel: u64) -> Option<u32> {
    let rel = usize::try_from(rel).ok()?;
    match e {
        Expr::Const(b) => {
            let b = strip(b);
            if b.len() > 32 || rel + 4 > 32 {
                return None;
            }
            let mut w = [0u8; 32];
            w[32 - b.len()..].copy_from_slice(b);
            Some(u32::from_be_bytes(w[rel..rel + 4].try_into().ok()?))
        }
        Expr::Op("shl", a) if rel == 0 && a.len() == 2 && a[0].const_value() == Some(224) => {
            u32::try_from(a[1].const_value()?).ok()
        }
        _ => None,
    }
}

/// Reads whose binding can't be dropped from the text: calls and
/// contract creation.
fn read_name_has_effects(op: &str) -> bool {
    matches!(
        op,
        "call" | "callcode" | "delegatecall" | "staticcall" | "create" | "create2" | FOLDED_CALL
    )
}

/// Binding of the variable a folded external call assigns (wrapping
/// the raw call): never inlined into later statements.
const FOLDED_CALL: &str = "xcall";

/// Whether `e` mentions a variable `pred` accepts.
fn mentions_var(e: &Expr, pred: &dyn Fn(&str) -> bool) -> bool {
    match e {
        Expr::Var(v) => pred(v),
        Expr::Op(_, args) => args.iter().any(|a| mentions_var(a, pred)),
        Expr::Const(_) => false,
    }
}

/// A resolved value that reads the same wherever it is shown:
/// constants, ABI parameters, call-wide environment values, and pure
/// operations on them.
fn stable_value(e: &Expr) -> bool {
    match e {
        Expr::Const(_) => true,
        Expr::Var(_) => is_param(e),
        Expr::Op(op, args) if args.is_empty() => shows_inline(e) || *op == "address(this)",
        Expr::Op(op, args) => {
            ((0..=0xff).any(|o| pure_name(o) == Some(op)) || matches!(*op, "address" | "bool"))
                && *op != "calldataload"
                && args.iter().all(stable_value)
        }
    }
}

fn mentions_op(e: &Expr, name: &str) -> bool {
    match e {
        Expr::Op(op, args) => *op == name || args.iter().any(|a| mentions_op(a, name)),
        _ => false,
    }
}

/// The selector in a `selector << 224` constant.
fn shifted_selector(e: &Expr) -> Option<u32> {
    let Expr::Const(b) = e else { return None };
    let b = strip(b);
    if b.len() < 29 || b[b.len() - 28..].iter().any(|&x| x != 0) {
        return None;
    }
    let mut sel = [0u8; 4];
    sel[4 - (b.len() - 28)..].copy_from_slice(&b[..b.len() - 28]);
    Some(u32::from_be_bytes(sel))
}

/// A left-aligned, zero-padded ASCII word (a short revert reason).
fn ascii_word(e: &Expr) -> Option<String> {
    let Expr::Const(b) = e else { return None };
    let end = b.iter().rposition(|&x| x != 0)? + 1;
    let text = std::str::from_utf8(&b[..end]).ok()?;
    (b.len() == 32 && text.chars().all(|c| c.is_ascii_graphic() || c == ' '))
        .then(|| text.to_string())
}

/// An `Error(string)` reason stored word by word after its length
/// word (`[…, len, w0, w1, …]`), as solc writes reasons longer than
/// 32 bytes when it doesn't `codecopy` them.
fn multiword_reason(stores: &[&Expr]) -> Option<String> {
    let (len, words) = (2..=stores.len().saturating_sub(1)).find_map(|n| {
        let len = usize::try_from(stores[stores.len() - n - 1].const_value()?).ok()?;
        (len > 32 * (n - 1) && len <= 32 * n).then(|| (len, &stores[stores.len() - n..]))
    })?;
    let mut raw = Vec::with_capacity(32 * words.len());
    for w in words {
        let Expr::Const(b) = w else { return None };
        if b.len() != 32 {
            return None;
        }
        raw.extend_from_slice(b);
    }
    let text = std::str::from_utf8(&raw[..len]).ok()?;
    (raw[len..].iter().all(|&x| x == 0) && text.chars().all(|c| c.is_ascii_graphic() || c == ' '))
        .then(|| text.to_string())
}

fn negate(e: Expr) -> Expr {
    match e {
        Expr::Op("iszero", mut args) if args.len() == 1 => args.pop().unwrap(),
        Expr::Op("bool", args) => Expr::Op("iszero", args),
        Expr::Op(op, args) if args.len() == 2 && inverse_cmp(op).is_some() => {
            Expr::Op(inverse_cmp(op).unwrap(), args)
        }
        other => Expr::Op("iszero", vec![other]),
    }
}

fn inverse_cmp(op: &str) -> Option<&'static str> {
    Some(match op {
        "eq" => "ne",
        "ne" => "eq",
        "lt" => "ge",
        "ge" => "lt",
        "gt" => "le",
        "le" => "gt",
        _ => return None,
    })
}

/// The same comparison with its operands swapped.
fn mirror_cmp(op: &str) -> Option<&'static str> {
    Some(match op {
        "eq" => "eq",
        "ne" => "ne",
        "lt" => "gt",
        "gt" => "lt",
        "le" => "ge",
        "ge" => "le",
        _ => return None,
    })
}

// ---------------------------------------------------------------------
// Opcode classes
// ---------------------------------------------------------------------

/// Environment reads that are fixed for the duration of a call.
fn env_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x30 => "address(this)",
        0x32 => "tx.origin",
        0x33 => "msg.sender",
        0x34 => "msg.value",
        0x36 => "msg.data.length",
        0x38 => "codesize",
        0x3a => "tx.gasprice",
        0x41 => "block.coinbase",
        0x42 => "block.timestamp",
        0x43 => "block.number",
        0x44 => "block.prevrandao",
        0x45 => "block.gaslimit",
        0x46 => "block.chainid",
        0x48 => "block.basefee",
        0x4a => "block.blobbasefee",
        _ => return None,
    })
}

/// Pure operations: value depends only on operands (and the call's
/// fixed inputs).
fn pure_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x01 => "add",
        0x02 => "mul",
        0x03 => "sub",
        0x04 => "div",
        0x05 => "sdiv",
        0x06 => "mod",
        0x07 => "smod",
        0x08 => "addmod",
        0x09 => "mulmod",
        0x0a => "exp",
        0x0b => "signextend",
        0x10 => "lt",
        0x11 => "gt",
        0x12 => "slt",
        0x13 => "sgt",
        0x14 => "eq",
        0x15 => "iszero",
        0x16 => "and",
        0x17 => "or",
        0x18 => "xor",
        0x19 => "not",
        0x1a => "byte",
        0x1b => "shl",
        0x1c => "shr",
        0x1d => "sar",
        0x1e => "clz",
        0x35 => "calldataload",
        0x40 => "blockhash",
        0x49 => "blobhash",
        _ => return None,
    })
}

/// Reads of mutable state (or calls) that produce one value.
fn read_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x20 => "keccak256",
        0x31 => "balance",
        0x3b => "extcodesize",
        0x3d => "returndatasize",
        0x3f => "extcodehash",
        0x47 => "selfbalance",
        0x51 => "mload",
        0x54 => "sload",
        0x59 => "msize",
        0x5a => "gasleft",
        0x5c => "tload",
        0xf0 => "create",
        0xf1 => "call",
        0xf2 => "callcode",
        0xf4 => "delegatecall",
        0xf5 => "create2",
        0xfa => "staticcall",
        _ => return None,
    })
}

/// Side effects with no result.
fn effect_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x37 => "calldatacopy",
        0x39 => "codecopy",
        0x3c => "extcodecopy",
        0x3e => "returndatacopy",
        0x52 => "mstore",
        0x53 => "mstore8",
        0x55 => "sstore",
        0x5d => "tstore",
        0x5e => "mcopy",
        0xa0 => "log0",
        0xa1 => "log1",
        0xa2 => "log2",
        0xa3 => "log3",
        0xa4 => "log4",
        _ => return None,
    })
}

// ---------------------------------------------------------------------
// Whole-program driver
// ---------------------------------------------------------------------

/// Shared inputs for lifting.
pub(crate) struct LiftCtx<'a> {
    /// The whole contract, for reading `codecopy`'d constants.
    pub code: &'a [u8],
    pub insns: &'a [DecodedInsn],
    pub cfg: &'a Cfg,
    /// Function names by entry address.
    pub names: &'a BTreeMap<u64, String>,
    /// Instruction-listing fallback for blocks that can't be lifted
    /// (unreachable code, leftovers).
    pub listing: &'a dyn Fn(&[DecodedInsn]) -> Vec<Stmt>,
    /// Addresses of call continuations (return addresses).
    pub continuations: HashSet<u64>,
    /// External functions (by entry address) with the name of each
    /// 32-byte word of their ABI-encoded parameters' head: word `k` is
    /// `calldataload(4 + 32k)`.
    pub params: HashMap<u64, Vec<String>>,
    /// External functions that may be public-variable getters: the
    /// name their known signature gives them and how many (static)
    /// parameters it takes.
    pub getters: HashMap<u64, (String, usize)>,
    /// Vyper code: mapping slots hash `slot ‖ key` (Solidity hashes
    /// `key ‖ slot`), and 0.1 / 0.2 keep the selector at memory 0.
    pub vyper: bool,
    /// Where to record stack names, when the caller wants them.
    pub trace: Option<&'a RefCell<LiftTrace>>,
}

impl LiftCtx<'_> {
    fn target_name(&self, addr: u64) -> String {
        self.names
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("L_{addr:04x}"))
    }

    fn blocks_in(&self, start: u64, end: u64) -> Vec<usize> {
        let mut v: Vec<usize> = (0..self.cfg.blocks.len())
            .filter(|&b| {
                let s = self.cfg.blocks[b].start;
                s >= start && s < end
            })
            .collect();
        v.sort_by_key(|&b| self.cfg.blocks[b].start);
        v
    }
}

/// Analysis passes before the one whose text is kept: the first
/// summarises what internal functions return, the second sees those
/// results at call sites (a public getter that calls an internal
/// accessor).
const ANALYSIS_PASSES: usize = 2;

/// What one lifting pass learned, for the next.
#[derive(Debug, Default)]
struct Facts {
    /// Values each `return` of an internal function hands back, keyed
    /// by entry block, in terms of its `argN`.
    returns: HashMap<usize, Vec<Vec<Expr>>>,
    /// Words each `return abi.encode(…)` of an external function
    /// returns, keyed by entry address.
    encoded: HashMap<u64, Vec<Vec<Expr>>>,
}

/// Per internal function (by entry block), each return value that is
/// the same expression of the arguments at every `return`.
type Summaries = HashMap<usize, Vec<Option<Expr>>>;

/// Lift every function range `[start, end)` to a statement body.
pub(crate) fn lift_ranges(ctx: &LiftCtx<'_>, ranges: &[(u64, u64)]) -> Vec<Vec<Stmt>> {
    let mut plan = Plan::default();
    let slices: Vec<Vec<usize>> = ranges.iter().map(|&(s, e)| ctx.blocks_in(s, e)).collect();
    for slice in &slices {
        plan_slice(ctx, slice, None, &mut plan);
    }
    let labels = collect_labels(ctx, &plan);
    let pass = |summaries: &Summaries, facts: &mut Facts| -> Vec<Vec<Stmt>> {
        // Shared by every range, so known values (Vyper's `msg.sig`
        // kept in a stack slot) reach each dispatcher case.
        let mut exits = Exits::new();
        slices
            .iter()
            .zip(ranges)
            .map(|(slice, &(start, _))| {
                let mut fb = FnBuilder {
                    ctx,
                    plan: &plan,
                    labels: &labels,
                    range_start: start,
                    temps: 0,
                    summaries,
                    exits: &mut exits,
                    facts: &mut *facts,
                };
                let mut body = fb.build(slice, None);
                fold_short_circuits(&mut body);
                body
            })
            .collect()
    };
    let mut summaries = Summaries::new();
    let mut facts = Facts::default();
    for _ in 0..ANALYSIS_PASSES {
        facts = Facts::default();
        pass(&summaries, &mut facts);
        summaries = summarize(&facts);
    }
    let names = storage_names(ctx, &facts);
    if let Some(trace) = ctx.trace {
        let mut t = trace.borrow_mut();
        t.storage.clone_from(&names);
        t.params.clone_from(&ctx.params);
    }
    let _scope = StorageScope::enter(names);
    pass(&summaries, &mut Facts::default())
}

fn summarize(facts: &Facts) -> Summaries {
    facts
        .returns
        .iter()
        .map(|(&f, sites)| {
            let n = sites.first().map_or(0, Vec::len);
            let values = (0..n)
                .map(|k| {
                    let first = &sites[0][k];
                    (sites.iter().all(|s| s.len() == n && s[k] == *first) && summary_safe(first))
                        .then(|| first.clone())
                })
                .collect();
            (f, values)
        })
        .collect()
}

/// Whether `e` is a value of the arguments alone: no unknown entry
/// slot, no variable but `argN` (and return-address labels).
fn summary_safe(e: &Expr) -> bool {
    match e {
        Expr::Const(_) => true,
        Expr::Var(v) => v.starts_with("L_") || v.strip_prefix("arg").is_some_and(is_digits),
        Expr::Op(op, args) => *op != UNKNOWN && *op != MPTR && args.iter().all(summary_safe),
    }
}

/// Whether a known entry value is shown in place of its slot
/// variable: constants, ABI parameters and call-wide environment
/// values (`msg.sig`, `msg.sender`, …), none of which can change while
/// the slot holds them.
fn shows_inline(e: &Expr) -> bool {
    match e {
        Expr::Const(_) => true,
        Expr::Var(_) => is_param(e),
        Expr::Op(op, args) => {
            args.is_empty() && (*op == "msg.sig" || (0x30..=0x4a).any(|o| env_name(o) == Some(op)))
        }
    }
}

/// `msg.sig`, `msg.sender`, `block.number`, …
fn is_env(e: &Expr) -> bool {
    matches!(e, Expr::Op(..)) && shows_inline(e)
}

fn is_param(e: &Expr) -> bool {
    matches!(e, Expr::Var(v) if v.starts_with("param"))
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Name storage slots after the public getters that read them: a
/// function whose known signature is `name(k0, k1, …)` and that
/// returns `sload(slot)` or `sload(mapping(…mapping(slot, k0)…, kN))`
/// keyed by its parameters in order. A slot claimed by two names, or a
/// name by two slots, stays unnamed, as do the ERC-1967 slots.
fn storage_names(ctx: &LiftCtx<'_>, facts: &Facts) -> StorageNames {
    let mut claims: Vec<(Vec<u8>, &str)> = Vec::new();
    for (addr, (name, nparams)) in &ctx.getters {
        let Some([first, rest @ ..]) = facts.encoded.get(addr).map(Vec::as_slice) else {
            continue;
        };
        if rest.iter().any(|w| w != first) {
            continue;
        }
        let [word] = first.as_slice() else { continue };
        if let Some(slot) = getter_slot(word, *nparams)
            && !is_standard_slot(&slot)
            && !claims.contains(&(slot.clone(), name.as_str()))
        {
            claims.push((slot, name));
        }
    }
    unique_claims(&claims)
}

/// The `(slot, name)` claims whose slot and name each appear in no
/// other claim.
fn unique_claims(claims: &[(Vec<u8>, &str)]) -> StorageNames {
    claims
        .iter()
        .filter(|(slot, name)| {
            claims.iter().filter(|(s, _)| s == slot).count() == 1
                && claims.iter().filter(|(_, n)| n == name).count() == 1
        })
        .map(|(slot, name)| (slot.clone(), (*name).to_string()))
        .collect()
}

/// Whether `slot` is one of the standard slots
/// [`crate::signatures::evm::slot_name`] already names.
fn is_standard_slot(slot: &[u8]) -> bool {
    if slot.len() > 32 {
        return false;
    }
    let mut word = [0u8; 32];
    word[32 - slot.len()..].copy_from_slice(slot);
    crate::signatures::evm::slot_name(&word).is_some()
}

/// The root slot a getter's returned `word` reads, when the read is
/// keyed by exactly the getter's `nparams` parameters in order.
fn getter_slot(word: &Expr, nparams: usize) -> Option<Vec<u8>> {
    let Expr::Op("sload", a) = strip_cleanup(word) else {
        return None;
    };
    let mut slot = &a[0];
    let mut keys = Vec::new();
    while let Expr::Op("mapping", m) = slot {
        keys.push(&m[1]);
        slot = &m[0];
    }
    keys.reverse();
    let Expr::Const(b) = slot else { return None };
    let in_order = keys
        .iter()
        .enumerate()
        .all(|(k, key)| matches!(strip_cleanup(key), Expr::Var(v) if *v == format!("param{k}")));
    (keys.len() == nparams && in_order).then(|| strip(b).to_vec())
}

/// `e` without the type cleanup compilers wrap around loaded values:
/// `address(x)`, `bool(x)`, low-byte masks, `signextend`, `x / 1`.
fn strip_cleanup(mut e: &Expr) -> &Expr {
    let low_mask = |m: &Expr| m.is_const_bytes(|b| !b.is_empty() && b.iter().all(|&x| x == 0xff));
    loop {
        e = match e {
            Expr::Op("address" | "bool" | RESULT, a) if a.len() == 1 => &a[0],
            Expr::Op("and", a) if a.len() == 2 && low_mask(&a[1]) => &a[0],
            Expr::Op("and", a) if a.len() == 2 && low_mask(&a[0]) => &a[1],
            Expr::Op("signextend", a) if a.len() == 2 && a[0].const_value().is_some() => &a[1],
            Expr::Op("div", a) if a.len() == 2 && a[1].const_value() == Some(1) => &a[0],
            _ => return e,
        };
    }
}

/// `v = a; if (v) { v = b }` is `v = a && b` (and `if (!v)` is `||`):
/// how compilers evaluate `&&` / `||`. Merges the three statements,
/// keeping their bytes in order.
fn fold_short_circuits(stmts: &mut Vec<Stmt>) {
    for st in stmts.iter_mut() {
        match st {
            Stmt::IfBranch {
                then_body,
                else_body,
                ..
            } => {
                fold_short_circuits(then_body);
                if let Some(e) = else_body {
                    fold_short_circuits(e);
                }
            }
            Stmt::WhileBlock { body, .. } | Stmt::Loop { body, .. } => fold_short_circuits(body),
            _ => {}
        }
    }
    let mut i = 0;
    while i + 1 < stmts.len() {
        let folded = match (&stmts[i], &stmts[i + 1]) {
            (
                Stmt::Move {
                    dst,
                    src: lhs,
                    bytes: b1,
                },
                Stmt::IfBranch {
                    cond_text,
                    cond_bytes,
                    then_body,
                    else_body: None,
                    pre_body,
                    ..
                },
            ) if pre_body.is_empty() && !dst.contains(',') => {
                let op = if *cond_text == *dst {
                    Some("&&")
                } else if *cond_text == format!("!{dst}") {
                    Some("||")
                } else {
                    None
                };
                match (op, then_body.as_slice()) {
                    (
                        Some(op),
                        [
                            Stmt::Move {
                                dst: d2,
                                src: rhs,
                                bytes: b2,
                            },
                        ],
                    ) if d2 == dst && !b1.is_empty() => {
                        let mut bytes = b1.clone();
                        bytes.extend(cond_bytes);
                        bytes.extend(b2);
                        Some(Stmt::Move {
                            dst: dst.clone(),
                            src: format!("{} {op} {}", paren(lhs), paren(rhs)),
                            bytes,
                        })
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(st) = folded {
            stmts[i] = st;
            stmts.remove(i + 1);
            // Chains (`a && b && c`) fold again with the next `if`.
        } else {
            i += 1;
        }
    }
}

fn paren(s: &str) -> String {
    if s.contains(' ') && !(s.starts_with('(') && s.ends_with(')')) {
        format!("({s})")
    } else {
        s.to_string()
    }
}

/// A structured `JUMPI`, as indices into the block slice it was
/// planned in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IfShape {
    /// Index of the jump target: the `then` run is `i+1..target`.
    target: usize,
    /// `Some(end)`: the `then` run ends by jumping to the block at
    /// `end` (or to the block following the slice, when `end` is the
    /// slice length), and `target..end` is an `else` run entered only
    /// from the `JUMPI`.
    else_end: Option<usize>,
    /// The `then` run ends by jumping back to the `JUMPI` block: a
    /// `while` loop.
    is_loop: bool,
}

#[derive(Debug, Default)]
struct Plan {
    /// Structured `JUMPI` blocks.
    ifs: HashMap<usize, IfShape>,
    /// Bottom-tested loops: head block → tail block whose `JUMPI`
    /// jumps back to the head.
    do_whiles: HashMap<usize, usize>,
}

/// Decide which `JUMPI`s become structured. `follow` is the block
/// control reaches after the slice, if known.
fn plan_slice(ctx: &LiftCtx<'_>, blocks: &[usize], follow: Option<usize>, plan: &mut Plan) {
    let mut i = 0;
    while i < blocks.len() {
        // A head's own body slice starts with the head again; it is
        // already planned.
        if !plan.do_whiles.contains_key(&blocks[i])
            && let Some(j) = do_while_tail(ctx, blocks, i)
        {
            plan.do_whiles.insert(blocks[i], blocks[j]);
            plan_slice(ctx, &blocks[i..j], Some(blocks[j]), plan);
            i = j + 1;
            continue;
        }
        if let Some(shape) = if_shape(ctx, blocks, i, follow) {
            plan.ifs.insert(blocks[i], shape);
            let join = shape.else_end.map_or(Some(blocks[shape.target]), |m| {
                blocks.get(m).copied().or(follow)
            });
            plan_slice(ctx, &blocks[i + 1..shape.target], join, plan);
            if let Some(end) = shape.else_end {
                plan_slice(ctx, &blocks[shape.target..end], join, plan);
                i = end;
            } else {
                i = shape.target;
            }
            continue;
        }
        i += 1;
    }
}

/// Whether every block of `run` is reached and entered only from
/// `from` or from inside `run`.
fn single_entry(ctx: &LiftCtx<'_>, run: &[usize], from: usize) -> bool {
    let inside: HashSet<usize> = run.iter().copied().collect();
    !run.is_empty()
        && run.iter().all(|&r| {
            ctx.cfg.reached[r]
                && ctx.cfg.preds[r]
                    .iter()
                    .all(|p| *p == from || inside.contains(p))
        })
}

/// The single local-jump target of block `b`, if that's how it ends.
fn local_jump_target(ctx: &LiftCtx<'_>, b: usize) -> Option<usize> {
    let cfg = ctx.cfg;
    (cfg.blocks[b].term == Term::Jump
        && cfg.role[b] == JumpRole::Local
        && cfg.targets[b].len() == 1)
        .then(|| *cfg.targets[b].iter().next().expect("one target"))
}

/// If `blocks[i]` heads a bottom-tested loop — a later block in the
/// slice ends with a `JUMPI` back to it, and nothing enters the loop
/// body except through the head — return the tail's index.
fn do_while_tail(ctx: &LiftCtx<'_>, blocks: &[usize], i: usize) -> Option<usize> {
    let cfg = ctx.cfg;
    let head = blocks[i];
    if !cfg.reached[head] {
        return None;
    }
    (i..blocks.len()).find(|&j| {
        let t = blocks[j];
        cfg.blocks[t].term == Term::JumpI
            && cfg.targets[t].len() == 1
            && cfg.targets[t].contains(&head)
            && (j == i || single_entry(ctx, &blocks[i + 1..=j], head))
    })
}

/// Structure of the `JUMPI` ending `blocks[i]`, when it jumps forward
/// over a single-entry run of the blocks that follow it.
fn if_shape(
    ctx: &LiftCtx<'_>,
    blocks: &[usize],
    i: usize,
    follow: Option<usize>,
) -> Option<IfShape> {
    let cfg = ctx.cfg;
    let b = blocks[i];
    let blk = &cfg.blocks[b];
    if blk.term != Term::JumpI || !cfg.reached[b] || cfg.targets[b].len() != 1 {
        return None;
    }
    let target = *cfg.targets[b].iter().next()?;
    let k = blocks.iter().position(|&x| x == target)?;
    if k <= i + 1 || cfg.blocks[blocks[i + 1]].start != blk.end {
        return None;
    }
    if !single_entry(ctx, &blocks[i + 1..k], b) {
        return None;
    }
    let tail = local_jump_target(ctx, blocks[k - 1]);
    let is_loop = tail == Some(b);
    let else_end = tail.filter(|_| !is_loop).and_then(|x| {
        let m = blocks
            .iter()
            .position(|&y| y == x)
            .or_else(|| (Some(x) == follow).then_some(blocks.len()))?;
        (m > k && single_entry(ctx, &blocks[k..m], b)).then_some(m)
    });
    Some(IfShape {
        target: k,
        else_end,
        is_loop,
    })
}

/// Addresses that need a `// L_xxxx:` label because some displayed
/// jump names them. Back-edges of structured loops are left out: the
/// builder labels a loop head itself if it can't render the loop.
fn collect_labels(ctx: &LiftCtx<'_>, plan: &Plan) -> HashSet<u64> {
    let cfg = ctx.cfg;
    let loop_heads: HashSet<usize> = plan
        .ifs
        .iter()
        .filter(|(_, s)| s.is_loop)
        .map(|(&b, _)| b)
        .collect();
    let do_while_tails: HashSet<usize> = plan.do_whiles.values().copied().collect();
    let mut out = HashSet::new();
    for (b, blk) in cfg.blocks.iter().enumerate() {
        if !cfg.reached[b] {
            continue;
        }
        let starts = |set: &std::collections::BTreeSet<usize>| {
            set.iter()
                .filter(|t| !loop_heads.contains(t))
                .map(|&t| cfg.blocks[t].start)
                .collect::<Vec<_>>()
        };
        match (blk.term, cfg.role[b]) {
            (Term::JumpI, _) if !plan.ifs.contains_key(&b) && !do_while_tails.contains(&b) => {
                out.extend(starts(&cfg.targets[b]));
            }
            (Term::Jump, JumpRole::Local) => out.extend(starts(&cfg.targets[b])),
            (Term::Jump, JumpRole::Call) => {
                for &c in cfg.conts.get(&b).into_iter().flatten() {
                    if cfg.blocks[c].start != blk.end {
                        out.insert(cfg.blocks[c].start);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

struct FnBuilder<'a, 'c> {
    ctx: &'a LiftCtx<'c>,
    plan: &'a Plan,
    labels: &'a HashSet<u64>,
    range_start: u64,
    temps: usize,
    summaries: &'a Summaries,
    exits: &'a mut Exits,
    facts: &'a mut Facts,
}

/// What each block lifted so far leaves on the stack for its
/// successors: the range it was lifted in, its frame, and known values
/// by frame position.
type Exits = HashMap<usize, (u64, FrameId, HashMap<i64, Expr>)>;

/// How a lifted block hands control on.
enum BlockEnd {
    /// `JUMPI`: the `if` is built by the caller, which knows whether
    /// the fall-through run is structured.
    Cond {
        cond: Expr,
        target: Option<u64>,
        bytes: Vec<u8>,
    },
    Other,
}

impl FnBuilder<'_, '_> {
    fn label(&self, b: usize) -> Option<Stmt> {
        let start = self.ctx.cfg.blocks[b].start;
        (start != self.range_start && self.labels.contains(&start))
            .then(|| Stmt::Comment(format!("L_{start:04x}:")))
    }

    /// Statements for a run of blocks; `follow` is the block control
    /// reaches after it (see [`plan_slice`]).
    #[allow(clippy::too_many_lines)]
    fn build(&mut self, blocks: &[usize], follow: Option<usize>) -> Vec<Stmt> {
        let cfg = self.ctx.cfg;
        let mut out = Vec::new();
        let mut i = 0;
        while i < blocks.len() {
            let b = blocks[i];
            if let Some(&tail) = self.plan.do_whiles.get(&b)
                && let Some(j) = blocks[i..].iter().position(|&x| x == tail).map(|p| p + i)
            {
                self.build_do_while(&blocks[i..j], tail, &mut out);
                i = j + 1;
                continue;
            }
            if !cfg.reached[b] {
                out.extend(self.label(b));
                out.extend((self.ctx.listing)(
                    &self.ctx.insns[cfg.blocks[b].insns.clone()],
                ));
                i += 1;
                continue;
            }
            let (stmts, end, last) = self.lift_block(b, &blocks[i + 1..]);
            // A chain of blocks lifted as one ends where its last block
            // does, and is planned as that block.
            let label_b = b;
            let b = last;
            if let Some(k) = blocks[i..].iter().position(|&x| x == last) {
                i += k;
            }
            let BlockEnd::Cond {
                cond,
                target,
                bytes,
            } = end
            else {
                out.extend(self.label(label_b));
                out.extend(stmts);
                i += 1;
                continue;
            };
            let Some(&shape) = self.plan.ifs.get(&b) else {
                out.extend(self.label(label_b));
                out.extend(stmts);
                // A jump to a block that only fails (via-IR shares one
                // per error) reads as that failure, inline.
                let failure = target
                    .and_then(|t| cfg.block_at(t))
                    .and_then(|tb| self.failure_of(tb));
                if let Some(fail) = failure {
                    out.push(
                        as_guard(&negate(cond.clone()), &bytes, std::slice::from_ref(&fail))
                            .unwrap_or_else(|| Stmt::IfBranch {
                                cond_text: render(&cond),
                                cond_bytes: bytes,
                                attrs: Vec::new(),
                                pre_body: Vec::new(),
                                then_body: vec![fail],
                                else_body: None,
                            }),
                    );
                } else {
                    let dest = target.map_or_else(|| "?".to_string(), |t| self.ctx.target_name(t));
                    out.push(cond_jump(&cond, bytes, dest));
                }
                i += 1;
                continue;
            };
            let join = shape.else_end.map_or(Some(blocks[shape.target]), |m| {
                blocks.get(m).copied().or(follow)
            });
            let mut then_body = self.build(&blocks[i + 1..shape.target], join);
            if shape.is_loop
                && stmts.is_empty()
                && !bytes.is_empty()
                && matches!(then_body.last(), Some(Stmt::Call { name, bytes, .. }) if name == "jump" && !bytes.is_empty())
            {
                // Head computes only the condition: `while (cond) { … }`
                // with the back-edge jump as the loop's tail bytes.
                let Some(Stmt::Call {
                    bytes: tail_bytes, ..
                }) = then_body.pop()
                else {
                    unreachable!("checked above")
                };
                out.extend(self.label(label_b));
                out.push(Stmt::WhileBlock {
                    cond_text: render(&negate(cond)),
                    entry_bytes: bytes,
                    tail_bytes,
                    body: then_body,
                });
                i = shape.target;
                continue;
            }
            // A loop the `while` form can't hold keeps its label for the
            // back-edge jump.
            let start = cfg.blocks[b].start;
            if shape.is_loop && start != self.range_start && !self.labels.contains(&start) {
                out.push(Stmt::Comment(format!("L_{start:04x}:")));
            }
            out.extend(self.label(label_b));
            out.extend(stmts);
            if shape.else_end.is_none()
                && let Some(guard) = as_guard(&cond, &bytes, &then_body)
            {
                out.push(guard);
                i = shape.target;
                continue;
            }
            let else_body = shape
                .else_end
                .map(|end| self.build(&blocks[shape.target..end], join));
            out.push(Stmt::IfBranch {
                cond_text: render(&negate(cond)),
                cond_bytes: bytes,
                attrs: Vec::new(),
                pre_body: Vec::new(),
                then_body,
                else_body,
            });
            i = shape.else_end.unwrap_or(shape.target);
        }
        out
    }

    /// If block `b` does nothing but fail — `revert(…)`, `panic(…)`,
    /// `invalid()` — that failure as a zero-byte statement (the bytes
    /// stay with the block itself).
    fn failure_of(&mut self, b: usize) -> Option<Stmt> {
        let cfg = self.ctx.cfg;
        if !cfg.reached[b] || cfg.blocks[b].term != Term::Halt {
            return None;
        }
        let saved = self.temps;
        let (stmts, _, _) = self.lift_block(b, &[]);
        self.temps = saved;
        let mut real = stmts.into_iter().filter(|s| !matches!(s, Stmt::Comment(_)));
        match (real.next(), real.next()) {
            (Some(Stmt::Call { name, args, .. }), None)
                if matches!(name.as_str(), "revert" | "panic" | "invalid") =>
            {
                Some(Stmt::Call {
                    name,
                    args,
                    bytes: Vec::new(),
                    direct_target: None,
                })
            }
            _ => None,
        }
    }

    /// `do { body } while (cond)`: `body_blocks` run from the head up
    /// to (not including) `tail`, whose `JUMPI` jumps back.
    fn build_do_while(&mut self, body_blocks: &[usize], tail: usize, out: &mut Vec<Stmt>) {
        let head = body_blocks.first().copied().unwrap_or(tail);
        let mut body = self.build(body_blocks, Some(tail));
        if body_blocks.is_empty() {
            body.extend(self.label(tail));
        }
        let (stmts, end, _) = self.lift_block(tail, &[]);
        body.extend(stmts);
        let BlockEnd::Cond { cond, bytes, .. } = end else {
            unreachable!("do-while tail ends in JUMPI")
        };
        if bytes.is_empty() {
            // No bytes left for the loop condition: show the back-edge
            // as an explicit jump to a labelled head instead.
            let start = self.ctx.cfg.blocks[head].start;
            if !self.labels.contains(&start) {
                body.insert(0, Stmt::Comment(format!("L_{start:04x}:")));
            }
            out.extend(body);
            out.push(cond_jump(&cond, bytes, self.ctx.target_name(start)));
            return;
        }
        out.push(Stmt::Loop {
            cond_text: render(&cond),
            entry_jmp_bytes: None,
            tail_bytes: bytes,
            body,
        });
    }

    /// Lift block `b` — and, where it ends in a guard whose failure
    /// path and continuation are the next blocks of `rest`, those too
    /// (see [`BlockLift::try_chain`]). Returns the statements, how the
    /// last block lifted ends, and that block.
    fn lift_block(&mut self, b: usize, rest: &[usize]) -> (Vec<Stmt>, BlockEnd, usize) {
        let depth = self.ctx.cfg.depth[b];
        let entry = self.entry_values(b);
        let mut bl = BlockLift {
            ctx: self.ctx,
            depth,
            stack: Vec::new(),
            pulled: 0,
            pending: self.ctx.cfg.blocks[b].insns.start,
            out: Vec::new(),
            temps: &mut self.temps,
            mstores: Vec::new(),
            bindings: HashMap::new(),
            flat: HashMap::new(),
            fmp_epoch: 0,
            fmp_id: None,
            params: self
                .ctx
                .params
                .get(&self.range_start)
                .map_or(&[], Vec::as_slice),
            entry,
            resolved: HashMap::new(),
            summaries: self.summaries,
            exit: None,
            returned: None,
            encoded: None,
            rest,
            last: b,
            code_checks: HashSet::new(),
            folded: None,
        };
        let end = bl.run(b);
        let BlockLift {
            out,
            exit,
            returned,
            encoded,
            last,
            ..
        } = bl;
        if let (Some(exit), Some(d)) = (exit, depth) {
            self.exits.insert(last, (self.range_start, d.frame, exit));
        }
        if let (Some(vals), Some(frame)) = (returned, depth.and_then(|d| d.frame)) {
            self.facts.returns.entry(frame).or_default().push(vals);
        }
        if let Some(words) = encoded {
            self.facts
                .encoded
                .entry(self.range_start)
                .or_default()
                .push(words);
        }
        (out, end, last)
    }

    /// Known values of `b`'s entry stack, by frame position: the
    /// arguments at an internal function's entry, else what every
    /// predecessor (all lifted already, in the same frame) agrees on.
    fn entry_values(&self, b: usize) -> HashMap<i64, Expr> {
        let cfg = self.ctx.cfg;
        let Some(d) = cfg.depth[b] else {
            return HashMap::new();
        };
        if let Some(info) = cfg.functions.get(&b) {
            return (0..info.nargs)
                .map(|k| (k as i64 + 1, Expr::Var(format!("arg{k}"))))
                .collect();
        }
        let mut known: Option<HashMap<i64, Expr>> = None;
        for p in &cfg.preds[b] {
            let Some((range, frame, exit)) = self.exits.get(p) else {
                return HashMap::new();
            };
            if *frame != d.frame {
                return HashMap::new();
            }
            // Into another range only call-wide environment values
            // flow (`msg.sig` kept in a slot by Vyper's dispatcher):
            // `paramN` would name the other range's parameters, and
            // constants left behind there would change how this range
            // reads (an ABI encoding into memory it set up itself).
            let exit = exit
                .iter()
                .filter(|&(_, e)| *range == self.range_start || is_env(e));
            match &mut known {
                None => {
                    known = Some(
                        exit.filter(|&(&pos, _)| pos < d.depth)
                            .map(|(&pos, e)| (pos, e.clone()))
                            .collect(),
                    );
                }
                Some(k) => {
                    let exit: HashMap<&i64, &Expr> = exit.collect();
                    k.retain(|pos, e| exit.get(pos) == Some(&&*e));
                }
            }
        }
        known.unwrap_or_default()
    }
}

/// `e` with each `argN` replaced by `args[N]`, all at once.
fn subst_args(e: &Expr, args: &[Expr]) -> Expr {
    match e {
        Expr::Var(v) => v
            .strip_prefix("arg")
            .filter(|k| is_digits(k))
            .and_then(|k| args.get(k.parse::<usize>().ok()?))
            .map_or_else(|| e.clone(), Clone::clone),
        Expr::Op(op, a) => {
            let r = simplify(Expr::Op(
                op,
                a.iter().map(|x| subst_args(x, args)).collect(),
            ));
            if r.nodes() > RESOLVE_MAX_NODES {
                Expr::Op(UNKNOWN, Vec::new())
            } else {
                r
            }
        }
        Expr::Const(_) => e.clone(),
    }
}

/// The one `revert(…)` / `panic(…)` / `invalid()` a failure block's
/// statements come down to.
fn single_failure(stmts: Vec<Stmt>) -> Option<Stmt> {
    let mut real = stmts.into_iter().filter(|s| !matches!(s, Stmt::Comment(_)));
    match (real.next(), real.next()) {
        (Some(st @ Stmt::Call { .. }), None)
            if matches!(&st, Stmt::Call { name, .. }
                if matches!(name.as_str(), "revert" | "panic" | "invalid")) =>
        {
            Some(st)
        }
        _ => None,
    }
}

/// Whether a failure block's statements re-raise the return data of
/// the call that failed: `returndatacopy(p, 0x0, returndatasize())`,
/// then `revert(p, returndatasize())`.
fn is_bubble(stmts: &[Stmt]) -> bool {
    let calls: Vec<(&str, &[String])> = stmts
        .iter()
        .filter_map(|s| match s {
            Stmt::Call { name, args, .. } => Some((name.as_str(), args.as_slice())),
            _ => None,
        })
        .collect();
    let moves_ok = stmts.iter().all(|s| match s {
        Stmt::Move { src, .. } => src == "returndatasize()",
        _ => true,
    });
    matches!(calls.as_slice(), [("returndatacopy", [p, z, n]), ("revert", [q, _])]
        if p == q && z == "0x0" && n == "returndatasize()")
        && moves_ok
}

/// Whether a failure block's statements are a bare `revert(0x0, 0x0)`.
fn is_plain_revert(stmts: &[Stmt]) -> bool {
    let mut real = stmts.iter().filter(|s| !matches!(s, Stmt::Comment(_)));
    matches!((real.next(), real.next()), (Some(Stmt::Call { name, args, .. }), None)
        if name == "revert" && args.len() == 2 && args.iter().all(|a| a == "0x0"))
}

/// `if (!ok) { revert(…) }` as `require(ok, …)`, and `if (!ok) {
/// invalid() }` (solc ≤0.7 `assert` and bounds checks) as `assert(ok)`.
/// `ok` is the `JUMPI` condition: the jump skips the failure path.
fn as_guard(ok: &Expr, cond_bytes: &[u8], then_body: &[Stmt]) -> Option<Stmt> {
    let [
        Stmt::Call {
            name, args, bytes, ..
        },
    ] = then_body
    else {
        return None;
    };
    let mut new_args = vec![render_arg(ok)];
    let name = match (name.as_str(), args.as_slice()) {
        ("revert", [a, b]) if a == "0x0" && b == "0x0" => "require",
        ("revert", [reason]) => {
            new_args.push(reason.clone());
            "require"
        }
        ("invalid", []) => "assert",
        _ => return None,
    };
    let mut all = cond_bytes.to_vec();
    all.extend(bytes);
    Some(Stmt::Call {
        name: name.into(),
        args: new_args,
        bytes: all,
        direct_target: None,
    })
}

/// `if (cond) { jump(dest) }` — an unstructured conditional jump.
fn cond_jump(cond: &Expr, bytes: Vec<u8>, dest: String) -> Stmt {
    Stmt::IfBranch {
        cond_text: render(cond),
        cond_bytes: bytes,
        attrs: Vec::new(),
        pre_body: Vec::new(),
        then_body: vec![jump_stmt(dest, Vec::new())],
        else_body: None,
    }
}

fn jump_stmt(dest: String, bytes: Vec<u8>) -> Stmt {
    Stmt::Call {
        name: "jump".into(),
        args: vec![dest],
        bytes,
        direct_target: None,
    }
}

// ---------------------------------------------------------------------
// Per-block symbolic execution
// ---------------------------------------------------------------------

/// An `mstore` emitted by the block being lifted.
#[derive(Clone)]
struct MStore {
    /// Index of its statement in `BlockLift::out`.
    at: usize,
    offset: Expr,
    value: Expr,
    /// `offset` resolved by [`lin`] when the store happened, so later
    /// rebinding of a variable it mentions can't change what it means.
    place: Option<(String, u64)>,
    /// `value` resolved when the store happened (see
    /// [`BlockLift::resolve`]), for the same reason.
    resolved: Expr,
    /// `offset` resolved, as a base plus a constant (see [`rlin`]).
    rplace: Option<(Option<Expr>, u64)>,
}

struct BlockLift<'a, 'c> {
    ctx: &'a LiftCtx<'c>,
    depth: Option<BlockDepth>,
    /// Bottom → top. Entry items are pulled in lazily below.
    stack: Vec<Expr>,
    /// Entry items pulled so far.
    pulled: usize,
    /// First instruction not yet attributed to a statement.
    pending: usize,
    out: Vec<Stmt>,
    temps: &'a mut usize,
    /// `mstore`s emitted in this block, for the mapping-slot and
    /// ABI-encoding idioms.
    mstores: Vec<MStore>,
    /// What each variable bound in this block was bound to. A
    /// free-memory-pointer read is recorded as `fmp(epoch)`.
    bindings: HashMap<String, Expr>,
    /// Variables bound in this block whose values mention no variable
    /// (but parameters and labels), as those values: free-memory
    /// pointer reads stay `fmp(epoch)`.
    flat: HashMap<String, Expr>,
    /// Bumped by every `mstore(0x40, …)`: free-memory-pointer reads in
    /// the same epoch see the same value.
    fmp_epoch: u64,
    /// The id of the current epoch's free-memory pointer once read
    /// (see [`MPTR`]).
    fmp_id: Option<u64>,
    /// Names of the ABI head words of the external function being
    /// lifted (see [`LiftCtx::params`]).
    params: &'a [String],
    /// Known entry-stack values by frame position (see
    /// [`FnBuilder::entry_values`]).
    entry: HashMap<i64, Expr>,
    /// Each variable bound in this block, as an expression of the
    /// entry values ([`Self::resolve`]).
    resolved: HashMap<String, Expr>,
    summaries: &'a Summaries,
    /// Set when control leaves for successor blocks: the stack it
    /// leaves, resolved, by frame position.
    exit: Option<HashMap<i64, Expr>>,
    /// Set by an internal function's `return`: the values returned,
    /// resolved, deepest first.
    returned: Option<Vec<Expr>>,
    /// Set by `return abi.encode(…)`: the words returned, resolved.
    encoded: Option<Vec<Expr>>,
    /// The blocks after the current one in the slice being built, for
    /// lifting a guarded continuation in the same pass.
    rest: &'a [usize],
    /// The block being lifted (the last of a chain).
    last: usize,
    /// Indices in `out` of `require`s that only check that a call's
    /// target has code (solc's `extcodesize` check).
    code_checks: HashSet<usize>,
    /// The external call [`Self::fold_external_call`] folded last.
    folded: Option<FoldedCall>,
}

/// An external call folded into one statement, kept so the checks
/// that follow it can be taken in.
struct FoldedCall {
    /// Index of its statement in `BlockLift::out`.
    at: usize,
    /// The variable holding its success flag.
    var: String,
    kind: &'static str,
    sel: u32,
    gas: Expr,
    to: Expr,
    value: Option<Expr>,
    args: Vec<Expr>,
}

impl FoldedCall {
    /// The statement's right-hand side: the low-level call that
    /// returns the success flag — `t.call(IERC20.transfer(a, n))` —
    /// or, once a failure re-raises its revert data (`checked`), the
    /// high-level call Solidity compiles that way —
    /// `IERC20(t).transfer(a, n)`. A non-zero value and an explicit
    /// gas limit show as `.value(v)` / `.gas(g)` modifiers, as Solidity
    /// 0.6 wrote them; an unknown selector as `t.call(0xsel, a, …)`.
    fn text(&self, checked: bool) -> String {
        let to = match &self.to {
            Expr::Op("address", x) if x.len() == 1 => &x[0],
            other => other,
        };
        let mut mods = String::new();
        if let Some(v) = self.value.as_ref().filter(|v| v.const_value() != Some(0)) {
            let _ = write!(mods, ".value({})", render_arg(v));
        }
        if !matches!(&self.gas, Expr::Op("gasleft", a) if a.is_empty()) {
            let _ = write!(mods, ".gas({})", render_arg(&self.gas));
        }
        let mut parts: Vec<String> = self.args.iter().map(render_arg).collect();
        let Some(sig) = crate::signatures::evm::function_by_selector(self.sel) else {
            parts.insert(0, format!("0x{:08x}", self.sel));
            return format!(
                "{}.{}{mods}({})",
                render_arg(to),
                self.kind,
                parts.join(", ")
            );
        };
        let name = sig.split('(').next().unwrap_or(sig);
        let iface = crate::signatures::evm::interface_of(sig).unwrap_or("Iface");
        if checked {
            format!("{iface}({}).{name}{mods}({})", render(to), parts.join(", "))
        } else {
            format!(
                "{}.{}{mods}({iface}.{name}({}))",
                render_arg(to),
                self.kind,
                parts.join(", ")
            )
        }
    }
}

impl BlockLift<'_, '_> {
    /// `mstore(0x0, key); mstore(0x20, slot); keccak256(0x0, 0x40)` is
    /// how Solidity addresses `mapping` entries. When the two stores
    /// are the statements just emitted, fold all three into
    /// `mapping(slot, key)`, returning it, its resolved form and the
    /// stores' bytes.
    fn take_mapping_stores(&mut self, args: &[Expr]) -> Option<(Expr, Expr, Vec<u8>)> {
        if args[0].const_value() != Some(0) || args[1].const_value() != Some(0x40) {
            return None;
        }
        let n = self.out.len();
        let [.., a, b] = self.mstores.as_slice() else {
            return None;
        };
        if (a.at, b.at) != (n.checked_sub(2)?, n - 1) {
            return None;
        }
        let (lo, hi) = match (a.offset.const_value()?, b.offset.const_value()?) {
            (0, 0x20) => (a, b),
            (0x20, 0) => (b, a),
            _ => return None,
        };
        let (key, slot) = if self.ctx.vyper { (hi, lo) } else { (lo, hi) };
        let val = Expr::Op("mapping", vec![slot.value.clone(), key.value.clone()]);
        let resolved = simplify(Expr::Op(
            "mapping",
            vec![slot.resolved.clone(), key.resolved.clone()],
        ));
        let mut bytes = Vec::new();
        for stmt in self.out.drain(n - 2..) {
            let Stmt::Call { bytes: b, .. } = stmt else {
                unreachable!("mstore is a call")
            };
            bytes.extend(b);
        }
        self.mstores.truncate(self.mstores.len() - 2);
        Some((val, resolved, bytes))
    }

    /// `e` in terms of the block's entry values, for analysis: bound
    /// variables are replaced by what they were bound to, entry slots
    /// by their known values, and anything else by [`UNKNOWN`].
    fn resolve(&self, e: &Expr) -> Expr {
        match e {
            Expr::Var(n) => {
                if let Some(v) = self.resolved.get(n) {
                    return v.clone();
                }
                if n.starts_with("param") || n.starts_with("L_") {
                    return e.clone();
                }
                self.entry_pos(n)
                    .and_then(|p| self.entry.get(&p))
                    .cloned()
                    .unwrap_or_else(|| Expr::Op(UNKNOWN, Vec::new()))
            }
            Expr::Op(op, args) => {
                let r = simplify(Expr::Op(op, args.iter().map(|a| self.resolve(a)).collect()));
                // Values are trees, so repeated substitution can grow
                // them geometrically; analysis only needs small ones.
                if r.nodes() > RESOLVE_MAX_NODES {
                    Expr::Op(UNKNOWN, Vec::new())
                } else {
                    r
                }
            }
            Expr::Const(_) => e.clone(),
        }
    }

    /// Record a binding of `name` for both rendering and analysis.
    fn bind(&mut self, name: &str, val: Expr) {
        let resolved = if matches!(val, Expr::Op("fmp", _)) {
            Expr::Op(UNKNOWN, Vec::new())
        } else {
            self.resolve(&val)
        };
        self.bind_resolved(name, val, resolved);
    }

    fn bind_resolved(&mut self, name: &str, val: Expr, resolved: Expr) {
        // The value in terms of no variable at all, where it is one
        // (pointer arithmetic over free-memory-pointer reads, mostly).
        let mut flat = val.clone();
        for (v, f) in &self.flat {
            if flat.mentions(v) {
                flat = flat.substitute(v, f);
            }
        }
        if mentions_var(&flat, &|v| !v.starts_with("param") && !v.starts_with("L_"))
            || flat.nodes() > RESOLVE_MAX_NODES
        {
            self.flat.remove(name);
        } else {
            self.flat.insert(name.to_string(), flat);
        }
        self.resolved.insert(name.to_string(), resolved);
        self.bindings.insert(name.to_string(), val);
    }

    /// Frame position of the entry slot called `name`.
    fn entry_pos(&self, name: &str) -> Option<i64> {
        let d = self.depth?;
        let num = |s: &str| s.parse::<i64>().ok();
        let pos = match d.frame {
            Some(_) if name == "ret" => 0,
            Some(_) => match name.strip_prefix("arg") {
                Some(k) => num(k)? + 1,
                None => num(name.strip_prefix('v')?)?,
            },
            None => num(name.strip_prefix('v')?)?,
        };
        (pos < d.depth).then_some(pos)
    }

    /// The stack as control leaves the block, resolved, by frame
    /// position: slots below what the block touched keep their entry
    /// values.
    fn exit_values(&self) -> Option<HashMap<i64, Expr>> {
        let d = self.depth?;
        let base = d.depth - self.pulled as i64;
        let mut out: HashMap<i64, Expr> = self
            .entry
            .iter()
            .filter(|&(&p, _)| p < base)
            .map(|(&p, e)| (p, e.clone()))
            .collect();
        for (i, e) in self.stack.iter().enumerate() {
            out.insert(base + i as i64, self.resolve(e));
        }
        Some(out)
    }

    /// `calldataload(4 + 32k)` as the external function's parameter
    /// in head word `k`.
    fn param_at(&self, offset: &Expr) -> Option<Expr> {
        let rel = offset.const_value()?.checked_sub(4)?;
        if rel % 32 != 0 {
            return None;
        }
        let k = usize::try_from(rel / 32).ok()?;
        self.params.get(k).map(|name| Expr::Var(name.clone()))
    }

    /// `e` with its calldata reads at parameter offsets named.
    fn paramize(&self, e: Expr) -> Expr {
        match e {
            Expr::Op("calldataload", a) if a.len() == 1 && self.param_at(&a[0]).is_some() => {
                self.param_at(&a[0]).expect("checked")
            }
            Expr::Op(op, a) => Expr::Op(op, a.into_iter().map(|x| self.paramize(x)).collect()),
            other => other,
        }
    }

    fn slot_name(&self, pos: i64) -> Option<String> {
        let d = self.depth?;
        if pos < 0 {
            return None;
        }
        Some(match d.frame {
            Some(entry) => {
                let info = &self.ctx.cfg.functions[&entry];
                let (below, nargs) = (info.nbelow as i64, info.nargs as i64);
                match pos {
                    p if p < below => format!("arg{p}"),
                    p if p == below && !info.ret_spilled => "ret".to_string(),
                    p if p > below && p <= below + nargs => format!("arg{}", p - 1),
                    p => format!("v{p}"),
                }
            }
            None => format!("v{pos}"),
        })
    }

    /// Frame position of stack index `i` (0 = bottom of `stack`).
    fn pos_of(&self, i: usize) -> Option<i64> {
        self.depth.map(|d| d.depth - self.pulled as i64 + i as i64)
    }

    fn name_at(&self, i: usize) -> Option<String> {
        self.pos_of(i).and_then(|p| self.slot_name(p))
    }

    fn entry_name(&self, j: usize) -> String {
        self.depth
            .and_then(|d| self.slot_name(d.depth - 1 - j as i64))
            .unwrap_or_else(|| format!("s{j}"))
    }

    /// Record the names of the stack items into the trace, if one is
    /// being kept: before instruction `at`, or (`fall`) after a block
    /// ending just before it.
    fn record(&self, at: usize, fall: bool) {
        let Some(trace) = self.ctx.trace else {
            return;
        };
        let mut names: Vec<SlotNames> = self
            .stack
            .iter()
            .enumerate()
            .rev()
            .map(|(i, e)| SlotNames {
                var: match e {
                    Expr::Var(v) => Some(v.clone()),
                    _ => None,
                },
                slot: self.name_at(i),
            })
            .take(TRACE_DEPTH)
            .collect();
        let mut j = self.pulled;
        while names.len() < TRACE_DEPTH {
            names.push(SlotNames {
                var: match self.entry_item(j) {
                    Expr::Var(v) => Some(v),
                    _ => None,
                },
                slot: Some(self.entry_name(j)),
            });
            j += 1;
        }
        let mut t = trace.borrow_mut();
        let map = if fall { &mut t.fall_end } else { &mut t.before };
        map.insert(at, names);
    }

    fn ensure(&mut self, n: usize) {
        while self.stack.len() < n {
            let item = self.entry_item(self.pulled);
            self.stack.insert(0, item);
            self.pulled += 1;
        }
    }

    /// The `j`th entry item from the top: its known value when that
    /// reads better than the slot name (see [`shows_inline`]), else
    /// the slot variable.
    fn entry_item(&self, j: usize) -> Expr {
        self.depth
            .and_then(|d| self.entry.get(&(d.depth - 1 - j as i64)))
            .filter(|e| shows_inline(e))
            .cloned()
            .unwrap_or_else(|| Expr::Var(self.entry_name(j)))
    }

    fn pop(&mut self) -> Expr {
        self.ensure(1);
        self.stack.pop().expect("ensured")
    }

    fn pop_n(&mut self, n: usize) -> Vec<Expr> {
        (0..n).map(|_| self.pop()).collect()
    }

    fn take(&mut self, upto: usize) -> Vec<u8> {
        let bytes = self.ctx.insns[self.pending..=upto]
            .iter()
            .flat_map(|i| i.original_bytes.iter().copied())
            .collect();
        self.pending = upto + 1;
        bytes
    }

    /// A variable name for a value that will sit at stack index `i`,
    /// avoiding any name still referenced by another live value.
    fn bind_name(&mut self, i: usize) -> String {
        if let Some(name) = self.name_at(i)
            && !self
                .stack
                .iter()
                .enumerate()
                .any(|(j, e)| j != i && e.mentions(&name))
        {
            return name;
        }
        *self.temps += 1;
        format!("t{}", self.temps)
    }

    fn emit_assign(&mut self, dst: String, src: String, upto: usize) {
        let bytes = self.take(upto);
        self.out.push(Stmt::Move { dst, src, bytes });
    }

    fn emit_call(&mut self, name: &str, args: &[Expr], upto: usize) {
        let bytes = self.take(upto);
        self.out.push(Stmt::Call {
            name: name.to_string(),
            args: args.iter().map(render_arg).collect(),
            bytes,
            direct_target: None,
        });
    }

    /// Slots whose content changed, as `(names, values)`.
    fn exit_writes(&self) -> Option<(Vec<String>, Vec<Expr>)> {
        let mut names = Vec::new();
        let mut vals = Vec::new();
        for (i, e) in self.stack.iter().enumerate() {
            let name = self
                .name_at(i)
                .unwrap_or_else(|| format!("s{}", self.pulled as i64 - 1 - i as i64));
            // A slot still holding its entry value needs no write-back.
            let unchanged = i < self.pulled && *e == self.entry_item(self.pulled - 1 - i);
            if !unchanged && *e != Expr::Var(name.clone()) {
                names.push(name);
                vals.push(e.clone());
            }
        }
        (!names.is_empty()).then_some((names, vals))
    }

    fn assign_text(names: &[String], vals: &[Expr]) -> (String, String) {
        if names.len() == 1 {
            (names[0].clone(), render_rhs(&vals[0]))
        } else {
            let srcs: Vec<String> = vals.iter().map(render_arg).collect();
            (names.join(", "), srcs.join(", "))
        }
    }

    /// Write back changed slots; if that needs a statement, it takes
    /// the bytes through `upto` and the caller's statement gets none.
    /// Returns whether it did.
    fn flush_exit(&mut self, upto: usize) -> bool {
        let Some((names, vals)) = self.exit_writes() else {
            return false;
        };
        let (dst, src) = Self::assign_text(&names, &vals);
        self.emit_assign(dst, src, upto);
        true
    }

    /// Bytes for the control statement ending at instruction `i`
    /// (a jump). Pending slot write-backs are emitted first and take
    /// everything before `i`, leaving the jump its own instruction.
    fn jump_bytes(&mut self, i: usize) -> Vec<u8> {
        if self.exit_writes().is_none() {
            return self.take(i);
        }
        if self.pending < i {
            self.flush_exit(i - 1);
            self.take(i)
        } else {
            self.flush_exit(i);
            Vec::new()
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run(&mut self, b: usize) -> BlockEnd {
        let cfg = self.ctx.cfg;
        self.last = b;
        let blk = cfg.blocks[b].clone();
        let last = blk.insns.end - 1;
        // Vyper 0.2 returns with `mload(slot); JUMP`, its return address
        // spilled to memory on entry: reads that only feed the return
        // (that load and the values below it) stay in the `return`.
        let spilled_return = blk.term == Term::Jump
            && cfg.role[b] == JumpRole::Return
            && self
                .depth
                .and_then(|d| d.frame)
                .is_some_and(|f| cfg.functions[&f].ret_spilled);
        let quiet_tail = if spilled_return {
            let quiet = self.ctx.insns[blk.insns.start..last]
                .iter()
                .rev()
                .take_while(|n| matches!(n.opcode, 0x51 | 0x5f..=0x9f))
                .count();
            last - quiet
        } else {
            usize::MAX
        };
        for i in blk.insns.clone() {
            self.record(i, false);
            let ins = &self.ctx.insns[i];
            let op = ins.opcode;
            // A statement on the last instruction of a fall-through
            // block would leave the slot write-back with no bytes, so
            // value-producing statements defer to it there.
            let defer = (blk.term == Term::Fall && i == last) || (op == 0x51 && i >= quiet_tail);
            match op {
                0x5b => {}
                0x5f..=0x7f => {
                    // A pending return address reads better as its label.
                    let label = ins
                        .push_value()
                        .filter(|v| self.ctx.continuations.contains(v));
                    self.stack.push(match label {
                        Some(v) => Expr::Var(format!("L_{v:04x}")),
                        None => Expr::Const(ins.immediate().to_vec()),
                    });
                }
                0x58 => self
                    .stack
                    .push(Expr::Const(ins.addr.0.to_be_bytes().to_vec())),
                0x50 => {
                    self.pop();
                }
                0x80..=0x8f => {
                    let n = usize::from(op - 0x80) + 1;
                    self.ensure(n);
                    let idx = self.stack.len() - n;
                    if self.stack[idx].nodes() > DUP_INLINE_MAX_NODES && !defer {
                        let name = self.bind_name(idx);
                        let val = std::mem::replace(&mut self.stack[idx], Expr::Var(name.clone()));
                        self.emit_assign(name.clone(), render_rhs(&val), i);
                        self.bind(&name, val);
                    }
                    let v = self.stack[idx].clone();
                    self.stack.push(v);
                }
                0x90..=0x9f => {
                    let n = usize::from(op - 0x90) + 1;
                    self.ensure(n + 1);
                    let len = self.stack.len();
                    self.stack.swap(len - 1, len - 1 - n);
                }
                _ if env_name(op).is_some() => {
                    self.stack.push(Expr::Op(env_name(op).unwrap(), vec![]));
                }
                _ if pure_name(op).is_some() => {
                    let args = self.pop_n(OPCODE_TABLE[op as usize].pops.into());
                    let param = (op == 0x35).then(|| self.param_at(&args[0])).flatten();
                    self.stack.push(match param {
                        Some(p) => p,
                        None => simplify(Expr::Op(pure_name(op).unwrap(), args)),
                    });
                }
                0x20 if !defer && self.mapping_ready() => {
                    let args = self.pop_n(2);
                    if let Some((val, resolved, mut bytes)) = self.take_mapping_stores(&args) {
                        // A slot address is a pure function of its
                        // inputs: keep it as an expression.
                        bytes.extend(self.take(i));
                        let idx = self.stack.len();
                        // Not a name the slot expression uses, so a
                        // later read can fold nested mappings back in.
                        let mut name = self.bind_name(idx);
                        if val.mentions(&name) {
                            *self.temps += 1;
                            name = format!("t{}", self.temps);
                        }
                        self.out.push(Stmt::Move {
                            dst: name.clone(),
                            src: render_rhs(&val),
                            bytes,
                        });
                        self.bind_resolved(&name, val, resolved);
                        self.stack.push(Expr::Var(name));
                    } else {
                        self.bind_read(&Expr::Op("keccak256", args), i);
                    }
                }
                // Vyper 0.1 / 0.2 dispatch: `PUSH4 sel; PUSH1 0; MLOAD; EQ`
                // reads the selector it stored at memory 0 on entry.
                0x51 if self.ctx.vyper
                    && i >= 2
                    && self.ctx.insns[i - 2].opcode == 0x63
                    && self.ctx.insns.get(i + 1).is_some_and(|n| n.opcode == 0x14)
                    && self.stack.last().and_then(Expr::const_value) == Some(0) =>
                {
                    self.pop();
                    self.stack.push(Expr::Op("msg.sig", vec![]));
                }
                _ if read_name(op).is_some() => {
                    let args = self.pop_n(OPCODE_TABLE[op as usize].pops.into());
                    let val = Expr::Op(read_name(op).unwrap(), args);
                    if defer {
                        self.stack.push(val);
                    } else {
                        self.bind_read(&val, i);
                    }
                }
                _ if effect_name(op).is_some() => {
                    let args = self.pop_n(OPCODE_TABLE[op as usize].pops.into());
                    let event = (0xa1..=0xa4)
                        .contains(&op)
                        .then(|| match &args[2] {
                            Expr::Const(t) if t.len() == 32 => {
                                event_by_topic(t.as_slice().try_into().expect("32"))
                            }
                            _ => None,
                        })
                        .flatten();
                    if let Some(sig) = event {
                        if let Some((data, _, bytes)) = self.collapse_encoded(&args[0], &args[1], i)
                        {
                            // `emit Name(indexed…, data…)`: compilers put
                            // indexed parameters first in the vast
                            // majority of events; the comment keeps the
                            // declared types.
                            let name = sig.split('(').next().unwrap_or(sig);
                            let parts: Vec<String> =
                                args[3..].iter().chain(&data).map(render_arg).collect();
                            self.out.push(Stmt::Comment(format!("event {sig}")));
                            self.out.push(Stmt::Call {
                                name: "emit".into(),
                                args: vec![format!("{name}({})", parts.join(", "))],
                                bytes,
                                direct_target: None,
                            });
                            continue;
                        }
                        self.out.push(Stmt::Comment(format!("event {sig}")));
                    }
                    let (args, prefix) = self.inline_last(args);
                    if op == 0x39
                        && let Some(text) = self.copied_string(&args[1], &args[2])
                    {
                        self.out.push(Stmt::Comment(text));
                    }
                    if op == 0x52 {
                        if args[0].const_value() == Some(0x40) {
                            self.fmp_epoch += 1;
                            self.fmp_id = None;
                        }
                        self.mstores.push(MStore {
                            at: self.out.len(),
                            offset: args[0].clone(),
                            value: args[1].clone(),
                            place: lin(&args[0], &self.bindings, 0),
                            resolved: self.resolve(&args[1]),
                            rplace: rlin(&self.resolve(&args[0])),
                        });
                    }
                    // A store to named storage reads as an assignment.
                    // Not on a fall-through block's last instruction,
                    // whose bytes a slot write-back may need to take.
                    if op == 0x55
                        && !defer
                        && let Some(place) = storage_lvalue(&args[0])
                    {
                        let mut bytes = prefix;
                        bytes.extend(self.take(i));
                        self.out.push(Stmt::Move {
                            dst: render_raw(&place),
                            src: render_rhs(&args[1]),
                            bytes,
                        });
                        continue;
                    }
                    let mut bytes = prefix;
                    bytes.extend(self.take(i));
                    self.out.push(Stmt::Call {
                        name: effect_name(op).unwrap().to_string(),
                        args: args.iter().map(render_arg).collect(),
                        bytes,
                        direct_target: None,
                    });
                }
                0x00 => {
                    self.emit_call("stop", &[], i);
                    return BlockEnd::Other;
                }
                0xf3 => {
                    let args = self.pop_n(2);
                    let (text, bytes) = match self.collapse_encoded(&args[0], &args[1], i) {
                        Some((words, resolved, bytes)) => {
                            self.encoded = Some(resolved);
                            let parts: Vec<String> = words.iter().map(render_arg).collect();
                            (format!("abi.encode({})", parts.join(", ")), bytes)
                        }
                        None => (
                            format!("memory({}, {})", render_arg(&args[0]), render_arg(&args[1])),
                            self.take(i),
                        ),
                    };
                    self.out.push(Stmt::ReturnExpr { text, bytes });
                    return BlockEnd::Other;
                }
                0xfd => {
                    let args = self.pop_n(2);
                    if !self.collapse_revert(i) {
                        self.emit_call("revert", &args, i);
                    }
                    return BlockEnd::Other;
                }
                0xff => {
                    let args = self.pop_n(1);
                    self.emit_call("selfdestruct", &args, i);
                    return BlockEnd::Other;
                }
                0x56 => return self.lift_jump(b, i),
                0x57 => {
                    let target = self.pop();
                    // Only the condition's truth matters: `a ^ b` (Vyper's
                    // selector test) is `a != b`.
                    let cond = match self.pop() {
                        Expr::Op("xor", ab) => simplify(Expr::Op("ne", ab)),
                        c => c,
                    };
                    if let Some(next) = self.try_chain(b, i, &cond) {
                        return self.run(next);
                    }
                    self.exit = self.exit_values();
                    let bytes = self.jump_bytes(i);
                    let target = target.const_value().or_else(|| {
                        let t = &cfg.targets[b];
                        (t.len() == 1).then(|| cfg.blocks[*t.iter().next().unwrap()].start)
                    });
                    return BlockEnd::Cond {
                        cond,
                        target,
                        bytes,
                    };
                }
                // INVALID and unassigned opcodes.
                _ => {
                    self.emit_call("invalid", &[], i);
                    return BlockEnd::Other;
                }
            }
        }
        // Fell off the end of the block.
        self.exit = self.exit_values();
        self.record(blk.insns.end, true);
        if self.exit_writes().is_some() {
            if self.pending < blk.insns.end {
                self.flush_exit(last);
            } else if let Some(bytes) = self.steal_last_call_bytes() {
                let (names, vals) = self.exit_writes().expect("checked");
                let (dst, src) = Self::assign_text(&names, &vals);
                self.out.push(Stmt::Move { dst, src, bytes });
            }
        } else if self.pending < blk.insns.end {
            let rest = &self.ctx.insns[self.pending..blk.insns.end];
            self.out.extend((self.ctx.listing)(rest));
            self.pending = blk.insns.end;
        }
        BlockEnd::Other
    }

    /// Lift on through a guard: when block `b` ends in a `JUMPI` (at
    /// instruction `i`, on `cond`) that falls through into a block that
    /// only fails and otherwise jumps to the block right after it, and
    /// both are entered only from here and come next in the slice,
    /// emit `require(cond, …)` and return the continuation, to be
    /// lifted with the stack and memory as this block left them. Only
    /// done where the continuation makes an external call, so a call's
    /// setup and the call itself (solc ≤0.8 checks `extcodesize` in
    /// between) are seen together.
    fn try_chain(&mut self, b: usize, i: usize, cond: &Expr) -> Option<usize> {
        let cfg = self.ctx.cfg;
        let [fail_b, cont, ..] = *self.rest else {
            return None;
        };
        let blk = &cfg.blocks[b];
        let d = self.depth?;
        let at_t = BlockDepth {
            frame: d.frame,
            depth: self.pos_of(self.stack.len())?,
        };
        let calls = cfg.blocks[cont]
            .insns
            .clone()
            .any(|k| matches!(self.ctx.insns[k].opcode, 0xf1 | 0xf2 | 0xf4 | 0xfa));
        let after_call = self.folded.as_ref().is_some_and(|fc| {
            self.out.len() == fc.at + 1
                && strip_cleanup(&negate(negate(cond.clone()))) == &Expr::Var(fc.var.clone())
        });
        let ok = (calls || after_call)
            && cfg.blocks[fail_b].start == blk.end
            && cfg.blocks[cont].start == cfg.blocks[fail_b].end
            && cfg.blocks[fail_b].term == Term::Halt
            && cfg.targets[b].len() == 1
            && cfg.targets[b].contains(&cont)
            && cfg.preds[fail_b] == [b]
            && cfg.preds[cont] == [b]
            && cfg.reached[fail_b]
            && cfg.reached[cont]
            && cfg.depth[cont] == Some(at_t)
            && !cfg.functions.contains_key(&cont);
        if !ok || self.pending > i {
            return None;
        }
        let pending = self.pending;
        let mut jumpi = self.take(i);
        let fail = self.inline_failure(fail_b);
        // `if (!success) { returndatacopy(…); revert(…) }` right after a
        // folded call is how Solidity's high-level call bubbles a
        // failure up, and `if (!success) { revert(0, 0) }` how Vyper's
        // fails: the call statement takes the check in and reads as one.
        if after_call
            && fail
                .as_deref()
                .is_some_and(|s| is_bubble(s) || is_plain_revert(s))
        {
            let fc = self.folded.take().expect("checked");
            for st in fail.unwrap_or_default() {
                if let Stmt::Move { bytes, .. } | Stmt::Call { bytes, .. } = st {
                    jumpi.extend(bytes);
                }
            }
            if let Some(Stmt::Move { src, bytes, .. }) = self.out.get_mut(fc.at) {
                bytes.extend(jumpi);
                *src = fc.text(true);
            }
            self.rest = &self.rest[2..];
            return Some(cont);
        }
        let Some(guard) = fail
            .and_then(single_failure)
            .and_then(|fail| as_guard(cond, &jumpi, std::slice::from_ref(&fail)))
        else {
            self.pending = pending;
            return None;
        };
        if mentions_op(&self.resolve(cond), "extcodesize") {
            self.code_checks.insert(self.out.len());
        }
        self.out.push(guard);
        self.rest = &self.rest[2..];
        Some(cont)
    }

    /// Lift failure block `f` from the current state, which is left
    /// as it was (but for the instructions consumed), to the
    /// statements it ends in.
    fn inline_failure(&mut self, f: usize) -> Option<Vec<Stmt>> {
        let saved = (
            self.stack.clone(),
            self.pulled,
            std::mem::take(&mut self.out),
            std::mem::take(&mut self.mstores),
            (self.bindings.clone(), self.flat.clone()),
            self.resolved.clone(),
            *self.temps,
            (self.fmp_epoch, self.fmp_id),
            (self.rest, self.last),
        );
        let start = self.pending;
        self.rest = &[];
        self.run(f);
        let stmts = std::mem::take(&mut self.out);
        let (stack, pulled, out, mstores, bindings, resolved, temps, fmp, rest) = saved;
        self.out = out;
        self.stack = stack;
        self.pulled = pulled;
        self.mstores = mstores;
        (self.bindings, self.flat) = bindings;
        self.resolved = resolved;
        *self.temps = temps;
        (self.fmp_epoch, self.fmp_id) = fmp;
        (self.rest, self.last) = rest;
        self.exit = None;
        self.returned = None;
        self.encoded = None;
        (self.pending == self.ctx.cfg.blocks[f].insns.end && start <= self.pending).then_some(stmts)
    }

    /// Fold an ABI-encoded `Error(string)` / `Panic(uint256)` revert
    /// built in this block into `revert("reason")` / `panic(code)`.
    /// The payload is written to fresh memory with `mstore`s (and a
    /// `codecopy` for long strings) right before the `REVERT`; those
    /// statements carry no other effect worth showing, since a revert
    /// discards everything.
    fn collapse_revert(&mut self, i: usize) -> bool {
        const ERROR: u32 = 0x08c3_79a0;
        const PANIC: u32 = 0x4e48_7b71;
        let Some(start) = self
            .mstores
            .iter()
            .rev()
            .find_map(|m| Some((m.at, shifted_selector(&m.value)?)))
        else {
            return false;
        };
        let (mut at, sel) = start;
        // The free-memory-pointer read that located the payload.
        if at > 0 && matches!(&self.out[at - 1], Stmt::Move { src, .. } if src == "mload(0x40)") {
            at -= 1;
        }
        let tail = &self.out[at..];
        let only_payload = tail.iter().all(|st| match st {
            Stmt::Move { .. } | Stmt::Comment(_) => true,
            Stmt::Call { name, .. } => matches!(name.as_str(), "mstore" | "codecopy"),
            _ => false,
        });
        if !only_payload {
            return false;
        }
        let stores: Vec<&Expr> = self
            .mstores
            .iter()
            .filter(|m| m.at > at)
            .map(|m| &m.value)
            .collect();
        let (name, arg) = if sel != ERROR && sel != PANIC {
            // Custom error: `revert(Name(args…))`, args being the words
            // stored after the selector.
            let name = crate::signatures::evm::function_by_selector(sel)
                .and_then(|sig| sig.split('(').next())
                .map_or_else(|| format!("error_0x{sel:08x}"), str::to_string);
            let args: Vec<String> = stores.iter().map(|v| render_arg(v)).collect();
            ("revert", format!("{name}({})", args.join(", ")))
        } else if sel == ERROR {
            // A `codecopy`'d reason is already a quoted comment; a short
            // one is the last `mstore`'d word.
            let copied = tail.iter().find_map(|st| match st {
                Stmt::Comment(c) if c.starts_with('"') => {
                    Some(c.trim_matches('"').replace("\\\"", "\""))
                }
                _ => None,
            });
            let inline =
                || multiword_reason(&stores).or_else(|| stores.last().and_then(|v| ascii_word(v)));
            let Some(reason) = copied.or_else(inline) else {
                return false;
            };
            ("revert", reason)
        } else {
            let Some(code) = stores.first() else {
                return false;
            };
            ("panic", render_arg(code))
        };
        let mut bytes: Vec<u8> = Vec::new();
        for st in self.out.drain(at..) {
            match st {
                Stmt::Move { bytes: b, .. } | Stmt::Call { bytes: b, .. } => bytes.extend(b),
                _ => {}
            }
        }
        bytes.extend(self.take(i));
        self.mstores.retain(|m| m.at < at);
        self.out.push(Stmt::Call {
            name: name.into(),
            args: vec![arg],
            bytes,
            direct_target: None,
        });
        true
    }

    /// `codecopy` of printable text (revert reasons, mostly) as a
    /// quoted comment.
    fn copied_string(&self, offset: &Expr, len: &Expr) -> Option<String> {
        let off = usize::try_from(offset.const_value()?).ok()?;
        let len = usize::try_from(len.const_value()?).ok()?;
        let bytes = self.ctx.code.get(off..off.checked_add(len)?)?;
        let text = std::str::from_utf8(bytes).ok()?;
        (!text.is_empty() && text.chars().all(|c| c.is_ascii_graphic() || c == ' '))
            .then(|| format!("{text:?}"))
    }

    fn mapping_ready(&self) -> bool {
        self.mstores.len() >= 2
    }

    /// Bind a state read to the variable for the slot it lands in.
    fn bind_read(&mut self, val: &Expr, i: usize) {
        let is_fmp = matches!(val, Expr::Op("mload", a) if a[0].const_value() == Some(0x40));
        // Before inlining: inlined values may name variables since
        // rebound.
        let resolved = if is_fmp {
            let id = *self.fmp_id.get_or_insert(i as u64);
            Expr::Op(MPTR, vec![Expr::Const(id.to_be_bytes().to_vec())])
        } else {
            self.resolve(val)
        };
        if self.fold_external_call(val, &resolved, i) {
            return;
        }
        let (val, mut bytes) = if is_fmp {
            (val.clone(), Vec::new())
        } else {
            let Expr::Op(op, args) = val.clone() else {
                unreachable!("reads are ops")
            };
            let (args, prefix) = self.inline_last(args);
            (Expr::Op(op, args), prefix)
        };
        let src = self
            .stipend_send(&val, &resolved)
            .unwrap_or_else(|| render_rhs(&val));
        let idx = self.stack.len();
        let name = self.bind_name(idx);
        bytes.extend(self.take(i));
        self.out.push(Stmt::Move {
            dst: name.clone(),
            src,
            bytes,
        });
        let bound = if is_fmp {
            Expr::Op(
                "fmp",
                vec![Expr::Const(self.fmp_epoch.to_be_bytes().to_vec())],
            )
        } else {
            val
        };
        self.bind_resolved(&name, bound, resolved);
        self.stack.push(Expr::Var(name));
    }

    /// `call(!v * 2300, to, v, p, 0, p, 0)` — a value transfer with
    /// only the gas stipend, no data and nothing returned — is
    /// Solidity's `to.send(v)` (`to.transfer(v)` when a `require` of
    /// the result follows). `resolved` is `val` resolved.
    fn stipend_send(&self, val: &Expr, resolved: &Expr) -> Option<String> {
        let (Expr::Op("call", a), Expr::Op("call", r)) = (val, resolved) else {
            return None;
        };
        let stipend = |x: &Expr, y: &Expr| {
            x.const_value() == Some(2300)
                && matches!(y, Expr::Op("iszero", v) if v.len() == 1 && v[0] == r[2])
        };
        let gas_ok = matches!(&r[0], Expr::Op("mul", m) if m.len() == 2
            && (stipend(&m[0], &m[1]) || stipend(&m[1], &m[0])));
        let no_input = a[4].const_value() == Some(0)
            || matches!(simplify(a[4].clone()), Expr::Op("sub", ab) if ab.len() == 2
                && lin(&ab[0], &self.bindings, 0).is_some()
                && lin(&ab[0], &self.bindings, 0) == lin(&ab[1], &self.bindings, 0));
        if !(gas_ok && no_input && a[6].const_value() == Some(0)) {
            return None;
        }
        // Member syntax only after a plain name: the text format's `.`
        // lives inside identifiers.
        let to = match &a[1] {
            Expr::Op("address", x) if x.len() == 1 => &x[0],
            other => other,
        };
        let name = render_arg(to);
        let value = render_arg(&a[2]);
        Some(
            if name.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
                && name
                    .chars()
                    .all(|c| c == '_' || c == '.' || c.is_ascii_alphanumeric())
            {
                format!("{name}.send({value})")
            } else {
                format!("send({}, {value})", render_arg(&a[1]))
            },
        )
    }

    /// The most recent store covering bytes `[start, start + n)` of
    /// memory at `base`, if one stored them all and no store after it
    /// (or at a place analysis can't follow) touched them.
    fn store_covering(&self, base: Option<&Expr>, start: u64, n: u64) -> Option<&MStore> {
        for m in self.mstores.iter().rev() {
            let (b, q) = m.rplace.as_ref()?;
            if b.as_ref() != base || q + 32 <= start || start + n <= *q {
                continue;
            }
            return (*q <= start && start + n <= q + 32).then_some(m);
        }
        None
    }

    /// A `CALL` / `STATICCALL` whose input is a selector and static ABI
    /// words stored in memory just before it — `mstore(p, sel << 224);
    /// mstore(p + 4, a); …; call(g, t, v, p, 4 + 32n, …)`, or Vyper's
    /// selector right-aligned in the word before the input — reads as
    /// `Iface(t).name(a, …)`, and `t.call(0x…, a, …)` for an unknown
    /// selector. The encoding statements fold into the call's, which
    /// assigns the call's success flag. `resolved` is `val` resolved.
    /// Returns whether it emitted the statement.
    fn fold_external_call(&mut self, val: &Expr, resolved: &Expr, i: usize) -> bool {
        let (Expr::Op(kind @ ("call" | "staticcall"), a), Expr::Op(_, r)) = (val, resolved) else {
            return false;
        };
        let Some((mut fc, first)) = self.external_call_text(kind, a, r) else {
            return false;
        };
        let text = fc.text(false);
        let mut bytes = Vec::new();
        for st in self.out.drain(first..) {
            match st {
                Stmt::Move { bytes: b, .. } | Stmt::Call { bytes: b, .. } => bytes.extend(b),
                _ => {}
            }
        }
        self.mstores.retain(|m| m.at < first);
        bytes.extend(self.take(i));
        let idx = self.stack.len();
        let name = self.bind_name(idx);
        self.out.push(Stmt::Move {
            dst: name.clone(),
            src: text,
            bytes,
        });
        // The raw call must not be inlined back into a later statement.
        self.bind_resolved(
            &name,
            Expr::Op(FOLDED_CALL, vec![val.clone()]),
            resolved.clone(),
        );
        fc.at = self.out.len() - 1;
        fc.var.clone_from(&name);
        self.folded = Some(fc);
        self.stack.push(Expr::Var(name));
        true
    }

    /// The text of an external call folded by
    /// [`Self::fold_external_call`] and the index of the first
    /// statement it absorbs. Rewrites stack items that name variables
    /// bound in the absorbed statements to their values.
    #[allow(clippy::too_many_lines)]
    fn external_call_text(
        &mut self,
        kind: &'static str,
        a: &[Expr],
        r: &[Expr],
    ) -> Option<(FoldedCall, usize)> {
        let (value, at) = if kind == "call" {
            (Some(&a[2]), 3)
        } else {
            (None, 2)
        };
        let (base, off) = rlin(&r[at])?;
        let (None, len) = rlin(&r[at + 1])? else {
            return None;
        };
        if len < 4 || (len - 4) % 32 != 0 || len > 4 + 32 * 16 {
            return None;
        }
        let nargs = usize::try_from((len - 4) / 32).ok()?;
        let base = base.as_ref();
        let sel_store = self.store_covering(base, off, 4)?;
        let rel = off - sel_store.rplace.as_ref()?.1;
        let sel = word_bytes4(&sel_store.resolved, rel)?;
        if let Some(sig) = crate::signatures::evm::function_by_selector(sel)
            && super::evm::static_head_words(sig) != Some(nargs)
        {
            return None;
        }
        let mut first = sel_store.at;
        let mut used = vec![sel_store.at];
        let mut words = Vec::new();
        for k in 0..nargs as u64 {
            let m = self.store_covering(base, off + 4 + 32 * k, 32)?;
            if m.rplace.as_ref()?.1 != off + 4 + 32 * k {
                return None;
            }
            first = first.min(m.at);
            used.push(m.at);
            words.push((m.at, m.value.clone(), m.resolved.clone()));
        }
        // Take in the pointer reads that located the buffer.
        while first > 0
            && matches!(&self.out[first - 1], Stmt::Move { src, .. } if src == "mload(0x40)")
        {
            first -= 1;
        }
        // A buffer pointer the code goes on using (the output, often)
        // keeps its assignment.
        while let Some(Stmt::Move { dst, .. }) = self.out.get(first)
            && matches!(self.bindings.get(dst), Some(Expr::Op("fmp", _)))
            && self.stack.iter().any(|e| e.mentions(dst))
        {
            first += 1;
        }
        // Only encoding work may be folded away: the stores, and
        // single assignments that compute pointers or read state.
        let mut dropped: Vec<String> = Vec::new();
        for (k, st) in self.out.iter().enumerate().skip(first) {
            match st {
                Stmt::Comment(_) => {}
                Stmt::Call { name, .. } if name == "mstore" && used.contains(&k) => {}
                Stmt::Call { name, .. } if name == "require" && self.code_checks.contains(&k) => {}
                Stmt::Move { dst, .. }
                    if !dst.contains(',')
                        && !matches!(self.bindings.get(dst), Some(Expr::Op(op, _))
                            if read_name_has_effects(op)) =>
                {
                    dropped.push(dst.clone());
                }
                _ => return None,
            }
        }
        // Words name the variables they were stored from; those must
        // still hold the same values at the call.
        for (at, value, _) in &words {
            let reassigned = self.out[at + 1..]
                .iter()
                .any(|st| matches!(st, Stmt::Move { dst, .. } if value.mentions(dst)));
            if reassigned {
                return None;
            }
        }
        // Values bound in the dropped statements are put in: free-memory
        // pointer reads as `mload(0x40)`, which still reads the same at
        // the call (any `mstore(0x40, …)` would have stopped the fold).
        let epoch = Expr::Const(self.fmp_epoch.to_be_bytes().to_vec());
        //
        // Going back through the dropped assignments, each one a value
        // mentions is replaced by what it assigned, in names as they
        // were just before it — so what is left names values as they
        // were before the folded statements, where the call statement
        // now starts. Only a variable's last assignment is known.
        let unfold = |e: &Expr, bindings: &HashMap<String, Expr>| -> Option<Expr> {
            let mut e = e.clone();
            let mut seen: HashSet<&str> = HashSet::new();
            for d in dropped.iter().rev() {
                let latest = seen.insert(d.as_str());
                if !e.mentions(d) {
                    continue;
                }
                match (latest, self.flat.get(d), bindings.get(d)) {
                    (true, Some(f), _) => e = e.substitute(d, f),
                    (true, None, Some(b)) if !matches!(b, Expr::Op("fmp", _)) => {
                        e = e.substitute(d, b);
                    }
                    _ => return None,
                }
            }
            replace_fmp(&e, &epoch)
        };
        // A word whose text can't be recovered may still be a value
        // that reads the same anywhere (a parameter, a constant).
        let mut args = Vec::new();
        for (_, value, res) in &words {
            match unfold(value, &self.bindings) {
                Some(v) => args.push(v),
                None if stable_value(res) => args.push(res.clone()),
                None => return None,
            }
        }
        let to = unfold(&a[1], &self.bindings)?;
        let gas = unfold(&a[0], &self.bindings)?;
        let value = match value {
            Some(v) => Some(unfold(v, &self.bindings)?),
            None => None,
        };
        // What stays on the stack must not name a dropped variable.
        let mut stack = self.stack.clone();
        for e in &mut stack {
            *e = unfold(e, &self.bindings)?;
        }
        self.stack = stack;
        let fc = FoldedCall {
            at: 0,
            var: String::new(),
            kind,
            sel,
            gas,
            to,
            value,
            args,
        };
        Some((fc, first))
    }

    /// Fold the statement just emitted into `args` when it bound a
    /// variable that `args` use exactly once and nothing else still
    /// holds: `v3 = mapping(…); v3 = sload(v3)` reads as
    /// `v3 = sload(mapping(…))`. Repeats while it applies. Returns the
    /// folded statements' bytes, which precede the caller's.
    fn inline_last(&mut self, mut args: Vec<Expr>) -> (Vec<Expr>, Vec<u8>) {
        let mut prefix: Vec<u8> = Vec::new();
        while let Some(Stmt::Move { dst, .. }) = self.out.last() {
            let dst = dst.clone();
            let Some(bound) = self.bindings.get(&dst).cloned() else {
                break;
            };
            let uses: usize = args.iter().map(|a| a.count(&dst)).sum();
            if matches!(bound, Expr::Op("fmp" | FOLDED_CALL, _))
                || uses != 1
                || self.stack.iter().any(|e| e.mentions(&dst))
            {
                break;
            }
            let Some(Stmt::Move { bytes, .. }) = self.out.pop() else {
                unreachable!("checked above")
            };
            self.bindings.remove(&dst);
            self.flat.remove(&dst);
            for a in &mut args {
                *a = a.substitute(&dst, &bound);
            }
            let mut b = bytes;
            b.extend(prefix);
            prefix = b;
        }
        (args, prefix)
    }

    /// Recognise the ABI encoding of static words into fresh memory —
    /// `p = mload(0x40); mstore(p, a); mstore(p + 0x20, b); …` — feeding
    /// a `RETURN` / `LOGn` of `(offset, len)` at instruction `i`. On a
    /// match the encoding statements are removed and their bytes (plus
    /// the instruction's) returned with the words, as written and
    /// resolved.
    fn collapse_encoded(
        &mut self,
        offset: &Expr,
        len: &Expr,
        i: usize,
    ) -> Option<(Vec<Expr>, Vec<Expr>, Vec<u8>)> {
        let (base, start_off) = lin(offset, &self.bindings, 0)?;
        let n_bytes = if let Some(n) = len.const_value() {
            n
        } else {
            // `end - start` over the same buffer.
            let Expr::Op("sub", ab) = simplify(len.clone()) else {
                return None;
            };
            let (b1, o1) = lin(&ab[0], &self.bindings, 0)?;
            let (b2, o2) = lin(&ab[1], &self.bindings, 0)?;
            if b1 != b2 {
                return None;
            }
            o1.checked_sub(o2)?
        };
        if n_bytes == 0 || n_bytes % 32 != 0 || n_bytes > 32 * 16 || base.is_empty() {
            return None;
        }
        let mut first = self.out.len();
        let mut words = Vec::new();
        let mut resolved = Vec::new();
        for k in 0..n_bytes / 32 {
            let want = (base.clone(), start_off + 32 * k);
            let m = self
                .mstores
                .iter()
                .rev()
                .find(|m| m.place.as_ref() == Some(&want))?;
            first = first.min(m.at);
            words.push(m.value.clone());
            resolved.push(m.resolved.clone());
        }
        // Take in the pointer reads that located the buffer.
        while first > 0
            && matches!(&self.out[first - 1], Stmt::Move { src, .. } if src == "mload(0x40)")
        {
            first -= 1;
        }
        // Only encoding work may be folded away; its variables must be
        // dead afterwards.
        let mut dropped: Vec<String> = Vec::new();
        for st in &self.out[first..] {
            match st {
                Stmt::Comment(_) => {}
                Stmt::Call { name, .. } if name == "mstore" => {}
                Stmt::Move { dst, .. } if !dst.contains(',') => dropped.push(dst.clone()),
                _ => return None,
            }
        }
        if dropped
            .iter()
            .any(|d| self.stack.iter().any(|e| e.mentions(d)))
        {
            return None;
        }
        // Words may name variables bound inside the folded range: put
        // their values in.
        for d in dropped.iter().rev() {
            if let Some(bound) = self.bindings.get(d) {
                if matches!(bound, Expr::Op("fmp", _)) {
                    if words.iter().any(|w| w.mentions(d)) {
                        return None;
                    }
                    continue;
                }
                for w in &mut words {
                    *w = w.substitute(d, bound);
                }
            }
        }
        let mut bytes = Vec::new();
        for st in self.out.drain(first..) {
            match st {
                Stmt::Move { bytes: b, .. } | Stmt::Call { bytes: b, .. } => bytes.extend(b),
                _ => {}
            }
        }
        self.mstores.retain(|m| m.at < first);
        bytes.extend(self.take(i));
        Some((words, resolved, bytes))
    }

    /// Move the bytes of the most recent byte-carrying call statement
    /// out of it (calls may carry none; assignments may not).
    fn steal_last_call_bytes(&mut self) -> Option<Vec<u8>> {
        match self
            .out
            .iter_mut()
            .rev()
            .find(|s| !matches!(s, Stmt::Comment(_)))?
        {
            Stmt::Call { bytes, .. } if !bytes.is_empty() => Some(std::mem::take(bytes)),
            _ => None,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn lift_jump(&mut self, b: usize, i: usize) -> BlockEnd {
        let cfg = self.ctx.cfg;
        let target = self.pop();
        match cfg.role[b] {
            JumpRole::Call => {
                let c = cfg.calls[&b];
                let mut args = self.pop_n(c.nargs);
                args.reverse(); // arg0 was deepest
                self.pop(); // return address
                // Arguments passed below the return address come first.
                let mut below = self.pop_n(cfg.functions[&c.callee].nbelow);
                below.reverse();
                below.extend(args);
                let args = below;
                let callee = self.ctx.target_name(cfg.blocks[c.callee].start);
                let call_text = {
                    let parts: Vec<String> = args.iter().map(render_arg).collect();
                    format!("{callee}({})", parts.join(", "))
                };
                if cfg.tail_calls.contains(&b) {
                    // Returns to our own caller: `return f(…);`.
                    let bytes = self.take(i);
                    self.out.push(Stmt::ReturnExpr {
                        text: call_text,
                        bytes,
                    });
                    return BlockEnd::Other;
                }
                let info = cfg.functions[&c.callee];
                let nrets = info.nrets;
                // The continuation sees the stack below the call plus
                // the callee's results, as far as its summary says.
                self.exit = self.exit_values().map(|mut exit| {
                    let base = self.pos_of(self.stack.len()).unwrap_or_default();
                    let actual: Vec<Expr> = args.iter().map(|a| self.resolve(a)).collect();
                    let summary = self.summaries.get(&c.callee);
                    for k in 0..nrets.unwrap_or(0) {
                        let value = summary
                            .and_then(|s| s.get(k)?.as_ref())
                            .map_or(Expr::Op(UNKNOWN, Vec::new()), |v| {
                                self.paramize(subst_args(v, &actual))
                            });
                        // A decoded parameter replaces the result's
                        // variable; any other value keeps the call's
                        // name in the text.
                        let value = if is_param(&value) {
                            value
                        } else {
                            Expr::Op(RESULT, vec![value])
                        };
                        exit.insert(base + k as i64, value);
                    }
                    exit
                });
                let ret_names: Vec<String> = (0..nrets.unwrap_or(0))
                    .map(|k| {
                        if k == 0 && info.keeps_ret {
                            return "_".to_string();
                        }
                        let idx = self.stack.len() + k;
                        // A decoded parameter is named as such.
                        let value = self.pos_of(idx).and_then(|p| self.exit.as_ref()?.get(&p));
                        if let Some(Expr::Var(param)) = value.filter(|v| is_param(v)) {
                            return param.clone();
                        }
                        self.name_at(idx).unwrap_or_else(|| format!("r{k}"))
                    })
                    .collect();
                match (self.exit_writes(), ret_names.is_empty()) {
                    (Some((mut names, vals)), false) => {
                        let mut srcs: Vec<String> = vals.iter().map(render_arg).collect();
                        names.extend(ret_names);
                        srcs.push(call_text);
                        self.emit_assign(names.join(", "), srcs.join(", "), i);
                    }
                    (Some(_), true) => {
                        self.flush_exit(i);
                        self.out.push(Stmt::Call {
                            name: callee,
                            args: args.iter().map(render_arg).collect(),
                            bytes: Vec::new(),
                            direct_target: None,
                        });
                    }
                    (None, false) => self.emit_assign(ret_names.join(", "), call_text, i),
                    (None, true) => {
                        let bytes = self.take(i);
                        self.out.push(Stmt::Call {
                            name: callee,
                            args: args.iter().map(render_arg).collect(),
                            bytes,
                            direct_target: None,
                        });
                    }
                }
                if info.noreturn {
                    self.out.push(Stmt::Comment("does not return".into()));
                } else if nrets.is_none() {
                    self.out
                        .push(Stmt::Comment("return-value count unknown".into()));
                }
                let conts: Vec<u64> = cfg
                    .conts
                    .get(&b)
                    .into_iter()
                    .flatten()
                    .map(|&c| cfg.blocks[c].start)
                    .collect();
                match conts.as_slice() {
                    [only] if *only == cfg.blocks[b].end => {}
                    [only] => self
                        .out
                        .push(Stmt::Comment(format!("returns to L_{only:04x}"))),
                    [] => {}
                    many => {
                        let list: Vec<String> = many.iter().map(|c| format!("L_{c:04x}")).collect();
                        self.out.push(Stmt::Comment(format!(
                            "shared code: returns to the caller's continuation, one of {}",
                            list.join(", ")
                        )));
                    }
                }
            }
            JumpRole::Return => {
                let nrets = self
                    .depth
                    .and_then(|d| d.frame)
                    .and_then(|f| cfg.functions[&f].nrets)
                    .unwrap_or(0);
                let mut vals = self.pop_n(nrets);
                vals.reverse();
                self.returned = Some(vals.iter().map(|v| self.resolve(v)).collect());
                let keeps_ret = self
                    .depth
                    .and_then(|d| d.frame)
                    .is_some_and(|f| cfg.functions[&f].keeps_ret);
                if keeps_ret && !vals.is_empty() {
                    vals.remove(0); // the return address, left for the caller
                }
                let text = vals.iter().map(render_arg).collect::<Vec<_>>().join(", ");
                let bytes = self.take(i);
                self.out.push(Stmt::ReturnExpr { text, bytes });
            }
            JumpRole::Local | JumpRole::Unknown => {
                self.exit = self.exit_values();
                let dest = match target.const_value() {
                    Some(v) => self.ctx.target_name(v),
                    None if cfg.targets[b].len() == 1 => {
                        let t = *cfg.targets[b].iter().next().unwrap();
                        self.ctx.target_name(cfg.blocks[t].start)
                    }
                    None => render_arg(&target),
                };
                let bytes = self.jump_bytes(i);
                self.out.push(jump_stmt(dest, bytes));
                if target.const_value().is_none() && cfg.targets[b].len() > 1 {
                    let ts: Vec<String> = cfg.targets[b]
                        .iter()
                        .map(|&t| self.ctx.target_name(cfg.blocks[t].start))
                        .collect();
                    self.out
                        .push(Stmt::Comment(format!("one of: {}", ts.join(", "))));
                }
            }
        }
        BlockEnd::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: u64) -> Expr {
        Expr::Const(v.to_be_bytes().to_vec())
    }

    #[test]
    fn renders_infix_and_idioms() {
        let sig = simplify(Expr::Op(
            "shr",
            vec![c(224), Expr::Op("calldataload", vec![c(0)])],
        ));
        assert_eq!(render_raw(&sig), "msg.sig");
        let cmp = Expr::Op("eq", vec![c(0xa905_9cbb), sig.clone()]);
        assert_eq!(render(&cmp), "msg.sig == 0xa9059cbb");
        assert_eq!(render(&negate(cmp.clone())), "msg.sig != 0xa9059cbb");
        assert_eq!(render_rhs(&cmp), "(msg.sig == 0xa9059cbb)");
        let sum = Expr::Op("add", vec![Expr::Var("arg0".into()), c(0x20)]);
        assert_eq!(render_arg(&sum), "(arg0 + 0x20)");
        let shl = Expr::Op("shl", vec![c(3), Expr::Var("v1".into())]);
        assert_eq!(render(&shl), "v1 << 0x3");
        let mut mask = vec![0u8; 12];
        mask.extend([0xff; 20]);
        let addr = Expr::Op(
            "and",
            vec![Expr::Op("msg.sender", vec![]), Expr::Const(mask)],
        );
        assert_eq!(render(&addr), "address(msg.sender)");
        assert_eq!(render(&negate(Expr::Op("msg.value", vec![]))), "!msg.value");
    }

    fn op(name: &'static str, args: Vec<Expr>) -> Expr {
        Expr::Op(name, args)
    }

    fn var(name: &str) -> Expr {
        Expr::Var(name.into())
    }

    #[test]
    fn getters_name_their_slots() {
        // allowance(a, b): sload(mapping(mapping(4, address(a)), b)).
        let nested = op(
            "sload",
            vec![op(
                "mapping",
                vec![
                    op("mapping", vec![c(4), op("address", vec![var("param0")])]),
                    var("param1"),
                ],
            )],
        );
        assert_eq!(getter_slot(&nested, 2), Some(vec![4]));
        assert_eq!(getter_slot(&nested, 1), None, "key count must match");
        let swapped = op(
            "sload",
            vec![op(
                "mapping",
                vec![op("mapping", vec![c(4), var("param1")]), var("param0")],
            )],
        );
        assert_eq!(getter_slot(&swapped, 2), None, "keys must be in order");
        // owner(): address(sload(0)), and legacy `0xff & (x / 1)`.
        assert_eq!(
            getter_slot(&op("address", vec![op("sload", vec![c(0)])]), 0),
            Some(vec![])
        );
        let legacy = op(
            "and",
            vec![c(0xff), op("div", vec![op("sload", vec![c(2)]), c(1)])],
        );
        assert_eq!(getter_slot(&legacy, 0), Some(vec![2]));
        assert_eq!(getter_slot(&op("sload", vec![var("v1")]), 0), None);
        // Conflicting claims leave both sides unnamed.
        let claims = [
            (vec![2], "totalSupply"),
            (vec![3], "balanceOf"),
            (vec![3], "shares"),
            (vec![5], "owner"),
            (vec![6], "owner"),
        ];
        let names = unique_claims(&claims);
        assert_eq!(names.len(), 1);
        assert_eq!(names[&vec![2]], "totalSupply");
    }

    #[test]
    fn call_summaries_substitute_all_arguments_at_once() {
        // f(arg0, arg1) = arg0 - arg1, called as f(arg1, arg0).
        let body = op("sub", vec![var("arg0"), var("arg1")]);
        let r = subst_args(&body, &[var("arg1"), var("arg0")]);
        assert_eq!(r, op("sub", vec![var("arg1"), var("arg0")]));
        assert_eq!(subst_args(&body, &[c(5), c(3)]), c(2));
        assert!(summary_safe(&body));
        assert!(!summary_safe(&op("add", vec![var("v3"), c(1)])));
        assert!(!summary_safe(&op(UNKNOWN, vec![])));
        // Only stable values replace a slot's name in the text.
        assert!(shows_inline(&c(4)) && shows_inline(&var("param1.f0")));
        assert!(shows_inline(&op("msg.sender", vec![])));
        assert!(!shows_inline(&op("returndatasize", vec![])));
        assert!(!shows_inline(&op(RESULT, vec![c(1)])));
    }

    #[test]
    fn external_call_pieces() {
        let p = op(MPTR, vec![c(0x92c)]);
        // `(p + 0x24) - p` is a length; `p + 0x4` a place.
        let end = op("add", vec![c(0x20), op("add", vec![c(4), p.clone()])]);
        assert_eq!(rlin(&op("sub", vec![end, p.clone()])), Some((None, 0x24)));
        assert_eq!(
            rlin(&op("add", vec![c(4), p.clone()])),
            Some((Some(p.clone()), 4))
        );
        assert_eq!(rlin(&op("add", vec![p.clone(), p.clone()])), None);
        assert_eq!(rlin(&op(UNKNOWN, vec![])), None);
        // Solidity's left-aligned selector, Vyper's right-aligned one.
        let shifted = op("shl", vec![c(224), c(0xa905_9cbb)]);
        assert_eq!(word_bytes4(&shifted, 0), Some(0xa905_9cbb));
        assert_eq!(word_bytes4(&c(0x1816_0ddd), 28), Some(0x1816_0ddd));
        assert_eq!(word_bytes4(&c(0x1816_0ddd), 0), Some(0));
        assert_eq!(word_bytes4(&var("v1"), 0), None);

        let fc = FoldedCall {
            at: 0,
            var: "v3".into(),
            kind: "call",
            sel: 0xa905_9cbb,
            gas: op("gasleft", vec![]),
            to: op("address", vec![var("v1")]),
            value: Some(c(0)),
            args: vec![var("param0"), c(5)],
        };
        assert_eq!(fc.text(false), "v1.call(IERC20.transfer(param0, 0x5))");
        assert_eq!(fc.text(true), "IERC20(v1).transfer(param0, 0x5)");
        let fc = FoldedCall {
            sel: 0xdead_beef,
            value: Some(var("v2")),
            gas: c(2300),
            ..fc
        };
        assert_eq!(
            fc.text(true),
            "v1.call.value(v2).gas(0x8fc)(0xdeadbeef, param0, 0x5)"
        );
        // A failed call's revert data re-raised.
        let call = |name: &str, args: &[&str]| Stmt::Call {
            name: name.into(),
            args: args.iter().map(|a| (*a).to_string()).collect(),
            bytes: vec![0],
            direct_target: None,
        };
        let bubble = [
            call("returndatacopy", &["0x0", "0x0", "returndatasize()"]),
            Stmt::Move {
                dst: "v4".into(),
                src: "returndatasize()".into(),
                bytes: vec![0],
            },
            call("revert", &["0x0", "v4"]),
        ];
        assert!(is_bubble(&bubble));
        assert!(!is_bubble(&bubble[1..]));
        assert!(is_plain_revert(&[call("revert", &["0x0", "0x0"])]));
        assert!(!is_plain_revert(&bubble));
    }

    #[test]
    fn named_storage_renders_as_variables() {
        let names: StorageNames = [
            (vec![2], "totalSupply".to_string()),
            (vec![4], "allowance".to_string()),
        ]
        .into();
        let _scope = StorageScope::enter(names);
        let (a, b) = (var("a"), var("b"));
        let slot = op("mapping", vec![op("mapping", vec![c(4), a.clone()]), b]);
        assert_eq!(render(&op("sload", vec![c(2)])), "totalSupply");
        assert_eq!(render(&op("sload", vec![slot.clone()])), "allowance[a][b]");
        assert_eq!(
            render_rhs(&op("mapping", vec![c(4), a.clone()])),
            "&allowance[a]"
        );
        assert_eq!(
            render_raw(&storage_lvalue(&slot).unwrap()),
            "allowance[a][b]"
        );
        // Unnamed slots keep the raw form.
        assert_eq!(
            render(&op("sload", vec![op("mapping", vec![c(3), a])])),
            "sload(mapping(0x3, a))"
        );
    }
}

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
//! A forward `JUMPI` whose fall-through run of blocks is entered only
//! from that `JUMPI` becomes `if (!cond) { … }`; any other jump stays
//! explicit as `jump(L_xxxx)`.
//!
//! The text is a reading aid: every statement pins the bytes of the
//! instructions it stands for, in order, so lowering reproduces the
//! code exactly. Edits to lifted text don't change the output.

// Stack depths and positions are bounded by the EVM's 1024-item
// limit, so the usize/i64 conversions between them can't wrap.
#![allow(clippy::cast_possible_wrap)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use crate::arch::evm::{DecodedInsn, OPCODE_TABLE};
use crate::ast::Stmt;
use crate::signatures::evm::event_by_topic;
use crate::translate::decompile::evm_cfg::{BlockDepth, Cfg, JumpRole, Term};

/// DUPs of expressions at least this large bind a variable instead of
/// duplicating the text.
const DUP_INLINE_MAX_NODES: usize = 2;

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
    let is_mask = |x: &Expr, bytes: usize| {
        x.is_const_bytes(|b| b.len() == bytes && b.iter().all(|&v| v == 0xff))
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
    render_raw(&simplify(e.clone()))
}

/// Rendering for a call argument or tuple element: no bare spaces at
/// the top level, so infix expressions get parentheses.
fn render_arg(e: &Expr) -> String {
    render_child(&simplify(e.clone()))
}

/// Rendering for the right-hand side of an assignment: comparisons
/// are parenthesised so their `=` can't be mistaken for the
/// assignment's.
fn render_rhs(e: &Expr) -> String {
    let s = simplify(e.clone());
    match &s {
        Expr::Op(op, args) if args.len() == 2 && matches!(*op, "eq" | "ne" | "le" | "ge") => {
            format!("({})", render_raw(&s))
        }
        _ => render_raw(&s),
    }
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
    /// External functions (by entry address) whose ABI parameters are
    /// all static, with their count.
    pub params: HashMap<u64, usize>,
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

/// Lift every function range `[start, end)` to a statement body.
pub(crate) fn lift_ranges(ctx: &LiftCtx<'_>, ranges: &[(u64, u64)]) -> Vec<Vec<Stmt>> {
    let mut plan = Plan::default();
    let slices: Vec<Vec<usize>> = ranges.iter().map(|&(s, e)| ctx.blocks_in(s, e)).collect();
    for slice in &slices {
        plan_slice(ctx, slice, None, &mut plan);
    }
    let labels = collect_labels(ctx, &plan);
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
            };
            let mut body = fb.build(slice, None);
            fold_short_circuits(&mut body);
            body
        })
        .collect()
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
}

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
            let (stmts, end) = self.lift_block(b);
            let BlockEnd::Cond {
                cond,
                target,
                bytes,
            } = end
            else {
                out.extend(self.label(b));
                out.extend(stmts);
                i += 1;
                continue;
            };
            let Some(&shape) = self.plan.ifs.get(&b) else {
                out.extend(self.label(b));
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
                out.extend(self.label(b));
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
            out.extend(self.label(b));
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
        let (stmts, _) = self.lift_block(b);
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
        let (stmts, end) = self.lift_block(tail);
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

    fn lift_block(&mut self, b: usize) -> (Vec<Stmt>, BlockEnd) {
        let mut bl = BlockLift {
            ctx: self.ctx,
            depth: self.ctx.cfg.depth[b],
            stack: Vec::new(),
            pulled: 0,
            pending: self.ctx.cfg.blocks[b].insns.start,
            out: Vec::new(),
            temps: &mut self.temps,
            mstores: Vec::new(),
            bindings: HashMap::new(),
            fmp_epoch: 0,
            params: self.ctx.params.get(&self.range_start).copied().unwrap_or(0),
        };
        let end = bl.run(b);
        (bl.out, end)
    }
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
struct MStore {
    /// Index of its statement in `BlockLift::out`.
    at: usize,
    offset: Expr,
    value: Expr,
    /// `offset` resolved by [`lin`] when the store happened, so later
    /// rebinding of a variable it mentions can't change what it means.
    place: Option<(String, u64)>,
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
    /// Bumped by every `mstore(0x40, …)`: free-memory-pointer reads in
    /// the same epoch see the same value.
    fmp_epoch: u64,
    /// ABI parameters of the external function being lifted: the
    /// `k`th static parameter is `calldataload(4 + 32k)`.
    params: usize,
}

impl BlockLift<'_, '_> {
    /// `mstore(0x0, key); mstore(0x20, slot); keccak256(0x0, 0x40)` is
    /// how Solidity addresses `mapping` entries. When the two stores
    /// are the statements just emitted, fold all three into
    /// `mapping(slot, key)`, returning the stores' bytes.
    fn take_mapping_stores(&mut self, args: &[Expr]) -> Option<(Expr, Vec<u8>)> {
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
        let (key, slot) = match (a.offset.const_value()?, b.offset.const_value()?) {
            (0, 0x20) => (a.value.clone(), b.value.clone()),
            (0x20, 0) => (b.value.clone(), a.value.clone()),
            _ => return None,
        };
        let mut bytes = Vec::new();
        for stmt in self.out.drain(n - 2..) {
            let Stmt::Call { bytes: b, .. } = stmt else {
                unreachable!("mstore is a call")
            };
            bytes.extend(b);
        }
        self.mstores.truncate(self.mstores.len() - 2);
        Some((Expr::Op("mapping", vec![slot, key]), bytes))
    }

    fn slot_name(&self, pos: i64) -> Option<String> {
        let d = self.depth?;
        if pos < 0 {
            return None;
        }
        Some(match d.frame {
            Some(entry) => {
                let nargs = self.ctx.cfg.functions[&entry].nargs as i64;
                match pos {
                    0 => "ret".to_string(),
                    p if p <= nargs => format!("arg{}", p - 1),
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

    fn ensure(&mut self, n: usize) {
        while self.stack.len() < n {
            let name = self.entry_name(self.pulled);
            self.stack.insert(0, Expr::Var(name));
            self.pulled += 1;
        }
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
            if *e != Expr::Var(name.clone()) {
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
        let blk = cfg.blocks[b].clone();
        let last = blk.insns.end - 1;
        for i in blk.insns.clone() {
            let ins = &self.ctx.insns[i];
            let op = ins.opcode;
            // A statement on the last instruction of a fall-through
            // block would leave the slot write-back with no bytes, so
            // value-producing statements defer to it there.
            let defer = blk.term == Term::Fall && i == last;
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
                        self.bindings.insert(name, val);
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
                    let param = (op == 0x35)
                        .then(|| args[0].const_value())
                        .flatten()
                        .and_then(|off| off.checked_sub(4))
                        .filter(|rel| rel % 32 == 0 && rel / 32 < self.params as u64);
                    self.stack.push(match param {
                        Some(rel) => Expr::Var(format!("param{}", rel / 32)),
                        None => simplify(Expr::Op(pure_name(op).unwrap(), args)),
                    });
                }
                0x20 if !defer && self.mapping_ready() => {
                    let args = self.pop_n(2);
                    if let Some((val, mut bytes)) = self.take_mapping_stores(&args) {
                        // A slot address is a pure function of its
                        // inputs: keep it as an expression.
                        bytes.extend(self.take(i));
                        let idx = self.stack.len();
                        let name = self.bind_name(idx);
                        self.out.push(Stmt::Move {
                            dst: name.clone(),
                            src: render_rhs(&val),
                            bytes,
                        });
                        self.bindings.insert(name.clone(), val);
                        self.stack.push(Expr::Var(name));
                    } else {
                        self.bind_read(&Expr::Op("keccak256", args), i);
                    }
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
                        if let Some((data, bytes)) = self.collapse_encoded(&args[0], &args[1], i) {
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
                        }
                        self.mstores.push(MStore {
                            at: self.out.len(),
                            offset: args[0].clone(),
                            value: args[1].clone(),
                            place: lin(&args[0], &self.bindings, 0),
                        });
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
                        Some((words, bytes)) => {
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
                    let cond = self.pop();
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
            let inline = || stores.last().and_then(|v| ascii_word(v));
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
        let (val, mut bytes) = if is_fmp {
            (val.clone(), Vec::new())
        } else {
            let Expr::Op(op, args) = val.clone() else {
                unreachable!("reads are ops")
            };
            let (args, prefix) = self.inline_last(args);
            (Expr::Op(op, args), prefix)
        };
        let idx = self.stack.len();
        let name = self.bind_name(idx);
        bytes.extend(self.take(i));
        self.out.push(Stmt::Move {
            dst: name.clone(),
            src: render_rhs(&val),
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
        self.bindings.insert(name.clone(), bound);
        self.stack.push(Expr::Var(name));
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
            if matches!(bound, Expr::Op("fmp", _))
                || uses != 1
                || self.stack.iter().any(|e| e.mentions(&dst))
            {
                break;
            }
            let Some(Stmt::Move { bytes, .. }) = self.out.pop() else {
                unreachable!("checked above")
            };
            self.bindings.remove(&dst);
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
    /// the instruction's) returned with the words.
    fn collapse_encoded(
        &mut self,
        offset: &Expr,
        len: &Expr,
        i: usize,
    ) -> Option<(Vec<Expr>, Vec<u8>)> {
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
        for k in 0..n_bytes / 32 {
            let want = (base.clone(), start_off + 32 * k);
            let m = self
                .mstores
                .iter()
                .rev()
                .find(|m| m.place.as_ref() == Some(&want))?;
            first = first.min(m.at);
            words.push(m.value.clone());
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
        Some((words, bytes))
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
                let ret_names: Vec<String> = (0..nrets.unwrap_or(0))
                    .map(|k| {
                        if k == 0 && info.keeps_ret {
                            return "_".to_string();
                        }
                        let idx = self.stack.len() + k;
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
                if nrets.is_none() {
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
}

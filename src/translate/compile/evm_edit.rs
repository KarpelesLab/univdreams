//! Compile edited statements of a lifted EVM `.ud` file.
//!
//! Lifted statements pin the bytes they stand for, so an unedited file
//! lowers to the original code. To honour edits, the lowerer:
//!
//! 1. **Detects them by re-rendering.** The pinned bytes are lowered as
//!    usual, re-lifted, and the canonical statements compared with the
//!    parsed ones (both through `emit` → `parse`). Pairs are matched by
//!    their bytes; a statement whose text differs from its canonical
//!    twin was edited, and a statement without bytes that matches
//!    nothing was added. No edits: the pinned bytes are the output,
//!    byte for byte. Files must therefore be compiled by the version
//!    that decompiled them; a re-lift that doesn't line up with the
//!    file is reported as an error rather than guessed at.
//! 2. **Compiles the new text against the original stack.** The re-lift
//!    records which variable (`v6`, `arg2`, `t1`, …) every stack item
//!    held at each instruction (`evm_lift::LiftTrace`). The edited
//!    statement's instructions are executed symbolically to learn what
//!    they left on the stack for the code after them; the generated
//!    code performs the new text and then rebuilds that stack
//!    ([`Emitter::materialize`]), so unedited neighbours see what
//!    they expect. When the operands a condition names were consumed
//!    by instructions the lifter attributed to the previous statement,
//!    the replacement starts that much earlier.
//! 3. **Re-lays out the contract with symbolic labels.** Every
//!    `JUMPDEST` becomes a label and every `PUSH` that feeds a jump or
//!    survives as a return address (per block, against the recovered
//!    CFG) or gives a `CODECOPY` source offset becomes a reference, so
//!    code that grows or shrinks relocates the whole contract.
//!
//! Editable: assignments to stack variables, `sstore` / `mstore` /
//! `mstore8` / `tstore`, `require(cond)` / `require(cond, "reason")` /
//! `assert(cond)`, `revert()` / `revert("reason")` / `revert(o, n)` /
//! `panic(code)` / `stop()` / `invalid()`, `return abi.encode(…)` /
//! `return memory(o, n)` and internal `return a, b;` values, `emit`
//! arguments (same event and arity), and the conditions of `if`,
//! `while` and `do … while`. New statements of those kinds (plus `if`
//! blocks around them; not `emit`) can be added without bytes.
//! An assignment may also change its target — another stack variable
//! or a storage variable — and the variables it no longer writes keep
//! their previous values. A statement commented out in place (`// …`,
//! keeping its byte list) is deleted: its effects go, and the stack
//! it left is rebuilt for the code after it (`require` / `assert`
//! continue where the check passes).
//!
//! Calls: an internal call (`sub_xxxx(args)`, alone or as the last
//! value of an assignment whose last targets take its results) is
//! compiled from the callee's CFG summary — the arguments it takes
//! below and above the return address, how many values it returns —
//! as `PUSH ret; args…; PUSH sub_xxxx; JUMP`, returning straight to
//! the old continuation when the results land where it expects them.
//! External calls spelt as `call(…)` / `callcode(…)` (7 arguments),
//! `staticcall(…)` / `delegatecall(…)` (6) and `to.send(v)` /
//! `send(to, v)` (`call(!v * 2300, to, v, 0, 0, 0, 0)`) are compiled
//! in place of the call opcode. Either kind can be edited, added or
//! deleted. An EIP-1167 clone's `delegatecall` can be pointed at
//! another implementation. Vyper's `PUSH d; PC; ADD` return addresses become label
//! pushes inside edited code, and wherever an edit changes the size of
//! the code between one and its target.
//!
//! Embedded contracts (`@section`s) are compiled first; when an edit
//! moves code inside one, the enclosing code is laid out again with
//! the constants its deploying code uses adjusted ([`deploy_fixups`]):
//! the length it copies and returns, and the immutables it writes into
//! the copy. `codesize() - n` (constructor arguments appended to the
//! code) follows the move too; any other `CODESIZE` refuses a size
//! change.
//!
//! Everything else — calls in other forms or inside expressions,
//! statements that end a block, names no longer on the stack — is an
//! error naming the statement.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

use super::evm_emit::{
    Emitter, INVALID, JUMP, JUMPDEST, JUMPI, MSTORE, Opts, Piece, STOP, Sym, Target, lower_expr,
    lower_place, negate,
};
use super::evm_expr::{BinOp, EExpr, UnOp, parse_expr, parse_list};
use crate::arch::evm::{DecodedInsn, OPCODE_TABLE, assemble_one};
use crate::ast::{FnDecl, Item, Stmt, UdFile};
use crate::translate::decompile::evm::{Relift, relift};
use crate::translate::decompile::evm_cfg::{self, Cfg, FuncInfo, JumpRole};
use crate::translate::decompile::evm_lift::SlotNames;

/// An edit that can't be compiled.
#[derive(Debug, thiserror::Error)]
#[error("{place}: {message}")]
pub struct EvmEditError {
    /// `fn name, offset 0x…: statement text`, or a whole-file context.
    pub place: String,
    pub message: String,
}

fn whole_file(message: impl Into<String>) -> EvmEditError {
    EvmEditError {
        place: "evm".into(),
        message: message.into(),
    }
}

/// An embedded contract (`@section`) whose code an edit changed.
#[derive(Debug)]
pub(crate) struct SectionChange {
    /// Its offset in the enclosing code.
    pub addr: u64,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
    /// Where its original instructions start now, by original offset;
    /// `None` when none moved.
    pub moved: Option<HashMap<u64, u64>>,
}

/// Code with its edits compiled.
#[derive(Debug)]
pub(crate) struct Edited {
    pub code: Vec<u8>,
    /// See [`SectionChange::moved`].
    pub moved: Option<HashMap<u64, u64>>,
}

/// Lower `file`'s edits, given `code` from its pinned bytes and the
/// embedded contracts in it that changed. `None` when nothing was
/// edited (or the file isn't lifted output).
pub(crate) fn apply_edits(
    file: &UdFile,
    code: &[u8],
    sections: &[SectionChange],
) -> Result<Option<Edited>, EvmEditError> {
    // Embedded contracts that kept their layout drop in as they are.
    let in_place = sections
        .iter()
        .all(|s| s.new.len() == s.old.len() && s.moved.is_none());
    let splice = || {
        let mut out = code.to_vec();
        for s in sections {
            let at = s.addr as usize;
            out[at..at + s.new.len()].copy_from_slice(&s.new);
        }
        Edited {
            code: out,
            moved: None,
        }
    };
    if !has_lifted_statements(file) {
        return match (sections.is_empty(), in_place) {
            (true, _) => Ok(None),
            (false, true) => Ok(Some(splice())),
            (false, false) => Err(whole_file(
                "an embedded contract's code moved, and the code deploying it isn't in lifted form, so it can't be adjusted",
            )),
        };
    }
    let rl = relift(code);
    let canonical = crate::translate::compile::parse(&crate::ast::emit(&rl.file))
        .map_err(|e| whole_file(format!("re-lifted text doesn't parse: {e}")))?;
    let jobs = align_file(file, &canonical)?;
    if jobs.is_empty() {
        if sections.is_empty() {
            return Ok(None);
        }
        if in_place {
            return Ok(Some(splice()));
        }
    }
    if let Some(proxy) = crate::format::evm::minimal_proxy(code) {
        return proxy_edit(&jobs, &proxy, code).map(|code| Some(Edited { code, moved: None }));
    }

    let cfg = evm_cfg::build(&rl.insns);
    let data_spans: Vec<(u64, u64)> = file
        .items
        .iter()
        .filter_map(|it| match it {
            Item::Raw { addr, bytes } => Some((*addr, *addr + bytes.len() as u64)),
            _ => None,
        })
        .collect();
    let reloc = analyze_reloc(&rl.insns, &cfg, &data_spans);
    let opts = Opts {
        push0: rl.insns.iter().any(|i| i.opcode == 0x5f),
        shifts: rl.insns.iter().any(|i| matches!(i.opcode, 0x1b..=0x1d)),
        vyper: rl.vyper,
    };
    let ctx = Ctx::new(&rl, &cfg, &reloc, opts);
    let mut fresh = 0u32;
    let mut patches: Vec<Patch> = Vec::new();
    for job in &jobs {
        let patch = match job {
            Job::Replace(r) => ctx.replace(r, &mut fresh),
            Job::Delete(r) => ctx.delete(r, &mut fresh),
            Job::Insert(ins) => ctx.insert(ins, &mut fresh),
        }
        .map_err(|message| EvmEditError {
            place: job.place(),
            message,
        })?;
        patches.push(patch);
    }
    let rewrites = pc_rewrites(&ctx, &patches)?;
    let data_starts: Vec<u64> = data_spans.iter().map(|d| d.0).collect();
    let fix = deploy_fixups(&rl.insns, &cfg, sections, code.len() as u64, &data_starts)?;
    let (out, marks) = layout(
        file,
        &rl.insns,
        &reloc,
        patches,
        &Adjust {
            pc_rewrites: &rewrites,
            fixups: &fix.fixups,
            sections,
        },
    )?;
    if out.len() != code.len()
        && let Some(at) = fix.codesize
    {
        return Err(whole_file(format!(
            "the contract reads `CODESIZE` at 0x{at:x}, other than as `codesize() - n` past its own end, and the edit changes its size"
        )));
    }
    let moved = (marks.iter().any(|(a, b)| a != b) || out.len() != code.len()).then_some(marks);
    Ok(Some(Edited { code: out, moved }))
}

/// An EIP-1167 clone pointed at another implementation: its one
/// statement, `return delegatecall(<implementation>, msg.data);`, with
/// a new address. Data appended after the proxy code stays.
fn proxy_edit(
    jobs: &[Job],
    proxy: &crate::format::evm::MinimalProxy,
    code: &[u8],
) -> Result<Vec<u8>, EvmEditError> {
    let [Job::Replace(r)] = jobs else {
        return Err(whole_file(
            "a minimal proxy's only edit is the implementation its `delegatecall` forwards to",
        ));
    };
    let fail = |m: &str| EvmEditError {
        place: jobs[0].place(),
        message: m.into(),
    };
    let Stmt::ReturnExpr { text, .. } = &r.stmt else {
        return Err(fail(
            "expected `return delegatecall(<implementation>, msg.data);`",
        ));
    };
    let target = match parse_expr(text) {
        Ok(EExpr::Call(n, args)) if n == "delegatecall" => match args.as_slice() {
            [EExpr::Num(a), EExpr::Name(d)] if d == "msg.data" && a.len() <= 20 => a.clone(),
            _ => return Err(fail("expected `delegatecall(<20-byte address>, msg.data)`")),
        },
        _ => {
            return Err(fail(
                "expected `return delegatecall(<implementation>, msg.data);`",
            ));
        }
    };
    // Keep a vanity address's short `PUSHn` while the new one fits.
    let old_n = 20 - proxy.target.iter().take_while(|&&b| b == 0).count();
    let n = target.len().max(old_n);
    let mut addr = vec![0u8; n - target.len()];
    addr.extend(&target);
    let mut out = vec![0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d];
    out.push(0x5f + n as u8);
    out.extend(&addr);
    out.extend([0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91]);
    out.extend([0x60, (out.len() + 2 + 2) as u8]);
    out.extend([0x57, 0xfd, 0x5b, 0xf3]);
    out.extend(&code[proxy.code_len..]);
    Ok(out)
}

pub(crate) fn has_lifted_statements(file: &UdFile) -> bool {
    file.items.iter().any(|it| match it {
        Item::Function(f) => f
            .body
            .iter()
            .any(|s| !matches!(s, Stmt::Asm { .. } | Stmt::Comment(_))),
        _ => false,
    })
}

/// Drop statements added without bytes that the generic lowerer can't
/// pass over (assignments, numeric returns), and restore commented-out
/// (deleted) ones, so the pinned bytes alone can be lowered.
pub(crate) fn strip_added(file: &UdFile) -> UdFile {
    let lifted = has_lifted_statements(file);
    let items = file
        .items
        .iter()
        .map(|it| match it {
            Item::Function(f) => Item::Function(FnDecl {
                body: rebuild(&f.body, &|s| {
                    if let Stmt::Comment(text) = s
                        && lifted
                        && let Some(gone) = commented_out(text)
                    {
                        // Deleted: its bytes are still the original code.
                        return Some(gone);
                    }
                    let added = matches!(
                        s,
                        Stmt::Move { bytes, .. } | Stmt::Return { bytes, .. } if bytes.is_empty()
                    );
                    (!added).then(|| s.clone())
                }),
                ..f.clone()
            }),
            other => other.clone(),
        })
        .collect();
    UdFile {
        module: file.module.clone(),
        items,
    }
}

/// A lifted statement commented out to delete it: `// text [bytes]`,
/// a single-line statement keeping its byte list.
fn commented_out(text: &str) -> Option<Stmt> {
    let t = text.trim();
    if !t.ends_with(']') || t.starts_with('@') {
        return None;
    }
    let src = format!("@module {{\n    arch: \"evm\",\n}}\n\nfn f() {{\n    {t}\n}}\n");
    let file = crate::translate::compile::parse(&src).ok()?;
    let [Item::Function(f)] = file.items.as_slice() else {
        return None;
    };
    let [s] = f.body.as_slice() else {
        return None;
    };
    let carries = match s {
        Stmt::Move { bytes, .. }
        | Stmt::Call { bytes, .. }
        | Stmt::ReturnExpr { bytes, .. }
        | Stmt::Return { bytes, .. } => !bytes.is_empty(),
        _ => false,
    };
    carries.then(|| s.clone())
}

/// `stmts` with `f` applied to every statement (nested ones first);
/// `None` drops it.
fn rebuild(stmts: &[Stmt], f: &dyn Fn(&Stmt) -> Option<Stmt>) -> Vec<Stmt> {
    stmts
        .iter()
        .filter_map(|s| {
            let s = match s {
                Stmt::IfBranch {
                    cond_text,
                    cond_bytes,
                    attrs,
                    pre_body,
                    then_body,
                    else_body,
                } => Stmt::IfBranch {
                    cond_text: cond_text.clone(),
                    cond_bytes: cond_bytes.clone(),
                    attrs: attrs.clone(),
                    pre_body: rebuild(pre_body, f),
                    then_body: rebuild(then_body, f),
                    else_body: else_body.as_deref().map(|e| rebuild(e, f)),
                },
                Stmt::WhileBlock {
                    cond_text,
                    entry_bytes,
                    tail_bytes,
                    body,
                } => Stmt::WhileBlock {
                    cond_text: cond_text.clone(),
                    entry_bytes: entry_bytes.clone(),
                    tail_bytes: tail_bytes.clone(),
                    body: rebuild(body, f),
                },
                Stmt::Loop {
                    cond_text,
                    entry_jmp_bytes,
                    tail_bytes,
                    body,
                } => Stmt::Loop {
                    cond_text: cond_text.clone(),
                    entry_jmp_bytes: entry_jmp_bytes.clone(),
                    tail_bytes: tail_bytes.clone(),
                    body: rebuild(body, f),
                },
                other => other.clone(),
            };
            f(&s)
        })
        .collect()
}

/// The parser reads `return 0x1;` as a numeric [`Stmt::Return`]; to
/// the EVM lowerer every return is a [`Stmt::ReturnExpr`].
fn normalize(stmts: &[Stmt]) -> Vec<Stmt> {
    rebuild(stmts, &|s| {
        Some(match s {
            Stmt::Return { value, bytes } => Stmt::ReturnExpr {
                text: format!("0x{value:x}"),
                bytes: bytes.clone(),
            },
            other => other.clone(),
        })
    })
}

// ---------------------------------------------------------------------
// Alignment: which statements were edited or added
// ---------------------------------------------------------------------

/// A previous sibling the replacement of an edited statement may
/// extend back over.
#[derive(Debug, Clone)]
struct Sib {
    start: u64,
    end: u64,
    /// Variables it assigns.
    dsts: Vec<String>,
}

#[derive(Debug)]
struct Replace {
    function: String,
    /// Entry offset of the function.
    fn_addr: u64,
    /// The statement as written.
    stmt: Stmt,
    /// Its re-lifted twin.
    canon: Stmt,
    /// Offsets of the bytes the statement's text stands for.
    start: u64,
    end: u64,
    /// Contiguous earlier siblings, nearest last.
    prev: Vec<Sib>,
    /// Identifiers the function's statements use, as written.
    used: Rc<HashSet<String>>,
}

#[derive(Debug)]
struct Insert {
    function: String,
    fn_addr: u64,
    stmts: Vec<Stmt>,
    /// Code offset the statements go before.
    at: u64,
    /// Added at the end of a body (after its last statement) rather
    /// than before a following one.
    end_of_list: bool,
}

#[derive(Debug)]
enum Job {
    Replace(Box<Replace>),
    /// A statement commented out; `stmt` is what it said.
    Delete(Box<Replace>),
    Insert(Insert),
}

impl Job {
    fn place(&self) -> String {
        match self {
            Job::Delete(r) => format!(
                "fn {}, offset 0x{:x}: deleted `{}`",
                r.function,
                r.start,
                stmt_text(&r.stmt).unwrap_or_default()
            ),
            Job::Replace(r) => format!(
                "fn {}, offset 0x{:x}: `{}`",
                r.function,
                r.start,
                stmt_text(&r.stmt).unwrap_or_default()
            ),
            Job::Insert(i) => format!(
                "fn {}, offset 0x{:x}: added `{}`",
                i.function,
                i.at,
                i.stmts.first().and_then(stmt_text).unwrap_or_default()
            ),
        }
    }
}

fn functions(file: &UdFile) -> Vec<&FnDecl> {
    file.items
        .iter()
        .filter_map(|it| match it {
            Item::Function(f) => Some(f),
            _ => None,
        })
        .collect()
}

fn align_file(file: &UdFile, canonical: &UdFile) -> Result<Vec<Job>, EvmEditError> {
    let (fp, fc) = (functions(file), functions(canonical));
    let mismatch = || {
        whole_file(
            "the functions don't match the re-lifted code; decompile again with this version and re-apply the edits",
        )
    };
    if fp.len() != fc.len() {
        return Err(mismatch());
    }
    let mut jobs = Vec::new();
    for (p, c) in fp.iter().zip(&fc) {
        if p.name != c.name || p.addr != c.addr {
            return Err(mismatch());
        }
        let mut used = HashSet::new();
        used_names(&p.body, &mut used);
        let mut al = Aligner {
            function: &p.name,
            fn_addr: c.addr.unwrap_or(0),
            cursor: c.addr.unwrap_or(0),
            jobs: &mut jobs,
            used: Rc::new(used),
        };
        al.list(&normalize(&p.body), &normalize(&c.body))?;
    }
    Ok(jobs)
}

/// Every identifier the live statements of `stmts` mention.
fn used_names(stmts: &[Stmt], out: &mut HashSet<String>) {
    for s in stmts {
        if let Some(t) = stmt_text(s) {
            out.extend(
                t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
                    .map(str::to_string),
            );
        }
        match s {
            Stmt::IfBranch {
                pre_body,
                then_body,
                else_body,
                ..
            } => {
                used_names(pre_body, out);
                used_names(then_body, out);
                used_names(else_body.as_deref().unwrap_or_default(), out);
            }
            Stmt::WhileBlock { body, .. } | Stmt::Loop { body, .. } => used_names(body, out),
            _ => {}
        }
    }
}

/// Text a statement's edit is detected by.
fn stmt_text(s: &Stmt) -> Option<String> {
    Some(match s {
        Stmt::Move { dst, src, .. } => format!("{dst} = {src}"),
        Stmt::Call { name, args, .. } => format!("{name}({})", args.join(", ")),
        Stmt::ReturnExpr { text, .. } => format!("return {text}"),
        Stmt::IfBranch { cond_text, .. } => format!("if ({cond_text})"),
        Stmt::WhileBlock { cond_text, .. } => format!("while ({cond_text})"),
        Stmt::Loop { cond_text, .. } => format!("do … while ({cond_text})"),
        Stmt::Asm { text, .. } => text.clone(),
        _ => return None,
    })
}

/// Bytes an `@asm` line stands for.
fn asm_bytes(text: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        assemble_one(text).ok()
    } else {
        Some(bytes.to_vec())
    }
}

/// The bytes a statement carries itself (not its nested bodies').
fn own_len(s: &Stmt) -> usize {
    match s {
        Stmt::Asm { text, bytes } => asm_bytes(text, bytes).map_or(0, |b| b.len()),
        Stmt::Move { bytes, .. } | Stmt::Call { bytes, .. } | Stmt::ReturnExpr { bytes, .. } => {
            bytes.len()
        }
        Stmt::IfBranch { cond_bytes, .. } => cond_bytes.len(),
        Stmt::WhileBlock { entry_bytes, .. } => entry_bytes.len(),
        Stmt::Loop { tail_bytes, .. } => tail_bytes.len(),
        _ => 0,
    }
}

/// Whether `p` (as written) and `c` (re-lifted) stand for the same
/// bytes and structure.
fn same_shape(p: &Stmt, c: &Stmt) -> bool {
    match (p, c) {
        (
            Stmt::Asm {
                text: t1,
                bytes: b1,
            },
            Stmt::Asm {
                text: t2,
                bytes: b2,
            },
        ) => asm_bytes(t1, b1).is_some() && asm_bytes(t1, b1) == asm_bytes(t2, b2),
        (Stmt::Move { bytes: b1, .. }, Stmt::Move { bytes: b2, .. })
        | (Stmt::ReturnExpr { bytes: b1, .. }, Stmt::ReturnExpr { bytes: b2, .. }) => b1 == b2,
        (
            Stmt::Call {
                bytes: b1,
                direct_target: d1,
                ..
            },
            Stmt::Call {
                bytes: b2,
                direct_target: d2,
                ..
            },
        ) => b1 == b2 && d1 == d2,
        (
            Stmt::IfBranch {
                cond_bytes: b1,
                pre_body: p1,
                else_body: e1,
                ..
            },
            Stmt::IfBranch {
                cond_bytes: b2,
                pre_body: p2,
                else_body: e2,
                ..
            },
        ) => b1 == b2 && p1.is_empty() && p2.is_empty() && e1.is_some() == e2.is_some(),
        (
            Stmt::WhileBlock {
                entry_bytes: a1,
                tail_bytes: t1,
                ..
            },
            Stmt::WhileBlock {
                entry_bytes: a2,
                tail_bytes: t2,
                ..
            },
        ) => a1 == a2 && t1 == t2,
        (
            Stmt::Loop {
                entry_jmp_bytes: a1,
                tail_bytes: t1,
                ..
            },
            Stmt::Loop {
                entry_jmp_bytes: a2,
                tail_bytes: t2,
                ..
            },
        ) => a1 == a2 && t1 == t2,
        _ => false,
    }
}

/// A statement written without bytes, standing for new code.
fn is_added(s: &Stmt) -> bool {
    match s {
        Stmt::Move { bytes, .. } | Stmt::Call { bytes, .. } | Stmt::ReturnExpr { bytes, .. } => {
            bytes.is_empty()
        }
        Stmt::IfBranch {
            cond_bytes,
            pre_body,
            then_body,
            else_body,
            ..
        } => {
            cond_bytes.is_empty()
                && pre_body.is_empty()
                && then_body
                    .iter()
                    .all(|s| matches!(s, Stmt::Comment(_)) || is_added(s))
                && else_body
                    .iter()
                    .flatten()
                    .all(|s| matches!(s, Stmt::Comment(_)) || is_added(s))
        }
        _ => false,
    }
}

fn is_zero_byte_body(stmts: &[Stmt]) -> bool {
    stmts
        .iter()
        .all(|s| matches!(s, Stmt::Comment(_)) || (own_len(s) == 0 && !is_structured(s)))
}

fn is_structured(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::IfBranch { .. } | Stmt::WhileBlock { .. } | Stmt::Loop { .. }
    )
}

struct Aligner<'j> {
    function: &'j str,
    fn_addr: u64,
    cursor: u64,
    jobs: &'j mut Vec<Job>,
    used: Rc<HashSet<String>>,
}

/// A statement as written: live, or commented out to delete it.
enum Written<'s> {
    Live(&'s Stmt),
    Deleted(Stmt),
}

impl Aligner<'_> {
    fn err(&self, s: &Stmt, message: &str) -> EvmEditError {
        EvmEditError {
            place: format!(
                "fn {}, offset 0x{:x}: `{}`",
                self.function,
                self.cursor,
                stmt_text(s).unwrap_or_default()
            ),
            message: message.into(),
        }
    }

    fn flush_added(&mut self, added: &mut Vec<Stmt>, end_of_list: bool) {
        if !added.is_empty() {
            self.jobs.push(Job::Insert(Insert {
                function: self.function.to_string(),
                fn_addr: self.fn_addr,
                stmts: std::mem::take(added),
                at: self.cursor,
                end_of_list,
            }));
        }
    }

    fn list(&mut self, p: &[Stmt], c: &[Stmt]) -> Result<(), EvmEditError> {
        let p: Vec<Written<'_>> = p
            .iter()
            .filter_map(|s| match s {
                Stmt::Comment(t) => {
                    commented_out(t).map(|gone| Written::Deleted(normalize(&[gone]).remove(0)))
                }
                s => Some(Written::Live(s)),
            })
            .collect();
        let c: Vec<&Stmt> = c
            .iter()
            .filter(|s| !matches!(s, Stmt::Comment(_)))
            .collect();
        let mut j = 0;
        let mut added: Vec<Stmt> = Vec::new();
        let mut sibs: Vec<Sib> = Vec::new();
        for ps in p {
            let ps = match ps {
                Written::Deleted(gone) => {
                    if j >= c.len() || !same_shape(&gone, c[j]) {
                        return Err(self.err(
                            &gone,
                            "this commented-out statement doesn't match the re-lifted code here (comment a statement out in place, keeping its byte list, to delete it)",
                        ));
                    }
                    self.flush_added(&mut added, false);
                    let start = self.cursor;
                    let len = own_len(c[j]) as u64;
                    if is_structured(c[j]) || len == 0 {
                        return Err(self.err(
                            &gone,
                            "only statements with bytes of their own can be deleted",
                        ));
                    }
                    self.jobs.push(Job::Delete(Box::new(Replace {
                        function: self.function.to_string(),
                        fn_addr: self.fn_addr,
                        stmt: gone,
                        canon: c[j].clone(),
                        start,
                        end: start + len,
                        prev: sibs.clone(),
                        used: self.used.clone(),
                    })));
                    self.cursor += len;
                    sibs.clear();
                    j += 1;
                    continue;
                }
                Written::Live(ps) => ps,
            };
            if j < c.len() && same_shape(ps, c[j]) {
                if !added.is_empty() {
                    self.flush_added(&mut added, false);
                    sibs.clear();
                }
                let start = self.cursor;
                let edited = self.stmt(ps, c[j], &sibs)?;
                match c[j] {
                    Stmt::Move { dst, .. } if !edited => sibs.push(Sib {
                        start,
                        end: self.cursor,
                        dsts: dst.split(", ").map(str::to_string).collect(),
                    }),
                    Stmt::Call { .. } if !edited && self.cursor > start => sibs.push(Sib {
                        start,
                        end: self.cursor,
                        dsts: Vec::new(),
                    }),
                    _ => sibs.clear(),
                }
                j += 1;
            } else if is_added(ps) {
                added.push(ps.clone());
            } else {
                return Err(self.err(
                    ps,
                    "doesn't match the re-lifted code (statements can be edited in place, added without bytes, or commented out to delete them, not moved or given new bytes); decompile again with this version if the file came from another one",
                ));
            }
        }
        if let Some(missing) = c.get(j) {
            return Err(self.err(
                missing,
                "this statement is missing; to delete a statement, comment it out keeping its byte list",
            ));
        }
        self.flush_added(&mut added, true);
        Ok(())
    }

    /// Align one matched pair; returns whether its own text was edited.
    fn stmt(&mut self, p: &Stmt, c: &Stmt, sibs: &[Sib]) -> Result<bool, EvmEditError> {
        match (p, c) {
            (
                Stmt::IfBranch {
                    then_body: pt,
                    else_body: pe,
                    ..
                },
                Stmt::IfBranch {
                    then_body: ct,
                    else_body: ce,
                    ..
                },
            ) => {
                let edited = self.own(p, c, sibs)?;
                self.list(pt, ct)?;
                if let (Some(pe), Some(ce)) = (pe, ce) {
                    self.list(pe, ce)?;
                }
                Ok(edited)
            }
            (
                Stmt::WhileBlock { body: pb, .. },
                Stmt::WhileBlock {
                    body: cb,
                    tail_bytes,
                    ..
                },
            ) => {
                let edited = self.own(p, c, sibs)?;
                self.list(pb, cb)?;
                self.cursor += tail_bytes.len() as u64;
                Ok(edited)
            }
            (
                Stmt::Loop { body: pb, .. },
                Stmt::Loop {
                    body: cb,
                    entry_jmp_bytes,
                    ..
                },
            ) => {
                self.cursor += entry_jmp_bytes.as_ref().map_or(0, Vec::len) as u64;
                self.list(pb, cb)?;
                self.own(p, c, &[])
            }
            _ => self.own(p, c, sibs),
        }
    }

    fn own(&mut self, p: &Stmt, c: &Stmt, sibs: &[Sib]) -> Result<bool, EvmEditError> {
        let start = self.cursor;
        let len = own_len(c) as u64;
        let edited = !matches!(p, Stmt::Asm { .. }) && stmt_text(p) != stmt_text(c);
        if edited {
            if len == 0 {
                return Err(self.err(
                    p,
                    "this statement carries no bytes of its own (it restates code shown elsewhere); edit the statement that does",
                ));
            }
            self.jobs.push(Job::Replace(Box::new(Replace {
                function: self.function.to_string(),
                fn_addr: self.fn_addr,
                stmt: p.clone(),
                canon: c.clone(),
                start,
                end: start + len,
                prev: sibs.to_vec(),
                used: self.used.clone(),
            })));
        }
        self.cursor += len;
        Ok(edited)
    }
}

// ---------------------------------------------------------------------
// Relocation analysis
// ---------------------------------------------------------------------

/// Which `PUSH` instructions hold offsets the layout must update.
#[derive(Debug, Default)]
struct Reloc {
    /// Code addresses: jump targets and return addresses.
    code: HashSet<usize>,
    /// `CODECOPY` source offsets.
    data: HashSet<usize>,
    /// Code-address pushes also used as plain numbers.
    fixed: HashSet<usize>,
}

impl Reloc {
    fn is_ref(&self, idx: usize) -> bool {
        self.code.contains(&idx) || self.data.contains(&idx)
    }
}

/// Follow every `PUSH` through its block. A pushed `JUMPDEST` offset
/// is a code reference when it is jumped to, or when it outlives the
/// block (a return address or a function pointer passed down), the
/// CFG knows it as a jump target and no copy of it is used as a
/// number. A constant `CODECOPY` offset is a data reference.
#[allow(clippy::many_single_char_names)]
fn analyze_reloc(insns: &[DecodedInsn], cfg: &Cfg, data_spans: &[(u64, u64)]) -> Reloc {
    let jumpdests: HashSet<u64> = insns
        .iter()
        .filter(|i| i.opcode == JUMPDEST)
        .map(|i| i.addr.0)
        .collect();
    let start_of = |b: &usize| cfg.blocks[*b].start;
    let mut known: HashSet<u64> = cfg.targets.iter().flatten().map(start_of).collect();
    known.extend(cfg.conts.values().flatten().map(start_of));
    known.extend(cfg.calls.values().map(|c| cfg.blocks[c.callee].start));
    let code_end = insns.last().map_or(0, DecodedInsn::next_addr);
    let in_data = |v: u64| v < code_end || data_spans.iter().any(|&(s, e)| v >= s && v <= e);

    let mut r = Reloc::default();
    let mut as_number: HashSet<usize> = HashSet::new();
    let mut carried: HashSet<usize> = HashSet::new();
    let value = |i: usize| insns[i].push_value();
    for blk in &cfg.blocks {
        let mut stack: Vec<Option<usize>> = Vec::new();
        let pop = |stack: &mut Vec<Option<usize>>| stack.pop().flatten();
        for i in blk.insns.clone() {
            let ins = &insns[i];
            match ins.opcode {
                0x5f..=0x7f => stack.push(Some(i)),
                0x80..=0x8f => {
                    let n = usize::from(ins.opcode - 0x80) + 1;
                    let v = stack.len().checked_sub(n).and_then(|k| stack[k]);
                    stack.push(v);
                }
                0x90..=0x9f => {
                    let n = usize::from(ins.opcode - 0x90) + 1;
                    while stack.len() <= n {
                        stack.insert(0, None);
                    }
                    let len = stack.len();
                    stack.swap(len - 1, len - 1 - n);
                }
                0x50 => {
                    stack.pop();
                }
                0x16 => {
                    // `AND` with a mask keeps a target (solc 0.5–0.7).
                    let (a, b) = (pop(&mut stack), pop(&mut stack));
                    let is_target = |x: Option<usize>| {
                        x.and_then(value).is_some_and(|v| jumpdests.contains(&v))
                    };
                    let kept = match (a, b) {
                        (Some(t), Some(m)) | (Some(m), Some(t)) if is_target(Some(t)) => {
                            as_number.insert(m);
                            Some(t)
                        }
                        _ => {
                            as_number.extend(a);
                            as_number.extend(b);
                            None
                        }
                    };
                    stack.push(kept);
                }
                0x56 | 0x57 => {
                    if let Some(t) = pop(&mut stack)
                        && value(t).is_some_and(|v| jumpdests.contains(&v))
                    {
                        r.code.insert(t);
                    }
                    if ins.opcode == 0x57 {
                        as_number.extend(pop(&mut stack));
                    }
                }
                0x39 => {
                    let dest = pop(&mut stack);
                    let off = pop(&mut stack);
                    let size = pop(&mut stack);
                    as_number.extend(dest);
                    as_number.extend(size);
                    if let Some(o) = off
                        && value(o).is_some_and(in_data)
                    {
                        r.data.insert(o);
                    }
                }
                op => {
                    let info = &OPCODE_TABLE[op as usize];
                    for _ in 0..info.pops {
                        as_number.extend(pop(&mut stack));
                    }
                    for _ in 0..info.pushes {
                        stack.push(None);
                    }
                }
            }
        }
        // Survivors: return addresses and passed-down targets.
        for &i in stack.iter().flatten() {
            if value(i).is_some_and(|v| jumpdests.contains(&v) && known.contains(&v)) {
                carried.insert(i);
            }
        }
    }
    // A survivor also used as a number is data that happens to equal
    // a code offset (Vyper's fixed memory slots); one also jumped to
    // can't be moved at all.
    r.fixed = r.code.intersection(&as_number).copied().collect();
    r.code.extend(carried.difference(&as_number));
    r
}

// ---------------------------------------------------------------------
// Statement compilation
// ---------------------------------------------------------------------

/// Generated code replacing instructions `from..to` (`from == to`:
/// inserted before `from`).
#[derive(Debug)]
struct Patch {
    from: usize,
    to: usize,
    pieces: Vec<Piece>,
}

/// Stack effect of a run of original instructions, over the items on
/// the stack before it (`Sym::Slot`).
#[derive(Debug, Default)]
struct Sim {
    /// Bottom → top: what replaced the top `consumed` items.
    items: Vec<Sym>,
    consumed: usize,
    /// Side-effect opcodes executed, with their operands.
    effects: Vec<(u8, Vec<Sym>)>,
}

impl Sim {
    fn ensure(&mut self, n: usize) {
        while self.items.len() < n {
            self.items.insert(0, Sym::Slot(self.consumed));
            self.consumed += 1;
        }
    }

    fn pop(&mut self) -> Sym {
        self.ensure(1);
        self.items.pop().expect("ensured")
    }

    /// The stack top-first index `t` names, extending the replaced
    /// region downwards as needed.
    fn at_mut(&mut self, t: usize) -> &mut Sym {
        self.ensure(t + 1);
        let len = self.items.len();
        &mut self.items[len - 1 - t]
    }
}

/// Whether a lifted assignment's right-hand side is an external call
/// with its ABI encoding folded in — member syntax on a call result
/// (`IERC20(t).transfer(a, n)`) or a `.call` / `.staticcall` member
/// (`t.call(IERC20.transfer(a, n))`).
fn is_folded_call(src: &str) -> bool {
    src.contains(").")
        || src
            .split(|c: char| !(c == '.' || c == '_' || c.is_ascii_alphanumeric()))
            .any(|w| w.contains(".call") || w.contains(".staticcall"))
}

/// Opcodes whose result depends only on operands and fixed call
/// context, so recomputing them is safe.
fn is_pure(op: u8) -> bool {
    matches!(
        op,
        0x01..=0x0b | 0x10..=0x1e | 0x30 | 0x32..=0x36 | 0x38 | 0x3a | 0x40..=0x46 | 0x48..=0x4a
    )
}

/// An assignment [`Ctx::rewrite`] generates.
struct Rewrite<'w> {
    /// Stack targets (none for a store).
    dsts: &'w [&'w str],
    srcs: &'w [EExpr],
    /// The storage variable written instead.
    place: Option<&'w EExpr>,
    /// Stack targets of the original statement.
    old: &'w [&'w str],
    /// The original stored to a storage variable.
    old_place: bool,
}

impl<'w> Rewrite<'w> {
    /// A call statement assigning nothing: `srcs` is the call, or
    /// empty to drop it.
    fn call(srcs: &'w [EExpr]) -> Self {
        Self {
            dsts: &[],
            srcs,
            place: None,
            old: &[],
            old_place: false,
        }
    }
}

/// `sub_xxxx(…)`.
fn is_internal_call(e: &EExpr) -> bool {
    matches!(e, EExpr::Call(n, _) if n.starts_with("sub_"))
}

/// An external call the text can spell: its opcode and stack
/// arguments, top first. `to.send(v)` / `send(to, v)` are
/// `call(!v * 2300, to, v, 0, 0, 0, 0)`.
fn ext_call(e: &EExpr) -> Option<(u8, Vec<EExpr>)> {
    let EExpr::Call(name, args) = e else {
        return None;
    };
    let send = |to: EExpr, v: &EExpr| {
        let gas = EExpr::Binary(
            BinOp::Mul,
            Box::new(EExpr::Unary(UnOp::Not, Box::new(v.clone()))),
            Box::new(EExpr::Num(vec![0x08, 0xfc])),
        );
        let zero = || EExpr::Num(Vec::new());
        Some((
            0xf1,
            vec![gas, to, v.clone(), zero(), zero(), zero(), zero()],
        ))
    };
    match (name.as_str(), args.as_slice()) {
        ("call", [..]) if args.len() == 7 => Some((0xf1, args.clone())),
        ("callcode", [..]) if args.len() == 7 => Some((0xf2, args.clone())),
        ("delegatecall", [..]) if args.len() == 6 => Some((0xf4, args.clone())),
        ("staticcall", [..]) if args.len() == 6 => Some((0xfa, args.clone())),
        ("send", [to, v]) => send(to.clone(), v),
        (n, [v]) => send(EExpr::Name(n.strip_suffix(".send")?.to_string()), v),
        _ => None,
    }
}

struct Ctx<'a> {
    insns: &'a [DecodedInsn],
    trace: &'a crate::translate::decompile::evm_lift::LiftTrace,
    cfg: &'a Cfg,
    reloc: &'a Reloc,
    opts: Opts,
    /// Instruction index by start offset, plus one past each segment.
    index: HashMap<u64, usize>,
    referenced: HashSet<u64>,
    /// Root slot of each named storage variable.
    storage: HashMap<String, Vec<u8>>,
}

type Res<T> = Result<T, String>;

/// The four kinds of `Call` statement an edit may produce.
fn store_opcode(name: &str) -> Option<u8> {
    Some(match name {
        "sstore" => 0x55,
        "mstore" => MSTORE,
        "mstore8" => 0x53,
        "tstore" => 0x5d,
        _ => return None,
    })
}

/// Identifiers an expression refers to that must come from the stack.
fn stack_names(e: &EExpr, out: &mut Vec<String>) {
    match e {
        EExpr::Name(n) => {
            let special = n.contains('.') || n == "this" || n.starts_with("L_");
            if !special && !out.contains(n) {
                out.push(n.clone());
            }
        }
        EExpr::Unary(_, x) => stack_names(x, out),
        EExpr::Binary(_, a, b) => {
            stack_names(a, out);
            stack_names(b, out);
        }
        EExpr::Index(_, k) => stack_names(k, out),
        EExpr::Call(_, args) => args.iter().for_each(|a| stack_names(a, out)),
        EExpr::Num(_) | EExpr::Str(_) => {}
    }
}

/// Resolve names against a snapshot: the nearest item holding each.
fn slot_resolver(names: &[SlotNames]) -> impl Fn(&str) -> Option<Sym> + '_ {
    move |n: &str| {
        names
            .iter()
            .position(|s| s.var.as_deref() == Some(n))
            .map(Sym::Slot)
    }
}

/// Top-first positions holding `dst`: as a variable, else as the
/// frame slot of that name.
fn dst_positions(names: &[SlotNames], dst: &str) -> Vec<usize> {
    let by = |f: &dyn Fn(&SlotNames) -> bool| -> Vec<usize> {
        names
            .iter()
            .enumerate()
            .filter(|(_, s)| f(s))
            .map(|(t, _)| t)
            .collect()
    };
    let v = by(&|s| s.var.as_deref() == Some(dst));
    if v.is_empty() {
        by(&|s| s.slot.as_deref() == Some(dst))
    } else {
        v
    }
}

/// A `require` / `revert` reason argument: quoted or bare text.
fn reason_text(arg: &str) -> Res<String> {
    let t = arg.trim();
    if let Ok(EExpr::Str(s)) = parse_expr(t) {
        return Ok(s);
    }
    if t.contains('(') && t.ends_with(')') {
        return Err(format!(
            "custom error `{t}` can't be compiled; use a string reason"
        ));
    }
    Ok(t.to_string())
}

impl<'a> Ctx<'a> {
    fn new(rl: &'a Relift, cfg: &'a Cfg, reloc: &'a Reloc, opts: Opts) -> Self {
        let mut index = HashMap::new();
        for (k, i) in rl.insns.iter().enumerate() {
            index.insert(i.next_addr(), k + 1);
        }
        for (k, i) in rl.insns.iter().enumerate() {
            index.insert(i.addr.0, k);
        }
        let referenced = rl
            .insns
            .iter()
            .enumerate()
            .filter(|(k, _)| reloc.code.contains(k))
            .filter_map(|(_, i)| i.push_value())
            .collect();
        let storage = rl
            .trace
            .storage
            .iter()
            .map(|(slot, name)| (name.clone(), slot.clone()))
            .collect();
        Self {
            insns: &rl.insns,
            trace: &rl.trace,
            cfg,
            reloc,
            opts,
            index,
            referenced,
            storage,
        }
    }

    /// Identifiers in function `fn_addr` beyond the stack variables
    /// `vars` resolves: ABI parameters (`calldataload` of their head
    /// word) and storage variables (`names("&x")` is the root slot).
    fn names<'s>(
        &'s self,
        fn_addr: u64,
        vars: impl Fn(&str) -> Option<Sym> + 's,
    ) -> impl Fn(&str) -> Option<Sym> + 's {
        move |n: &str| {
            if let Some(var) = n.strip_prefix('&') {
                return self.storage.get(var).map(|slot| Sym::Const(slot.clone()));
            }
            vars(n).or_else(|| {
                let k = self
                    .trace
                    .params
                    .get(&fn_addr)?
                    .iter()
                    .position(|w| w == n)?;
                Some(Sym::Op(0x35, vec![Sym::konst(4 + 32 * k as u64)]))
            })
        }
    }

    /// Names at a snapshot, in function `fn_addr`.
    fn at<'s>(&'s self, fn_addr: u64, snap: &'s [SlotNames]) -> impl Fn(&str) -> Option<Sym> + 's {
        self.names(fn_addr, slot_resolver(snap))
    }

    /// The names in `es` that must come from the stack (not parameters
    /// or storage variables).
    fn needed(&self, fn_addr: u64, es: &[&EExpr]) -> Vec<String> {
        let mut v = Vec::new();
        for e in es {
            stack_names(e, &mut v);
        }
        let params = self.trace.params.get(&fn_addr);
        v.retain(|n| {
            !self.storage.contains_key(n) && !params.is_some_and(|p| p.iter().any(|w| w == n))
        });
        v
    }

    /// Whether `e` names storage (`owner`, `allowance[a][b]`).
    fn is_place(&self, e: &EExpr) -> bool {
        match e {
            EExpr::Name(n) => self.storage.contains_key(n),
            EExpr::Index(base, _) => self.is_place(base),
            _ => false,
        }
    }

    fn idx(&self, addr: u64) -> Res<usize> {
        self.index
            .get(&addr)
            .copied()
            .ok_or_else(|| format!("offset 0x{addr:x} isn't an instruction boundary"))
    }

    fn before(&self, k: usize) -> Res<&'a [SlotNames]> {
        self.trace
            .before
            .get(&k)
            .map(Vec::as_slice)
            .ok_or_else(|| "this code wasn't lifted (unreachable?), so its stack is unknown".into())
    }

    /// Names after the instruction before `k`.
    fn after(&self, k: usize) -> Res<&'a [SlotNames]> {
        self.trace
            .fall_end
            .get(&k)
            .map(Vec::as_slice)
            .map_or_else(|| self.before(k), Ok)
    }

    /// Symbolically run instructions `from..to`, which mustn't jump or
    /// halt; a `JUMPDEST` inside them must not be a jump target.
    fn simulate(&self, from: usize, to: usize) -> Res<Sim> {
        self.simulate_from(Sim::default(), from, from, to)
    }

    /// [`Self::simulate`] of `from..to` continuing from state `s`;
    /// `first` is where the statement's code starts.
    fn simulate_from(&self, mut s: Sim, first: usize, from: usize, to: usize) -> Res<Sim> {
        for k in from..to {
            let ins = &self.insns[k];
            let op = ins.opcode;
            // A Vyper return address `PC + d`: the label it computes.
            if op == 0x58
                && let Some((lo, end, target)) = pc_return(self.insns, &self.index, k)
                && lo >= first
                && end <= to
            {
                if lo < k {
                    s.pop();
                }
                s.items.push(Sym::Label(Target::Orig(target), 2));
                // Continue after the `ADD`.
                return self.simulate_from(s, first, end, to);
            }
            match op {
                JUMPDEST => {
                    if k != first && self.referenced.contains(&ins.addr.0) {
                        return Err(format!(
                            "the statement's code spans the jump target 0x{:x}",
                            ins.addr.0
                        ));
                    }
                }
                0x5f..=0x7f => {
                    if ins.is_truncated() {
                        return Err("truncated PUSH".into());
                    }
                    let imm = ins.immediate();
                    let v = if self.reloc.is_ref(k) {
                        Sym::Label(
                            Target::Orig(ins.push_value().unwrap_or_default()),
                            imm.len() as u8,
                        )
                    } else {
                        let first = imm.iter().position(|&x| x != 0).unwrap_or(imm.len());
                        Sym::Const(imm[first..].to_vec())
                    };
                    s.items.push(v);
                }
                0x80..=0x8f => {
                    let n = usize::from(op - 0x80) + 1;
                    s.ensure(n);
                    let v = s.items[s.items.len() - n].clone();
                    s.items.push(v);
                }
                0x90..=0x9f => {
                    let n = usize::from(op - 0x90) + 1;
                    s.ensure(n + 1);
                    let len = s.items.len();
                    s.items.swap(len - 1, len - 1 - n);
                }
                0x50 => {
                    s.pop();
                }
                0x56 | 0x57 | 0x00 | 0xf3 | 0xfd | 0xfe | 0xff | 0x58 => {
                    return Err(format!(
                        "unexpected `{}` inside the statement's code",
                        OPCODE_TABLE[op as usize].name
                    ));
                }
                _ => {
                    let info = &OPCODE_TABLE[op as usize];
                    if !info.is_defined() {
                        return Err("undefined opcode inside the statement's code".into());
                    }
                    let args: Vec<Sym> = (0..info.pops).map(|_| s.pop()).collect();
                    // State reads: results can't be recomputed, but
                    // running them has no effect.
                    let read = matches!(
                        op,
                        0x20 | 0x31 | 0x3b | 0x3d | 0x3f | 0x47 | 0x51 | 0x54 | 0x59 | 0x5a | 0x5c
                    );
                    if info.pushes == 1 {
                        s.items.push(if is_pure(op) {
                            Sym::Op(op, args.clone())
                        } else {
                            Sym::Opaque(k)
                        });
                    }
                    if !is_pure(op) && !read {
                        s.effects.push((op, args));
                    }
                }
            }
        }
        Ok(s)
    }

    /// Where the replacement of `r` starts: at its own bytes, or
    /// earlier over unedited siblings when the names its new text uses
    /// were consumed before it.
    fn pick_start(&self, r: &Replace, needed: &[String]) -> Res<usize> {
        let mut starts = vec![r.start];
        let mut cut = r.start;
        let mut rebound: Vec<&String> = Vec::new();
        for sib in r.prev.iter().rev().take(4) {
            if sib.end != cut {
                break;
            }
            rebound.extend(&sib.dsts);
            if needed.iter().any(|n| rebound.contains(&n)) {
                break;
            }
            starts.push(sib.start);
            cut = sib.start;
        }
        let mut missing: Vec<&String> = Vec::new();
        for (n, &start) in starts.iter().enumerate() {
            let k = self.idx(start)?;
            let names = self.before(k)?;
            let res = slot_resolver(names);
            let here: Vec<&String> = needed.iter().filter(|x| res(x).is_none()).collect();
            if here.is_empty() {
                return Ok(k);
            }
            if n == 0 {
                missing = here;
            }
        }
        Err(format!(
            "{} isn't on the stack here",
            missing
                .iter()
                .map(|m| format!("`{m}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    fn opcode_at(&self, k: usize) -> Option<u8> {
        self.insns.get(k).map(|i| i.opcode)
    }

    /// An emitter for code replacing instructions from `k`, opening
    /// with the label of a `JUMPDEST` there.
    fn emitter<'f>(&self, k: usize, depth: usize, fresh: &'f mut u32) -> Emitter<'f> {
        let mut em = Emitter::new(self.opts, fresh, depth + 17);
        if self.opcode_at(k) == Some(JUMPDEST) {
            em.place(Target::Orig(self.insns[k].addr.0));
        }
        em
    }

    #[allow(clippy::too_many_lines, clippy::many_single_char_names)]
    fn replace(&self, r: &Replace, fresh: &mut u32) -> Res<Patch> {
        let a = self.idx(r.start)?;
        let b = self.idx(r.end)?;
        let opts = self.opts;
        let parse = |t: &str| parse_expr(t).map_err(|e| format!("can't parse `{t}`: {e}"));
        let parse_many = |t: &str| parse_list(t).map_err(|e| format!("can't parse `{t}`: {e}"));
        let lower = |e: &EExpr, names: &[SlotNames]| {
            lower_expr(e, &self.at(r.fn_addr, names), opts).map_err(|e| e.0)
        };
        let names_of = |es: &[EExpr]| self.needed(r.fn_addr, &es.iter().collect::<Vec<_>>());
        let last = self.opcode_at(b - 1).unwrap_or(STOP);

        match (&r.stmt, &r.canon) {
            (
                Stmt::Move { dst, src, .. },
                Stmt::Move {
                    dst: cdst,
                    src: csrc,
                    ..
                },
            ) => {
                // `IERC20(t).transfer(a, n)` / `t.call(IERC20.transfer(…))`:
                // a call with its ABI encoding folded in.
                if is_folded_call(csrc) {
                    return Err("editing external calls (`Iface(t).f(…)`) isn't supported".into());
                }
                self.assign(r, Some((dst, src)), cdst, a, b, fresh)
            }
            (Stmt::Call { name, args, .. }, Stmt::Call { .. }) if self.call_site(b).is_some() => {
                if !name.starts_with("sub_") {
                    return Err(format!(
                        "turning an internal call into `{name}(…)` isn't supported"
                    ));
                }
                let call = parse(&format!("{name}({})", args.join(", ")))?;
                self.rewrite(r, &Rewrite::call(std::slice::from_ref(&call)), a, b, fresh)
            }
            (Stmt::Call { name, args, .. }, Stmt::Call { name: cname, .. }) => {
                if name != cname
                    && !(matches!(name.as_str(), "require" | "assert")
                        && matches!(cname.as_str(), "require" | "assert"))
                {
                    return Err(format!(
                        "turning `{cname}(…)` into `{name}(…)` isn't supported"
                    ));
                }
                match name.as_str() {
                    "require" | "assert" => self.replace_require(r, name, args, a, b, fresh),
                    "emit" => self.replace_emit(r, b, fresh),
                    n if store_opcode(n).is_some() => {
                        let op = store_opcode(n).expect("checked");
                        let [key, val] = args.as_slice() else {
                            return Err(format!("`{n}` takes 2 arguments"));
                        };
                        self.replace_store(r, op, &parse(key)?, false, &parse(val)?, b, fresh)
                    }
                    "revert" | "stop" | "invalid" | "panic" => {
                        let want = match name.as_str() {
                            "revert" | "panic" => 0xfd,
                            "stop" => STOP,
                            _ => INVALID,
                        };
                        if last != want {
                            return Err(
                                "the statement's code doesn't end the way its text says".into()
                            );
                        }
                        self.replace_halt(
                            r,
                            &|em, pre| self.halt_call(em, name, args, &self.at(r.fn_addr, pre)),
                            b,
                            fresh,
                        )
                    }
                    _ => Err(format!("editing `{name}(…)` statements isn't supported")),
                }
            }
            (Stmt::ReturnExpr { text, .. }, Stmt::ReturnExpr { text: ctext, .. }) => {
                let external = |t: &str| t.starts_with("abi.encode(") || t.starts_with("memory(");
                if external(ctext) {
                    if last != 0xf3 {
                        return Err("the statement's code doesn't end in RETURN".into());
                    }
                    let e = parse(text)?;
                    return self.replace_halt(
                        r,
                        &|em, pre| self.external_return(em, &e, &self.at(r.fn_addr, pre)),
                        b,
                        fresh,
                    );
                }
                // Internal return: values below the return address.
                let ends_in_return = last == JUMP
                    && self
                        .cfg
                        .blocks
                        .iter()
                        .position(|blk| blk.insns.contains(&(b - 1)))
                        .is_some_and(|blk| self.cfg.role[blk] == JumpRole::Return);
                if !ends_in_return {
                    return Err(
                        "only the values of internal returns can be edited (not tail calls)".into(),
                    );
                }
                let vals = parse_many(text)?;
                let n = parse_many(ctext)?.len();
                if vals.len() != n {
                    return Err(format!("the function returns {n} value(s)"));
                }
                let k = self.pick_start(r, &names_of(&vals))?;
                let mut sim = self.simulate(k, b - 1)?;
                if !sim.effects.iter().all(|(o, _)| *o == MSTORE) {
                    return Err("the statement's code has effects its text doesn't show".into());
                }
                let pre = self.before(k)?;
                for (i, v) in vals.iter().enumerate() {
                    *sim.at_mut(n - i) = lower(v, pre)?;
                }
                // Vyper 0.2 loads its spilled return address in the
                // `return` itself: load it again, after the new values
                // (which write at most the scratch words below 0x40).
                if let Sym::Opaque(j) = *sim.at_mut(0)
                    && self.insns[j].opcode == 0x51
                    && let Some(slot) = j
                        .checked_sub(1)
                        .and_then(|p| self.insns[p].push_value())
                        .filter(|&s| s >= 0x40 && j > k)
                {
                    *sim.at_mut(0) = Sym::Op(0x51, vec![Sym::konst(slot)]);
                }
                let mut em = self.emitter(k, sim.consumed, fresh);
                em.materialize(sim.consumed, &sim.items).map_err(|e| e.0)?;
                em.op(JUMP, None).map_err(|e| e.0)?;
                Ok(Patch {
                    from: k,
                    to: b,
                    pieces: em.pieces,
                })
            }
            (Stmt::IfBranch { cond_text, .. }, Stmt::IfBranch { then_body, .. }) => {
                // `if (c) { jump(…) }` / `if (c) { revert(…) }` restate a
                // jump taken when `c`; structured `if`s fall into their
                // body when `c`, jumping over it otherwise.
                let taken = is_zero_byte_body(then_body);
                self.replace_cond(r, cond_text, taken, b, fresh)
            }
            (Stmt::WhileBlock { cond_text, .. }, _) => {
                self.replace_cond(r, cond_text, false, b, fresh)
            }
            (Stmt::Loop { cond_text, .. }, _) => self.replace_cond(r, cond_text, true, b, fresh),
            _ => Err("editing this kind of statement isn't supported".into()),
        }
    }

    /// Rewrite the assignment `old = …` spanning `a..b` to `new` (`None`
    /// deletes it). Stack variables it no longer writes keep the values
    /// they had before it; one that had none is left as zero when no
    /// other statement mentions it.
    #[allow(clippy::many_single_char_names)]
    fn assign(
        &self,
        r: &Replace,
        new: Option<(&str, &str)>,
        old: &str,
        a: usize,
        b: usize,
        fresh: &mut u32,
    ) -> Res<Patch> {
        let parse = |t: &str| parse_expr(t).map_err(|e| format!("can't parse `{t}`: {e}"));
        let as_place = |d: &str| parse_expr(d).ok().filter(|e| self.is_place(e));
        let old_place = as_place(old);
        let new_place = new.and_then(|(d, _)| as_place(d));
        let (dsts, srcs): (Vec<&str>, Vec<EExpr>) = match new {
            None => (Vec::new(), Vec::new()),
            Some((_, src)) if new_place.is_some() => (Vec::new(), vec![parse(src)?]),
            Some((dst, src)) => (
                dst.split(", ").collect(),
                parse_list(src).map_err(|e| format!("can't parse `{src}`: {e}"))?,
            ),
        };
        let calls = |e: &EExpr| is_internal_call(e) || ext_call(e).is_some();
        // `owner = v` / `balanceOf[k] = v` store to named storage.
        if let (Some(_), Some(place), [src]) = (&old_place, &new_place, srcs.as_slice())
            && self.call_site(b).is_none()
            && !calls(src)
        {
            return self.replace_store(r, 0x55, place, true, src, b, fresh);
        }
        let old_dsts: Vec<&str> = if old_place.is_some() {
            Vec::new()
        } else {
            old.split(", ").collect()
        };
        self.rewrite(
            r,
            &Rewrite {
                dsts: &dsts,
                srcs: &srcs,
                place: new_place.as_ref(),
                old: &old_dsts,
                old_place: old_place.is_some(),
            },
            a,
            b,
            fresh,
        )
    }

    /// The internal call whose `JUMP` ends just before `b`: its call
    /// site's block.
    fn call_site(&self, b: usize) -> Option<usize> {
        if b == 0 || self.opcode_at(b - 1) != Some(JUMP) {
            return None;
        }
        let blk = self
            .cfg
            .blocks
            .iter()
            .position(|blk| blk.insns.contains(&(b - 1)))?;
        (self.cfg.role[blk] == JumpRole::Call && !self.cfg.tail_calls.contains(&blk)).then_some(blk)
    }

    /// The internal function `sub_xxxx` names: entry offset and summary.
    fn callee(&self, name: &str) -> Res<(u64, FuncInfo)> {
        name.strip_prefix("sub_")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .and_then(|addr| {
                let blk = self.cfg.block_at(addr)?;
                Some((addr, *self.cfg.functions.get(&blk)?))
            })
            .ok_or_else(|| format!("`{name}` isn't an internal function"))
    }

    /// Generate `w.dsts = w.srcs` (or `w.place = w.srcs[0]`) in place of
    /// the statement spanning `a..b`, which assigned `w.old`. The last
    /// value may be an internal call (`sub_xxxx(args)`, its results
    /// filling the last targets) and one value an external call; the
    /// original statement may itself be an internal call, whose frame
    /// the new code no longer builds unless it calls again.
    #[allow(
        clippy::too_many_lines,
        clippy::many_single_char_names,
        clippy::single_match_else
    )]
    fn rewrite(
        &self,
        r: &Replace,
        w: &Rewrite<'_>,
        a: usize,
        b: usize,
        fresh: &mut u32,
    ) -> Res<Patch> {
        // Ids of values that don't exist before the new code runs.
        const OLD_RESULT: usize = usize::MAX - 0x100;
        const NEW_RESULT: usize = usize::MAX - 0x200;
        const NEW_EXT: usize = usize::MAX - 0x300;
        let opts = self.opts;
        // The original call.
        let site = self.call_site(b);
        let orig = match site {
            Some(blk) => {
                let info = self.cfg.functions[&self.cfg.calls[&blk].callee];
                if info.noreturn {
                    return Err("calls to functions that never return can't be edited".into());
                }
                let n = info
                    .nrets
                    .ok_or("the called function's return-value count is unknown")?;
                let cont = self.insns.get(b).map(|i| i.addr.0);
                let here =
                    self.cfg.conts.get(&blk).is_some_and(|cs| {
                        cs.iter().all(|&c| Some(self.cfg.blocks[c].start) == cont)
                    });
                if !here || self.opcode_at(b) != Some(JUMPDEST) {
                    return Err("the call returns elsewhere than to the code after it".into());
                }
                Some((info, n))
            }
            None => {
                if self.insns[a..b]
                    .iter()
                    .any(|i| matches!(i.opcode, 0x56 | 0x57))
                {
                    return Err("the statement's code jumps, which its text doesn't show".into());
                }
                None
            }
        };
        let onrets = orig.map_or(0, |(_, n)| n);
        // The new internal call: the last value.
        let icall = match w.srcs.last() {
            Some(EExpr::Call(n, args)) if n.starts_with("sub_") => {
                let (addr, info) = self.callee(n)?;
                if args.len() != info.total_args() {
                    return Err(format!("`{n}` takes {} argument(s)", info.total_args()));
                }
                let nn = if info.noreturn {
                    0
                } else {
                    info.nrets
                        .ok_or_else(|| format!("`{n}`'s return-value count is unknown"))?
                };
                Some((addr, info, nn, args.as_slice()))
            }
            _ => None,
        };
        let plain = &w.srcs[..w.srcs.len() - usize::from(icall.is_some())];
        if plain.iter().any(is_internal_call) {
            return Err("an internal call must be the whole of the last value".into());
        }
        let ext_at: Vec<usize> = (0..plain.len())
            .filter(|&i| ext_call(&plain[i]).is_some())
            .collect();
        if ext_at.len() + usize::from(icall.is_some()) > 1 {
            return Err("one call per statement".into());
        }
        let ext_at = ext_at.first().copied();
        let nn = icall.map_or(0, |c| c.2);
        if icall.is_some_and(|c| c.1.noreturn) && !w.dsts.is_empty() {
            return Err("the called function never returns".into());
        }
        if w.place.is_some() && (icall.is_some() || ext_at.is_some()) {
            return Err("a call's result can only be assigned to stack variables".into());
        }
        if w.place.is_none() && w.dsts.len() != plain.len() + nn {
            return Err(format!(
                "{} target(s) but {} value(s)",
                w.dsts.len(),
                plain.len() + nn
            ));
        }
        let mut exprs: Vec<&EExpr> = w.srcs.iter().collect();
        exprs.extend(w.place);
        let k = self.pick_start(r, &self.needed(r.fn_addr, &exprs))?;
        let end = if orig.is_some() { b - 1 } else { b };
        let mut sim = self.simulate(k, end)?;
        // Effects: scratch `mstore`s, the store the text shows, and an
        // external call it shows.
        let canon_calls = stmt_text(&r.canon).is_some_and(|t| {
            parse_list(t.split_once(" = ").map_or(t.as_str(), |x| x.1))
                .is_ok_and(|es| es.iter().any(|e| ext_call(e).is_some()))
        });
        let mut old_ext = None;
        let mut stores = 0;
        for (op, _) in &sim.effects {
            match op {
                &MSTORE => {}
                0x55 => stores += 1,
                0xf1 | 0xf2 | 0xf4 | 0xfa if canon_calls && old_ext.is_none() => {
                    old_ext = (k..end).find(|&i| self.insns[i].opcode == *op);
                }
                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                    return Err(
                        "this form of external call can't be edited; only `call(…)`, `staticcall(…)`, `delegatecall(…)`, `callcode(…)` and `to.send(v)`".into(),
                    );
                }
                op => {
                    return Err(format!(
                        "the statement's code also runs `{}`, which its text doesn't show",
                        OPCODE_TABLE[*op as usize].name
                    ));
                }
            }
        }
        if stores != usize::from(w.old_place) {
            return Err(
                "the statement's code also runs `SSTORE`, which its text doesn't show".into(),
            );
        }
        if let Some((info, _)) = orig {
            sim.pop(); // the callee
            for _ in 0..info.nargs {
                sim.pop();
            }
            sim.pop(); // the return address
            for _ in 0..info.nbelow {
                sim.pop();
            }
            for i in 0..onrets {
                sim.items.push(Sym::Opaque(OLD_RESULT + i));
            }
        }
        let pre = self.before(k)?;
        let post = if orig.is_some() {
            self.before(b)?
        } else {
            self.after(b)?
        };
        let names = self.at(r.fn_addr, pre);
        let ext_id = Sym::Opaque(old_ext.unwrap_or(NEW_EXT));
        let mut vals: Vec<Sym> = Vec::new();
        for (i, e) in plain.iter().enumerate() {
            vals.push(if Some(i) == ext_at {
                ext_id.clone()
            } else {
                lower_expr(e, &names, opts).map_err(|e| e.0)?
            });
        }
        let results: Vec<Sym> = (0..nn).map(|i| Sym::Opaque(NEW_RESULT + i)).collect();
        vals.extend(results.iter().cloned());
        if w.place.is_none() {
            for (i, (d, v)) in w.dsts.iter().zip(&vals).enumerate() {
                if *d == "_" {
                    // A kept return address: where the old call's was.
                    if let Some(j) = i.checked_sub(plain.len()).filter(|&j| j < onrets) {
                        *sim.at_mut(onrets - 1 - j) = v.clone();
                    }
                    continue;
                }
                let at = dst_positions(post, d);
                if at.is_empty() {
                    return Err(format!(
                        "`{d}` isn't on the stack after this statement; assign a variable the code after it holds"
                    ));
                }
                for t in at {
                    *sim.at_mut(t) = v.clone();
                }
            }
        }
        for d in w.old {
            if *d == "_" || w.dsts.contains(d) {
                continue;
            }
            // Siblings the replacement extends over mustn't write it.
            if r.prev.iter().any(|sib| {
                self.index.get(&sib.start).is_some_and(|&s| s >= k)
                    && sib.dsts.iter().any(|x| x == d)
            }) {
                return Err(format!(
                    "`{d}` is also assigned just before; edit that statement instead"
                ));
            }
            let kept = match pre.iter().position(|s| s.var.as_deref() == Some(*d)) {
                Some(t) => Sym::Slot(t),
                None if !r.used.contains(*d) => Sym::konst(0),
                None => {
                    return Err(format!(
                        "`{d}` has no value without this assignment, but other statements use it"
                    ));
                }
            };
            for t in dst_positions(post, d) {
                *sim.at_mut(t) = kept.clone();
            }
        }
        // Results of the old call nothing names (a kept return address).
        for item in &mut sim.items {
            if matches!(item, Sym::Opaque(x) if (OLD_RESULT..OLD_RESULT + 0x100).contains(x)) {
                *item = Sym::konst(0);
            }
        }
        let ext = match ext_at {
            Some(i) => Some(self.lower_ext(&plain[i], &names)?),
            None => None,
        };

        let emit = |ret: Target, fresh: &mut u32| -> Res<(Vec<Piece>, bool)> {
            let mut em = self.emitter(k, sim.consumed, fresh);
            let Some((addr, info, nn, args)) = icall else {
                let mut extra = 0;
                if let Some((op, args)) = &ext {
                    for x in args.iter().rev() {
                        em.value(x).map_err(|e| e.0)?;
                    }
                    em.op(*op, Some(ext_id.clone())).map_err(|e| e.0)?;
                    extra = 1;
                }
                if let Some(place) = w.place {
                    let slot = lower_place(place, &names, opts)
                        .map_err(|e| e.0)?
                        .ok_or("not a storage location")?;
                    em.value(&vals[0]).map_err(|e| e.0)?;
                    em.value(&slot).map_err(|e| e.0)?;
                    em.op(0x55, None).map_err(|e| e.0)?;
                }
                em.materialize(sim.consumed + extra, &sim.items)
                    .map_err(|e| e.0)?;
                return Ok((em.pieces, false));
            };
            let argv: Vec<Sym> = args
                .iter()
                .map(|x| lower_expr(x, &names, opts).map_err(|e| e.0))
                .collect::<Res<_>>()?;
            let below_n = sim.items.len() - onrets;
            let is_new = |x: &Sym| matches!(x, Sym::Opaque(i) if (NEW_RESULT..NEW_RESULT + 0x100).contains(i));
            let mut goal: Vec<Sym> = sim.items[..below_n]
                .iter()
                .map(|x| if is_new(x) { Sym::konst(0) } else { x.clone() })
                .collect();
            goal.extend(argv[..info.nbelow].iter().cloned());
            goal.push(Sym::Label(ret, 2));
            goal.extend(argv[info.nbelow..].iter().cloned());
            goal.push(Sym::Label(Target::Orig(addr), 2));
            em.materialize(sim.consumed, &goal).map_err(|e| e.0)?;
            em.op(JUMP, None).map_err(|e| e.0)?;
            if info.noreturn {
                return Ok((em.pieces, false));
            }
            if matches!(ret, Target::Fresh(_)) {
                em.place(ret);
            }
            em.returned(info.total_args() + 1, &results[..nn])
                .map_err(|e| e.0)?;
            let before = em.pieces.clone();
            em.materialize(below_n + nn, &sim.items).map_err(|e| e.0)?;
            let trivial = em.pieces == before;
            Ok((em.pieces, trivial))
        };
        // Return straight to the old continuation when the results
        // land where it expects them.
        let cont = match (orig, self.insns.get(b)) {
            (Some(_), Some(c)) if icall.is_some() => Some(Target::Orig(c.addr.0)),
            _ => None,
        };
        let pieces = match cont.map(|t| emit(t, fresh)).transpose()? {
            Some((pieces, true)) => pieces,
            _ => {
                *fresh += 1;
                emit(Target::Fresh(*fresh), fresh)?.0
            }
        };
        Ok(Patch {
            from: k,
            to: b,
            pieces,
        })
    }

    /// An external call's opcode and its stack arguments, top first.
    fn lower_ext(&self, e: &EExpr, names: &dyn Fn(&str) -> Option<Sym>) -> Res<(u8, Vec<Sym>)> {
        let (op, args) = ext_call(e).ok_or("not an external call")?;
        let args: Vec<Sym> = args
            .iter()
            .map(|x| lower_expr(x, names, self.opts).map_err(|e| e.0))
            .collect::<Res<_>>()?;
        Ok((op, args))
    }

    /// Code for a commented-out statement: what it left on the stack
    /// for the code after it, without its effects.
    fn delete(&self, r: &Replace, fresh: &mut u32) -> Res<Patch> {
        let a = self.idx(r.start)?;
        let b = self.idx(r.end)?;
        let last = self.opcode_at(b - 1).unwrap_or(STOP);
        match &r.canon {
            Stmt::Move { src, .. } if is_folded_call(src) => {
                Err("deleting external calls (`Iface(t).f(…)`) isn't supported".into())
            }
            Stmt::Move { dst, .. } => self.assign(r, None, dst, a, b, fresh),
            Stmt::Call { name, .. } if matches!(name.as_str(), "require" | "assert") => {
                self.delete_guard(a, b, fresh)
            }
            Stmt::Call { .. } if self.call_site(b).is_some() => {
                self.rewrite(r, &Rewrite::call(&[]), a, b, fresh)
            }
            _ if matches!(last, 0x00 | 0xf3 | 0xfd | 0xfe | 0xff | JUMP | JUMPI) => Err(
                "a statement that ends its block (a halt, return or jump) can't be deleted; edit it instead".into(),
            ),
            Stmt::Call { .. } => {
                let sim = self.simulate(a, b)?;
                let mut em = self.emitter(a, sim.consumed, fresh);
                em.materialize(sim.consumed, &sim.items).map_err(|e| e.0)?;
                Ok(Patch {
                    from: a,
                    to: b,
                    pieces: em.pieces,
                })
            }
            _ => Err("deleting this kind of statement isn't supported".into()),
        }
    }

    /// A deleted `require` / `assert`: continue where its check passes.
    fn delete_guard(&self, a: usize, b: usize, fresh: &mut u32) -> Res<Patch> {
        let j = (a..b)
            .find(|&k| matches!(self.insns[k].opcode, 0x56 | 0x57))
            .filter(|&k| self.insns[k].opcode == JUMPI)
            .ok_or("the statement's code has no conditional jump")?;
        let mut sim = self.simulate(a, j)?;
        if !sim.effects.iter().all(|(o, _)| *o == MSTORE) {
            return Err("the condition's code has effects its text doesn't show".into());
        }
        let target = sim.pop();
        sim.pop();
        let dest = match &target {
            Sym::Label(Target::Orig(t), _) => Some(*t),
            // Pushed by an earlier statement: as the CFG resolved it.
            _ => self
                .cfg
                .blocks
                .iter()
                .position(|blk| blk.insns.contains(&j))
                .and_then(
                    |blk| match self.cfg.targets[blk].iter().collect::<Vec<_>>()[..] {
                        [&t] => Some(self.cfg.blocks[t].start),
                        _ => None,
                    },
                ),
        };
        let dest = dest.ok_or("the jump target isn't known")?;
        let mut em = self.emitter(a, sim.consumed, fresh);
        let falls_in = self
            .insns
            .get(b)
            .is_some_and(|i| i.opcode == JUMPDEST && i.addr.0 == dest);
        if falls_in {
            em.materialize(sim.consumed, &sim.items).map_err(|e| e.0)?;
        } else {
            let mut goal = sim.items.clone();
            goal.push(target);
            em.materialize(sim.consumed, &goal).map_err(|e| e.0)?;
            em.op(JUMP, None).map_err(|e| e.0)?;
        }
        Ok(Patch {
            from: a,
            to: b,
            pieces: em.pieces,
        })
    }

    /// A store (`op`) of `val` at `key` — an address, or with `place`
    /// a storage variable — replacing a statement ending at `b`.
    #[allow(clippy::too_many_arguments)]
    fn replace_store(
        &self,
        r: &Replace,
        op: u8,
        key: &EExpr,
        place: bool,
        val: &EExpr,
        b: usize,
        fresh: &mut u32,
    ) -> Res<Patch> {
        let k = self.pick_start(r, &self.needed(r.fn_addr, &[key, val]))?;
        let sim = self.simulate(k, b)?;
        let mains = sim.effects.iter().filter(|(o, _)| *o == op).count();
        if (mains != 1 && op != MSTORE) || sim.effects.iter().any(|(o, _)| *o != op && *o != MSTORE)
        {
            return Err("the statement's code has other effects than its text shows".into());
        }
        let names = self.at(r.fn_addr, self.before(k)?);
        let key = if place {
            lower_place(key, &names, self.opts)
                .map_err(|e| e.0)?
                .ok_or("not a storage location")?
        } else {
            lower_expr(key, &names, self.opts).map_err(|e| e.0)?
        };
        let val = lower_expr(val, &names, self.opts).map_err(|e| e.0)?;
        let mut em = self.emitter(k, sim.consumed, fresh);
        em.value(&val).map_err(|e| e.0)?;
        em.value(&key).map_err(|e| e.0)?;
        em.op(op, None).map_err(|e| e.0)?;
        em.materialize(sim.consumed, &sim.items).map_err(|e| e.0)?;
        Ok(Patch {
            from: k,
            to: b,
            pieces: em.pieces,
        })
    }

    /// The conditional jump ending `a..b`, with its condition rebuilt
    /// from `cond_text` (`taken`: the jump happens when it holds).
    fn replace_cond(
        &self,
        r: &Replace,
        cond_text: &str,
        taken: bool,
        b: usize,
        fresh: &mut u32,
    ) -> Res<Patch> {
        if self.opcode_at(b - 1) != Some(JUMPI) {
            return Err("the statement's code doesn't end in JUMPI".into());
        }
        let cond = parse_expr(cond_text).map_err(|e| format!("can't parse `{cond_text}`: {e}"))?;
        let k = self.pick_start(r, &self.needed(r.fn_addr, &[&cond]))?;
        let mut sim = self.simulate(k, b - 1)?;
        if !sim.effects.iter().all(|(o, _)| *o == MSTORE) {
            return Err("the condition's code has effects its text doesn't show".into());
        }
        let Sym::Label(target, width) = sim.pop() else {
            return Err("the jump target isn't a constant".into());
        };
        sim.pop();
        let c =
            lower_expr(&cond, &self.at(r.fn_addr, self.before(k)?), self.opts).map_err(|e| e.0)?;
        let c = if taken { c } else { negate(c) };
        let mut em = self.emitter(k, sim.consumed, fresh);
        em.cond_jump(sim.consumed, &sim.items, c, target, width)
            .map_err(|e| e.0)?;
        Ok(Patch {
            from: k,
            to: b,
            pieces: em.pieces,
        })
    }

    #[allow(clippy::many_single_char_names)]
    fn replace_require(
        &self,
        r: &Replace,
        name: &str,
        args: &[String],
        a: usize,
        b: usize,
        fresh: &mut u32,
    ) -> Res<Patch> {
        let (cond_text, reason) = match (name, args) {
            (_, [c]) => (c, None),
            ("require", [c, reason]) => (c, Some(reason_text(reason)?)),
            _ => return Err(format!("`{name}` takes a condition (and a reason)")),
        };
        let j = (a..b)
            .find(|&k| matches!(self.insns[k].opcode, 0x56 | 0x57))
            .filter(|&k| self.insns[k].opcode == JUMPI)
            .ok_or("the statement's code has no conditional jump")?;
        let tail_ok = j + 1 == b
            || (matches!(self.opcode_at(b - 1), Some(0xfd | 0xfe))
                && self.simulate(j + 1, b - 1).is_ok());
        if !tail_ok {
            return Err("the statement's code doesn't end in a failure".into());
        }
        let cond = parse_expr(cond_text).map_err(|e| format!("can't parse `{cond_text}`: {e}"))?;
        let k = self.pick_start(r, &self.needed(r.fn_addr, &[&cond]))?;
        let mut sim = self.simulate(k, j)?;
        if !sim.effects.iter().all(|(o, _)| *o == MSTORE) {
            return Err("the condition's code has effects its text doesn't show".into());
        }
        sim.pop();
        sim.pop();
        let c =
            lower_expr(&cond, &self.at(r.fn_addr, self.before(k)?), self.opts).map_err(|e| e.0)?;
        let mut em = self.emitter(k, sim.consumed, fresh);
        // Continue at the `JUMPDEST` that follows, if there is one.
        let next = self.insns.get(b).filter(|i| i.opcode == JUMPDEST);
        let ok = next.map_or_else(|| em.fresh_label(), |i| Target::Orig(i.addr.0));
        em.cond_jump(sim.consumed, &sim.items, c, ok, 2)
            .map_err(|e| e.0)?;
        match (name, reason) {
            ("assert", _) => em.op(INVALID, None),
            (_, Some(reason)) => em.revert_reason(&reason),
            (_, None) => em.revert_empty(),
        }
        .map_err(|e| e.0)?;
        if next.is_none() {
            em.place(ok);
        }
        Ok(Patch {
            from: k,
            to: b,
            pieces: em.pieces,
        })
    }

    fn replace_emit(&self, r: &Replace, b: usize, fresh: &mut u32) -> Res<Patch> {
        let parse_event = |s: &Stmt| -> Res<(String, Vec<EExpr>)> {
            let Stmt::Call { args, .. } = s else {
                unreachable!("emit is a call")
            };
            match args.as_slice().first().map(|t| parse_expr(t)) {
                Some(Ok(EExpr::Call(n, a))) if args.len() == 1 => Ok((n, a)),
                _ => Err("expected `emit(Event(args…))`".into()),
            }
        };
        let (name, vals) = parse_event(&r.stmt)?;
        let (cname, cvals) = parse_event(&r.canon)?;
        if name != cname || vals.len() != cvals.len() {
            return Err(format!(
                "only the arguments of `{cname}` can be edited ({} of them)",
                cvals.len()
            ));
        }
        let k = self.pick_start(r, &self.needed(r.fn_addr, &vals.iter().collect::<Vec<_>>()))?;
        let sim = self.simulate(k, b)?;
        let logs: Vec<&(u8, Vec<Sym>)> = sim
            .effects
            .iter()
            .filter(|(o, _)| (0xa1..=0xa4).contains(o))
            .collect();
        let [(op, largs)] = logs.as_slice() else {
            return Err("the statement's code isn't a single event".into());
        };
        if sim.effects.iter().any(|(o, _)| *o != MSTORE && *o != *op) {
            return Err("the statement's code has effects its text doesn't show".into());
        }
        let topic0 = largs.get(2).cloned().ok_or("malformed LOG")?;
        let indexed = usize::from(op - 0xa1);
        if vals.len() < indexed {
            return Err("fewer arguments than indexed topics".into());
        }
        let res = self.at(r.fn_addr, self.before(k)?);
        let syms: Vec<Sym> = vals
            .iter()
            .map(|v| lower_expr(v, &res, self.opts).map_err(|e| e.0))
            .collect::<Res<_>>()?;
        let mut topics = vec![topic0];
        topics.extend(syms[..indexed].iter().cloned());
        let mut em = self.emitter(k, sim.consumed, fresh);
        em.log(&topics, &syms[indexed..]).map_err(|e| e.0)?;
        em.materialize(sim.consumed, &sim.items).map_err(|e| e.0)?;
        Ok(Patch {
            from: k,
            to: b,
            pieces: em.pieces,
        })
    }

    /// Replace a halting statement: `body` generates the new halt from
    /// the stack names at its start.
    fn replace_halt(
        &self,
        r: &Replace,
        body: &dyn Fn(&mut Emitter<'_>, &[SlotNames]) -> Res<()>,
        b: usize,
        fresh: &mut u32,
    ) -> Res<Patch> {
        let exprs = halt_exprs(&r.stmt);
        let k = self.pick_start(
            r,
            &self.needed(r.fn_addr, &exprs.iter().collect::<Vec<_>>()),
        )?;
        // Everything up to the halt must be encoding work.
        self.simulate(k, b - 1)?;
        let pre = self.before(k)?;
        let mut em = self.emitter(k, 0, fresh);
        body(&mut em, pre)?;
        Ok(Patch {
            from: k,
            to: b,
            pieces: em.pieces,
        })
    }

    fn halt_call(
        &self,
        em: &mut Emitter<'_>,
        name: &str,
        args: &[String],
        names: &dyn Fn(&str) -> Option<Sym>,
    ) -> Res<()> {
        let lower = |t: &str| -> Res<Sym> {
            let e = parse_expr(t).map_err(|e| format!("can't parse `{t}`: {e}"))?;
            lower_expr(&e, names, self.opts).map_err(|e| e.0)
        };
        match (name, args) {
            ("stop", []) => em.op(STOP, None),
            ("invalid", []) => em.op(INVALID, None),
            ("revert", []) => em.revert_empty(),
            ("revert", [o, n]) => {
                let (o, n) = (lower(o)?, lower(n)?);
                em.halt_mem(&o, &n, 0xfd)
            }
            ("revert", [reason]) => em.revert_reason(&reason_text(reason)?),
            ("panic", [code]) => {
                let c = lower(code)?;
                em.revert_panic(&c)
            }
            _ => return Err(format!("unsupported form of `{name}(…)`")),
        }
        .map_err(|e| e.0)
    }

    fn external_return(
        &self,
        em: &mut Emitter<'_>,
        e: &EExpr,
        names: &dyn Fn(&str) -> Option<Sym>,
    ) -> Res<()> {
        let lower = |x: &EExpr| lower_expr(x, names, self.opts).map_err(|e| e.0);
        match e {
            EExpr::Call(n, args) if n == "abi.encode" => {
                let words: Vec<Sym> = args.iter().map(lower).collect::<Res<_>>()?;
                em.ret(&words).map_err(|e| e.0)
            }
            EExpr::Call(n, args) if n == "memory" && args.len() == 2 => {
                let (o, l) = (lower(&args[0])?, lower(&args[1])?);
                em.halt_mem(&o, &l, 0xf3).map_err(|e| e.0)
            }
            _ => Err("expected `abi.encode(…)` or `memory(offset, length)`".into()),
        }
    }

    /// Compile statements added before instruction `at`.
    fn insert(&self, ins: &Insert, fresh: &mut u32) -> Res<Patch> {
        let mut k = self.idx(ins.at)?;
        let names = if ins.end_of_list {
            if k == 0
                || matches!(
                    self.opcode_at(k - 1),
                    Some(0x56 | 0x00 | 0xf3 | 0xfd | 0xfe | 0xff)
                )
            {
                return Err("added after a jump or halt, where it would never run".into());
            }
            self.after(k)?
        } else {
            let n = self.before(k)?;
            if self.opcode_at(k) == Some(JUMPDEST) {
                // Run on every path into the next statement.
                k += 1;
            }
            n
        };
        let mut scope: HashMap<String, Sym> = HashMap::new();
        for (t, s) in names.iter().enumerate() {
            if let Some(v) = &s.var {
                scope.entry(v.clone()).or_insert(Sym::Slot(t));
            }
        }
        let mut em = Emitter::new(self.opts, fresh, names.len());
        for s in &ins.stmts {
            self.added(&mut em, s, ins.fn_addr, names, &mut scope)?;
        }
        Ok(Patch {
            from: k,
            to: k,
            pieces: em.pieces,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn added(
        &self,
        em: &mut Emitter<'_>,
        s: &Stmt,
        fn_addr: u64,
        names: &[SlotNames],
        scope: &mut HashMap<String, Sym>,
    ) -> Res<()> {
        let opts = self.opts;
        let lower = |t: &str, scope: &HashMap<String, Sym>| -> Res<Sym> {
            let e = parse_expr(t).map_err(|e| format!("can't parse `{t}`: {e}"))?;
            lower_expr(&e, &self.names(fn_addr, |n| scope.get(n).cloned()), opts).map_err(|e| e.0)
        };
        let pre: Vec<SlotNames> = names.to_vec();
        match s {
            Stmt::Comment(_) => Ok(()),
            Stmt::Move { dst, src, .. } => {
                if let Ok(place) = parse_expr(dst)
                    && self.is_place(&place)
                {
                    let res = self.names(fn_addr, |n| scope.get(n).cloned());
                    let slot = lower_place(&place, &res, opts)
                        .map_err(|e| e.0)?
                        .ok_or("not a storage location")?;
                    let v = lower(src, scope)?;
                    em.value(&v).map_err(|e| e.0)?;
                    em.value(&slot).map_err(|e| e.0)?;
                    return em.op(0x55, None).map_err(|e| e.0);
                }
                let dsts: Vec<&str> = dst.split(", ").collect();
                let srcs = parse_list(src).map_err(|e| format!("can't parse `{src}`: {e}"))?;
                let calls = srcs
                    .iter()
                    .filter(|e| is_internal_call(e) || ext_call(e).is_some())
                    .count();
                if calls > 1 {
                    return Err("one call per statement".into());
                }
                // The call runs first; its results stay on top.
                let mut results = Vec::new();
                let mut vals: Vec<Sym> = Vec::new();
                for e in &srcs {
                    let res = self.names(fn_addr, |n| scope.get(n).cloned());
                    if is_internal_call(e) || ext_call(e).is_some() {
                        results = self.added_call(em, e, &res)?;
                        vals.extend(results.iter().cloned());
                    } else {
                        vals.push(lower_expr(e, &res, opts).map_err(|e| e.0)?);
                    }
                }
                if vals.len() != dsts.len() {
                    return Err(format!(
                        "{} target(s) but {} value(s)",
                        dsts.len(),
                        vals.len()
                    ));
                }
                let mut repl: Vec<(usize, Sym)> = Vec::new();
                for (d, v) in dsts.iter().zip(&vals) {
                    if *d == "_" {
                        continue;
                    }
                    let at = dst_positions(&pre, d);
                    if at.is_empty() {
                        return Err(format!("`{d}` isn't a stack variable here"));
                    }
                    repl.extend(at.into_iter().map(|t| (t, v.clone())));
                }
                let depth = repl.iter().map(|(t, _)| t + 1).max().unwrap_or(0);
                let n = results.len();
                let mut goal = em.top(depth + n).map_err(|e| e.0)?;
                goal.truncate(depth);
                for (t, v) in &repl {
                    let len = goal.len();
                    goal[len - 1 - t] = v.clone();
                }
                em.materialize(depth + n, &goal).map_err(|e| e.0)?;
                for (d, v) in dsts.iter().zip(vals) {
                    scope.insert((*d).to_string(), v);
                }
                Ok(())
            }
            Stmt::Call { name, args, .. } => match name.as_str() {
                n if store_opcode(n).is_some() => {
                    let [k, v] = args.as_slice() else {
                        return Err(format!("`{n}` takes 2 arguments"));
                    };
                    let (k, v) = (lower(k, scope)?, lower(v, scope)?);
                    em.value(&v).map_err(|e| e.0)?;
                    em.value(&k).map_err(|e| e.0)?;
                    em.op(store_opcode(n).expect("checked"), None)
                        .map_err(|e| e.0)
                }
                "require" | "assert" => {
                    let (c, reason) = match (name.as_str(), args.as_slice()) {
                        (_, [c]) => (c, None),
                        ("require", [c, r]) => (c, Some(reason_text(r)?)),
                        _ => return Err(format!("`{name}` takes a condition (and a reason)")),
                    };
                    let c = lower(c, scope)?;
                    let ok = em.fresh_label();
                    em.cond_jump(0, &[], c, ok, 2).map_err(|e| e.0)?;
                    match (name.as_str(), reason) {
                        ("assert", _) => em.op(INVALID, None),
                        (_, Some(r)) => em.revert_reason(&r),
                        (_, None) => em.revert_empty(),
                    }
                    .map_err(|e| e.0)?;
                    em.place(ok);
                    Ok(())
                }
                "revert" | "stop" | "invalid" | "panic" => self.halt_call(
                    em,
                    name,
                    args,
                    &self.names(fn_addr, |n| scope.get(n).cloned()),
                ),
                _ => {
                    let call = parse_expr(&format!("{name}({})", args.join(", ")))
                        .map_err(|e| format!("can't parse the call: {e}"))?;
                    if !is_internal_call(&call) && ext_call(&call).is_none() {
                        return Err(format!("adding `{name}(…)` statements isn't supported"));
                    }
                    let res = self.names(fn_addr, |n| scope.get(n).cloned());
                    let results = self.added_call(em, &call, &res)?;
                    // Results nothing names are dropped.
                    em.materialize(results.len(), &[]).map_err(|e| e.0)
                }
            },
            Stmt::ReturnExpr { text, .. } => {
                let e = parse_expr(text).map_err(|e| format!("can't parse `{text}`: {e}"))?;
                self.external_return(em, &e, &self.names(fn_addr, |n| scope.get(n).cloned()))
            }
            Stmt::IfBranch {
                cond_text,
                then_body,
                else_body,
                ..
            } => {
                let c = lower(cond_text, scope)?;
                let before = em.top(names.len()).map_err(|e| e.0)?;
                let saved = scope.clone();
                let end = em.fresh_label();
                let skip = if else_body.is_some() {
                    em.fresh_label()
                } else {
                    end
                };
                em.cond_jump(0, &[], negate(c), skip, 2).map_err(|e| e.0)?;
                for st in then_body {
                    self.added(em, st, fn_addr, names, scope)?;
                }
                if let Some(else_body) = else_body {
                    em.push_label(end, 2);
                    em.op(JUMP, None).map_err(|e| e.0)?;
                    em.place(skip);
                    *scope = saved.clone();
                    em.reset_top(&before).map_err(|e| e.0)?;
                    for st in else_body {
                        self.added(em, st, fn_addr, names, scope)?;
                    }
                }
                em.place(end);
                // After the join a slot assigned in a branch holds one of
                // two values: forget both.
                em.forget_changes(&before).map_err(|e| e.0)?;
                *scope = saved;
                scope.retain(|_, v| em.holds(v));
                Ok(())
            }
            _ => Err("adding this kind of statement isn't supported".into()),
        }
    }
}

impl Ctx<'_> {
    /// Emit an internal call (returning to a fresh label) or an
    /// external one; its results are left on the stack, bottom first.
    fn added_call(
        &self,
        em: &mut Emitter<'_>,
        e: &EExpr,
        names: &dyn Fn(&str) -> Option<Sym>,
    ) -> Res<Vec<Sym>> {
        if let Some((op, args)) = ext_call(e) {
            let args: Vec<Sym> = args
                .iter()
                .map(|x| lower_expr(x, names, self.opts).map_err(|e| e.0))
                .collect::<Res<_>>()?;
            for x in args.iter().rev() {
                em.value(x).map_err(|e| e.0)?;
            }
            let r = em.fresh_opaque();
            em.op(op, Some(r.clone())).map_err(|e| e.0)?;
            return Ok(vec![r]);
        }
        let EExpr::Call(name, args) = e else {
            return Err("not a call".into());
        };
        let (addr, info) = self.callee(name)?;
        if info.noreturn {
            return Err(format!("`{name}` never returns; it can't be called here"));
        }
        let nrets = info
            .nrets
            .ok_or_else(|| format!("`{name}`'s return-value count is unknown"))?;
        if args.len() != info.total_args() {
            return Err(format!("`{name}` takes {} argument(s)", info.total_args()));
        }
        let args: Vec<Sym> = args
            .iter()
            .map(|x| lower_expr(x, names, self.opts).map_err(|e| e.0))
            .collect::<Res<_>>()?;
        let ret = em.fresh_label();
        for x in &args[..info.nbelow] {
            em.value(x).map_err(|e| e.0)?;
        }
        em.push_label(ret, 2);
        for x in &args[info.nbelow..] {
            em.value(x).map_err(|e| e.0)?;
        }
        em.push_label(Target::Orig(addr), 2);
        em.op(JUMP, None).map_err(|e| e.0)?;
        em.place(ret);
        let results: Vec<Sym> = (0..nrets).map(|_| em.fresh_opaque()).collect();
        em.returned(info.total_args() + 1, &results)
            .map_err(|e| e.0)?;
        Ok(results)
    }
}

/// The expressions a halting statement's text uses.
fn halt_exprs(s: &Stmt) -> Vec<EExpr> {
    let texts: Vec<String> = match s {
        Stmt::Call { name, args, .. } if name == "revert" && args.len() == 1 => Vec::new(),
        Stmt::Call { args, .. } => args.clone(),
        Stmt::ReturnExpr { text, .. } => vec![text.clone()],
        _ => Vec::new(),
    };
    texts.iter().filter_map(|t| parse_expr(t).ok()).collect()
}

/// `PUSH d; PC; ADD` or `PC; PUSH d; ADD` around the `PC` at `p`, a
/// Vyper return address: `(first, end, target)` — instructions
/// `first..end` compute `target`, a `JUMPDEST`.
fn pc_return(
    insns: &[DecodedInsn],
    index: &HashMap<u64, usize>,
    p: usize,
) -> Option<(usize, usize, u64)> {
    let at = |k: usize| insns.get(k);
    let is_push = |k: usize| at(k).is_some_and(|i| (0x60..=0x7f).contains(&i.opcode));
    let is_add = |k: usize| at(k).is_some_and(|i| i.opcode == 0x01);
    let (first, push, end) = if p > 0 && is_push(p - 1) && is_add(p + 1) {
        (p - 1, p - 1, p + 2)
    } else if is_push(p + 1) && is_add(p + 2) {
        (p, p + 1, p + 3)
    } else {
        return None;
    };
    let target = insns[p].addr.0.checked_add(insns[push].push_value()?)?;
    let q = *index.get(&target)?;
    (at(q)?.opcode == JUMPDEST).then_some((first, end, target))
}

/// Bytes a patch's pieces take (labels at their widest).
fn pieces_len(pieces: &[Piece]) -> u64 {
    pieces
        .iter()
        .map(|p| match p {
            Piece::Bytes(b) | Piece::Data { bytes: b, .. } => b.len() as u64,
            Piece::Label(_) | Piece::Mark(_) => 0,
            Piece::Push { width, .. } => 1 + u64::from(*width),
        })
        .sum()
}

/// `PC` values move with the code. Vyper 0.2 only uses them for
/// return addresses, `PUSHn d; PC; ADD`, which stay right as long as
/// nothing between the `PC` and `PC + d` changes size; those an edit
/// does change are rewritten to push their target's label (returned
/// as `(first, end, target)`, see [`pc_return`]), and so are those a
/// rewrite shrinks in turn. Any other `PC` mustn't move.
fn pc_rewrites(ctx: &Ctx<'_>, patches: &[Patch]) -> Result<Vec<(usize, usize, u64)>, EvmEditError> {
    let orig_len = |from: usize, to: usize| -> u64 {
        ctx.insns[from..to]
            .iter()
            .map(|i| i.original_bytes.len() as u64)
            .sum()
    };
    let mut resized: Vec<(usize, usize)> = patches
        .iter()
        .filter(|p| pieces_len(&p.pieces) != orig_len(p.from, p.to))
        .map(|p| (p.from, p.to))
        .collect();
    let in_patch = |k: usize| patches.iter().any(|e| e.from <= k && k < e.to);
    // `(pc, first, end, target)`.
    let mut triples: Vec<(usize, usize, usize, u64)> = Vec::new();
    for (p, ins) in ctx
        .insns
        .iter()
        .enumerate()
        .filter(|(_, i)| i.opcode == 0x58)
    {
        if in_patch(p) {
            continue;
        }
        match pc_return(ctx.insns, &ctx.index, p) {
            Some((first, end, target)) if !(first..end).any(in_patch) => {
                triples.push((p, first, end, target));
            }
            Some(_) => {
                return Err(whole_file(format!(
                    "an edit splits the return address the `PC` at 0x{:x} computes",
                    ins.addr.0
                )));
            }
            None if resized.iter().any(|&(f, _)| f <= p) => {
                return Err(whole_file(format!(
                    "`PC` at 0x{:x} isn't a return address, and the edit moves it",
                    ins.addr.0
                )));
            }
            None => {}
        }
    }
    let mut out = Vec::new();
    let mut todo = triples;
    loop {
        let (hit, keep): (Vec<_>, Vec<_>) = todo.into_iter().partition(|&(p, _, _, target)| {
            let q = ctx.index[&target];
            resized
                .iter()
                .any(|&(from, to)| (from > p && from <= q) || (from < q && to > p))
        });
        todo = keep;
        if hit.is_empty() {
            break;
        }
        for (_, first, end, target) in hit {
            resized.push((first, end));
            out.push((first, end, target));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Deploying code: embedded contracts' lengths, immutables, CODESIZE
// ---------------------------------------------------------------------

/// A new value for a `PUSH` the layout writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixup {
    Const(u64),
    /// The size of the laid-out code.
    End,
    /// Where a data region now starts, by its original offset.
    Data(u64),
}

/// What [`deploy_fixups`] found.
#[derive(Debug, Default)]
struct DeployFixups {
    fixups: HashMap<usize, Fixup>,
    /// A `CODESIZE` used other than as `codesize() - n` with `n` the
    /// code's own size (constructor arguments appended after it).
    codesize: Option<u64>,
}

/// Offsets (from the contract's start) of the `PUSH32 0` placeholders
/// solc leaves for immutables in a runtime, by `PUSH32` offset.
fn immutable_slots(code: &[u8]) -> Vec<u64> {
    crate::arch::evm::decode_range(code, 0)
        .iter()
        .filter(|i| i.opcode == 0x7f && i.immediate().iter().all(|&b| b == 0))
        .filter(|i| !i.is_truncated())
        .map(|i| i.addr.0)
        .collect()
}

/// The constants deploying code needs changed when an embedded
/// contract it copies out changes: the length its `CODECOPY` copies
/// and the `RETURN` / `CREATE` that follow use, and the offsets of the
/// immutables it writes into the copy afterwards (`mstore(dest + off,
/// v)` in the same block). Also the `n` of `codesize() - n` — the
/// size of constructor arguments appended to the code, `n` its end or
/// the start of the data region holding them — which follows the move.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn deploy_fixups(
    insns: &[DecodedInsn],
    cfg: &Cfg,
    sections: &[SectionChange],
    size: u64,
    data_starts: &[u64],
) -> Result<DeployFixups, EvmEditError> {
    #[derive(Debug, Clone)]
    enum Val {
        Push(usize),
        /// A sum with these pushes among its operands.
        Plus(Vec<usize>),
        CodeSize,
    }
    let value = |i: usize| insns[i].push_value();
    let mut out = DeployFixups::default();
    // Old → new offset of each immutable's immediate, per section.
    let mut slots: Vec<HashMap<u64, u64>> = Vec::new();
    for s in sections {
        let mut m = HashMap::new();
        if let Some(moved) = &s.moved {
            for p in immutable_slots(&s.old) {
                let Some(&n) = moved.get(&p) else {
                    return Err(whole_file(format!(
                        "an immutable's placeholder at 0x{p:x} in the embedded contract at 0x{:x} was inside edited code",
                        s.addr
                    )));
                };
                m.insert(p + 1, n + 1);
            }
        }
        slots.push(m);
    }
    let resized = |s: &SectionChange| s.new.len() != s.old.len();
    let mut copied: Vec<bool> = vec![false; sections.len()];
    let fix = |out: &mut DeployFixups, i: usize, f: Fixup| -> Result<(), EvmEditError> {
        if out.fixups.insert(i, f).is_some_and(|g| g != f) {
            return Err(whole_file(format!(
                "the constant at 0x{:x} is used for two embedded contracts",
                insns[i].addr.0
            )));
        }
        Ok(())
    };
    for blk in &cfg.blocks {
        let mut st: Vec<Option<Val>> = Vec::new();
        // Sections this block copied out so far.
        let mut here: Vec<usize> = Vec::new();
        let pop = |st: &mut Vec<Option<Val>>| st.pop().flatten();
        let codesize_used = |out: &mut DeployFixups, v: &Option<Val>, at: usize| {
            if matches!(v, Some(Val::CodeSize)) && out.codesize.is_none() {
                out.codesize = Some(insns[at].addr.0);
            }
        };
        for i in blk.insns.clone() {
            let op = insns[i].opcode;
            match op {
                0x5f..=0x7f => st.push(Some(Val::Push(i))),
                0x38 => st.push(Some(Val::CodeSize)),
                0x80..=0x8f => {
                    let n = usize::from(op - 0x80) + 1;
                    let v = st.len().checked_sub(n).and_then(|k| st[k].clone());
                    st.push(v);
                }
                0x90..=0x9f => {
                    let n = usize::from(op - 0x90) + 1;
                    while st.len() <= n {
                        st.insert(0, None);
                    }
                    let len = st.len();
                    st.swap(len - 1, len - 1 - n);
                }
                0x50 => {
                    st.pop();
                }
                0x01 => {
                    let (a, b) = (pop(&mut st), pop(&mut st));
                    let mut v = Vec::new();
                    for x in [&a, &b] {
                        codesize_used(&mut out, x, i);
                        match x {
                            Some(Val::Push(j)) => v.push(*j),
                            Some(Val::Plus(js)) => v.extend(js),
                            _ => {}
                        }
                    }
                    st.push(Some(Val::Plus(v)));
                }
                0x03 => {
                    let (a, b) = (pop(&mut st), pop(&mut st));
                    match (&a, &b) {
                        // `codesize() - n`: the constructor arguments.
                        (Some(Val::CodeSize), Some(Val::Push(j)))
                            if value(*j) == Some(size)
                                || value(*j).is_some_and(|v| data_starts.contains(&v)) =>
                        {
                            let v = value(*j).unwrap_or_default();
                            let f = if v == size {
                                Fixup::End
                            } else {
                                Fixup::Data(v)
                            };
                            fix(&mut out, *j, f)?;
                        }
                        _ => {
                            codesize_used(&mut out, &a, i);
                            codesize_used(&mut out, &b, i);
                        }
                    }
                    st.push(None);
                }
                0x39 => {
                    let (dest, off, len) = (pop(&mut st), pop(&mut st), pop(&mut st));
                    for x in [&dest, &off, &len] {
                        codesize_used(&mut out, x, i);
                    }
                    let Some(Val::Push(o)) = off else { continue };
                    for (n, s) in sections.iter().enumerate() {
                        if value(o) != Some(s.addr) {
                            continue;
                        }
                        here.push(n);
                        copied[n] = true;
                        if !resized(s) {
                            continue;
                        }
                        match &len {
                            Some(Val::Push(z)) if value(*z) == Some(s.old.len() as u64) => {
                                fix(&mut out, *z, Fixup::Const(s.new.len() as u64))?;
                            }
                            _ => {
                                return Err(whole_file(format!(
                                    "the `CODECOPY` at 0x{:x} doesn't copy the embedded contract at 0x{:x} with a constant length, which its new size would change",
                                    insns[i].addr.0, s.addr
                                )));
                            }
                        }
                    }
                }
                // `RETURN` / `CREATE` / `CREATE2` of the copy.
                0xf3 | 0xf0 | 0xf5 => {
                    let info = &OPCODE_TABLE[op as usize];
                    let args: Vec<Option<Val>> = (0..info.pops).map(|_| pop(&mut st)).collect();
                    for x in &args {
                        codesize_used(&mut out, x, i);
                    }
                    let len = if op == 0xf3 { &args[1] } else { &args[2] };
                    if let Some(Val::Push(z)) = len {
                        for &n in &here {
                            let s = &sections[n];
                            if resized(s) && value(*z) == Some(s.old.len() as u64) {
                                fix(&mut out, *z, Fixup::Const(s.new.len() as u64))?;
                            }
                        }
                    }
                    if info.pushes == 1 {
                        st.push(None);
                    }
                }
                // Immutables written into the copy.
                MSTORE => {
                    let (off, v) = (pop(&mut st), pop(&mut st));
                    codesize_used(&mut out, &off, i);
                    codesize_used(&mut out, &v, i);
                    let cands = match off {
                        Some(Val::Push(j)) => vec![j],
                        Some(Val::Plus(js)) => js,
                        _ => Vec::new(),
                    };
                    for j in cands {
                        for &n in &here {
                            if let Some(&new) = value(j).and_then(|x| slots[n].get(&x)) {
                                fix(&mut out, j, Fixup::Const(new))?;
                            }
                        }
                    }
                }
                _ => {
                    let info = &OPCODE_TABLE[op as usize];
                    for _ in 0..info.pops {
                        let x = st.pop().flatten();
                        codesize_used(&mut out, &x, i);
                    }
                    for _ in 0..info.pushes {
                        st.push(None);
                    }
                }
            }
        }
        for x in &st {
            let at = blk.insns.end.saturating_sub(1);
            codesize_used(&mut out, x, at);
        }
    }
    if let Some(n) = (0..sections.len()).find(|&n| !copied[n] && sections[n].moved.is_some()) {
        return Err(whole_file(format!(
            "no constant `CODECOPY` deploys the embedded contract at 0x{:x}, whose code the edit moved",
            sections[n].addr
        )));
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------

/// Changes the layout makes besides the patches.
struct Adjust<'a> {
    /// See [`pc_rewrites`].
    pc_rewrites: &'a [(usize, usize, u64)],
    /// See [`deploy_fixups`].
    fixups: &'a HashMap<usize, Fixup>,
    sections: &'a [SectionChange],
}

/// Lay out the contract: the code and its patches, the data regions
/// (with changed embedded contracts' new bytes). Also returns where
/// each instruction kept as it was now starts.
#[allow(clippy::too_many_lines)]
fn layout(
    file: &UdFile,
    insns: &[DecodedInsn],
    reloc: &Reloc,
    patches: Vec<Patch>,
    adjust: &Adjust<'_>,
) -> Result<(Vec<u8>, HashMap<u64, u64>), EvmEditError> {
    let rewrites: HashMap<usize, (usize, u64)> = adjust
        .pc_rewrites
        .iter()
        .map(|&(first, end, target)| (first, (end, target)))
        .collect();
    let data_piece = |addr: u64, bytes: &[u8]| {
        let new = adjust.sections.iter().find(|s| s.addr == addr);
        Piece::Data {
            orig: addr,
            orig_len: bytes.len() as u64,
            bytes: new.map_or_else(|| bytes.to_vec(), |s| s.new.clone()),
        }
    };
    // Patches by start; check they don't overlap.
    let mut by_start: BTreeMap<usize, Vec<Patch>> = BTreeMap::new();
    for p in patches {
        by_start.entry(p.from).or_default().push(p);
    }
    let mut covered_to = 0usize;
    for (&from, ps) in &by_start {
        if from < covered_to {
            return Err(whole_file(
                "two edits touch the same instructions; edit fewer neighbouring statements at once",
            ));
        }
        for p in ps {
            covered_to = covered_to.max(p.to);
        }
    }

    let mut pieces: Vec<Piece> = Vec::new();
    let mut data: Vec<(u64, &[u8])> = file
        .items
        .iter()
        .filter_map(|it| match it {
            Item::Raw { addr, bytes } => Some((*addr, bytes.as_slice())),
            _ => None,
        })
        .collect();
    data.sort_by_key(|d| d.0);
    let mut data = data.into_iter().peekable();
    let mut k = 0;
    while k < insns.len() {
        let ins = &insns[k];
        while let Some((addr, bytes)) = data.next_if(|d| d.0 <= ins.addr.0) {
            pieces.push(data_piece(addr, bytes));
        }
        if let Some(ps) = by_start.remove(&k) {
            let mut next = k;
            // Insertions first, then a replacement.
            let (ins_ps, rep): (Vec<Patch>, Vec<Patch>) =
                ps.into_iter().partition(|p| p.to == p.from);
            for p in ins_ps {
                pieces.extend(p.pieces);
            }
            if let Some(p) = rep.into_iter().next() {
                pieces.extend(p.pieces);
                next = p.to;
            }
            if next != k {
                k = next;
                continue;
            }
        }
        if let Some(&(end, target)) = rewrites.get(&k) {
            // `PUSH d; PC; ADD` → `PUSH2 target`.
            pieces.push(Piece::Push {
                width: 2,
                target: Target::Orig(target),
                fixed: false,
            });
            k = end;
            continue;
        }
        pieces.push(Piece::Mark(ins.addr.0));
        if ins.opcode == JUMPDEST {
            pieces.push(Piece::Label(Target::Orig(ins.addr.0)));
        }
        let width = ins.info().imm_len;
        if let Some(fix) = adjust.fixups.get(&k) {
            match *fix {
                Fixup::End | Fixup::Data(_) => pieces.push(Piece::Push {
                    width,
                    target: match *fix {
                        Fixup::Data(v) => Target::Orig(v),
                        _ => Target::End,
                    },
                    fixed: false,
                }),
                Fixup::Const(v) => {
                    let w = usize::from(width);
                    if w < 8 && v >> (8 * w) != 0 {
                        return Err(whole_file(format!(
                            "the deploying code's constant 0x{v:x} no longer fits its PUSH{w}"
                        )));
                    }
                    let be = v.to_be_bytes();
                    let mut b = vec![ins.opcode];
                    b.extend((0..w).map(|i| (i + 8).checked_sub(w).map_or(0, |j| be[j])));
                    pieces.push(Piece::Bytes(b));
                }
            }
        } else if reloc.is_ref(k) && !ins.is_truncated() {
            pieces.push(Piece::Push {
                width: ins.info().imm_len,
                target: Target::Orig(ins.push_value().unwrap_or_default()),
                fixed: reloc.fixed.contains(&k),
            });
        } else {
            pieces.push(Piece::Bytes(ins.original_bytes.clone()));
        }
        k += 1;
    }
    // Insertions at the very end.
    for (_, ps) in by_start {
        for p in ps {
            pieces.extend(p.pieces);
        }
    }
    for (addr, bytes) in data {
        pieces.push(data_piece(addr, bytes));
    }
    resolve(&pieces)
}

/// Assign offsets and emit bytes; also returns where each
/// [`Piece::Mark`]ed instruction starts.
fn resolve(pieces: &[Piece]) -> Result<(Vec<u8>, HashMap<u64, u64>), EvmEditError> {
    let mut labels: HashMap<Target, u64> = HashMap::new();
    let mut marks: HashMap<u64, u64> = HashMap::new();
    // `(orig, new offset, orig len, new len)`.
    let mut spans: Vec<(u64, u64, u64, u64)> = Vec::new();
    let mut pc = 0u64;
    for p in pieces {
        match p {
            Piece::Bytes(b) => pc += b.len() as u64,
            Piece::Label(t) => {
                labels.insert(*t, pc);
            }
            Piece::Mark(a) => {
                marks.insert(*a, pc);
            }
            Piece::Push { width, .. } => pc += 1 + u64::from(*width),
            Piece::Data {
                orig,
                orig_len,
                bytes,
            } => {
                spans.push((*orig, pc, *orig_len, bytes.len() as u64));
                pc += bytes.len() as u64;
            }
        }
    }
    labels.insert(Target::End, pc);
    let find = |t: &Target| -> Option<u64> {
        if let Some(&v) = labels.get(t) {
            return Some(v);
        }
        let Target::Orig(x) = *t else { return None };
        // A region's start, then its end, then inside one that kept
        // its size.
        let start = spans.iter().find(|s| s.0 == x).map(|s| s.1);
        let end = || spans.iter().find(|s| s.0 + s.2 == x).map(|s| s.1 + s.3);
        let inside = || {
            spans
                .iter()
                .find(|s| x > s.0 && x < s.0 + s.2 && s.2 == s.3)
                .map(|s| s.1 + (x - s.0))
        };
        start.or_else(end).or_else(inside)
    };
    let mut out = Vec::with_capacity(pc as usize);
    for p in pieces {
        match p {
            Piece::Bytes(b) | Piece::Data { bytes: b, .. } => out.extend(b),
            Piece::Label(_) | Piece::Mark(_) => {}
            Piece::Push {
                width,
                target,
                fixed,
            } => {
                let v = find(target).ok_or_else(|| {
                    let mut s = String::from("a jump target ");
                    if let Target::Orig(x) = target {
                        let _ = write!(s, "(0x{x:x}) ");
                    }
                    s.push_str("was inside an edited statement's code");
                    whole_file(s)
                })?;
                if *fixed && *target != Target::Orig(v) {
                    return Err(whole_file(format!(
                        "the constant {target:?} is used both as a jump target and as a number, and the edit moves it"
                    )));
                }
                let w = usize::from(*width);
                if w < 8 && v >> (8 * w) != 0 {
                    return Err(whole_file(format!(
                        "offset 0x{v:x} no longer fits a PUSH{w}"
                    )));
                }
                out.push(0x5f + *width);
                let be = v.to_be_bytes();
                out.extend((0..w).map(|i| (i + 8).checked_sub(w).map_or(0, |j| be[j])));
            }
        }
    }
    Ok((out, marks))
}

#[cfg(test)]
mod tests {
    use crate::arch::evm::interp::{Call, Machine, Outcome, U256, calldata};
    use crate::translate::compile::{lower_to_evm, parse};
    use crate::translate::decompile::decompile_evm_to_text;

    fn weth() -> Vec<u8> {
        fixture("weth9-mainnet.evm")
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
        let code = std::fs::read(path).expect("read fixture");
        assert!(
            !code.starts_with(b"version https://git-lfs"),
            "{name} is an LFS pointer; run `git lfs pull`"
        );
        code
    }

    /// The one line holding pinned bytes starting with `bytes` (as
    /// printed, e.g. `"0x10, 0x15"`) and also containing `hint`.
    fn find_line(text: &str, bytes: &str, hint: &str) -> usize {
        let marker = format!(" [{bytes}");
        let hits: Vec<usize> = text
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains(&marker) && l.contains(hint))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "statement [{bytes}…] ~ `{hint}` not unique");
        hits[0]
    }

    /// Rewrite the text of that statement, keeping its bytes (and a
    /// block head's `{`).
    fn retext(text: &str, bytes: &str, hint: &str, new: &str) -> String {
        let n = find_line(text, bytes, hint);
        let marker = format!(" [{bytes}");
        text.lines()
            .enumerate()
            .map(|(i, line)| {
                if i == n {
                    let indent = line.len() - line.trim_start().len();
                    let at = line.find(&marker).expect("marker");
                    format!("{}{new}{}\n", &line[..indent], &line[at..])
                } else {
                    format!("{line}\n")
                }
            })
            .collect()
    }

    /// Insert `new` (statements without bytes) before that statement.
    fn insert_before(text: &str, bytes: &str, hint: &str, new: &str) -> String {
        let n = find_line(text, bytes, hint);
        let mut out = String::new();
        for (i, line) in text.lines().enumerate() {
            if i == n {
                let indent = &line[..line.len() - line.trim_start().len()];
                for l in new.lines() {
                    out.push_str(indent);
                    out.push_str(l);
                    out.push('\n');
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Comment that statement out, deleting it.
    fn comment_out(text: &str, bytes: &str, hint: &str) -> String {
        let n = find_line(text, bytes, hint);
        text.lines()
            .enumerate()
            .map(|(i, line)| {
                if i == n {
                    let indent = line.len() - line.trim_start().len();
                    format!("{}// {}\n", &line[..indent], line.trim_start())
                } else {
                    format!("{line}\n")
                }
            })
            .collect()
    }

    fn compile(text: &str) -> Result<Vec<u8>, String> {
        let ast = parse(text).map_err(|e| e.to_string())?;
        lower_to_evm(&ast).map_err(|e| e.to_string())
    }

    fn u(v: u64) -> U256 {
        U256::from_u64(v)
    }

    fn word(v: u64) -> Vec<u8> {
        u(v).to_be().to_vec()
    }

    const ALICE: u64 = 0xa11ce;
    const BOB: u64 = 0xb0b;

    fn send(m: &mut Machine, from: u64, value: u64, sig: &str, args: &[U256]) -> Outcome {
        m.run(&Call {
            caller: u(from),
            value: u(value),
            data: calldata(sig, args),
            address: u(0xeeee),
            balance: u(1_000_000),
        })
    }

    fn balance_of(m: &mut Machine, who: u64) -> U256 {
        match send(m, who, 0, "balanceOf(address)", &[u(who)]) {
            Outcome::Return(d) => U256::from_be(&d),
            other => panic!("balanceOf: {other:?}"),
        }
    }

    /// withdraw's `require(balance >= wad)`.
    const WITHDRAW_REQUIRE: &str = "0x10, 0x15, 0x15, 0x15, 0x61, 0x0a, 0x27";

    #[test]
    fn unedited_weth_is_untouched() {
        let code = weth();
        assert_eq!(compile(&decompile_evm_to_text(&code)).unwrap(), code);
    }

    #[test]
    fn edited_require_recompiles_and_runs() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // Make withdraw keep 100 wei behind.
        let edited = retext(
            &text,
            WITHDRAW_REQUIRE,
            "",
            "require((v3 >= (arg0 + 0x64)))",
        );
        let new = compile(&edited).unwrap();
        assert_ne!(new, code);
        let relifted = decompile_evm_to_text(&new);
        assert!(
            relifted.contains("require((v3 >= (arg0 + 0x64)))"),
            "{relifted}"
        );
        // The re-lifted edit compiles back to itself.
        assert_eq!(compile(&relifted).unwrap(), new);

        for (bin, edited) in [(&code, false), (&new, true)] {
            let mut m = Machine::new(bin);
            assert_eq!(send(&mut m, ALICE, 1000, "deposit()", &[]), Outcome::Stop);
            assert_eq!(balance_of(&mut m, ALICE), u(1000));
            let out = send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(950)]);
            assert_eq!(matches!(out, Outcome::Revert(_)), edited, "{out:?}");
            if edited {
                assert_eq!(
                    send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(900)]),
                    Outcome::Stop
                );
            }
            let sent = if edited { 900 } else { 950 };
            assert_eq!(m.calls.last(), Some(&(u(ALICE), u(sent))));
            assert_eq!(balance_of(&mut m, ALICE), u(1000 - sent));
            // The other entry points still work after relocation.
            assert_eq!(
                send(
                    &mut m,
                    ALICE,
                    0,
                    "transfer(address,uint256)",
                    &[u(BOB), u(10)]
                ),
                Outcome::Return(word(1))
            );
            assert_eq!(balance_of(&mut m, BOB), u(10));
            assert_eq!(
                send(
                    &mut m,
                    ALICE,
                    0,
                    "approve(address,uint256)",
                    &[u(BOB), u(5)]
                ),
                Outcome::Return(word(1))
            );
            assert_eq!(
                send(
                    &mut m,
                    BOB,
                    0,
                    "allowance(address,address)",
                    &[u(ALICE), u(BOB)]
                ),
                Outcome::Return(word(5))
            );
            assert_eq!(
                send(&mut m, BOB, 0, "decimals()", &[]),
                Outcome::Return(word(0))
            );
        }
    }

    #[test]
    fn edited_assignment_and_event() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // deposit credits twice the value and logs 42 as the amount.
        let edited = retext(
            &text,
            "0x01, 0x92, 0x50, 0x50, 0x81]",
            "msg.value",
            "v1 = v5 + (msg.value * 0x2)",
        );
        let edited = retext(
            &edited,
            "0x50, 0x33, 0x73",
            "Deposit",
            "emit(Deposit(address(msg.sender), 0x2a))",
        );
        let new = compile(&edited).unwrap();
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 7, "deposit()", &[]), Outcome::Stop);
        assert_eq!(balance_of(&mut m, ALICE), u(14));
        let (topics, data) = m.logs.last().expect("a log").clone();
        assert_eq!(topics.len(), 2);
        assert_eq!(topics[1], u(ALICE));
        assert_eq!(data, word(42));
    }

    #[test]
    fn edited_if_condition_and_internal_return() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // transferFrom skips the allowance check.
        let edited = retext(&text, "0x5b, 0x15, 0x61, 0x08, 0xcf, 0x57", "", "if (0x0)");
        // totalSupply's helper reports one wei more.
        let edited = retext(&edited, "0x90, 0x50, 0x90, 0x56]", "", "return v2 + 0x1;");
        let new = compile(&edited).unwrap();
        for (bin, open) in [(&code, false), (&new, true)] {
            let mut m = Machine::new(bin);
            send(&mut m, ALICE, 100, "deposit()", &[]);
            let out = send(
                &mut m,
                BOB,
                0,
                "transferFrom(address,address,uint256)",
                &[u(ALICE), u(BOB), u(30)],
            );
            assert_eq!(matches!(out, Outcome::Return(_)), open, "{out:?}");
            assert_eq!(balance_of(&mut m, BOB), u(if open { 30 } else { 0 }));
            let supply = 1_000_000 + u64::from(open);
            assert_eq!(
                send(&mut m, BOB, 0, "totalSupply()", &[]),
                Outcome::Return(word(supply))
            );
        }
    }

    /// Vyper 0.2's private returns load the spilled return address as
    /// part of `return v;`; an edited value still returns there.
    #[test]
    fn edited_vyper02_internal_return() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/curve-3pool-mainnet.evm"
        );
        let code = std::fs::read(path).expect("read 3pool fixture");
        let text = decompile_evm_to_text(&code);
        // `_A()` (every path), behind `A()`.
        let ret = "return mload(0x0); [0x60, 0x00, 0x51, 0x61, 0x01, 0x40, 0x51, 0x56]";
        assert_eq!(text.matches(ret).count(), 3, "{text}");
        let edited = text.replace(
            ret,
            "return mload(0x0) + 0x7; [0x60, 0x00, 0x51, 0x61, 0x01, 0x40, 0x51, 0x56]",
        );
        let new = compile(&edited).unwrap();
        assert_ne!(new, code);
        for (bin, extra) in [(&code, 0), (&new, 7)] {
            let mut m = Machine::new(bin);
            assert_eq!(
                send(&mut m, ALICE, 0, "A()", &[]),
                Outcome::Return(word(extra))
            );
        }
    }

    #[test]
    fn added_statements_compile() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // In transfer(), before the call into the internal helper.
        let edited = insert_before(
            &text,
            "0x5b, 0x61, 0x03, 0xb0",
            "",
            "require(param1 != 0x0, \"zero amount\")\nsstore(0x99, param1)\nif (param1 == 0x7) {\n    revert()\n}",
        );
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert!(relifted.contains("sstore(0x99, "), "{relifted}");
        let mut m = Machine::new(&new);
        send(&mut m, ALICE, 50, "deposit()", &[]);
        let out = send(
            &mut m,
            ALICE,
            0,
            "transfer(address,uint256)",
            &[u(BOB), u(0)],
        );
        let Outcome::Revert(data) = out else {
            panic!("{out:?}")
        };
        assert_eq!(&data[..4], &[0x08, 0xc3, 0x79, 0xa0]);
        assert_eq!(&data[0x44..0x44 + 11], b"zero amount");
        let out = send(
            &mut m,
            ALICE,
            0,
            "transfer(address,uint256)",
            &[u(BOB), u(7)],
        );
        assert_eq!(out, Outcome::Revert(Vec::new()));
        let out = send(
            &mut m,
            ALICE,
            0,
            "transfer(address,uint256)",
            &[u(BOB), u(5)],
        );
        assert_eq!(out, Outcome::Return(word(1)));
        assert_eq!(m.storage.get(&u(0x99)), Some(&u(5)));
        assert_eq!(balance_of(&mut m, BOB), u(5));
    }

    #[test]
    fn storage_variables_by_name() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // approve() grants one more than asked.
        let edited = retext(
            &text,
            "",
            "allowance[address(msg.sender)][address(arg0)] = arg1",
            "allowance[address(msg.sender)][address(arg0)] = arg1 + 0x1",
        );
        // deposit() starts from 42.
        let edited = insert_before(
            &edited,
            "0x5b, 0x61, 0x03, 0xd2",
            "",
            "balanceOf[address(msg.sender)] = 0x2a",
        );
        let new = compile(&edited).unwrap();
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 7, "deposit()", &[]), Outcome::Stop);
        assert_eq!(balance_of(&mut m, ALICE), u(49));
        send(
            &mut m,
            ALICE,
            0,
            "approve(address,uint256)",
            &[u(BOB), u(5)],
        );
        assert_eq!(
            send(
                &mut m,
                BOB,
                0,
                "allowance(address,address)",
                &[u(ALICE), u(BOB)]
            ),
            Outcome::Return(word(6))
        );
        let relifted = decompile_evm_to_text(&new);
        assert!(
            relifted.contains("balanceOf[address(msg.sender)] = 0x2a"),
            "{relifted}"
        );
    }

    /// Edits inside the runtime a constructor deploys compile with that
    /// runtime, as long as its size (which the constructor copies) holds.
    #[test]
    fn edits_inside_embedded_runtime() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/initcode-immutable-mainnet.evm"
        );
        let code = std::fs::read(path).expect("fixture");
        let text = decompile_evm_to_text(&code);
        assert!(text.contains("@section(\"runtime\""), "{text}");
        let same = retext(
            &text,
            "0x60, 0x80, 0x60, 0x40, 0x52",
            "mstore(0x40, 0x80)",
            "mstore(0x40, 0x90)",
        );
        let new = compile(&same).unwrap();
        assert_eq!(new.len(), code.len());
        let diff: Vec<usize> = (0..code.len()).filter(|&i| new[i] != code[i]).collect();
        assert_eq!(diff.len(), 1, "{diff:?}");
        assert!(decompile_evm_to_text(&new).contains("mstore(0x40, 0x90)"));
        let grown = retext(
            &text,
            "0x60, 0x80, 0x60, 0x40, 0x52",
            "mstore(0x40, 0x80)",
            "mstore(0x40, (0x80 + msg.value))",
        );
        let new = compile(&grown).unwrap();
        assert_eq!(new.len(), code.len() + 2);
        assert!(decompile_evm_to_text(&new).contains("mstore(0x40, (0x80 + msg.value))"));
    }

    /// The runtime deployed by running `initcode` from ALICE.
    fn deploy(initcode: &[u8]) -> Vec<u8> {
        let mut m = Machine::new(initcode);
        match send(&mut m, ALICE, 0, "", &[]) {
            Outcome::Return(runtime) => runtime,
            other => panic!("deploy: {other:?}"),
        }
    }

    /// Growing the runtime a constructor deploys: the deploying code's
    /// copy length, returned size, immutables' offsets and constructor
    /// arguments' offset follow.
    #[test]
    fn resized_embedded_runtime() {
        for name in [
            "initcode-immutable-mainnet.evm",
            "initcode-ctor-args-mainnet.evm",
        ] {
            let code = fixture(name);
            let text = decompile_evm_to_text(&code);
            let at = text.find("@section(\"runtime\"").expect("runtime");
            let body = at + text[at..].find("fn entry() {\n").expect("entry") + 13;
            let edited = format!(
                "{}        sstore(0xdead, 0x1)\n{}",
                &text[..body],
                &text[body..]
            );
            let new = compile(&edited).unwrap();
            assert!(new.len() > code.len(), "{name}");
            let (old_rt, new_rt) = (deploy(&code), deploy(&new));
            assert_eq!(new_rt.len(), old_rt.len() + 6, "{name}");
            // The immutables were written into the moved placeholders:
            // the deployed code reads the same, plus the store.
            let (old_t, new_t) = (
                decompile_evm_to_text(&old_rt),
                decompile_evm_to_text(&new_rt),
            );
            assert!(new_t.contains("sstore(0xdead, 0x1)"), "{name}");
            let words = |rt: &[u8]| -> Vec<Vec<u8>> {
                crate::arch::evm::decode_range(rt, 0)
                    .iter()
                    .filter(|i| i.opcode == 0x7f)
                    .map(|i| i.immediate().to_vec())
                    .collect()
            };
            assert_eq!(words(&old_rt), words(&new_rt), "{name}");
            assert!(
                words(&new_rt)
                    .iter()
                    .all(|w| w.iter().any(|&b| b != 0) || words(&code).is_empty()),
                "{name}: an immutable placeholder was left unwritten"
            );
            let (old_s, new_s) = (shape(&old_t), shape(&new_t));
            assert_eq!(old_s.len() + 1, new_s.len(), "{name}");
        }
    }

    /// Replace every `0x…` number, `L_xxxx` / `sub_xxxx` label and byte
    /// list with a placeholder, so lifted texts compare by structure.
    /// Comments are dropped (caller lists aren't ordered).
    fn shape(text: &str) -> Vec<String> {
        text.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| {
                let b = line.as_bytes();
                let mut out = String::new();
                let mut i = 0;
                while i < b.len() {
                    let rest = &line[i..];
                    if rest.starts_with("0x") {
                        i += 2;
                        while i < b.len() && b[i].is_ascii_hexdigit() {
                            i += 1;
                        }
                        out.push('N');
                    } else if rest.starts_with("L_") || rest.starts_with("sub_") {
                        i += rest.find('_').expect("prefix") + 1;
                        while i < b.len() && b[i].is_ascii_hexdigit() {
                            i += 1;
                        }
                        // A constant that equalled a code offset reads as a
                        // label; after relocation it may not.
                        out.push('N');
                    } else if rest.starts_with("[0x") || rest.starts_with("[]") {
                        i += rest.find(']').expect("closed byte list") + 1;
                    } else {
                        let c = rest.chars().next().expect("in bounds");
                        out.push(c);
                        i += c.len_utf8();
                    }
                }
                // A label plus an offset folds once it is a number.
                while out.contains("N + N") || out.contains("(N)") {
                    out = out.replace("N + N", "N").replace("(N)", "N");
                }
                out
            })
            .collect()
    }

    /// Growing the entry code moves every other function: after
    /// relocation each fixture still lifts to the same program.
    #[test]
    fn relocation_preserves_every_fixture() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .expect("testdata")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "evm"))
            .collect();
        paths.sort();
        assert!(!paths.is_empty());
        for path in paths {
            let code = std::fs::read(&path).expect("fixture");
            let text = decompile_evm_to_text(&code);
            // EIP-1167 clones have no lifted body to grow.
            let Some(at) = text.find("fn entry() {\n") else {
                continue;
            };
            let at = at + "fn entry() {\n".len();
            let edited = format!("{}    sstore(0xdead, 0x1)\n{}", &text[..at], &text[at..]);
            let new = match compile(&edited) {
                Ok(new) => new,
                Err(e) => panic!("{}: {e}", path.display()),
            };
            assert!(new.len() > code.len());
            let (old, new) = (shape(&text), shape(&decompile_evm_to_text(&new)));
            let first = old.iter().zip(&new).position(|(a, b)| a != b);
            let first = first.unwrap_or(old.len());
            assert_eq!(new[first].trim(), "sstore(N, N)", "{}", path.display());
            if let Some(d) = old[first..]
                .iter()
                .zip(&new[first + 1..])
                .position(|(a, b)| a != b)
            {
                let d = first + d;
                panic!("{}: `{}` became `{}`", path.display(), old[d], new[d + 1]);
            }
            assert_eq!(old.len() + 1, new.len(), "{}", path.display());
        }
    }

    /// Calls with their ABI encoding folded in lower unedited, and an
    /// edit to one is rejected naming the statement.
    #[test]
    fn folded_external_calls_reject_edits() {
        let code = fixture("uniswap-v2-router02-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        assert_eq!(compile(&text).unwrap(), code);
        let line = text
            .lines()
            .find(|l| l.contains(" = IWETH(") && l.contains(").withdraw("))
            .expect("folded withdraw call");
        let edited = text.replacen(
            line,
            &line.replacen(").withdraw(", ").withdraw(0x1 + ", 1),
            1,
        );
        let e = compile(&edited).expect_err("edit should be rejected");
        assert!(e.contains("external calls") && e.contains("IWETH("), "{e}");
    }

    #[test]
    fn unsupported_edits_fail_clearly() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        let err = |t: &str| compile(t).expect_err("edit should be rejected");
        // Internal calls with the wrong arguments, or to no function.
        let e = err(&retext(
            &text,
            "0x5b, 0x61, 0x02, 0x64",
            "",
            "sub_09d9(0x1, 0x2)",
        ));
        assert!(e.contains("takes 1 argument"), "{e}");
        let e = err(&retext(
            &text,
            "0x5b, 0x61, 0x02, 0x64",
            "",
            "sub_09da(0x1)",
        ));
        assert!(e.contains("isn't an internal function"), "{e}");
        // A call whose results aren't all assigned.
        let e = err(&retext(&text, "0x5b, 0x61, 0x02, 0x64", "", "sub_066d()"));
        assert!(e.contains("0 target(s) but 1 value(s)"), "{e}");
        // An internal call inside an expression.
        let e = err(&retext(
            &text,
            WITHDRAW_REQUIRE,
            "",
            "require((v3 >= sub_066d()))",
        ));
        assert!(e.contains("can't be compiled"), "{e}");
        // A name that isn't on the stack.
        let e = err(&retext(
            &text,
            WITHDRAW_REQUIRE,
            "",
            "require((v3 >= nosuch))",
        ));
        assert!(e.contains("`nosuch`"), "{e}");
        // A statement removed outright, rather than commented out.
        let n = find_line(&text, WITHDRAW_REQUIRE, "");
        let gone: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != n)
            .map(|(_, l)| l)
            .collect();
        let gone = gone.join("\n");
        let e = err(&gone);
        assert!(e.contains("comment"), "{e}");
        // Deleting an assignment whose variable is still read.
        let e = err(&comment_out(&text, "0x03, 0x92, 0x50, 0x50, 0x81]", "arg0"));
        assert!(e.contains("`v2` has no value"), "{e}");
        // Renaming to a variable that isn't on the stack.
        let e = err(&retext(
            &text,
            "0x03, 0x92, 0x50, 0x50, 0x81]",
            "arg0",
            "nosuch = v6 - arg0",
        ));
        assert!(e.contains("`nosuch`"), "{e}");
    }

    #[test]
    fn deleted_statements_compile() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // withdraw() without its balance check, and deposit() without
        // its event.
        let edited = comment_out(&text, WITHDRAW_REQUIRE, "");
        let edited = comment_out(&edited, "0x50, 0x33, 0x73", "Deposit");
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert!(!relifted.contains("require((v3 >= arg0))"), "{relifted}");
        assert!(!relifted.contains("emit(Deposit"), "{relifted}");
        assert_eq!(compile(&relifted).unwrap(), new);
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 1000, "deposit()", &[]), Outcome::Stop);
        assert!(m.logs.is_empty());
        assert_eq!(balance_of(&mut m, ALICE), u(1000));
        assert_eq!(
            send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(1500)]),
            Outcome::Stop
        );
        assert_eq!(m.calls.last(), Some(&(u(ALICE), u(1500))));
        assert_eq!(
            balance_of(&mut m, ALICE),
            U256([!499, u64::MAX, u64::MAX, u64::MAX])
        );

        // withdraw() that doesn't debit: its `sstore` deleted.
        let edited = comment_out(&text, "0x90, 0x55]", "sstore(v3, v2)");
        let new = compile(&edited).unwrap();
        let mut m = Machine::new(&new);
        send(&mut m, ALICE, 1000, "deposit()", &[]);
        assert_eq!(
            send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(400)]),
            Outcome::Stop
        );
        assert_eq!(m.calls.last(), Some(&(u(ALICE), u(400))));
        assert_eq!(balance_of(&mut m, ALICE), u(1000));
        let out = send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(1001)]);
        assert!(matches!(out, Outcome::Revert(_)), "{out:?}");
    }

    /// The router's `quote()` without its non-zero-amount check.
    #[test]
    fn deleted_require_in_router() {
        let code = fixture("uniswap-v2-router02-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        let edited = comment_out(&text, "0x57, 0x60, 0x40", "INSUFFICIENT_AMOUNT\")");
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert!(!relifted.contains("INSUFFICIENT_AMOUNT\")"), "{relifted}");
        let quote = "quote(uint256,uint256,uint256)";
        for (bin, edited) in [(&code, false), (&new, true)] {
            let mut m = Machine::new(bin);
            let out = send(&mut m, ALICE, 0, quote, &[u(0), u(5), u(7)]);
            if edited {
                assert_eq!(out, Outcome::Return(word(0)));
            } else {
                assert!(matches!(out, Outcome::Revert(_)), "{out:?}");
            }
            let out = send(&mut m, ALICE, 0, quote, &[u(10), u(5), u(7)]);
            assert_eq!(out, Outcome::Return(word(14)));
            let out = send(&mut m, ALICE, 0, quote, &[u(10), u(0), u(7)]);
            assert!(matches!(out, Outcome::Revert(_)), "{out:?}");
        }
    }

    #[test]
    fn edited_and_added_calls() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // withdraw() takes half and pays it to BOB; deposit() credits
        // twice; transfer() pulls from `param0` to the caller instead.
        let edited = retext(
            &text,
            "0x5b, 0x61, 0x02, 0x64",
            "",
            "sub_09d9(param0 / 0x2)",
        );
        let edited = retext(&edited, "0xf1]", "send", "v6 = send(0xb0b, arg0)");
        let edited = insert_before(&edited, "0x5b, 0x61, 0x03, 0xd2", "", "sub_0440()");
        let edited = retext(
            &edited,
            "0x5b, 0x61, 0x03, 0xb0",
            "",
            "v1 = sub_068c(address(param0), msg.sender, param1)",
        );
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert!(relifted.contains("0xb0b.send(arg0)") || relifted.contains("send(0xb0b, arg0)"));
        assert!(relifted.contains("(param0 / 0x2))"), "{relifted}");
        assert_eq!(compile(&relifted).unwrap(), new);
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 1000, "deposit()", &[]), Outcome::Stop);
        assert_eq!(m.logs.len(), 2);
        assert_eq!(balance_of(&mut m, ALICE), u(2000));
        assert_eq!(
            send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(600)]),
            Outcome::Stop
        );
        assert_eq!(m.calls.last(), Some(&(u(BOB), u(300))));
        assert_eq!(balance_of(&mut m, ALICE), u(1700));
        send(
            &mut m,
            ALICE,
            0,
            "approve(address,uint256)",
            &[u(BOB), u(50)],
        );
        let out = send(
            &mut m,
            BOB,
            0,
            "transfer(address,uint256)",
            &[u(ALICE), u(30)],
        );
        assert_eq!(out, Outcome::Return(word(1)));
        assert_eq!(balance_of(&mut m, BOB), u(30));
        assert_eq!(balance_of(&mut m, ALICE), u(1670));
        let out = send(
            &mut m,
            BOB,
            0,
            "allowance(address,address)",
            &[u(ALICE), u(BOB)],
        );
        assert_eq!(out, Outcome::Return(word(20)));
        let out = send(
            &mut m,
            BOB,
            0,
            "transfer(address,uint256)",
            &[u(ALICE), u(30)],
        );
        assert!(matches!(out, Outcome::Revert(_)), "{out:?}");

        // deposit() without its call.
        let edited = comment_out(&text, "0x5b, 0x61, 0x03, 0xd2", "sub_0440()");
        let new = compile(&edited).unwrap();
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 1000, "deposit()", &[]), Outcome::Stop);
        assert!(m.logs.is_empty());
        assert_eq!(balance_of(&mut m, ALICE), u(0));
    }

    /// The router's `removeLiquidityETH` helper unwraps WETH with a raw
    /// `call(…)`: its arguments and kind are editable.
    #[test]
    fn edited_raw_external_call() {
        let code = fixture("uniswap-v2-router02-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        // `pair.swap(…, data)`: dynamic arguments keep the raw form.
        let call = "v15 = call(gasleft(), v12, 0x0, v16, v20 - v16, v16, 0x0)";
        let edited = in_fn(&text, "sub_4381", |t| {
            retext(
                t,
                "0x5b, 0x50, 0x5a, 0xf1]",
                call,
                "v15 = call(gasleft(), v12, 0x7, v16, v20 - v16, v16, 0x20)",
            )
        });
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert!(
            relifted.contains("call(gasleft(), v12, 0x7, v16, v20 - v16, v16, 0x20)"),
            "{relifted}"
        );
        assert_eq!(compile(&relifted).unwrap(), new);
        let edited = in_fn(&text, "sub_4381", |t| {
            retext(
                t,
                "0x5b, 0x50, 0x5a, 0xf1]",
                call,
                "v15 = staticcall(gasleft(), v12, v16, v20 - v16, v16, 0x0)",
            )
        });
        let relifted = decompile_evm_to_text(&compile(&edited).unwrap());
        assert!(
            relifted.contains("staticcall(gasleft(), v12, v16, v20 - v16, v16, 0x0)"),
            "{relifted}"
        );
    }

    /// `f` applied to the text of function `name` alone.
    fn in_fn(text: &str, name: &str, f: impl Fn(&str) -> String) -> String {
        let start = text.find(&format!("fn {name}() {{")).expect("function");
        let end = start + text[start..].find("\n}\n").expect("end") + 3;
        format!("{}{}{}", &text[..start], f(&text[start..end]), &text[end..])
    }

    /// Deleting a folded external call is refused too.
    #[test]
    fn folded_external_calls_refuse_deletion() {
        let code = fixture("uniswap-v2-router02-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        let line = text
            .lines()
            .find(|l| l.contains(" = IWETH(") && l.contains(").withdraw("))
            .expect("folded withdraw call");
        let gone = format!("    // {}", line.trim_start());
        let e = compile(&text.replacen(line, &gone, 1)).expect_err("deletion should be rejected");
        assert!(
            e.contains("deleting external calls") && e.contains("IWETH("),
            "{e}"
        );
    }

    #[test]
    fn edited_clone_target() {
        let code = fixture("eip1167-clone-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        let start = text.find("return delegatecall(").expect("clone") + 20;
        let end = start + text[start..].find(',').expect("address");
        let other = "0x1111111111111111111111111111111111111111";
        let edited = format!("{}{other}{}", &text[..start], &text[end..]);
        let new = compile(&edited).unwrap();
        assert_eq!(new.len(), code.len());
        let proxy = crate::format::evm::minimal_proxy(&new).expect("still a clone");
        assert_eq!(proxy.target, [0x11; 20]);
        let e = compile(&edited.replace("msg.data", "0x0")).expect_err("not a forward");
        assert!(e.contains("msg.data"), "{e}");
    }

    /// Vyper calls push their return address as `PC + d`; an edited or
    /// added call pushes the label instead.
    #[test]
    fn vyper_calls() {
        let code = fixture("curve-3pool-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        let call = "0x5b, 0x60, 0x06, 0x58, 0x01, 0x61, 0x00, 0xa9, 0x56";
        let mut m = Machine::new(&code);
        let a = send(&mut m, ALICE, 0, "A()", &[]);
        let Outcome::Return(a) = a else {
            panic!("{a:?}")
        };
        // A() calls its helper twice, then returns 7 more.
        let edited = in_fn(&text, "A", |t| {
            insert_before(
                t,
                "0x5b, 0x61, 0x01, 0x40, 0x52",
                "",
                "v0 = sub_00a9()\nv0 = v0 + 0x7",
            )
        });
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert_eq!(compile(&relifted).unwrap(), new);
        let mut m = Machine::new(&new);
        let want = U256::from_be(&a).add(u(7)).to_be().to_vec();
        assert_eq!(send(&mut m, ALICE, 0, "A()", &[]), Outcome::Return(want));
        // A() without the call, returning a constant.
        let edited = in_fn(&text, "A", |t| comment_out(t, call, "v0 = sub_00a9()"));
        let edited = in_fn(&edited, "A", |t| {
            retext(t, "0x5b, 0x61, 0x01, 0x40, 0x52", "", "mstore(0x140, 0x7)")
        });
        let new = compile(&edited).unwrap();
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 0, "A()", &[]), Outcome::Return(word(7)));
    }

    /// Vyper: the 3pool's `A()` made payable.
    #[test]
    fn deleted_require_in_vyper() {
        let code = fixture("curve-3pool-mainnet.evm");
        let text = decompile_evm_to_text(&code);
        let edited = comment_out(&text, "0x34, 0x15, 0x61, 0x02, 0x5d", "require(!msg.value)");
        let new = compile(&edited).unwrap();
        assert!(new.len() < code.len());
        let mut m = Machine::new(&code);
        let free = send(&mut m, ALICE, 0, "A()", &[]);
        assert!(matches!(free, Outcome::Return(_)), "{free:?}");
        let paid = send(&mut m, ALICE, 1, "A()", &[]);
        assert!(matches!(paid, Outcome::Revert(_)), "{paid:?}");
        let mut m = Machine::new(&new);
        assert_eq!(send(&mut m, ALICE, 0, "A()", &[]), free);
        assert_eq!(send(&mut m, ALICE, 1, "A()", &[]), free);
    }

    #[test]
    fn renamed_assignment_targets() {
        let code = weth();
        let text = decompile_evm_to_text(&code);
        // approve() records the allowance the other way round.
        let edited = retext(
            &text,
            "",
            "allowance[address(msg.sender)][address(arg0)] = arg1",
            "allowance[address(arg0)][address(msg.sender)] = arg1",
        );
        // withdraw() writes what remains to BOB's balance instead of
        // the caller's: the assignment to `v2` becomes a store, and the
        // `sstore` of `v2` goes.
        let edited = retext(
            &edited,
            "0x03, 0x92, 0x50, 0x50, 0x81]",
            "arg0",
            "balanceOf[address(0xb0b)] = v6 - arg0",
        );
        let edited = comment_out(&edited, "0x90, 0x55]", "sstore(v3, v2)");
        let new = compile(&edited).unwrap();
        let relifted = decompile_evm_to_text(&new);
        assert!(
            relifted.contains("allowance[address(arg0)][address(msg.sender)] = arg1"),
            "{relifted}"
        );
        assert_eq!(compile(&relifted).unwrap(), new);
        let mut m = Machine::new(&new);
        send(&mut m, ALICE, 1000, "deposit()", &[]);
        send(
            &mut m,
            ALICE,
            0,
            "approve(address,uint256)",
            &[u(BOB), u(5)],
        );
        let allowance = |m: &mut Machine, a: u64, b: u64| {
            send(m, a, 0, "allowance(address,address)", &[u(a), u(b)])
        };
        assert_eq!(allowance(&mut m, BOB, ALICE), Outcome::Return(word(5)));
        assert_eq!(allowance(&mut m, ALICE, BOB), Outcome::Return(word(0)));
        assert_eq!(
            send(&mut m, ALICE, 0, "withdraw(uint256)", &[u(300)]),
            Outcome::Stop
        );
        assert_eq!(balance_of(&mut m, ALICE), u(1000));
        assert_eq!(balance_of(&mut m, BOB), u(700));
    }
}

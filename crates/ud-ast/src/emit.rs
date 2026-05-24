//! Canonical pretty-printer.
//!
//! The output is the source of truth for what `.ud` looks like. Any
//! valid AST emits in exactly one canonical shape; the parser will
//! accept that shape (and a handful of trivial whitespace variations)
//! and reproduce it on re-emit. So `emit(parse(canonical)) == canonical`
//! is a hard invariant the test suite defends.
//!
//! Indentation: 4 spaces per level. Top-level blocks have a blank line
//! between them.

use std::fmt::Write as _;

use crate::types::{
    AttrValue, Attribute, Field, FnDecl, Item, Module, Param, Signature, Stmt, Type, UdFile, Value,
};

/// Format an entire AST as canonical `.ud` text. Trailing newline is
/// included; the file always ends in `\n`.
#[must_use]
pub fn emit(file: &UdFile) -> String {
    let mut out = String::new();
    emit_module(&mut out, &file.module);
    for item in &file.items {
        out.push('\n');
        emit_item(&mut out, item);
    }
    out
}

fn emit_module(out: &mut String, module: &Module) {
    writeln!(out, "@module {{").unwrap();
    for f in &module.fields {
        emit_field(out, f, 1);
    }
    writeln!(out, "}}").unwrap();
}

fn emit_item(out: &mut String, item: &Item) {
    emit_item_indented(out, item, 0);
}

fn emit_item_indented(out: &mut String, item: &Item, depth: usize) {
    let indent = " ".repeat(depth * 4);
    match item {
        Item::Comment(text) => writeln!(out, "{indent}// {text}").unwrap(),
        Item::Function(f) => emit_fn_indented(out, f, depth),
        Item::Raw { addr, bytes } => emit_raw(out, *addr, bytes, depth),
        Item::Strings { addr, strings } => emit_strings(out, *addr, strings, depth),
        Item::Notes { addr, entries } => emit_notes(out, *addr, entries, depth),
        Item::Section { name, addr, items } => emit_section(out, name, *addr, items, depth),
        Item::JumpTable {
            addr,
            dispatch,
            entries,
        } => emit_jump_table(out, *addr, dispatch, entries, depth),
    }
}

fn emit_raw(out: &mut String, addr: u64, bytes: &[u8], depth: usize) {
    let indent = " ".repeat(depth * 4);
    write!(out, "{indent}@raw(0x{addr:x}, [").unwrap();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write!(out, "0x{b:02x}").unwrap();
    }
    writeln!(out, "])").unwrap();
}

fn emit_strings(out: &mut String, addr: u64, strings: &[String], depth: usize) {
    let indent = " ".repeat(depth * 4);
    let inner = " ".repeat((depth + 1) * 4);
    writeln!(out, "{indent}@strings(0x{addr:x}, [").unwrap();
    for s in strings {
        write!(out, "{inner}").unwrap();
        out.push_str(&quote_string(s));
        out.push_str(",\n");
    }
    writeln!(out, "{indent}])").unwrap();
}

fn emit_jump_table(
    out: &mut String,
    addr: u64,
    dispatch: &str,
    entries: &[crate::JumpTableEntry],
    depth: usize,
) {
    let indent = " ".repeat(depth * 4);
    let inner = " ".repeat((depth + 1) * 4);
    writeln!(
        out,
        "{indent}@jump_table(0x{addr:x}, dispatch={}) {{",
        quote_string(dispatch)
    )
    .unwrap();
    for e in entries {
        writeln!(out, "{inner}case_{}: label_{:x},", e.case, e.target).unwrap();
    }
    writeln!(out, "{indent}}}").unwrap();
}

fn emit_notes(out: &mut String, addr: u64, entries: &[crate::NoteEntry], depth: usize) {
    let indent = " ".repeat(depth * 4);
    let inner = " ".repeat((depth + 1) * 4);
    let kv = " ".repeat((depth + 2) * 4);
    writeln!(out, "{indent}@notes(0x{addr:x}, [").unwrap();
    for e in entries {
        writeln!(out, "{inner}{{").unwrap();
        writeln!(out, "{kv}type: 0x{:x},", e.note_type).unwrap();
        write!(out, "{kv}name: ").unwrap();
        out.push_str(&quote_string(&e.name));
        out.push_str(",\n");
        write!(out, "{kv}desc: [").unwrap();
        for (i, b) in e.desc.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            write!(out, "0x{b:02x}").unwrap();
        }
        out.push_str("],\n");
        writeln!(out, "{inner}}},").unwrap();
    }
    writeln!(out, "{indent}])").unwrap();
}

fn emit_section(out: &mut String, name: &str, addr: u64, items: &[Item], depth: usize) {
    let indent = " ".repeat(depth * 4);
    writeln!(
        out,
        "{indent}@section({}, 0x{addr:x}) {{",
        quote_string(name)
    )
    .unwrap();
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_item_indented(out, item, depth + 1);
    }
    writeln!(out, "{indent}}}").unwrap();
}

fn emit_fn_indented(out: &mut String, f: &FnDecl, depth: usize) {
    let indent = " ".repeat(depth * 4);
    let body_indent = " ".repeat((depth + 1) * 4);
    if let Some(addr) = f.addr {
        writeln!(out, "{indent}@addr(0x{addr:x})").unwrap();
    }
    write!(out, "{indent}fn {}(", f.name).unwrap();
    if let Some(sig) = &f.signature {
        emit_params(out, &sig.params);
    }
    write!(out, ")").unwrap();
    if let Some(sig) = &f.signature {
        if !matches!(sig.return_type, Type::Void) {
            write!(out, " -> ").unwrap();
            emit_type(out, &sig.return_type);
        }
    }
    if !f.attrs.is_empty() {
        let before = out.len();
        // Function-level attrs have no omission rules yet.
        out.push(' ');
        emit_attrs(out, &f.attrs, |_| false);
        if out.len() == before + 1 {
            // The placeholder space we pushed wasn't needed —
            // emit_attrs filtered everything out.
            out.pop();
        }
    }
    writeln!(out, " {{").unwrap();
    if !f.locals.is_empty() {
        emit_locals(out, &f.locals, &body_indent);
        // Blank line between the declarations and the body so the
        // function reads as "vars; then code" rather than running
        // them together.
        if !f.body.is_empty() {
            out.push('\n');
        }
    }
    emit_stmts(out, &f.body, &body_indent);
    writeln!(out, "{indent}}}").unwrap();
}

/// Render the `let name: ty;` declarations at the head of a function.
///
/// Stack-backed locals get one `let name: ty;` line each — they're
/// the function's variables. Register-backed locals are coalesced
/// onto a single trailing `let ebp: u64, esp: u64, …: @reg;` line so
/// they don't dominate the function visually; they're metadata
/// (`@reg`-kind types per register the body touches), and the
/// reader rarely cares about the per-register sizes individually.
fn emit_locals(out: &mut String, locals: &[crate::types::LocalDecl], indent: &str) {
    use crate::types::LocalKind;
    for l in locals {
        if matches!(l.kind, LocalKind::Stack) {
            write!(out, "{indent}let {}: ", l.name).unwrap();
            emit_type(out, &l.ty);
            writeln!(out, ";").unwrap();
        }
    }
    let regs: Vec<&crate::types::LocalDecl> = locals
        .iter()
        .filter(|l| matches!(l.kind, LocalKind::Register))
        .collect();
    if regs.is_empty() {
        return;
    }
    write!(out, "{indent}let ").unwrap();
    for (i, l) in regs.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write!(out, "{}: ", l.name).unwrap();
        emit_type(out, &l.ty);
    }
    writeln!(out, " @reg;").unwrap();
}

fn emit_stmts(out: &mut String, stmts: &[Stmt], indent: &str) {
    for stmt in stmts {
        emit_stmt(out, stmt, indent);
    }
}

#[allow(clippy::too_many_lines)]
fn emit_stmt(out: &mut String, stmt: &Stmt, indent: &str) {
    match stmt {
        Stmt::Asm { text, bytes } if bytes.is_empty() => {
            writeln!(out, "{indent}@asm({})", quote_string(text)).unwrap();
        }
        Stmt::Asm { text, bytes } => {
            write!(out, "{indent}@asm({}, [", quote_string(text)).unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::Comment(text) => {
            writeln!(out, "{indent}// {text}").unwrap();
        }
        Stmt::Return { value, bytes } => {
            // Render in C-style `return EXPR; [bytes]` keyword form
            // rather than the legacy `@return(EXPR, [bytes])` directive
            // form — closer to ghidra's output and faster to scan.
            if *value < 10 {
                write!(out, "{indent}return {value};").unwrap();
            } else {
                write!(out, "{indent}return 0x{value:x};").unwrap();
            }
            if bytes.is_empty() {
                writeln!(out).unwrap();
            } else {
                out.push_str(" [");
                emit_byte_list(out, bytes);
                writeln!(out, "]").unwrap();
            }
        }
        Stmt::Prologue {
            kind,
            params,
            bytes,
        } => {
            emit_prologue(out, indent, kind, params.as_ref(), bytes);
        }
        Stmt::Epilogue {
            kind,
            params,
            bytes,
        } => {
            emit_epilogue(out, indent, kind, params.as_ref(), bytes);
        }
        Stmt::Save { reg, bytes } => {
            write!(out, "{indent}@save({}, [", quote_string(reg)).unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::Restore { reg, bytes } => {
            write!(out, "{indent}@restore({}, [", quote_string(reg)).unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::IfReturn {
            cond_text,
            value_text,
            target_addr,
            cmp_bytes,
            cond_code,
            wide,
        } => {
            write!(out, "{indent}if ({cond_text}) return").unwrap();
            if !value_text.is_empty() {
                write!(out, " {value_text}").unwrap();
            }
            emit_jcc_attrs(out, *cond_code, *wide, cmp_bytes, *target_addr, true);
            writeln!(out, ";").unwrap();
        }
        Stmt::Label { addr } => {
            // No bytes — labels are pure markers. Render dedented
            // by one level (like C-style labels) so they're easy
            // to scan past flow-of-control lines.
            let outdent = if indent.len() >= 4 {
                &indent[..indent.len() - 4]
            } else {
                indent
            };
            writeln!(out, "{outdent}label_{addr:x}:").unwrap();
        }
        Stmt::Goto { target_addr, wide } => {
            if *wide {
                writeln!(out, "{indent}goto label_{target_addr:x} #[wide];").unwrap();
            } else {
                writeln!(out, "{indent}goto label_{target_addr:x};").unwrap();
            }
        }
        Stmt::IfGoto {
            cond_text,
            target_addr,
            cmp_bytes,
            cond_code,
            wide,
        } => {
            write!(out, "{indent}if ({cond_text}) goto label_{target_addr:x}").unwrap();
            emit_jcc_attrs(out, *cond_code, *wide, cmp_bytes, *target_addr, false);
            writeln!(out, ";").unwrap();
        }
        Stmt::SehInstall { bytes } => {
            write!(out, "{indent}@seh_install([").unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::SehRestore { bytes } => {
            write!(out, "{indent}@seh_restore([").unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::Switch {
            selector,
            cases,
            default_addr,
            dispatch,
            table_va,
        } => {
            // Source-language shape:
            // `switch (sel) #[dispatch="…", table_va=…] { case N: goto …; default: goto …; }`
            //
            // The dispatch bytes are NOT pinned to the source. The
            // lower path re-encodes them from `selector`, `cases`,
            // `default_addr`, and `table_va` — so editing any of
            // those fields (or the case targets) flows into the
            // rebuilt binary instead of being silently overridden
            // by a stale byte literal.
            let body_indent = format!("{indent}    ");
            writeln!(
                out,
                "{indent}switch ({selector}) #[dispatch={dispatch:?}, table_va=0x{table_va:x}] {{",
            )
            .unwrap();
            for (i, target) in cases.iter().enumerate() {
                writeln!(out, "{body_indent}case {i}: goto label_{target:x};").unwrap();
            }
            writeln!(out, "{body_indent}default: goto label_{default_addr:x};").unwrap();
            writeln!(out, "{indent}}}").unwrap();
        }
        Stmt::ReturnExpr { text, bytes } => {
            // C-style `return EXPR; [bytes]` form — same shape the
            // `if (cond) return EXPR; [bytes]` early-return uses.
            write!(out, "{indent}return {text};").unwrap();
            out.push_str(" [");
            emit_byte_list(out, bytes);
            writeln!(out, "]").unwrap();
        }
        Stmt::ArgSpill { arg_index, bytes } => {
            write!(out, "{indent}@arg_spill({arg_index}, [").unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::Call {
            name,
            args,
            bytes,
            direct_target,
        } => {
            write!(out, "{indent}{name}(").unwrap();
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                if arg_is_unquoted_safe(a) {
                    out.push_str(a);
                } else {
                    out.push_str(&quote_string(a));
                }
            }
            out.push(')');
            if let Some(target) = direct_target {
                write!(out, " #[target=0x{target:x}]").unwrap();
            }
            if bytes.is_empty() {
                writeln!(out).unwrap();
            } else {
                out.push_str(" [");
                emit_byte_list(out, bytes);
                writeln!(out, "]").unwrap();
            }
        }
        Stmt::IfBranch {
            cond_text,
            cond_bytes,
            attrs,
            pre_body,
            then_body,
            else_body,
        } => {
            emit_if_branch(
                out,
                cond_text,
                cond_bytes,
                attrs,
                pre_body,
                then_body,
                else_body.as_deref(),
                indent,
            );
        }
        Stmt::Loop {
            cond_text,
            entry_jmp_bytes,
            tail_bytes,
            body,
        } => {
            write!(out, "{indent}do").unwrap();
            if let Some(jmp_bytes) = entry_jmp_bytes {
                out.push_str(" entry=[");
                emit_byte_list(out, jmp_bytes);
                out.push(']');
            }
            writeln!(out, " {{").unwrap();
            let body_indent = format!("{indent}    ");
            emit_stmts(out, body, &body_indent);
            write!(out, "{indent}}} while ({}) [", render_cond(cond_text)).unwrap();
            emit_byte_list(out, tail_bytes);
            writeln!(out, "]").unwrap();
        }
        Stmt::LocalSet { slot, value, bytes } => {
            write!(out, "{indent}@local_set(").unwrap();
            emit_signed_hex(out, *slot);
            out.push_str(", ");
            emit_signed_hex(out, *value);
            out.push_str(", [");
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::LocalArith {
            slot,
            op,
            value,
            bytes,
        } => {
            write!(out, "{indent}@local_arith(").unwrap();
            emit_signed_hex(out, *slot);
            write!(out, ", {}, ", quote_string(op)).unwrap();
            emit_signed_hex(out, *value);
            out.push_str(", [");
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::LocalCompound {
            dst,
            op,
            src,
            bytes,
        } => {
            write!(out, "{indent}@local_compound(").unwrap();
            emit_signed_hex(out, *dst);
            write!(out, ", {}, ", quote_string(op)).unwrap();
            emit_signed_hex(out, *src);
            out.push_str(", [");
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::Move { dst, src, bytes } => {
            write!(out, "{indent}").unwrap();
            emit_move_side(out, dst);
            out.push_str(" = ");
            emit_move_side(out, src);
            // Omit the `[]` byte list when bytes were dropped at
            // decompile time — the parser accepts both forms.
            if !bytes.is_empty() {
                out.push_str(" [");
                emit_byte_list(out, bytes);
                out.push(']');
            }
            writeln!(out).unwrap();
        }
        Stmt::Inc16 { lo, hi, bytes } => {
            write!(
                out,
                "{indent}@inc16({}, {}, [",
                quote_string(lo),
                quote_string(hi),
            )
            .unwrap();
            emit_byte_list(out, bytes);
            writeln!(out, "])").unwrap();
        }
        Stmt::IfBlock {
            cond_text,
            cond_bytes,
            then_body,
            then_tail_jmp,
            else_body,
        } => {
            // `ifblock` (one word) distinguishes the structural
            // if/else recovered by the BPF-side CFG pass from the
            // x86 `Stmt::IfBranch` which emits a bare `if`. The
            // bytes layout is also different (no separate cmp
            // prefix, optional tail-jmp). Treat them as cousins
            // sharing the source-language "if" concept.
            write!(out, "{indent}ifblock ({}) [", render_cond(cond_text)).unwrap();
            emit_byte_list(out, cond_bytes);
            writeln!(out, "] {{").unwrap();
            let body_indent = format!("{indent}    ");
            emit_stmts(out, then_body, &body_indent);
            if else_body.is_empty() && then_tail_jmp.is_empty() {
                writeln!(out, "{indent}}}").unwrap();
            } else {
                write!(out, "{indent}}} else").unwrap();
                if !then_tail_jmp.is_empty() {
                    out.push_str(" tail=[");
                    emit_byte_list(out, then_tail_jmp);
                    out.push(']');
                }
                writeln!(out, " {{").unwrap();
                emit_stmts(out, else_body, &body_indent);
                writeln!(out, "{indent}}}").unwrap();
            }
        }
        Stmt::WhileBlock {
            cond_text,
            entry_bytes,
            tail_bytes,
            body,
        } => {
            write!(
                out,
                "{indent}whileblock ({}) entry=[",
                render_cond(cond_text)
            )
            .unwrap();
            emit_byte_list(out, entry_bytes);
            out.push_str("] tail=[");
            emit_byte_list(out, tail_bytes);
            writeln!(out, "] {{").unwrap();
            let body_indent = format!("{indent}    ");
            emit_stmts(out, body, &body_indent);
            writeln!(out, "{indent}}}").unwrap();
        }
        Stmt::RegArith {
            dst,
            op,
            src,
            bytes,
        } => {
            write!(out, "{indent}").unwrap();
            emit_move_side(out, dst);
            write!(out, " {op} ").unwrap();
            emit_move_side(out, src);
            if bytes.is_empty() {
                writeln!(out, ";").unwrap();
            } else {
                out.push_str("; [");
                emit_byte_list(out, bytes);
                writeln!(out, "]").unwrap();
            }
        }
    }
}

/// Render an `if`/`while` condition text. Conds are typically the
/// raw 6502 assembly form (`CMP X; BEQ tgt`). If the text is safe
/// Emit one side of an assignment statement: the destination or
/// source text of a [`Stmt::Move`]. Falls back to a quoted string
/// when the text would otherwise lex weirdly (control chars,
/// embedded `"`, unbalanced parens, etc.); the parser accepts both
/// forms.
fn emit_move_side(out: &mut String, s: &str) {
    if move_side_is_unquoted_safe(s) {
        out.push_str(s);
    } else {
        out.push_str(&quote_string(s));
    }
}

fn move_side_is_unquoted_safe(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for c in s.chars() {
        if c.is_control() {
            return false;
        }
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '\\' => return false,
            '(' | '[' => depth += 1,
            ')' | ']' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    !in_string && depth == 0
}

/// Render an `if`/`while` condition text. Conds are typically the
/// raw 6502 assembly form (`CMP X; BEQ tgt`). If the text is safe
/// to emit unquoted (ASCII-graphic-or-space, balanced parens, no
/// stray `)` that would close the condition early) it is emitted
/// raw; otherwise it goes back into a quoted string.
fn render_cond(s: &str) -> String {
    if cond_is_unquoted_safe(s) {
        s.to_string()
    } else {
        quote_string(s)
    }
}

fn cond_is_unquoted_safe(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut depth = 0i32;
    for c in s.chars() {
        // Allow space + tab inside conds (the inline `;` annotations
        // have leading whitespace), but no control chars or newlines.
        if c.is_control() {
            return false;
        }
        match c {
            '"' | '\\' => return false,
            '(' | '[' => depth += 1,
            ')' | ']' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    depth == 0
}

/// Heuristic: is this arg safe to emit unquoted in a call
/// statement? Rules:
///
/// * Non-empty.
/// * All ASCII graphic chars (no whitespace, no control chars, no
///   embedded `"` or `\\`).
/// * Parens / brackets balanced.
/// * No top-level `,`, `)`, or `]` — those would be parsed as the
///   end of the arg / arg list.
fn arg_is_unquoted_safe(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    // Track whether we ever saw a non-string token. The parser
    // treats single-quoted-string-token args specially (strips
    // outer quotes on parse), so if the whole arg is a bare
    // `"foo"` it would round-trip asymmetrically. Reject that
    // shape here to force auto-quoting; multi-token shapes
    // (`&"foo"`, `[expr+"foo"]`, …) survive verbatim.
    let mut saw_non_string = false;
    for c in s.chars() {
        // Inside a quoted string, allow any printable char
        // (including spaces) so `&"Hello World"` survives bare.
        // Outside, demand graphic-ASCII so a bare space can't
        // break token splitting on parse.
        if in_string {
            if c.is_control() {
                return false;
            }
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        // Outside string/brackets, demand graphic-ASCII so a bare
        // space can't break token splitting on parse. Inside
        // brackets the parser already consumes everything up to
        // the matching close, so spaces are safe there.
        if !c.is_ascii_graphic() && depth == 0 {
            return false;
        }
        if c.is_whitespace() && depth > 0 {
            saw_non_string = true;
            continue;
        }
        if !c.is_ascii_graphic() {
            return false;
        }
        match c {
            '"' => in_string = true,
            '\\' => return false,
            '(' | '[' => {
                depth += 1;
                saw_non_string = true;
            }
            ')' | ']' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                saw_non_string = true;
            }
            ',' if depth == 0 => return false,
            _ => {
                saw_non_string = true;
            }
        }
    }
    if in_string || depth != 0 {
        return false;
    }
    // Bare single-string arg → reject (parser would strip our
    // outer quotes asymmetrically).
    if !saw_non_string {
        return false;
    }
    true
}

fn emit_signed_hex(out: &mut String, n: i64) {
    if n < 0 {
        write!(out, "-0x{:x}", n.unsigned_abs()).unwrap();
    } else {
        write!(out, "0x{n:x}").unwrap();
    }
}

/// Render the trailing attribute list for an `if (...) goto/return …`
/// statement: any combination of `#[cond="je"]`, `#[cmp=[bytes]]`,
/// `#[wide]`, and (for `return` forms only) `#[target=0x…]`.
fn emit_jcc_attrs(
    out: &mut String,
    cond_code: u8,
    wide: bool,
    cmp_bytes: &[u8],
    target_addr: u64,
    include_target: bool,
) {
    let mut parts: Vec<String> = Vec::new();
    let cond_name = jcc_cond_name_for_emit(cond_code);
    parts.push(format!("cond={cond_name:?}"));
    if !cmp_bytes.is_empty() {
        let mut s = String::from("cmp=[");
        for (i, b) in cmp_bytes.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            write!(s, "0x{b:02x}").unwrap();
        }
        s.push(']');
        parts.push(s);
    }
    if wide {
        parts.push("wide".into());
    }
    if include_target {
        parts.push(format!("target=0x{target_addr:x}"));
    }
    out.push_str(" #[");
    out.push_str(&parts.join(", "));
    out.push(']');
}

fn jcc_cond_name_for_emit(cond_code: u8) -> &'static str {
    // Canonical lowercase names; lower / parse uses the same mapping.
    match cond_code & 0x0f {
        0x0 => "jo",
        0x1 => "jno",
        0x2 => "jb",
        0x3 => "jae",
        0x4 => "je",
        0x5 => "jne",
        0x6 => "jbe",
        0x7 => "ja",
        0x8 => "js",
        0x9 => "jns",
        0xa => "jp",
        0xb => "jnp",
        0xc => "jl",
        0xd => "jge",
        0xe => "jle",
        _ => "jg",
    }
}

fn emit_byte_list(out: &mut String, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write!(out, "0x{b:02x}").unwrap();
    }
}

/// Emit `#[k1=v1, k2=v2, …]` inline. Caller positions the cursor; the
/// trailing space (if anything follows) is the caller's job. Emits
/// nothing when the filtered list is empty so call sites can
/// sprinkle this in unconditionally.
pub(crate) fn emit_attrs<F>(out: &mut String, attrs: &[Attribute], mut omit: F)
where
    F: FnMut(&Attribute) -> bool,
{
    let kept: Vec<&Attribute> = attrs.iter().filter(|a| !omit(a)).collect();
    if kept.is_empty() {
        return;
    }
    out.push_str("#[");
    for (i, a) in kept.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&a.key);
        // Flag attrs render bare (`#[naked]`); everything else gets
        // an `=value` part.
        if !matches!(a.value, AttrValue::Flag) {
            out.push('=');
            emit_attr_value(out, &a.value);
        }
    }
    out.push(']');
}

/// Should the given attribute be omitted on emit because the
/// surrounding context derives the same value? Today that's just
/// the `head_bytes` attribute on an `if`: when the cond text's
/// cmp/test portion encodes back to the same bytes (canonical Intel
/// form), the attribute is redundant — the parser will derive
/// identical bytes when it reads the file back.
fn head_bytes_is_derivable(attr: &Attribute, cond_text: &str) -> bool {
    if attr.key != "head_bytes" {
        return false;
    }
    let AttrValue::ByteList(bytes) = &attr.value else {
        return false;
    };
    ud_arch_x86::encode_head_from_cond_text(cond_text).is_some_and(|derived| &derived == bytes)
}

fn emit_attr_value(out: &mut String, value: &AttrValue) {
    match value {
        AttrValue::String(s) => out.push_str(&quote_string(s)),
        AttrValue::Int(n) => write!(out, "0x{n:x}").unwrap(),
        AttrValue::ByteList(bytes) => {
            out.push('[');
            emit_byte_list(out, bytes);
            out.push(']');
        }
        // Caller-side already short-circuited to drop the `=value`
        // for Flag attrs; if we reach here something's off — emit
        // an empty value to keep the source valid.
        AttrValue::Flag => {}
    }
}

/// Emit an `if` statement.
///
/// Two source shapes:
///
/// * **Simple** — `attrs.is_empty() && pre_body.is_empty()`. Renders
///   as `if (cond) [bytes] { then } [else { else }]` (the historical
///   form, unchanged so the bulk of fixtures stay terse).
/// * **Attributed** — anything else. Renders with the attribute
///   sandwich and an explicit `@then`/`@else` arm structure so
///   `pre_body` stmts and the cond head/tail bytes are placed in
///   readable positions.
#[allow(clippy::too_many_arguments)]
fn emit_if_branch(
    out: &mut String,
    cond_text: &str,
    cond_bytes: &[u8],
    attrs: &[Attribute],
    pre_body: &[Stmt],
    then_body: &[Stmt],
    else_body: Option<&[Stmt]>,
    indent: &str,
) {
    let body_indent = format!("{indent}    ");
    // Decide which attrs survive emission. `head_bytes` drops out
    // when the cond text's cmp/test portion re-encodes to the same
    // bytes — the parser will re-derive identical bytes from the
    // text alone.
    let attrs_visible_count = attrs
        .iter()
        .filter(|a| !head_bytes_is_derivable(a, cond_text))
        .count();

    if attrs_visible_count == 0 && pre_body.is_empty() {
        write!(out, "{indent}if ({}) [", render_cond(cond_text)).unwrap();
        emit_byte_list(out, cond_bytes);
        writeln!(out, "] {{").unwrap();
        emit_stmts(out, then_body, &body_indent);
        if let Some(else_body) = else_body {
            writeln!(out, "{indent}}} else {{").unwrap();
            emit_stmts(out, else_body, &body_indent);
        }
        writeln!(out, "{indent}}}").unwrap();
        return;
    }
    write!(out, "{indent}if ({}) ", render_cond(cond_text)).unwrap();
    let before_attrs_len = out.len();
    emit_attrs(out, attrs, |a| head_bytes_is_derivable(a, cond_text));
    if out.len() > before_attrs_len {
        out.push(' ');
    }
    out.push('[');
    emit_byte_list(out, cond_bytes);
    writeln!(out, "] {{").unwrap();
    emit_stmts(out, pre_body, &body_indent);
    writeln!(out, "{body_indent}@then {{").unwrap();
    let arm_indent = format!("{body_indent}    ");
    emit_stmts(out, then_body, &arm_indent);
    writeln!(out, "{body_indent}}}").unwrap();
    if let Some(else_body) = else_body {
        writeln!(out, "{body_indent}@else {{").unwrap();
        emit_stmts(out, else_body, &arm_indent);
        writeln!(out, "{body_indent}}}").unwrap();
    }
    writeln!(out, "{indent}}}").unwrap();
}

fn emit_field(out: &mut String, f: &Field, depth: usize) {
    let indent = " ".repeat(depth * 4);
    write!(out, "{indent}{}: ", f.name).unwrap();
    emit_value(out, &f.value, depth);
    writeln!(out, ",").unwrap();
}

fn emit_value(out: &mut String, v: &Value, depth: usize) {
    match v {
        Value::String(s) => out.push_str(&quote_string(s)),
        Value::Int(n) => write!(out, "0x{n:x}").unwrap(),
        Value::List(items) => emit_list(out, items, depth),
        Value::Block(fields) => emit_block(out, fields, depth),
    }
}

fn emit_list(out: &mut String, items: &[Value], depth: usize) {
    out.push('[');
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        emit_value(out, v, depth);
    }
    out.push(']');
}

fn emit_block(out: &mut String, fields: &[Field], depth: usize) {
    out.push('{');
    out.push('\n');
    for f in fields {
        emit_field(out, f, depth + 1);
    }
    let close_indent = " ".repeat(depth * 4);
    out.push_str(&close_indent);
    out.push('}');
}

fn emit_params(out: &mut String, params: &[Param]) {
    for (i, p) in params.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        write!(out, "{}: ", p.name).unwrap();
        emit_type(out, &p.ty);
        if let Some(loc) = &p.location {
            write!(out, " @{loc}").unwrap();
        }
    }
}

fn emit_type(out: &mut String, t: &Type) {
    match t {
        Type::Void => out.push_str("void"),
        Type::I8 => out.push_str("i8"),
        Type::I16 => out.push_str("i16"),
        Type::I32 => out.push_str("i32"),
        Type::I64 => out.push_str("i64"),
        Type::U8 => out.push_str("u8"),
        Type::U16 => out.push_str("u16"),
        Type::U32 => out.push_str("u32"),
        Type::U64 => out.push_str("u64"),
        Type::F32 => out.push_str("f32"),
        Type::F64 => out.push_str("f64"),
        Type::Bool => out.push_str("bool"),
        Type::Char => out.push_str("char"),
        Type::Pointer(inner) => {
            out.push_str("ptr<");
            emit_type(out, inner);
            out.push('>');
        }
        Type::Unknown => out.push_str("unknown"),
    }
}

// Suppress unused-when-no-signature warning by referencing in tests below.
#[allow(dead_code)]
fn _signature_used(_: &Signature) {}

/// Quote a string for `.ud` output: surround in `"…"`, escape backslash
/// and double-quote.
/// Render a `Stmt::Prologue`. When `params` is present, emit
/// the structured form (`saves: [...], frame, sub: 0xN, cf`)
/// and drop the byte list — the parser regenerates identical
/// bytes via the arch's codec. When `params` is absent, fall
/// back to the legacy `("kind", [bytes])` form.
fn emit_prologue(
    out: &mut String,
    indent: &str,
    kind: &str,
    params: Option<&crate::types::PrologueParams>,
    bytes: &[u8],
) {
    if let Some(p) = params {
        write!(out, "{indent}@prologue({}", quote_string(kind)).unwrap();
        emit_prologue_params(out, p);
        writeln!(out, ")").unwrap();
        return;
    }
    write!(out, "{indent}@prologue({}, [", quote_string(kind)).unwrap();
    emit_byte_list(out, bytes);
    writeln!(out, "])").unwrap();
}

fn emit_epilogue(
    out: &mut String,
    indent: &str,
    kind: &str,
    params: Option<&crate::types::EpilogueParams>,
    bytes: &[u8],
) {
    if let Some(e) = params {
        write!(out, "{indent}@epilogue({}", quote_string(kind)).unwrap();
        emit_epilogue_params(out, e);
        writeln!(out, ")").unwrap();
        return;
    }
    write!(out, "{indent}@epilogue({}, [", quote_string(kind)).unwrap();
    emit_byte_list(out, bytes);
    writeln!(out, "])").unwrap();
}

fn emit_prologue_params(out: &mut String, p: &crate::types::PrologueParams) {
    if !p.saves.is_empty() {
        out.push_str(", saves: [");
        for (i, r) in p.saves.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(r);
        }
        out.push(']');
    }
    if p.frame {
        if p.frame_alt {
            out.push_str(", frame=alt");
        } else {
            out.push_str(", frame");
        }
    }
    if p.sub_esp > 0 {
        write!(out, ", sub: 0x{:x}", p.sub_esp).unwrap();
    }
    if !p.saves_after.is_empty() {
        out.push_str(", saves_after: [");
        for (i, r) in p.saves_after.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(r);
        }
        out.push(']');
    }
    if p.cf_protect {
        out.push_str(", cf");
    }
}

fn emit_epilogue_params(out: &mut String, e: &crate::types::EpilogueParams) {
    if !e.saves.is_empty() {
        out.push_str(", saves: [");
        for (i, r) in e.saves.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(r);
        }
        out.push(']');
    }
    if e.add_esp > 0 {
        write!(out, ", add: 0x{:x}", e.add_esp).unwrap();
    }
    if e.leave {
        out.push_str(", leave");
    } else if e.pop_frame {
        out.push_str(", pop_frame");
    }
    if e.ret_imm > 0 {
        write!(out, ", ret_imm: 0x{:x}", e.ret_imm).unwrap();
    }
}

fn quote_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '\0' => out.push_str(r"\0"),
            c if (c as u32) < 0x20 || c == '\x7f' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_module() -> Module {
        Module { fields: vec![] }
    }

    #[test]
    fn empty_file_emits_just_module_header() {
        let f = UdFile {
            module: empty_module(),
            items: vec![],
        };
        assert_eq!(emit(&f), "@module {\n}\n");
    }

    #[test]
    fn module_fields_indent_with_four_spaces() {
        let f = UdFile {
            module: Module {
                fields: vec![
                    Field {
                        name: "arch".into(),
                        value: Value::String("x86_64".into()),
                    },
                    Field {
                        name: "bits".into(),
                        value: Value::Int(64),
                    },
                ],
            },
            items: vec![],
        };
        let out = emit(&f);
        assert!(out.contains("    arch: \"x86_64\","));
        assert!(out.contains("    bits: 0x40,"));
    }

    #[test]
    fn nested_blocks_indent_correctly() {
        let f = UdFile {
            module: Module {
                fields: vec![Field {
                    name: "build".into(),
                    value: Value::Block(vec![Field {
                        name: "e_flags".into(),
                        value: Value::Int(0),
                    }]),
                }],
            },
            items: vec![],
        };
        let out = emit(&f);
        assert!(
            out.contains("    build: {\n        e_flags: 0x0,\n    },\n"),
            "actual: {out:?}"
        );
    }

    #[test]
    fn list_values_inline_on_one_line() {
        let f = UdFile {
            module: Module {
                fields: vec![Field {
                    name: "ident".into(),
                    value: Value::List(vec![Value::Int(0x7f), Value::Int(0x45)]),
                }],
            },
            items: vec![],
        };
        let out = emit(&f);
        assert!(out.contains("    ident: [0x7f, 0x45],"));
    }

    #[test]
    fn function_with_asm_lines_text_only() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1080),
                name: "_start".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![
                    Stmt::asm_text("endbr64"),
                    Stmt::Comment("block: 0x1084".into()),
                    Stmt::asm_text("ret"),
                ],
            })],
        };
        let out = emit(&f);
        assert!(out.contains("@addr(0x1080)\nfn _start() {\n"));
        assert!(out.contains("    @asm(\"endbr64\")\n"));
        assert!(out.contains("    // block: 0x1084\n"));
        assert!(out.contains("    @asm(\"ret\")\n"));
    }

    #[test]
    fn function_with_asm_lines_and_pinned_bytes() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1080),
                name: "f".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![
                    Stmt::asm("endbr64", vec![0xf3, 0x0f, 0x1e, 0xfa]),
                    Stmt::asm("ret", vec![0xc3]),
                ],
            })],
        };
        let out = emit(&f);
        assert!(out.contains("    @asm(\"endbr64\", [0xf3, 0x0f, 0x1e, 0xfa])\n"));
        assert!(out.contains("    @asm(\"ret\", [0xc3])\n"));
    }

    #[test]
    fn raw_item_emits_addr_and_byte_list() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Raw {
                addr: 0x10c0,
                bytes: vec![0xcc, 0xcc, 0xcc],
            }],
        };
        let out = emit(&f);
        assert!(out.contains("@raw(0x10c0, [0xcc, 0xcc, 0xcc])\n"));
    }

    #[test]
    fn section_wraps_nested_items_with_indentation() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Section {
                name: ".text".into(),
                addr: 0x1000,
                items: vec![
                    Item::Function(FnDecl {
                        addr: Some(0x1000),
                        name: "f".into(),
                        attrs: Vec::new(),
                        locals: Vec::new(),
                        signature: None,
                        body: vec![Stmt::asm("ret", vec![0xc3])],
                    }),
                    Item::Raw {
                        addr: 0x1001,
                        bytes: vec![0x90, 0x90],
                    },
                ],
            }],
        };
        let out = emit(&f);
        assert!(out.contains("@section(\".text\", 0x1000) {\n"));
        assert!(out.contains("    @addr(0x1000)\n"));
        assert!(out.contains("    fn f() {\n"));
        assert!(out.contains("        @asm(\"ret\", [0xc3])\n"));
        assert!(out.contains("    @raw(0x1001, [0x90, 0x90])\n"));
    }

    #[test]
    fn if_branch_emits_then_and_else_arms() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1000),
                name: "f".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![Stmt::IfBranch {
                    cond_text: "cmp [rbp-4],1; jne".into(),
                    cond_bytes: vec![0x83, 0x7d, 0xfc, 0x01, 0x75, 0x07],
                    attrs: Vec::new(),
                    pre_body: Vec::new(),
                    then_body: vec![Stmt::asm("ret", vec![0xc3])],
                    else_body: Some(vec![Stmt::asm("nop", vec![0x90])]),
                }],
            })],
        };
        let out = emit(&f);
        assert!(
            out.contains("    if (cmp [rbp-4],1; jne) [0x83, 0x7d, 0xfc, 0x01, 0x75, 0x07] {\n"),
            "actual: {out}"
        );
        assert!(out.contains("        @asm(\"ret\", [0xc3])\n"));
        assert!(out.contains("    } else {\n"));
        assert!(out.contains("        @asm(\"nop\", [0x90])\n"));
    }

    #[test]
    fn if_branch_without_else_omits_else_block() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::Function(FnDecl {
                addr: Some(0x1000),
                name: "f".into(),
                attrs: Vec::new(),
                locals: Vec::new(),
                signature: None,
                body: vec![Stmt::IfBranch {
                    cond_text: "test rax,rax; je".into(),
                    cond_bytes: vec![0x48, 0x85, 0xc0, 0x74, 0x02],
                    attrs: Vec::new(),
                    pre_body: Vec::new(),
                    then_body: vec![Stmt::asm("call rax", vec![0xff, 0xd0])],
                    else_body: None,
                }],
            })],
        };
        let out = emit(&f);
        assert!(out.contains("    if ("));
        assert!(!out.contains("else"), "should not emit else: {out}");
    }

    #[test]
    fn quote_string_escapes_quote_and_backslash() {
        assert_eq!(quote_string("a"), r#""a""#);
        assert_eq!(quote_string(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_string(r"\n"), r#""\\n""#);
    }

    #[test]
    fn jump_table_emits_addr_dispatch_and_cases() {
        let f = UdFile {
            module: empty_module(),
            items: vec![Item::JumpTable {
                addr: 0x2020,
                dispatch: "gcc_pie_rel32".into(),
                entries: vec![
                    crate::JumpTableEntry {
                        case: 0,
                        target: 0x117a,
                    },
                    crate::JumpTableEntry {
                        case: 1,
                        target: 0x1183,
                    },
                ],
            }],
        };
        let out = emit(&f);
        assert!(
            out.contains("@jump_table(0x2020, dispatch=\"gcc_pie_rel32\") {"),
            "actual:\n{out}"
        );
        assert!(out.contains("case_0: label_117a,"), "actual:\n{out}");
        assert!(out.contains("case_1: label_1183,"), "actual:\n{out}");
    }
}

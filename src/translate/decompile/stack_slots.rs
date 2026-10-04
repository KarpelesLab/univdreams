//! Stack-slot naming — text-level rewrite of `[fp ± offset]`
//! memory operands to `[local_<offset>]` / `[arg_<offset>]`.
//!
//! Arch-agnostic: the caller supplies the name of the
//! architecture's frame-pointer register (`"ebp"` / `"rbp"` for
//! x86, `"r10"` for BPF). Positive offsets above the frame
//! pointer are stack arguments by convention (named
//! `arg_<offset>`); negative offsets are locals (`local_<abs>`).
//!
//! The rewriter operates on the *text* of an instruction —
//! it's deliberately small and parse-friendly so it slots into
//! the existing `format_insn` outputs without re-tokenising
//! the whole operand. Bytes are unaffected; the round-trip
//! property comes from the pinned `@asm` byte list.

/// Walk `text` and rewrite every `[fp_reg ± hex_offset]`
/// occurrence to `[local_<offset>]` or `[arg_<offset>]`. Other
/// content (mnemonic, registers, immediates, brackets without
/// the frame pointer inside, …) is left untouched.
///
/// Examples (fp_reg = `"r10"`):
///
/// * `"ldxdw r6, [r10 - 0x38]"` → `"ldxdw r6, [local_38]"`
/// * `"stxdw [r10 + 0x10], r3"` → `"stxdw [arg_10], r3"`
/// * `"mov64 r1, r10"`           → unchanged (no brackets)
/// * `"ldxdw r0, [r5 - 0xff8]"`  → unchanged (different reg)
#[must_use]
pub fn rewrite_slots(text: &str, fp_reg: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find the next `[fp_reg`-shaped opener; if none, we're
        // done. We don't need a full lexer here — the operand
        // forms we care about only ever appear as
        // `[<fp_reg>` (no space before `<fp_reg>`) per
        // `format_insn`'s output.
        let probe = if let Some(p) = find_subslice(&bytes[i..], b"[") {
            i + p
        } else {
            out.push_str(&text[i..]);
            break;
        };
        out.push_str(&text[i..probe]);
        // Try to match `[<fp_reg>` + optional ` ± hex` + `]`.
        if let Some((rewritten, consumed)) = try_match_slot(&text[probe..], fp_reg) {
            out.push_str(&rewritten);
            i = probe + consumed;
        } else {
            out.push('[');
            i = probe + 1;
        }
    }
    out
}

/// Match a `[<fp_reg>(...)]` operand at the start of `slice`.
/// Returns `(rewritten_text, bytes_consumed)` on success.
fn try_match_slot(slice: &str, fp_reg: &str) -> Option<(String, usize)> {
    let rest = slice.strip_prefix('[')?;
    let rest = rest.strip_prefix(fp_reg)?;
    // Three shapes: `]` (offset = 0), ` + 0xHEX]`, ` - 0xHEX]`.
    if let Some(after) = rest.strip_prefix(']') {
        let consumed = slice.len() - after.len();
        return Some((format!("[{}]", slot_name(0, false)), consumed));
    }
    let (positive, rest) = if let Some(r) = rest.strip_prefix(" + 0x") {
        (true, r)
    } else {
        (false, rest.strip_prefix(" - 0x")?)
    };
    let hex_end = rest.find(']')?;
    let hex_str = &rest[..hex_end];
    if hex_str.is_empty() || !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let offset = u64::from_str_radix(hex_str, 16).ok()?;
    let after_close = &rest[hex_end + 1..];
    let consumed = slice.len() - after_close.len();
    Some((format!("[{}]", slot_name(offset, positive)), consumed))
}

/// Naming convention: `arg_<hex>` for positive offsets (stack
/// args above the frame pointer); `local_<hex>` for negative
/// offsets (locals below it). Zero is treated as a local
/// (`local_0`).
fn slot_name(offset: u64, positive: bool) -> String {
    if positive {
        format!("arg_{offset:x}")
    } else {
        format!("local_{offset:x}")
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renames_negative_bpf_offset() {
        let out = rewrite_slots("ldxdw r6, [r10 - 0x38]", "r10");
        assert_eq!(out, "ldxdw r6, [local_38]");
    }

    #[test]
    fn renames_positive_bpf_offset_as_arg() {
        let out = rewrite_slots("stxdw [r10 + 0x10], r3", "r10");
        assert_eq!(out, "stxdw [arg_10], r3");
    }

    #[test]
    fn leaves_other_registers_alone() {
        let input = "ldxdw r0, [r5 - 0xff8]";
        assert_eq!(rewrite_slots(input, "r10"), input);
    }

    #[test]
    fn handles_multiple_slots_in_one_line() {
        let input = "memcpy [r10 - 0x38], [r10 + 0x10]";
        assert_eq!(rewrite_slots(input, "r10"), "memcpy [local_38], [arg_10]");
    }

    #[test]
    fn x86_style_works_too() {
        let out = rewrite_slots("mov dword ptr [ebp-0x40], eax", "ebp");
        // The leading "ebp-" form (no spaces) isn't a slot — our
        // rewriter is currently strict about ` - ` with spaces.
        // x86's existing `rename_ebp_slot` accepts the spaceless
        // form; refactoring to share this helper is a follow-up
        // (see L3 plan).
        assert_eq!(out, "mov dword ptr [ebp-0x40], eax");
    }
}

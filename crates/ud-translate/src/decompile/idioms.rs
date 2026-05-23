//! BPF idiom recognition (decompile L6c, focused subset).
//!
//! Two layers ride here:
//!
//! 1. [`solana_syscall_signature`] — when a `call
//!    <syscall_name>` is rendered (via L1's relocation-derived
//!    name map), we add a `// <signature>` comment underneath
//!    listing the expected argument names and types from the
//!    Solana SDK. Makes `call sol_log_` immediately legible as
//!    `sol_log_(msg: *const u8, len: u64)`.
//!
//! 2. [`solana_semantic_comment`] + [`annotate_pda_verify`] —
//!    a security-audit reading layer. Pubkey-sized
//!    `sol_memcmp_` calls get flagged as "Pubkey equality
//!    check"; `sol_try_find_program_address` followed by a
//!    32-byte `sol_memcmp_` inside the same function is
//!    flagged as a PDA verification guard. `sol_invoke_signed_*`
//!    sites are tagged as CPI for grep-ability.
//!
//! Round-trip neutral: every annotation is a `Stmt::Comment`,
//! zero bytes at lower time.
//!
//! A full L6c with slice-index / option / struct-field idiom
//! recognition needs the SSA + expression-simplification
//! infrastructure that lives in `ssa.rs` and `expr.rs` —
//! currently x86-coupled. Generalising those (L6a) unlocks
//! the next tier of idiom matches.

use ud_ast::Stmt;

/// Solana SDK / Anza syscalls and their argument signatures.
/// The list is intentionally small — only the syscalls we've
/// seen on-chain in practice. Adding new entries is purely
/// additive.
#[must_use]
pub fn solana_syscall_signature(name: &str) -> Option<&'static str> {
    match name {
        "sol_log_" => Some("sol_log_(msg: *const u8, len: u64)"),
        "sol_log_64_" => Some("sol_log_64_(a: u64, b: u64, c: u64, d: u64, e: u64)"),
        "sol_log_pubkey" => Some("sol_log_pubkey(pubkey: *const Pubkey)"),
        "sol_log_compute_units_" => Some("sol_log_compute_units_()"),
        "sol_log_data" => Some("sol_log_data(data: *const SliceArray, n: u64)"),
        "sol_memcpy_" => Some("sol_memcpy_(dst: *mut u8, src: *const u8, n: u64)"),
        "sol_memset_" => Some("sol_memset_(dst: *mut u8, value: u8, n: u64)"),
        "sol_memcmp_" => Some("sol_memcmp_(a: *const u8, b: *const u8, n: u64) -> i32"),
        "sol_memmove_" => Some("sol_memmove_(dst: *mut u8, src: *const u8, n: u64)"),
        "sol_invoke_signed_rust" => Some(
            "sol_invoke_signed_rust(insn: *const Instruction, account_infos: *const AccountInfo, \
             account_infos_len: u64, signers_seeds: *const SignerSeeds, signers_seeds_len: u64) -> u64",
        ),
        "sol_invoke_signed_c" => Some(
            "sol_invoke_signed_c(insn: *const Instruction, account_infos: *const AccountInfo, \
             account_infos_len: u64, signers_seeds: *const SignerSeeds, signers_seeds_len: u64) -> u64",
        ),
        "sol_try_find_program_address" => Some(
            "sol_try_find_program_address(seeds: *const Seed, seeds_len: u64, \
             program_id: *const Pubkey, address: *mut Pubkey, bump: *mut u8) -> u64",
        ),
        "sol_create_program_address" => Some(
            "sol_create_program_address(seeds: *const Seed, seeds_len: u64, \
             program_id: *const Pubkey, address: *mut Pubkey) -> u64",
        ),
        "sol_get_clock_sysvar" => Some("sol_get_clock_sysvar(buf: *mut Clock) -> u64"),
        "sol_get_rent_sysvar" => Some("sol_get_rent_sysvar(buf: *mut Rent) -> u64"),
        "sol_get_epoch_schedule_sysvar" => {
            Some("sol_get_epoch_schedule_sysvar(buf: *mut EpochSchedule) -> u64")
        }
        "sol_get_fees_sysvar" => Some("sol_get_fees_sysvar(buf: *mut Fees) -> u64"),
        "sol_get_stack_height" => Some("sol_get_stack_height() -> u64"),
        "sol_get_return_data" => {
            Some("sol_get_return_data(data: *mut u8, len: u64, program_id: *mut Pubkey) -> u64")
        }
        "sol_set_return_data" => Some("sol_set_return_data(data: *const u8, len: u64)"),
        "sol_sha256" => {
            Some("sol_sha256(slices: *const Slice, n: u64, result: *mut [u8; 32]) -> u64")
        }
        "sol_keccak256" => {
            Some("sol_keccak256(slices: *const Slice, n: u64, result: *mut [u8; 32]) -> u64")
        }
        "sol_secp256k1_recover" => Some(
            "sol_secp256k1_recover(hash: *const u8, recovery_id: u64, signature: *const u8, \
             result: *mut u8) -> u64",
        ),
        "sol_blake3" => {
            Some("sol_blake3(slices: *const Slice, n: u64, result: *mut [u8; 32]) -> u64")
        }
        "sol_curve_validate_point" => {
            Some("sol_curve_validate_point(curve: u64, point: *const u8) -> u64")
        }
        "sol_curve_group_op" => Some(
            "sol_curve_group_op(curve: u64, op: u64, a: *const u8, b: *const u8, \
             result: *mut u8) -> u64",
        ),
        "sol_alloc_free_" => Some("sol_alloc_free_(size: u64, freep: *mut u8) -> *mut u8"),
        "sol_panic_" => Some("sol_panic_(filename: *const u8, len: u64, line: u64, column: u64)"),
        "sol_remaining_compute_units" => Some("sol_remaining_compute_units() -> u64"),
        "abort" => Some("abort() -> !"),
        _ => None,
    }
}

/// Marker prefix every annotation in this module emits, so
/// downstream tools can grep for "Solana idiom" hits without
/// false positives from arbitrary user comments.
const TAG: &str = "[solana]";

/// Per-call semantic annotation. Returns `Some(comment)` for
/// recognised Solana patterns where the call's argument values
/// alone are enough to commit to an interpretation; `None`
/// otherwise.
///
/// The `args` array is the L6c+ tracker's snapshot of r1..r5
/// at the call site — already-rendered text, not parsed
/// values. We look at it textually because the tracker stores
/// hex literals (`"0x20"`) and locals (`"local_50"`) the same
/// way.
#[must_use]
pub fn solana_semantic_comment(name: &str, args: &[Option<String>; 5]) -> Option<String> {
    match name {
        "sol_memcmp_" => {
            // sol_memcmp_(a, b, n) -> i32; n is in r3 (args[2]).
            // A constant n tells us what's being compared.
            args[2].as_deref().and_then(parse_int_arg).map(|n| match n {
                32 => format!("{TAG} 32-byte compare — likely Pubkey equality check"),
                8 => format!("{TAG} 8-byte compare — likely discriminator / u64 check"),
                16 => format!("{TAG} 16-byte compare — likely u128 / hash-prefix check"),
                64 => format!("{TAG} 64-byte compare — likely signature / hash check"),
                n => format!("{TAG} {n}-byte memcmp"),
            })
        }
        "sol_try_find_program_address" => Some(format!(
            "{TAG} PDA derivation — derives Pubkey + bump from seeds + program_id"
        )),
        "sol_create_program_address" => Some(format!(
            "{TAG} PDA derivation (no-bump) — derives Pubkey from seeds + program_id"
        )),
        "sol_invoke_signed_rust" | "sol_invoke_signed_c" => Some(format!(
            "{TAG} CPI — signed cross-program invocation (program acts as PDA signer)"
        )),
        "sol_get_clock_sysvar" => Some(format!(
            "{TAG} sysvar fetch — Clock (slot, unix_timestamp, epoch, …)"
        )),
        "sol_get_rent_sysvar" => Some(format!("{TAG} sysvar fetch — Rent (exemption thresholds)")),
        "sol_get_epoch_schedule_sysvar" => Some(format!("{TAG} sysvar fetch — EpochSchedule")),
        "sol_get_fees_sysvar" => Some(format!("{TAG} sysvar fetch — Fees")),
        "sol_set_return_data" => Some(format!(
            "{TAG} sets program return data (visible to caller of this CPI)"
        )),
        "sol_get_return_data" => Some(format!(
            "{TAG} reads return data set by the most recent CPI callee"
        )),
        "sol_secp256k1_recover" => Some(format!(
            "{TAG} secp256k1 signature recovery — outputs the recovered pubkey"
        )),
        "sol_sha256" | "sol_keccak256" | "sol_blake3" => {
            Some(format!("{TAG} cryptographic hash — output is 32 bytes"))
        }
        "sol_log_data" => Some(format!(
            "{TAG} emits structured log data (visible in tx logs / event consumers)"
        )),
        _ => None,
    }
}

/// Post-process a function body, inserting "PDA verification
/// check" annotations.
///
/// Pattern: a `sol_try_find_program_address` / `sol_create_program_address`
/// call followed within `WINDOW` statements by a 32-byte
/// `sol_memcmp_` call. The PDA syscall writes the derived
/// address into a local; if the program then memcmps that
/// 32-byte buffer against another buffer, the program is
/// almost certainly verifying "this incoming account is the
/// PDA we expect."
///
/// We do this lexically over already-emitted statements so we
/// don't need value-flow analysis — the tag on the memcmp
/// (which we already emitted via [`solana_semantic_comment`])
/// gives us the n=32 filter cheaply.
pub fn annotate_pda_verify(body: &mut Vec<Stmt>) {
    annotate_pda_verify_in(body);
}

/// How many statements after a PDA-derive we'll still
/// consider a 32-byte memcmp as "PDA verification". The
/// derivation typically leaves r0 set to the address
/// buffer and a memcmp follows within a few ops; 30 is
/// generous enough for register-shuffle prologue.
const PDA_VERIFY_WINDOW: usize = 30;

/// Recursive worker. Annotates the slice in place, then
/// descends into any `IfBlock` / `WhileBlock` children so a
/// memcmp nested inside structural wrapping still gets the
/// "PDA verification check" tag. Sibling structural blocks
/// don't carry the pattern across each other — the search
/// stops at the boundary of the current `Vec<Stmt>`.
fn annotate_pda_verify_in(body: &mut Vec<Stmt>) {
    // Recurse first so deeper levels are annotated before we
    // scan this level. Order doesn't affect correctness — the
    // PDA-derive/memcmp pair is constrained to one nesting
    // level by `is_pda_derive_marker` / `is_pubkey_memcmp_marker`
    // matching only direct `Stmt::Comment` children of the
    // current vector — but doing it bottom-up keeps the
    // semantics easy to reason about.
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::IfBlock {
                then_body,
                else_body,
                ..
            } => {
                annotate_pda_verify_in(then_body);
                annotate_pda_verify_in(else_body);
            }
            Stmt::WhileBlock { body: wb, .. } => annotate_pda_verify_in(wb),
            _ => {}
        }
    }

    // Walk back-to-front so insertions don't invalidate
    // earlier indices.
    let mut hits: Vec<usize> = Vec::new();
    for (i, stmt) in body.iter().enumerate() {
        if !is_pda_derive_marker(stmt) {
            continue;
        }
        let end = body.len().min(i + 1 + PDA_VERIFY_WINDOW);
        for (j, candidate) in body.iter().enumerate().take(end).skip(i + 1) {
            if is_pubkey_memcmp_marker(candidate) {
                hits.push(j);
                break;
            }
        }
    }
    for hit in hits.into_iter().rev() {
        body.insert(
            hit,
            Stmt::Comment(format!(
                "{TAG} >>> PDA verification check: derived PDA being compared against passed-in pubkey"
            )),
        );
    }
}

fn is_pda_derive_marker(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Comment(s) if s.contains("PDA derivation"))
}

/// Insert per-handler region banners.
///
/// For each detected handler marker (a `lddw r?,
/// "Instruction: <variant>…"` asm line, or a `→ sol_log_("…",
/// N)` comment whose first N chars carry the `Instruction:`
/// prefix), prepend a `// [solana] === handler: <variant> ===`
/// banner comment immediately above. Banners act as navigation
/// anchors for the giant inlined dispatchers Rust emits at
/// -O2/-O3 (chiefstaker fits all 18 instruction handlers into
/// one ~30K-line function).
///
/// We dedup consecutive banners for the same variant — when a
/// variant is referenced twice in quick succession (e.g. once
/// in a lddw and once in a downstream sol_log_ comment), only
/// the first banner appears.
///
/// Round-trip neutral: every inserted statement is a
/// `Stmt::Comment`, which lowers to zero bytes.
pub fn annotate_handler_banners(body: &mut Vec<Stmt>) {
    annotate_handler_banners_in(body);
}

fn annotate_handler_banners_in(body: &mut Vec<Stmt>) {
    // Recurse into structural wrappers first.
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::IfBlock {
                then_body,
                else_body,
                ..
            } => {
                annotate_handler_banners_in(then_body);
                annotate_handler_banners_in(else_body);
            }
            Stmt::WhileBlock { body: wb, .. } => annotate_handler_banners_in(wb),
            _ => {}
        }
    }

    // Pass 1: collect (index, variant_name) for every hit at
    // this nesting level.
    let mut hits: Vec<(usize, String)> = Vec::new();
    let mut last_seen: Option<String> = None;
    for (i, stmt) in body.iter().enumerate() {
        let detected = match stmt {
            Stmt::Asm { text, .. } => extract_instruction_handler_from_lddw(text),
            Stmt::Comment(s) => extract_instruction_handler(s),
            _ => None,
        };
        if let Some(name) = detected {
            // Dedup: skip when we just emitted a banner for
            // this exact variant. We track only the most-
            // recent variant — distinct variants always get
            // a fresh banner, even if interleaved.
            if last_seen.as_deref() != Some(name.as_str()) {
                hits.push((i, name.clone()));
                last_seen = Some(name);
            }
        }
    }

    // Pass 2: insert back-to-front so earlier indices stay
    // valid.
    for (at, name) in hits.into_iter().rev() {
        body.insert(at, Stmt::Comment(format!("{TAG} === handler: {name} ===")));
    }
}

fn is_pubkey_memcmp_marker(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Comment(s) if s.contains("32-byte compare"))
}

/// Parse a tracker-rendered scalar arg into an integer.
/// Accepts both `"0x20"` and `"32"` shapes; returns `None`
/// for compound expressions (locals, addresses, …) since we
/// can't commit to a value for those.
/// Scan a function body for security-relevant syscalls and
/// return a one-line summary suitable for the head of the
/// function. Returns `None` when the function only touches
/// trivial helpers (`sol_log_`, plain memcpy / memset).
///
/// The output is grep-friendly: every interesting capability
/// shows as a fixed lowercase token (`cpi`, `pda-derive`,
/// `sysvar`, `return-data`, `pubkey-memcmp`, `log-data`).
/// Auditors can grep the dump for "function-summary: .*cpi"
/// to enumerate every function that performs a cross-program
/// invocation, without re-reading the source.
///
/// When the body contains a `sol_log_("Instruction: …", N)`
/// call (the canonical pattern Solana programs use to mark
/// their instruction-dispatch handlers), the variant name
/// rides in the caps list as `handler:<name>` — so grepping
/// `function-summary: .*handler:` enumerates every
/// instruction handler in the program.
#[must_use]
pub fn solana_function_summary(body: &[Stmt]) -> Option<String> {
    let mut caps: Vec<String> = Vec::new();
    walk_for_summary(body, &mut caps);
    if caps.is_empty() {
        return None;
    }
    caps.sort_unstable();
    caps.dedup();
    Some(format!("{TAG} function-summary: {}", caps.join(", ")))
}

fn walk_for_summary(body: &[Stmt], caps: &mut Vec<String>) {
    for stmt in body {
        match stmt {
            // Instruction-handler markers via `lddw r?,
            // "Instruction: <variant>…"`. Catches the
            // `msg!()`-formatted log paths where the eventual
            // `sol_log_` call's args[0] points at a
            // stack-allocated formatter output rather than
            // the original rodata literal.
            Stmt::Asm { text, .. } if text.starts_with("lddw ") => {
                if let Some(name) = extract_instruction_handler_from_lddw(text) {
                    caps.push(format!("handler:{name}"));
                }
            }
            Stmt::Asm { text, .. } if text.starts_with("call ") => match text.as_str() {
                "call sol_invoke_signed_rust" | "call sol_invoke_signed_c" => {
                    caps.push("cpi".into());
                }
                "call sol_try_find_program_address" | "call sol_create_program_address" => {
                    caps.push("pda-derive".into());
                }
                "call sol_get_clock_sysvar"
                | "call sol_get_rent_sysvar"
                | "call sol_get_epoch_schedule_sysvar"
                | "call sol_get_fees_sysvar" => {
                    caps.push("sysvar".into());
                }
                "call sol_set_return_data" | "call sol_get_return_data" => {
                    caps.push("return-data".into());
                }
                "call sol_memcmp_" => caps.push("memcmp".into()),
                "call sol_secp256k1_recover" => caps.push("secp256k1".into()),
                "call sol_sha256" | "call sol_keccak256" | "call sol_blake3" => {
                    caps.push("hash".into());
                }
                "call sol_log_data" => caps.push("log-data".into()),
                _ => {}
            },
            // Instruction-handler markers ride in the
            // tracker-rendered call comment beneath each
            // `call sol_log_`. The L6c+ tracker resolves r1
            // (msg) to its rodata string literal and r2 (len)
            // to a known integer, so the comment shape is
            // `→ sol_log_("…", 0xN)` — exactly what we need
            // to slice the first N chars off the string and
            // check for the "Instruction: " prefix.
            Stmt::Comment(s) => {
                if let Some(name) = extract_instruction_handler(s) {
                    caps.push(format!("handler:{name}"));
                }
            }
            Stmt::IfBlock {
                then_body,
                else_body,
                ..
            } => {
                walk_for_summary(then_body, caps);
                walk_for_summary(else_body, caps);
            }
            Stmt::WhileBlock { body: wb, .. } => walk_for_summary(wb, caps),
            _ => {}
        }
    }
}

fn parse_int_arg(text: &str) -> Option<u64> {
    let t = text.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    t.parse::<u64>().ok()
}

/// Extract a Solana instruction-handler variant name from a
/// `lddw r?, "Instruction: …"` asm line.
///
/// The L6c+ string-resolver embeds the rodata literal in the
/// `lddw`'s rendered text, so it's visible regardless of how
/// the bytes get consumed downstream — important because
/// Rust's `msg!()` formatter pipelines the literal through a
/// stack-allocated `fmt::Arguments` struct, and the eventual
/// `sol_log_` call sees the formatter's *output* (a heap
/// buffer) rather than the original literal. Scanning `lddw`
/// catches those handlers; scanning the rendered
/// `→ sol_log_(…)` comment only catches the unformatted path.
///
/// Variant-name boundary heuristic: rodata strings in
/// Solana programs are typically concatenated, so the
/// literal we see is `"Instruction: <variant>Instruction:
/// <next-variant>…"`. The next `"Instruction:"` substring
/// after the prefix is the boundary. When no second prefix
/// is found, we take the entire remainder.
#[must_use]
pub fn extract_instruction_handler_from_lddw(text: &str) -> Option<String> {
    // Match shape `lddw r?, "Instruction: …"`.
    let body = text.strip_prefix("lddw ")?;
    let (_reg, rest) = body.split_once(", ")?;
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    let after_prefix = inner.strip_prefix("Instruction: ")?;
    // Boundary: the earliest of `"Instruction:"` (next
    // concatenated variant in rodata) or ` (` (start of the
    // format-string parameter list, e.g. `" (amount="`). When
    // neither is found we refuse to commit, because the
    // rendered literal is a truncated window into rodata and
    // could span into an unrelated string downstream — which
    // would manifest as a junky variant name like
    // `FixStakeAccountconnection reset)`. Refusing those is
    // safe: cleanly-bounded callers (the `→ sol_log_(…, N)`
    // path) already pick them up.
    let by_next_marker = after_prefix.find("Instruction:");
    let by_param_open = after_prefix.find(" (");
    let end = match (by_next_marker, by_param_open) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    let name = after_prefix[..end].trim_end();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Extract a Solana instruction-handler variant name from a
/// rendered call comment.
///
/// Looks for the shape `→ sol_log_("…", N)` and, when the
/// first `N` characters of the literal start with the
/// canonical `"Instruction: "` prefix Solana programs use to
/// announce their dispatch leaf, returns the trailing
/// variant name (e.g. `"Stake (amount="`).
///
/// We tolerate the literal being longer than `N` — the L6c+
/// renderer truncates `.rodata` blobs at a fixed visible
/// width, but the trailing characters past `N` aren't part of
/// the actual logged message. We tolerate `N` being longer
/// than what the renderer kept by slicing to whichever is
/// smaller; in practice every handler-mark fits.
#[must_use]
pub fn extract_instruction_handler(comment: &str) -> Option<String> {
    // Anchor: only match the L6c+ "→ sol_log_(" call-site
    // comment shape. Other comments (signatures, semantic
    // tags) won't carry the (literal, len) pair.
    let body = comment.strip_prefix("→ sol_log_(")?.trim_end_matches(')');
    // The literal is the first comma-separated arg, quoted.
    let lit_start = body.find('"')? + 1;
    let lit_end = lit_start
        + body[lit_start..]
            .char_indices()
            .find_map(|(i, c)| (c == '"').then_some(i))?;
    let literal = &body[lit_start..lit_end];
    // The length is the second comma-separated arg.
    let tail = body[lit_end + 1..].trim_start_matches(',').trim();
    let len = parse_int_arg(tail.split(',').next()?.trim())? as usize;
    let bytes = literal.as_bytes();
    let effective_len = len.min(bytes.len());
    // Be safe with UTF-8: truncate to the largest valid char
    // boundary at-or-below `effective_len`.
    let prefix_end = (0..=effective_len)
        .rev()
        .find(|&i| literal.is_char_boundary(i))?;
    let prefix = &literal[..prefix_end];
    let name = prefix.strip_prefix("Instruction: ")?;
    // Canonicalise: clip off the format-args list when one is
    // present, so the comment-based path and the lddw-based
    // path emit the same string for the same variant.
    let canonical = match name.find(" (") {
        Some(at) => &name[..at],
        None => name,
    };
    if canonical.is_empty() {
        return None;
    }
    Some(canonical.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `slot` returns `Option<String>` so callers can plug it
    // straight into the `[Option<String>; 5]` shape that the
    // tracker hands us — wrapping/unwrapping inside each test
    // body would be noisier than the wrap here.
    #[allow(clippy::unnecessary_wraps)]
    fn slot(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn memcmp_pubkey_size_is_flagged() {
        let args = [None, None, slot("0x20"), None, None];
        let c = solana_semantic_comment("sol_memcmp_", &args).unwrap();
        assert!(c.contains("Pubkey equality check"), "{c}");
    }

    #[test]
    fn memcmp_discriminator_size_is_flagged() {
        let args = [None, None, slot("0x8"), None, None];
        let c = solana_semantic_comment("sol_memcmp_", &args).unwrap();
        assert!(c.contains("discriminator"), "{c}");
    }

    #[test]
    fn memcmp_with_unknown_n_yields_no_comment() {
        let args = [None, None, None, None, None];
        assert!(solana_semantic_comment("sol_memcmp_", &args).is_none());
    }

    #[test]
    fn cpi_call_is_tagged() {
        let args: [Option<String>; 5] = Default::default();
        let c = solana_semantic_comment("sol_invoke_signed_rust", &args).unwrap();
        assert!(c.contains("CPI"));
    }

    #[test]
    fn pda_verify_post_pass_inserts_annotation() {
        let mut body = vec![
            Stmt::Comment(format!("{TAG} PDA derivation — derives Pubkey + bump")),
            Stmt::Asm {
                text: "mov64 r1, r0".into(),
                bytes: vec![],
            },
            Stmt::Comment(format!(
                "{TAG} 32-byte compare — likely Pubkey equality check"
            )),
        ];
        annotate_pda_verify(&mut body);
        assert_eq!(body.len(), 4);
        // The "PDA verification check" comment should land
        // immediately before the 32-byte-compare tag.
        match &body[2] {
            Stmt::Comment(s) => {
                assert!(s.contains("PDA verification check"), "{s}");
            }
            _ => panic!("expected a Comment at index 2; got {:?}", body[2]),
        }
    }

    #[test]
    fn pda_verify_post_pass_skips_when_no_memcmp_follows() {
        let mut body = vec![Stmt::Comment(format!(
            "{TAG} PDA derivation — derives Pubkey + bump"
        ))];
        annotate_pda_verify(&mut body);
        assert_eq!(body.len(), 1);
    }

    #[test]
    fn parse_int_arg_decimal_and_hex() {
        assert_eq!(parse_int_arg("32"), Some(32));
        assert_eq!(parse_int_arg("0x20"), Some(32));
        assert_eq!(parse_int_arg("local_50"), None);
    }

    #[test]
    fn extract_handler_simple_with_params() {
        // "Instruction: " (13) + "Stake (amount=" (14) = 27 chars = 0x1b.
        // The trailing " (amount=" is the format-args list;
        // both extractors canonicalise to just "Stake".
        let c = r#"→ sol_log_("Instruction: Stake (amount=more rodata blob…", 0x1b)"#;
        assert_eq!(extract_instruction_handler(c), Some("Stake".to_string()));
    }

    #[test]
    fn extract_handler_decimal_len() {
        // 13 chars after the prefix = "ClaimRewards" -> "Instruction: ClaimRewards" = 25.
        let c = r#"→ sol_log_("Instruction: ClaimRewardstrailing junk", 25)"#;
        assert_eq!(
            extract_instruction_handler(c),
            Some("ClaimRewards".to_string())
        );
    }

    #[test]
    fn extract_handler_no_match_for_other_log_strings() {
        let c = r#"→ sol_log_("error: bad input", 0x10)"#;
        assert_eq!(extract_instruction_handler(c), None);
    }

    #[test]
    fn extract_handler_no_match_for_non_log_comments() {
        let c = "[solana] CPI — signed cross-program invocation";
        assert_eq!(extract_instruction_handler(c), None);
    }

    #[test]
    fn lddw_extract_param_boundary() {
        // " (" delimits the variant name from its format-args list.
        let t = r#"lddw r1, "Instruction: Stake (amount=""#;
        assert_eq!(
            extract_instruction_handler_from_lddw(t),
            Some("Stake".to_string())
        );
    }

    #[test]
    fn lddw_extract_first_of_concatenated_variants() {
        let t = r#"lddw r1, "Instruction: CompleteUnstakeInstruction: CancelUnstakeRequestInstruction: CloseStakeAccountInstr""#;
        assert_eq!(
            extract_instruction_handler_from_lddw(t),
            Some("CompleteUnstake".to_string())
        );
    }

    #[test]
    fn lddw_extract_refuses_truncated_blob_with_no_boundary() {
        // No second "Instruction:" and no " (" — could be a
        // truncated rodata window into an unrelated string.
        let t = r#"lddw r1, "Instruction: FixStakeAccountconnection reset) when slicing""#;
        assert_eq!(extract_instruction_handler_from_lddw(t), None);
    }

    #[test]
    fn lddw_extract_rejects_non_instruction_strings() {
        let t = r#"lddw r1, "some other string""#;
        assert_eq!(extract_instruction_handler_from_lddw(t), None);
    }

    #[test]
    fn lddw_extract_rejects_non_lddw_asm() {
        let t = r#"mov64 r1, "Instruction: Stake (a""#;
        assert_eq!(extract_instruction_handler_from_lddw(t), None);
    }

    #[test]
    fn function_summary_picks_up_handler_from_lddw() {
        let body = vec![Stmt::Asm {
            text: r#"lddw r1, "Instruction: InitializePool (tau=""#.into(),
            bytes: vec![],
        }];
        let s = solana_function_summary(&body).unwrap();
        assert!(s.contains("handler:InitializePool"), "{s}");
    }

    #[test]
    fn function_summary_picks_up_handler() {
        // "Instruction: " (13) + "Unstake (amount=" (16) = 29 chars = 0x1d.
        // Variant canonicalises to "Unstake" (param list stripped).
        let body = vec![
            Stmt::Asm {
                text: "call sol_log_".into(),
                bytes: vec![],
            },
            Stmt::Comment(r#"→ sol_log_("Instruction: Unstake (amount=more rodata", 0x1d)"#.into()),
        ];
        let s = solana_function_summary(&body).unwrap();
        assert!(s.contains("handler:Unstake"), "{s}");
        assert!(!s.contains("handler:Unstake ("), "{s}");
    }

    #[test]
    fn handler_banners_insert_above_each_marker() {
        let mut body = vec![
            Stmt::Asm {
                text: r#"lddw r1, "Instruction: Stake (amount=""#.into(),
                bytes: vec![],
            },
            Stmt::Asm {
                text: "call sol_log_".into(),
                bytes: vec![],
            },
            Stmt::Asm {
                text: r#"lddw r1, "Instruction: Unstake (amount=""#.into(),
                bytes: vec![],
            },
        ];
        annotate_handler_banners(&mut body);
        assert_eq!(body.len(), 5);
        match &body[0] {
            Stmt::Comment(s) => assert!(s.contains("=== handler: Stake ==="), "{s}"),
            _ => panic!("expected a banner Comment at index 0; got {:?}", body[0]),
        }
        match &body[3] {
            Stmt::Comment(s) => assert!(s.contains("=== handler: Unstake ==="), "{s}"),
            _ => panic!("expected a banner Comment at index 3; got {:?}", body[3]),
        }
    }

    #[test]
    fn handler_banners_dedup_consecutive_same_variant() {
        // Two consecutive markers for the same variant — only
        // one banner should land.
        let mut body = vec![
            Stmt::Asm {
                text: r#"lddw r1, "Instruction: ClaimRewardsInstruction: DepositRewards""#.into(),
                bytes: vec![],
            },
            Stmt::Comment(r#"→ sol_log_("Instruction: ClaimRewardsInstruction:", 0x19)"#.into()),
        ];
        annotate_handler_banners(&mut body);
        let banners: Vec<&String> = body
            .iter()
            .filter_map(|s| match s {
                Stmt::Comment(t) if t.contains("=== handler: ClaimRewards ===") => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(
            banners.len(),
            1,
            "expected exactly one banner, got {body:?}"
        );
    }
}

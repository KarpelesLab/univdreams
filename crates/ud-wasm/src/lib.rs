//! WebAssembly bindings for the univdreams pipeline.
//!
//! Exposes two functions to the JS playground at `site/playground/`:
//!
//! * [`decompile`] takes binary bytes and a format hint, dispatches
//!   to the appropriate format-specific decompiler, and returns
//!   `.ud` source text.
//! * [`compile`] takes `.ud` source text, parses it, reads
//!   `@module.format` to pick a backend, and returns the rebuilt
//!   binary bytes.
//!
//! Errors get stringified at the JS boundary — the playground only
//! ever needs a human-readable message.

use wasm_bindgen::prelude::*;

use ud_ast::{Module, Value};
use ud_format::solana::LoaderKind;
use ud_translate::compile::AsmWarning;

/// Decompile a binary blob to `.ud` source.
///
/// `format` picks the decompile path:
///
/// * `"auto"` — header-detect ELF64-LE, PE, thin Mach-O, or WASM.
///   Refuses inputs without a recognisable header so that arbitrary
///   bytes (which 6502 raw images, by definition, are) can't be
///   silently misinterpreted as code.
/// * `"elf"` — force ELF64-LE.
/// * `"pe"` — force PE/COFF.
/// * `"macho"` — force thin 64-bit Mach-O.
/// * `"wasm"` — force a WebAssembly module.
/// * `"raw-6502"` — interpret as a raw 6502 image whose load address
///   is derived from the file length (top of the 16-bit address
///   space).
#[wasm_bindgen]
pub fn decompile(bytes: &[u8], format: &str) -> Result<String, JsError> {
    set_panic_hook();
    match format {
        "auto" => decompile_auto(bytes),
        "elf" => decompile_as_elf(bytes),
        "pe" => decompile_as_pe(bytes),
        "macho" => decompile_as_macho(bytes),
        "wasm" => decompile_as_wasm(bytes),
        "raw-6502" => decompile_as_raw_6502(bytes),
        other => Err(JsError::new(&format!(
            "unsupported format hint {other:?} (expected \"auto\", \"elf\", \"pe\", \"macho\", \"wasm\", or \"raw-6502\")"
        ))),
    }
}

fn decompile_auto(bytes: &[u8]) -> Result<String, JsError> {
    if ud_format::elf::is_elf64_le(bytes) {
        return decompile_as_elf(bytes);
    }
    if ud_format::pe::is_pe(bytes) {
        return decompile_as_pe(bytes);
    }
    if ud_format::macho::is_macho64(bytes) {
        return decompile_as_macho(bytes);
    }
    if ud_format::wasm::is_wasm(bytes) {
        return decompile_as_wasm(bytes);
    }
    Err(JsError::new(
        "auto-detect found no ELF / PE / Mach-O / WASM header. Pick an explicit format if this is a raw image (e.g. 6502).",
    ))
}

fn decompile_as_elf(bytes: &[u8]) -> Result<String, JsError> {
    let elf = ud_format::elf::Elf64File::parse(bytes)
        .map_err(|e| JsError::new(&format!("parse ELF: {e}")))?;
    ud_translate::decompile::decompile_to_text(&elf)
        .map_err(|e| JsError::new(&format!("decompile ELF: {e}")))
}

fn decompile_as_pe(bytes: &[u8]) -> Result<String, JsError> {
    let pe =
        ud_format::pe::PeFile::parse(bytes).map_err(|e| JsError::new(&format!("parse PE: {e}")))?;
    Ok(ud_translate::decompile::decompile_pe_to_text(&pe))
}

fn decompile_as_macho(bytes: &[u8]) -> Result<String, JsError> {
    let macho = ud_format::macho::MachoFile::parse(bytes)
        .map_err(|e| JsError::new(&format!("parse Mach-O: {e}")))?;
    Ok(ud_translate::decompile::decompile_macho_to_text(&macho))
}

fn decompile_as_wasm(bytes: &[u8]) -> Result<String, JsError> {
    let wasm = ud_format::wasm::WasmFile::parse(bytes)
        .map_err(|e| JsError::new(&format!("parse WASM: {e}")))?;
    Ok(ud_translate::decompile::decompile_wasm_to_text(&wasm))
}

fn decompile_as_raw_6502(bytes: &[u8]) -> Result<String, JsError> {
    let load_addr = raw_6502_load_addr(bytes).ok_or_else(|| {
        JsError::new(
            "6502 raw image: file must be 6..=65536 bytes and the reset vector at $FFFC must point inside the image",
        )
    })?;
    let image = ud_format::raw::RawImage::new(bytes.to_vec(), load_addr);
    ud_translate::decompile::decompile_raw_6502_to_text(&image)
        .map_err(|e| JsError::new(&format!("decompile 6502 raw: {e}")))
}

/// Compile `.ud` source to binary bytes. Dispatches on the parsed
/// `@module.format` field — `"elf"` → ELF, `"pe"` → PE, `"raw"` →
/// raw image. Missing or unknown formats fail.
///
/// `verify_asm` warnings are appended to the JS error message when
/// the lower step itself fails, so the playground surfaces both
/// the hard failure and the soft mismatches together.
#[wasm_bindgen]
pub fn compile(source: &str) -> Result<Vec<u8>, JsError> {
    set_panic_hook();
    let ast = ud_translate::compile::parse(source)
        .map_err(|e| JsError::new(&format!("parse .ud: {e}")))?;
    let format = read_string(&ast.module, "format").ok_or_else(|| {
        JsError::new(
            "missing `@module.format` (expected \"elf\", \"pe\", \"macho\", \"wasm\", or \"raw\")",
        )
    })?;
    let warnings = ud_translate::compile::verify_asm(&ast);
    let bytes = match format.as_str() {
        "elf" => ud_translate::compile::lower_to_elf(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to ELF: {e}"), &warnings))),
        "pe" => ud_translate::compile::lower_to_pe(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to PE: {e}"), &warnings))),
        "macho" => ud_translate::compile::lower_to_macho(&ast).map_err(|e| {
            JsError::new(&with_warnings(&format!("lower to Mach-O: {e}"), &warnings))
        }),
        "wasm" => ud_translate::compile::lower_to_wasm(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to WASM: {e}"), &warnings))),
        "raw" => ud_translate::compile::lower_to_raw(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to raw: {e}"), &warnings))),
        other => Err(JsError::new(&format!(
            "unsupported `@module.format` value {other:?} (expected \"elf\", \"pe\", \"macho\", \"wasm\", or \"raw\")"
        ))),
    }?;
    Ok(bytes)
}

/// Return verify-asm warnings without invoking the lower step.
/// Surfaced as a separate JS function so the playground can show
/// them inline as the user types, distinct from compile failures.
#[wasm_bindgen]
pub fn verify(source: &str) -> Result<String, JsError> {
    set_panic_hook();
    let ast = ud_translate::compile::parse(source)
        .map_err(|e| JsError::new(&format!("parse .ud: {e}")))?;
    let warnings = ud_translate::compile::verify_asm(&ast);
    Ok(format_warnings(&warnings))
}

/// Classify a Solana account's owner pubkey against the three
/// loaders univdreams knows how to strip.
///
/// `owner` is the base58 string Solana RPC returns in the
/// `value.owner` field of `getAccountInfo`. The browser
/// playground passes it through verbatim — no decoding
/// needed.
///
/// Returns one of `"bpf_loader_2"`, `"upgradeable"`,
/// `"loader_v4"`, or `"unknown"`. The JS side dispatches on
/// the result: BpfLoader2 / LoaderV4 strip immediately,
/// Upgradeable requires a second RPC fetch (see
/// [`solana_programdata_pubkey_base58`]).
#[wasm_bindgen]
#[must_use]
pub fn solana_classify_loader(owner: &str) -> String {
    set_panic_hook();
    match ud_format::solana::classify_loader(owner) {
        LoaderKind::BpfLoader2 => "bpf_loader_2",
        LoaderKind::Upgradeable => "upgradeable",
        LoaderKind::LoaderV4 => "loader_v4",
        LoaderKind::Unknown => "unknown",
    }
    .to_string()
}

/// For an upgradeable Program account, return the base58
/// pubkey of the ProgramData account it points at. JS uses
/// this to issue the second `getAccountInfo` call.
#[wasm_bindgen]
pub fn solana_programdata_pubkey_base58(program_data: &[u8]) -> Result<String, JsError> {
    set_panic_hook();
    let pk = ud_format::solana::programdata_pubkey(program_data)
        .map_err(|e| JsError::new(&format!("Solana Program account: {e}")))?;
    Ok(bs58::encode(pk).into_string())
}

/// Strip the loader-state wrapping. `loader` is one of the
/// strings [`solana_classify_loader`] returns
/// (`"bpf_loader_2"`, `"upgradeable"`, `"loader_v4"`). For
/// the upgradeable kind, pass the **ProgramData** account's
/// raw data (NOT the original Program account's) — JS is
/// responsible for fetching that account first.
#[wasm_bindgen]
pub fn solana_strip_elf(account_data: &[u8], loader: &str) -> Result<Vec<u8>, JsError> {
    set_panic_hook();
    let stripped: &[u8] = match loader {
        "bpf_loader_2" => ud_format::solana::strip_bpf_loader_v2(account_data)
            .map_err(|e| JsError::new(&format!("BPFLoader2: {e}")))?,
        "upgradeable" => ud_format::solana::strip_bpf_loader_upgradeable(account_data)
            .map_err(|e| JsError::new(&format!("BPFLoaderUpgradeable: {e}")))?,
        "loader_v4" => ud_format::solana::strip_loader_v4(account_data)
            .map_err(|e| JsError::new(&format!("LoaderV4: {e}")))?,
        other => {
            return Err(JsError::new(&format!(
                "unknown loader hint {other:?} (expected \"bpf_loader_2\", \"upgradeable\", \"loader_v4\")"
            )))
        }
    };
    Ok(stripped.to_vec())
}

fn with_warnings(msg: &str, warnings: &[AsmWarning]) -> String {
    if warnings.is_empty() {
        msg.into()
    } else {
        let mut out = String::from(msg);
        out.push('\n');
        out.push_str(&format_warnings(warnings));
        out
    }
}

fn format_warnings(warnings: &[AsmWarning]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for (i, w) in warnings.iter().enumerate() {
        if i > 0 {
            s.push('\n');
        }
        let _ = write!(s, "{w:?}");
    }
    s
}

fn read_string(module: &Module, name: &str) -> Option<String> {
    module.fields.iter().find_map(|f| {
        if f.name != name {
            return None;
        }
        let Value::String(s) = &f.value else {
            return None;
        };
        Some(s.clone())
    })
}

/// 6502 raw-image load-address heuristic. Mirrors
/// `ud_cli::raw_6502_load_addr` but duplicated here so the WASM
/// build doesn't pull `clap` (and the rest of the CLI deps) in.
///
/// Convention: a 6502 image of length L "wants" to live so that it
/// ends at `$FFFF`, putting the canonical NMI/RESET/IRQ vectors at
/// `$FFFA..$FFFF`. We then sanity-check that the reset vector at
/// `$FFFC` points back inside the image — a cheap "is this even
/// 6502 code" filter that pseudoinputs like `0`-filled regions
/// fail.
fn raw_6502_load_addr(bytes: &[u8]) -> Option<u64> {
    let len = bytes.len();
    if !(6..=0x10000).contains(&len) {
        return None;
    }
    let load_addr = 0x10000u64 - len as u64;
    let end = 0x10000u64;
    let reset_lo_off = usize::try_from(0xFFFCu64 - load_addr).ok()?;
    let reset_hi_off = reset_lo_off.checked_add(1)?;
    let lo = u64::from(*bytes.get(reset_lo_off)?);
    let hi = u64::from(*bytes.get(reset_hi_off)?);
    let reset = (hi << 8) | lo;
    if reset < load_addr || reset >= end {
        None
    } else {
        Some(load_addr)
    }
}

/// Wire the panic hook once so panics show up in the browser
/// console with a useful stack trace instead of `unreachable
/// executed`.
fn set_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        console_error_panic_hook::set_once();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompile_then_compile_elf_round_trips() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/hello-gcc13-O0");
        let Ok(bytes) = std::fs::read(path) else {
            return; // fixture missing; skip
        };
        let text = decompile(&bytes, "auto").expect("decompile");
        let rebuilt = compile(&text).expect("compile");
        assert_eq!(
            rebuilt,
            bytes,
            "round-trip diverged: input {} bytes, rebuilt {} bytes",
            bytes.len(),
            rebuilt.len()
        );
    }

    // Error-path tests can't run natively: `JsError::new` is a
    // wasm-bindgen import that panics on non-wasm targets. The
    // success-path round-trip above exercises both functions
    // through the full pipeline, which is what we actually care
    // about. The auto-refuses-6502 behaviour is tested manually
    // in the playground.
}

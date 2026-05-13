//! WebAssembly bindings for the univdreams pipeline.
//!
//! Exposes two functions to the JS playground at `site/playground/`:
//!
//! * [`decompile`] takes binary bytes (uploaded file contents),
//!   detects ELF / PE / 6502-raw via the same byte-signature checks
//!   the CLI uses, and returns `.ud` source text.
//! * [`compile`] takes `.ud` source text, parses it, reads
//!   `@module.format` to pick a backend, and returns the rebuilt
//!   binary bytes.
//!
//! Errors get stringified at the JS boundary — the playground only
//! ever needs a human-readable message.

use wasm_bindgen::prelude::*;

use ud_ast::{Module, Value};
use ud_compile::AsmWarning;

/// Decompile a binary blob to `.ud` source. Routes on byte
/// signature: ELF64-LE → PE → 6502-raw (16K-and-under image whose
/// reset vector points inside itself). Unrecognised formats fail.
#[wasm_bindgen]
pub fn decompile(bytes: &[u8]) -> Result<String, JsError> {
    set_panic_hook();
    if ud_format_elf::is_elf64_le(bytes) {
        let elf = ud_format_elf::Elf64File::parse(bytes)
            .map_err(|e| JsError::new(&format!("parse ELF: {e}")))?;
        return ud_decompile::decompile_to_text(&elf)
            .map_err(|e| JsError::new(&format!("decompile ELF: {e}")));
    }
    if ud_format_pe::is_pe(bytes) {
        let pe = ud_format_pe::PeFile::parse(bytes)
            .map_err(|e| JsError::new(&format!("parse PE: {e}")))?;
        return Ok(ud_decompile::decompile_pe_to_text(&pe));
    }
    if ud_format_macho::is_macho64(bytes) {
        let macho = ud_format_macho::MachoFile::parse(bytes)
            .map_err(|e| JsError::new(&format!("parse Mach-O: {e}")))?;
        return Ok(ud_decompile::decompile_macho_to_text(&macho));
    }
    if let Some(load_addr) = raw_6502_load_addr(bytes) {
        let image = ud_format_raw::RawImage::new(bytes.to_vec(), load_addr);
        return ud_decompile::decompile_raw_6502_to_text(&image)
            .map_err(|e| JsError::new(&format!("decompile 6502 raw: {e}")));
    }
    Err(JsError::new(
        "unrecognised binary format (expected ELF64-LE, PE, Mach-O, or a 6502 raw image)",
    ))
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
    let ast = ud_compile::parse(source).map_err(|e| JsError::new(&format!("parse .ud: {e}")))?;
    let format = read_string(&ast.module, "format").ok_or_else(|| {
        JsError::new("missing `@module.format` (expected \"elf\", \"pe\", \"macho\", or \"raw\")")
    })?;
    let warnings = ud_compile::verify_asm(&ast);
    let bytes = match format.as_str() {
        "elf" => ud_compile::lower_to_elf(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to ELF: {e}"), &warnings))),
        "pe" => ud_compile::lower_to_pe(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to PE: {e}"), &warnings))),
        "macho" => ud_compile::lower_to_macho(&ast).map_err(|e| {
            JsError::new(&with_warnings(&format!("lower to Mach-O: {e}"), &warnings))
        }),
        "raw" => ud_compile::lower_to_raw(&ast)
            .map_err(|e| JsError::new(&with_warnings(&format!("lower to raw: {e}"), &warnings))),
        other => Err(JsError::new(&format!(
            "unsupported `@module.format` value {other:?} (expected \"elf\", \"pe\", \"macho\", or \"raw\")"
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
    let ast = ud_compile::parse(source).map_err(|e| JsError::new(&format!("parse .ud: {e}")))?;
    let warnings = ud_compile::verify_asm(&ast);
    Ok(format_warnings(&warnings))
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

/// 6502 raw-image detection — identical to `ud_cli::raw_6502_load_addr`.
/// Duplicated here to avoid pulling clap into the WASM build via the
/// CLI crate's dependency graph.
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
        let text = decompile(&bytes).expect("decompile");
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
    // about. Error formatting is tested manually in the playground.
}

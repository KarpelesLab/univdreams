//! Codec corpus test runner.
//!
//! Walks `testdata/external/codec-corpus.toml` and, for every
//! `arch = "i386"` entry, fetches the DLL (HTTPS + local cache)
//! and tries to load it into the sandbox. Records:
//!
//! * `loaded` — `Sandbox::load` succeeded.
//! * `dll_main_ok` — `DllMain(DLL_PROCESS_ATTACH)` returned.
//! * `unresolved_imports` — the set of `(dll, function)` pairs
//!   the codec imports that the current stub registry didn't
//!   cover. Drives the "which Win32 stub to add next" prioritisation.
//!
//! Marked `#[ignore]`: opt-in via
//! `cargo test --release -p ud-emulator codec_corpus -- --ignored --nocapture`.
//! Most days you don't want to hit 60+ HTTPS endpoints for a
//! routine `cargo test`. CI flips it on.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;
use ud_emulator::Sandbox;

#[derive(Deserialize, Debug)]
struct CodecManifest {
    codec: Vec<Codec>,
}

#[derive(Deserialize, Debug)]
struct Codec {
    name: String,
    base_url: String,
    family: String,
    kind: String,
    arch: String,
    #[serde(default)]
    fourcc: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").is_file() && p.join("crates").is_dir())
        .map(std::path::Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn load_manifest() -> CodecManifest {
    let path = workspace_root().join("testdata/external/codec-corpus.toml");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Outcome {
    fetched: bool,
    loaded: bool,
    dll_main_ok: bool,
    /// Codec exports a VfW `DriverProc` entry point.
    has_driver_proc: bool,
    /// VfW probe outcome: the codec accepted `ICOpen` in
    /// decompress mode and handed back a non-zero `HIC`. Only
    /// attempted when `dll_main_ok` AND there were no
    /// unresolved imports (otherwise the synthetic zero-stubs
    /// would corrupt the IC* dispatch).
    vfw_open_ok: bool,
    /// Non-empty when load or DllMain failed.
    error: Option<String>,
    /// `(dll, function)` pairs the codec imports that the
    /// current stub registry doesn't resolve. Surfaced
    /// directly from the load error when it's
    /// `UnknownImport`; for other failure modes, empty.
    unresolved_imports: BTreeSet<(String, String)>,
}

fn run_one(codec: &Codec) -> Outcome {
    let mut out = Outcome::default();

    let bytes = match common::fetch_or_load(&codec.base_url, &codec.name) {
        Ok(b) => b,
        Err(e) => {
            out.error = Some(format!("fetch: {e}"));
            return out;
        }
    };
    out.fetched = true;

    // `Sandbox::load` is one-shot per sandbox (it maps sections
    // at fixed virtual addresses), so a retry loop needs a
    // FRESH sandbox each iteration. On every `UnknownImport`
    // we record the (dll, name) pair, then build a new sandbox
    // pre-loaded with synthetic zero-returning stubs for every
    // import discovered so far and try again. The loader is
    // deterministic, so each retry advances at least one
    // unknown — convergence is bounded by the import-table
    // entry count.
    let mut missing: BTreeSet<(String, String)> = BTreeSet::new();
    let img;
    let mut runner;
    loop {
        runner = Sandbox::new();
        for (dll, name) in &missing {
            runner.registry.register(dll, name, stub_zero, 0);
        }
        match runner.load(&codec.name, &bytes) {
            Ok(i) => {
                img = i;
                break;
            }
            Err(ud_emulator::Error::PeLoader(
                ud_emulator::pe::PeError::UnknownImportFunction { dll, name },
            )) => {
                let pair = (dll.clone(), name.clone());
                if !missing.insert(pair) {
                    // Re-seeing the same (dll, name) means we
                    // didn't actually register it — likely the
                    // name uses an ordinal or some other shape
                    // the loader doesn't satisfy via the stub
                    // registry. Bail.
                    out.error = Some(format!(
                        "load: {dll}!{name} unregisterable via synthetic stub"
                    ));
                    out.unresolved_imports = missing;
                    return out;
                }
                if missing.len() > 1024 {
                    out.error = Some("load: too many distinct imports".into());
                    out.unresolved_imports = missing;
                    return out;
                }
            }
            Err(e) => {
                out.error = Some(format!("load: {e}"));
                out.unresolved_imports = missing;
                return out;
            }
        }
    }
    out.loaded = true;
    out.unresolved_imports = missing;

    // Cap the run to keep adversarial loops bounded. Some
    // codecs (wmvdecod.dll, ~6M steps) do heavy CRT init and
    // table generation in DllMain; 10M covers them with margin
    // and still bounds malicious infinite loops.
    runner.host.instruction_budget = Some(10_000_000);
    match runner.call_dll_main(&img, ud_emulator::DLL_PROCESS_ATTACH) {
        Ok(_) => {
            out.dll_main_ok = true;
        }
        Err(e) => {
            out.error = Some(format!("dll_main: {e}"));
        }
    }

    // VfW probe — only meaningful when the codec exports a
    // `DriverProc` AND the real registry fully satisfied its
    // imports (no synthetic zero-stubs in the way, which would
    // corrupt the IC* dispatch). Drive `install_codec` +
    // `ICOpen(VIDC, fourcc, ICMODE_DECOMPRESS)` and record
    // whether the codec handed back a live `HIC`.
    out.has_driver_proc = img.export("DriverProc").is_some();
    if out.dll_main_ok
        && out.unresolved_imports.is_empty()
        && out.has_driver_proc
        && runner.install_codec(&img).is_ok()
    {
        const ICMODE_DECOMPRESS: u32 = 1;
        let fcc_type = u32::from_le_bytes(*b"VIDC");
        let fcc_handler = fourcc_to_u32(&codec.fourcc.clone().unwrap_or_default());
        runner.host.instruction_budget = Some(20_000_000);
        if let Ok(hic) = runner.ic_open(fcc_type, fcc_handler, ICMODE_DECOMPRESS) {
            out.vfw_open_ok = hic != 0;
        }
    }
    out
}

/// Pack a (up to 4-char) FourCC string into a little-endian
/// `u32`, space-padded — `"MP43"` → `0x3334_504d`.
fn fourcc_to_u32(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

/// Synthetic stub that always returns 0. Used by the corpus
/// runner to probe the full set of unresolved imports without
/// patching the production stub registry. The `Result` wrap
/// is dictated by the `StubFn` signature.
#[allow(clippy::unnecessary_wraps)]
fn stub_zero(
    _cpu: &mut ud_emulator::emulator::Cpu,
    _mmu: &mut ud_emulator::emulator::Mmu,
    _state: &mut ud_emulator::win32::HostState,
    _registry: &ud_emulator::win32::Registry,
) -> Result<u32, ud_emulator::win32::Win32Error> {
    Ok(0)
}

#[test]
#[ignore = "fetches the 60+ codec DLLs from samples.oxideav.org; opt-in via --ignored"]
fn codec_corpus_load_and_dll_main() {
    let manifest = load_manifest();
    println!("Codec corpus: {} entries", manifest.codec.len());

    // i386_total, loaded, dll_main_ok, skipped, vfw_codecs, vfw_open_ok
    let mut totals = [0usize; 6];
    let mut unresolved_global: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut report_rows: Vec<String> = Vec::new();

    for codec in &manifest.codec {
        if codec.arch != "i386" {
            totals[3] += 1;
            let note = codec
                .notes
                .as_deref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default();
            println!(
                "  SKIP {} ({} {} arch={}){note}",
                codec.name, codec.family, codec.kind, codec.arch,
            );
            continue;
        }
        totals[0] += 1;

        let outcome = run_one(codec);
        if outcome.loaded {
            totals[1] += 1;
        }
        if outcome.dll_main_ok {
            totals[2] += 1;
        }
        if outcome.has_driver_proc {
            totals[4] += 1;
        }
        if outcome.vfw_open_ok {
            totals[5] += 1;
        }
        for imp in &outcome.unresolved_imports {
            *unresolved_global.entry(imp.clone()).or_default() += 1;
        }

        let status = if outcome.dll_main_ok {
            "ok"
        } else if outcome.loaded {
            "load-only"
        } else if outcome.fetched {
            "load-fail"
        } else {
            "fetch-fail"
        };
        let vfw = if outcome.vfw_open_ok {
            " [VfW ICOpen ok]"
        } else if outcome.has_driver_proc {
            " [VfW DriverProc, ICOpen not confirmed]"
        } else {
            ""
        };
        let line = format!(
            "  {status:10} {} ({} unresolved imports){vfw}{}",
            codec.name,
            outcome.unresolved_imports.len(),
            outcome
                .error
                .as_ref()
                .map(|e| format!("  — {e}"))
                .unwrap_or_default(),
        );
        report_rows.push(line);
    }

    for r in &report_rows {
        println!("{r}");
    }
    println!();
    println!("Totals (i386 only):");
    println!(
        "  fetched + loaded:           {} / {}",
        totals[1], totals[0]
    );
    println!(
        "  fetched + DllMain returned: {} / {}",
        totals[2], totals[0]
    );
    println!(
        "  VfW codecs (DriverProc):    {} ({} accepted ICOpen)",
        totals[4], totals[5]
    );
    println!("  skipped (non-i386 / win16): {}", totals[3]);

    if !unresolved_global.is_empty() {
        println!();
        println!("Unresolved imports across the corpus (top 40, ordered by codec hit count):");
        let mut sorted: Vec<_> = unresolved_global.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for ((dll, name), count) in sorted.into_iter().take(40) {
            println!("  {count:4}× {dll}!{name}");
        }
    }
}

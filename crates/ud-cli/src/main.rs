use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "ud",
    version,
    about = "univdreams: a universal compiler/decompiler suite",
    long_about = "Decompile binaries to a directive-rich C-like source language and \
                  recompile to byte-identical binaries."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the full pipeline (decompile then compile) and verify byte-equality
    /// with the input.
    ///
    /// Without `--through-source`, routes through `ud-format-elf`'s
    /// parse + write-to-vec — defends the format-level round-trip.
    ///
    /// With `--through-source`, routes through the full source pipeline:
    /// decompile → emit → parse → lower_to_elf. Surfaces verify-asm
    /// warnings and a byte-diff offset when the result diverges; never
    /// fails on warnings, only on hard pipeline errors.
    Roundtrip {
        /// Input binary.
        input: PathBuf,

        /// Where to write the rebuilt binary. Defaults to `<input>.rebuilt`.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Route through the source language (decompile → text → parse →
        /// lower_to_elf) instead of the format-level path.
        #[arg(long)]
        through_source: bool,
    },

    /// Decompile a binary to `.ud` source.
    ///
    /// v0 emits one `fn` block per discovered function with `@asm("…")`
    /// lines for every instruction. Padding between functions and
    /// non-text sections aren't represented yet.
    Decompile {
        /// Input binary.
        input: PathBuf,

        /// Where to write the `.ud` source. Defaults to stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Verify a `.ud` source file: parse, then check every `@asm`
    /// line's text against the canonical form for its pinned bytes.
    /// Warnings go to stderr; the exit code is non-zero only on
    /// parse errors, not on warnings.
    Verify {
        /// `.ud` source file.
        input: PathBuf,
    },

    /// Compile a `.ud` source file back to a binary. Dispatches on
    /// the `@module.format` field — `"elf"` → ELF, `"pe"` → PE,
    /// `"macho"` → Mach-O, `"raw"` → raw image.
    ///
    /// Editing the source between decompile and compile is the
    /// supported workflow: PC-relative encoders (jmp, jcc, call,
    /// switch) re-resolve at lower time so moving a function or
    /// growing its body produces a working binary.
    Compile {
        /// `.ud` source file.
        input: PathBuf,

        /// Where to write the rebuilt binary. Defaults to
        /// `<input>.bin`.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Run a binary inside the bounded i386 emulator and report
    /// what it does — Win32 calls, code coverage, traps. Treats
    /// the input as untrusted (it's the whole point of a
    /// sandboxed run) but inspects the structured execution
    /// trace, not the raw output. Today supports PE32 DLLs;
    /// the run drives `DllMain(PROCESS_ATTACH)` and reports
    /// every Win32 API the codec touched plus a coverage
    /// summary.
    Analyze {
        /// PE32 DLL (or DLL-shaped binary) to analyse.
        input: PathBuf,

        /// Cap the run at this many guest instructions.
        /// `DllMain` of a CRT-driven codec usually fits in a
        /// few million; the cap is just a safety net for
        /// adversarial samples that loop.
        #[arg(long, default_value_t = 5_000_000)]
        max_instructions: u64,

        /// Emit a JSON report on stdout instead of the
        /// human-readable summary. Suitable for piping into
        /// downstream analysis tooling.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ud: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Roundtrip {
            input,
            out,
            through_source,
        } => {
            let output = out.unwrap_or_else(|| {
                let mut p = input.clone().into_os_string();
                p.push(".rebuilt");
                PathBuf::from(p)
            });
            if through_source {
                let report =
                    ud_cli::roundtrip_through_source(&input, &output).with_context(|| {
                        format!(
                            "source round-trip from {} to {}",
                            input.display(),
                            output.display()
                        )
                    })?;
                for w in &report.warnings {
                    eprintln!("warning: {}", format_warning(w));
                }
                if !report.warnings.is_empty() {
                    eprintln!("({} verify warning(s))", report.warnings.len());
                }
                if report.byte_identical {
                    println!(
                        "source round-trip ok: {} == {} ({} bytes)",
                        input.display(),
                        output.display(),
                        report.input_len,
                    );
                } else {
                    let offset = report
                        .first_diff_offset
                        .map_or("?".into(), |o| format!("0x{o:x}"));
                    println!(
                        "source round-trip differs: {} != {} (input {} bytes, output {} bytes; first diff at {})",
                        input.display(),
                        output.display(),
                        report.input_len,
                        report.output_len,
                        offset,
                    );
                    if let Some(ctx) = &report.diff_context {
                        eprintln!(
                            "input  @ 0x{:x}: {}",
                            ctx.window_start,
                            hex_window(&ctx.input_window)
                        );
                        eprintln!(
                            "output @ 0x{:x}: {}",
                            ctx.window_start,
                            hex_window(&ctx.output_window)
                        );
                    }
                }
                Ok(())
            } else {
                ud_cli::roundtrip(&input, &output).with_context(|| {
                    format!(
                        "round-trip from {} to {}",
                        input.display(),
                        output.display()
                    )
                })?;
                println!("round-trip ok: {} == {}", input.display(), output.display());
                Ok(())
            }
        }
        Command::Decompile { input, out } => {
            let bytes =
                std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            let source = if ud_format_elf::is_elf64_le(&bytes) {
                let elf = ud_format_elf::Elf64File::parse(&bytes)
                    .with_context(|| format!("parse {} as ELF", input.display()))?;
                ud_decompile::decompile_to_text(&elf)
                    .with_context(|| format!("decompile {}", input.display()))?
            } else if ud_format_pe::is_pe(&bytes) {
                let pe = ud_format_pe::PeFile::parse(&bytes)
                    .with_context(|| format!("parse {} as PE", input.display()))?;
                ud_decompile::decompile_pe_to_text(&pe)
            } else if ud_format_macho::is_macho64(&bytes) {
                let macho = ud_format_macho::MachoFile::parse(&bytes)
                    .with_context(|| format!("parse {} as Mach-O", input.display()))?;
                ud_decompile::decompile_macho_to_text(&macho)
            } else if let Some(load_addr) = ud_cli::raw_6502_load_addr(&bytes) {
                let image = ud_format_raw::RawImage::new(bytes, load_addr);
                ud_decompile::decompile_raw_6502_to_text(&image)
                    .with_context(|| format!("decompile {} as 6502 raw", input.display()))?
            } else {
                anyhow::bail!(
                    "unrecognised binary format: {} (expected ELF, PE, Mach-O, or 6502 raw image)",
                    input.display()
                );
            };
            if let Some(path) = out {
                std::fs::write(&path, source)
                    .with_context(|| format!("write {}", path.display()))?;
            } else {
                use std::io::Write as _;
                std::io::stdout().write_all(source.as_bytes())?;
            }
            Ok(())
        }
        Command::Verify { input } => {
            let text = std::fs::read_to_string(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let ast =
                ud_compile::parse(&text).with_context(|| format!("parse {}", input.display()))?;
            let warnings = ud_compile::verify_asm(&ast);
            if warnings.is_empty() {
                println!(
                    "ok: {} ({} item{})",
                    input.display(),
                    ast.items.len(),
                    if ast.items.len() == 1 { "" } else { "s" }
                );
                return Ok(());
            }
            for w in &warnings {
                eprintln!("{}", format_warning(w));
            }
            eprintln!("{} warning(s) in {}", warnings.len(), input.display());
            Ok(())
        }
        Command::Compile { input, out } => {
            let output = out.unwrap_or_else(|| {
                let mut p = input.clone().into_os_string();
                p.push(".bin");
                PathBuf::from(p)
            });
            let text = std::fs::read_to_string(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let ast =
                ud_compile::parse(&text).with_context(|| format!("parse {}", input.display()))?;
            let format = ast
                .module
                .fields
                .iter()
                .find(|f| f.name == "format")
                .and_then(|f| match &f.value {
                    ud_ast::Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("`@module.format` is missing — expected \"elf\", \"pe\", \"macho\", or \"raw\"")
                })?;
            let bytes = match format.as_str() {
                "elf" => ud_compile::lower_to_elf(&ast)
                    .with_context(|| format!("lower {} to ELF", input.display()))?,
                "pe" => ud_compile::lower_to_pe(&ast)
                    .with_context(|| format!("lower {} to PE", input.display()))?,
                "macho" => ud_compile::lower_to_macho(&ast)
                    .with_context(|| format!("lower {} to Mach-O", input.display()))?,
                "raw" => ud_compile::lower_to_raw(&ast)
                    .with_context(|| format!("lower {} to raw", input.display()))?,
                other => anyhow::bail!(
                    "unsupported `@module.format` value {other:?} (expected \"elf\", \"pe\", \"macho\", or \"raw\")"
                ),
            };
            std::fs::write(&output, &bytes)
                .with_context(|| format!("write {}", output.display()))?;
            println!(
                "compiled: {} → {} ({} bytes, format: {})",
                input.display(),
                output.display(),
                bytes.len(),
                format,
            );
            Ok(())
        }
        Command::Analyze {
            input,
            max_instructions,
            json,
        } => analyze(&input, max_instructions, json),
    }
}

fn analyze(input: &Path, max_instructions: u64, as_json: bool) -> anyhow::Result<()> {
    let bytes = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;
    if !ud_format_pe::is_pe(&bytes) {
        anyhow::bail!(
            "ud analyze currently only supports PE32 DLLs; {} is not a PE",
            input.display()
        );
    }
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("input");

    let mut sandbox = ud_emulator::Sandbox::new();
    sandbox.host.trace_stubs = true;
    sandbox.host.instruction_budget = Some(max_instructions);

    let load_result = sandbox.load(stem, &bytes);
    let image = match load_result {
        Ok(img) => img,
        Err(e) => {
            // Surface load failures cleanly in both text and
            // JSON shapes — the front-end consumer cares
            // whether the load even got off the ground.
            if as_json {
                let report = AnalyzeReport {
                    input: input.display().to_string(),
                    image_base: 0,
                    entry_point: 0,
                    dll_main: DllMainOutcome::LoadFailed {
                        message: e.to_string(),
                    },
                    win32_calls: Vec::new(),
                    win32_calls_by_function: Vec::new(),
                    coverage: CoverageSummary::default(),
                    instructions_executed: 0,
                    instruction_budget: max_instructions,
                };
                let s = serde_json::to_string_pretty(&report)?;
                println!("{s}");
                return Ok(());
            }
            anyhow::bail!("load {}: {}", input.display(), e);
        }
    };

    let dll_main_result = sandbox.call_dll_main(&image, ud_emulator::DLL_PROCESS_ATTACH);
    let trace: Vec<String> = std::mem::take(&mut sandbox.host.stub_trace);
    let instructions_executed = sandbox.host.instructions_executed;

    let win32_calls: Vec<Win32Call> = trace
        .iter()
        .filter_map(|line| {
            // Format: `dll!name → 0xRET`
            let (lhs, ret) = line.rsplit_once(" → ")?;
            let (dll, name) = lhs.split_once('!')?;
            let ret_u32 = ret
                .strip_prefix("0x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .unwrap_or(0);
            Some(Win32Call {
                dll: dll.to_string(),
                name: name.to_string(),
                return_value: ret_u32,
            })
        })
        .collect();

    let mut by_func: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for c in &win32_calls {
        *by_func.entry(format!("{}!{}", c.dll, c.name)).or_default() += 1;
    }
    let win32_calls_by_function: Vec<Win32CallCount> = by_func
        .into_iter()
        .map(|(function, count)| Win32CallCount { function, count })
        .collect();

    let cov = sandbox.coverage();
    let ranges = cov.executed_ranges();
    let writes = cov.written_addresses().count();
    let smc: Vec<u32> = cov.self_modifying_addresses().collect();
    let coverage = CoverageSummary {
        executed_addresses: cov.executed_count(),
        executed_ranges: ranges.len(),
        bytes_written: writes,
        self_modifying_bytes: smc.len(),
        self_modifying_sample: smc.iter().take(8).copied().collect(),
    };

    let dll_main = match &dll_main_result {
        Ok(ret) => DllMainOutcome::Returned { value: *ret },
        Err(e) => DllMainOutcome::Trapped {
            message: e.to_string(),
        },
    };

    let report = AnalyzeReport {
        input: input.display().to_string(),
        image_base: image.image_base,
        entry_point: image.entry_point,
        dll_main,
        win32_calls,
        win32_calls_by_function,
        coverage,
        instructions_executed,
        instruction_budget: max_instructions,
    };

    if as_json {
        let s = serde_json::to_string_pretty(&report)?;
        println!("{s}");
    } else {
        report.write_text(input);
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct AnalyzeReport {
    input: String,
    image_base: u32,
    entry_point: u32,
    dll_main: DllMainOutcome,
    win32_calls: Vec<Win32Call>,
    win32_calls_by_function: Vec<Win32CallCount>,
    coverage: CoverageSummary,
    instructions_executed: u64,
    instruction_budget: u64,
}

impl AnalyzeReport {
    fn write_text(&self, input: &Path) {
        println!(
            "loaded: {} (image_base 0x{:x}, entry 0x{:x})",
            input.display(),
            self.image_base,
            self.entry_point
        );
        println!();
        println!("Win32 calls observed: {}", self.win32_calls.len());
        for c in &self.win32_calls_by_function {
            println!("  {:5}× {}", c.count, c.function);
        }
        println!();
        println!("Coverage:");
        println!(
            "  {} distinct EIP addresses executed",
            self.coverage.executed_addresses
        );
        println!(
            "  {} executed address ranges (contiguous spans)",
            self.coverage.executed_ranges
        );
        println!("  {} guest bytes written", self.coverage.bytes_written);
        println!(
            "  {} bytes were both written and executed (self-modifying / unpacker)",
            self.coverage.self_modifying_bytes
        );
        if !self.coverage.self_modifying_sample.is_empty() {
            let preview: Vec<String> = self
                .coverage
                .self_modifying_sample
                .iter()
                .map(|a| format!("0x{a:x}"))
                .collect();
            println!("    first few: {}", preview.join(", "));
        }
        println!();
        println!(
            "Instructions executed: {} of {}",
            self.instructions_executed, self.instruction_budget
        );
        println!();
        match &self.dll_main {
            DllMainOutcome::Returned { value } => {
                println!("DllMain(DLL_PROCESS_ATTACH) returned 0x{value:x}");
            }
            DllMainOutcome::Trapped { message } => {
                println!("DllMain trapped: {message}");
            }
            DllMainOutcome::LoadFailed { message } => {
                println!("load failed: {message}");
            }
        }
    }
}

#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DllMainOutcome {
    Returned { value: u32 },
    Trapped { message: String },
    LoadFailed { message: String },
}

#[derive(serde::Serialize)]
struct Win32Call {
    dll: String,
    name: String,
    return_value: u32,
}

#[derive(serde::Serialize)]
struct Win32CallCount {
    function: String,
    count: usize,
}

#[derive(serde::Serialize, Default)]
struct CoverageSummary {
    executed_addresses: usize,
    executed_ranges: usize,
    bytes_written: usize,
    self_modifying_bytes: usize,
    self_modifying_sample: Vec<u32>,
}

fn format_warning(w: &ud_compile::AsmWarning) -> String {
    match w {
        ud_compile::AsmWarning::Divergence {
            location,
            text,
            canonical,
        } => format!(
            "{}: text {:?} disagrees with canonical form {:?}",
            format_location(location),
            text,
            canonical,
        ),
        ud_compile::AsmWarning::Undecodable { location, text } => format!(
            "{}: pinned bytes don't decode as a valid x86 instruction (text was {:?})",
            format_location(location),
            text,
        ),
        ud_compile::AsmWarning::MultipleInsns {
            location,
            text,
            count,
        } => format!(
            "{}: pinned bytes decode to {} instructions, not 1 (text was {:?})",
            format_location(location),
            count,
            text,
        ),
    }
}

fn format_location(l: &ud_compile::AsmLocation) -> String {
    let section = l.section.as_deref().unwrap_or("<top-level>");
    let function = l.function.as_deref().unwrap_or("<no fn>");
    format!("{section}::{function}#{}", l.stmt_index)
}

fn hex_window(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

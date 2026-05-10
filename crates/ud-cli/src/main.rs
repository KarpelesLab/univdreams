use std::path::PathBuf;
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
            let elf = ud_format_elf::Elf64File::parse(&bytes)
                .with_context(|| format!("parse {} as ELF64-LE", input.display()))?;
            let source = ud_decompile::decompile_to_text(&elf)
                .with_context(|| format!("decompile {}", input.display()))?;
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
    }
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

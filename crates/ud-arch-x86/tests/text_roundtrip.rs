//! Decode-then-re-encode the executable sections of every x86_64 ELF
//! fixture and assert byte-identity. This is the proof that the arch
//! backend actually preserves the encoding choices observed in real
//! compiler output.
//!
//! Non-x86 ELFs are skipped. Non-ELF and 32-bit ELF files are skipped
//! by `ud-format-elf::is_elf64_le` returning false. The integration test
//! in `ud-cli` covers their byte-copy round-trip path; this one is
//! about the structural decode/encode bijection.

use std::path::{Path, PathBuf};

use ud_arch_x86::{roundtrip_bytes, Bitness};
use ud_format_elf::{is_elf64_le, Elf64File, EM_X86_64, SHF_EXECINSTR};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .find(|p| p.join("Cargo.toml").exists() && p.join("crates").is_dir())
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn collect_fixtures(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            out.extend(collect_fixtures(&path));
        } else if meta.is_file() {
            out.push(path);
        }
    }
    out
}

fn hex_window(bytes: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(4);
    let end = (offset + 12).min(bytes.len());
    bytes[start..end]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn x86_64_text_sections_roundtrip() {
    let testdata = workspace_root().join("testdata");
    if !testdata.is_dir() {
        eprintln!("note: {} is missing; nothing to test", testdata.display());
        return;
    }

    let fixtures = collect_fixtures(&testdata);
    let mut covered_sections = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let bytes = std::fs::read(fixture).expect("read fixture");
        if !is_elf64_le(&bytes) {
            continue;
        }
        let Ok(elf) = Elf64File::parse(&bytes) else {
            continue;
        };
        if elf.ehdr.e_machine != EM_X86_64 {
            eprintln!(
                "skip  {} (e_machine = {}, not x86_64)",
                fixture.display(),
                elf.ehdr.e_machine
            );
            continue;
        }

        for (idx, sh, data) in elf.sections() {
            if sh.sh_flags & SHF_EXECINSTR == 0 || data.is_empty() {
                continue;
            }
            match roundtrip_bytes(Bitness::Bits64, data, sh.sh_addr) {
                Ok(decoded) => {
                    eprintln!(
                        "ok    {} section #{idx} (addr=0x{:x}, {} bytes, {} insns)",
                        fixture.display(),
                        sh.sh_addr,
                        data.len(),
                        decoded.len(),
                    );
                    covered_sections += 1;
                }
                Err(e) => {
                    let context = match &e {
                        ud_arch_x86::Error::ByteMismatch { offset, .. } => {
                            format!(" [near: {}]", hex_window(data, *offset))
                        }
                        _ => String::new(),
                    };
                    failures.push(format!(
                        "{} section #{idx} (addr=0x{:x}): {}{}",
                        fixture.display(),
                        sh.sh_addr,
                        e,
                        context,
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} executable section(s) failed round-trip:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );

    if covered_sections == 0 {
        eprintln!(
            "note: no x86_64 executable sections found under {}",
            testdata.display()
        );
    }
}

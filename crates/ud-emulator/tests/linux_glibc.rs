//! Boot a **real static glibc** amd64 binary end-to-end.
//!
//! This compiles a tiny C program with `gcc -static` at test time and runs
//! the resulting ELF through the emulator, asserting captured stdout and the
//! exit code. It exercises the full glibc startup path (IRELATIVE/ifunc
//! resolution, CPUID-driven SSE2 dispatch, TLS setup, `arch_prctl`, the SSE2
//! string/mem routines) — not just hand-assembled opcodes.
//!
//! The test is **skipped** (returns early, printing why) when no working
//! `gcc -static` toolchain is present, so it never fails on hosts without one.

use std::process::Command;

use ud_emulator::Sandbox;

/// Compile `src` with `gcc -static -O2`. Returns the ELF bytes, or `None`
/// (with a printed reason) if the toolchain can't produce a static binary.
fn compile_static(src: &str, name: &str) -> Option<Vec<u8>> {
    // Work inside cargo's per-test temp area.
    let dir = std::env::temp_dir().join(format!("ud_glibc_{name}_{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let cfile = dir.join("prog.c");
    let ofile = dir.join("prog");
    if std::fs::write(&cfile, src).is_err() {
        return None;
    }
    let out = Command::new("gcc")
        .args(["-static", "-O2", "-o"])
        .arg(&ofile)
        .arg(&cfile)
        .output();
    let ok = match out {
        Ok(o) => o.status.success(),
        Err(_) => false, // gcc not installed
    };
    if !ok {
        eprintln!("SKIP: no working `gcc -static` toolchain on this host");
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let bytes = std::fs::read(&ofile).ok();
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

fn run(bytes: &[u8]) -> (String, i32) {
    let mut sb = Sandbox::new_linux();
    sb.host.instruction_budget = Some(50_000_000);
    sb.load_linux_elf("prog", bytes)
        .expect("load static glibc ELF");
    let exit = sb.run_linux().expect("run");
    (String::from_utf8_lossy(&sb.linux.stdout).into_owned(), exit)
}

#[test]
fn static_glibc_hello_world() {
    let src = r#"
        #include <stdio.h>
        int main(void) { printf("hello from glibc %d\n", 123); return 0; }
    "#;
    let Some(elf) = compile_static(src, "hello") else {
        return;
    };
    let (stdout, exit) = run(&elf);
    assert_eq!(stdout, "hello from glibc 123\n", "glibc printf output");
    assert_eq!(exit, 0, "exit code");
}

#[test]
fn static_glibc_returns_exit_code() {
    let src = "int main(void) { return 42; }";
    let Some(elf) = compile_static(src, "ret") else {
        return;
    };
    let (_stdout, exit) = run(&elf);
    assert_eq!(exit, 42, "main()'s return becomes the process exit code");
}

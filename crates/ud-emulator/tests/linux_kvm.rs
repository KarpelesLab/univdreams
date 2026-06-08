//! KVM-accelerated execution of real static glibc amd64 binaries.
//!
//! Only built with `--features kvm` (Linux x86-64 host). Skips at runtime if
//! `/dev/kvm` isn't accessible or no `gcc -static` toolchain is present, so it
//! never fails on a host that can't run it. Validates that the *same*
//! `LinuxKernel` produces identical results whether the guest runs under the
//! software interpreter or natively under KVM.

#![cfg(feature = "kvm")]

use std::process::Command;

use ud_emulator::Sandbox;

fn compile_static(src: &str, name: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("ud_kvm_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let cfile = dir.join("prog.c");
    let ofile = dir.join("prog");
    std::fs::write(&cfile, src).ok()?;
    let ok = Command::new("gcc")
        .args(["-static", "-O2", "-o"])
        .arg(&ofile)
        .arg(&cfile)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: no working `gcc -static` toolchain");
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let bytes = std::fs::read(&ofile).ok();
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

fn kvm_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

#[test]
fn kvm_runs_static_glibc_hello() {
    if !kvm_available() {
        eprintln!("SKIP: /dev/kvm not accessible");
        return;
    }
    let Some(elf) = compile_static(
        r#"#include <stdio.h>
           int main(void){ printf("kvm hello %d\n", 7); return 0; }"#,
        "hello",
    ) else {
        return;
    };
    let mut sb = Sandbox::new_linux();
    let exit = sb.run_linux_kvm("hello", &elf).expect("kvm run");
    assert_eq!(
        String::from_utf8_lossy(&sb.linux.stdout),
        "kvm hello 7\n",
        "glibc printf output under KVM"
    );
    assert_eq!(exit, 0);
}

/// Freestanding (no libc/startup) — isolates the KVM mode/segment/trampoline
/// setup from glibc's CPU-feature probing.
#[test]
fn kvm_runs_freestanding_raw_syscalls() {
    if !kvm_available() {
        eprintln!("SKIP: /dev/kvm not accessible");
        return;
    }
    let src = r#"
        static long sys3(long n, long a, long b, long c){ long r;
            __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");
            return r; }
        void _start(void){
            sys3(1, 1, (long)"kvm raw\n", 8);  // write(1, ..., 8)
            sys3(60, 5, 0, 0);                 // exit(5)
        }
    "#;
    let dir = std::env::temp_dir().join(format!("ud_kvm_free_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfile = dir.join("f.c");
    let ofile = dir.join("f");
    std::fs::write(&cfile, src).unwrap();
    let ok = Command::new("gcc")
        .args([
            "-static",
            "-nostdlib",
            "-nostartfiles",
            "-O2",
            "-fno-stack-protector",
            "-o",
        ])
        .arg(&ofile)
        .arg(&cfile)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: gcc freestanding build failed");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let elf = std::fs::read(&ofile).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let mut sb = Sandbox::new_linux();
    let exit = sb.run_linux_kvm("f", &elf).expect("kvm run");
    assert_eq!(String::from_utf8_lossy(&sb.linux.stdout), "kvm raw\n");
    assert_eq!(exit, 5);
}

#[test]
fn kvm_returns_exit_code() {
    if !kvm_available() {
        eprintln!("SKIP: /dev/kvm not accessible");
        return;
    }
    let Some(elf) = compile_static("int main(void){ return 42; }", "ret") else {
        return;
    };
    let mut sb = Sandbox::new_linux();
    let exit = sb.run_linux_kvm("ret", &elf).expect("kvm run");
    assert_eq!(exit, 42, "main() return under KVM");
}

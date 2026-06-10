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
    compile_static_opt(src, name, "-O2")
}

/// Like [`compile_static`] but at a caller-chosen optimisation level. `-O0`
/// is useful for tests that only need to exercise syscalls and shouldn't ride
/// on the interpreter's SSE2-string codegen coverage (some `-O2` glibc tails
/// reach byte-shift opcodes the software CPU doesn't model yet).
fn compile_static_opt(src: &str, name: &str, opt: &str) -> Option<Vec<u8>> {
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
        .args(["-static", opt, "-o"])
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
fn static_glibc_reads_proc_and_dev() {
    // The synthetic /proc and /dev mounts auto-installed for Linux runs:
    // /proc/cpuinfo, /proc/self/maps, /dev/urandom (deterministic), /dev/null.
    let src = r#"
        #include <stdio.h>
        #include <string.h>
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            char buf[256];
            int f = open("/proc/cpuinfo", O_RDONLY);
            int n = read(f, buf, 32); close(f);
            buf[n > 0 ? n : 0] = 0;
            int cpu_ok = (n > 0) && strstr(buf, "processor") != NULL;
            f = open("/proc/self/maps", O_RDONLY);
            n = read(f, buf, 32); close(f);
            int maps_ok = (n > 0) && strstr(buf, "00400000") != NULL;
            f = open("/dev/urandom", O_RDONLY);
            unsigned char r = 0; int got = read(f, &r, 1); close(f);
            f = open("/dev/null", O_WRONLY);
            int w = write(f, "x", 1); close(f);
            printf("cpu=%d maps=%d rand=%d null=%d\n", cpu_ok, maps_ok, got == 1, w == 1);
            return 0;
        }
    "#;
    let Some(elf) = compile_static(src, "procdev") else {
        return;
    };
    let (stdout, exit) = run(&elf);
    assert_eq!(
        stdout, "cpu=1 maps=1 rand=1 null=1\n",
        "/proc + /dev served"
    );
    assert_eq!(exit, 0);
}

#[test]
fn static_glibc_dir_syscalls_mkdir_stat_getdents() {
    // Exercise the directory-aware syscalls against the in-memory root:
    // mkdir, O_CREAT writes, real stat (size + S_ISREG), and getdents64 via
    // opendir/readdir. Empty dirs aren't materialised in the flat namespace,
    // so the created files (not the empty subdir) are what readdir reports.
    let src = r#"
        #include <stdio.h>
        #include <dirent.h>
        #include <sys/stat.h>
        #include <fcntl.h>
        #include <unistd.h>
        #include <string.h>
        int main(void) {
            mkdir("/work", 0755);
            int fd = open("/work/a.txt", O_RDWR | O_CREAT, 0644);
            write(fd, "hello", 5); close(fd);
            fd = open("/work/b.txt", O_RDWR | O_CREAT, 0644);
            write(fd, "world!!", 7); close(fd);
            struct stat st;
            int sok = stat("/work/b.txt", &st) == 0;
            DIR *d = opendir("/work");
            int n = 0, saw_a = 0, saw_b = 0;
            if (d) {
                struct dirent *e;
                while ((e = readdir(d))) {
                    n++;
                    if (!strcmp(e->d_name, "a.txt")) saw_a = 1;
                    if (!strcmp(e->d_name, "b.txt")) saw_b = 1;
                }
                closedir(d);
            }
            printf("size=%lld reg=%d n=%d a=%d b=%d\n",
                   (long long)st.st_size, sok && S_ISREG(st.st_mode), n, saw_a, saw_b);
            return 0;
        }
    "#;
    let Some(elf) = compile_static_opt(src, "dirsys", "-O0") else {
        return;
    };
    let (stdout, exit) = run(&elf);
    // size=7 (b.txt), reg=1 (regular file), n=4 (. .. a.txt b.txt), both seen.
    assert_eq!(stdout, "size=7 reg=1 n=4 a=1 b=1\n", "dir syscalls");
    assert_eq!(exit, 0, "exit code");
}

#[test]
fn static_glibc_cwd_dirfd_dup_access() {
    // chdir + getcwd + relative-path (AT_FDCWD) resolution + dup + access,
    // against the in-memory root. Creating /work/foo.txt first materialises
    // /work as a (synthesised) directory so chdir into it succeeds.
    let src = r#"
        #include <stdio.h>
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            int fd = open("/work/foo.txt", O_RDWR | O_CREAT, 0644);
            write(fd, "hi", 2); close(fd);
            chdir("/work");
            char cwd[64] = {0}; getcwd(cwd, sizeof cwd);
            int rfd = open("foo.txt", O_RDONLY);   // relative to cwd
            char b[8] = {0}; int n = read(rfd, b, 7);
            int dupfd = dup(rfd);
            int acc = access("foo.txt", F_OK);      // exists
            printf("cwd=%s read=%.*s acc=%d dup=%d\n", cwd, n, b, acc, dupfd > 2);
            return 0;
        }
    "#;
    let Some(elf) = compile_static_opt(src, "cwd", "-O0") else {
        return;
    };
    let (stdout, exit) = run(&elf);
    assert_eq!(
        stdout, "cwd=/work read=hi acc=0 dup=1\n",
        "cwd/dirfd/dup/access"
    );
    assert_eq!(exit, 0);
}

#[test]
fn static_glibc_fork_pipe_wait() {
    // fork + pipe + waitpid against the in-memory root. The child writes to the
    // pipe and exits with a code; the parent reaps it and reads the bytes. Our
    // fork model runs the child synchronously to completion, and the pipe lives
    // in the shared kernel, so this round-trips.
    let src = r#"
        #include <stdio.h>
        #include <unistd.h>
        #include <sys/wait.h>
        int main(void) {
            int p[2];
            if (pipe(p)) { perror("pipe"); return 1; }
            pid_t pid = fork();
            if (pid == 0) {           // child
                write(p[1], "hello", 5);
                _exit(7);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            char b[8] = {0};
            int n = read(p[0], b, 5);
            printf("got=%.*s status=%d\n", n, b, WEXITSTATUS(status));
            return 0;
        }
    "#;
    let Some(elf) = compile_static_opt(src, "forkpipe", "-O0") else {
        return;
    };
    let (stdout, exit) = run(&elf);
    assert_eq!(stdout, "got=hello status=7\n", "fork/pipe/waitpid");
    assert_eq!(exit, 0);
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

#[test]
fn static_glibc_pthreads_run_join_and_share_memory() {
    // Three worker threads each bump a shared counter and return a value the
    // main thread collects via pthread_join. Exercises clone (thread spawn,
    // CLONE_VM shared memory, CLONE_SETTLS per-thread TLS), futex wait/wake,
    // and CLONE_CHILD_CLEARTID join wakeups in the scheduler.
    let src = r#"
        #include <pthread.h>
        #include <stdio.h>
        static int counter = 0;
        static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
        static void *worker(void *arg) {
            long id = (long)arg;
            for (int i = 0; i < 1000; i++) {
                pthread_mutex_lock(&lock);
                counter++;
                pthread_mutex_unlock(&lock);
            }
            return (void *)(id * 10);
        }
        int main(void) {
            pthread_t t[3];
            for (long i = 0; i < 3; i++) pthread_create(&t[i], NULL, worker, (void *)i);
            long sum = 0;
            for (int i = 0; i < 3; i++) { void *r; pthread_join(t[i], &r); sum += (long)r; }
            printf("counter=%d sum=%ld\n", counter, sum);
            return 0;
        }
    "#;
    let Some(elf) = compile_static(src, "thr") else {
        return;
    };
    let (stdout, exit) = run(&elf);
    assert_eq!(
        stdout, "counter=3000 sum=30\n",
        "3 threads × 1000 increments under a mutex, join returns 0+10+20"
    );
    assert_eq!(exit, 0, "exit code");
}

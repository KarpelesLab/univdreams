# univdreams

A universal compiler **and** decompiler suite. The premise:

> Given a compiled binary `B`, produce source `S` such that compiling `S` reproduces `B` **byte for byte**.

**Try it in your browser:** <https://karpeleslab.github.io/univdreams/>

Most decompilers paraphrase. They lose the choices a compiler made — register allocation, instruction encoding, instruction order, padding, jump-table layout — and a recompile of their output is structurally similar but not identical to the input. univdreams treats those choices as first-class information in the source language: they live in attributes/directives that pin the compiler back to the same shape on the way out.

## Status

**The headline property is working and defended on every push, for every format:**

```
lower_to_{elf,pe,macho,raw}(parse(decompile_to_text(bin)))   ==   bin-bytes
```

For every committed fixture, the entire file — headers, segment / section tables, every section's content, every interstitial padding gap, and code-signature blobs — round-trips through the `.ud` source language byte-identically. The corpus covers 15 binaries totalling roughly **490 KB**, plus the 420 KB `wmpcdcs8-mpg4c32.dll` (Windows msmpeg4 codec) as an opt-in external fixture.

What's working today:

- **Byte-identical round-trip** across ELF64, PE/COFF, thin Mach-O (x86-64 + arm64), and 16-bit Windows NE, plus 6502 raw images.
- **Architectures**: x86-64 + i386 via `iced-x86`, AArch64 (decode + lift), 6502 (full assembler + disassembler).
- **Structured statement lifting**, not just `@asm()` dumps: `if`/`switch`/`goto`, register-named locals, `dword ptr [global] = expr` stores, `lea`-as-`&` address-of, `sub_foo(arg_8, arg_c)` calls with stdcall/cdecl push-chain folding, `tail_F(args)` for tail-jmps, prologue/epilogue auto-generation, SSA expression composition.
- **PE / Mach-O readability** comparable to Ghidra's Headers + Memory Map + Symbol Table + Listing panes: structural decode of load commands (`LC_SEGMENT_64`, `LC_SYMTAB`, `LC_MAIN`, `LC_BUILD_VERSION`, `LC_LOAD_DYLIB`, etc.), inline disassembly comments, IAT-resolved imports (`GetDriverModuleHandle(arg_c)`).
- **DWARF reader** for typed function signatures (parameters and return type from `.debug_info`).
- **Function discovery** layered across `.symtab`, `.dynsym`, `.eh_frame`, PE export table, byte-pattern signatures (CRT helpers), and size-filling for unsymbolised binaries.
- **WASM playground** at <https://karpeleslab.github.io/univdreams/> running the full pipeline in-browser.
- **250 tests across 17 crates**, fmt + clippy + tests defended on every push.

What's not done yet:

- Higher-level decompilation: loops as `for`/`while` rather than `goto`, struct-field naming from offset patterns, type recovery from access patterns when DWARF is absent.
- libc / Win32 / Foundation runtime signature DBs beyond the current CRT-helper set.
- Fat (universal) Mach-O wrappers; 32-bit Mach-O.
- Mach-O code-signature regeneration after edits (currently the signature blob rides as opaque bytes — editing the source breaks the signature, same as any binary edit).
- Edit semantics: `@asm` edits whose re-encoded length changes don't yet warn.

See [docs/roadmap.md](docs/roadmap.md) for what's done in detail and what's next.

## What it does today

Decompile a binary to canonical `.ud` source:

```bash
$ ud decompile testdata/external/wmpcdcs8-mpg4c32.dll
@module {
    arch: "x86",
    format: "pe",
    bits: 0x20,
    endian: "little",
    build: { … coff, sections, optional_header, padding, file_size … },
}

fn DriverProc() #[abi="stdcall", autogen_pro] {
    let arg_8: u32;
    let arg_c: u32;
    let arg_10: u32;
    let arg_14: u32;
    let arg_18: u32;
    let eax: u32, edx: u32, ecx: u32 @reg;

    eax = arg_10 [0x8b, 0x45, 0x10]
    edx = arg_14 [0x8b, 0x55, 0x14]
    ecx = 0x4004 [0xb9, 0x04, 0x40, 0x00, 0x00]
    if (eax >u ecx) goto label_2116;
    if (eax == ecx) goto label_2103;
    ecx = &[eax - 1]
    switch (ecx) {
        case 0: goto label_209d;
        case 1: goto label_20fb;
        …
    }

label_209d:
    if (dword ptr [0x1c262194] == 0) {
        GetDriverModuleHandle(arg_c)
        [0x1c262194] = eax
    }
    dword ptr [0x1c26219c] = dword ptr [0x1c26219c] + 1
    goto label_20fb;

label_2288:
    eax = arg_14
    pushed_args([eax], [eax + 4], [eax + 8], [eax + 0x24], [eax + 0x28], …, [eax + 0x20])
    sub_3469(arg_8)
    goto label_2466;

    …
}
```

Compare the same idea for Mach-O:

```bash
$ ud decompile testdata/hello-clang-macho-x86_64
@module {
    arch: "x86_64", abi: "macho", format: "macho", …
    build: {
        commands: [
            { cmd: 0x19, segment: { name: "__TEXT", sections: [
                { name: "__text",   addr: 0x100000470, size: 0x23, … },
                { name: "__stubs",  addr: 0x100000494, … },
                { name: "__cstring", … },
            ] } },
            { cmd: 0xe, dylinker: { name: "/usr/lib/dyld", … } },
            { cmd: 0x1b, uuid: "E567B4F0-B55D-3028-B141-EA1067085478" },
            { cmd: 0x80000028, main: { entryoff: 0x470, stacksize: 0 } },
            { cmd: 0xc, dylib: { name: "/usr/lib/libSystem.B.dylib", … } },
            …
        ],
    },
}

// ── symbols ── (decoded from LC_SYMTAB; informational, not round-trip source)
// 0x0000000100000470  SECT EXT        sect=1  _main
// 0x0000000000000000  UNDF EXT        sect=0  _puts

// ── disassembly of __text @ 0x100000470 (35 bytes) ──
// 0x0000000100000470  55                        push rbp
// 0x0000000100000471  48 89 e5                  mov rbp,rsp
// 0x0000000100000474  48 83 ec 10               sub rsp,10h
// 0x0000000100000478  c7 45 fc 00 00 00 00      mov dword ptr [rbp-4],0
// 0x000000010000047f  48 8d 3d 14 00 00 00      lea rdi,[10000049Ah]
// 0x0000000100000486  e8 09 00 00 00            call 0000000100000494h
// 0x000000010000048b  31 c0                     xor eax,eax
// 0x000000010000048d  48 83 c4 10               add rsp,10h
// 0x0000000100000491  5d                        pop rbp
// 0x0000000100000492  c3                        ret
```

Recompile the same `.ud` source back to a byte-identical binary:

```bash
$ ud roundtrip --through-source testdata/external/wmpcdcs8-mpg4c32.dll \
    --out /tmp/mpg4c32.rebuilt
source round-trip ok: testdata/external/wmpcdcs8-mpg4c32.dll == /tmp/mpg4c32.rebuilt (420240 bytes)
```

## Targets

| Tier | Format | Architectures | Status |
|------|--------|---------------|--------|
| **v1 (working)** | ELF64 | x86-64 (SysV), x86 (32-bit), aarch64 | ✅ whole-binary source round-trip; DWARF; structured lifts |
| **v1 (working)** | PE/COFF | x86-64, x86 (Windows MSVC + MinGW) | ✅ whole-binary source round-trip; imports + signatures |
| **v1 (working)** | Mach-O (thin) | x86-64, arm64 (macOS) | ✅ whole-binary source round-trip; Ghidra-style listing |
| **v1 (working)** | NE | x86-16 (Windows 1.x–3.x) | ✅ whole-binary source round-trip; Ghidra-style listing (imports, exports, 16-bit disasm) — structured lifting pending |
| **v1 (working)** | raw / flat | 6502 (Apple I / WozMon) | ✅ round-trip + lift |
| 2 | Mach-O fat | universal binaries | demux to thin first |
| 2 | ARM / Thumb | 32-bit ARM | not yet |
| 3 | High-level lifting | loops, types, struct fields | partial — see roadmap |

The v1 complexity bar reached: **scalar code from gcc / clang / MSVC / MinGW with or without debug info**. Auto-vectorization, LTO/PGO, hand-tuned asm, and packed binaries are explicit non-goals for v1.

## Use cases driving the design

- **Reverse engineering and patching**: edit a function, recompile, ship a binary indistinguishable from the original except for your edit.
- **Education / research / CTF**: see what the compiler actually did, in a language that explains itself.
- **Reproducible-build verification** (later): independently compile a vendor's source and verify it matches their shipped binary.

Binary porting between architectures is *not* in v1. A faithful round-trip on one arch is the precondition for cross-arch porting later.

## Implementation language

Rust. Reasoning, briefly:
- Strong type system catches IR-transformation bugs that are otherwise silent.
- The ecosystem is the best fit: [`iced-x86`](https://crates.io/crates/iced-x86) for x86 enc/dec, [`gimli`](https://crates.io/crates/gimli) for DWARF / `.eh_frame`, hand-rolled ELF / PE / Mach-O readers / writers for round-trip control.
- Memory safety matters when parsing untrusted binaries.

## Repository layout

```
.
├── README.md
├── Cargo.toml                  # workspace
├── docs/
│   ├── architecture.md         # pipeline, IR, how directives preserve info
│   ├── roadmap.md              # phased milestones, what's done
│   ├── source-language.md      # the .ud language, directives, examples
│   ├── round-trip-contract.md  # what "identical bytes" means precisely
│   └── installers.md           # running Win32 installers under `ud analyze --monitor`
└── crates/
    ├── ud-core/                # shared types: VAddr, Result, byte helpers
    ├── ud-format/              # ELF64 + PE/COFF + thin Mach-O + NE + raw readers + writers (byte-identical)
    ├── ud-arch-x86/            # x86 decode + lift + Intel formatter + assembler
    ├── ud-arch-aarch64/        # AArch64 decode + lift
    ├── ud-arch-6502/           # 6502 decode + lift + assembler
    ├── ud-ir/                  # Function, BasicBlock, Terminator (generic over arch)
    ├── ud-analysis/            # function discovery (symtab / eh_frame / signatures)
    ├── ud-signatures/          # byte-pattern DB (CRT helpers)
    ├── ud-debug/               # DWARF reader → typed signatures
    ├── ud-ast/                 # .ud AST + canonical pretty-printer
    ├── ud-translate/           # .ud → binary lowering + binary → .ud decompile (all formats)
    ├── ud-emulator/            # 32-bit i386 sandbox: MMU, CPU, PE loader, Win32 stubs, VfW IC*
    ├── ud-cli/                 # the `ud` binary
    └── ud-wasm/                # wasm-bindgen bindings for the browser playground
```

## Quick start

```bash
# Build
cargo build --workspace

# Run end-to-end byte-identical round-trip on the test corpus
cargo test --workspace

# Decompile any supported binary to .ud (auto-detects ELF / PE / Mach-O / 6502)
cargo run --bin ud -- decompile path/to/binary

# Source round-trip: decompile → emit → parse → lower → check byte-equality
cargo run --bin ud -- roundtrip --through-source path/to/binary

# Verify an .ud file's @asm lines decode to canonical Intel-syntax form
cargo run --bin ud -- verify path/to/file.ud
```

## Library use: drive a guest like a foreign library

`ud-emulator` ships an FFI-shaped front end over the underlying sandbox. A Rust consumer can drive a Windows DLL the same way they would `dlopen` a shared library — useful for codec analysis, malware triage, and any "load this 32-bit Win32 binary safely and tell me what it does" workflow. All in safe Rust; no `unsafe`, no host filesystem, network, or registry access from the guest unless an emulation [`Context`] explicitly attaches a virtual one.

```rust
use ud_emulator::Guest;

let bytes = std::fs::read("codec.dll")?;
let mut guest = Guest::load("codec.dll", &bytes)?;       // dlopen-shaped: also runs DllMain

// Call an exported function like an extern fn — typed in, typed out.
let version: u32 = guest.call("GetCodecVersion", ())?;

// Marshal a buffer into guest memory, pass the pointer, read it back.
let payload = vec![0u8; 4096];
let ptr = guest.alloc(&payload)?;
let rc: i32 = guest.call("Decompress", (ptr, payload.len() as u32))?;
let decoded = guest.read(ptr, payload.len())?;
```

| FFI concept | `Guest` API |
|---|---|
| `dlopen` / `LoadLibrary` | `Guest::load(name, bytes)` |
| calling an `extern fn` | `guest.call("Export", (a, b, c))` |
| typed arguments | tuples (`()`–8-arity) of `u32` / `i32` / `u16` / `u8` / `bool` |
| typed return | `R: FromRet` — `u32` / `i32` / `bool` / `()`, inferred |
| `*const T` | `guest.alloc(&bytes)` → guest pointer |
| `*const c_char` | `guest.alloc_cstr("…")` |
| reading an out-param | `guest.read(ptr, len)` after the call |

The default call convention is **stdcall** (the Win32 norm — args pushed right-to-left, callee cleans the stack). cdecl exports work too: the run-loop unwinds to a synthetic return sentinel, so who-cleans-the-stack doesn't change the observed return. The underlying `Sandbox` stays reachable via `guest.sandbox()` / `sandbox_mut()` for coverage maps, the `Context` VFS/registry, and the VfW `IC*` helpers (`ic_open`, `ic_decompress_*`, `ic_compress_*`).

Pre-built variants for less-common cases: `Guest::load_raw` skips `DllMain` (useful when you want to instrument the module before any guest code runs); `Guest::load_into` / `load_raw_into` accept a caller-provided `Sandbox` so you can attach a `Context`, set an instruction budget, or seed coverage tracking before loading.

See `cargo doc -p ud-emulator --open` for the full API.

## How to read this repo

If you're skimming, read this README and skim [docs/source-language.md](docs/source-language.md) — the directives in the example are the load-bearing idea.

If you want the full design and current state:

1. [docs/architecture.md](docs/architecture.md) — pipeline, crate roles, how the pieces fit.
2. [docs/round-trip-contract.md](docs/round-trip-contract.md) — what we promise to preserve and at which layer it's tested.
3. [docs/source-language.md](docs/source-language.md) — directive vocabulary with worked examples.
4. [docs/roadmap.md](docs/roadmap.md) — what's shipped, what's in progress, what's still ahead.
5. [docs/installers.md](docs/installers.md) — running Win32 installers under `ud analyze --monitor`; how to extract an installer's payload + capture its install effects (files, registry).

## License

MIT. Copyright (c) 2026 Karpeles Lab Inc. See [LICENSE](LICENSE).

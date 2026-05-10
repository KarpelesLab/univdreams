# univdreams

A universal compiler **and** decompiler suite. The premise:

> Given a compiled binary `B`, produce source `S` such that compiling `S` reproduces `B` **byte for byte**.

Most decompilers paraphrase. They lose the choices a compiler made — register allocation, instruction encoding, instruction order, padding, jump-table layout — and a recompile of their output is structurally similar but not identical to the input. univdreams treats those choices as first-class information in the source language: they live in attributes/directives that pin the compiler back to the same shape on the way out.

## Status

**The headline property is working and defended on every push:**

```
lower_to_elf(parse(decompile_to_text(elf)))   ==   elf-bytes
```

For ELF64 x86-64 binaries (gcc-built, with debug info), the entire file — header, program-header table, section-header table, every section's content, and every interstitial padding gap — round-trips through the `.ud` source language byte-identically. The current corpus of two real fixtures totals **33,680 bytes byte-identical** through source.

What's working today:

- ELF64 reader/writer with byte-identical round-trip.
- x86-64 instruction decode + dual-path emit (preserved bytes for round-trip; `iced` reencode for analysis).
- Function discovery layered across `.symtab`, `.dynsym`, `.eh_frame`, byte-pattern signatures (CRT helpers), and a size-filling pass for size-less sources.
- IR (Function/BasicBlock/Terminator) generic over an arch instruction type; CFG construction via iced flow control.
- `.ud` AST and canonical pretty-printer.
- `.ud` parser (text → AST) with diagnostics.
- Decompile pipeline: ELF → discover → lift → AST → text.
- Lower pipeline: text → AST → bytes per function and per section; `lower_to_elf` builds a complete `Elf64File` and emits.
- DWARF reader for typed function signatures (parameters and return type from `.debug_info`).
- 104 tests across 11 crates, fmt + clippy + tests defended on every push.

What's not done yet:

- 16- and 32-bit x86, ARM, and Mach-O / PE backends — only ELF64-LE x86-64 is on the structured source path; other formats round-trip via byte-copy.
- Structured statement lifting — function bodies are still sequences of `@asm("text", [bytes])` lines; expressions like `let x = a + b` aren't yet recovered.
- Edit semantics — editing an `@asm` line in a way that would change re-encoded length doesn't yet warn.
- libc / runtime signature DBs for static binaries.
- Type recovery from access patterns when DWARF is absent.

See [docs/roadmap.md](docs/roadmap.md) for what's done in detail and what's next.

## What it does today

Decompile a binary to canonical `.ud` source:

```bash
$ ud decompile testdata/sqrt-gcc13-O0
@module {
    arch: "x86_64",
    abi: "sysv",
    format: "elf",
    bits: 0x40,
    endian: "little",
    type: 0x3,
    entry: 0x10a0,
    build: { … e_ident, phdrs, shdrs, padding, file_size … },
}

@section(".text", 0x10a0) {
    @addr(0x10a0)
    fn _start() {
        @asm("endbr64", [0xf3, 0x0f, 0x1e, 0xfa])
        @asm("xor ebp,ebp", [0x31, 0xed])
        …
    }

    @addr(0x10b0)
    fn deregister_tm_clones() { … }    // recovered via signature

    @addr(0x10e0)
    fn register_tm_clones() { … }      // recovered via signature

    @addr(0x1189)
    fn test_sqrt(v: f64) {              // signature from DWARF
        @asm("endbr64", [0xf3, 0x0f, 0x1e, 0xfa])
        …
    }

    @addr(0x11da)
    fn do_fac(v: i32) -> i32 {          // signature from DWARF
        …
    }

    @addr(0x1209)
    fn main() -> i32 {                  // signature from DWARF
        …
    }
}

@section(".rodata", 0x2000) {
    @raw(0x2000, [ … bytes … ])
}

…
```

Recompile the same `.ud` source back to a byte-identical binary (round-trip is enforced by the test suite; a CLI flag for routing through source is on the near-term list).

## Targets

| Tier | Format | Architecture | Status |
|------|--------|--------------|--------|
| **v1 (working)** | ELF64 | x86-64 (SysV) | ✅ whole-binary source round-trip; signatures + DWARF |
| 2 | ELF | x86 (32-bit), arm32, arm64 | byte-copy round-trip only |
| 3 | PE/COFF | x86-64, x86 (Windows MSVC + MinGW) | byte-copy round-trip only |
| 3 | Mach-O | x86-64, arm64 (macOS/iOS) | not yet |
| Future | raw / flat | x86-16, embedded ARM, others | not yet |

The v1 complexity bar reached: **scalar code from gcc with debug info and `-fcf-protection`**. Auto-vectorization, LTO/PGO, hand-tuned asm, and packed binaries are explicit non-goals for v1.

## Use cases driving the design

- Reverse engineering and patching: edit a function, recompile, ship a binary indistinguishable from the original except for your edit.
- Education / research / CTF: see what the compiler actually did, in a language that explains itself.
- Reproducible-build verification (later): independently compile a vendor's source and verify it matches their shipped binary.

Binary porting between architectures is *not* in v1. A faithful round-trip on one arch is the precondition for cross-arch porting later.

## Implementation language

Rust. Reasoning, briefly:
- Strong type system catches IR-transformation bugs that are otherwise silent.
- The ecosystem is the best fit: [`iced-x86`](https://crates.io/crates/iced-x86) for x86 enc/dec, [`gimli`](https://crates.io/crates/gimli) for DWARF / `.eh_frame`, hand-rolled ELF for round-trip control.
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
│   └── round-trip-contract.md  # what "identical bytes" means precisely
└── crates/
    ├── ud-core/                # shared types: VAddr, Result, byte helpers
    ├── ud-format-elf/          # ELF64 reader + writer (byte-identical)
    ├── ud-arch-x86/            # x86 decode + lift + Intel formatter
    ├── ud-ir/                  # Function, BasicBlock, Terminator (generic over arch)
    ├── ud-analysis/            # function discovery (symtab / eh_frame / signatures)
    ├── ud-signatures/          # byte-pattern DB (CRT helpers)
    ├── ud-debug/               # DWARF reader → typed signatures
    ├── ud-ast/                 # .ud AST + canonical pretty-printer
    ├── ud-compile/             # .ud parser + lower_to_elf
    ├── ud-decompile/           # ELF → AST pipeline
    └── ud-cli/                 # the `ud` binary
```

## Quick start

```bash
# Build
cargo build --workspace

# Run end-to-end byte-identical round-trip on the test corpus
cargo test --workspace

# Decompile an ELF64-LE x86-64 binary to .ud
cargo run --bin ud -- decompile path/to/binary

# Verify that bytes can be read and rewritten via the byte-level path
cargo run --bin ud -- roundtrip path/to/binary
```

## How to read this repo

If you're skimming, read this README and skim [docs/source-language.md](docs/source-language.md) — the directives in the example are the load-bearing idea.

If you want the full design and current state:

1. [docs/architecture.md](docs/architecture.md) — pipeline, crate roles, how the pieces fit.
2. [docs/round-trip-contract.md](docs/round-trip-contract.md) — what we promise to preserve and at which layer it's tested.
3. [docs/source-language.md](docs/source-language.md) — directive vocabulary with worked examples.
4. [docs/roadmap.md](docs/roadmap.md) — what's shipped, what's in progress, what's still ahead.

## License

MIT. Copyright (c) 2026 Karpeles Lab Inc. See [LICENSE](LICENSE).

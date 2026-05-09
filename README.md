# univdreams

A universal compiler **and** decompiler suite. The premise:

> Given a compiled binary `B`, produce source `S` such that compiling `S` reproduces `B` **byte for byte**.

Most decompilers paraphrase. They lose the choices a compiler made — register allocation, instruction encoding, instruction order, padding, jump-table layout — and a recompile of their output is structurally similar but not identical to the input. univdreams treats those choices as first-class information in the source language: they live in attributes/directives that pin the compiler back to the same shape on the way out.

## Status

**Phase 0: planning.** This repository currently contains design documents and a Cargo workspace skeleton. No code paths are wired up yet. See [docs/roadmap.md](docs/roadmap.md) for the staged plan.

## What it does (when finished)

- **Decompile** native binaries to a C/C++-like source language (`.ud`) annotated with directives that capture every non-semantic choice the original compiler made.
- **Compile** that source back to a native binary that is identical to the original at the byte level (within the contract; see [docs/round-trip-contract.md](docs/round-trip-contract.md)).
- **Identify standard library functions** (libc primitives like `strlen`, `memcpy`, …) via signatures and name them accordingly, leaving everything else as `sub_<address>` so that link-order is preserved by default.
- **Use debug info when present** (DWARF, PDB, stabs, Mach-O `.dSYM`) to recover real names, types, and source locations.
- **Stay modular across architectures.** Each architecture is a backend implementing a small trait surface (decode, encode, lift, lower).

## Targets

| Tier | Format | Architecture | Status |
|------|--------|--------------|--------|
| 1 (first milestone) | ELF | x86-64 (SysV) | planned |
| 2 | ELF | x86 (32-bit), arm64, arm32 | planned |
| 3 | PE/COFF | x86-64, x86 (Windows MSVC + MinGW) | planned |
| 3 | Mach-O | x86-64, arm64 (macOS/iOS) | planned |
| Future | raw / flat | x86-16, embedded ARM, others | open |

The v1 complexity bar is **scalar -O2 output** from gcc/clang. SIMD/auto-vectorization, LTO/PGO, hand-tuned assembly, and packed/obfuscated binaries are explicit non-goals for v1 but are not architecturally precluded.

## Use cases driving the design

- Reverse engineering and patching: edit a function, recompile, ship a binary indistinguishable from the original except for your edit.
- Education / research / CTF: see what the compiler actually did, in a language that explains itself.
- Reproducible-build verification (later): independently compile a vendor's source and verify it matches their shipped binary.

Binary porting between architectures is *not* in v1. A faithful round-trip on one arch is the precondition for cross-arch porting later — once the IR is rich enough to round-trip, retargeting it is a separate, smaller problem.

## Implementation language

Rust. Reasoning, briefly:
- Strong type system catches IR-transformation bugs that are otherwise silent.
- The ecosystem is the best fit: [`iced-x86`](https://crates.io/crates/iced-x86) for x86 enc/dec, [`capstone`](https://crates.io/crates/capstone) and [`keystone`](https://crates.io/crates/keystone-engine) for breadth, [`goblin`](https://crates.io/crates/goblin) for ELF/PE/Mach-O, [`gimli`](https://crates.io/crates/gimli) for DWARF, [`pdb`](https://crates.io/crates/pdb) for PDB.
- Memory safety matters when parsing untrusted binaries.

## Repository layout (planned)

```
.
├── README.md
├── Cargo.toml                  # workspace
├── docs/
│   ├── architecture.md         # pipeline, IR, how directives preserve info
│   ├── roadmap.md              # phased milestones
│   ├── source-language.md      # the .ud language, directives, examples
│   └── round-trip-contract.md  # what "identical bytes" means precisely
└── crates/
    ├── ud-core/                # shared types: addresses, ranges, errors
    ├── ud-format/              # ELF/PE/Mach-O loaders + writers
    ├── ud-arch/                # arch trait + x86, arm, … backends
    ├── ud-ir/                  # the lossless IR
    ├── ud-analysis/            # function discovery, type recovery, sig matching
    ├── ud-debug/               # DWARF/PDB/stabs readers
    ├── ud-signatures/          # FLIRT-style signature DB
    ├── ud-decompile/           # IR → AST → .ud source
    ├── ud-compile/             # .ud source → AST → IR → bytes
    └── ud-cli/                 # the `ud` binary
```

Crates are added as they're implemented. The skeleton is empty for now.

## Quick start

Once Phase 1 lands:

```bash
# decompile
ud decompile target/release/myprog -o myprog.ud

# round-trip check
ud compile myprog.ud -o myprog.rebuilt
cmp target/release/myprog myprog.rebuilt   # should produce no output
```

Today, the workspace is empty (no member crates yet). `cargo metadata` succeeds; `cargo build` is a no-op until the first crate lands in Phase 0.

## How to read this repo right now

If you're skimming, read `README.md` (this file) and skim [docs/source-language.md](docs/source-language.md) — the directives in the example are the single most important idea in the project.

If you want the full design, read in order:

1. [docs/architecture.md](docs/architecture.md) — overall pipeline and module surface.
2. [docs/round-trip-contract.md](docs/round-trip-contract.md) — what we promise to preserve, what we don't, and the escape hatches.
3. [docs/source-language.md](docs/source-language.md) — directive vocabulary, with worked examples.
4. [docs/roadmap.md](docs/roadmap.md) — what we ship in what order.

## License

TBD.

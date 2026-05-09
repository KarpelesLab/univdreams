# Architecture

This document describes the overall structure of univdreams — the pipelines, the IR, and how the system preserves enough information to round-trip a binary through source and back.

## The single load-bearing idea

Most decompilers are lossy because the source languages they emit (C, pseudocode) cannot express the choices a compiler made. There is no syntax for "the compiler used `rbx` for this loop counter," or "this branch was encoded as a short jump even though near would also work," or "the linker padded the function tail with `nop` `nop` `int3`." So the information is dropped, and recompiling produces a *different* binary.

univdreams's source language (`.ud`) has first-class directives for every non-semantic choice. The decompiler writes those directives. The compiler reads them and pins itself to the same choice. Result: the source is a complete, executable specification of the binary.

When the system encounters something it cannot lift to structured source, it falls back through a chain of escape hatches — typed expression → inline assembly → raw bytes — none of which break round-trip. The roof never collapses; it just degrades clarity.

See [round-trip-contract.md](round-trip-contract.md) for the precise definition of what "identical" means and which information categories are preserved.

## Pipelines

### Decompile pipeline

```
binary file
   │
   ▼
loader              detect format (ELF/PE/Mach-O), parse headers, sections,
                    symbols, relocations, debug info into a memory model
   │
   ▼
section catalog     enumerate executable ranges and their attributes
   │
   ▼
disassembler        per-arch: bytes → instruction stream with full encoding
                    detail (prefixes, displacement size, REX bits, …)
   │
   ▼
function discovery  combine: symbol table, exception/unwind tables (.eh_frame,
                    .pdata), prologue patterns, call-target sweep, control-
                    flow recovery from entry points
   │
   ▼
CFG reconstruction  per function: basic blocks, edges, loop nests
   │
   ▼
IR lifter           per-arch: instructions → arch-tagged IR ops. Lifting is
                    deliberately mechanical — no semantics-changing rewrites.
                    Every encoding choice is captured as IR-op metadata.
   │
   ▼
analysis passes     type recovery, calling-convention inference, signature
                    matching against a libc/runtime DB, naming, debug-info
                    overlay
   │
   ▼
structuring         IR → AST: re-discover loops (while/for/do), if/else,
                    switch tables, short-circuit boolean operators. Anything
                    irreducible falls through as @cfg{ goto } blocks.
   │
   ▼
emitter             AST → .ud source text with directives sufficient to pin
                    every captured choice
```

### Compile pipeline

```
.ud source
   │
   ▼
lexer + parser      produce AST. Directives are validated against the
                    target arch and ABI at parse time.
   │
   ▼
AST → IR            structured constructs lower to IR; directives attach
                    as constraints on IR ops and on layout.
   │
   ▼
instruction sel.    per-arch: IR → arch instructions. Where directives pin
                    a choice (register, encoding, ordering) the selector
                    obeys; otherwise it picks deterministically.
   │
   ▼
encoder             per-arch: instructions → bytes. Encoding directives
                    (e.g. force-near jump, REX.W=0) are honored.
   │
   ▼
section assembler   build .text and other sections, applying alignment and
                    padding as directed.
   │
   ▼
relocations         resolve cross-references; emit dynamic relocations
                    according to the format's expectations.
   │
   ▼
format writer       emit ELF/PE/Mach-O with the original layout, headers,
                    and metadata pinned by the directives at the top of
                    the source.
```

The two pipelines are inverses. The IR is the pivot. The directives are the residuum that makes the inversion exact.

## IR design

The IR is **arch-tagged**, not generic. There is no aspiration to a single SSA form that works for every architecture. Each arch has its own IR vocabulary that maps closely to its instruction semantics, augmented with shared concepts (basic blocks, function boundaries, types, memory references).

Why not a generic IR like LLVM:
- LLVM IR is *lossy* by design. It throws away precisely the information we need (encoding choices, register hints, instruction order across non-aliasing memory).
- A generic IR would force us to invent a way to round-trip arch-specific quirks anyway, and that invented mechanism is what we call the IR. Better to start there.

Why not shared by all arches:
- Shared semantics shouldn't outweigh the modeling cost of pretending that x86 segment overrides and ARM predication and MIPS branch delay slots are all the same thing. They aren't.
- Cross-arch porting (out of scope for v1) can use a *separate* lowering between two arch IRs when needed. We don't pay for that complexity until we want it.

What every arch IR has in common:
- Function (entry block, exit blocks, parameters/returns described by ABI tags)
- Basic block (sequence of ops, terminator)
- Op (an arch-specific instruction-class, with operands and *encoding metadata*)
- Operand (register, immediate, memory ref, label)
- Type (integer width, float kind, pointer-to, array-of, struct-of — recovered, often partially)

Encoding metadata on each op records every reversible-choice bit the assembler can flip: prefix bytes, displacement size, REX/VEX/EVEX choices, segment override, address-size override. The encoder reads the metadata; if absent, it picks the canonical shortest form deterministically.

## Module breakdown

| Crate | Purpose |
|-------|---------|
| `ud-core` | Common types: `Address`, `Range`, `ByteSlice`, error chain. |
| `ud-format` | Format dispatch + per-format readers/writers (ELF first). |
| `ud-arch` | The arch trait. Each arch is a sub-crate behind features. |
| `ud-arch-x86` | x86-16/32/64 backend. Decode, encode, lift, lower. Uses `iced-x86`. |
| `ud-arch-arm` | arm32/arm64 backend. Stub initially. |
| `ud-ir` | IR types, traversal helpers, validation. |
| `ud-analysis` | Function discovery, prologue detection, CFG, type recovery, calling-convention inference, naming. |
| `ud-debug` | DWARF (gimli), PDB, stabs, Mach-O `.dSYM` readers. |
| `ud-signatures` | FLIRT-style signature DB and matcher for libc/runtime functions. |
| `ud-decompile` | IR → AST structuring + `.ud` emitter. |
| `ud-compile` | `.ud` parser + AST → IR + driver of the per-arch lowering. |
| `ud-cli` | The `ud` binary: `decompile`, `compile`, `roundtrip`, `inspect`. |

## Function-discovery strategy

Function-boundary detection is the single most error-prone step. The system layers signals from highest to lowest confidence and merges them:

1. **Symbol table** (if present and not stripped). Authoritative for what it covers.
2. **Exception/unwind tables.** `.eh_frame` (ELF), `.pdata`/`.xdata` (PE x64), `LC_FUNCTION_STARTS` (Mach-O). These are emitted by every modern compiler and survive stripping.
3. **Compiler prologue patterns.** Per-arch, per-toolchain library of byte/instruction patterns that signal "function starts here." Configurable; users can add patterns.
4. **Reachability sweep from known entries.** Recursive disassembly from `_start`, exported symbols, signature-matched stdlib, and from any address mentioned as a call target.
5. **User overrides** in a sidecar config: `--function 0x401050 my_decoder`.

Conflicts (e.g., a prologue match in the middle of another function) are reported but not silently resolved.

## Standard-function recognition

A signature DB for common runtime functions (libc primitives, C++ runtime, common compiler builtins) ships with the project. Matching is conservative — false positives are worse than false negatives, since a misidentified `strlen` would silently change behavior on round-trip if a user edits the file. Default policy: identify only on a high-quality match; otherwise leave the function as `sub_<address>`.

The signature format is FLIRT-influenced but extended with multi-encoding, since the same source `strlen` can compile to wildly different bytes depending on the toolchain and flags. We store per-toolchain variants.

## Source-level naming

Default function name: `sub_<hex_address>` (e.g., `sub_401050`). The numeric address in the name is parsed by the compiler and used as the link-order key, so by default the binary's `.text` section comes back in the same order without anyone having to think about it.

A function may opt out by giving an explicit name and an `@addr(...)` directive:

```
@addr(0x401050)
fn parse_header(buf: ptr, len: usize) -> i32 { … }
```

The `@addr` is honored on recompile; the link-order key falls back to it.

When debug info is present, the recovered name is used directly (still with `@addr` to preserve order) and types from DWARF/PDB are folded into the source.

## Calling-convention handling

ABIs are first-class. A function header carries `@abi(...)` (e.g., `@abi("sysv")`, `@abi("ms64")`, `@abi("aapcs")`, `@abi("custom")`). For SysV/MS64/AAPCS, parameter and return-value placement is implicit; the compiler emits the standard register/stack mapping. For `custom`, every parameter gets an explicit `@reg(...)` or `@stack(offset=...)` annotation.

A correctly inferred ABI on decompile means a clean source. An incorrectly inferred ABI is recoverable: the user can override the `@abi(...)` directive and recompile.

## Failure modes and escape hatches

- **An instruction we can't lift to typed IR**: emit `@asm("...")` with the textual disassembly. The compiler's assembler handles it.
- **Bytes we can't disassemble at all** (data-in-code, jump tables embedded in `.text`, padding): emit `@raw(at=0x..., bytes=[...])`. Identity-preserving; opaque to analysis.
- **A compiler quirk we don't model yet**: emit `@encoding(opaque="...")` with the exact bytes for the op. Lints flag this so we know to grow the model.

These are not bugs; they are pressure valves. Round-trip is preserved at every level of degradation.

## Testing strategy

The single most important test is the **round-trip suite**: a corpus of small programs, each compiled with multiple toolchains and flags, decompiled, recompiled, and byte-compared. Any byte difference is a hard failure.

Tiers of the suite:
1. Hand-crafted fixtures targeting specific instructions/encodings.
2. A growing set of small open-source programs (busybox applets, coreutils-likes, single-file C programs).
3. (Later) larger programs and full distros.

Property-based tests on the parser and emitter ensure `parse(emit(ast)) == ast`.

Per-arch backends have unit tests for every encoding choice they claim to support, asserting `decode(encode(op)) == op` and `encode(decode(bytes)) == bytes`.

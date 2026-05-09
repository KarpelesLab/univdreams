# Roadmap

Phases are ordered by dependency, not calendar. Each phase has a definition of done that gates the next.

## Phase 0 — Foundations (current)

**Goal:** A buildable workspace, agreed-upon design, and the round-trip test harness.

- [x] Project plan, README, design docs.
- [ ] Cargo workspace skeleton (`ud-core`, `ud-cli` only — no logic).
- [ ] CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
- [ ] Round-trip test harness skeleton (compile a tiny C program with gcc/clang at multiple optimization levels, store as fixture, run a placeholder round-trip that initially just `cmp`s the file with itself).
- [ ] License decision.

**Done when:** `cargo build --workspace` succeeds, CI is green, harness runs end-to-end on at least one fixture (with the placeholder round-trip).

## Phase 1 — ELF + x86-64 instruction-level round-trip

**Goal:** Read an ELF file, disassemble every instruction in `.text`, re-encode each one, write back an ELF, and produce a byte-identical output.

This phase intentionally does **not** introduce IR or structured source. The "source" form is a flat sequence of `@asm(...)` and `@raw(...)` directives. The point is to prove the encode/decode round-trip and the format reader/writer.

- [ ] `ud-format-elf`: minimal ELF64 reader covering the sections the test corpus uses.
- [ ] `ud-format-elf`: ELF64 writer that reconstructs the input byte-for-byte from a structured representation.
- [ ] `ud-arch-x86`: integration with `iced-x86` for decode/encode. Capture all encoding metadata (prefixes, displacement size, REX/VEX bits).
- [ ] CLI: `ud roundtrip <bin>` runs the loop and reports diffs.

**Done when:** the round-trip test corpus from Phase 0 passes byte-identical, where the corpus is small statically-linked C programs at `-O0` and `-O2`. No structuring yet.

## Phase 2 — Function discovery + IR lifting

**Goal:** Recognize functions, lift their instructions to IR, and emit one `fn` per discovered function in the source — still with bodies that are mostly raw `@asm(...)` lines, but now wrapped in functions with proper headers.

- [ ] Symbol table consumer.
- [ ] `.eh_frame` parser (function-boundary signal).
- [ ] Prologue-pattern matcher (gcc/clang sysv-x64 patterns).
- [ ] Function-boundary fusion (combine signals, report conflicts).
- [ ] `ud-ir`: IR types for x86-64.
- [ ] x86 → IR lifter, with full encoding metadata preserved.
- [ ] IR → x86 lowerer.
- [ ] Default `sub_<addr>` naming with `@addr` ordering preserved.

**Done when:** Phase 1's corpus round-trips, and the source now has a `fn sub_<addr>(…) { @asm … }` per function instead of one flat blob. The bytes still match.

## Phase 3 — Source language v0

**Goal:** A real lexer/parser for `.ud`, the directive vocabulary defined in [source-language.md](source-language.md), and end-to-end use as the canonical source format.

- [ ] Grammar specified.
- [ ] Parser + AST.
- [ ] Pretty-printer (deterministic).
- [ ] Round-trip property test on parser/emitter.
- [ ] All Phase 2 directives recognized: `@arch`, `@abi`, `@addr`, `@section`, `@reg`, `@align`, `@pad`, `@encoding`, `@asm`, `@raw`.

**Done when:** the same corpus round-trips, edited by hand-rewriting one function from `@asm(...)` lines to a typed expression, with the encoder respecting the directives so the bytes still match.

## Phase 4 — Structured control flow

**Goal:** Recover loops, if/else, and switches from the CFG. Emit them as structured constructs with directives that pin lowering choices.

- [ ] CFG construction.
- [ ] Loop nesting forest.
- [ ] Reducible CFG → structured AST (Sharir, Cifuentes-style).
- [ ] Irreducible CFG fallback: `@cfg { … goto … }` blocks.
- [ ] Switch-table recognition (jump tables in `.rodata`).
- [ ] Short-circuit boolean rebuild for `&&` / `||`.
- [ ] Directives: `@loop(kind=…, encoding=…)`, `@switch(table=…)`, `@branch(encoding=…)`.

**Done when:** human-readable loops appear in the decompiled source for at least the corpus's hot paths, while the byte-identity test still passes.

## Phase 5 — Type recovery and stdlib signatures

**Goal:** Names and types in the output that are useful to a human reader.

- [ ] Type-recovery pass: integer widths, pointer-vs-integer, struct field inference from access patterns.
- [ ] DWARF reader (gimli) and overlay onto recovered types.
- [ ] FLIRT-style signature DB with the most common libc primitives (memcpy/memmove/memset/strlen/strcpy/strcmp/strncmp/malloc/free/printf-family) for glibc/musl.
- [ ] Conservative match policy with confidence scores.
- [ ] Source uses recognized names (`strlen`, `memcpy`, …) instead of `sub_<addr>`.

**Done when:** decompiling a stripped statically-linked busybox-like binary produces source with libc primitives correctly named, and the round-trip still byte-matches.

## Phase 6 — `-O2 scalar` correctness

**Goal:** Cleanly handle the optimizations that scalar `-O2` performs: register allocation, instruction reordering, tail calls, dead-store elimination effects, common subexpression elimination, peephole choices.

This is mostly about *preserving* what the compiler did, not redoing it. The decompiler captures choices; the recompiler honors them.

- [ ] Reordering directives (`@no_reorder`, ordering hints).
- [ ] Register-allocation pinning (`@reg`, `@spill_at`).
- [ ] Tail-call recognition with `@tail`.
- [ ] Calling-convention inference covering common variations.
- [ ] Sufficient corpus diversity to catch regressions.

**Done when:** the corpus expands to mid-size programs (≥10k LOC each) compiled at `-O2`, and round-trips remain byte-identical.

## Phase 7 — Second arch and second format

**Goal:** Validate modularity. Pick one of {ARM64 ELF, x86-64 PE, x86-64 Mach-O}.

- [ ] Implement the format reader/writer.
- [ ] Implement the arch backend (or wire up the appropriate format if same arch).
- [ ] Toolchain-specific runtime/CRT signatures.

**Done when:** an analogous corpus on the new target round-trips byte-identically.

## Beyond v1

In open consideration once v1 stabilizes:
- SIMD/vectorized code lifting and pinning.
- Cross-arch porting via shared semantic IR (deliberate lossy step).
- LTO/PGO output.
- Packed/obfuscated binaries.
- Full GUI / IDE integration.
- Decompiling non-CPU bytecode (Java, Wasm, Python `.pyc`, JVM, MSIL) — same architecture, new backends.

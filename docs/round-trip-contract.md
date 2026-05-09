# The round-trip contract

This document defines what univdreams promises to preserve, what it does not, and the escape hatches that let it preserve everything anyway.

## The contract, stated precisely

For any binary `B` that the system claims to support:

```
compile(decompile(B)) == B            (byte-equal)
```

with the qualification that **the user has not edited the intermediate `.ud` source**. If the user edits the source, the recompile reflects the edit, and byte-equality holds only over the parts the user did not change.

"Supports" means: the binary's format is implemented, all its arches/sections/relocations are within the implemented set, and no required information has been irrecoverably lost (e.g., by stripping in a way the system cannot reconstruct).

## What is preserved

### Byte-level layout
- Section order, sizes, alignment, and padding fill bytes.
- Header fields, including non-deterministic ones (build IDs, timestamps, `e_flags` quirks). These are captured into the `@module.build` block on decompile and written back unchanged on compile.
- Symbol table (or its absence). A stripped binary on input means a stripped binary on output.
- Relocations (static and dynamic), preserved structurally and re-emitted at the same offsets with the same kinds.

### Instruction-level layout
- Function order in `.text` (default `sub_<addr>` naming makes this automatic).
- Per-instruction encoding choices: prefix bytes, REX/VEX/EVEX bits, displacement size, immediate size, segment overrides.
- Branch encoding size: short vs near vs far.
- Specific zeroing/move idioms (`xor reg,reg` vs `mov reg,0`, etc.).
- Padding inside functions (alignment after a `ret`, `int3` filler) preserved as `@pad` directives or as `@raw` blocks for non-instruction filler.

### Function-level layout
- Prologue/epilogue shape, even when nonstandard, via `@prologue("custom")` followed by an inline-asm body.
- Stack-frame size and slot assignments, via `@stack` and `@spill`.
- Register-allocation choices that affect bytes (i.e., where a different choice of register would change the encoded instruction), pinned via `@reg(...)`.
- Tail-call lowering (jmp vs call), pinned via `@tail`.

### Data-section content
- Read-only data, including string literals, jump tables, and switch dispatch tables, preserved with their addresses and contents.
- Initialized writable data preserved verbatim.
- BSS sized correctly.

## What is **not** preserved

These categories are explicitly out of scope. If they matter for a given binary, the system reports a hard failure rather than silently producing different bytes.

- **Compiler-injected non-determinism not captured in headers.** Some compilers inject randomness into otherwise-stable structures (e.g., hashed-symbol-table seed). When detected, these are captured into `@module.build` and round-tripped. When undetected, the round-trip fails the byte-equality test and the user sees a diff.
- **Self-modifying code at runtime.** The on-disk bytes round-trip; what the program does at runtime is the program's business.
- **Output of compilers / passes we have not modeled.** Optimizations beyond v1's scope (auto-vectorization, LTO across the link, PGO-driven layout) frequently produce shapes the lifter cannot recognize. Affected functions degrade to `@asm` blocks; round-trip is preserved, but the source is unstructured for those functions.
- **Behavior of `_RANDOM` build flags.** If the build was non-reproducible upstream (e.g., `-frandom-seed` left unset), the same source compiles to different bytes; we round-trip the *observed* binary, not the abstract program.

## Escape hatches and the degradation chain

When the lifter cannot produce structured source, it degrades along a chain. At every level, byte-identity is preserved.

```
typed expression  →  inline asm  →  raw bytes
```

1. **Typed expression**: the normal output. `let x: u32 = a + b;`
2. **Inline asm**: when the instruction is implemented on this arch but the IR lifter can't produce a typed expression for it (e.g., uncommon instruction, intrinsic-like behavior). Emitted as `@asm("rdtsc")`. The compiler's assembler handles encoding; encoding metadata is preserved by per-asm-line `@encoding(...)` annotations when relevant.
3. **Raw bytes**: when the disassembler refuses or the bytes are data-in-code. Emitted as `@raw(at=0x..., bytes=[...])`. The compiler emits these bytes verbatim at the pinned address.

These are not failure modes. They are part of the language. A `.ud` file that is 100% `@raw` blocks is a perfectly valid round-tripping representation — it just won't help a human read the program.

## Verification methodology

The round-trip property is checked by an automated suite. The suite is the system's primary regression detector and ships as part of the repo.

For each fixture:
1. The fixture binary is committed to the repo (or generated reproducibly from committed source).
2. `ud roundtrip <fixture>` runs the full decompile → recompile pipeline.
3. The output bytes are compared against the fixture using `cmp`.
4. Any difference is a hard failure; the diff (offset + bytes) is reported.

Fixtures are chosen to cover, in increasing order:
1. Each documented encoding choice (one fixture per).
2. Each ABI permutation (parameter overflow to stack, struct returns, varargs).
3. Each control-flow construct (loops, switches with various table layouts, irreducible CFGs).
4. Each section/relocation kind we claim to handle.
5. Real small open-source programs at multiple `-O` levels and toolchains.

A failure at any tier blocks merging changes that affect that area.

## Hard-failure policy

When the system cannot satisfy the contract — even with all escape hatches engaged — it must fail loudly, not produce different bytes. Concretely:

- The decompiler refuses to emit if it cannot account for every input byte (covered by either a directive or an `@raw` block).
- The compiler refuses to emit if it cannot honor every directive in the source.
- The CLI's `roundtrip` command exits non-zero on any byte difference and prints a diff.

There is no "best effort" fallback. Best-effort decompilers exist; this isn't one. The whole project is the bet that the byte-identity property is achievable and worth the engineering cost — and that means we don't quietly drop it when it gets hard.

# The round-trip contract

This document defines what univdreams preserves, at which layer of the pipeline each property is tested, and what's still in scope for future iterations.

## The contract, stated precisely

For any binary `B` that the system claims to support:

```
compile(decompile(B)) == B            (byte-equal)
```

with the qualification that **the user has not edited the intermediate `.ud` source**. Editing semantics are not yet defined; see the bottom of this document.

"Supports" today means: ELF64-LE x86-64 produced by GCC with debug info. Other formats and architectures fall through to the byte-copy path in `ud roundtrip` (which is also byte-identical, just trivially).

## Layered round-trip properties

Each layer of the pipeline has its own round-trip property, and each is tested by CI on every push.

### Layer 1: ELF format

> `Elf64File::write_to_vec(Elf64File::parse(bytes)?)`  ==  `bytes`

The hand-rolled ELF64-LE reader/writer captures every byte: header fields, program-header table, section-header table, every section's content, every interstitial padding gap. Anything we don't interpret is preserved as opaque bytes and re-emitted verbatim.

Tested in `crates/ud-format-elf/tests/fixtures.rs` against every ELF64-LE fixture in `testdata/`.

### Layer 2: x86 instruction stream

> Decoding bytes to a `Vec<DecodedInsn>` and concatenating each instruction's `original_bytes`  ==  the input bytes.

We deliberately do *not* round-trip via iced's `BlockEncoder` — it canonicalizes redundant prefixes (e.g. drops the `66` data16 override on alignment NOPs), and our test corpus exposed this immediately. Instead, decode captures each instruction's exact bytes; emit re-uses them. iced's structured `Instruction` lives alongside as the analysis form.

Tested in `crates/ud-arch-x86/tests/text_roundtrip.rs` across every x86_64 executable section (12 sections, 259 instructions in the current corpus).

### Layer 3: IR Function

> `Function::emit_bytes(lift_function(insns))` == concatenation of `insns` `original_bytes`.

The IR is a *view* over the byte stream, not a transformation. CFG construction (leaders / blocks / terminators) doesn't change the bytes; emission concatenates each instruction's preserved bytes in address order.

Tested in `crates/ud-arch-x86/tests/lift_fixtures.rs`: every function discovered in every fixture is lifted, then `emit_bytes` is compared against its original slice.

### Layer 4: AST round-trip (synthetic)

> `parse(emit(ast))` is structurally equal to `ast`.
> `emit(parse(canonical_text))` is byte-equal to `canonical_text`.

The pretty-printer is deterministic; the parser is whitespace-tolerant but normalizes to the canonical form on re-emit.

Tested in `crates/ud-compile/tests/round_trip.rs` against synthetic ASTs.

### Layer 5: Source-level round-trip via decompile

> `parse(decompile_to_text(elf))`  ==  `decompile(elf)`

The AST that comes out of `decompile`, pretty-printed, then parsed back, is structurally identical to the AST we started with. This is what defends the parser against drift in the decompiler's text output and vice versa.

Tested in `crates/ud-decompile/tests/decompile_fixtures.rs`.

### Layer 6: Per-function source round-trip

> `lower_functions(parse(decompile_to_text(elf)))` produces, for each function, the same bytes as in the input ELF.

12 functions, 562 bytes verified across the corpus.

Tested in `crates/ud-compile/tests/source_round_trip.rs`.

### Layer 7: Per-section source round-trip

> `lower_sections(parse(decompile_to_text(elf)))` produces, for each `@section`, the same bytes as in the input ELF section.

68 sections, 9,093 bytes verified across the corpus — including `.text`, `.rodata`, `.dynamic`, `.data`, `.symtab`, `.strtab`, `.shstrtab`, debug sections.

Tested in `crates/ud-compile/tests/section_round_trip.rs`.

### Layer 8: Whole-binary round-trip via source

> `lower_to_elf(parse(decompile_to_text(elf)))`  ==  `elf-bytes`

Every byte of the input ELF — header, program-header table, section-header table, every section's content, every interstitial padding gap — survives a round trip through the `.ud` source language byte-identically.

**33,680 bytes across two real-world fixtures** (`hello-gcc13-O0`, `sqrt-gcc13-O0`) verified byte-identical.

Tested in `crates/ud-compile/tests/whole_binary_round_trip.rs`.

## What's preserved

### Byte-level layout
- Section order, sizes, alignment, and padding fill bytes.
- Header fields, including non-deterministic ones (build IDs, timestamps, `e_flags` quirks). These are captured into `@module.build` on decompile and written back unchanged on compile.
- Program-header table, section-header table, every entry's every field.
- Every interstitial gap between structured regions, captured as `@module.build.padding` and re-spliced on lower.

### Instruction-level layout
- Function order in `.text` (emitted in section-layout order; `@addr` pins addresses).
- Per-instruction encoding choices: every byte preserved in `@asm`'s pinned-bytes field. Includes redundant prefixes like the `66` data16 on alignment NOPs.
- Branch encoding size: short vs near vs far — captured in the bytes directly.
- Padding inside functions (alignment after a `ret`, NOP filler) preserved verbatim either inside the function's `@asm` stream or as `@raw` blocks between functions.

### Function-level layout
- Function names: real names from `.symtab` / `.dynsym` when present; pattern-matched names (CRT helpers) when signatures recognise them; otherwise `sub_<hex_addr>` which encodes the address.
- Function sizes: from `.eh_frame` / `.symtab` when supplied; otherwise filled in from neighbouring functions (distance to next discovered start in the same executable section).
- Typed signatures: parameter and return types from DWARF when present.

### Data-section content
- Read-only data, jump tables, switch dispatch tables, dynamic linker structures (`.dynamic`, `.got`, `.plt`-related sections), debug info — all preserved verbatim as `@raw` inside their respective `@section` blocks.

## What is **not** preserved (yet)

- **PE/COFF, Mach-O, 32-bit ELF, ARM** — these fall through to `ud roundtrip`'s byte-copy path. The byte-copy is byte-identical (trivially), but the source-language layer doesn't apply.
- **Edits to `.ud` that change function size** — if you edit an `@asm` line's text such that re-encoding would change the function's byte length, the bytes pinned in the `.ud` still get emitted as-is, producing a binary whose text disagrees with its bytes. A warning for this case is the next CLI work item.

## Verification methodology

Every property above is checked by an automated test in CI on every push. Property failures are hard CI failures; merging is gated on green.

The fixture corpus is two ELF64 binaries totalling 33,680 bytes:

| Fixture | Toolchain | Notes |
|---------|-----------|-------|
| `testdata/hello-gcc13-O0` | gcc 13.3.1, `-O0 -ggdb -fcf-protection` | minimal hello-world |
| `testdata/sqrt-gcc13-O0` | gcc 13.3.1, `-O0 -ggdb -fcf-protection` | dynamic-link to libm; recursion in `do_fac` |

Plus three byte-copy-only fixtures (`sqrt-gcc13-O0-m32` 32-bit ELF, `sqrt-mingw15-O0.exe` PE32, `sqrt-gcc14-O0-aarch64` aarch64 ELF) that exercise the byte-copy fallback.

## Hard-failure policy

When the system can't satisfy a layer's contract, it must fail loudly, not produce different bytes. Concretely:

- The decompiler refuses to emit if it can't account for every input byte (covered by either an `@section`/function/`@raw`).
- The lower path refuses to emit if any required section is missing, if `@section` lengths don't match `shdrs[].sh_size`, or if an `@asm` is missing pinned bytes.
- The CLI's `roundtrip` exits non-zero on any byte difference.

There is no "best-effort" fallback that produces different bytes. The whole project is the bet that the byte-identity property is achievable and worth the engineering cost — and that means we don't quietly drop it when it gets hard.

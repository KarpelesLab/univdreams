# Architecture

This document describes the structure of univdreams as it exists today — the pipelines, the IR, the crate boundaries, and how the system preserves enough information to round-trip a binary through source and back.

## The single load-bearing idea

Most decompilers are lossy because the source languages they emit (C, pseudocode) cannot express the choices a compiler made. There is no syntax for "the compiler used `rbx` for this loop counter," or "this branch was encoded as a short jump even though near would also work," or "the linker padded the function tail with `nop` `nop` `int3`." So the information is dropped, and recompiling produces a *different* binary.

univdreams's source language (`.ud`) makes those choices first-class. Today's primary mechanism is **pinning the bytes** alongside each instruction (`@asm("text", [bytes])`) and capturing every other byte (headers, padding, data sections) as either structured `@module.build` metadata or `@raw` blocks. The result: a `.ud` file is a complete, executable specification of its binary. The lower path reconstructs the binary byte-for-byte.

When the system encounters something it cannot lift to structured source, it falls back through a chain of escape hatches — typed function signature → `@asm` with bytes → `@raw` bytes — none of which break round-trip. The roof never collapses; it just degrades clarity.

See [round-trip-contract.md](round-trip-contract.md) for the precise definition of what's preserved and at which layer.

## Pipelines

### Decompile pipeline

```
binary file
   │
   ▼
ud-format-elf::Elf64File::parse
   │  parses ehdr / phdrs / shdrs, captures every section's bytes,
   │  and every interstitial padding gap.
   ▼
ud-analysis::discover_functions
   │  layered sources merged into a FunctionMap:
   │    .symtab → names + sizes (when not stripped)
   │    .dynsym → names + sizes for dynamic exports
   │    .eh_frame → sizes via FDE walk; placeholder names
   │    ud-signatures DB → CRT helpers by byte pattern
   │    fill-in pass → size = distance to next neighbour
   ▼
ud-debug::read_debug_info
   │  parses .debug_info via gimli, returns DebugFunction
   │  records (addr → typed signature) for AST attachment.
   ▼
ud-arch-x86::decode + ud-arch-x86::lift_function
   │  per function: bytes → DecodedInsn[] → Function<DecodedInsn>
   │  with CFG (basic blocks + Terminators) recovered from iced
   │  flow-control classification.
   ▼
ud-decompile::build_module + build_function
   │  Build the .ud AST: @module with full ELF metadata,
   │  @section for each ELF section with on-disk content,
   │  Item::Function for each lifted function (with DWARF-
   │  attached signature when available), Item::Raw for the
   │  inter-function gaps and non-text sections.
   ▼
ud-ast::emit
   │  canonical pretty-printer.
   ▼
.ud source text
```

### Compile pipeline

```
.ud source text
   │
   ▼
ud-compile::parse
   │  hand-rolled lexer + recursive-descent parser; produces
   │  a ud_ast::UdFile.
   ▼
ud-compile::lower_to_elf
   │  Read @module.build to reconstruct Ehdr64 / Vec<Phdr64> /
   │  Vec<Shdr64> / padding. Lower every @section to bytes;
   │  match section names to shdr entries (via the resolved
   │  `name` field carried on each shdr); verify each section's
   │  lowered length equals its sh_size. Build an Elf64File
   │  via from_parts, call write_to_vec.
   ▼
binary file
```

The two pipelines are inverses. The AST is the pivot. Pinned bytes in `@asm` and `@raw`, plus the metadata in `@module.build`, are the residuum that makes the inversion exact.

## IR design

The IR is **arch-tagged**, not generic. There is no aspiration to a single SSA form that works for every architecture.

`ud-ir` provides shared concepts (`Function`, `BasicBlock`, `Terminator`) generic over an arch instruction type via the [`ArchInsn`] trait. Per-arch crates implement `ArchInsn` for their decoded type and provide the arch-specific lifter:

```rust
pub trait ArchInsn {
    fn addr(&self) -> VAddr;
    fn original_bytes(&self) -> &[u8];
}
```

The byte-identity contract for the IR layer:

> For any `Function` built from real bytes by an arch's lifter,
> `Function::emit_bytes` returns exactly the input bytes.

This is true by construction — `emit_bytes` concatenates each instruction's preserved `original_bytes` in address order. The CFG is a *view* over the byte stream, not a transformation of it.

`ud-arch-x86::DecodedInsn` carries the iced `Instruction` for analysis plus the original byte slice. iced's `BlockEncoder` is available via `reencode_via_iced` for analysis-then-edit workflows where canonical encoding is acceptable; the round-trip path goes through `emit_preserved` which never re-encodes.

[`ArchInsn`]: ../crates/ud-ir/src/lib.rs

## Crate breakdown

| Crate | Purpose |
|-------|---------|
| `ud-core` | Shared types: `VAddr`, `Result`, `Error`, `assert_bytes_equal`. |
| `ud-format-elf` | ELF64-LE reader + writer with byte-identical round-trip. Public `Elf64File::from_parts` for reconstructive callers. |
| `ud-arch-x86` | x86 backend: decode (iced), Intel formatter, lift to IR with CFG, `DecodedInsn` implementing `ArchInsn`. |
| `ud-ir` | `Function<I>`, `BasicBlock<I>`, `Terminator`, `ArchInsn` trait. Generic over the per-arch instruction type. |
| `ud-analysis` | Function discovery: layered sources (symtab / dynsym / eh_frame / signatures), merge logic in `FunctionMap`, size-filling pass. |
| `ud-signatures` | Byte-pattern matcher with wildcards. v0 DB: x86-64 CRT helpers. |
| `ud-debug` | DWARF reader (gimli). Returns `DebugFunction { addr, name, return_type, params }` for typed signature attachment. PDB / stabs / Mach-O dSYM are future modules. |
| `ud-ast` | `UdFile`, `Module`, `Item`, `FnDecl`, `Stmt`, `Type`, `Param`, `Signature`. Canonical pretty-printer (`emit`). Source of truth for what `.ud` looks like. |
| `ud-compile` | `.ud` parser (text → AST). `lower_function_bytes`, `lower_section_bytes`, `lower_to_elf`. |
| `ud-decompile` | Decompile orchestration: ELF → discover → lift → build AST. `decompile()` returns a `UdFile`; `decompile_to_text` is `emit(decompile(elf)?)`. |
| `ud-cli` | The `ud` binary. Subcommands today: `roundtrip`, `decompile`. |

## Function-discovery strategy

`ud-analysis::discover_functions` runs every available source in increasing-confidence order so the merge in `FunctionMap` resolves name conflicts in favour of the higher-confidence source:

1. **Prologue patterns** (Phase 0; not yet wired but the slot exists in `FunctionSource`).
2. **`.eh_frame`** — FDE walks via gimli. Yields accurate sizes; placeholder `sub_<addr>` names. Survives stripping.
3. **`ud-signatures`** — byte-pattern DB. Yields meaningful names (`deregister_tm_clones`, etc.) for functions that no other source covers. Sizes start at zero; filled in by the post-pass.
4. **`.dynsym`** — names for exported / imported symbols.
5. **`.symtab`** — full symbol table (when not stripped). Authoritative names + sizes.
6. **User overrides** (sidecar config; future).

After all sources merge, `fill_in_sizes_from_neighbors` closes any size-zero entry by setting its size to the distance to the next discovered function in the same executable section. This catches functions for which no source recorded a size — `_init`, `_fini`, signature-matched CRT helpers without an `.eh_frame` entry, etc.

## Naming conventions

- Real names from symtab / DWARF are used as-is.
- Recognized stdlib / CRT helpers get their canonical name from the signature DB.
- Everything else falls back to `sub_<hex_addr>`. The numeric address in the name is parsed by the lower path and used as the layout key, so by default the binary's `.text` section comes back in the same order.

## Failure modes and escape hatches

The structural escape-hatch chain, from richest to most opaque:

1. **Typed function signature**: `fn name(args: T, …) -> R { @asm … }`. Used when DWARF or other source supplies types.
2. **Untyped function**: `fn name() { @asm … }`. Used when no signature is available.
3. **`@raw(addr, [bytes])`**: a slice of bytes inside a section that the analyser couldn't lift to a function. Used for alignment padding inside `.text` and for the entire content of non-loadable sections (`.dynamic`, `.symtab`, debug info).
4. **`@module.build.padding`**: bytes that fall outside any structured region, captured at the file level.

These aren't bugs; they're how round-trip stays intact at every level of structural recovery. A `.ud` file that's 100% `@raw` is a perfectly valid round-tripping representation — it just won't help a human read the program.

## Testing strategy

Every layer of the pipeline has a round-trip property defended by CI. See [round-trip-contract.md](round-trip-contract.md) for the full list. The fixture corpus is two ELF64 binaries totalling 33,680 bytes (whole-binary byte-identity) plus byte-copy-only coverage for 32-bit ELF, PE32, and aarch64 ELF.

The CI pipeline:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

All three jobs run in parallel on every push. 104 tests across 11 crates as of this writing.

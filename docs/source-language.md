# Source language: `.ud`

The `.ud` ("universal dreams") source language is a C-like surface syntax with first-class **directives** that pin compiler choices. The directives are what makes the language capable of being a complete, executable specification of a binary.

This document describes the language as it exists today, with the directive vocabulary actually wired up by the parser and emitter. Forward-looking syntax (`@reg`, `@encoding`, ABI variants beyond what's used today) is mentioned only where called out.

## Design principles

1. **Familiar where it can be.** Functions, types, expressions, and statements look like C/C++. A reader who knows C should be able to skim a `.ud` file and understand control flow at first glance.
2. **Explicit where it must be.** Every choice that affects the emitted bytes is either pinned by a directive or determined by a deterministic rule.
3. **Round-trip first.** The pretty-printer is deterministic. The parser is whitespace-tolerant but normalizes to the canonical form on re-emit. `parse(emit(ast)) == ast` and `emit(parse(canonical_text)) == canonical_text` are tested invariants.
4. **Escape hatches are first-class.** `@asm` carries pinned bytes alongside the textual disassembly; `@raw` captures bytes the analyser couldn't lift to a function. A `.ud` file is *always* a complete representation of its binary.

## File-level header

Every `.ud` file begins with a `@module { … }` block that pins target context plus the full ELF metadata the lower path needs to reconstruct the binary:

```ud
@module {
    arch: "x86_64",
    abi: "sysv",
    format: "elf",
    bits: 0x40,
    endian: "little",
    type: 0x3,
    entry: 0x10a0,
    build: {
        e_ident: [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, …],
        e_machine: 0x3e,
        e_version: 0x1,
        e_phoff: 0x40,
        e_shoff: 0x3a78,
        e_flags: 0x0,
        e_ehsize: 0x40,
        e_phentsize: 0x38,
        e_phnum: 0xd,
        e_shentsize: 0x40,
        e_shnum: 0x24,
        e_shstrndx: 0x23,
        file_size: 0x42b8,
        phdrs: [
            { p_type: 0x6, p_flags: 0x4, p_offset: 0x40, p_vaddr: 0x40, … },
            …
        ],
        shdrs: [
            { name: "", sh_name: 0x0, sh_type: 0x0, … },
            { name: ".interp", sh_name: 0x1b, sh_type: 0x1, … },
            …
        ],
        padding: [
            { offset: 0x334, bytes: [0x00, 0x00, 0x00, 0x00] },
            …
        ],
    },
}
```

The friendly fields at the top (`arch`, `abi`, etc.) reflect interpretation of the ELF header. Inside `build` are every byte of metadata the lower path needs to reconstruct the binary — the program-header table, the section-header table (with each entry's resolved `name` for matching to `@section` blocks), the file size, and every interstitial byte the file has between structured regions.

## Sections

Every section with on-disk content is emitted as a `@section` block. The first argument is the section's name (matched against `shdrs[].name`); the second is its start address (the runtime virtual address for loadable sections, `0x0` for sections without one):

```ud
@section(".text", 0x10a0) {
    @addr(0x10a0)
    fn _start() {
        @asm("endbr64", [0xf3, 0x0f, 0x1e, 0xfa])
        …
    }

    @addr(0x10b0)
    fn deregister_tm_clones() {
        …
    }

    // alignment padding that doesn't belong to any function
    @raw(0x10da, [0x90, 0x90, 0x90, 0x90, 0x90, 0x90])

    @addr(0x10e0)
    fn register_tm_clones() {
        …
    }
}

@section(".rodata", 0x2000) {
    @raw(0x2000, [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00, …])
}

@section(".symtab", 0x0) {
    @raw(0x0, [ … ])
}
```

Inside a section, items must cover the section contiguously: the first item starts at the section's address, and each subsequent item starts exactly where the previous one ended. Gaps and overlaps are hard errors at lower time.

## Functions

```ud
@addr(0x1209)
fn main() -> i32 {
    @asm("endbr64", [0xf3, 0x0f, 0x1e, 0xfa])
    @asm("push rbp", [0x55])
    @asm("mov rbp,rsp", [0x48, 0x89, 0xe5])
    @asm("lea rax,[2004h]", [0x48, 0x8d, 0x05, 0x8c, 0x0e, 0x00, 0x00])
    @asm("mov rdi,rax", [0x48, 0x89, 0xc7])
    @asm("call 0000000000001060h", [0xe8, 0xe0, 0xfe, 0xff, 0xff])
    @asm("mov esi,2Ah", [0xbe, 0x2a, 0x00, 0x00, 0x00])
    @asm("lea rax,[2011h]", [0x48, 0x8d, 0x05, 0x85, 0x0e, 0x00, 0x00])
    @asm("mov rdi,rax", [0x48, 0x89, 0xc7])
    @asm("mov eax,0", [0xb8, 0x00, 0x00, 0x00, 0x00])
    @asm("call 0000000000001070h", [0xe8, 0xd7, 0xfe, 0xff, 0xff])
    @asm("mov eax,0", [0xb8, 0x00, 0x00, 0x00, 0x00])
    @asm("pop rbp", [0x5d])
    @asm("ret", [0xc3])
}
```

What's pinned here:

- **Function address**: `@addr(0x1209)` — used by the lower path to slice the function back into its section's coordinate space. Default function name is `sub_<hex_addr>` for any function the discovery layer couldn't put a real name on; that name encodes the address, so even unnamed functions sort correctly.
- **Typed signature** (when DWARF / signatures supplied one): `() -> i32`. Signature is optional; without one the form is `fn name() { … }`. Parameter types and return types use the type vocabulary below.
- **Per-instruction pinned bytes**: every `@asm("text", [bytes])` has both a human-readable disassembly and the exact encoded bytes. Bytes are the ground truth for round-trip; text is for humans. Future iterations may drop the bytes when a text assembler can produce byte-identical output.

Block boundaries from the lifted CFG surface as `// block: 0x…` comments and direct-branch targets as `// -> 0x…` annotations. They're informational; the parser preserves them through round-trip.

## Type vocabulary

Types appear inside parameter declarations and after `->` in function signatures.

| Type | Meaning |
|------|---------|
| `void` | Unit / no value. Default return type when no `->` clause. |
| `i8`, `i16`, `i32`, `i64` | Signed integers. |
| `u8`, `u16`, `u32`, `u64` | Unsigned integers. |
| `f32`, `f64` | Floating-point. |
| `bool` | C `_Bool`. |
| `char` | A single byte representing a character. |
| `ptr<T>` | Pointer to `T`. Recursive: `ptr<ptr<u8>>` is "pointer to pointer to u8" (e.g. `char**`). |
| `unknown` | A type we couldn't recover. Round-trips verbatim; parser accepts it. |

## Directive vocabulary

Module / section level:

| Directive | Effect |
|-----------|--------|
| `@module { … }` | Required at the top of every file. Pins the target plus full ELF reconstruction metadata. |
| `@section(name, addr) { … }` | Group items under an ELF section. Items must cover the section contiguously. |
| `@raw(addr, [bytes])` | Pin a slice of bytes at a virtual address (or section-relative offset for `sh_addr=0` sections). Used for alignment padding inside `.text` and for the entire content of non-text sections. |

Function-scoped:

| Directive | Effect |
|-----------|--------|
| `@addr(0x…)` | Pin the function's address. Used by the lower path to slice bytes from the section. |

Function body:

| Directive | Effect |
|-----------|--------|
| `@asm("text")` | Instruction in textual assembly form. Bytes derived by a future assembler (not yet implemented). |
| `@asm("text", [bytes])` | Instruction with both text *and* pinned bytes. Bytes are the ground truth on lower today. |

Comments:

| Form | Effect |
|------|--------|
| `// …` (top level) | Free-floating note. Survives round-trip. |
| `// …` (inside section / function) | Same. |

The decompiler emits `// note: …` lines at the top level for functions that exist (per discovery) but couldn't be bodied (typically because no source recorded a size and the size-filling pass couldn't infer one). These are informational and survive round-trip.

## Worked example

Input C:

```c
int do_fac(int n) {
    if (n <= 1) return 1;
    return n * do_fac(n - 1);
}
```

Decompiled:

```ud
@addr(0x11da)
fn do_fac(v: i32) -> i32 {
    @asm("endbr64", [0xf3, 0x0f, 0x1e, 0xfa])
    @asm("push rbp", [0x55])
    @asm("mov rbp,rsp", [0x48, 0x89, 0xe5])
    @asm("sub rsp,10h", [0x48, 0x83, 0xec, 0x10])
    @asm("mov dword ptr [rbp-4],edi", [0x89, 0x7d, 0xfc])
    @asm("cmp dword ptr [rbp-4],1", [0x83, 0x7d, 0xfc, 0x01])
    @asm("jg short 11F4h", [0x7f, 0x07])
    // -> { taken: 0x11f4, fallthrough: 0x11ed }
    // block: 0x11ed
    @asm("mov eax,1", [0xb8, 0x01, 0x00, 0x00, 0x00])
    @asm("jmp short 1206h", [0xeb, 0x14])
    // -> 0x1206
    // block: 0x11f4
    @asm("mov eax,dword ptr [rbp-4]", [0x8b, 0x45, 0xfc])
    @asm("sub eax,1", [0x83, 0xe8, 0x01])
    @asm("mov edi,eax", [0x89, 0xc7])
    @asm("call 00000000000011DAh", [0xe8, 0xdb, 0xff, 0xff, 0xff])
    @asm("imul eax,dword ptr [rbp-4]", [0x0f, 0xaf, 0x45, 0xfc])
    // block: 0x1206
    @asm("leave", [0xc9])
    @asm("ret", [0xc3])
}
```

What's preserved:

- DWARF gave us `(v: i32) -> i32`.
- The CFG structure is implicit: `// block: 0x…` markers show where the lifter decided basic blocks end, and `// -> { taken, fallthrough }` shows direct-branch targets.
- Every byte is pinned via `@asm`'s second argument. iced's Intel formatter gives the human-readable form; the bytes are the ground truth.

## What it doesn't try to do (today)

- **Structured statements.** Function bodies are `@asm` lines. Recovering `let x = a + b` from the assembly is a future phase.
- **Edit-aware re-encoding.** If you change an `@asm` line's text in a way that would alter byte length, the lower path emits the original bytes (which now disagree with the text). A warning for this case is on the near-term list.
- **No semantic refactoring on emit.** The pretty-printer never reorders statements, never renames variables, never simplifies `x = x + 1` to `x++`.

## Reserved syntax

The `@` sigil is reserved for directives. Identifiers may not begin with `@`. Comments are `//` to end of line. String literals support standard C escapes plus `\xNN`. Numeric literals: decimal, `0x` hex; `_` separators allowed.

Keywords that the parser distinguishes from idents: `fn`, `void`, `i8`/`i16`/`i32`/`i64`, `u8`/`u16`/`u32`/`u64`, `f32`/`f64`, `bool`, `char`, `ptr`, `unknown`.

Punctuation tokens: `{` `}` `(` `)` `[` `]` `,` `:` `@` `->` `<` `>`.

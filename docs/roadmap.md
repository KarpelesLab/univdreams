# Roadmap

Phases are ordered by dependency, not calendar. Each phase has a definition of done; the suite of tests defending the contract is the gate.

## Phase 0 — Foundations ✅

- [x] Project plan, README, design docs.
- [x] Cargo workspace skeleton.
- [x] CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
- [x] Round-trip test harness running on real fixtures.
- [x] License (MIT, 2026 Karpeles Lab Inc).

## Phase 1 — ELF + x86-64 instruction-level round-trip ✅

- [x] `ud-format-elf`: hand-rolled ELF64-LE reader + writer, byte-identical.
- [x] `ud-arch-x86`: iced-x86 integration; decode + dual-path emit (preserved bytes for round-trip; `BlockEncoder` for analysis-then-edit).
- [x] CLI: `ud roundtrip <bin>` runs the loop and reports diffs.

The phase exposed iced's canonicalization of redundant prefixes (e.g. drops the `66` data16 on alignment NOPs). The fix shaped the design: structured form ≠ encoder source; original bytes preserve fidelity.

## Phase 2 — Function discovery + IR lifting ✅

- [x] `.symtab` / `.dynsym` consumer (`ud-analysis::discover_from_symbol_tables`).
- [x] `.eh_frame` parser (`ud-analysis::discover_from_eh_frame`).
- [x] Function-boundary fusion via `FunctionMap` merge logic.
- [x] `ud-ir`: generic `Function<I>` / `BasicBlock<I>` / `Terminator` over an `ArchInsn` trait.
- [x] x86 → IR lifter with CFG construction (leaders / blocks / terminators) using iced flow-control.
- [x] Default `sub_<hex_addr>` naming with `@addr` ordering preserved.

## Phase 3 — Source language v0 ✅

- [x] `ud-ast`: AST types + canonical pretty-printer.
- [x] `ud-compile`: hand-rolled lexer + recursive-descent parser; ParseError with line/col diagnostics.
- [x] Round-trip property tests on parser/emitter (synthetic + against real decompile output).
- [x] Directives wired up: `@module`, `@section`, `@addr`, `@asm` (with optional pinned bytes), `@raw`, top-level and section-level comments.
- [x] AST extended with typed function signatures (`Type`, `Param`, `Signature`).

## Phase 4 — Whole-binary source round-trip ✅

- [x] AST / parser / emitter handle complete ELF metadata in `@module.build`: ehdr fields, phdrs, shdrs (with resolved names), padding regions.
- [x] `ud-format-elf::Elf64File::from_parts` exposed for reconstructive callers.
- [x] `ud-compile::lower_to_elf` reads the AST and produces a byte-identical ELF.
- [x] Whole-binary round-trip property defended on every push: `lower_to_elf(parse(decompile_to_text(elf)))` byte-equals the input. Verified across both x86_64 fixtures (33,680 bytes).

This phase wasn't in the original numbering — the original Phase 3 was "structured control flow." Whole-binary round-trip turned out to be the right next step because it's the precondition for everything that follows: edits, signature recovery, type recovery, etc.

## Phase 5 — Type recovery and stdlib signatures (in progress)

What's done:

- [x] `ud-signatures` crate with byte-pattern matcher (exact + wildcard) and DB for x86-64 CRT helpers (`deregister_tm_clones`, `register_tm_clones`, `__do_global_dtors_aux`, `frame_dummy`).
- [x] Size-filling pass for size-less discovery sources (signatures, symtab entries with `st_size = 0`).
- [x] `ud-debug` crate with DWARF reader. `DW_TAG_subprogram` walks yield typed function signatures: parameter and return types via `DW_TAG_base_type` (size+encoding) and `DW_TAG_pointer_type` (recursive).
- [x] Decompile attaches DWARF signatures to `FnDecl` AST nodes.

Still ahead:

- [ ] Conservative confidence scoring for signature matches (currently always-trusts-the-DB).
- [ ] Static-link fixture corpus + libc primitive signatures (`memcpy`, `memmove`, `memset`, `strlen`, `strcpy`, `strcmp`, `strncmp`, `malloc`, `free`, `printf`-family) for glibc/musl.
- [ ] Type recovery from access patterns when DWARF is absent.
- [ ] Composite types (structs, unions, arrays) in the AST type vocabulary.

## Phase 6 — `-O2 scalar` correctness (not started)

Goal: cleanly handle the optimizations scalar `-O2` performs — register allocation, instruction reordering, tail calls, dead-store elimination effects, common subexpression elimination, peephole choices. Mostly about *preserving* what the compiler did, not redoing it.

- [ ] Reordering directives (`@no_reorder`, ordering hints).
- [ ] Register-allocation pinning (`@reg(rN)`).
- [ ] Tail-call recognition (`@tail`).
- [ ] Calling-convention inference covering common variations.
- [ ] Sufficient corpus diversity to catch regressions.

## Phase 7 — Structured statement lifting (not started)

Function bodies today are sequences of `@asm("text", [bytes])` lines. This phase replaces some of those with typed expressions where the lifter can recover them safely:

- [ ] `let x: T = expr;`
- [ ] `return expr;`
- [ ] Simple arithmetic via DWARF + iced semantics.
- [ ] If / while / for from CFG structuring (Sharir, Cifuentes-style).
- [ ] Switch-table recognition (jump tables in `.rodata`).
- [ ] Short-circuit boolean rebuild for `&&` / `||`.

The escape hatch (`@asm` with bytes) remains available at every level of incomplete recovery. Round-trip is preserved by construction — the bytes are still pinned.

## Phase 8 — Edit-aware lower (not started)

Editing semantics are not yet defined. Concretely:

- [ ] Warn (but don't fail) when an `@asm` line's text and pinned bytes disagree.
- [ ] When a function's lowered length changes due to an edit, surface the change so the user can decide whether to repack.
- [ ] Provide a "drop bytes, re-encode from text" mode behind a flag for users who want canonical encodings (paying the cost of losing redundant-prefix preservation).

## Phase 9 — Second arch and second format (not started)

- [ ] PE/COFF reader/writer or Mach-O reader/writer.
- [ ] arm64 backend (or x86 32-bit on the existing format).
- [ ] Toolchain-specific runtime/CRT signatures for the new target.

The arch-trait abstraction (`ArchInsn`) is in place; adding a backend is mostly a question of writing the decoder/encoder/lifter for the new arch and shipping signatures.

### NE (16-bit Windows New Executable) — round-trip + readable listing ✅

- [x] `ud-format::ne`: hand-rolled NE reader (DOS stub, 64-byte NE header, segment / entry / resident+non-resident name / module-reference tables) with byte-identical `write_to_vec`.
- [x] `ud-translate::decompile::decompile_ne`: `@module.format = "ne"` with the full structural decode in `build{}`, plus Ghidra-style `//` listings — imported modules (KERNEL/GDI/USER/…), exported entry points, and a per-segment 16-bit disassembly (`Bitness::Bits16`).
- [x] `ud-translate::compile::lower_to_ne`: reconstructs the file from the authoritative `@raw` coverage; whole-binary source round-trip defended via the `SITEX10.EXE` external fixture.
- [ ] Structured 16-bit lifting (segment:offset addressing, NE relocation records as imports, `if`/`switch`/`goto`) — the natural next increment, mirroring how PE/ELF grew from "skeleton + raw" into structured lifts.

### NE (Win16) execution — Phase 1: loader + 16-bit segmented CPU ✅

`ud analyze --monitor` can now load and *run* a 16-bit Windows NE binary, not
just decode it — reusing the existing Sandbox / Context VFS+registry /
fail-soft-thunk / monitor-report machinery.

- [x] 16-bit segmented mode in the i386 executor (`emulator::isa_int`): a
  `code16` flag making the default operand/address size 16-bit, real segment
  bases (`seg_translate` extended from the FS/GS-only model), 16-bit ModR/M
  addressing (`decode::resolve_modrm16`), far `CALL`/`JMP`/`RETF` and
  `MOV Sreg`, and a selector→base table. The flat 32-bit codec path is
  behaviour-identical (all bases 0, default size 32-bit); 235 emulator unit
  tests stay green.
- [x] NE loader (`ne::load_ne`): reuses `ud_format::ne::NeFile`, maps each
  segment to a 64 KiB linear window, applies internal + imported-ordinal
  relocations (imports → fail-soft thunks via `register_unknown_fallback`),
  and returns an `NeImage` (entry `CS:IP`, `SS:SP`, selector table).
- [x] `Sandbox::load_ne_fail_soft` + `call_ne_entry` drive the entry in 16-bit
  mode through the existing `run_until_sentinel` loop; `ud analyze --monitor`
  detects NE before PE and reports the Win16 call surface.
- Demonstrated on `SITEX10.EXE` (StuffIt Expander 1.0 Setup): loads 3 segments
  + 227 imported ordinals, executes the entry prologue, and reaches the first
  Win16 call (`KERNEL.91` = `InitTask`), surfaced as a fail-soft trap.
### NE (Win16) execution — Phase 2: FAR PASCAL API layer (in progress)

- [x] **FAR PASCAL call ABI** in `win32::dispatch_stub` (it branches on the CPU's
  16-bit mode): arguments read left-to-right as 16-bit words / far pointers,
  return value in `DX:AX`, far return (`RETF n`) with callee stack cleanup.
  `Registry::register_far_pascal` registers stubs keyed by `(module, "@ord")`.
- [x] **Win16 stub module** (`win16`): KERNEL `InitTask` (91, the keystone —
  returns the task's `AX/CX/DX/SI/DI/ES:BX` register block), `WaitEvent` (23),
  `GetVersion` (3); the NE loader resolves known ordinals to these stubs and
  only falls back to trap-on-call for the rest.
- [x] **DOS `INT 21h`** serviced in the run loop (`Trap::SoftwareInterrupt` →
  `win16::service_interrupt`): get-version, current-drive, get/set-vector, …
- [x] Fixed a CPU bug surfaced by real code: the `MOV moffs` opcodes
  (`A0`–`A3`) now use a 16-bit offset in 16-bit address mode.
- Result: `SITEX10.EXE` now executes its MFC / C-runtime startup through
  `InitTask → WaitEvent → GetVersion → INT 21h` (34 instructions, was 3),
  stopping at the next unimplemented ordinal (`KERNEL.30`).
- [ ] Remaining Phase 2: the rest of the KERNEL startup surface, then USER /
  GDI (window class, message loop, dialog procs).
- [ ] **Phase 3** — drive the installer's silent path + capture the extracted
  `EXPANDER.EXE` via `--dump-vfs`.

## Beyond v1

In open consideration once Phases 5–9 stabilize:

- SIMD/vectorized code lifting.
- Cross-arch porting via shared semantic IR (deliberate lossy step).
- LTO/PGO output.
- Packed/obfuscated binaries.
- GUI / IDE integration.
- Decompiling non-CPU bytecode (Java, Wasm, Python `.pyc`, JVM, MSIL) — same architecture, new backends.

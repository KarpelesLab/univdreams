# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until we hit `1.0.0`, minor-version bumps signal intentional API breakage.

## [Unreleased]

## [0.1.2] — 2026-05-16

### Added
- **`ud_emulator::Guest` — FFI-shaped front end over `Sandbox`.** Lets a Rust
  consumer drive a guest module the way they would `dlopen` a shared library:
  `Guest::load(name, bytes)` (auto-runs `DllMain`), `guest.call("Export",
  (arg, …))` with a typed argument tuple and inferred return type,
  `alloc` / `alloc_cstr` / `read` / `write` for the host↔guest data
  boundary. Trait surface: `CallArgs` (`()` through 8-arity), `Dword`
  (`u32` / `i32` / `u16` / `u8` / `bool`), `FromRet` (`u32` / `i32` /
  `bool` / `()`). See README §"Library use" for examples.
- **Win32 stub coverage for the codec-corpus probe path.** New stub
  modules: `version`, `comctl32`, `shell32`, `shlwapi`. ~30 new
  `kernel32` stubs (string / locale / console / time helpers, wide
  twins of existing ANSI stubs, identity `EncodePointer` /
  `DecodePointer`). ~34 new `msvcrt` stubs (real ASCII ctype and
  string / mem implementations, fail-soft I/O, `calloc` / `realloc`,
  a minimal `localeconv`). Six user32 / gdi32 config-dialog
  leftovers.
- Codec-corpus `SKIP` lines now surface the manifest `notes` field so
  non-i386 entries explain themselves.

### Changed
- Codec-corpus probe: ICOpen-confirmed codecs go **7 → 9** (Cinepak
  and HuffYUV newly confirmed). All five previously-blocked targets
  (Cinepak / IAC25 / HuffYUV / Lagarith / MagicYUV) now resolve every
  import.

### Fixed
- CI is green: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, and `cargo test --workspace
  --all-targets` all pass on master after a sweep of mechanical
  clippy fixes and targeted `#[allow(...)]` where the lint flags a
  deliberate design choice (LRESULT / HRESULT casts,
  `PeFile::from_parts` argument count, `StubFn`-mandated `Result`
  wrap, locally-scoped enum globs).
- `TSD.DLL` is labelled `win16` in the codec-corpus manifest — it's
  a 16-bit NE executable, not a 32-bit PE.

## [0.1.1] — 2026-05-15

### Changed
- **Workspace consolidation.** `ud-compile` + `ud-decompile` merged
  into `ud-translate`; `ud-format-{elf,pe,macho,raw}` merged into
  `ud-format`. Same APIs, fewer crates to track.

### Added
- `ud vfw {probe,decode,encode}` — drive a Video-for-Windows codec
  DLL through the `IC*` pipeline inside the sandbox.
- `ud analyze` — sandboxed PE run with a structured JSON report
  (Win32 calls, code-coverage map, traps).
- Optional emulation `Context` layer: a virtual filesystem and a
  virtual registry attach to a `Sandbox` to satisfy samples that
  touch host-shaped resources without ever leaving the sandbox.
- Always-on execution + write coverage tracking.
- 73-entry codec-corpus manifest with an automated
  load / DllMain / `ICOpen` probe runner.
- Import-by-ordinal resolution; `FWAIT` (`0x9B`) decode.
- Thin Mach-O reader / writer with structural `LC_*` decode and
  source-pipeline byte-identical round-trip.

### Fixed
- All broken intra-doc links across the workspace.

## [0.1.0] — 2026-05-15

Initial release.

- Byte-identical round-trip across ELF64, PE/COFF, thin Mach-O
  (x86-64 + arm64), and 6502 raw images, through the `.ud` source
  language.
- Architectures: x86-64 + i386 (via `iced-x86`), AArch64
  (decode + lift), 6502 (full assembler + disassembler).
- Structured statement lifting: `if` / `switch` / `goto`,
  register-named locals, `dword ptr [global] = expr` stores,
  `lea`-as-`&` address-of, stdcall / cdecl push-chain folding,
  tail-call `tail_F(args)`, prologue / epilogue auto-generation,
  SSA expression composition.
- PE / Mach-O readability comparable to Ghidra's Headers + Memory
  Map + Symbol Table + Listing panes.
- DWARF reader for typed function signatures.
- Function discovery layered across `.symtab`, `.dynsym`,
  `.eh_frame`, PE export table, byte-pattern signatures, and
  size-filling for unsymbolised binaries.
- 32-bit i386 software emulator (`ud-emulator`): MMU, regs,
  integer / FPU / MMX ISAs, PE runtime loader, Win32 stub registry
  (`kernel32`, `user32`, `gdi32`, `advapi32`, `ole32`, `mfplat`,
  `msvcrt` with `msvcr71` / `pncrt` aliases, `winmm`, `vfw32`).
- WASM playground at
  <https://karpeleslab.github.io/univdreams/> running the full
  pipeline in-browser.

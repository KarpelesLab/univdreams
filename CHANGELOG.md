# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until we hit `1.0.0`, minor-version bumps signal intentional API breakage.

## [Unreleased]

### Added
- BPF function discovery from call sites (decompile layer 2
  of 6). New `ud-analysis::call_sites::discover_from_bpf_call_sites`
  walks executable sections, decodes every BPF slot, and
  treats every `InsnKind::Call` target (excluding the syscall
  sites already named by layer 1) as a function entry. Synthesizes
  `sub_<addr>` `Function` entries with `FunctionSource::CallSite`;
  the existing `fill_in_sizes_from_neighbors` pass closes
  their sizes off neighbour-function-start. New
  `ud-arch-bpf::call_target` helper exposes the `imm`-based
  target computation for non-syscall calls.
  For `3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr`: 215
  newly-discovered functions split the 39 K-line `fragment_120`
  blob into 217 named blocks total, with round-trip
  byte-identical preserved.
- BPF call-site name resolution (decompile layer 1 of 6). New
  `ud-analysis::bpf_relocs::build_call_site_names` walks
  `SHT_REL` (`.rel.dyn`) entries of type `R_BPF_64_32`,
  resolves the symbol via `.dynsym` + `.dynstr`, and produces
  a `HashMap<u64, String>` from call-instruction address to
  imported symbol name. The BPF decompile renderer consults
  the map for every `InsnKind::Call`, so `call 0xeca`
  becomes `call sol_log_` whenever a relocation covers the
  site. For the example Solana program
  `3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr` this swaps
  268 of the 1661 raw-hex calls to their syscall names
  (205 `abort`, 62 `sol_*`, 1 `custom_panic`); round-trip
  stays byte-identical because the pinned `@asm` bytes are
  untouched.
- ELF format constants for the BPF relocation family
  (`SHT_REL`, `R_BPF_NONE`/`64_64`/`ABS64`/`ABS32`/
  `NODYLD32`/`64_32`/`64_RELATIVE`).

### Added (previous in this Unreleased block)
- `ud solana <program-id>` — fetch a Solana on-chain program
  directly from a JSON-RPC endpoint and decompile it. Recognises
  the three current SBF loaders (`BPFLoader2`,
  `BPFLoaderUpgradeable`, `LoaderV4`), strips their loader-state
  header (validating the ELF magic at the chosen offset), and
  feeds the raw ELF into the standard decompile path. Fetched
  ELFs are cached under `~/.cache/univdreams/solana/` so
  repeated invocations don't hammer the RPC; `--no-cache`
  forces a refresh. End-to-end demo:
  `ud solana 3Ecf8gyRURyrBtGHS1XAVXyQik5PqgDch4VkxrH4ECcr`
  fetches a 365 KB ELF and round-trips it byte-identical through
  `.ud` source.
- `decompile/mod.rs::emit_gap` — for executable BPF sections,
  byte runs that aren't covered by a function symbol are lifted
  as anonymous `fragment_<addr>` functions instead of riding out
  as one giant `@raw` blob. Stripped Solana programs (which
  only expose `.dynsym` with the entrypoint + a panic handler)
  now surface as readable BPF instead of ~315 KB of hex.
- New `ud-arch-bpf` crate — Linux eBPF + Solana SBF
  (sBPFv1 / sBPFv2) instruction decoder, classifier, lifter,
  and `format_insn` text renderer. Fixed-width 8-byte slots
  with `lddw` (opcode 0x18) coalescing its two slots into one
  `DecodedInsn` carrying the combined 64-bit immediate plus a
  follow-up `LddwSecondHalf` continuation, so round-trip
  preserves the full 16 bytes verbatim. Variant-gated mnemonics
  for `callx` (SBFv1+) and the sBPFv2 PQR division ops.
- ELF `e_machine` constants: `EM_BPF = 247` (Linux eBPF) and
  `EM_SBF = 263` (Solana SBF, both v1 and v2). The decompile
  dispatch picks BPF when either is present.
- New `decompile/bpf.rs` renderer — mirrors `decompile/aarch64.rs`:
  one `@asm("text", [bytes])` line per slot, with `// -> name`
  annotations on direct jumps whose target is a known function.
- Linux eBPF round-trip test (`tests/bpf_round_trip.rs`) +
  fixture (`testdata/hello-clang-ebpf-linux.o`, built via
  `scripts/build-bpf-fixtures.sh` against brew-llvm with the
  `bpf` target). The test currently round-trips byte-identical
  via `lower_to_elf(parse(decompile_to_text(elf)))`.
- `@module.arch` mapping for `i386`, `aarch64`, `bpf`, `sbf`
  next to the existing `x86_64` entry — these were previously
  rendered as `"unknown"`.

### Changed
- `ud_analysis::discover_from_symbol_tables` no longer skips
  function symbols with `st_value == 0`. Relocatable ELF
  objects (`.o`) commonly place the first function in `.text`
  at offset 0; the old check rejected those. Linked
  executables don't put real symbols at vaddr 0, so this is
  strictly a relaxation of an over-strict filter.
- `decompile::build_section_items` now only attaches
  discovered functions to executable (`SHF_EXECINSTR`)
  sections. Without this, a function at offset 0 inside `.text`
  of a relocatable `.o` would also get rendered into every
  other `sh_addr == 0` section (`.symtab`, `.strtab`, …).

### Out of scope (deferred)
- Real BPF assembler (text → bytes from scratch). Round-trip
  works via the pinned `@asm` byte list — same shape as x86.
- BPF relocation interpretation. `.rel<sec>` / `.rela<sec>`
  ride as opaque section bytes.
- Murmur3 syscall-hash → name resolution for SBF `call imm`.
- Solana SBFv1 / SBFv2 test fixtures — the platform-tools
  download is large enough that committing pre-built `.so`
  artefacts is the practical path; placeholder lives in
  `scripts/build-bpf-fixtures.sh`.

## [0.1.5] — 2026-05-21

### Added
- AVX / AVX2 coverage for the SSE2 integer family — enough to
  finish MagicYUV's encode + decode end-to-end and the corpus
  hits **12/12 encode + 12/12 decode, 5/5 lossless round-trips
  pixel-exact**. New ops:
  - `0x66 0F 60..6F / 70..7F / D0..FF` SSE2 integer family
    (PUNPCK / PACK / PCMP / PADD / PSUB / PMUL / PMIN / PMAX /
    PAVG / PSAD / PMADD / saturating add+sub) dispatched per-lane
    on both `xmm` and `ymm`; the ymm form runs the same per-128
    kernel across both halves.
  - VEX-encoded Group 12/13/14 imm8 shifts (`0F 71/72/73`) at
    both `xmm` and `ymm` sizes, including PSRLDQ / PSLLDQ.
  - VEX `PSHUFD` / `PSHUFLW` / `PSHUFHW` (`0F 70` with `66/F3/F2`
    prefix) on `xmm` + `ymm`.
  - VPBROADCAST{B,W,D,Q} and VBROADCASTI128 (AVX2 `0F 38 5x/7x`).
  - VEX MOV family: VMOVUPS/VMOVAPS load+store, VMOVDQA/VMOVDQU
    load+store, VMOVNTDQ/VMOVNTPS stores — all in both 128 and
    256-bit sizes.
  - VEX scalar moves: VMOVD load/store, VMOVQ load/store,
    VPINSRB/W, VPEXTRB/W/D, VPMOVMSKB (128 and 256).
  - VPCMPEQD ymm (256-bit), VPXOR/VPAND/VPANDN/VPOR (128 and
    256), VZEROUPPER.
  - Non-VEX `0F 38 F0/F1` — MOVBE r32, m32 / m32, r32 (with the
    `0x66` operand-size prefix reducing to 16-bit). MagicYUV's
    decode path uses big-endian byte-swap loads on its packed
    output stream.
- `Bih.tail: Vec<u8>` — the bytes past the canonical 40-byte
  header when the codec advertises `bi_size > 40`. Several
  codecs store per-instance config in the BIH extension area;
  HuffYUV in particular keeps its Huffman code-length tables
  here and reads them back at compress time via `bih + 0x2c`.
  `host_bih_to_guest` writes the tail verbatim after the
  header; `guest_bih_to_host` reads
  `bi_size.saturating_sub(40)` bytes (capped at `BIH_TAIL_CAP`
  = 1024) into it. Every IC* allocator now reserves room for
  the extension up-front, so codecs writing more than 40 bytes
  no longer get their tail silently truncated.
- `0F B3 /r` — `BTR r/m32, r32` (Bit Test and Reset). Used by
  HuffYUV's `ICDecompress` Huffman-table walk.
- SSE2 XMM dispatch (`isa_sse::dispatch_xmm_int`) — handles
  `0x66 0F 6F/7F/EF` (MOVDQA load/store, PXOR xmm). The
  MMX-shaped opcode space `0F 60..6F | 70..7F | D0..FF`
  becomes XMM 128-bit when the `0x66` mandatory prefix is set;
  routing those through the MMX dispatcher silently zeroed
  only the low 64 bits of XMM stores and left the high 64
  garbage. MagicYUV's stack-resident buffer descriptor relied
  on a full `movdqa [stack], xmm0` zeroing all 16 bytes — the
  missing high 8 made `sub_30410` think there was capacity and
  hand `memcpy` a NULL `current` pointer.
- AVX/AVX2 opcodes used by MagicYUV's encode path:
  `VPCMPEQD ymm` (`VEX.256.66.0F.WIG 76`), `VMOVDQA xmm`
  load/store (`VEX.128.66.0F 6F/7F`), `VMOVDQA ymm` load/store
  (`VEX.256.66.0F 6F/7F`), `VZEROUPPER`
  (`VEX.128.NP.0F 77`).
- `stub_memcpy` trap now reports the caller's return address
  and the top 14 stack dwords. Sub-30410-style helpers that
  forward args without a frame leak their caller's frame into
  the same stack window, so the 2nd-level return address is
  visible without writing a separate stack-walk pass.
- `encode_decode_corpus` failure diagnostics now include
  `codec_eips=[…]` — the distinct EIPs in the codec's image
  preceding the trap. Reveals the path through the codec for
  trace-driven opcode triage.

### Changed
- HuffYUV's ICCompress + ICDecompress now work end-to-end with
  pixel-exact lossless round-trip on a 32×32 RGB24 gradient
  (was the lone remaining encode failure in the corpus
  harness). The previous infinite Kraft-inequality loop was
  caused by `ic_compress_get_format` truncating the codec's
  output BIH at 40 bytes — HuffYUV's Huffman code lengths live
  past that boundary, so the validation loop accumulated zeros
  forever. The decompiler walk via `ud decompile huffyuv-i386.dll`
  + tracing `sub_2820` / `sub_2030` / `sub_1e10` pinned the
  exact `bih + 0x2c` dereference; the fix is structural rather
  than per-codec.
- `encode_decode_corpus` failure diagnostics now show
  *unique* trace-ring EIPs (skeleton of any spinning loop) plus
  a stub-call tail condensed to `dll!name×N` runs plus the
  final three calls with their args. Much easier to spot
  whether a failing codec is in API-call rage, pure guest
  loop, or a single bad pointer.

### State
- `encode + decode` end-to-end: **11 / 12** (excluding Indeo 3,
  decode-only by design).
- Lossless round-trip pixel-exact: **4 / 5** — CamStudio 1.4,
  CamStudio 1.5, Lagarith, HuffYUV. Only MagicYUV remains lossy
  (decode succeeds without trap, but pixels differ — its native
  format is YUV not RGB, so chroma round-tripping isn't bit-
  exact on an RGB input).
- Lone remaining encode failure: MagicYUV traps on a `memcpy`
  with `src = NULL`. The BIH-tail preservation unblocked
  enough of MagicYUV's encode path that it now reaches a NULL
  pointer deeper in — previously masked by the
  `ICCompressGetSize` fallback. Next iteration.

### Investigated
- HuffYUV's `ICCompress` infinite loop pinned to RVA
  `0x1ed8..0x1f50` — a Kraft-inequality check on Huffman
  code lengths:
  ```
    movzx esi, [ecx]    ; read 1 byte (code length)
    ...
    add ebp, esi        ; accumulate
    cmp ebp, 0x100      ; loop until 256
    jl loop_start
  ```
  Only ~37 Win32 stub calls happen across 100 M instructions,
  so the loop is in pure guest code reading from HuffYUV's
  internal state (allocated during `DRV_OPEN` and populated
  from `GetPrivateProfileIntA`-driven config). Our stub
  returns the caller's default for every config key, so the
  Huffman code-length table stays zero-filled and `esi` is
  always 0 → loop never terminates. Closing this needs a
  pre-populated virtual `HKCU\Software\Ben Rudiak-Gould\Huffyuv`
  in `Context.registry` (and possibly seed Huffman tables in
  the INI surface) so the codec's open-mode init actually
  fills its tables. Future work.

## [0.1.4] — 2026-05-19

### Added
- `crates/ud-emulator/tests/encode_decode_corpus.rs` — single
  integration test that drives the VfW IC* compress + decompress
  pipeline end-to-end on each of the 13 ICOpen-confirmed video
  codecs (32×32 RGB24 synthetic input). Reports per-codec pass /
  fail; tracks pixel-exact round-trip for the lossless set.
  Final state of this release:
  ```
    DivX 3.11               enc=ok(105 B)   dec=ok(3072 B)
    DivX 3.11 fast          enc=ok(94 B)    dec=ok(3072 B)
    Cinepak                 enc=ok(706 B)   dec=ok(3072 B)
    Indeo 3                 enc=N/A         dec=N/A   (decode-only by design)
    Indeo 4                 enc=ok(150 B)   dec=ok(3072 B)
    Indeo 5                 enc=ok(128 B)   dec=ok(3072 B)
    MS-MPEG-4 v3 (wmpcdcs8) enc=ok(105 B)   dec=ok(3072 B)
    MS-MPEG-4 v3 (winxp)    enc=ok(162 B)   dec=ok(3072 B)
    HuffYUV                 enc=FAIL  (infinite config-parse loop)
    CamStudio 1.4           enc=ok(3091 B)  dec=ok(3072 B)  rt=EXACT
    CamStudio 1.5           enc=ok(3091 B)  dec=ok(3072 B)  rt=EXACT
    Lagarith                enc=ok(159 B)   dec=ok(3072 B)  rt=EXACT
    MagicYUV                enc=ok(65536 B) dec=ok(3072 B)  rt=lossy
    ─────────────────────────────────────────────────────────
    encode + decode:                       11 / 12
    lossless round-trip pixel-exact:        3 /  5
  ```
- `Cpu::xmm[8]` (128-bit XMM register file), `ymm_high[8]`
  (upper 128 of YMM), `sse_dispatch_count`, `avx_dispatch_count`.
- SSE1 instruction executor with `MOVLPS` / `MOVHLPS` /
  `MOVHPS` / `MOVLHPS` plus store-variants (4 opcodes); AVX VEX
  decoder with `VPXOR`, `VMOVUPS-store`, BMI2 `SHLX` / `SHRX` /
  `SARX` (3 opcodes); x87 `FYL2X` (`D9 F1`).
- `kernel32!VirtualProtect` actually updates MMU page
  permissions and round-trips `lpflOldProtect`.
- Stub-thunk region mapped R-only zeroed at `Sandbox::new` so
  codecs that read a function pointer's bytes (CamStudio's
  hot-patch probe) don't fault on the previously-unmapped
  region.
- `Sandbox::new` pre-registers the canonical system DLL names
  in `state.modules` with synthetic non-zero handles (in the
  `0x7800_0000..0x7900_0000` band, clear of every other mapped
  region); `GetModuleHandleW` / `LoadLibraryW` now actually
  read the wide string and resolve through `state.modules`.
- `kernel32!GetProcAddress` reverse-resolves `hModule` via
  `state.modules` and looks up the function name through the
  stub registry (previously always returned NULL).
- `Sandbox::load` records the loaded codec under its filename
  so `GetModuleHandleA("codec.dll")` finds it.
- `msvcrt!_errno` is now a function returning a stable pointer
  to a lazily-allocated heap cell (was incorrectly registered
  as a data import).
- `msvcr80.dll` / `msvcr90.dll` aliased to the `msvcrt` stub
  set; ~12 new MSVC 8 / 9 CRT additions
  (`_decode_pointer` / `_encode_pointer` identity, `_initterm_e`,
  `sprintf_s` / `sscanf` / `sscanf_s`, `_malloc_crt`, …).
- ~70 Win32 stubs to unblock probe (round 2): new modules
  `version.dll` / `comctl32.dll` / `shell32.dll` / `shlwapi.dll`;
  extensions to `kernel32` / `user32` / `gdi32` / `msvcrt`.
- `Sandbox::ic_get_state` / `ic_set_state` — VfW `ICM_GETSTATE`
  / `ICM_SETSTATE` wrappers, mirroring `ic_compress_*`.
- `ud_emulator::Guest` — FFI-shaped front end over `Sandbox`
  (`dlopen` / typed `call` / `alloc` / `read` / `write`).
- README §"Library use" introduces the `Guest` API.

### Changed
- Heap arena now maps R+W+X (was R+W). Cinepak's encoder ships
  inner-loop assembly that it copies into `malloc`'d memory and
  calls; modelling Windows' default executable heap is simpler
  than chasing per-codec `VirtualProtect(PAGE_EXEC*)`.
- Codec-corpus ICOpen-confirmed: **9 → 13 of 17 DriverProc
  exporters**. The 4 remaining are all audio codecs (3 `.acm` +
  IAC25 Indeo Audio in a DS-filter wrapper) where the `VIDC`
  probe is N/A by design — **every genuine video codec in the
  corpus that exports `DriverProc` now probes `ICOpen`
  successfully**.
- Codec-corpus DllMain: **61 → 64 of 66 i386 entries**.
  Remaining failures: `wmvcore.dll` (145 unresolved imports —
  out of scope), `RealMediaSplitter.ax` (now bails on a
  different fault than before; more honest accounting now that
  the previous "ok" was actually an early bail).
- MagicYUV manifest fourcc corrected `MYUV` → `M8RG`.
- Stale TSD.DLL manifest fix: relabelled `i386` → `win16`
  (it's a 16-bit NE executable).

### Fixed
- `cargo clippy --all-targets -- -D warnings` is clean on
  master; previously several pre-existing lints were tripping
  CI.

### Added
- `crates/ud-emulator/src/emulator/isa_avx.rs` — VEX-encoded AVX
  instruction executor. Handles both VEX prefix forms (2-byte
  `0xC5` and 3-byte `0xC4`), discriminated from legacy LES/LDS
  by the high-bit-set rule on the byte after the prefix. The
  decoded VEX carries `(map, pp, L, vvvv, W)` and the trap on
  any unimplemented combination packs all five plus the opcode
  byte into a single u32 id so the next handler to write is
  obvious. Adds 8 × 128-bit `ymm_high` registers to `Cpu`
  (YMM = `(ymm_high << 128) | xmm`) and `avx_dispatch_count`.
  Three opcodes implemented trace-driven from MagicYUV:
  * `VPXOR xmm1, xmm2, xmm3/m128` (`66 0F EF`)
  * `VMOVUPS xmm2/m128, xmm1` store (`NP 0F 11`)
  * BMI2 `SHLX` / `SHRX` / `SARX` on GP regs
    (`{66,F2,F3} 0F 38 F7`)
- `HostState.errno_cell: Option<u32>` — lazy-allocated CRT
  errno cell address. `msvcrt!_errno` was previously registered
  as a *data* import, which made the PE loader stuff the data
  slot's address (in the `0x70100000` band) into the IAT and
  the codec's `call [iat]` then fetched from a R+W-no-X page.
  Reregistered as a function stub that returns a stable pointer
  to a heap-arena-allocated `u32`. The MSVC contract
  (`int *_errno(void)`) is satisfied because successive calls
  return the same address.
- `kernel32!GetProcAddress` now reverse-resolves `hModule`
  through `state.modules` (the system-DLL pre-registration plus
  the codec's own `Sandbox::load` entry) and looks the name up
  in the stub registry under the matched DLL. Returns the thunk
  address on hit, NULL otherwise. Previously always returned
  NULL.

### Changed
- System-DLL synthetic handle band moved from
  `0x7000_0000..0x7100_0000` to `0x7800_0000..0x7900_0000` —
  the previous band collided exactly with `CONST_ARENA_START`
  (`0x7000_0000`, the host's canned-string region, R+W
  mapped). Codecs that walked `kernel32`'s "PE image" starting
  at its handle were reading const-arena bytes and computing
  function pointers landing inside the arena (R+W, no X) →
  exec-protect fault. The new band sits clear of every other
  mapped region (heap arena, const arena, data-import region,
  TEB, stack, VirtualAlloc range, thunk space) so an
  inadvertent PE-walk produces a clean `MemoryFault` instead.
- Codec-corpus ICOpen-confirmed: **12 → 13 of 17 DriverProc
  exporters** (MagicYUV newly confirmed). The 4 remaining are
  all audio codecs (3 `.acm` + IAC25 Indeo Audio in a
  DS-filter wrapper) where the `VIDC` probe is N/A by design —
  **every genuine video codec in the corpus that exports
  `DriverProc` now probes `ICOpen` successfully**.
- MagicYUV manifest fourcc corrected `MYUV` -> `M8RG` (the
  former is not in the codec's supported set; the latter is).

### Added
- `crates/ud-emulator/src/emulator/isa_sse.rs` — SSE1 instruction
  executor, routed from `dispatch_0f` for the opcode ranges
  `0F 10..1F`, `0F 28..2F`, `0F 50..5F`, `0F C2/C4..C6`. Four
  opcodes implemented (trace-driven from MagicYUV's `DRV_OPEN`):
  `0F 12` MOVLPS / MOVHLPS, `0F 13` MOVLPS m64-store, `0F 16`
  MOVHPS / MOVLHPS, `0F 17` MOVHPS m64-store. Plus eight 128-bit
  `xmm` registers on `Cpu` and an `sse_dispatch_count` for
  observability. The mandatory-prefix discriminator
  (`0x66`/`0xF2`/`0xF3`) is in place — new opcodes can be added
  mechanically as future codecs surface them.
- Three new `pub(super)` accessors on `Cpu` so ISA executors
  outside `isa_int` can read the prefix state: `op_size_16()`,
  `rep_prefix_byte()`, and `advance_eip(n)`.
- MagicYUV's manifest fourcc corrected from `MYUV` (not in
  MagicYUV's supported set) to `M8RG`, an actual MagicYUV
  fourcc. With the corrected fourcc the codec passes its
  fourcc-lookup and enters its decode body — surfacing the
  *next* gap.

### Changed
- MagicYUV's `DRV_OPEN` no longer traps on `0F 12`; it now
  progresses past the SSE1 surface and hits opcode `0xC5`,
  which is the **AVX 2-byte VEX prefix** (MagicYUV is a 2015+
  codec that requires AVX, not just SSE). Closing it needs
  VEX decoding + 256-bit YMM registers + the AVX opcode table
  — substantially larger than the SSE1 surface and out of
  scope for this round.

### Added
- `Sandbox::new` pre-registers the canonical system DLL names
  (`kernel32` / `user32` / `gdi32` / `advapi32` / `ole32` /
  `shell32` / `shlwapi` / `comctl32` / `winmm` / `msvcrt` /
  `msvcr71` / `msvcr80` / `msvcr90` / `pncrt` / `mfplat` /
  `version` / `vfw32`) in `state.modules` with synthetic
  distinct non-zero handles. Codec CRTs commonly probe
  `GetModuleHandleW(L"KERNEL32.DLL")` during init and roll back
  if the handle comes back NULL — Lagarith's CRT was destroying
  its newly-created heap on the NULL return path, then bailing
  in `malloc` once `DRV_OPEN` ran. Closes that bug.
- `GetModuleHandleW` and `LoadLibraryW` now read the wide
  string and resolve through `state.modules` (matching the
  ANSI variants). The W-stubs previously returned 0 for any
  non-NULL pointer regardless of name. Closes Lagarith's
  `ICOpen` rejection path (corpus probe: **11 → 12 of 17
  DriverProc exporters**).

### Fixed
- `kernel32!VirtualProtect` now actually updates MMU page
  permissions for the requested range, and writes the prior
  protection (translated from the page's `Perm` bits back to a
  Win32 `PAGE_*` constant) into `lpflOldProtect`. The previous
  implementation was a no-op that just returned success, which
  caused four corpus codecs (`wmvdecod.dll`, `wmvsdecd.dll`,
  CamStudio 1.4 + 1.5) to fault during `DllMain` when they
  flipped `.text` writable to self-patch a thunk, wrote, then
  flipped it back. `VirtualProtect` on an unmapped address
  correctly returns FALSE.
- Stub-thunk region `[0xFFFE_0000, 0xFFFF_0000)` is now mapped
  R-only (zeroed) at `Sandbox::new`. The run loop already
  intercepts execution at `eip == thunk_addr` before the MMU
  permission check, so execution still routes through
  `dispatch_stub` — but codecs that *read* a function
  pointer's bytes (e.g. CamStudio's hot-patch / forwarder probe
  in DllMain) no longer fault on the unmapped region.

### Added
- `msvcr80.dll` / `msvcr90.dll` are now aliased to the
  `msvcrt` stub set (Visual Studio 2005 / 2008 CRTs — CamStudio
  1.4 links msvcr80, CamStudio 1.5 links msvcr90). Adds the
  MSVC 8 / 9 specific helpers: `__clean_type_info_names_internal`,
  `_crt_debugger_hook`, `_decode_pointer` / `_encode_pointer`
  (identity transform), `_encoded_null`, `_except_handler4_common`,
  `_initterm_e`, `_malloc_crt`, `sprintf_s` / `sscanf` / `sscanf_s`.
- `user32!GetWindowTextA` — config-probe stub returning 0.
- `tests/icopen_trace.rs` — diagnostic harness that drives
  `ICOpen` on a codec with stub-call tracing on, dumping the
  `DllMain` and `DRV_OPEN`-phase Win32 call sequence. Records
  the current findings for the two remaining unconfirmed video
  codecs:
  * **Lagarith** — fixed (see new "Added" entries above).
    The fault chain was a CRT allocator wrapper that called
    `sub_4981(0xff) → ExitProcess(0xff)` whenever `_crtheap`
    was NULL; the heap was being destroyed inside `_CRT_INIT`
    because that function checks `GetModuleHandleW(L"KERNEL32.DLL")`
    and our wide stub was returning 0 for every non-NULL name.
    Diagnosed by running `ud decompile` on the codec and
    reading the function tree — `sub_27ff` (`_CRT_INIT`),
    `sub_466f` (the KERNEL32 probe), `sub_5379` / `sub_5397`
    (heap create / destroy).
  * **MagicYUV** — traps on `UndefinedOpcode 0xF12` (`0F 12` =
    `MOVLPS` / `MOVHLPS`). The codec is SIMD-heavy; closing
    this likely needs an SSE/SSE2 surface expansion, not a
    single opcode add.

### Changed
- Codec-corpus DllMain coverage: **61 → 65 of 66 i386 entries**.
  The four wmv-decoder + CamStudio failures from 0.1.3 are
  resolved by the `VirtualProtect` fix and the thunk-region
  mapping. The lone remaining failure is `wmvcore.dll`
  (145 unresolved imports — fundamentally a missing-stubs
  problem, not an emulator bug).
- Codec-corpus ICOpen-confirmed: **9 → 11 of 17 DriverProc
  exporters** (both CamStudio codecs now probe cleanly).
  Of the 6 remaining: 4 are audio codecs (3 `.acm` + Indeo
  Audio `IAC25_32.AX`) where the `VIDC` probe is N/A by
  design; 2 are video codecs (`lagarith-i386`, `magicyuv-i386`)
  whose `ICOpen` handler returns 0 — a codec-internal matter,
  not a missing-stub one.
- Codec-corpus `DllMain` instruction budget raised from 2 M to
  10 M to cover codecs (`wmvdecod.dll`, ~6 M steps) that do
  heavy CRT init and table generation. Still bounded enough to
  stop adversarial infinite loops in tractable time.

## [0.1.3] — 2026-05-17

### Added
- `Sandbox::ic_get_state` / `Sandbox::ic_set_state` — host-side
  wrappers around the VfW `ICM_GETSTATE` (`0x5009`) and
  `ICM_SETSTATE` (`0x500A`) messages, mirroring the existing
  `ic_compress_*` family. Required by oxideav-tracevfw to drive
  the codec encoder's per-quality-knob round-trip via the public
  state-serialisation surface. Empirical finding: `mpg4c32.dll`
  returns `ICERR_UNSUPPORTED` for both messages (stateless codec)
  — the wrapper surfaces the raw LRESULT so callers can detect
  this cleanly. Ported from oxideav-vfw round 70.
- Forensic test `tests/round69_msadds32_inner_decode_watch.rs` —
  5-test harness that arms `Cpu::add_register_watchpoint`
  snapshots at the four NULL-arg guards inside `msadds32.ax`'s
  inner-decode body at RVA `0xc887..0xc973` and proves all four
  PASS (the bail target `0xc969` is never reached). Pins the
  actual `E_FAIL` (`0x80004005`) source to RVA `0xe2bb` inside
  function `0xe0f4`. Ported from oxideav-vfw round 69.
- Forensic test `tests/round70_msadds32_ea3a_forensic.rs` —
  4-test harness that traces into `0xea3a` (called from RVA
  `0xe13c` inside `0xe0f4`) and pins the loop-overflow bail JCC
  at `0xe282` (`jge +0x37` after `cmp edi, [ebp+0x10]`) with
  concrete register state (`EDI = 0x748`, `[ebp+0x10] = 0x748`).
  Phase 2 A/B falsifies round 63's `helper_addref_patch`
  (proves it's retirable but kept for prior-round test
  backwards compat). Ported from oxideav-vfw round 70.
- Integration test `tests/round70_ic_get_set_state.rs` — 3-test
  harness driving `Sandbox::ic_get_state` / `ic_set_state`
  end-to-end against `mpg4c32.dll`: the MSDN size-discovery probe
  pattern (a zero-length-buffer call returns the byte count or
  `ICERR_UNSUPPORTED`), `get → set → get` idempotency, and a
  smoke against a canned in-test driver. Confirms the empirical
  `ICERR_UNSUPPORTED` outcome at the integration layer. Ported
  from oxideav-vfw round 70.
- 5 in-module unit tests in `src/win32/vfw32.rs` covering
  `ICM_GETSTATE`/`ICM_SETSTATE` constant values, dispatch
  surface, success path, failure path, and probe call.

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

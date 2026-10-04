# arch::codec

The shared spine every `univdreams` arch backend speaks. One
trait, one open registry; the compile and decompile pipelines
dispatch through it so every arch sees the same plumbing
without duplicating it.

## What's in the crate

- `ArchCodec` — the trait. Methods cover the encoder surface
  the rest of the pipeline needs (assemble, jump, call,
  conditional jump, switch dispatch, move, arith, return,
  size queries) with `Unsupported` defaults so arches only
  implement what they model.
- `ArchError` — soft (`Unsupported`) vs hard (`Assemble`,
  `OutOfRange`, `UnknownArch`) errors. The pipeline treats
  `Unsupported` as "fall back to pinned bytes."
- `EncodeHints` — per-call interpretation hints (today just
  `wide`, x86's short-vs-rel32 toggle).
- `SwitchSpec` — shared dispatch descriptor (today only
  `"msvc-jmp-table"` is recognised).
- `registry::register / for_arch` — open registry of
  `(arch_name, e_machine) -> Box<dyn ArchCodec>` factories.

## Adding a new arch

1. Create the arch module (`src/arch/<name>/`) and declare it in
   `src/arch/mod.rs`.
2. Implement `ArchCodec` for your codec type. Start with the
   four "always-supported" methods (`assemble_one`,
   `encode_jump`, `encode_call`, `encode_cond_jump`) and the
   three size queries — return `Unsupported` from everything
   else until you need it.
3. Expose a `pub fn register()` that submits your factory:

   ```rust
   pub fn register() {
       univdreams::arch::codec::register(factory);
   }

   fn factory(
       arch_name: Option<&str>,
       e_machine: Option<u64>,
   ) -> Option<Box<dyn ArchCodec>> {
       if arch_name == Some("riscv64") { Some(Box::new(RiscV64Codec)) }
       else { None }
   }
   ```

4. Call `crate::arch::<name>::register()` from
   `univdreams::translate::register_all_arches` (the workspace's
   single entry point for arch registration). The CLI and
   wasm playground both invoke that automatically.

That's the contract. The lower path and decompile-side
byte-drop pass start using your codec as soon as `for_arch`
resolves it from a parsed `@module` block.

## Stmt → trait method map

| `Stmt::` variant | Codec method asked at lower time | Falls back to |
|---|---|---|
| `Asm { text }` (empty bytes) | `assemble_one(text, ip)` (+ desymbolize) | Hard error |
| `Goto { target, wide }` | `encode_jump(source, target, hints)` | Hard error |
| `IfGoto { cond_code, target, wide }` | `encode_cond_jump_with_code(cond_code, …)` | Hard error |
| `Call { direct_target }` (when set) | `encode_call(source, target, hints)` | Hard error |
| `Switch { dispatch, … }` | `encode_switch_dispatch(spec)` | Hard error |
| `IfBlock` cond/tail (empty) | `encode_cond_jump(text, …)` / `encode_jump(…)` | Hard error |
| `WhileBlock` entry/tail (empty) | same | Hard error |
| `Move { dst, src }` (empty bytes) | `encode_move(dst, src)` | Hard error |
| `Return { value }` (empty bytes) | `encode_return(value)` | Hard error |

The decompile-side byte-drop pass mirrors each of these: it
only clears `bytes` when the codec re-encodes them to match
the original. The byte-identity guard is unconditional.

## Layering note

`arch::codec` deliberately doesn't depend on `ast` —
`ast` already depends on `arch::x86` (for the
canonical-emit derivation of `head_bytes`), so making
`arch::codec` depend on `ast` would close a cycle. The
registry takes raw `(arch_name, e_machine)` pairs that
`translate` extracts from a parsed module.

If you need richer Stmt-aware encoder types here later, do
it through a side crate that depends on both — not by
broadening `arch::codec`.

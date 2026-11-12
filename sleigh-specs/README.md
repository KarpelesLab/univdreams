# SLEIGH processor specifications

These are Ghidra's processor specifications (`.ldefs`, `.pspec`,
`.slaspec`, `.sinc`) for the architectures univdreams has no
hand-written decoder for. They come unmodified from
`Ghidra/Processors/<name>/data/languages/` in
<https://github.com/NationalSecurityAgency/ghidra> (12.2-DEV, commit
`8ca9077040cc43cd790babcfccf19475622a3e9a`).

They are licensed under the Apache License 2.0: see `LICENSE` and
`NOTICE` in this directory.

`build.rs` embeds every file here when the `sleigh` feature is on (the
default), and `src/arch/sleigh.rs` compiles them on first use with the
SLEIGH engine vendored from icicle-emu in `src/sleigh/`.

To add an architecture, copy its `data/languages/` spec files here
under the processor's directory name.

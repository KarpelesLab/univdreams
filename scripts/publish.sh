#!/usr/bin/env bash
# Publish every univdreams crate to crates.io in dependency order.
#
# Usage:
#   scripts/publish.sh           # dry-run all crates
#   scripts/publish.sh --do-it   # actually publish
#
# Each crate is published, then the script waits a few seconds
# so its entry is indexed before the next crate (which depends
# on it) is uploaded.
#
# Requirements: `cargo login <token>` must have been run with a
# token that has publish rights on every crate name.

set -euo pipefail

DO_IT=0
if [[ "${1:-}" == "--do-it" ]]; then
    DO_IT=1
fi

# Topologically sorted (deps first). Mirrors the output of the
# helper in `scripts/publish-order.py`. Re-derive when adding
# new crates.
ORDER=(
    ud-core
    ud-format-elf
    ud-signatures
    ud-analysis
    ud-ir
    ud-arch-6502
    ud-arch-aarch64
    ud-arch-x86
    ud-ast
    ud-format-macho
    ud-format-pe
    ud-compile
    ud-debug
    ud-format-raw
    ud-decompile
    ud-emulator
    ud-cli
    ud-wasm
)

for crate in "${ORDER[@]}"; do
    if [[ $DO_IT -eq 1 ]]; then
        echo "==> publishing $crate"
        cargo publish -p "$crate"
        echo "    waiting for crates.io to index $crate..."
        sleep 15
    else
        echo "==> dry-run $crate"
        cargo publish --dry-run --allow-dirty -p "$crate" || true
    fi
done

echo "all done"

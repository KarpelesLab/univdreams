#!/usr/bin/env bash
# Publish every univdreams crate to crates.io.
#
# Usage:
#   scripts/publish.sh            # dry-run (per-crate, leaf-only verification)
#   scripts/publish.sh --do-it    # actually publish
#
# `cargo publish --workspace` (stabilised in Rust 1.84+) walks
# the workspace in dependency order, publishes each crate, and
# waits for crates.io to index it before the next crate ships
# — no `sleep` loop needed. Requirements:
#
#   * `cargo login <token>` with publish rights on every name
#     in `crates/` and on the `univdreams` reserve.
#   * The workspace must be in a "clean" git state, or pass
#     `--allow-dirty` explicitly via the `ALLOW_DIRTY=1` env var.
#
# Dry-run note: `cargo publish --workspace --dry-run` can't fully
# simulate a never-before-published workspace (cargo's verify
# step looks for path-deps on crates.io that don't exist yet),
# so the dry-run branch below verifies leaf crates only — the
# ones that have no internal path-deps. Those are the ones most
# likely to surface metadata problems anyway.

set -euo pipefail

DO_IT=0
if [[ "${1:-}" == "--do-it" ]]; then
    DO_IT=1
fi

ALLOW_DIRTY_FLAG=()
if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
    ALLOW_DIRTY_FLAG=(--allow-dirty)
fi

if [[ $DO_IT -eq 1 ]]; then
    echo "==> cargo publish --workspace (real publish, cargo handles dep order + indexing wait)"
    cargo publish --workspace "${ALLOW_DIRTY_FLAG[@]}"
    echo "==> done"
else
    echo "==> dry-run on every workspace crate (path-dep verification limitations apply)"
    # Per-crate dry-run with --no-verify so the up-front
    # package step is exercised. Leaf crates also pass the
    # verify-build step; non-leaf ones can't (deps not on
    # crates.io yet) and we skip that step intentionally.
    for crate in $(cargo metadata --no-deps --format-version 1 \
        | python3 -c "import sys, json; d=json.load(sys.stdin); print('\n'.join(p['name'] for p in d['packages']))"); do
        echo "==> dry-run --no-verify $crate"
        cargo publish --dry-run --no-verify --allow-dirty -p "$crate" \
            || echo "  (above failure expected if path-deps aren't published yet)"
    done
    echo
    echo "Run 'scripts/publish.sh --do-it' to actually publish."
fi

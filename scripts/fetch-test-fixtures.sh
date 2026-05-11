#!/usr/bin/env bash
#
# Fetch the external test fixtures listed in
# testdata/external/MANIFEST. Each manifest line is
#   <sha256>  <relative-path>  <url>
#
# Files already present with the right hash are skipped; mismatched
# files are redownloaded. Missing manifest, missing tools, or
# network failures exit non-zero with a message.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$repo_root/testdata/external/MANIFEST"
dest_dir="$repo_root/testdata/external"

if [ ! -f "$manifest" ]; then
    echo "fetch-test-fixtures: no manifest at $manifest" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_cmd() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    hash_cmd() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    echo "fetch-test-fixtures: need sha256sum or shasum on PATH" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "fetch-test-fixtures: curl is required" >&2
    exit 1
fi

while IFS= read -r raw_line; do
    line="${raw_line%%#*}"
    line="${line## }"
    line="${line%% }"
    [ -z "$line" ] && continue
    read -r expected_hash rel_path url <<<"$line"
    [ -z "$url" ] && {
        echo "fetch-test-fixtures: malformed line: $raw_line" >&2
        exit 1
    }
    out_path="$dest_dir/$rel_path"
    if [ -f "$out_path" ]; then
        actual=$(hash_cmd "$out_path")
        if [ "$actual" = "$expected_hash" ]; then
            echo "ok   $rel_path"
            continue
        fi
        echo "warn $rel_path: hash mismatch, redownloading" >&2
    fi
    echo "fetch $rel_path"
    mkdir -p "$(dirname "$out_path")"
    tmp="$out_path.partial"
    curl -fsSL "$url" -o "$tmp"
    actual=$(hash_cmd "$tmp")
    if [ "$actual" != "$expected_hash" ]; then
        echo "fail $rel_path: expected $expected_hash, got $actual" >&2
        rm -f "$tmp"
        exit 1
    fi
    mv "$tmp" "$out_path"
done <"$manifest"

echo "fetch-test-fixtures: done"

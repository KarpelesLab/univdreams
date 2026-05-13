#!/usr/bin/env bash
#
# Build the thin x86-64 and arm64 Mach-O fixtures the test
# corpus relies on. Run on a macOS dev box (clang must be
# present and target both architectures). The output binaries
# are committed under testdata/ so CI on Linux doesn't have to
# rebuild them.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
testdata="$repo_root/testdata"

if ! command -v clang >/dev/null 2>&1; then
    echo "build-macho-fixtures: clang not on PATH; install Xcode CLT" >&2
    exit 1
fi

src="$(mktemp -t ud-macho-hello.XXXXX.c)"
trap 'rm -f "$src"' EXIT
cat > "$src" <<'EOF'
#include <stdio.h>
int main(void) { puts("Hello from macho!"); return 0; }
EOF

clang -arch x86_64 -o "$testdata/hello-clang-macho-x86_64" "$src"
clang -arch arm64  -o "$testdata/hello-clang-macho-arm64"  "$src"

echo "wrote:"
echo "  $testdata/hello-clang-macho-x86_64"
echo "  $testdata/hello-clang-macho-arm64"

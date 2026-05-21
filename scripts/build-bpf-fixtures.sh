#!/usr/bin/env bash
# Rebuild the BPF test fixtures committed to testdata/.
#
# Linux eBPF: produced via brew-installed LLVM (Apple Clang
# ships without the `bpf` target). Committed binary is small
# enough that CI doesn't need clang available.
#
# Solana SBF (sBPFv1 / sBPFv2): produced via `cargo-build-sbf`
# from the Agave toolchain. Sourcing those requires
# `solana-install init` plus a download of the Solana
# platform-tools (~250 MB). When the fixtures aren't present,
# the `bpf_byte_identity_through_source` test simply walks the
# Linux fixture; the SBF code paths still build.

set -euo pipefail
cd "$(dirname "$0")/.."

CLANG="${CLANG:-/opt/homebrew/opt/llvm/bin/clang}"
if ! "${CLANG}" -print-targets 2>&1 | grep -q '^[[:space:]]*bpf'; then
    echo "error: ${CLANG} doesn't support the bpf target." >&2
    echo "       brew install llvm  # Apple Clang skips bpf" >&2
    exit 1
fi

# ---- Linux eBPF .o ----------------------------------------
cat > /tmp/ud-ebpf-filter.c <<'EOF'
int filter(void *ctx) {
    long *p = (long *)ctx;
    long v = p[0];
    if (v == 0) return 0;
    return (int)(v + 1);
}
EOF
"${CLANG}" -target bpf -O2 -c /tmp/ud-ebpf-filter.c -o testdata/hello-clang-ebpf-linux.o
echo "built: testdata/hello-clang-ebpf-linux.o"

# ---- Solana SBF (sBPFv1) ----------------------------------
# To produce: install the Agave toolchain
#   sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
#   export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
#   cargo-build-sbf --manifest-path … --sbf-out-dir testdata/
# Then rename the resulting hello_sbf.so to:
#   testdata/hello-solana-sbfv1.so

# ---- Solana SBFv2 (Agave) ---------------------------------
# Same as above but with `cargo-build-sbf --arch sbfv2`. The
# resulting ELF has `e_machine = 263 (EM_SBF)` plus a flag bit
# in `e_flags` distinguishing v2 from v1. Confirm with:
#   llvm-readelf -h hello-solana-sbfv2.so

echo "done."

#!/usr/bin/env bash
# Build all four versions of editorconfig-core-c (base, correct, incomplete, regression)
# for the security-patch-validator project (Role 1 deliverable).
#
# Two build flavors per version:
#   * build-normal/ : release-style build (no sanitizer)
#   * build-asan/   : ASan/UBSan instrumented build with FORTIFY disabled
#
# Outputs:
#   targets/editorconfig/<version>/build-normal/bin/editorconfig
#   targets/editorconfig/<version>/build-normal/lib/libeditorconfig.so*
#   targets/editorconfig/<version>/build-asan/bin/editorconfig
#   targets/editorconfig/<version>/build-asan/lib/libeditorconfig.so*
#
# The base/ tree is the source tree at commit b4724e4 (parent of the official
# fix commit 5159be8). The correct/ tree has the official fix applied. The
# incomplete/ tree has the fix but with '>' instead of '>=' (off-by-one).
# The regression/ tree has the correct fix plus a guard that rejects any
# pattern containing '{', breaking valid brace alternation.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NORMAL_FLAGS="-g -O0 -fno-omit-frame-pointer -fno-pie -no-pie -fstack-protector-strong -Wl,-z,relro,-z,now"
# Disable FORTIFY so the overflow is caught by ASan, not by __fortify_fail.
# Without FORTIFY, ASan can see the actual stack-buffer-overflow write.
SANITIZE_FLAGS="-g -O0 -fno-omit-frame-pointer -fno-pie -no-pie -fstack-protector-strong -fsanitize=address,undefined -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"
# Executables: keep -fno-pie -no-pie so ASan stack-frame layout is stable and
# the editorconfig binary is non-PIE (matches the name-length target profile).
SANITIZE_EXE_LDFLAGS="-fsanitize=address,undefined -fno-pie -no-pie"
# Shared libraries: never pass -no-pie, otherwise ld treats the .so as an
# executable and fails with "undefined reference to main".
SANITIZE_SHARED_LDFLAGS="-fsanitize=address,undefined"

VERSIONS=(base correct incomplete regression)
for V in "${VERSIONS[@]}"; do
    if [[ ! -d "$V/src/lib" ]]; then
        echo "ERROR: $V/src/lib missing" >&2
        exit 1
    fi

    # Normal build
    echo "=== Building $V (normal) ==="
    rm -rf "$V/build-normal"
    mkdir -p "$V/build-normal"
    ( cd "$V/build-normal" && cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="$NORMAL_FLAGS" \
        .. > /tmp/cmake-normal.log 2>&1 )
    ( cd "$V/build-normal" && make -j4 editorconfig_bin > /tmp/make-normal.log 2>&1 )
    if [[ ! -x "$V/build-normal/bin/editorconfig" ]]; then
        echo "FAILED: $V/build-normal/bin/editorconfig not produced" >&2
        tail -20 /tmp/cmake-normal.log /tmp/make-normal.log >&2
        exit 1
    fi
    echo "  $V/build-normal/bin/editorconfig OK"

    # ASan/UBSan build
    echo "=== Building $V (asan) ==="
    rm -rf "$V/build-asan"
    mkdir -p "$V/build-asan"
    ( cd "$V/build-asan" && cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="$SANITIZE_FLAGS" \
        -DCMAKE_EXE_LINKER_FLAGS="$SANITIZE_EXE_LDFLAGS" \
        -DCMAKE_SHARED_LINKER_FLAGS="$SANITIZE_SHARED_LDFLAGS" \
        .. > /tmp/cmake-asan.log 2>&1 )
    ( cd "$V/build-asan" && make -j4 editorconfig_bin > /tmp/make-asan.log 2>&1 )
    if [[ ! -x "$V/build-asan/bin/editorconfig" ]]; then
        echo "FAILED: $V/build-asan/bin/editorconfig not produced" >&2
        tail -20 /tmp/cmake-asan.log /tmp/make-asan.log >&2
        exit 1
    fi
    echo "  $V/build-asan/bin/editorconfig OK"
done

echo
echo "All four versions built (normal + asan)."
for V in "${VERSIONS[@]}"; do
    echo "  $V:"
    echo "    normal: $(readlink -f $V/build-normal/bin/editorconfig)"
    echo "    asan:   $(readlink -f $V/build-asan/bin/editorconfig)"
done

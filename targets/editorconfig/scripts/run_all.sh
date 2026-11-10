#!/usr/bin/env bash
# Run all security PoCs (A and B) and functional tests on all four versions
# (base, correct, incomplete, regression) of editorconfig-core-c, both the
# normal and ASan-instrumented builds. Produces evidence logs under
# targets/editorconfig/evidence/<version>/<build>/<test-id>.log
#
# This is a Role-1 deliverable: prove that the PoCs reproduce on the
# vulnerable base, that the correct fix suppresses them, that the bypass
# PoC still crashes the incomplete patch, and that the regression patch
# breaks valid behavior while remaining secure.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

POC_TREES="$ROOT/poc-trees"
EVIDENCE="$ROOT/evidence"
mkdir -p "$EVIDENCE"

# Rebuild PoC trees to be sure.
rm -rf "$POC_TREES"
mkdir -p "$POC_TREES"
python3 scripts/make_poc.py --root "$POC_TREES/A" --variant A
python3 scripts/make_poc.py --root "$POC_TREES/B" --variant B

# Find the trigger files. They are very deep, so find them programmatically.
poc_a_trigger=$(python3 -c "
import os
for r,_,fs in os.walk('$POC_TREES/A'):
    for f in fs:
        if f=='trigger.py':
            print(os.path.join(r,f)); raise SystemExit
")
poc_b_trigger=$(python3 -c "
import os
for r,_,fs in os.walk('$POC_TREES/B'):
    for f in fs:
        if f=='trigger.py':
            print(os.path.join(r,f)); raise SystemExit
")
echo "PoC A trigger: len=${#poc_a_trigger}"
echo "PoC B trigger: len=${#poc_b_trigger}"

# Prepare functional test tree (brace alternation). This is a VALID EditorConfig
# pattern per spec.editorconfig.org that base/correct/incomplete handle
# correctly but regression breaks.
FUNC_TREE="$ROOT/func-trees/brace"
rm -rf "$FUNC_TREE"
mkdir -p "$FUNC_TREE"
# .editorconfig with a brace alternation section: [{foo,bar}.py]
cat > "$FUNC_TREE/.editorconfig" <<'EOF'
[{foo,bar}.py]
indent_style = space
indent_size = 4
EOF
# A matching file: foo.py (should match the brace alternation)
echo "print('hello')" > "$FUNC_TREE/foo.py"
# A non-matching file: baz.py
echo "print('world')" > "$FUNC_TREE/baz.py"

# Helper: run one editorconfig binary against one file with ASan env.
run_one() {
    local version="$1"; local build="$2"; local test_id="$3"; local target="$4"
    local version_dir="$version/build-$build"
    local binary="$version_dir/bin/editorconfig"
    local library="$version_dir/lib"
    local outdir="$EVIDENCE/$version/$build"
    mkdir -p "$outdir"
    local outfile="$outdir/$test_id.log"

    # Use ASan options that print stack traces and abort on the first error.
    # detect_leaks=0 because the editorconfig library has harmless leaks
    # that would mask the actual overflow.
    local env_args="ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:symbolize=1:print_stacktrace=1:abort_on_error=1"
    env_args="$env_args UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1"
    env_args="$env_args LD_LIBRARY_PATH=$library"

    # Run with a 30-second timeout (the long path may take a moment).
    local start=$(date +%s.%N)
    local cmd="env $env_args timeout 30 $binary \"$target\""
    echo "$ $cmd" > "$outfile"
    bash -c "$cmd" >> "$outfile" 2>&1
    local rc=$?
    local end=$(date +%s.%N)
    echo "" >> "$outfile"
    echo "exit_code=$rc duration=$(echo "$end - $start" | bc -l 2>/dev/null || echo '?')" >> "$outfile"

    # Quick summary to stdout.
    local line1 line2
    line1=$(head -1 "$outfile")
    if grep -q 'AddressSanitizer' "$outfile"; then
        line2="ASAN_OVERFLOW"
    elif grep -q 'runtime error:' "$outfile"; then
        line2="UBSAN_ERROR"
    else
        line2=$(sed -n '2p' "$outfile" | tr -d '\n' | head -c 80)
    fi
    printf "  %-10s %-8s %-22s rc=%-4s %s\n" "$version" "$build" "$test_id" "$rc" "$line2"
}

echo
echo "=== Security PoCs ==="
for V in base correct incomplete regression; do
    for B in normal asan; do
        run_one "$V" "$B" "poc-A-original" "$poc_a_trigger"
        run_one "$V" "$B" "poc-B-bypass"    "$poc_b_trigger"
    done
done

echo
echo "=== Functional tests (brace alternation: spec.editorconfig.org) ==="
# Expected on base/correct/incomplete: foo.py matches -> indent_style=space
# Expected on regression: foo.py does NOT match -> empty output (broken)
for V in base correct incomplete regression; do
    for B in normal asan; do
        run_one "$V" "$B" "func-brace-match"    "$FUNC_TREE/foo.py"
        run_one "$V" "$B" "func-brace-nomatch"  "$FUNC_TREE/baz.py"
    done
done

echo
echo "Evidence logs are in $EVIDENCE/<version>/<build>/<test-id>.log"

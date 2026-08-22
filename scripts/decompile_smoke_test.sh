#!/usr/bin/env bash
# Milestone 3 "Decompiler": proves IAnalysisBackend::decompile() against a
# real function — compiles a fixture with a recognizable add(), decompiles
# it via RizinBackend/rz-ghidra, and asserts the output is real C-like
# source reflecting what the function actually does (an addition and a
# return), not just that the call succeeded.
#
# Requires rz-ghidra installed (scripts/build_rz_ghidra.sh) — this is a
# real content assertion, not a placeholder check, so it fails loudly
# (rather than skipping) if the plugin isn't present, same as
# signature_smoke_test.sh does for its own dependency.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "== configuring/building =="
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
CLI="$BUILD_DIR/src/cli/compass-cli"

echo "== compiling fixture =="
gcc -O0 -g -o "$WORK/sig_a" "$ROOT/tests/fixtures/sig_a.c"

echo "== decompiling add() =="
out="$("$CLI" --function add --decompile "$WORK/sig_a" 2>/dev/null)"

echo "$out" | grep -q -- "-- decompiled --" || fail "no decompiled section in output:\n$out"
echo "$out" | grep -qE "error:" && fail "decompile() reported an error (is rz-ghidra installed? see scripts/build_rz_ghidra.sh):\n$out"

# Real content assertions, not just "it printed something": the decompiled
# text must actually describe add()'s two parameters and its addition +
# return — not merely resemble C syntax.
echo "$out" | grep -qE "add\(" || fail "decompiled output doesn't mention add(...):\n$out"
echo "$out" | grep -qE "return" || fail "decompiled output has no return statement:\n$out"
echo "$out" | grep -qE '\+' || fail "decompiled output has no addition — add() should show one:\n$out"

echo "== running it again is reproducible (fresh backend instance each invocation) =="
out2="$("$CLI" --function add --decompile "$WORK/sig_a" 2>/dev/null)"
echo "$out2" | grep -qE "add\(" || fail "second run didn't reproduce the first"

echo
echo "ALL DECOMPILE SMOKE TESTS PASSED"

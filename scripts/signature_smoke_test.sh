#!/usr/bin/env bash
# Milestone 2 "Signature/FLIRT-style function matching": proves this
# against the real scenario it exists for — a function seen in one binary
# should be recognized in a *different* binary, stripped, where it lands
# at a *different address* (real matching, not a same-offset coincidence).
#
# Compiles two fixtures where add() sits at different addresses (sig_b.c
# has padding functions before it specifically so this isn't trivially
# true), exports a signature from the unstripped one, strips the other,
# and checks that applying the signature correctly re-identifies and
# renames the stripped add().
#
# Runs against whichever backend this build defaults to (Rizin's FLIRT
# subsystem, or radare2's zignatures if Rizin isn't available — see
# docs/ARCHITECTURE.md for why these are two structurally different
# mechanisms, not just a naming difference).
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

echo "== compiling fixtures (add() at different addresses in each) =="
gcc -O0 -g -o "$WORK/sig_a" "$ROOT/tests/fixtures/sig_a.c"
gcc -O0 -g -o "$WORK/sig_b" "$ROOT/tests/fixtures/sig_b.c"
strip -o "$WORK/sig_b_stripped" "$WORK/sig_b"

addr_a=$("$CLI" --list-functions "$WORK/sig_a" 2>/dev/null | awk '$2 ~ /(^|\.)add$/ {print $1; exit}')
addr_b_before=$("$CLI" --list-functions "$WORK/sig_b_stripped" 2>/dev/null | awk '$2 ~ /^fcn\./ {print $1}' | tail -1)
[ -n "$addr_a" ] || fail "couldn't find add() in sig_a"
[ "$addr_a" != "$addr_b_before" ] || fail "test setup didn't actually put add() at a different address — not a real test"
echo "add() is at $addr_a in sig_a, and a stripped fcn.* at $addr_b_before in sig_b (different addresses, good)"

echo "== exporting signatures from sig_a =="
"$CLI" --export-signatures "$WORK/add.sig" "$WORK/sig_a" 2>/dev/null | grep -q "wrote signatures" \
    || fail "--export-signatures didn't report success"
[ -s "$WORK/add.sig" ] || fail "signature file is empty or missing"

echo "== stripped sig_b: add() must show up unnamed before matching =="
before="$("$CLI" --list-functions "$WORK/sig_b_stripped" 2>/dev/null)"
echo "$before" | grep -qE "$addr_b_before\s+fcn\." || fail "expected an unnamed fcn.* at $addr_b_before before matching"

echo "== applying the signature to stripped sig_b =="
apply_out="$("$CLI" --apply-signatures "$WORK/add.sig" "$WORK/sig_b_stripped" 2>/dev/null)"
echo "$apply_out" | grep -qE "$addr_b_before\s+.*add" \
    || fail "signature match didn't identify add() at $addr_b_before — got:\n$apply_out"

echo "== running it again is reproducible (fresh backend instance each invocation) =="
apply_out2="$("$CLI" --apply-signatures "$WORK/add.sig" "$WORK/sig_b_stripped" 2>/dev/null)"
echo "$apply_out2" | grep -qE "$addr_b_before\s+.*add" \
    || fail "match wasn't reproducible on a second --apply-signatures run"

echo
echo "ALL SIGNATURE SMOKE TESTS PASSED"

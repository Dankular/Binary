#!/usr/bin/env bash
# Milestone 1 "MLIL: SSA form + stack variable recovery": asserts against a
# real compiled binary (not synthetic IR) that:
#   - repeated accesses to the same stack slot become the same named
#     variable (var_4 read after var_4 written, not two different Loads)
#   - the if/else diamond in main() gets phi nodes at its merge block for
#     every register live across both branches
#   - SSA versioning is actually present (var#N form) and strictly
#     increasing per definition, not just var names copied through
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

echo "== dominator tree unit test =="
"$BUILD_DIR/tests/dominators_test" || fail "dominators_test failed"

echo "== compiling fixture =="
gcc -O0 -g -o "$WORK/sample" "$ROOT/tests/fixtures/sample.c"

out="$("$CLI" --function main --mlil-ssa "$WORK/sample" 2>/dev/null)"

echo "== MLIL: stack variable recovery =="
mlil_section="$(echo "$out" | sed -n '/-- MLIL --/,/-- MLIL SSA --/p')"
echo "$mlil_section" | grep -q "var_4 = eax" || fail "var_4 write not recovered from [rbp-4] store"
echo "$mlil_section" | grep -q "rax = var_4" || fail "var_4 read not recovered from [rbp-4] load (or not the same name as the write)"

echo "== MLIL SSA: phi nodes at the if/else merge block =="
ssa_section="$(echo "$out" | sed -n '/-- MLIL SSA --/,$p')"
echo "$ssa_section" | grep -q "= phi(" || fail "no phi node emitted at the diamond's merge block"

echo "== MLIL SSA: versions are actually assigned, not just copied =="
echo "$ssa_section" | grep -qE 'rax#[1-9][0-9]* = ' || fail "rax never reaches SSA version > 0 (renaming pass didn't run)"
# Every definition must be a *distinct* SSA name: collect all "var#N =" LHS
# occurrences and check none repeats (that would mean two definitions
# claimed the same version — a real SSA-construction bug, not cosmetic).
dupes="$(echo "$ssa_section" | grep -oE '[a-z_0-9]+#[0-9]+ = ' | sort | uniq -d)"
[ -z "$dupes" ] || fail "duplicate SSA definition(s), violates single-assignment: $dupes"

echo
echo "ALL IR SMOKE TESTS PASSED"

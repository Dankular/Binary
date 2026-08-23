#!/usr/bin/env bash
# Milestone 3 "p-code → MLIL translation" (docs/DECOMPILER.md's deferred
# item): proves il::translatePcode() against 3 real fixtures chosen to
# exercise the parts of the design that took real iteration to get right —
# see pcode_translator.cpp's file header for how each was verified against
# rz-ghidra's actual `pdgx` XML before being locked in here:
#
#   1. add(a, b): the base case — arithmetic + return.
#   2. max3(a, b, c): two if/else chains, each merging a variable back
#      together at the join point via a real MULTIEQUAL (phi) — proves the
#      "phi already represented by shared-name reassignment" folding.
#   3. arr_sum(arr, n): a for-loop with array indexing (PTRADD+LOAD) and a
#      function call — proves control-flow reconstruction from blockedge,
#      pointer arithmetic, and Call/Ret operand handling together.
#
# Requires rz-ghidra installed (scripts/build_rz_ghidra.sh) — same
# real-content-assertion, fails-loudly-not-skips policy as
# decompile_smoke_test.sh.
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

pcode_of() { "$CLI" --function "$1" --pcode-mlil "$2" 2>/dev/null; }

echo "== add(a, b): arithmetic + return =="
cat > "$WORK/add.c" <<'EOF'
int add(int a, int b) { return a + b; }
EOF
gcc -O0 -g -c -o "$WORK/add.o" "$WORK/add.c"
out="$(pcode_of add "$WORK/add.o")"
echo "$out" | grep -qE "error:" && fail "pcode-mlil reported an error (is rz-ghidra installed? see scripts/build_rz_ghidra.sh):\n$out"
echo "$out" | grep -qE "= add\(param_2, param_1\)|= add\(param_1, param_2\)" \
    || fail "add()'s translated MLIL doesn't show the real addition over its params:\n$out"
echo "$out" | grep -qE "<return" || fail "add()'s translated MLIL has no Ret:\n$out"

echo "== max3(a, b, c): if/else chains with a real MULTIEQUAL merge each =="
cat > "$WORK/max3.c" <<'EOF'
int max3(int a, int b, int c) {
    int m = a;
    if (b > m) m = b;
    if (c > m) m = c;
    return m;
}
EOF
gcc -O0 -g -c -o "$WORK/max3.o" "$WORK/max3.c"
out="$(pcode_of max3 "$WORK/max3.o")"
echo "$out" | grep -qE "error:" && fail "pcode-mlil reported an error:\n$out"
# The MULTIEQUAL folding this exists to regression-guard: no raw
# "unimplemented(\"MULTIEQUAL\"" should ever appear for this fixture — every
# phi here merges a variable with itself under one shared name.
echo "$out" | grep -qi 'unimplemented("MULTIEQUAL"' \
    && fail "max3()'s phi merges should fold away via shared naming, not fall back to Unimplemented:\n$out"
echo "$out" | grep -qE "= cmp\(" || fail "max3()'s comparisons weren't translated:\n$out"
echo "$out" | grep -qE "^0x[0-9a-f]+  if \(t_[0-9a-f]+\) goto 0x[0-9a-f]+ else 0x[0-9a-f]+" \
    || fail "max3()'s translated MLIL has no If node with real branch targets:\n$out"
# Both reassignments of the merged variable (the initial `m = a` and one of
# the two conditional updates) must share one name — proof the translation
# actually recognizes them as the same logical variable, not 3 unrelated
# ones.
merged_name="$(echo "$out" | grep -oE '^0x[0-9a-f]+  [a-zA-Z_][a-zA-Z0-9_]* = a$' | awk '{print $2}' | head -1)"
[ -n "$merged_name" ] || fail "couldn't find max3()'s merged variable's initial assignment from a:\n$out"
echo "$out" | grep -qE "^0x[0-9a-f]+  ${merged_name} = (b|c)\$" \
    || fail "max3()'s conditional reassignment doesn't reuse the same merged variable name ($merged_name):\n$out"

echo "== arr_sum(arr, n): loop + array indexing + call =="
cat > "$WORK/arr_sum.c" <<'EOF'
int helper(int x) { return x + 1; }
int arr_sum(int *arr, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += arr[i];
    }
    return helper(total);
}
EOF
gcc -O0 -g -c -o "$WORK/arr_sum.o" "$WORK/arr_sum.c"
out="$(pcode_of arr_sum "$WORK/arr_sum.o")"
echo "$out" | grep -qE "error:" && fail "pcode-mlil reported an error:\n$out"
echo "$out" | grep -qE "goto 0x" || fail "arr_sum()'s loop has no Goto in translated MLIL:\n$out"
echo "$out" | grep -qE "if \(" || fail "arr_sum()'s loop condition wasn't translated:\n$out"
# PTRADD (base + index*elementSize) is the real array-indexing evidence —
# verified directly against this exact fixture while designing the mapping.
echo "$out" | grep -qE "= add\(arr, mul\(" || fail "arr_sum()'s arr[i] wasn't translated as PTRADD (add+mul over arr):\n$out"
echo "$out" | grep -qE '\[.*\]\.4' || fail "arr_sum()'s array load wasn't translated as a Load:\n$out"
echo "$out" | grep -qE "call\(0x[0-9a-f]+, " || fail "arr_sum()'s call to helper() is missing its argument:\n$out"

echo
echo "ALL P-CODE TRANSLATION SMOKE TESTS PASSED"

#!/usr/bin/env bash
# Milestone 1/3 "Type system v1 extensions — signedness inference": proves
# il::attachTypes() actually distinguishes signed from unsigned stack
# variables against real compiled code, both directions (a false "always
# unsigned" would pass a signed-only test) — see docs/ARCHITECTURE.md.
#
# Also the regression test for two real bugs caught building this:
#   1. ESIL's sign-extend operator `~` wasn't consuming its 2 stack
#      operands (fell into the generic 0-pop-1-push unknown-token
#      fallback), corrupting the RPN stack for every op downstream of it
#      in the same statement — concretely, idiv's paired `~%`/`~/` results
#      came out swapped between eax/edx.
#   2. Signedness evidence collection initially only matched a stack
#      variable used *directly* as a signed op's operand — which never
#      happens at -O0 (the operand is always a register loaded from the
#      stack slot earlier in the block), so evidence never actually fired
#      until register-copy provenance was tracked, including resolving
#      x86-64 sub-register aliasing (eax/rax name the same physical
#      register at different widths, and a stack-to-register copy and the
#      later signed use routinely name it at two different widths).
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

echo "== compiling fixture (signed/unsigned pairs of div/mod/shift) =="
cat > "$WORK/sample.c" <<'EOF'
int sdiv_test(int a, int b) { return a / b; }
unsigned int udiv_test(unsigned int a, unsigned int b) { return a / b; }
int smod_test(int a, int b) { return a % b; }
unsigned int umod_test(unsigned int a, unsigned int b) { return a % b; }
int sar_test(int a) { return a >> 2; }
unsigned int shr_test(unsigned int a) { return a >> 2; }
EOF
# Object file, not a linked executable — this pass is purely static analysis
# over MLIL and needs no entry point (matches how this was verified manually
# against /tmp/signtest.o while developing the fix).
gcc -O0 -g -c -o "$WORK/sample.o" "$WORK/sample.c"

mlil_of() { "$CLI" --function "$1" --mlil "$WORK/sample.o" 2>/dev/null; }

echo "== signed division: no longer unimplemented, both params inferred signed =="
out="$(mlil_of sdiv_test)"
echo "$out" | grep -qi "unimplemented(\">>>>\"\|unimplemented(\"~/\"\|unimplemented(\"~%\")" \
    && fail "sdiv_test still shows a raw unimplemented signed op — lifter regression:\n$out"
echo "$out" | grep -qE "sdiv\(" || fail "sdiv_test's division wasn't lifted as sdiv:\n$out"
echo "$out" | grep -qE "int32_t var_rbp_4 = edi" || fail "sdiv_test's dividend (a) wasn't inferred signed:\n$out"
echo "$out" | grep -qE "int32_t var_rbp_8 = esi" || fail "sdiv_test's divisor (b) wasn't inferred signed:\n$out"

echo "== unsigned division: stays unsigned (this is the direction a fake 'always signed' pass would fail) =="
out="$(mlil_of udiv_test)"
echo "$out" | grep -qE "div\(" || fail "udiv_test's division wasn't lifted as div:\n$out"
echo "$out" | grep -qE "uint32_t var_rbp_4 = edi" || fail "udiv_test's dividend (a) should stay unsigned:\n$out"
echo "$out" | grep -qE "uint32_t var_rbp_8 = esi" || fail "udiv_test's divisor (b) should stay unsigned:\n$out"

echo "== signed modulo =="
out="$(mlil_of smod_test)"
echo "$out" | grep -qE "smod\(" || fail "smod_test's modulo wasn't lifted as smod:\n$out"
echo "$out" | grep -qE "int32_t var_rbp_4 = edi" || fail "smod_test's a wasn't inferred signed:\n$out"
echo "$out" | grep -qE "int32_t var_rbp_8 = esi" || fail "smod_test's b wasn't inferred signed:\n$out"

echo "== unsigned modulo =="
out="$(mlil_of umod_test)"
echo "$out" | grep -qE "mod\(" || fail "umod_test's modulo wasn't lifted as mod:\n$out"
echo "$out" | grep -qE "uint32_t var_rbp_4 = edi" || fail "umod_test's a should stay unsigned:\n$out"
echo "$out" | grep -qE "uint32_t var_rbp_8 = esi" || fail "umod_test's b should stay unsigned:\n$out"

echo "== arithmetic (signed) shift right =="
out="$(mlil_of sar_test)"
echo "$out" | grep -qE "sar\(" || fail "sar_test's shift wasn't lifted as sar:\n$out"
echo "$out" | grep -qE "int32_t var_rbp_4 = edi" || fail "sar_test's a wasn't inferred signed — the register-copy/aliasing bug this regression-guards:\n$out"

echo "== logical (unsigned) shift right =="
out="$(mlil_of shr_test)"
echo "$out" | grep -qE "shr\(" || fail "shr_test's shift wasn't lifted as shr:\n$out"
echo "$out" | grep -qE "uint32_t var_rbp_4 = edi" || fail "shr_test's a should stay unsigned:\n$out"

echo
echo "ALL TYPE INFERENCE SMOKE TESTS PASSED"

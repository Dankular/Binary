#!/usr/bin/env bash
# End-to-end smoke test for Milestone 0: builds a tiny real C program,
# runs compass-cli against it, and asserts the disassembly/CFG/LLIL output
# is what a correct lift of that program should look like. Not a substitute
# for unit tests on the lifter (none exist yet — see docs/ROADMAP.md), but
# it's the thing that actually proves the whole pipeline (load -> analyze
# -> disassemble -> lift) works end to end against a real binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== configuring/building =="
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
CLI="$BUILD_DIR/src/cli/compass-cli"

echo "== compiling fixture =="
gcc -O0 -g -o "$WORK/sample" "$ROOT/tests/fixtures/sample.c"

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "== --info =="
info="$("$CLI" --info "$WORK/sample" 2>/dev/null)"
echo "$info" | grep -q "arch:   x86_64" || fail "arch not reported as x86_64"
echo "$info" | grep -q "format: elf64" || fail "format not reported as elf64"

echo "== --list-functions =="
funcs="$("$CLI" --list-functions "$WORK/sample" 2>/dev/null)"
echo "$funcs" | grep -qE "main( |$)|\.main( |$)" || fail "main not found in function list"
echo "$funcs" | grep -qE "add( |$)|\.add( |$)" || fail "add not found in function list"

echo "== --function add --il =="
add_il="$("$CLI" --function add --il "$WORK/sample" 2>/dev/null)"
echo "$add_il" | grep -q "add eax, edx" || fail "add's disassembly missing expected instruction"
echo "$add_il" | grep -q "eax = add(eax, edx)" || fail "add's LLIL missing lifted arithmetic"
echo "$add_il" | grep -q "<return>" || fail "add's LLIL missing Ret node"

echo "== --function main --il =="
main_il="$("$CLI" --function main --il "$WORK/sample" 2>/dev/null)"
echo "$main_il" | grep -q "call(" || fail "main's LLIL missing at least one Call node"
echo "$main_il" | grep -q "if (" || fail "main's LLIL missing an If node for the branch"
echo "$main_il" | grep -q "goto 0x" || fail "main's LLIL missing a Goto/If branch target"

echo
echo "ALL SMOKE TESTS PASSED"

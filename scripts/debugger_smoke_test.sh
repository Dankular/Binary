#!/usr/bin/env bash
# Milestone 5 "Debugger": proves IDebuggerBackend (RzDebug via a dbg://
# core, native ptrace) against a real target — breakpoint hit with correct
# register state, and a clean exit with the correct exit code.
#
# Compiled *without* -no-pie deliberately: this is also the regression
# test for a real bug caught building this (see docs/DEBUGGER.md) where a
# PIE/ASLR target ran to completion unimpeded instead of stopping at its
# entry point, because launch() was missing rz_debug_use()/
# rz_debug_get_baddr() calls the CLI (`rizin -d`) makes but rz_core_new()
# alone does not replicate.
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

echo "== compiling fixture (PIE — see header comment) =="
cat > "$WORK/sample.c" <<'EOF'
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) {
    int x = add(11, 31);
    printf("%d\n", x);
    return 42;
}
EOF
gcc -O0 -g -o "$WORK/sample" "$WORK/sample.c"
file "$WORK/sample" | grep -q "PIE\|pie" || fail "test setup didn't actually produce a PIE binary — not testing what it claims to"

echo "== breakpoint: stops at add(), with the correct call-convention args =="
out="$("$CLI" --debug "$WORK/sample" --break add --timeout 10 2>/dev/null)"
echo "$out" | grep -q "^stopped: breakpoint" || fail "expected a breakpoint stop — got:\n$out"
bp_addr="$(echo "$out" | grep "^pc: " | awk '{print $2}')"
[ -n "$bp_addr" ] || fail "no pc printed on breakpoint stop"
echo "$out" | grep -qE "rdi = 0x(b|000+b)$" || fail "expected rdi = 0xb (11, first arg) — got:\n$out"
echo "$out" | grep -qE "rsi = 0x(1f|00+1f)$" || fail "expected rsi = 0x1f (31, second arg) — got:\n$out"

echo "== memory write: a real write followed by reading it back matches exactly =="
out1b="$("$CLI" --debug "$WORK/sample" --break add --timeout 10 --poke-stack deadbeef 2>/dev/null)"
echo "$out1b" | grep -q "^poke-stack: wrote=true readback=deadbeef$" \
    || fail "expected a poke-stack write/readback round trip — got:\n$out1b"

echo "== exit: runs to completion with the real exit code =="
out2="$("$CLI" --debug "$WORK/sample" --timeout 10 2>/dev/null)"
echo "$out2" | grep -q "^stopped: exited" || fail "expected an exited stop — got:\n$out2"
echo "$out2" | grep -q "^exitCode: 42" || fail "expected exitCode: 42 — got:\n$out2"

echo "== timeout: an infinite loop is forcibly killed, not left running =="
cat > "$WORK/loop.c" <<'EOF'
int main(void) { for (;;) {} return 0; }
EOF
gcc -O0 -g -o "$WORK/loop" "$WORK/loop.c"
start=$(date +%s)
out3="$("$CLI" --debug "$WORK/loop" --timeout 3 2>/dev/null)"
elapsed=$(( $(date +%s) - start ))
echo "$out3" | grep -q "^stopped: timeout" || fail "expected a timeout stop — got:\n$out3"
[ "$elapsed" -lt 15 ] || fail "took ${elapsed}s to report a timeout — kill isn't working"
sleep 1
if pgrep -f "$WORK/loop" >/dev/null 2>&1; then
    fail "timed-out debuggee is still running — not actually killed"
fi

echo
echo "ALL DEBUGGER SMOKE TESTS PASSED"

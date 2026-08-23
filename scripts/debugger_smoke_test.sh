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

echo "== multi-stop: continuing past a hit breakpoint without a fresh CLI invocation =="
# Milestone 5's "multi-stop session control" gap (docs/DEBUGGER.md) —
# continueExec() itself was already known-correct across repeated calls
# (verified separately); this is the regression test for the CLI actually
# exercising that in one process, driven by --continue.
cat > "$WORK/loopcall.c" <<'EOF'
#include <stdio.h>
int add(int a, int b) { return a + b; }
int main(void) {
    int total = 0;
    for (int i = 0; i < 3; i++) {
        total = add(total, i);
    }
    printf("total=%d\n", total);
    return 0;
}
EOF
gcc -O0 -g -o "$WORK/loopcall" "$WORK/loopcall.c"
out4="$("$CLI" --debug "$WORK/loopcall" --break add --continue 4 --timeout 10 2>/dev/null)"
echo "$out4" | grep -q -- "-- stop 1 --" || fail "expected a '-- stop 1 --' marker (--continue's per-stop output):\n$out4"
[ "$(echo "$out4" | grep -c '^stopped: breakpoint')" -eq 3 ] \
    || fail "expected exactly 3 breakpoint stops (add() called 3 times) before exit:\n$out4"
echo "$out4" | grep -q -- "-- stop 4 --" || fail "expected a 4th stop after the 3rd breakpoint hit:\n$out4"
echo "$out4" | grep -A1 -- "-- stop 4 --" | grep -q "^stopped: exited" \
    || fail "expected the 4th stop to be the process exiting:\n$out4"
# Real per-iteration register state, not just "3 stops happened": add(total,
# i) called with (0,0), then (0,1), then (1,2) — total is 0+0=0 after the
# first call, 0+1=1 after the second, matching what's live in rdi/rsi at
# the *next* call's breakpoint hit.
echo "$out4" | grep -qE "rdi = 0x0$" || fail "1st add() call: expected rdi=0 (total):\n$out4"
echo "$out4" | grep -qE "rsi = 0x1$" || fail "2nd add() call: expected rsi=1 (i) to appear somewhere in the trace:\n$out4"
echo "$out4" | grep -qE "rdi = 0x1$" || fail "3rd add() call: expected rdi=1 (total after 0+0+1) to appear:\n$out4"
echo "$out4" | grep -qE "rsi = 0x2$" || fail "3rd add() call: expected rsi=2 (i) to appear:\n$out4"

echo "== watchpoint: accepted and resolves a data symbol, doesn't disturb the rest of the session =="
# Milestone 5's other "debugger v1 rounding-out" gap. addWatchpoint()/
# removeWatchpoint() are implemented against RzDebug's real command surface
# (dbw, confirmed directly to share the breakpoint list/removal command
# with regular breakpoints — see rizin_debugger_backend.cpp) and
# resolveSymbol() now resolves *data* symbols (isj), not just functions,
# specifically so a watchpoint can target one. What this environment
# cannot verify: the watchpoint actually *firing* — RzDebug's own hardware
# watchpoint arming (`ptrace(PTRACE_POKEUSER)` on the x86 debug control
# register, dr7) fails here ("ptrace POKEUSER: Invalid argument"),
# confirmed via raw `rizin -d` too (not specific to this project's own
# code), while gdb's hardware watchpoints work fine in this exact
# container — a real RzDebug/environment interaction issue, not a
# regression to guard silently past. See docs/DEBUGGER.md.
cat > "$WORK/watchtarget.c" <<'EOF'
#include <stdio.h>
volatile int g_counter = 0;
int add(int a, int b) { return a + b; }
int main(void) {
    g_counter = add(1, 1);
    printf("%d\n", g_counter);
    return 0;
}
EOF
gcc -O0 -g -o "$WORK/watchtarget" "$WORK/watchtarget.c"
out5="$("$CLI" --debug "$WORK/watchtarget" --watch g_counter:4:rw --break add --timeout 10 2>&1)"
echo "$out5" | grep -qE "^watchpoint set: g_counter @ 0x[0-9a-f]+ size=4 perm=rw$" \
    || fail "expected a resolved watchpoint-set line for the g_counter data symbol:\n$out5"
echo "$out5" | grep -q "^stopped: breakpoint" \
    || fail "adding a watchpoint shouldn't stop add()'s own breakpoint from still working:\n$out5"

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

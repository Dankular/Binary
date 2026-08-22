#!/usr/bin/env bash
# Milestone 1 "multi-architecture validation": compiles the same fixture
# for x86-64, ARM64, ARM32, MIPS, and Windows/PE, and asserts compass-cli
# loads, disassembles, and lifts LLIL for every one of them without the
# lifter's generic ESIL evaluator falling over.
#
# This is also a regression test for a real bug this exact process found:
# ARM64's ESIL uses stack pseudo-ops (DUP) that don't exist in x86 ESIL: the
# lifter was silently treating unrecognized identifiers as register reads,
# so `DUP` became a fabricated `Reg("DUP")` instead of an honest
# `Unimplemented`. See llil_lifter.cpp's ALL-CAPS-token handling. `grep -v`
# below would need the fixed binary lifted with `--il` to spot a recurrence.
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
SRC="$ROOT/tests/fixtures/sample.c"

declare -A TOOLCHAINS=(
    [x86_64]="gcc -O0 -g"
    [arm64]="aarch64-linux-gnu-gcc -O0 -g -static"
    [arm32]="arm-linux-gnueabihf-gcc -O0 -g -static"
    [mips]="mips-linux-gnu-gcc -O0 -g -static"
    [pe64]="x86_64-w64-mingw32-gcc -O0 -g"
)

for arch in "${!TOOLCHAINS[@]}"; do
    read -r -a cmd <<< "${TOOLCHAINS[$arch]}"
    compiler="${cmd[0]}"
    command -v "$compiler" >/dev/null || fail "$compiler not installed (needed for $arch)"

    out="$WORK/sample_$arch"
    [ "$arch" = "pe64" ] && out="$out.exe"
    "${cmd[@]}" -o "$out" "$SRC" || fail "failed to compile $arch fixture"

    echo "== $arch: --info =="
    info="$("$CLI" --info "$out" 2>/dev/null)" || fail "$arch: --info failed"
    echo "$info" | grep -q "functions: [1-9]" || fail "$arch: no functions discovered"

    echo "== $arch: --function main --il =="
    il="$("$CLI" --function main --il "$out" 2>/dev/null)" || fail "$arch: --function main --il failed"
    echo "$il" | grep -q "call(" || fail "$arch: main's LLIL missing a Call node"
    echo "$il" | grep -qE "if \(|goto 0x" || fail "$arch: main's LLIL missing branch control flow"
    # Regression guard: an ESIL identifier the lifter doesn't model should
    # never masquerade as a register read (see header comment above).
    echo "$il" | grep -qE '= (DUP|POP|CLEAR)$' && fail "$arch: an ESIL pseudo-op leaked through as a fabricated register (regression!)"

    echo "== $arch: --function main --hlil (clean if/else, no fallback) =="
    hlil="$("$CLI" --function main --hlil "$out" 2>/dev/null)" || fail "$arch: --function main --hlil failed"
    hlil="$(echo "$hlil" | sed -n '/-- HLIL --/,$p')"
    echo "$hlil" | grep -q "^if (" || fail "$arch: HLIL missing a structured if statement"
    echo "$hlil" | grep -q "} else {" || fail "$arch: HLIL missing the else clause (should be a clean diamond)"
    # Regression guard: this exact case (MIPS branch-delay-slot placement)
    # previously made flattenBlock miss the branch entirely, producing
    # neither a structured if nor a fallback goto — a silently truncated
    # CFG. label_0x/goto here means structuring degraded (acceptable in
    # general, per hlil_builder.hpp's documented scope) OR a raw "if (...)
    # goto X else Y" one-liner means the If was misfiled as an ordinary
    # statement (never acceptable — see flattenBlock's header comment).
    echo "$hlil" | grep -qE "^if \(.*\) goto 0x" && fail "$arch: an If expression leaked through as a plain statement instead of structuring (regression!)"
done

echo
echo "ALL MULTI-ARCH SMOKE TESTS PASSED (${!TOOLCHAINS[@]})"

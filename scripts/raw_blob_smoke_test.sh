#!/usr/bin/env bash
# Milestone 1 "Raw firmware blob format validation" (docs/ROADMAP.md): proves
# IAnalysisBackend::loadRaw() against a real headerless flat binary (no
# ELF/PE/Mach-O header at all — objcopy -O binary, the same shape a firmware
# flash dump or bare shellcode file has), asserting real disassembled content
# comes back, not just that loading didn't crash.
#
# Regression test for a real bug found building this: the file's one
# whole-file IO map's permission comes directly from the flags loadRaw()
# opens it with (a raw file has no section headers of its own to carry an
# executable bit, unlike ELF/PE) — RZ_PERM_R/R_PERM_R (load()'s existing
# flag, fine for ELF/PE where each section's own executable bit is what
# analysis actually checks) left the map non-executable, so aa/aaa silently
# found zero functions even though disassembly at the exact same address
# was completely correct. Confirmed directly (`oml` showed the map as "r--"
# instead of "r-x", the one difference from an otherwise-identical manual
# `rizin` CLI session that did find functions) before fixing it to
# RZ_PERM_RX/R_PERM_RX — see rizin_backend.cpp/radare2_backend.cpp's
# loadRaw() comments.
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

echo "== producing a real headerless flat binary =="
cat > "$WORK/fw.c" <<'EOF'
int add(int a, int b) { return a + b; }
EOF
gcc -O0 -c -fno-pic -o "$WORK/fw.o" "$WORK/fw.c"
objcopy -O binary --only-section=.text "$WORK/fw.o" "$WORK/fw.bin"
# Sanity check on the fixture itself: this must NOT be a format loadRaw's
# regular load() path would already handle — otherwise this test wouldn't
# actually be exercising loadRaw() at all.
file "$WORK/fw.bin" | grep -qiE "ELF|PE32|Mach-O" && fail "test setup produced a real-header binary, not the headerless blob this test needs"

echo "== --raw with an unknown architecture is rejected, not silently mis-loaded =="
out0="$("$CLI" --raw bogus_arch --info "$WORK/fw.bin" 2>&1)" && fail "expected --raw bogus_arch to fail, but it succeeded:\n$out0"
echo "$out0" | grep -qi "unknown --raw architecture" || fail "expected a clear unknown-architecture error:\n$out0"

echo "== --info reflects the caller-supplied arch/format, not a guess =="
out1="$("$CLI" --raw x86_64 --info "$WORK/fw.bin" 2>/dev/null)"
echo "$out1" | grep -q "^format: raw$" || fail "expected format: raw:\n$out1"
echo "$out1" | grep -q "^arch:   x86_64$" || fail "expected arch: x86_64:\n$out1"
echo "$out1" | grep -q "^entry:  0x0$" || fail "expected entry: 0x0 (no --base-addr given):\n$out1"

echo "== --list-functions finds real code with no header to guide it =="
out2="$("$CLI" --raw x86_64 --list-functions "$WORK/fw.bin" 2>/dev/null)"
echo "$out2" | grep -qE "^0x0 +fcn\." || fail "expected a function found at address 0:\n$out2"

echo "== disassembly/LLIL show the real add() semantics, not empty/garbage output =="
fn_name="$(echo "$out2" | awk '{print $2}' | head -1)"
[ -n "$fn_name" ] || fail "couldn't extract the function name from --list-functions output"
out3="$("$CLI" --raw x86_64 --function "$fn_name" --il "$WORK/fw.bin" 2>/dev/null)"
echo "$out3" | grep -qE "^  0x0 +endbr64" || fail "expected the function to start with endbr64 at 0x0:\n$out3"
echo "$out3" | grep -q "eax = add(eax, edx)" || fail "expected add()'s lifted LLIL addition:\n$out3"
echo "$out3" | grep -q "<return>" || fail "expected a Ret node:\n$out3"

echo "== --base-addr rebases the whole file, not just cosmetically =="
out4="$("$CLI" --raw x86_64 --base-addr 0x08000000 --list-functions "$WORK/fw.bin" 2>/dev/null)"
echo "$out4" | grep -qE "^0x8000000 +fcn\." || fail "expected the function at the rebased address 0x8000000:\n$out4"

echo
echo "ALL RAW BLOB SMOKE TESTS PASSED"

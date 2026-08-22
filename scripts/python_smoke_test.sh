#!/usr/bin/env bash
# Milestone 2 "Python bindings mirroring the C++ API": builds compass_python
# (pybind11) and drives it from real Python — loading a binary, listing
# functions, lifting IL, and running a plugin-supplied pass — asserting on
# actual output, not just that it imports.
#
# Regression guard for two real bugs the Python path specifically surfaced
# (both fixed in plugin_manager.cpp, see docs/ARCHITECTURE.md):
#   1. dlerror() called twice in one expression (it clears its message on
#      read, so the second call always returns null) segfaulted trying to
#      build a std::string from that null on ANY dlopen failure.
#   2. A plugin dlopen()d from code living inside compass.so (which
#      Python's import loads RTLD_LOCAL, unlike an executable's own
#      symbols) couldn't resolve symbols like PassRegistry::instance()
#      back into it — dlopen itself failed with "undefined symbol". Fixed
#      by promoting compass-core's own object to RTLD_GLOBAL before the
#      first plugin load (plugin_manager.cpp's promoteSelfToGlobalScope()).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
PYTHON="${PYTHON:-python3.11}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

command -v "$PYTHON" >/dev/null || fail "$PYTHON not installed"

echo "== configuring/building (incl. Python bindings) =="
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null

MODULE_DIR="$BUILD_DIR/src/bindings/python"
MODULE=$(find "$MODULE_DIR" -maxdepth 1 -name "compass.cpython-*.so" | head -1)
[ -n "$MODULE" ] || fail "compass_python module wasn't built — is pybind11-dev installed?"

PLUGIN="$BUILD_DIR/plugins/example_io_flagger/example_io_flagger.so"
[ -f "$PLUGIN" ] || fail "example plugin .so wasn't built: $PLUGIN"

echo "== compiling fixture =="
gcc -O0 -g -o "$WORK/sample" "$ROOT/tests/fixtures/sample.c"

echo "== driving compass from real Python =="
# set -e means a non-zero exit here (an AssertionError, or Python itself
# crashing) fails this whole script immediately — no separate check needed
# after the heredoc.
PYTHONPATH="$MODULE_DIR" "$PYTHON" - "$WORK/sample" "$PLUGIN" <<'PYEOF'
import sys
import compass

sample_path, plugin_path = sys.argv[1], sys.argv[2]

s = compass.Session()
assert s.load(sample_path), f"load() failed: {s.last_error()}"

info = s.info()
assert info["arch"] == "x86_64", f"expected x86_64, got {info['arch']}"
assert info["format"] == "elf64", f"expected elf64, got {info['format']}"

names = [f[0] for f in s.list_functions()]
assert any(n.endswith("main") for n in names), f"main not found in {names}"
assert any(n.endswith("add") for n in names), f"add not found in {names}"

hlil = s.lift_hlil("main")
assert "if (" in hlil, "HLIL missing structured if statement"
assert "} else {" in hlil, "HLIL missing else clause"

mlil_ssa = s.lift_mlil("main", ssa=True)
assert "= phi(" in mlil_ssa, "MLIL SSA missing phi node at the if/else merge"

annotations = s.run_passes("main", [plugin_path], ["lift-all", "callgraph", "flag-io-callers"])
assert any("IO caller: printf" in a for a in annotations), f"missing printf flag in {annotations}"
assert any("IO caller: puts" in a for a in annotations), f"missing puts flag in {annotations}"

print("PYTHON_CHECKS_OK")
PYEOF

echo
echo "ALL PYTHON SMOKE TESTS PASSED"

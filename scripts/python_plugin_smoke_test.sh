#!/usr/bin/env bash
# Milestone 2 "Python-side plugin loading": importlib-discovered plugins
# written *in* Python (a PluginManager counterpart for Python authors),
# not just calling the C++ API from a Python script — the item
# docs/ROADMAP.md tracked as a real, un-picked-up follow-on. See
# src/bindings/python/compass_plugins.py and compass_py.cpp's file header
# for the design.
#
# Regression guard for two real bugs found running this against an actual
# pass (both in compass_py.cpp, see its comments):
#   1. PYBIND11_OVERRIDE_PURE's default argument-casting policy
#      (automatic_reference) resolves any lvalue-reference argument to
#      *copy*, not *reference* — so `Function& fn` crossing into a Python
#      override was silently copied every time, and fn.add_annotation(...)
#      inside a Python pass never reached the real Function. Fixed by
#      hand-building the override call with an explicit `reference` policy.
#   2. A pass constructed and registered inside a function (the normal
#      shape for a plugin's register()) with no Python variable left
#      outstanding afterward was garbage-collected before Workflow::run()
#      ever called it, despite PassRegistry holding a live shared_ptr to
#      it — pybind11's shared_ptr holder didn't keep the underlying
#      PyObject alive on its own. Fixed by pinning a real Python reference
#      to every registered pass for the process's lifetime (leaked
#      deliberately, same "never tear down" reasoning PluginManager's own
#      destructor doc note already documents for .so plugins — also
#      needed to avoid a Python-interpreter-shutdown-ordering crash a
#      plain static container's destructor hit).
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

PY_BINDINGS_DIR="$ROOT/src/bindings/python"
[ -f "$PY_BINDINGS_DIR/compass_plugins.py" ] || fail "compass_plugins.py loader is missing"

PLUGIN_DIR="$ROOT/plugins/example_py_io_flagger"
[ -f "$PLUGIN_DIR/io_flagger.py" ] || fail "example Python plugin is missing: $PLUGIN_DIR/io_flagger.py"

echo "== compiling fixture =="
gcc -O0 -g -o "$WORK/sample" "$ROOT/tests/fixtures/sample.c"

echo "== loading a Python-authored plugin, running it, and checking real findings =="
PYTHONPATH="$MODULE_DIR:$PY_BINDINGS_DIR" "$PYTHON" - "$WORK/sample" "$PLUGIN_DIR" <<'PYEOF'
import sys
import compass
import compass_plugins

sample_path, plugin_dir = sys.argv[1], sys.argv[2]

loaded = compass_plugins.load_directory(plugin_dir)
assert loaded == ["io_flagger"], f"expected to load io_flagger, got {loaded}"

# The pass must actually be resolvable through PassRegistry by name now —
# proof it's indistinguishable from a C++-supplied one, not a separate
# Python-only pass list.
s = compass.Session()
assert s.load(sample_path), f"load() failed: {s.last_error()}"

annotations = s.run_passes("main", [], ["py-flag-io-callers"])
assert any("IO caller (py): printf" in a for a in annotations), f"missing printf flag in {annotations}"
assert any("IO caller (py): puts" in a for a in annotations), f"missing puts flag in {annotations}"

# A pass that calls fn.add_annotation() from a name that ran and returned
# (register()'s own frame) must still be alive and produce real output —
# the specific shape both regression-guarded bugs above needed to surface.
print("PYTHON_PLUGIN_CHECKS_OK")
PYEOF

echo "== a second, independent run reproduces the same result (no leftover process state assumed) =="
out2=$(PYTHONPATH="$MODULE_DIR:$PY_BINDINGS_DIR" "$PYTHON" - "$WORK/sample" "$PLUGIN_DIR" <<'PYEOF'
import sys
import compass
import compass_plugins

sample_path, plugin_dir = sys.argv[1], sys.argv[2]
compass_plugins.load_directory(plugin_dir)
s = compass.Session()
s.load(sample_path)
print(len(s.run_passes("main", [], ["py-flag-io-callers"])))
PYEOF
)
[ "$out2" -ge 2 ] || fail "second independent run didn't reproduce at least 2 annotations, got: $out2"

echo
echo "ALL PYTHON PLUGIN SMOKE TESTS PASSED"

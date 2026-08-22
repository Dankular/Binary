#!/usr/bin/env bash
# Milestone 2 "plugin discovery/loading": builds the example plugin
# (plugins/example_io_flagger, a real standalone .so, not compiled into
# compass-core), loads it into compass-cli via dlopen, and asserts its
# pass actually runs and produces correct output.
#
# Also a regression test for a real crash this exact mechanism produced
# while being built: PluginManager used to dlclose() a plugin's .so once
# loaded, which segfaulted at process exit once PassRegistry's static
# destructor tried to destroy a shared_ptr<IAnalysisPass> whose vtable
# lived in the now-unmapped plugin code (see plugin_manager.cpp). This
# script's exit-code check on every invocation is what catches a
# regression of that.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

echo "== configuring/building (incl. example plugin) =="
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
CLI="$BUILD_DIR/src/cli/compass-cli"
PLUGIN="$BUILD_DIR/plugins/example_io_flagger/example_io_flagger.so"
[ -f "$PLUGIN" ] || fail "example plugin .so wasn't built: $PLUGIN"

echo "== compiling fixture =="
gcc -O0 -g -o "$WORK/sample" "$ROOT/tests/fixtures/sample.c"

echo "== --list-passes without any plugin (built-ins only) =="
builtin_passes="$("$CLI" --list-passes)"
echo "$builtin_passes" | grep -q "^lift-all" || fail "built-in pass lift-all missing"
echo "$builtin_passes" | grep -q "^callgraph" || fail "built-in pass callgraph missing"
echo "$builtin_passes" | grep -q "flag-io-callers" && fail "plugin pass visible without loading the plugin (registry not process-scoped correctly?)"

echo "== --list-passes with the plugin loaded =="
plugin_passes="$("$CLI" --list-passes --plugin "$PLUGIN" 2>/dev/null)"
echo "$plugin_passes" | grep -q "flag-io-callers" \
    || fail "plugin's pass not registered after loading — plugin and host may have separate PassRegistry singletons (see plugin_manager.cpp's ENABLE_EXPORTS note)"

echo "== running the plugin's pass against main() (calls printf and puts) =="
out="$("$CLI" --function main --plugin "$PLUGIN" --run-pass lift-all --run-pass flag-io-callers "$WORK/sample" 2>&1)"
exit_code=$?
[ "$exit_code" -eq 0 ] || fail "compass-cli exited $exit_code (regression: see the dlclose()/vtable-lifetime note above)"
echo "$out" | grep -q "IO caller: printf" || fail "flag-io-callers didn't flag the call to printf"
echo "$out" | grep -q "IO caller: puts" || fail "flag-io-callers didn't flag the call to puts"

echo "== unknown pass name is reported, not fatal =="
# Capture full output before grepping it (rather than piping straight into
# `grep -q`) — grep -q closes its stdin as soon as it finds a match, which
# SIGPIPEs compass-cli if it's still writing later output; with `set -o
# pipefail` that non-zero exit fails the pipeline even though grep did
# match. Hit exactly this while writing this test.
unknown_pass_out="$("$CLI" --function main --run-pass this-pass-does-not-exist "$WORK/sample" 2>&1)"
unknown_pass_exit=$?
[ "$unknown_pass_exit" -eq 0 ] || fail "compass-cli exited $unknown_pass_exit on an unknown pass name (should warn, not fail)"
echo "$unknown_pass_out" | grep -q "pass not found: this-pass-does-not-exist" \
    || fail "unknown pass name wasn't reported as a warning"

echo "== repeated runs don't crash (regression guard for the dlclose bug) =="
for i in 1 2 3; do
    "$CLI" --function main --plugin "$PLUGIN" --run-pass lift-all --run-pass flag-io-callers "$WORK/sample" >/dev/null 2>&1
    [ "$?" -eq 0 ] || fail "run $i exited non-zero"
done

echo
echo "ALL PLUGIN SMOKE TESTS PASSED"

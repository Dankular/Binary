# Decompiler (Milestone 3)

## What this is

`IAnalysisBackend::decompile(Address entry)` (`src/core/include/compass/core/backend.hpp`)
decompiles the function at `entry` to C-like source text. Implemented by
`RizinBackend` (`src/core/src/rizin_backend.cpp`) over
[rz-ghidra](https://github.com/rizinorg/rz-ghidra): a Rizin plugin that is a
**self-contained port of Ghidra's C++ decompiler** — the actual Ghidra Java
application, its Swing UI, and the JVM are never involved. Only the
decompiler's C++ source (vendored as a git submodule) is compiled, as a
static library linked into a `.so` Rizin dlopen's from its plugin
directory. This is the same reuse-over-reimplementation principle behind
choosing Rizin/radare2 over writing a disassembler from scratch: Ghidra's
decompiler is a mature, widely-used p-code-based decompiler, and there is
no value in re-deriving it.

## Getting it

```
scripts/build_rz_ghidra.sh
```

Requires Rizin already installed (`scripts/build_rizin.sh`) — rz-ghidra is
a plugin for it, not standalone. No Compass rebuild is needed afterward:
the plugin is dlopen'd at runtime, not linked at Compass's build time (see
"Why runtime, not build time" below).

Once installed:

```
compass-cli --function <name> --decompile <binary>
```

## Scope (v1)

`DecompiledFunction` is deliberately small:

```cpp
struct DecompiledFunction {
    bool success = false;
    std::string error;
    std::string code;  // C-like decompiled text
};
```

This is rz-ghidra's own rendered text (via its `pdgj` command's `code`
field), not a structured AST and not fused with Compass's own IL stack.
Compass already has a real, independent structuring decompiler — HLIL
(dominator-based if/else and while-loop recovery, see ARCHITECTURE.md) —
built from our own MLIL/SSA. rz-ghidra's decompiler is a **second,
separate view**, backed by Ghidra's mature type/calling-convention
inference, not a replacement for HLIL or a data source HLIL consumes (yet).

**Deferred, tracked as real follow-on work, not silently dropped:**
mapping rz-ghidra's p-code output back into Compass's own MLIL/HLIL (the
original plan sketched in an early draft of ARCHITECTURE.md) — the
per-token `annotations` array `pdgj` already returns (address, syntax
class, variable identity per span) is exactly what such a mapping would be
built on, and is sitting unused in the current implementation. This is
real, separate engineering (an AST/p-code walker, symbol correlation
against our own stack-variable naming), scoped out of this pass rather
than attempted alongside the debugger work in the same session.

## Backend scope: Rizin only

`Radare2Backend::decompile()` returns a clear "requires the Rizin backend"
error rather than attempting a parallel radare2/r2ghidra integration.
Same chosen-primary-backend scoping already documented for signature
matching in ARCHITECTURE.md — Rizin is this project's target production
backend; radare2 remains a fallback for the analysis pipeline it already
covers, not every new capability.

## A real bug this caught: plugin loading requires an explicit call

Early testing produced `decompile()` succeeding on data (`Lc`, Rizin's
plugin-list command, was empty) but `pdgj` failing with "not installed"
even though `scripts/build_rz_ghidra.sh` had installed the plugin
correctly and the standalone `rizin` CLI could run `pdg` against the same
binary just fine.

Root cause, found by direct comparison rather than assumption: `rz_core_new()`
does **not** dlopen `dir.plugins` itself — it only calls
`rz_core_loadlibs_init()`, which sets up the loader machinery but does not
run it. The actual directory scan is a separate call
(`rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL)`) that the `rizin` CLI's own
`main()` makes (confirmed by reading `librz/main/rizin.c` directly), which
nothing in `rz_core_new()`'s own path replicates. A plugin statically
compiled into a `librz_*.so` (e.g. `debug_native`, built directly into
`librz_debug.so`) works either way, which is what made this easy to miss —
only a plugin living as its own dlopen'd `.so` (like `core_ghidra.so`)
depends on this call. Fixed by adding `rz_core_loadlibs(core_,
RZ_CORE_LOADLIBS_ALL)` right after `rz_core_new()` in both
`RizinBackend::load()` and `RizinDebuggerBackend::launch()`.

## Why runtime, not build time

`rz-ghidra` isn't a library `compass-core` links against — it's a plugin
Rizin discovers and dlopen's from its plugin directory at runtime, the same
way `debug_native` or `analysis_x86` are. There is nothing to
`pkg_check_modules`-gate at CMake configure time (unlike Rizin itself,
which compass-core does link against). `RizinBackend::decompile()` checks
at runtime whether `pdgj` produced parseable JSON and reports a clear
"doesn't appear to be installed" error, pointing at
`scripts/build_rz_ghidra.sh`, if not — rather than the build failing or
succeeding based on whether the plugin happened to be present when
Compass itself was configured.

## Version pinning

`scripts/build_rz_ghidra.sh` pins to rz-ghidra tag `rz-0.7.0`, matched
against `build_rizin.sh`'s `RIZIN_VERSION=v0.7.4` — checked directly via
`git ls-remote --tags`, there is no `rz-0.7.4` tag (rz-ghidra doesn't cut a
tag for every Rizin patch release), so `rz-0.7.0` (same minor version
line) is the closest compatible one.

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

## p-code → MLIL translation

The follow-on this doc used to track as deferred — mapping rz-ghidra's
p-code output back into Compass's own IL — is implemented:
`IAnalysisBackend::pcodeMlil(Address entry)` / `il::translatePcode()`
(`src/core/src/pcode_translator.cpp`). It turned out the original plan
(building on `pdgj`'s per-token `annotations` array — address, syntax
class, variable identity per rendered-text span) was the wrong source
entirely: `annotations` only describes *rendered text*, not real p-code
operations. The actual source is a different rz-ghidra command, `pdgx`,
which dumps Ghidra's real p-code AST as XML — varnodes, per-block
operations (opcode + operands as varnode references), and inter-block
control-flow edges. This translator parses that XML (via expat — already
a standard system dependency, not a new one) and walks it directly into a
plain (non-SSA) `MLILFunction`, the same type `mlil_builder.cpp`'s
ESIL-driven pipeline produces — so it's a genuinely *second*, independent
MLIL for the same function, not a replacement for the first.

**Variable naming and phi folding.** A varnode's identity comes from
`pdgx`'s `<highlist>`: each `<high>` element groups every p-code SSA
version of one logical variable, with a `symref` into `<localdb>`'s symbol
table when Ghidra bound it to a real named parameter/local — confirmed
directly against real output, e.g. a local's `<high>` listing 5 different
varnode refs (one per SSA version across the whole function) as members,
all resolving to the same name Ghidra itself chose (`var_ch`, `a`, `b`,
...). Because Compass's plain MLIL already allows one variable name to be
reassigned many times, and Ghidra's own HighVariable grouping already
unifies every SSA version of one logical variable under one name, a
MULTIEQUAL (p-code's phi node) whose output and every input resolve to
that same name is *already* fully represented by ordinary reassignment —
verified directly against a real if/else-chain fixture (`max3`, two
independent phi merges) before trusting it. A MULTIEQUAL that doesn't
satisfy that check falls back to `Unimplemented` rather than risk emitting
something silently wrong.

**Opcode coverage.** Ghidra's p-code opcode numbers were cross-checked
directly against the vendored Ghidra decompiler's own `opcodes.hh`, not
recalled from memory. Arithmetic/logic/comparison ops (`INT_ADD`,
`INT_SDIV`, `INT_SLESS`, ...), control flow (`BRANCH`, `CBRANCH`, `CALL`,
`RETURN`), `LOAD`/`STORE`, `COPY`, and `PTRADD` (array/pointer indexing —
`base + index*elementSize`, verified against a real `arr[i]` fixture) all
map to real `MLILOp`s. Everything else — float ops, `SUBPIECE`/`CAST`
(truncation/reinterpretation), `PTRSUB` (struct field access),
`CALLIND`/`CALLOTHER`, flag-test ops with no `MLILOp` equivalent — becomes
an `Unimplemented` expression carrying Ghidra's own opcode name and every
available operand, the same never-silently-misrepresent fallback
`llil_lifter.cpp` already uses for unrecognized ESIL tokens. Extending
that coverage (pointer/struct-aware ops especially) is real, separate
follow-on work, same honest scoping as type system v1's remaining pieces
in ROADMAP.md — not attempted here since it depends on pointer/struct
recovery this project doesn't have yet either.

Verified end to end against 3 real fixtures —
`scripts/pcode_translation_smoke_test.sh` — chosen to exercise arithmetic,
the phi-folding design (an if/else chain with two real MULTIEQUAL merges),
and control-flow reconstruction + pointer arithmetic + calls together (a
for-loop over an array, calling another function).

`compass-cli --function <name> --pcode-mlil <binary>` prints the result.

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

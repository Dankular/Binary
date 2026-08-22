# Architecture

## Goals

1. **No dead ends.** Every layer is swappable behind an interface so a better
   backend (real Rizin instead of radare2, a native BNIL-equivalent lifter
   instead of ESIL translation, a different decompiler) can replace today's
   choice without a rewrite above it.
2. **Headless-first.** The GUI is a consumer of the core API, not the other
   way around — everything must work from `compass-cli` / a library before it
   gets a UI.
3. **Own the IL, borrow the plumbing.** File parsing, raw disassembly, and
   decompilation are commodity problems solved well by existing open projects.
   The thing that actually differentiates an RE tool — the IL stack, type
   system, and analysis passes — is where Compass writes original code.

## Layers

```
                    ┌─────────────────────────────────────────┐
                    │   GUI (Qt) — milestone 2, not built yet  │
                    └───────────────────┬───────────────────-─┘
                                         │ Core C++ API (+ planned Python bindings)
┌────────────────────────────────────────────────────────────────────────┐
│  Workflows (analysis pass pipeline)              — planned              │
│  Type system (types, archives, signatures)       — planned              │
│  HLIL  (structured, C-like)                      — planned              │
│  MLIL  (SSA, variables recovered)                — planned              │
│  LLIL  (register/flag/memory expr tree)          — IMPLEMENTED (subset) │
│  CFG / Function / BasicBlock / Instruction model — IMPLEMENTED          │
├────────────────────────────────────────────────────────────────────────┤
│  IAnalysisBackend           │  IDecompilerBackend  │  IDebuggerBackend  │
│  (radare2 today,            │  (Ghidra decompile   │  (r_debug —        │
│   Rizin drop-in later)      │   core — planned)     │   planned)         │
├────────────────────────────────────────────────────────────────────────┤
│         libr / librz (loading, disasm, ESIL, arch plugins)             │
└────────────────────────────────────────────────────────────────────────┘
```

## Backend: Rizin (primary) with a radare2 fallback

**Rizin** is the target production backend (LGPL-2.1, actively maintained,
cleaner API than upstream radare2) — and is implemented and working, not
just planned. `src/core/src/rizin_backend.cpp` is compiled and becomes the
default automatically whenever CMake finds `librz` via pkg-config; radare2
(`src/core/src/radare2_backend.cpp`) remains as the fallback for
environments without Rizin available, selected via `makeDefaultAnalysisBackend()`
in `backend.hpp`. Neither the CLI nor anything above `IAnalysisBackend`
needs to know or care which one is active.

Rizin isn't packaged for common distros (checked: not in Ubuntu 24.04's
repos), so getting it requires a from-source build —
`scripts/build_rizin.sh` automates this (meson + ninja, ~2000 build
targets, ~5-10 minutes). Two real, non-obvious things that build hits and
the script works around:

- Rizin's `tree-sitter` subproject downloads a GitHub release tarball by
  default, which a restrictive outbound proxy may reject (hit and fixed
  while developing this) — installing the system `libtree-sitter-dev`
  package and passing `-Duse_sys_tree_sitter=enabled` avoids that specific
  download (its default is `disabled`, not `auto`, so it doesn't fall back
  to the system package on its own even when present).
- Everything else Rizin's build needs (capstone, pcre2, `tree-sitter-c`,
  `sigdb`, ...) fetches via `git clone` through meson's `wrap-git`
  mechanism, which is unaffected by that proxy restriction.

Porting `radare2_backend.cpp` to Rizin was **not** the pure mechanical
rename this doc originally predicted — validating it against a real binary
surfaced two real, structural differences worth recording:

1. **No `agfj` equivalent.** radare2's `agfj` returns one JSON blob per
   function: blocks, each with an embedded `ops` array carrying
   `offset`/`esil`/`opcode`/`type`/`jump`/`fail` per instruction — exactly
   what `loadFunctionGraph()` needs in one call. Rizin's closest-named
   command, `agf json`/`agf json_disasm` (`agfj` itself doesn't exist),
   turned out to be a *different* schema: a generic node/edge graph with
   pre-rendered, ANSI-colored disassembly text blobs per node rather than
   structured per-instruction fields — not usable as a drop-in. The fix:
   compose two commands that do carry compatible structured fields —
   `afbj` for block boundaries/successors, then `pdj <ninstr> @ <block>`
   per block for its instructions (Rizin kept `pdj`'s per-instruction JSON
   shape compatible with radare2's, which is what makes this work at all).
   One extra round trip per block versus radare2's single call; not
   validated at a scale where that matters yet.
2. **Stray ANSI escape prefix on some JSON output.** `pdj`/`afbj` (not
   `ij`/`iSj`/`isj`/`aflj`) prepend a console "erase line" escape
   (`ESC[2K`) to their output even with `scr.color`/`scr.interactive`
   off — a rendering artifact, not JSON, that broke naive parsing. Fixed
   defensively in `runJson()` by parsing from the first `{`/`[` in the
   returned string rather than its start, so it doesn't matter which
   commands do this or why.

Both were caught the same way everything else in this IL stack's real bugs
were: running it against actual compiled binaries
(`scripts/multiarch_smoke_test.sh`, `scripts/ir_smoke_test.sh` — both pass
identically against either backend) rather than trusting that a
same-lineage API would behave the same.

## Core domain model

`src/core/include/compass/core/`:

- `types.hpp` — `Address`, `Architecture`, basic value types
- `instruction.hpp` — `Operand`, `Instruction` (mnemonic, operands, bytes, ESIL string)
- `basic_block.hpp` — `BasicBlock` (address range, successors/predecessors, instructions)
- `function.hpp` — `Function` (entry point, basic blocks, name, calling convention placeholder)
- `binary.hpp` — `Binary` (loaded file: sections, symbols, entry point, functions)
- `backend.hpp` — `IAnalysisBackend` interface
- `il/low_level_il.hpp` — `LLILExpr` node types + `LLILFunction`

## Low-Level IL (LLIL)

BNIL's real value is a *layered* IL: LLIL (near 1:1 with instructions) → MLIL
(SSA'd, stack vars recovered) → HLIL (structured, C-like). Building all three
well is a multi-month effort by itself. This milestone implements only LLIL,
as an expression tree:

```cpp
enum class LLILOp {
    Const, Reg, Flag, Load, Store, SetReg, SetFlag,
    Add, Sub, And, Or, Xor, Shl, Shr, Mul, Div,
    Cmp, If, Goto, Call, Ret, Push, Pop, Nop, Unimplemented
};
```

The lifter (`src/core/src/llil_lifter.cpp`) walks each instruction's ESIL
string (radare2/Rizin's stack-machine semantics language, e.g.
`rbx,rax,+=` for `add rax, rbx`) and emits LLIL expressions. Coverage today is
deliberately narrow — `mov`, `lea`, `add`/`sub`, `push`/`pop`, `cmp`/`test`,
`jmp`/conditional jumps, `call`/`ret` — chosen because they're enough to
produce a readable, correct IL for a real `main()` in a stripped-down C
binary (see the smoke test). Anything unhandled lifts to an explicit
`Unimplemented(esil_text)` node rather than silently producing wrong IL —
correctness over coverage.

## Medium-Level IL (MLIL) and SSA

`il::buildMlil()` (`src/core/src/mlil_builder.cpp`) lifts LLIL to MLIL by
promoting `Reg`/`Flag` reads and `SetReg`/`SetFlag` writes to named `Var`
nodes, and — the actually useful part — recognizing stack-relative
`Load`/`Store` (address shaped like `frame_reg +/- constant`, for a small
cross-arch set of stack/frame register names) as reads/writes of a *named
stack variable* instead of raw memory access. Repeated accesses to the same
slot become the same variable, e.g. a store to `[rbp-4]` and a later load
from `[rbp-4]` both become `var_4` — that's the actual value of this pass,
not just cosmetic renaming.

`il::buildMlilSsa()` (`src/core/src/mlil_ssa_builder.cpp`) then builds real
SSA form on top: dominance-frontier-driven phi placement followed by a
dominator-tree-order renaming pass (the standard Cytron/Ferrante/Rosen/
Zadeck construction), using `analysis::DominatorTree`
(`src/core/src/dominators.cpp`, unit-tested in `tests/dominators_test.cpp`
against hand-built diamond/loop/unreachable-block CFGs with known answers).
Every variable definition gets a fresh version; control-flow join points
get explicit `Phi` expressions with one operand per predecessor edge.
Verified against a real binary's if/else diamond in
`scripts/ir_smoke_test.sh` (phi nodes appear exactly at the merge block;
every SSA definition is checked to be genuinely unique, not just relabeled).

Neither pass is architecture-specific — both operate purely on LLIL/MLIL's
already-normalized expression trees, so they work unmodified across every
architecture the multi-arch smoke test exercises (x86-64, ARM64, ARM32,
MIPS) — see `scripts/multiarch_smoke_test.sh`.

## Type system v1

`compass::core::Type` (`src/core/include/compass/core/type.hpp`) models
primitives, pointers, arrays, structs/unions, and function signatures, with
C-like rendering (`render(const Type&)`). `il::attachTypes()`
(`src/core/src/type_inference.cpp`) is the "propagate through MLIL" step —
scoped honestly rather than aspirationally: it assigns an unsigned integer
`Type` to every recovered stack variable, sized from the actual
memory-access width that variable was promoted from (real evidence, so a
real assignment). It deliberately does **not** attempt signedness inference,
register/flag variable types (needs arch-specific register-width metadata
not yet consumed from the backend), or pointer/struct recovery (needs
cross-reference and usage analysis) — those are natural extensions of this
same pass, not a rewrite, and are better attempted once the Ghidra
decompiler integration (Milestone 3) exists to cross-check against.

## High-Level IL (HLIL)

`il::buildHlil()` (`src/core/src/hlil_builder.cpp`) structures MLIL's block
graph into a statement tree — `If`/`While` nesting instead of `Goto`/`If`
pointing at block addresses, which is the actual point of having this
layer. It recognizes exactly two shapes, both located via `DominatorTree`
rather than by pattern-matching instruction sequences (so, like MLIL/SSA,
it's architecture-agnostic by construction):

- **if/else diamonds**: a conditional branch whose two arms reconverge at a
  block whose immediate dominator is the branch block itself and which has
  more than one predecessor — the standard signature of "both arms flow
  back together here" (an arm's own start block also has the branch block
  as its idom, but has only one predecessor, which is what distinguishes
  "start of an arm" from "the reconvergence point").
- **simple loops**: a back edge into a header (found via
  `dom.dominates(successor, self)`) whose own conditional branch has
  exactly one target inside the natural loop body and one outside.

Anything else — irreducible control flow, multi-exit loops, switch-like
dispatch, a diamond whose merge point can't be found — degrades to an
explicit `Goto`/`Label` pair rather than being misstructured. This isn't
just a design intention: two real bugs turned up validating it against
actual compiled code (multi-arch, per `scripts/multiarch_smoke_test.sh`,
and a loop fixture, per `scripts/ir_smoke_test.sh`), both now fixed and
guarded by regression assertions:

1. **Stack-variable naming collision** (`mlil_builder.cpp`): a loop
   fixture's `total` local at `[rbp-8]` and the prologue's saved `rbp` at
   `[rsp-8]` were both named `var_8` — same numeric offset, different base
   register, genuinely different memory locations, silently merged into
   one fabricated variable. Fixed by keying the name on the base register
   too (`var_rbp_8` / `var_rsp_8`) — less pretty than Binary Ninja's fully
   canonicalized frame-relative naming (real, separate work: folding
   rsp-relative offsets into their rbp-relative equivalent by tracking
   cumulative stack height through the function), but never wrong.
2. **MIPS branch-delay-slot placement** (`hlil_builder.cpp`): `flattenBlock`
   assumed a block's control-flow expression (If/Goto/Ret) was its last
   instruction's last expression. On MIPS, the delay-slot instruction is
   placed *after* the branch in program order, so the If expression sat
   second-to-last — and silently fell through to being treated as an
   ordinary statement (rendering via MLIL's raw `if (cond) goto X else Y`
   form, which looked plausible enough to be easy to miss), leaving the
   block's real exit undetected. Fixed by scanning the whole block for the
   last control-flow expression regardless of position, rather than
   assuming where it sits.

Both are exactly the value multi-architecture testing was for: a lifter
validated against one architecture's compiler output will encode that
architecture's assumptions without knowing it.

## Decompiler integration (planned)

Ghidra's decompiler (`Decompiler.jar`'s native counterpart, actually a
standalone C++ binary — `decompile`/`ghidra_decompile` — talking XML over a
pipe) can run without the Java UI. The plan is a `GhidraDecompilerBackend`
that: emits a minimal Sleigh-compatible function description from our LLIL,
pipes it through `decompile`, and parses the returned p-code back into MLIL,
skipping Ghidra's Java front end and Swing UI entirely. This is real
integration work (the pipe protocol is undocumented and version-sensitive)
and is scoped as its own roadmap milestone rather than attempted in this
pass. Interim fallback while that lands: shell out to `r2dec`/`r2ghidra` for
a text-only decompilation view.

## Debugger integration (planned)

`r_debug`/`RzDebug` already wraps ptrace (Linux), a WinDbg-protocol client
(Windows), and gdbserver/lldb-server (remote). `IDebuggerBackend` will mirror
`IAnalysisBackend`'s shape: attach/launch, breakpoints, register/memory
read-write, single-step, mapped onto the same `Function`/`Address` types so
breakpoints and disassembly share one address space model.

## Plugin API (planned)

Two tiers, matching Binary Ninja's own split:

1. **C++ ABI-stable core API** — the same headers the CLI and (later) GUI use.
2. **Python bindings** via pybind11 over that same API, for the scripting
   audience the plugin ecosystem actually needs.

## GUI (planned, milestone 2)

Qt widgets, not QML — matches Binary Ninja's own approach and gives the best
native look/performance for dense graph/hex views. Planned view frames:
linear disassembly, graph view (using a proper layered-graph layout, e.g.
Sugiyama via a library like OGDF, not hand-rolled), hex editor, IL views
(LLIL/MLIL/HLIL toggle), type view. Docking via `QDockWidget` or a
kddockwidgets-style docking library for BN-like tabbed panes.

## Plugin API and workflows

`compass::core::IAnalysisPass` (`workflow.hpp`) is the extension point: a
named unit of analysis that runs against a `Function` (with `Binary`
context alongside it, for cross-function facts like symbol names at call
targets). `PassRegistry` is a process-wide singleton every pass — built-in
or plugin-supplied — ends up in; `Workflow` is just an ordered list of pass
names, resolved against the registry when it runs. Two built-in passes
ship in `workflow.cpp`: `lift-all` (populates llil/mlil/hlil if absent) and
`callgraph` (annotates each function with its statically-known call
targets).

Plugins (`plugin.hpp`, `plugin_manager.hpp`) are `.so` files loaded via
`dlopen`, exporting three `extern "C"` entry points
(`compass_plugin_abi_version`/`_create`/`_destroy` — `COMPASS_DECLARE_PLUGIN`
generates them) that `PluginManager` validates and calls. A loaded plugin's
`IPlugin::onLoad()` registers passes into the same `PassRegistry` the CLI
uses — see `plugins/example_io_flagger/` for a complete, real example (not
compiled into compass-core; built and dlopen'd as a genuinely separate
`.so` by `scripts/plugin_smoke_test.sh`) and `docs/ROADMAP.md`'s note on
what "ABI boundary" does and doesn't mean here.

Building and validating this surfaced two real bugs, both fixed:

1. **Disconnected singletons.** The example plugin's first CMake setup
   `target_link_libraries`'d it against `compass-core` (a static library)
   — which statically duplicates compass-core's object code, including
   `PassRegistry::instance()`'s function-local static, into the plugin's
   `.so`. The plugin registered its pass into *its own* copy of the
   registry; `compass-cli`'s `Workflow::run()` looked passes up in a
   *different* copy. The pass "loaded" successfully and then was reported
   "not found" at every lookup. Fixed with the standard plugin pattern
   instead: `compass-cli` is built with `ENABLE_EXPORTS` (`-rdynamic`) so
   its statically-linked compass-core symbols are visible at dlopen time;
   the plugin compiles only against compass-core's *headers*
   (`$<TARGET_PROPERTY:compass-core,INTERFACE_INCLUDE_DIRECTORIES>`, no
   `target_link_libraries`), leaving symbols like `PassRegistry::instance()`
   undefined in its own `.so` and resolved against the host process's copy
   at load time.
2. **Unmapped vtable at exit.** `PluginManager` used to `dlclose()` every
   plugin in its destructor. `PassRegistry` is a process-lifetime
   singleton, so it can (and, once a plugin registers a pass, does)
   outlive any individual `PluginManager` — it still held a
   `shared_ptr<IAnalysisPass>` whose vtable and destructor lived in that
   `.so` after it was unmapped. Destroying that `shared_ptr` during the
   registry's own static-destructor run at process exit segfaulted —
   caught with `gdb` (the crash backtrace pointed straight at
   `PassRegistry`'s destructor tearing down the plugin's `shared_ptr`), not
   a theoretical concern. Fixed by never calling `dlclose()` — the same
   choice most C++ plugin systems (LLVM, Qt) make for the same reason:
   load once, never unload, let process exit reclaim it.

## Python bindings

`src/bindings/python/compass_py.cpp` (pybind11) exposes a deliberately
flat `compass.Session` API — `load`, `info`, `list_functions`,
`disassemble`, `lift_llil`/`lift_mlil`/`lift_hlil` (return rendered text,
same as the CLI), `run_passes` (loads plugins, runs a workflow, returns
resulting annotations) — rather than the full C++ object graph
(`Function`/`BasicBlock`/`MLILExpr` as live Python classes referencing into
a shared `Binary`). That richer binding is real future work once something
needs it (a Python plugin building its own analysis over the IL tree);
solving its ownership/lifetime questions (who keeps a `Binary` alive while
Python holds one of its `Function`s, mutation through the same passes the
CLI runs) isn't free, and the flat API is a substantially simpler, fully
working slice to ship first — see `scripts/python_smoke_test.sh`.

Two real, environment-specific bugs turned up validating this — both in
`plugin_manager.cpp`, both invisible from the C++/CLI path because it
happened not to exercise them:

1. **`dlerror()` read twice.** `error = dlerror() ? dlerror() : "..."`
   calls `dlerror()` twice; it clears its stored message as a side effect
   of being read, so the second call (the one actually assigned) always
   sees it already cleared and returns null. Assigning that null to a
   `std::string` crashes — this had been sitting dormant because the CLI
   path had never actually hit a `dlopen` *failure*, so the buggy branch
   never ran. Fixed by reading it exactly once.
2. **Plugin symbols unresolved when the host is `compass.so`, not an
   executable.** `compass-cli` is built with `ENABLE_EXPORTS`
   (`-rdynamic`), so a plugin it `dlopen`s can resolve symbols like
   `PassRegistry::instance()` back into its statically-linked
   compass-core. Python's import machinery loads `compass.so` with
   `RTLD_LOCAL` by default, though — those same symbols aren't globally
   visible from there, so a plugin's `dlopen` (with `RTLD_NOW`, which
   resolves eagerly) failed outright with `undefined symbol:
   PassRegistry::registerPass`. Fixed with the standard technique for
   exactly this "an extension module that itself loads plugins" shape:
   `promoteSelfToGlobalScope()` uses `dladdr` to find the object containing
   compass-core's own code, then `dlopen`s that same path again with
   `RTLD_GLOBAL` — re-opening an already-loaded object by matching path
   just bumps its reference count and promotes its scope, it doesn't map a
   second copy. A no-op (already global) when the caller is `compass-cli`.

## Signature/FLIRT-style function matching

`IAnalysisBackend::exportSignatures()`/`applySignatures()` — "has this
function been seen before, even stripped/renamed" matching, implemented
per-backend against each one's *actual* signature subsystem, which turned
out to be a real, structural divergence rather than a naming difference
once checked directly (same discovery pattern as the `agfj` gap in the
Rizin backend swap):

- **radare2**: "zignatures" (`z`-prefixed commands) — its own scheme: byte
  patterns + mask, call-graph metrics, basic-block hash, all in an sdb
  file. `zg` generates them for every analyzed function, `zos`/`zo`
  save/load the file, `z/` matches loaded signatures against the current
  binary.
- **Rizin**: a genuine FLIRT implementation (`librz/sign/flirt.c`) — the
  same `.sig`/`.pat` format IDA Pro's FLIRT uses — under the `F` prefix
  (`Fc`/`Fs`), a structurally different subsystem, not just renamed
  commands. This is the more standards-aligned of the two, and matches
  what `docs/ROADMAP.md` actually meant by "Rizin zignatures" even though
  that turned out to be the wrong name for it.

A signature file from one backend is **not** portable to the other —
different serialization entirely. `compass-cli --export-signatures
<path>`/`--apply-signatures <path>` work against whichever backend the
build defaults to.

Verified against the actual real-world use case, not a same-address
coincidence: `scripts/signature_smoke_test.sh` compiles two *different*
programs where `add()` deliberately lands at different addresses (one has
padding functions before it), strips the second, exports a signature from
the first, and confirms applying it to the second correctly re-identifies
and renames the stripped, differently-addressed `add()` — checked against
both backends manually before writing the C++ (radare2's zignatures and
Rizin's FLIRT independently, via each project's own CLI) and against
whichever backend this build defaults to via the test script.

## Dynamic analysis sandbox

See [SANDBOX.md](SANDBOX.md) — this is architecturally a separate service
(a VM orchestrator), not part of the core static-analysis library, connected
via an `ISandboxProvider` interface that turns a detonation report into
annotations on the existing `Binary`/`Function` model (hit basic blocks,
observed syscalls, network IOCs). It runs on QEMU's TCG accelerator (pure
software CPU emulation, no `/dev/kvm` needed) — verified working in a plain
container via `scripts/tcg_probe.sh` — with KVM used opportunistically when
available, so this isn't gated on hypervisor infrastructure the way an
earlier draft of this doc assumed.

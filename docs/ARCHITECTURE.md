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

## Why radare2 today instead of Rizin

The target backend is **Rizin** (LGPL-2.1, actively maintained, cleaner API
than upstream radare2). This sandbox's package repositories don't carry a
`rizin`/`librz` package, so the skeleton is built and validated against
`libradare2-dev`, which is installable here and shares the same lineage and
API shape (`r_core`, `r_anal`, `r_asm`, `r_bin`, ESIL). All backend code lives
behind `IAnalysisBackend` in exactly one file
(`src/core/src/radare2_backend.cpp`) — porting to `librz`'s `Rz`-prefixed API
is a mechanical rename of that one translation unit, not an architecture
change. Track this in `docs/ROADMAP.md` under "Backend: switch to Rizin".

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

MLIL/HLIL are **not** implemented; `docs/ROADMAP.md` sequences them.

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

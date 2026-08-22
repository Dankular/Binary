# Compass

**Compass** is an open-source reverse engineering platform aiming, over time, at
feature parity with Binary Ninja — built entirely on open libraries and released
under an OSI-approved license.

> **Status: early foundation.** This repository currently contains a headless
> core engine — file loading → disassembly → CFG → a full LLIL/MLIL(+SSA)/HLIL
> IL stack, a type system v1, and dynamic-sandbox groundwork — validated
> across x86-64/ARM64/ARM32/MIPS and two interchangeable analysis backends
> (Rizin, radare2), plus the architecture and roadmap for everything else.
> It is **not** feature-complete, and claiming otherwise would be dishonest —
> Binary Ninja represents years of dedicated engineering. There is no GUI,
> no decompiler, no debugger, and no plugin API yet. See
> [ROADMAP.md](docs/ROADMAP.md) for what's real today vs. planned.

## Why "Compass" and not "Binary Ninja"?

This project is inspired by Binary Ninja's feature set but is an independent
implementation with no shared code, and deliberately uses its own name and
branding to avoid trademark confusion. Feature-table entries below reference
Binary Ninja only for comparison purposes.

## Architecture at a glance

Compass is a **hybrid** built on best-of-breed open components rather than one
monolithic reimplementation:

- **Analysis/disassembly substrate**: the radare2/Rizin family (`librz`/`libr`)
  — multi-architecture disassembly, binary loading, ESIL semantics, debugger
  backends, signature (FLIRT-like) matching. LGPL-2.1, used as a dynamically
  linked backend behind an internal interface (see below). **Both backends
  are implemented and working today** — Rizin (`librz`) is the production
  target and used automatically when available; radare2 (`libr`) is a
  fully-functional fallback, since Rizin isn't packaged for common distros
  yet (`scripts/build_rizin.sh` builds it from source).
- **Decompiler**: Ghidra's C++ decompiler core (`decompile`/Sleigh), driven
  headless via its native pipe protocol, feeding our own IL rather than
  Ghidra's Java UI. Apache-2.0.
- **Everything above that line — the IL stack (LLIL/MLIL/HLIL-equivalent),
  type system, plugin API, workflows engine, project management, GUI — is new
  code written for this project.**

Because both backends are hidden behind an `IAnalysisBackend` /
`IDecompilerBackend` interface (see `src/core/include/compass/core/backend.hpp`),
either can be swapped, run side-by-side per-architecture, or replaced entirely
without touching the IL/UI layers above them.

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What's implemented right now

- [x] CMake project scaffold, `compass-core` static library
- [x] `IAnalysisBackend` interface with **two working implementations** —
      Rizin (`rizin_backend.cpp`, the target production backend, used
      automatically when found) and radare2 (`radare2_backend.cpp`,
      fallback) — selected transparently via `makeDefaultAnalysisBackend()`
- [x] Binary loading (any format `r_bin`/`rz_bin` supports: ELF, PE,
      Mach-O, raw, ...) — ELF, PE64, and raw all validated end-to-end;
      Mach-O not yet (no Apple toolchain in the dev environment)
- [x] Function discovery, basic block/CFG construction
- [x] Disassembly validated end-to-end across x86-64, ARM64, ARM32, and
      MIPS (`scripts/multiarch_smoke_test.sh`)
- [x] Low-Level IL: an expression-tree IR (`Reg`, `Const`, `Load`,
      `Store`, `Add`, `Sub`, `SetReg`, `If`, `Goto`, `Call`, `Ret`, ...) with a
      generic ESIL→LLIL RPN evaluator — architecture-agnostic by
      construction, verified across all 4 architectures above
- [x] `compass-cli`: headless tool — load a binary, list functions, print
      disassembly + CFG edges + lifted LLIL for a chosen function
- [x] MLIL + real SSA construction (stack variable recovery, dominance-
      frontier phi placement) — `--mlil`/`--mlil-ssa`; validated cross-arch
      (x86-64/ARM64/ARM32/MIPS) and against a real if/else diamond
      (`scripts/ir_smoke_test.sh`, `scripts/multiarch_smoke_test.sh`)
- [x] Type system v1 (primitives/pointers/arrays/structs/unions, C-like
      rendering) with width-based propagation onto recovered stack
      variables — see docs/ARCHITECTURE.md for exactly what's in scope
- [x] HLIL structuring (`--hlil`): real if/else and while-loop recovery via
      dominator-tree analysis, honest Goto/Label fallback otherwise;
      verified cross-arch and caught two real bugs along the way (a stack
      variable naming collision, MIPS branch-delay-slot misdetection) —
      see docs/ARCHITECTURE.md
- [x] Plugin API + workflows (`--list-passes`/`--run-pass`/`--plugin`):
      `IAnalysisPass`/`PassRegistry`/`Workflow`, a real dlopen-based
      `PluginManager`, and a genuine standalone example plugin
      (`plugins/example_io_flagger/`) — validated end-to-end
      (`scripts/plugin_smoke_test.sh`), including two real bugs this
      caught and fixed (see docs/ARCHITECTURE.md)
- [x] Python bindings (pybind11): `compass.Session` — load a binary, list
      functions, lift LLIL/MLIL(+SSA)/HLIL as text, run a workflow
      (including plugin-supplied passes) — validated end-to-end from real
      Python (`scripts/python_smoke_test.sh`), including two real
      environment-specific bugs this surfaced and fixed (see
      docs/ARCHITECTURE.md)
- [x] Dynamic-sandbox groundwork: `ISandboxProvider` interface +
      `MockSandboxProvider`; verified-in-container proof that QEMU's TCG
      accelerator runs real code with no `/dev/kvm` (`scripts/tcg_probe.sh`);
      a real Debian guest boots under TCG from a disposable overlay and
      runs a command over a serial control channel
      (`scripts/linux_guest_probe.sh`) — see [docs/SANDBOX.md](docs/SANDBOX.md)
- [ ] Everything else in the feature table below — tracked in the roadmap.

## Building

```sh
# Minimum dependencies (Debian/Ubuntu) — builds against radare2:
sudo apt-get install -y libradare2-dev libxxhash-dev nlohmann-json3-dev cmake g++ pkg-config

cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
./build/src/cli/compass-cli --list-functions /bin/ls
./build/src/cli/compass-cli --function main --hlil /bin/ls
```

For the target production backend, build Rizin first (not packaged for
common distros yet — this builds it from source, ~5-10 minutes):

```sh
./scripts/build_rizin.sh
rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
# look for "Compass: Rizin (librz) found" in the configure output
cmake --build build -j
```

Python bindings build automatically when `pybind11-dev` and a matching
`python3-dev` are found (optional — the C++ build doesn't need them):

```sh
sudo apt-get install -y pybind11-dev python3-dev
```

Run the tests:

```sh
./scripts/smoke_test.sh            # core pipeline against a real binary
./scripts/ir_smoke_test.sh         # MLIL/SSA/HLIL, incl. dominator unit tests
./scripts/multiarch_smoke_test.sh  # x86-64/ARM64/ARM32/MIPS/PE64 (needs cross-compilers)
./scripts/plugin_smoke_test.sh     # plugin API: dlopen a real example plugin, run its pass
./scripts/python_smoke_test.sh     # Python bindings, incl. running a plugin's pass from Python
./scripts/tcg_probe.sh             # sandbox groundwork: QEMU TCG works with no /dev/kvm
./scripts/linux_guest_probe.sh     # sandbox groundwork: real guest boot + serial control
```

## Feature parity tracker

Status legend: ✅ implemented · 🚧 in progress / partial · 📋 designed, not built · — not yet planned

| Feature | Binary Ninja (Personal/Commercial/Enterprise) | Compass status | Open-source approach |
|---|---|---|---|
| Included installers | 4 platforms | 📋 | CI-built packages (deb/rpm/AppImage/macOS/Windows) once GUI exists |
| Multi-threaded analysis | ✅ | 🚧 | `librz`/`libr` analysis is already parallelizable per-function; our job scheduler is planned |
| Disassembler | ✅ | ✅ (x86-64, ARM64, ARM32, MIPS) | Rizin (primary)/radare2 (fallback) `rz_asm`/`r_asm`, Capstone under the hood |
| Decompiler | ✅ | 📋 | Ghidra decompiler core (headless), or `r2ghidra`/`r2dec` as interim |
| Decompilation architectures | 18+ | 🚧 (4 validated today) | Inherited from Ghidra Sleigh + Rizin arch plugins; enabled incrementally |
| Community architectures (extension manager) | ✅ | — | Depends on plugin manager (below) |
| File formats | 9+ | 🚧 (ELF, PE64, raw validated; Mach-O not yet) | `rz_bin`/`r_bin` already parses ELF/PE/Mach-O/raw/etc.; exposed via our loader today |
| Hex editor | ✅ | — | Milestone 2 (Qt GUI) |
| Type libraries/archives/signatures | ✅ | 🚧 | Type system v1 implemented (primitives/pointers/arrays/structs/unions + width-based propagation onto stack vars); libraries/archives/signatures still planned (Rizin FLIRT/zignatures + Ghidra data type archives) |
| Debugger | ✅ | — | `rz_debug`/`r_debug` backends (ptrace/gdbserver/WinDbg) behind `IDebuggerBackend` |
| "Sidekick"-capable (AI assist) | ✅ (partial purchase) | — | Optional plugin calling any LLM API; no vendor lock-in |
| Full BNIL introspection | ✅ | 🚧 | LLIL, MLIL (+ real SSA), and HLIL (dominator-based if/else + loop structuring) all implemented; MLIL-SSA-based HLIL construction and richer type propagation are the natural next steps |
| Plugin API | ✅ | 🚧 | C++ core API (dlopen-based, `IAnalysisPass`/`PassRegistry`/`PluginManager`) + Python bindings (pybind11) both implemented and validated end-to-end; a stable *cross-compiler* ABI (vs. today's same-compiler-toolchain boundary) is real, separate future work |
| Plugin manager / community plugins | ✅ | — | Package index + in-app manager, after plugin API lands |
| Workflows (custom analysis pipelines) | ✅ | — | Pass-based analysis pipeline over the IL, user-scriptable |
| Headless/GUI-less processing | ✅ | ✅ | `compass-cli` today; full headless API planned |
| Allows commercial use | ✅ | ✅ | Apache-2.0 (our code) — see [LICENSE](LICENSE) / [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) |
| External links between files | ✅ | — | Project manager milestone |
| Local project management | ✅ | — | SQLite-backed project format |
| Firmware Ninja (firmware-specific analysis) | ✅ | — | Built on file-format/loader layer once mature |
| Remote project management | ✅ | — | Project server milestone |
| Single sign-on (SSO) | ✅ | — | Project server milestone (OIDC) |
| Access control & auditing | ✅ | — | Project server milestone |
| Collaborative analysis | ✅ | — | Project server milestone (CRDT-based merge, like BN's) |
| Sandbox / dynamic detonation (any.run-style)* | — (not a BN feature) | 🚧 | See [docs/SANDBOX.md](docs/SANDBOX.md) — QEMU **TCG** (no `/dev/kvm` needed). A real Debian guest boots and runs commands over a serial channel today (`scripts/linux_guest_probe.sh`); remaining work is an in-guest agent + syscall/network capture. Windows guest is a documented bring-your-own-KVM-host item (both open builders investigated require KVM) |

\* Added per project owner's request — not part of Binary Ninja's feature set, but a natural extension for a modern RE platform.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — system design, IL stack, backend interfaces
- [docs/ROADMAP.md](docs/ROADMAP.md) — milestones, sequencing, and what "done" means for each
- [docs/SANDBOX.md](docs/SANDBOX.md) — dynamic analysis sandbox design
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — licenses of everything we build on

## License

Compass's own code is licensed under [Apache-2.0](LICENSE). It links against
LGPL-2.1 (radare2/Rizin) and Apache-2.0 (Ghidra decompiler) components as
dynamically-loaded backends — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for the full picture and what that means for downstream users.

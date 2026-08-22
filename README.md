# Compass

**Compass** is an open-source reverse engineering platform aiming, over time, at
feature parity with Binary Ninja — built entirely on open libraries and released
under an OSI-approved license.

> **Status: early foundation.** This repository currently contains a headless
> core-engine skeleton (file loading → disassembly → CFG → a first cut of a
> low-level IL), plus the architecture and roadmap for everything else. It is
> **not** feature-complete, and claiming otherwise would be dishonest — Binary
> Ninja represents years of dedicated engineering. See [ROADMAP.md](docs/ROADMAP.md)
> for what's real today vs. planned.

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
  linked backend behind an internal interface (see below).
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
- [x] `IAnalysisBackend` interface + a working radare2-backed implementation
- [x] Binary loading (any format `libr`'s `r_bin` supports: ELF, PE, Mach-O, raw, ...)
- [x] Function discovery, basic block/CFG construction
- [x] Linear disassembly for one architecture validated end-to-end (x86-64)
- [x] First-cut Low-Level IL: an expression-tree IR (`Reg`, `Const`, `Load`,
      `Store`, `Add`, `Sub`, `SetReg`, `If`, `Goto`, `Call`, `Ret`, ...) with an
      ESIL→LLIL lifter covering common x86-64 instructions (`mov`, `lea`,
      `add`/`sub`, `push`/`pop`, `cmp`/`test`, `jmp`/`jcc`, `call`/`ret`)
- [x] `compass-cli`: headless tool — load a binary, list functions, print
      disassembly + CFG edges + lifted LLIL for a chosen function
- [x] Dynamic-sandbox groundwork: `ISandboxProvider` interface +
      `MockSandboxProvider`; verified-in-container proof that QEMU's TCG
      accelerator runs real code with no `/dev/kvm` (`scripts/tcg_probe.sh`);
      a real Debian guest boots under TCG from a disposable overlay and
      runs a command over a serial control channel
      (`scripts/linux_guest_probe.sh`) — see [docs/SANDBOX.md](docs/SANDBOX.md)
- [ ] Everything else in the feature table below — tracked in the roadmap.

## Building

```sh
# Dependencies (Debian/Ubuntu): radare2 dev headers as the disassembly backend
# for this milestone (Rizin proper — see docs/ARCHITECTURE.md — is a drop-in
# swap once packaged in your environment).
sudo apt-get install -y libradare2-dev libxxhash-dev cmake g++ pkg-config

cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
./build/src/cli/compass-cli --list-functions /bin/ls
./build/src/cli/compass-cli --function main --il /bin/ls
```

Run the smoke test:

```sh
./scripts/smoke_test.sh
```

## Feature parity tracker

Status legend: ✅ implemented · 🚧 in progress / partial · 📋 designed, not built · — not yet planned

| Feature | Binary Ninja (Personal/Commercial/Enterprise) | Compass status | Open-source approach |
|---|---|---|---|
| Included installers | 4 platforms | 📋 | CI-built packages (deb/rpm/AppImage/macOS/Windows) once GUI exists |
| Multi-threaded analysis | ✅ | 🚧 | `libr`/Rizin analysis is already parallelizable per-function; our job scheduler is planned |
| Disassembler | ✅ | ✅ (x86-64) | radare2/Rizin `r_asm`/`r_anal`, Capstone under the hood |
| Decompiler | ✅ | 📋 | Ghidra decompiler core (headless), or `r2ghidra`/`r2dec` as interim |
| Decompilation architectures | 18+ | 🚧 (1 today) | Inherited from Ghidra Sleigh + Rizin arch plugins; enabled incrementally |
| Community architectures (extension manager) | ✅ | — | Depends on plugin manager (below) |
| File formats | 9+ | 🚧 | `r_bin` already parses ELF/PE/Mach-O/raw/etc.; exposed via our loader today |
| Hex editor | ✅ | — | Milestone 2 (Qt GUI) |
| Type libraries/archives/signatures | ✅ | — | Our type system (planned) + Rizin FLIRT/zignatures + Ghidra data type archives |
| Debugger | ✅ | — | `r_debug` backends (ptrace/gdbserver/WinDbg) behind `IDebuggerBackend` |
| "Sidekick"-capable (AI assist) | ✅ (partial purchase) | — | Optional plugin calling any LLM API; no vendor lock-in |
| Full BNIL introspection | ✅ | 🚧 | Our LLIL exists; MLIL/HLIL/SSA layers are the next IL milestones |
| Plugin API | ✅ | 📋 | C++ core API + Python bindings (pybind11), stable ABI boundary |
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

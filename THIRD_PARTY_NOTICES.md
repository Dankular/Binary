# Third-party notices

Compass's own source is Apache-2.0 (see [LICENSE](LICENSE)). It builds
against and, depending on distribution choice, may bundle the following
third-party components. This file exists so downstream users can evaluate
license compatibility for their own use case — it is not legal advice.

| Component | License | How it's used | Link |
|---|---|---|---|
| radare2 (`libr`) — fallback backend | LGPL-2.1 | Dynamically linked analysis/disassembly backend (`src/core/src/radare2_backend.cpp`), used when Rizin isn't available | https://github.com/radareorg/radare2 |
| Rizin (`librz`) — target backend | LGPL-2.1 | Dynamically linked analysis/disassembly backend (`src/core/src/rizin_backend.cpp`), used automatically when found via pkg-config — see `scripts/build_rizin.sh` | https://github.com/rizinorg/rizin |
| Capstone | BSD-3-Clause | Pulled in transitively by radare2/Rizin as their instruction decoder | https://github.com/capstone-engine/capstone |
| rz-ghidra (decompiler) | LGPL-3.0 | A Rizin plugin (`core_ghidra.so`) that Rizin dlopen's at runtime — never linked into Compass's own binary — see `scripts/build_rz_ghidra.sh` and docs/DECOMPILER.md | https://github.com/rizinorg/rz-ghidra |
| Ghidra decompiler source (vendored by rz-ghidra) | Apache-2.0 | Compiled as a static library inside rz-ghidra's plugin `.so` above — Ghidra's Java application/UI/JVM are not involved at all | https://github.com/rizinorg/ghidra (rz-ghidra's submodule fork of the decompiler source) |
| Qt | LGPL-3.0 (or commercial) | Planned GUI toolkit, dynamically linked, per Qt's LGPL terms | https://www.qt.io |
| pybind11 | BSD-3-Clause | Python bindings for the plugin API (`src/bindings/python`) | https://github.com/pybind/pybind11 |
| CAPEv2 / DRAKVUF / INetSim / FakeNet-NG | Various OSS (GPL/Apache/BSD mixes — see each project) | Planned dynamic-sandbox network fakery; run as separate out-of-process services, not linked into this codebase | see docs/SANDBOX.md |

## What LGPL-2.1 dynamic linking means here

Compass links against `libr`/`librz` as a **shared library**, invoked through
the `IAnalysisBackend` interface — Compass's own code is not derived from
radare2/Rizin's source. Under LGPL-2.1 this permits Compass to remain under
its own license (Apache-2.0) provided:

- radare2/Rizin remains dynamically linked (not statically linked into a
  single binary) in any distributed build, and
- users are able to replace the radare2/Rizin shared library with a modified
  version (standard LGPL requirement — satisfied automatically by dynamic
  linking against a system-installed or separately-shipped `.so`).

If a future build mode statically links `libr`/`librz`, that build must
either relicense under LGPL-2.1-compatible terms or ship relinkable object
files per LGPL §6. This is called out here so it isn't discovered later by
accident.

## Ghidra decompiler integration

Implemented (Milestone 3, see ROADMAP.md and docs/DECOMPILER.md) via
rz-ghidra: a Rizin plugin Rizin dlopen's from its plugin directory at
runtime, never linked into Compass's own binary at build time (there's
nothing to link against — see docs/DECOMPILER.md's "why runtime, not build
time"). No Ghidra/Java code is linked into or embedded in Compass either
way. rz-ghidra itself vendors Ghidra's decompiler C++ source (Apache-2.0)
as a git submodule and compiles it directly (not the out-of-process pipe
protocol an earlier draft of this roadmap item assumed necessary) — the
plugin `.so` this produces, `core_ghidra.so`, is LGPL-3.0 (rz-ghidra's own
license), separate from and stricter than the Apache-2.0 decompiler source
it wraps. Since it's dlopen'd rather than statically linked, this follows
the same dynamic-linking reasoning as radare2/Rizin above.

# Third-party notices

Compass's own source is Apache-2.0 (see [LICENSE](LICENSE)). It builds
against and, depending on distribution choice, may bundle the following
third-party components. This file exists so downstream users can evaluate
license compatibility for their own use case — it is not legal advice.

| Component | License | How it's used | Link |
|---|---|---|---|
| radare2 (`libr`) — current backend | LGPL-2.1 | Dynamically linked analysis/disassembly backend (`src/core/src/radare2_backend.cpp`) | https://github.com/radareorg/radare2 |
| Rizin (`librz`) — target backend | LGPL-2.1 | Planned drop-in replacement for radare2, same integration point | https://github.com/rizinorg/rizin |
| Capstone | BSD-3-Clause | Pulled in transitively by radare2/Rizin as their instruction decoder | https://github.com/capstone-engine/capstone |
| Ghidra (decompiler core only) | Apache-2.0 | Planned: headless native `decompile` process, invoked out-of-process (not linked) | https://github.com/NationalSecurityAgency/ghidra |
| Qt | LGPL-3.0 (or commercial) | Planned GUI toolkit, dynamically linked, per Qt's LGPL terms | https://www.qt.io |
| pybind11 | BSD-3-Clause | Planned Python bindings for the plugin API | https://github.com/pybind/pybind11 |
| CAPEv2 / DRAKVUF / INetSim / FakeNet-NG | Various OSS (GPL/Apache/BSD mixes — see each project) | Planned dynamic-sandbox orchestration; run as separate out-of-process services, not linked into this codebase | see docs/SANDBOX.md |

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

The plan (Milestone 3, see ROADMAP.md) invokes Ghidra's native decompiler as
a **separate process** communicating over a pipe, the same way Ghidra's own
Java front-end does — no Ghidra/Java code is linked into or embedded in this
codebase. Apache-2.0 has no copyleft/linking implications here regardless,
but out-of-process invocation is also the only currently-understood way to
drive that decompiler without dragging in the JVM.

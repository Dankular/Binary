# Roadmap

Milestones are sequenced so each one is independently useful and testable —
no "big bang" integration at the end. Ordering below was revised to push
the GUI to last: this project is being built and validated in headless
sandboxed environments, so milestones that stay fully testable there
(decompiler, sandbox, debugger, project management, headless plugin/API
work) come first; the GUI — the one milestone that genuinely needs a
different environment (a real display) to test — comes only once
everything it would sit on top of already exists and works.

## Milestone 0 — Core engine skeleton (complete)

- [x] Project scaffold, CMake build
- [x] `IAnalysisBackend` + radare2-backed implementation
- [x] Binary/Function/BasicBlock/Instruction model
- [x] CFG construction
- [x] LLIL subset + ESIL lifter for common x86-64 instructions
- [x] `compass-cli` headless tool
- [x] Smoke test against a real compiled binary

## Milestone 1 — Backend hardening (complete)

- [x] Switch backend from radare2 to Rizin (`librz`) — implemented
      (`src/core/src/rizin_backend.cpp`), auto-selected by CMake/
      `makeDefaultAnalysisBackend()` whenever `librz` is found, radare2
      remains the fallback. `scripts/build_rizin.sh` builds Rizin from
      source (not packaged for common distros yet). Not a pure rename as
      originally assumed — see docs/ARCHITECTURE.md for the two real
      schema differences this surfaced (no `agfj` equivalent; a stray
      ANSI-escape prefix on some JSON output) and how they were fixed.
      Validated against the full multi-arch + IR test suite against both
      backends with identical results
- [x] Multi-architecture validation (ARM64, MIPS, at minimum) — done for
      x86-64/ARM64/ARM32/MIPS, `scripts/multiarch_smoke_test.sh`. Caught and
      fixed a real lifter bug in the process: ARM64 ESIL's `DUP`
      stack-pseudo-op was silently becoming a fabricated register read (see
      llil_lifter.cpp's ALL-CAPS-token handling)
- [x] MLIL: SSA form + stack variable recovery over LLIL — real
      Cytron-et-al. SSA construction on a unit-tested dominator tree; stack
      variable recovery verified end-to-end (`scripts/ir_smoke_test.sh`,
      `tests/dominators_test.cpp`); see docs/ARCHITECTURE.md
- [x] HLIL: structuring pass (loops/if-else recovery) over MLIL — real
      dominator-tree-based structuring (if/else diamonds, simple while
      loops), honest Goto/Label fallback for anything else; caught and
      fixed two real bugs in the process (stack-var naming collision,
      MIPS branch-delay-slot misdetection) — see docs/ARCHITECTURE.md and
      `scripts/ir_smoke_test.sh`/`scripts/multiarch_smoke_test.sh`
- [x] Type system v1: primitive + struct/union/pointer types (data model +
      C-like rendering) implemented; propagation through MLIL implemented
      for stack-variable widths specifically (real evidence-based
      assignment) — register/flag types, signedness, and pointer/struct
      recovery are explicitly out of scope for v1, see docs/ARCHITECTURE.md
- [x] Expand file-format coverage validation — PE validated
      (`scripts/multiarch_smoke_test.sh`'s `pe64` case, via mingw-w64);
      Mach-O not attempted (no Apple toolchain available in this
      environment — a real, not fabricated, gap); raw firmware blobs not
      yet tested

## Milestone 2 — Plugin API + headless completeness (complete)

- [x] Stabilize C++ core API headers as the plugin ABI boundary — real
      caveat, not glossed over: this is a same-compiler/same-stdlib-ABI
      boundary (`extern "C"` entry points, C++ objects passed across
      after that), the same constraint most C++ plugin systems live with,
      not a stronger stable-ABI-across-compilers guarantee. See
      docs/ARCHITECTURE.md
- [x] Python bindings (pybind11) mirroring the C++ API — a deliberately
      flat `compass.Session` API (load/info/list_functions/disassemble/
      lift_llil/lift_mlil/lift_hlil/run_passes) rather than the full
      typed object graph; see docs/ARCHITECTURE.md for the scope reasoning
      and two real, Python-specific bugs this surfaced and fixed
      (a double `dlerror()` read; plugin symbol resolution failing when
      compass-core's code lives in a `RTLD_LOCAL`-loaded `compass.so`
      rather than an executable). Validated end-to-end in
      `scripts/python_smoke_test.sh`, including running a plugin's pass
      from Python
- [x] Plugin discovery/loading (dlopen-based for C++) — `PluginManager`,
      `IPlugin`/`PluginContext`, `COMPASS_DECLARE_PLUGIN`; validated with a
      real standalone example plugin (`plugins/example_io_flagger/`) via
      `scripts/plugin_smoke_test.sh`. Caught and fixed two real bugs in the
      process (disconnected PassRegistry singletons from a static-link
      mistake; a dlclose()-vs-vtable-lifetime segfault at process exit) —
      see docs/ARCHITECTURE.md. Python-side plugin loading (importlib)
      waits on the Python bindings item above
- [x] Workflows: pass-based analysis pipeline, user-registerable passes —
      `IAnalysisPass`/`PassRegistry`/`Workflow`; two built-in passes
      (`lift-all`, `callgraph`) plus the example plugin's `flag-io-callers`
      demonstrating a third-party-supplied pass; `--list-passes`/
      `--run-pass` in compass-cli
- [x] Signature/FLIRT-style function matching — `exportSignatures()`/
      `applySignatures()` on `IAnalysisBackend`, implemented per-backend
      against each one's actual (and structurally different — see
      docs/ARCHITECTURE.md) subsystem: Rizin's real FLIRT implementation
      (the roadmap's "Rizin zignatures" was the wrong name for this) and
      radare2's own zignatures. `--export-signatures`/`--apply-signatures`
      in compass-cli. Verified against the real use case — a function
      re-identified at a genuinely different address in a different,
      stripped binary, not a same-offset coincidence — for both backends
      (`scripts/signature_smoke_test.sh`)

## Milestone 3 — Decompiler (up next)

- [ ] `GhidraDecompilerBackend`: headless pipe integration with Ghidra's
      native `decompile` binary
- [ ] p-code → MLIL translation
- [ ] Interim: `r2dec`/`r2ghidra` text-output fallback view while the above
      is built

## Milestone 4 — Dynamic sandbox (up next)

- [x] Verify QEMU TCG (no KVM) actually executes code in a plain container
      — `scripts/tcg_probe.sh`
- [x] `ISandboxProvider` interface + `DetonationReport`/`SandboxProfile`
      types + `MockSandboxProvider` for testing
- [x] Boot a real Linux guest (official Debian cloud image) under TCG from
      a disposable qcow2 overlay, log in and run a command over a serial
      control channel — `scripts/linux_guest_probe.sh`
- [ ] Detonation report JSON schema
- [ ] In-guest agent (static Go/Rust binary) reporting syscalls/files/
      network activity back over that same channel
- [ ] `QemuTcgSandboxProvider`: generalizes the probe script — push a
      sample in, run under timeout, collect the agent's report
- [ ] Annotation merge: dynamic coverage, syscalls, network IOCs onto the
      static model
- [ ] Windows guest: investigated (see docs/SANDBOX.md) — both viable
      builders (dockur/windows, cocoonstack/windows) require KVM, which
      this environment doesn't have; stays a documented "bring your own on
      a KVM host" item, not something this project builds/ships
- [ ] GUI surface for sandbox results — deferred to Milestone 8, same as
      every other GUI-surfacing item; the sandbox's own headless pipeline
      (above) is fully testable without it

## Milestone 5 — Debugger

Headless-testable throughout (ptrace/gdbserver interaction, breakpoint/
register/memory state — none of it needs a display), which is why this
comes before the GUI despite being numbered after it in earlier drafts of
this roadmap.

- [ ] `IDebuggerBackend` over `r_debug`/`RzDebug`
- [ ] Local ptrace debugging (Linux), then remote (gdbserver/WinDbg protocol)
- [ ] GUI breakpoint/register/memory views — deferred to Milestone 8

## Milestone 6 — Project management & collaboration

- [ ] Local project format (SQLite-backed), external links between files
- [ ] "Firmware Ninja"-equivalent: multi-file firmware image analysis built
      on the loader layer
- [ ] Remote project server: sync protocol, OIDC-based SSO
- [ ] Access control & audit logging
- [ ] Collaborative analysis: CRDT-based merge for concurrent edits to the
      same database (types, comments, function names)

## Milestone 7 — Shellcode compiler (not in Binary Ninja's own feature
   table — added on request)

Not a decompiler-adjacent thing; the opposite direction — compiles a
restricted C dialect into position-independent shellcode (x86/x64/ARM/
AArch64/MIPS/PPC, ELF/Mach-O/PE or flat blobs), for patching/injecting
code into a target under analysis. Binary Ninja ships one
([Vector35/scc](https://github.com/Vector35/scc)) as a standalone,
already-MIT-licensed, separately-maintained project — not built on BNIL,
doesn't require Binary Ninja to run.

- [ ] Vendor/wrap the existing MIT-licensed `scc` rather than writing a new
      C-to-shellcode compiler — same "don't reimplement what's already
      good and open source" principle as the non-goals below. It's
      unmaintained upstream but PR-friendly per its own README; forking if
      a real fix is needed is reasonable, rewriting from scratch isn't.
- [ ] `compass-cli --compile-shellcode <file.c> --arch <arch> --os <os>`
      subcommand wrapping the vendored `scc` binary
- [ ] A Workflow pass (see Milestone 2) that compiles a C snippet and
      patches the resulting shellcode into the loaded binary at a chosen
      address — the actual useful RE workflow this unlocks, not just
      running `scc` as an external tool with no integration

## Milestone 8 — GUI (Qt) (last, deliberately)

Moved to last: this is the one milestone that genuinely needs a different
environment to test (a real display — headless sandboxes can't validate
"does this look and behave right"), and every other milestone above it
builds real, independently useful, headlessly-testable functionality this
GUI will eventually sit on top of. Every GUI-surfacing item deferred from
earlier milestones (sandbox results, debugger views, plugin manager UI)
lands here too.

- [ ] Application shell, docking, linear + graph disassembly views
- [ ] Hex editor view
- [ ] IL view (LLIL/MLIL/HLIL toggle) synced to disassembly selection
- [ ] Type view / type editor
- [ ] Plugin manager UI + community plugin index
- [ ] Sandbox detonation-result views (Milestone 4), debugger
      breakpoint/register/memory views (Milestone 5)
- [ ] Cross-platform installers (Linux deb/rpm/AppImage, macOS, Windows) via CI

## Explicit non-goals (for now)

- Reimplementing Capstone/Sleigh's instruction decoders from scratch — no
  value in duplicating well-tested disassemblers.
- A from-scratch decompiler before the Ghidra-backed one exists and is
  validated — decompilers are extremely easy to get subtly wrong.
- A from-scratch C-to-shellcode compiler — see Milestone 7: `scc` already
  exists, is already open source, and solves this.

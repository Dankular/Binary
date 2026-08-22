# Roadmap

Milestones are sequenced so each one is independently useful and testable —
no "big bang" integration at the end.

## Milestone 0 — Core engine skeleton (this session)

- [x] Project scaffold, CMake build
- [x] `IAnalysisBackend` + radare2-backed implementation
- [x] Binary/Function/BasicBlock/Instruction model
- [x] CFG construction
- [x] LLIL subset + ESIL lifter for common x86-64 instructions
- [x] `compass-cli` headless tool
- [x] Smoke test against a real compiled binary

## Milestone 1 — Backend hardening

- [ ] Switch backend from radare2 to Rizin (`librz`) once available; confirm
      via CI on an environment that packages it, or vendor/build it
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

## Milestone 2 — Plugin API + headless completeness

- [ ] Stabilize C++ core API headers as the plugin ABI boundary
- [ ] Python bindings (pybind11) mirroring the C++ API
- [ ] Plugin discovery/loading (dlopen-based for C++, importlib for Python)
- [ ] Workflows: pass-based analysis pipeline, user-registerable passes
- [ ] Signature/FLIRT-style function matching (via Rizin zignatures)

## Milestone 3 — Decompiler

- [ ] `GhidraDecompilerBackend`: headless pipe integration with Ghidra's
      native `decompile` binary
- [ ] p-code → MLIL translation
- [ ] Interim: `r2dec`/`r2ghidra` text-output fallback view while the above
      is built

## Milestone 4 — GUI (Qt)

- [ ] Application shell, docking, linear + graph disassembly views
- [ ] Hex editor view
- [ ] IL view (LLIL/MLIL/HLIL toggle) synced to disassembly selection
- [ ] Type view / type editor
- [ ] Plugin manager UI + community plugin index
- [ ] Cross-platform installers (Linux deb/rpm/AppImage, macOS, Windows) via CI

## Milestone 5 — Dynamic sandbox

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
- [ ] GUI surface for sandbox results

## Milestone 6 — Debugger

- [ ] `IDebuggerBackend` over `r_debug`/`RzDebug`
- [ ] Local ptrace debugging (Linux), then remote (gdbserver/WinDbg protocol)
- [ ] GUI breakpoint/register/memory views

## Milestone 7 — Project management & collaboration

- [ ] Local project format (SQLite-backed), external links between files
- [ ] "Firmware Ninja"-equivalent: multi-file firmware image analysis built
      on the loader layer
- [ ] Remote project server: sync protocol, OIDC-based SSO
- [ ] Access control & audit logging
- [ ] Collaborative analysis: CRDT-based merge for concurrent edits to the
      same database (types, comments, function names)

## Explicit non-goals (for now)

- Reimplementing Capstone/Sleigh's instruction decoders from scratch — no
  value in duplicating well-tested disassemblers.
- A from-scratch decompiler before the Ghidra-backed one exists and is
  validated — decompilers are extremely easy to get subtly wrong.

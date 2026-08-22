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
- [ ] Multi-architecture validation (ARM64, MIPS, at minimum)
- [ ] MLIL: SSA form + stack variable recovery over LLIL
- [ ] HLIL: structuring pass (loops/if-else recovery) over MLIL
- [ ] Type system v1: primitive + struct/union/pointer types, propagate
      through MLIL/HLIL
- [ ] Expand file-format coverage validation (PE, Mach-O, raw firmware blobs)

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
- [ ] Detonation report JSON schema
- [ ] Guest image (minimal Linux, TCG-booted) + in-guest agent
- [ ] `QemuTcgSandboxProvider`: QMP-driven launch/snapshot/collect, real
      orchestrator (see docs/SANDBOX.md for the exact plan) — no longer
      blocked on VM infrastructure the container doesn't have; blocked only
      on building the guest image + agent, which is real remaining work
- [ ] Annotation merge: dynamic coverage, syscalls, network IOCs onto the
      static model
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

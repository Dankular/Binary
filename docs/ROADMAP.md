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

## Milestone 1 — Backend hardening (core complete; Mach-O, firmware blobs, type libraries/archives, and a job scheduler are documented follow-ons)

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
- [ ] Mach-O file format support — blocked on an Apple toolchain to
      produce real test fixtures with, not on any known code gap in
      `rz_bin`/`r_bin` itself (both already parse Mach-O)
- [ ] Raw firmware blob format validation — untested, not necessarily
      unsupported; no fixture/test built yet
- [ ] Type libraries/archives (Ghidra-style shared struct/typedef
      definitions across projects/binaries) — mentioned in README's
      feature table, no design or implementation started; distinct from
      the per-binary type system v1 above
- [ ] Multi-threaded analysis / job scheduler — mentioned in README's
      feature table only, no roadmap item existed for this before now;
      `librz`/`libr` analysis is already parallelizable per-function, this
      would be the scheduler on top of that. Unscoped — needs a design
      pass before it's a real task, not just a name

## Milestone 2 — Plugin API + headless completeness (core complete; Python-side plugin loading and a richer Python object-graph binding are documented follow-ons)

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
      see docs/ARCHITECTURE.md. Python-side plugin loading (`importlib`-
      discovered plugins written *in* Python, not just calling the C++
      API *from* Python — the Python bindings item above only shipped the
      latter) was noted as waiting on the Python bindings item; that
      shipped and this was never revisited — still not done, tracked
      properly below instead of left implicit
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
- [ ] Python-side plugin loading: `importlib`-discovered plugins written
      *in* Python (a `PluginManager` counterpart for Python authors), not
      just today's ability to call the C++ API from a Python script. See
      the note above — flagged as blocked on the Python bindings item,
      those shipped, this was never picked back up
- [ ] Richer Python bindings: today's `compass.Session` API is
      deliberately flat (returns rendered text, not live objects); a
      Python plugin building its own analysis over the IL tree needs
      `Function`/`BasicBlock`/`MLILExpr` as real Python classes referencing
      into a shared `Binary` — real ownership/lifetime design work (who
      keeps a `Binary` alive while Python holds a `Function` from it,
      mutation through the same passes the CLI runs), not attempted yet;
      see ARCHITECTURE.md's Python bindings section

## Milestone 3 — Decompiler (text-output integration complete; p-code → MLIL translation and type system v1 extensions are documented follow-ons)

- [x] `IAnalysisBackend::decompile()`, implemented by `RizinBackend` over
      rz-ghidra — a self-contained port of Ghidra's C++ decompiler (no
      JVM/full Ghidra install, no undocumented pipe protocol to
      reverse-engineer — the original `GhidraDecompilerBackend` plan
      below), reused rather than reimplemented per this project's
      standing principle. `scripts/build_rz_ghidra.sh` builds/installs it;
      `compass-cli --function <name> --decompile <binary>`. Verified end
      to end — `scripts/decompile_smoke_test.sh` — asserting the
      decompiled text for a real `add()` fixture actually contains its
      parameters, an addition, and a return, not just that the call
      succeeded. Real bug found and fixed: `rz_core_new()` doesn't dlopen
      `dir.plugins` itself (only `rz_core_loadlibs_init()` does, which
      sets up the loader without running it) — a dlopen'd plugin like
      rz-ghidra silently never loaded until `rz_core_loadlibs(core,
      RZ_CORE_LOADLIBS_ALL)` was added explicitly; see docs/DECOMPILER.md.
- [x] Interim: real Ghidra-decompiler text-output view (rz-ghidra) — done
      as above, ahead of and instead of a hand-rolled `r2dec`/`r2ghidra`
      text shim
- [ ] p-code → MLIL translation — deferred, not attempted in this pass;
      `pdgj`'s per-token `annotations` (address/syntax-class/variable
      identity per span) already returned by the current integration are
      exactly what this would be built on. See docs/DECOMPILER.md's scope
      note for why this is real, separate work rather than a quick
      follow-on to the text-output integration above.
- [x] ~~`GhidraDecompilerBackend` (full Ghidra pipe integration)~~ —
      superseded, no longer planned: rz-ghidra above delivers the same
      underlying decompiler without the undocumented/version-sensitive
      pipe protocol or a JVM dependency this item originally assumed were
      necessary
- [ ] Type system v1 extensions: signedness inference, register/flag
      variable types, pointer/struct recovery — explicitly out of scope
      for v1 (see ARCHITECTURE.md's type system section) and explicitly
      gated there on "once the Ghidra decompiler integration exists to
      cross-check against" — true as of this milestone, so this item is
      now unblocked, not just theoretically future work

## Milestone 4 — Dynamic sandbox (core pipeline complete; Windows sample execution, opportunistic KVM, network fakery, and GUI surfacing are documented follow-ons)

- [x] Verify QEMU TCG (no KVM) actually executes code in a plain container
      — `scripts/tcg_probe.sh`
- [x] `ISandboxProvider` interface + `DetonationReport`/`SandboxProfile`
      types + `MockSandboxProvider` for testing
- [x] Boot a real Linux guest (official Debian cloud image) under TCG from
      a disposable qcow2 overlay, log in and run a command over a serial
      control channel — `scripts/linux_guest_probe.sh`
- [x] Detonation report JSON schema —
      `docs/schemas/detonation_report.schema.json`
- [x] In-guest agent reporting syscalls/files/network activity back over
      that same channel — `sandbox/agent/agent.sh`. Deviates from this
      item's original "static Go/Rust binary" wording: the guest is a
      full Debian image (not a minimal custom rootfs) and payload
      delivery is via a mounted ISO (see below), so a shell script driving
      `strace`/`tcpdump` is trivial to deliver and needs no cross-compiled
      agent binary or build step of its own
- [x] `QemuTcgSandboxProvider`: generalizes the probe script — push a
      sample in, run under timeout, collect the agent's report —
      `src/core/src/qemu_tcg_sandbox_provider.cpp`. Payload (agent + sample)
      delivered via a `genisoimage`-built ISO mounted as a second QEMU
      drive, chosen over base64-over-serial after measuring that a 785KB
      test binary would need 500+ chunked serial commands to transfer.
      Verified end to end — `scripts/sandbox_detonate_test.sh` — against a
      real fixture that drops a file and opens a TCP connection, asserting
      the returned `DetonationReport` contains the exact FileEvent/
      NetworkEvent/SyscallEvent data those syscalls should produce, not
      just that the run completed. Two real bugs found and fixed during
      this build (see docs/SANDBOX.md for full detail):
      1. `parseStraceLog()`'s regex matched 0 of 30 real captured lines —
         `std::getline` only splits on `\n`, so every line kept the guest
         terminal's trailing `\r`, and a trailing `\r` was enough to make
         `std::regex_match` reject the whole line even with a pattern
         ending in `(.*)$` — verified directly with an isolated test, not
         assumed. Fixed by stripping trailing `\r`/whitespace per line
         before matching.
      2. `qemu-img create -b <relative-path>` resolves the backing-file
         path relative to the *overlay's* directory, not the caller's
         cwd — broke the moment the overlay moved to a `/tmp` work dir.
         Fixed by canonicalizing the guest image path before use.
- [x] Annotation merge: dynamic coverage, syscalls, network IOCs onto the
      static model — `mergeDetonationReport()`
      (`src/core/include/compass/core/annotation_merge.hpp`),
      `compass-cli --detonate <sample> --merge-annotations`. See
      docs/ANNOTATIONS.md for the full design, including two real,
      honestly-scoped gaps this surfaced rather than papered over:
      1. No current provider populates `SyscallEvent::callSite` or
         `executedBlocks` (strace, `QemuTcgSandboxProvider`'s data source,
         reports syscall arguments, not the guest instruction pointer at
         the call) — the address-attribution merge logic is implemented
         and proven correct against hand-built data with real addresses
         (`tests/annotation_merge_test.cpp`) rather than left unbuilt
         until a provider exists to feed it; end to end today it merges
         file/network events only, verified against `/tmp/detonate_test`'s
         known behavior.
      2. Even once populated, those fields' addresses are the guest's
         *runtime* addresses — correlating them against a statically-loaded
         PIE binary needs the same ASLR-base normalization
         `RizinDebuggerBackend::launch()` already solved for local
         debugging (docs/DEBUGGER.md), not yet applied here since there's
         no data source to apply it to yet.
- [x] Windows guest: `WindowsSandboxProvider`
      (`src/core/src/windows_sandbox_provider.cpp`), wrapping `docker run
      docker.io/dockurr/windows` — the real, published container, not a
      reimplementation of its bootstrap — same reuse-don't-reimplement
      principle as Rizin/Ghidra/SCC. Verified end to end in this
      environment with a real Windows Server 2003 install (`VERSION=2003`
      is 0.6 GB — an earlier "impractical, multi-GB download" claim was
      revised once the actual size table was checked; see
      docs/SANDBOX.md) — watched to completion via a real screenshot of
      the actual setup screen (not inferred from indirect signals), full
      install to a real RDP handshake in 1398s (~23 minutes), including
      catching and fixing a real false-positive
      readiness bug (a plain TCP connect to the RDP port succeeds
      immediately, before Windows is anywhere near ready — fixed with a
      real RDP X.224 handshake probe) and working around this
      environment's TLS-intercepting proxy breaking dockur's own
      in-container downloader (solved via its own documented local-ISO
      bind-mount escape hatch, not a proxy workaround). `compass-cli
      --detonate <sample> --windows-iso <path-or-VERSION>`,
      `scripts/windows_sandbox_smoke_test.sh`. Honest v1 scope limit,
      matching the code's own behavior: `completed` never becomes `true`
      yet — there is no Windows-side sample delivery/execution mechanism
      (no equivalent of `sandbox/agent/agent.sh`) — see docs/SANDBOX.md.
- [ ] Opportunistic KVM acceleration — designed (see SANDBOX.md's
      "Accelerator selection") but never implemented; both
      `QemuTcgSandboxProvider` and `WindowsSandboxProvider` hardcode TCG
      unconditionally today. Correct everywhere this has run so far (no
      `/dev/kvm` in any environment used), but leaves real speed on the
      table wherever KVM is actually available.
- [ ] Network fakery: wire `-netdev user` DNS/proxy options at an
      INetSim/FakeNet-NG instance and capture a pcap — see SANDBOX.md.
      Today's `NetworkEvent`s come entirely from strace argument parsing,
      not a packet capture, and guest network egress is real, not faked.
- [ ] GUI surface for sandbox results — deferred to Milestone 8, same as
      every other GUI-surfacing item; the sandbox's own headless pipeline
      (above) is fully testable without it

## Milestone 5 — Debugger (local ptrace complete; remote debugging, watchpoints/memory writes/multi-stop, and GUI views are documented follow-ons)

Headless-testable throughout (ptrace/gdbserver interaction, breakpoint/
register/memory state — none of it needs a display), which is why this
comes before the GUI despite being numbered after it in earlier drafts of
this roadmap.

- [x] `IDebuggerBackend` over `RzDebug` —
      `src/core/include/compass/core/debugger.hpp` /
      `src/core/src/rizin_debugger_backend.cpp`. Rizin-only (radare2's
      `RDebug` is a structurally separate subsystem, same divergence
      already documented for signature matching), opened in-process via a
      `dbg://` core — the exact mechanism `rizin -d` uses.
- [x] Local ptrace debugging (Linux) — `compass-cli --debug <path>
      [--break <symbol>]... [--timeout <secs>]`. Verified end to end
      against a real dynamically-linked PIE fixture (deliberately not
      `-no-pie`) — `scripts/debugger_smoke_test.sh` — asserting a
      breakpoint stop with the correct call-convention register args, a
      clean exit with the correct real exit code, and a forced kill on
      timeout that leaves no orphaned process behind. Two real bugs found
      and fixed getting there (full detail in docs/DEBUGGER.md):
      1. A PIE target ran to completion, unimpeded, before `launch()`
         even returned — two setup calls `rizin -d` makes
         (`rz_debug_use()`, `rz_debug_get_baddr()` before
         `rz_core_bin_load()`) were missing; a non-PIE fixture happened to
         work without them (fixed load address needs no resolution),
         which is what let this ship past the first fixture tested.
      2. Exit codes were silently wrong by a factor of 256 (`42` reported
         as `10752`) — `PTRACE_GETEVENTMSG`'s exit message is the raw
         `wait(2)` status word and needs `WEXITSTATUS()` applied, which
         the code wasn't doing; caught only because the smoke test
         asserted the fixture's *actual* exit code rather than just
         "an exit happened."
- [ ] Remote debugging (gdbserver/WinDbg protocol) — deferred, not
      attempted in this pass; `RzDebug` already has backends for both, see
      docs/DEBUGGER.md's scope note
- [x] Memory writes — `IDebuggerBackend::writeMemory()`, verified end to
      end (`compass-cli --debug ... --poke-stack <hex>`,
      `scripts/debugger_smoke_test.sh`); see docs/DEBUGGER.md.
- [ ] Debugger v1 rounding-out: watchpoints, and multi-stop session
      control (continuing past a hit breakpoint without a fresh CLI
      invocation — `continueExec()` itself already supports repeated
      calls correctly, this is a CLI-only gap, see docs/DEBUGGER.md's
      scope note). Smaller and more contained than remote debugging above.
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

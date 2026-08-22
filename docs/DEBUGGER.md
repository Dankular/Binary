# Debugger (Milestone 5)

## What this is

`IDebuggerBackend` (`src/core/include/compass/core/debugger.hpp`) is a
narrow interface over process debugging — launch, breakpoints, continue,
register/memory read — mirroring `IAnalysisBackend`'s shape: one contract,
a real implementation behind it. `RizinDebuggerBackend`
(`src/core/src/rizin_debugger_backend.cpp`) implements it over **RzDebug**,
opened in-process via a `dbg://` core — the exact mechanism `rizin -d`
uses (confirmed by reading `librz/main/rizin.c` directly, not assumed).
Native ptrace on Linux today, via Rizin's own `debug_native` plugin.

Rizin-only, not radare2: `RzDebug` and `RDebug` are a structurally separate
subsystem fork (same divergence already documented for signature matching
in ARCHITECTURE.md), and Rizin is this project's target production backend.
Only declared/built when `COMPASS_HAVE_RIZIN` is set.

```
compass-cli --debug <path> [--debug-arg <arg>]... [--break <symbol>]... [--timeout <secs>]
```

Resumes execution once and reports the first stop (breakpoint hit, exit,
or timeout) — one action, one report, matching `--detonate`'s shape.

## Why breakpoints are set by symbol name, not a static address

`launch()` runs a light analysis pass (`aa`) against the **live debug
session's own memory**, right after the target is spawned and stopped —
not a separate static load. `resolveSymbol(name)` then reads a function's
address back out of that analysis. This is deliberate: it sidesteps
PIE/ASLR entirely. The addresses `resolveSymbol()` returns are whatever
this exact running process actually has mapped, never a static/file
address a caller would otherwise have to manually rebase against a
randomized load address they don't know yet. `--break` on the CLI takes a
symbol name for this reason, not a `--break-addr` taking a hex literal
(though `IDebuggerBackend::addBreakpoint(Address)` itself is address-based
underneath, for a caller that already resolved one).

## Two real bugs found building this

Both caught by testing against a real dynamically-linked PIE binary — the
project's default `gcc` output, not a special case — not by a toy fixture
alone. `scripts/debugger_smoke_test.sh` compiles its fixture *without*
`-no-pie` specifically so these stay caught.

### 1. A PIE target ran to completion, unimpeded, before `launch()` even returned

Early testing against a non-PIE (`-no-pie`) fixture worked cleanly:
breakpoints hit, registers read correctly. The same code against a
default (PIE, dynamically-linked) binary produced a target that just ran
to full completion — printed its own output, exited — during `launch()`,
before any breakpoint could be set. `aflj` (function listing) then found
nothing, because there was no live process left to analyze.

Root cause, found by diffing against `librz/main/rizin.c`'s actual `-d`
handling line by line rather than guessing: two calls the CLI makes are
missing from a bare `rz_core_file_open(core, "dbg://...", ...)` +
`rz_core_bin_load(core, NULL, UT64_MAX)` sequence:

```c
rz_debug_use(r->dbg, is_gdb ? "gdb" : debugbackend); // debugbackend defaults to "native"
baddr = rz_debug_get_baddr(r->dbg, pfile);           // NOTE: redefined to support PIE/ASLR
rz_core_bin_load(r, pfile, baddr);                   // passes pfile + the resolved baddr, not NULL/UT64_MAX
```

`rz_debug_use()` selects/initializes the actual debug backend (breakpoint
architecture, register profile); without it, whatever downstream logic is
supposed to stop the target at its entry point has nothing to work with,
and it free-runs. `rz_debug_get_baddr()` resolves the PIE binary's actual
ASLR-randomized load address — passing that into `rz_core_bin_load()`
(instead of `UT64_MAX`) is what lets analysis and breakpoint addresses
land on the real, running mapping. A static/non-PIE target's fixed load
address needs no resolution, which is exactly what made this easy to miss
on the first (non-PIE) fixture tested.

Fixed by adding both calls to `RizinDebuggerBackend::launch()`, in the
same order the CLI uses them. Verified directly: a standalone repro
against the same PIE binary went from "runs away, `aflj` finds nothing" to
"stops correctly, `aflj` finds `sym.add` at its real runtime address"
with no other change.

### 2. Exit codes were silently wrong by a factor of 256

`continueExec()`'s exit-code recovery (see below) initially reported `42`
as `10752`. `10752 == 42 << 8`.

Root cause: RzDebug's Linux backend reports a process exit two different
ways depending on whether `PTRACE_O_TRACEEXIT` is active (this build's
path does). Under `PTRACE_EVENT_EXIT`, the value `PTRACE_GETEVENTMSG`
retrieves is — per `ptrace(2)` — the same status word `wait(2)` would
return, i.e. the actual exit code sits in bits 8-15 and needs
`WEXITSTATUS()` (`(status >> 8) & 0xff`) applied; `linux_debug.c`'s
`eprintf` for this path prints that raw value verbatim, unshifted. The
*other* code path (plain `WIFEXITED`, decimal message) already has
`WEXITSTATUS()` applied before its own `eprintf` — so the two message
formats this file parses need different handling, not the same regex
capture treated uniformly. Caught by `debugger_smoke_test.sh` asserting
the fixture's actual exit code (`42`) rather than just "some exit
happened" — an assertion that specific would have caught this
immediately; a looser one ("exited: true") would not have.

Fixed in `parseExitCode()`: the hex-message path now applies `(raw >> 8) &
0xff`; the decimal-message path is left as-is (already correct).

## Why the exit-status text is authoritative, not `dbg->reason.type`

`continueExec()` reads the debuggee's stop reason from `core_->dbg->reason.type`
for breakpoints — but **not** for exits. Reading `librz/debug/debug.c`
directly: `rz_debug_wait()` returns `RZ_DEBUG_REASON_DEAD` on a plain
process exit via an **early return**, before the one line
(`dbg->reason.type = reason;`) that would ever actually write `DEAD` into
that field. The field is simply never updated for this case — it stays
whatever it was set to before the wait call (`RZ_DEBUG_REASON_UNKNOWN`).
Confirmed directly (a `--debug` run with no breakpoints, so the process
ran to completion normally, came back classified `Unknown` instead of
`Exited`) rather than assumed from documentation.

The only reliable signal this file has for a real exit is therefore the
same eprintf'd status text `parseExitCode()` already needs for the exit
code itself — captured by redirecting `stderr` to a temp file for the
duration of the `dc` call, the same text-log-parsing pattern already used
for the sandbox's strace output (see SANDBOX.md). `processAlive()`
(`kill(pid, 0)`) exists only as a secondary fallback for an exit whose
text didn't match either known message format — real evidence (the pid is
gone) without a recovered exit code, rather than nothing.

## Timeout handling

`continueExec(timeoutSeconds)` runs the blocking `dc` call on the calling
thread and a watchdog on a separate `std::thread` that sends a raw
`kill(pid, SIGKILL)` — a plain POSIX syscall, not another RzCore command —
if the deadline passes first. Deliberately not `rz_core_cmd_str(core_,
"dk 9")` from the watchdog thread: `RzCore` isn't designed for concurrent
command execution from two threads, and the tracee's pid, read once at
`launch()` and never mutated afterward, is safe to signal directly from
another thread without touching shared core state at all. Verified with a
real infinite-loop fixture: killed within the timeout window, confirmed
not still running afterward (`pgrep`), not left as a hung tracee.

## Scope (v1)

Local ptrace debugging only — ptrace, breakpoints (software, via `db`),
`continueExec()`'s single-stop-then-return shape, register/memory
read+write. `writeMemory()` (`RizinDebuggerBackend`) is `s <addr>; wx
<hex>` — verified end to end via `compass-cli --debug ... --poke-stack
<hex>`: a real write to the live debuggee's stack followed by reading the
same bytes back with the existing `readMemory()` matches exactly
(`scripts/debugger_smoke_test.sh`). Failure detection is text-based (`wx`
reports `ERROR: Could not write hexpair '..' at <addr>` on stdout, no
structured success/failure signal) — verified directly against a real
unmapped-address write, not assumed.

**Deferred, not attempted in this pass:** remote debugging (gdbserver/WinDbg
protocol — `RzDebug` already has backends for both, wiring them into
`IDebuggerBackend` is a real but separate follow-on), watchpoints, and
multi-stop session control (continuing past a hit breakpoint without a
fresh CLI invocation — `continueExec()` itself already handles being
called repeatedly correctly, confirmed directly against a real loop
fixture hitting the same breakpoint three times with the right
per-iteration register state each time; the gap is CLI-only).

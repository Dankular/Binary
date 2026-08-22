# Annotation merge (Milestone 4's remaining item)

## What this is

`mergeDetonationReport(Binary&, const DetonationReport&)`
(`src/core/include/compass/core/annotation_merge.hpp`) takes a completed
sandbox run's `DetonationReport` (see SANDBOX.md) and attaches it onto a
statically-loaded `Binary` as human-readable findings — the same
deliberately-simple free-form-string design `Function::annotations`
already uses for workflow-pass findings (see ARCHITECTURE.md's type
system section). `BasicBlock::annotations` and `Binary::annotations` were
added alongside it for the same reason.

```
compass-cli --detonate <sample> --merge-annotations [--guest-image ...] [--timeout ...]
```

Loads `<sample>` a second time through `IAnalysisBackend` (statically, no
guest involved) after detonating it, merges the report onto that load, and
prints the result grouped by where each finding attached: `[binary]`,
`[<function name>]`, or `[<function name> @ <block address>]`.

## Where a finding attaches, and why

| DetonationReport field | Attaches to | Why |
|---|---|---|
| `fileEvents`, `networkEvents` | `Binary::annotations` | Process-level observations — a file write or a TCP connect isn't tied to a specific instruction in any provider today (see below), so there's nothing more specific to attribute it to. |
| `syscalls[i]` **with** `callSite` set | The `BasicBlock` (or, failing that, the `Function`) containing `callSite` | `callSite` is exactly the piece of information needed for real per-block attribution — `Binary::functionContaining()`/`Function::blockAt()` do the address lookup. |
| `syscalls[i]` **without** `callSite` (`== 0`) | Nothing (no-op) | This is every syscall from every provider that exists today — see below. |
| `executedBlocks` | The `BasicBlock` at that address (deduped — coverage is boolean in v1, not a hit count) | Direct coverage data, once a provider produces it. |

## Real, honest gap: no provider populates `callSite` or `executedBlocks` yet

This was flagged as a known limitation when `DetonationReport` was
designed (see `docs/schemas/detonation_report.schema.json`'s notes) and
remains true today: `QemuTcgSandboxProvider`'s data source is `strace`
inside the guest, which reports syscall *arguments*, not the guest
instruction pointer at the point of the call — there is nothing to put in
`callSite`. Populating it for real needs either QEMU TCG plugin
instrumentation (execution tracing) or a ptrace-based provider using
`PTRACE_PEEKUSER` on `rip` at each syscall-stop — both real, separate
engineering, not attempted in this pass. `executedBlocks` has the same
gap for the same reason (no execution-tracing data source exists yet).

Rather than leave the address-attribution code path unbuilt-and-untested
until a provider exists to feed it, `mergeDetonationReport()` implements
it now and `tests/annotation_merge_test.cpp` proves it correct with
hand-built `DetonationReport`s carrying real addresses (matched against a
real fixture's actual instruction layout) — so when a provider does start
populating these fields, the merge side needs no further changes, and the
correctness of the attribution logic is already established rather than
first exercised by whatever provider ships it.

## A second, related gap: address-space correlation for a PIE sample

Even once a provider populates `executedBlocks`/`callSite`, those
addresses are the **guest's runtime addresses** — meaningful only if they
already share the statically-loaded `Binary`'s address space. That's true
for a non-PIE sample (fixed load address either way) but not for a PIE
one, whose guest-runtime addresses are offset by whatever ASLR base the
guest's kernel happened to choose for that run. This is the same problem
`RizinDebuggerBackend::launch()` solved for local ptrace debugging (see
docs/DEBUGGER.md) — resolving `rz_debug_get_baddr()` and normalizing
against it — and the same fix shape would apply here: the sandbox
provider (or the merge step) would need to know the guest's chosen load
base for the sample and subtract it back out before these addresses mean
anything against a static load. Not implemented, because there's no data
source populating the addresses in the first place yet (see above) — but
worth stating plainly now rather than being rediscovered as a surprise
once one exists.

## Testing

- `tests/annotation_merge_test.cpp` (unit test, no sandbox/QEMU
  involved): hand-built `Binary` and `DetonationReport` data with known
  answers — file/network events land on `Binary::annotations`; a
  syscall's `callSite` attributes to the exact containing block, not the
  function or binary; a syscall without `callSite` is a no-op everywhere;
  repeated coverage of the same block dedups to one annotation; an
  address outside every function's range is silently ignored rather than
  attributed anywhere or crashing.
- End-to-end, against the real pipeline (file/network only, since that's
  what the real pipeline produces today — see above): `compass-cli
  --detonate <sample> --merge-annotations`, verified manually against
  `/tmp/detonate_test`'s known file-drop and TCP-connect behavior,
  producing exactly the two expected `[binary]` annotations.

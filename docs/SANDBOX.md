# Dynamic analysis sandbox (any.run-style)

Not a Binary Ninja feature — added per project owner's request as a
complementary capability: detonate a sample in a disposable VM, capture its
behavior, and feed that back as annotations on top of the static analysis
this repo already does.

**Scope note:** this cannot be built or exercised inside a container-based
coding session like this one — it fundamentally needs nested virtualization
(KVM) or a real hypervisor host, which this sandbox does not expose. What
follows is the target architecture and interface so core-engine code can be
written against it today (via a mock provider) and pointed at a real
orchestrator later, in an environment with VM infrastructure.

## Design

```
Sample ──▶ Orchestrator ──▶ [disposable VM: Windows/Linux, KVM+QEMU snapshot]
                                   │
                     ┌─────────────┼──────────────┐
                     ▼             ▼               ▼
              syscall/API     network I/O     process/file/
              trace agent     capture         registry diffing
                     │             │               │
                     └─────────────┴───────┬───────┘
                                            ▼
                                   Detonation report (JSON)
                                            │
                                            ▼
                         ISandboxProvider::runReport(Binary&)
                                            │
                                            ▼
              Annotations merged onto Function/BasicBlock/IL:
              - basic blocks actually executed (dynamic coverage)
              - syscalls per call site
              - network IOCs (domains/IPs/URLs contacted)
              - dropped/modified files, registry keys, spawned processes
```

## Component choices (all open source)

| Concern | Choice | Why |
|---|---|---|
| VM + snapshotting | QEMU/KVM with `savevm`/external snapshots | Fast revert between runs; no licensing constraints (unlike commercial hypervisors) |
| Orchestration | CAPEv2 (Cuckoo-derived) or a purpose-built minimal orchestrator | CAPEv2 already solves snapshot lifecycle, task queueing, and report schema; heavier than we may want long-term |
| In-guest instrumentation | DRAKVUF (Xen-based, agentless, stealthier) *or* a lightweight in-guest agent (like CAPE's `agent.py`/hooked DLL) | DRAKVUF avoids in-guest hooks detectable by the sample, at the cost of requiring Xen instead of KVM — a real tradeoff to make explicitly, not silently |
| Network capture/faking | INetSim / FakeNet-NG + tcpdump | Standard, well-understood fake-internet approach so samples "phone home" into a controlled sink |
| Report format | JSON schema local to this project (`docs/schemas/detonation_report.schema.json`, not yet written) | Decouples the orchestrator choice from the core engine — any backend that emits this schema works |

## Interface (core-engine side)

```cpp
// src/core/include/compass/core/sandbox.hpp (not yet implemented)
struct DetonationReport {
    std::vector<Address> executedBlocks;
    std::vector<SyscallEvent> syscalls;
    std::vector<NetworkEvent> networkEvents;
    std::vector<FileEvent> fileEvents;
    // ...
};

class ISandboxProvider {
public:
    virtual ~ISandboxProvider() = default;
    virtual DetonationReport detonate(const std::filesystem::path& sample,
                                       const SandboxProfile& profile) = 0;
};
```

A `MockSandboxProvider` (returns a canned report from a fixture file) lets
the annotation-merging code in the core engine be built and tested now,
independent of having real VM infrastructure available.

## Safety/ethics notes for implementers

- Detonation VMs must be network-isolated from anything but the fake-internet
  sink by default; real internet egress is an explicit opt-in for research
  use, never the default.
- This is a defensive/research capability (malware analysis, incident
  response) — the orchestrator should refuse to target anything but a sample
  file path provided by the user, never a live host or third-party system.

## Sequencing

This is deliberately its own roadmap milestone (see ROADMAP.md, "Milestone
5: Dynamic sandbox"), after the static core, IL stack, and plugin API exist
— the sandbox's value is in annotating *those*, so it needs them first.

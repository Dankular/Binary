# Dynamic analysis sandbox (any.run-style)

Not a Binary Ninja feature — added per project owner's request as a
complementary capability: detonate a sample in a disposable VM, capture its
behavior, and feed that back as annotations on top of the static analysis
this repo already does.

**Runs in a plain container. No hypervisor host, no `/dev/kvm`, no elevated
privileges required.** The design uses QEMU's **TCG accelerator** — pure
software CPU emulation, the same engine QEMU falls back to when hardware
virtualization isn't available — instead of KVM. This was an open question
in an earlier draft of this doc; it's now verified, not assumed:
`scripts/tcg_probe.sh` boots a minimal real-mode payload
(`tests/fixtures/sandbox_probe/boot.asm`) under `qemu-system-x86_64 -accel
tcg` in this exact sandboxed environment (confirmed: no `/dev/kvm` present,
no root) and asserts the guest code actually executed. Run it yourself:

```sh
sudo apt-get install -y qemu-system-x86 nasm   # if not already present
./scripts/tcg_probe.sh
```

The tradeoff for not needing KVM is speed: TCG is roughly 5–20x slower than
hardware-accelerated virtualization for CPU-bound guest workloads. That's an
acceptable, explicit tradeoff for a portable sandbox (runs in CI, in this
kind of session, on a laptop, anywhere) and the orchestrator should still
prefer KVM opportunistically when `/dev/kvm` is present (see "Accelerator
selection" below) — TCG is the floor this design guarantees, not the only
mode it uses.

## Design

```
Sample ──▶ Orchestrator ──▶ [disposable VM: qemu-system-x86_64 -accel tcg,
                              QMP-controlled, qcow2 snapshot/overlay]
                                   │
                     ┌─────────────┼──────────────┐
                     ▼             ▼               ▼
              syscall/API     network I/O     process/file/
              trace agent     capture         registry diffing
              (in-guest,      (-netdev user,   (in-guest agent
               virtio-serial   no TAP/root      or disk diff
               to host)        needed)          between snapshots)
                     │             │               │
                     └─────────────┴───────┬───────┘
                                            ▼
                                   Detonation report (JSON)
                                            │
                                            ▼
                         ISandboxProvider::detonate(sample, profile)
                                            │
                                            ▼
              Annotations merged onto Function/BasicBlock/IL:
              - basic blocks actually executed (dynamic coverage)
              - syscalls per call site
              - network IOCs (domains/IPs/URLs contacted)
              - dropped/modified files, registry keys, spawned processes
```

## Accelerator selection

The orchestrator should probe for `/dev/kvm` (readable/writable) at startup
and pick per-run:

- **KVM present** (bare-metal host, a VM with nested-virt enabled, most
  dedicated malware-analysis infrastructure) → `-accel kvm`, full speed.
- **KVM absent** (this kind of container, most CI runners, a locked-down
  cloud sandbox) → `-accel tcg`, works everywhere, slower.

Same QEMU command line either way (`-accel` is the only thing that
changes), same QMP control protocol, same snapshot mechanism — the rest of
this design is accelerator-agnostic by construction.

## Component choices (all open source)

| Concern | Choice | Why |
|---|---|---|
| CPU emulation | QEMU (`qemu-system-x86_64`/`-aarch64`), `-accel tcg` with opportunistic `-accel kvm` | Verified to run in a plain container (see above); same binary/CLI/QMP protocol regardless of accelerator |
| VM control | QMP (QEMU Machine Protocol, a JSON-RPC socket QEMU exposes) | Scriptable start/stop/snapshot/monitor without touching the (non-existent, in TCG mode) hypervisor APIs directly |
| Snapshotting | qcow2 backing-file + overlay per run (`qemu-img create -b base.qcow2 -F qcow2 run.qcow2`), discarded after each detonation | Instant "revert to clean" without needing `savevm`'s full-RAM snapshot cost; works identically under TCG or KVM |
| Networking | `-netdev user` (QEMU's built-in SLIRP-based usermode NAT) | No TAP device, no `CAP_NET_ADMIN`, no root — works in exactly the kind of unprivileged container this was designed for. Point its DNS/proxy at an INetSim/FakeNet-NG instance for the "fake internet" behavior |
| Network capture | QEMU's own `-netdev user,...,pcap=file.pcap` or a host-side capture on the SLIRP socket | Built into the same `-netdev user` flag, no extra privilege needed |
| In-guest instrumentation | A lightweight in-guest agent (virtio-serial channel to the host, like CAPE's `agent.py`) | Simplest to build first; DRAKVUF-style agentless instrumentation (via Xen's VMI) is a possible later upgrade for stealth, but is Xen-specific and not needed for a first working version |
| Report format | JSON schema local to this project (`docs/schemas/detonation_report.schema.json`, not yet written) | Decouples the orchestrator's internals from the core engine — any backend that emits this schema works |

## Interface (core-engine side)

```cpp
// src/core/include/compass/core/sandbox.hpp
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

`MockSandboxProvider` (returns a canned report) and the `ISandboxProvider`
interface itself are implemented now — see `src/core/include/compass/core/sandbox.hpp`
and `src/core/src/mock_sandbox_provider.cpp` — so annotation-merging code
against the core model can be built and tested today. A real
`QemuTcgSandboxProvider` (launch QEMU, drive QMP, collect the in-guest
agent's output into a `DetonationReport`) is the next concrete step — see
Roadmap below; it needs a guest disk image, which this doc deliberately
doesn't attempt to acquire/build in a quick pass (hundreds of MB–GB
download, guest-side agent installation, base-snapshot preparation are all
real, separate pieces of work).

## Safety/ethics notes for implementers

- Detonation VMs must be network-isolated from anything but the fake-internet
  sink by default; real internet egress is an explicit opt-in for research
  use, never the default. `-netdev user`'s default NAT already only reaches
  the guest out through QEMU's userspace stack, not the host's real network
  stack directly — but treat that as defense-in-depth, not a substitute for
  pointing DNS/HTTP at INetSim/FakeNet-NG.
- This is a defensive/research capability (malware analysis, incident
  response) — the orchestrator should refuse to target anything but a sample
  file path provided by the user, never a live host or third-party system.

## Roadmap for this component

1. ~~Prove TCG execution works in a plain container~~ — done, see above.
2. `ISandboxProvider` + `DetonationReport` types + `MockSandboxProvider` —
   done, see `src/core/include/compass/core/sandbox.hpp`.
3. Acquire/build a minimal Linux guest qcow2 image with a boot-to-agent
   init (a good candidate: a stripped Alpine or Debian cloud image, TCG
   booted, cloud-init disabled, a static Go/Rust agent binary as PID 1's
   child) — real work, not attempted in this pass.
4. `QemuTcgSandboxProvider`: launch, wait for agent handshake over
   virtio-serial, push the sample in, run it under a timeout, collect the
   agent's syscall/file/process log, tear down the overlay.
5. Network fakery: wire `-netdev user` DNS/proxy options at an
   INetSim/FakeNet-NG instance; capture the pcap.
6. Windows guest support (needs a licensed/legally-obtainable Windows
   image — out of scope for this project to provide; document how to bring
   your own).
7. GUI surface for sandbox results (Milestone 4-adjacent, after the GUI
   itself exists).

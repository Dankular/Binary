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

**This isn't just a claim about `x86` toy code either — a real Linux
distribution boots under it.** `scripts/linux_guest_probe.sh` downloads an
official Debian 12 cloud image (checksummed against Debian's own
`SHA512SUMS`), boots it under `-accel tcg` from a disposable qcow2 overlay
(the same snapshot-per-run scheme described below), reaches a login prompt
in well under a minute, logs in, runs a command over a serial-socket control
channel, and confirms the output comes back — the same shape of channel a
real in-guest agent will use to report syscalls/files/network activity.
Run it yourself (downloads ~400MB on first run, cached under `.cache/`):

```sh
sudo apt-get install -y qemu-system-x86 python3
./scripts/linux_guest_probe.sh
```

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
against the core model can be built and tested today.

`QemuTcgSandboxProvider` (`src/core/src/qemu_tcg_sandbox_provider.cpp`) is
now real, not planned: it boots a disposable qcow2 overlay of a guest image
under `-accel tcg`, delivers the sample and the in-guest agent
(`sandbox/agent/agent.sh`) via a `genisoimage`-built ISO attached as a
second QEMU drive (chosen over base64-over-serial — a 785KB test binary
would need 500+ chunked serial commands, an ISO mount is one), drives login
and the agent run over the same unix-socket serial channel
`linux_guest_probe.sh` proved, retrieves the agent's `strace`/`tcpdump`
logs, and parses them into a `DetonationReport`. Verified end to end
against a real fixture (drops a file, opens a TCP connection) —
`scripts/sandbox_detonate_test.sh` — asserting the report contains the
exact events those syscalls should produce, not just that the run
completed.

Two real bugs were found and fixed while getting this from "runs, reports
empty" to "runs, reports correctly" — both caught by checking actual
captured data rather than trusting that a plausible-looking implementation
worked:

1. **`parseStraceLog()`'s regex matched nothing.** The end-to-end run
   completed successfully and the in-guest agent genuinely captured 30
   lines of real strace output, but the parser reported `syscalls: 0,
   fileEvents: 0, networkEvents: 0`. Dumping the raw retrieved log
   (`COMPASS_SANDBOX_DEBUG=1`) showed well-formed lines like
   `509   16:14:11.002380 brk(NULL)         = 0x19f5b000`. Isolating the
   regex in a standalone test program against that exact captured text
   still matched 0 of 30 lines. The initial hypothesis — that trailing
   `\r` from the guest terminal's `\r\n` line endings (visible as `^M` in
   `cat -A`) was the cause — seemed insufficient on paper, since
   ECMAScript's `.` matches `\r` by default and the pattern ends in
   `(.*)$`, so a greedy `.*` should still be able to consume a trailing
   `\r`. Reasoning about it further wasn't productive; testing it
   directly was: a minimal repro (`std::regex_match` against the same
   string with and without an appended `\r`) showed the match flips from
   `true` to `false` the moment `\r` is appended, confirming the cause
   empirically rather than by continuing to reason about ECMAScript
   semantics on paper. `std::getline` only splits on `\n`, so every line
   from this guest kept its trailing `\r`. Fixed by stripping trailing
   `\r`/whitespace from each line before matching.
2. **`qemu-img create -F qcow2 -b <relative-path>` resolves the backing
   file relative to the *overlay's* directory, not the caller's cwd.**
   `main.cpp` defaults the guest image to a relative path
   (`./.cache/debian-12-nocloud-amd64.qcow2`); `fs::exists()` happily
   found it from the process's cwd, but `qemu-img create` failed once the
   overlay was written to a `/tmp/compass_sandbox_XXXXXX` work dir,
   because it looks for the backing file relative to *that* directory
   instead. Reproduced directly with a manual `qemu-img create -b
   './relative/path'` from a different cwd before fixing. Fixed by
   canonicalizing the guest image path (`fs::absolute()`) before it's
   used as `-b`.

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
2. ~~`ISandboxProvider` + `DetonationReport` types + `MockSandboxProvider`~~
   — done, see `src/core/include/compass/core/sandbox.hpp`.
3. ~~Boot a real Linux guest under TCG and control it over a serial
   channel~~ — done, see `scripts/linux_guest_probe.sh` above. Uses
   Debian's official `nocloud` cloud image directly rather than a custom
   image, since it already boots straight to a root prompt with no
   provisioning step needed.
4. ~~`QemuTcgSandboxProvider`: same boot+control pattern as the probe
   script, generalized~~ — done, see `src/core/src/qemu_tcg_sandbox_provider.cpp`
   and the "corrected finding" note above for the real bugs found getting
   here. Payload delivery ended up being an ISO mount rather than virtio-9p
   — simpler to get working with `genisoimage` + a second `-drive`, no
   guest-side 9p mount support to depend on.
5. ~~In-guest agent~~ — done, `sandbox/agent/agent.sh`. Deviates from "a
   small static Go/Rust binary": the guest is a full Debian image, so a
   shell script driving `strace`/`tcpdump` needs no cross-compilation step
   and installs its own dependency (`apt-get install strace`) on first run.
6. Network fakery: wire `-netdev user` DNS/proxy options at an
   INetSim/FakeNet-NG instance; capture the pcap.
7. ~~**Windows guest support**~~ — `WindowsSandboxProvider`
   (`src/core/src/windows_sandbox_provider.cpp`), wrapping
   `docker run docker.io/dockurr/windows` rather than reimplementing its
   bootstrap. Verified end to end in this environment with a real Windows
   Server 2003 install — see below for the full account, including v1's
   honest scope limit (proves the guest boots and becomes reachable; does
   not yet deliver/execute a sample inside it).
8. GUI surface for sandbox results — deferred to Milestone 8 (GUI, moved
   to last: it's the one milestone needing a real display to test, and
   everything above is fully headlessly testable without it).

### Windows guest: corrected finding — TCG genuinely works here

An earlier version of this document claimed dockur/windows required KVM
with no TCG fallback. **That was wrong** — caught by going past its README
into its actual source (the shared `qemus/qemu` base project dockur/windows
builds on) and then verifying directly, not by reading a summary. Same
mistake shape as the sandbox's own original TCG claim in an earlier
session — checked the docs, not the code, and the docs undersell what the
code does.

**What the source actually does** (`qemus/qemu`'s `src/proc.sh`):

```sh
if ! disabled "${KVM:-}"; then
  configureKvm
else
  configureTcg
fi
```

`configureTcg()` sets `accel=tcg,thread=multi` — a real, coded path, not
theoretical. It's gated behind an explicit `KVM=N` environment variable
rather than auto-detected, and the container's default entrypoint treats
missing `/dev/kvm` as fatal *unless* that variable is set:

```
❯ ERROR: KVM acceleration is not available (/dev/kvm is missing), this
  will cause the machine to run about 10 times slower.
❯ ERROR: See the FAQ for possible causes, or disable acceleration by
  adding the "KVM=N" variable (not recommended).
```

**Verified directly in this environment**, not just read about: started
`dockerd` (available but not running by default here), pulled
`dockurr/windows`, and ran it twice —

1. Without `KVM=N`: hit exactly the ERROR above and stopped, confirming
   the "mandatory by default" behavior real users hit (see e.g. their
   issue #1577 — a user who didn't realize the override existed).
2. With `KVM=N`: the *same* message downgrades to a **warning**
   ("KVM acceleration is disabled, this will cause the machine to run
   about 10 times slower!") and the container proceeds — it went on to
   attempt downloading a ReactOS image (`VERSION=reactos`, chosen for a
   fast/cheap check: same shared boot pipeline as real Windows, ~0.1GB
   instead of several GB). The download itself failed on a TLS handshake
   error against `reactos.org` — this environment's outbound proxy
   rejecting that host's certificate, the same class of issue hit earlier
   getting Rizin's `tree-sitter` dependency (GitHub archive downloads
   blocked) — not a dockur/windows limitation. The part that matters was
   already proven by that point: **the TCG path is real, and it isn't
   blocked by anything about *this* environment** (no KVM, no root beyond
   what Docker itself needs, same proxy restrictions as everywhere else in
   this session).

**cocoonstack/windows** likewise supports `KVM=N`-style TCG per its own
docs (not independently re-verified here the way dockur/windows was) but
its GHCR package additionally distributes a **prebuilt, already-installed**
~14 GiB Windows qcow2 image — deliberately not pulled into this project. A
prebuilt disk image containing an installed copy of Windows is
redistribution of Microsoft's copyrighted OS binaries by a third party,
not an installer that fetches from Microsoft — a materially different (and
murkier) licensing situation than either builder's own source.

**Conclusion, revised again — this is now wired up and verified end to
end, not just structurally validated:** `WindowsSandboxProvider`
(`src/core/src/windows_sandbox_provider.cpp`) wraps
`docker run docker.io/dockurr/windows` — the actual published container,
not a reimplementation of its `entry.sh`/`define.sh`/`proc.sh`/`disk.sh`/
`answer.sh`/`image.sh` bootstrap — the same "reuse what's already open
source and working" principle applied to Rizin, Ghidra, and SCC.

### Disk space, revised: a full real-Windows run turned out to be practical after all

An earlier version of this document (and an earlier answer to the user)
said a full real-Windows install was "a multi-GB download and a long
install, genuinely impractical to complete inside a normal work session."
That was true for the default edition (`VERSION=11`, 7.9 GB) but wrong as
a blanket claim — dockur/windows documents a `VERSION` table with sizes
down to `2003` (Windows Server 2003, **0.6 GB**), which fits easily within
this environment's actual disk budget (checked directly with `df` before
starting — see the note on this environment's disk being a fixed
per-session allowance, not the filesystem's full size). Re-checking a
premise against the actual numbers, instead of repeating an earlier
"impractical" characterization from before the numbers were checked, is
exactly the discipline this project has tried to hold throughout.

### TLS interception breaks dockur's own in-container downloader — a documented, worked-around limitation

Running dockur/windows with a bare `VERSION=2003` (letting it download the
ISO itself) failed identically against all three of its ISO mirrors:

```
❯ ERROR: Failed to download https://dl.bobpony.com/windows/server/2003r2/...zip :
  SSL/TLS handshake failure: `not signed by known authorities or invalid'
❯ ERROR: Failed to download https://files.dog/MSDN/Windows%20Server%202003%20R2/...iso :
  SSL/TLS handshake failure: `not signed by known authorities or invalid'
❯ ERROR: Failed to download https://archive.org/download/.../....iso :
  SSL/TLS handshake failure: `not signed by known authorities or invalid'
❯ ERROR: All download methods failed for Windows Server 2003!
```

Same class of issue documented elsewhere in this project (Rizin's
tree-sitter dependency, `deb.debian.org` from inside the Linux guest): this
environment's outbound HTTPS goes through a TLS-intercepting proxy, and
the container's own trust store doesn't include that proxy's CA (it's a
separate filesystem from the host, which does have the CA configured).
Confirmed this was proxy-trust-specific, not a real network/mirror
failure: `curl` from the **host** against the exact same three URLs all
returned `200`, and the `archive.org` one downloaded the complete,
correct file — its SHA-256 matches the checksum dockur/windows's own
`define.sh` hardcodes for `win2003r2` byte-for-byte:

```
74245cba888f935b138b106c2744bec7f392925b472358960a0b5643cd6abb32
```

Rather than inject the proxy's CA into the container (untried, more
invasive), this used dockur/windows's own documented escape hatch:
binding a local ISO file to `/custom.iso` skips its downloader entirely
and lets it auto-detect the Windows version from the ISO's own contents.
`WindowsSandboxProvider` does exactly this when `isoOrVersion` is a local
file path (see its doc comment in `sandbox.hpp`); a bare `VERSION` string
is still supported for environments without this proxy's specific
trust-store gap.

### A real end-to-end run, in this environment

```
docker run -d --name win2003test -e KVM=N -e RAM_SIZE=1G -e DISK_SIZE=8G \
    -p 18006:8006 -p 13389:3389 --device=/dev/net/tun --cap-add NET_ADMIN \
    --stop-timeout 30 \
    -v /home/user/win2003_test/storage:/storage \
    -v /home/user/win2003_test/win2003.iso:/custom.iso \
    docker.io/dockurr/windows
```

Real output, confirming every claim above from source is what actually
happens: `Detected: Windows Server 2003 Standard` (ISO auto-detection),
`Warning: KVM acceleration is disabled...` (the `checkKvm()` downgrade
this document's earlier revision already found), and a real
`qemu-system-x86_64` process with exactly the TCG CPU model
`configureTcgAmd64WindowsModel()` computes for an Intel host running a
Windows guest:

```
-accel tcg,thread=multi -cpu Skylake-Client-v4,l3-cache=on,+hypervisor,vmx=off,-pcid,-tsc-deadline,-invpcid,-spec-ctrl,-xsavec,-xsaves,check
```

Disk usage (`/storage/data.img`, sparse) grew steadily during the
text-mode setup phase (650 MB → 1.1 GB over several minutes), and the
guest's own BIOS-level boot went from `Boot failed: not a bootable disk`
(first boot, installing from CD) to a successful `Booting from Hard
Disk...` on its post-text-mode-setup reboot — real, independent
confirmation the install is actually progressing, not just that a QEMU
process is running.

**Full outcome, not inferred — watched to completion**: rather than trust
indirect signals (disk growth, a bare TCP connect to the RDP port — see
below for why that one is actively misleading), the actual screen was
captured via a headless Chromium/Playwright session driving the
container's own noVNC web viewer (`http://127.0.0.1:8006/`). This showed
genuine setup progress through to the end: `Installing Windows —
Registering components` (`~10 minutes` remaining, per Windows' own
estimate), then `Finalizing installation — Saving settings` (`~4 minutes`
remaining), then a third BIOS-level reboot (into the newly-installed OS,
not the CD), and finally **a real, fully booted Windows Server 2003
desktop** — Start button, taskbar, Recycle Bin, clock — with a live RDP
server confirmed via the real X.224 handshake below (not a bare connect).
Total wall-clock time from container start to a real RDP handshake
succeeding: **1398 seconds (~23 minutes 18 seconds)**, comfortably inside
the CLI's 3600s Windows-guest default (see below) and this environment's
disk budget (final installed disk usage: **1.9 GB**, out of the 8 GB
allocated).

### A real false-positive readiness check, caught before it shipped

The obvious way to detect "is the guest up" is a TCP connect to the
published RDP port. Tested directly, that check reported success after
**0 seconds** — before Windows was anywhere near installed. Root cause:
dockur/windows's own container-side port-forwarding proxy accepts TCP
connections on 3389 immediately at container start, regardless of whether
anything inside the guest is listening yet. A plain-connect readiness
check would have been actively wrong, not just imprecise.

Fixed by checking at the protocol level instead: `rdpHandshakeOk()`
(`windows_sandbox_provider.cpp`) sends a real RDP X.224 Connection
Request TPDU (the same first packet `mstsc`/`xfreerdp` send) and only
treats a real X.224 Connection Confirm response (`0xD0` at the expected
offset) as "up." Verified this correctly reports "not up" throughout the
real install above (`Connection reset by peer` — nothing is listening on
3389 inside the guest yet) rather than the false "up" a bare connect gave
immediately.

### `WindowsSandboxProvider`'s honest v1 scope

Booting a real Windows guest under TCG and confirming it's genuinely
reachable is proven end to end, per above. What isn't built yet: any
mechanism to deliver a sample into the guest or execute/monitor it there
— there is no Windows-side equivalent of `sandbox/agent/agent.sh`. RDP
has no serial-console-style scripting channel the way the Linux provider
uses; delivering and running a sample would need its own mechanism (RDP
automation, or dockur/windows's Samba share plus a scheduled task, or its
documented one-shot `COMMAND` environment variable run at the end of
install — none implemented yet).

`WindowsSandboxProvider::detonate()` reflects this honestly rather than
papering over it: **`completed` never becomes `true` in v1**, even on a
fully successful boot — `error` is what actually distinguishes "the guest
booted and answered a real RDP handshake, sample execution just isn't
implemented yet" from a genuine failure (container wouldn't start, or
never became reachable within the timeout, with the container's own
recent log lines included for diagnosis).

```
compass-cli --detonate <sample> --windows-iso <path-or-VERSION> [--timeout <secs>]
```

`--timeout` defaults to 3600s (one hour) for a Windows guest specifically
when not passed explicitly — the CLI's general 30s default (fine for the
much lighter Linux guest boot) would otherwise report "never came up" on
every unmodified invocation, since a from-scratch install genuinely takes
on that order under TCG (see the real run above).

`scripts/windows_sandbox_smoke_test.sh` verifies the plumbing (container
construction, RDP port discovery, the real handshake probe correctly
reporting "not up yet," clean container teardown) against the real
`docker.io/dockurr/windows` image with a short timeout — deliberately not
a full install every run, since that would make the test take as long as
a real Windows install; the full install-to-real-RDP-handshake path was
separately verified manually, per above.

#!/bin/bash
# In-guest sandbox agent. Deliberately a shell script, not the compiled
# Go/Rust binary docs/ROADMAP.md originally sketched — that was written
# assuming a minimal custom guest image where a static binary avoids a
# libc mismatch. The actual guest (see docs/SANDBOX.md) is a full Debian
# image with bash/coreutils/apt already present, so that concern doesn't
# apply, and a script is trivially transferable over the proven serial
# shell channel (a heredoc, no base64/binary-transfer machinery needed)
# where a compiled binary would need chunked base64 transfer. All the
# smart parsing of what this produces happens host-side in C++
# (QemuTcgSandboxProvider) — this script's only job is to orchestrate
# strace/tcpdump and dump their raw output; keeping it this thin means the
# parsing logic that actually needs testing/iteration lives where it's
# easy to test, not inside the guest.
#
# Usage: agent.sh <sample-path> <timeout-seconds>
# Writes /tmp/agent.strace, /tmp/agent.net, /tmp/agent.meta, then prints
# "AGENT_DONE <exit_code>" as a sentinel the host driver watches for.
set -u

SAMPLE="$1"
TIMEOUT="${2:-10}"

STRACE_LOG=/tmp/agent.strace
NET_LOG=/tmp/agent.net
META_LOG=/tmp/agent.meta

if ! command -v strace >/dev/null 2>&1; then
    # Two real issues hit here, confirmed against a real guest boot:
    #   1. The nocloud image's apt cache is never primed by default (no
    #      `apt-get update` has ever run) — install fails with "Unable to
    #      locate package" without one first.
    #   2. HTTPS to deb.debian.org fails certificate verification from
    #      inside this guest — some outbound TLS-intercepting proxy in
    #      front of this sandbox's network path (same class of issue hit
    #      elsewhere building this project: Rizin's tree-sitter
    #      dependency, reactos.org while validating dockur/windows).
    #      Disabling verification is reasonable specifically here: this
    #      guest is an ephemeral, disposable overlay reset on every run —
    #      not a machine anything persists trust in — and the alternative
    #      is the install failing outright regardless of proxy CA setup
    #      this project doesn't control.
    apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false \
        update >/tmp/agent.apt.log 2>&1
    apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false \
        install -y strace >>/tmp/agent.apt.log 2>&1
fi

chmod +x "$SAMPLE" 2>/dev/null

: > "$STRACE_LOG"
: > "$NET_LOG"

if command -v tcpdump >/dev/null 2>&1; then
    timeout "$TIMEOUT" tcpdump -tt -n -l >"$NET_LOG" 2>/tmp/agent.tcpdump.err &
    TCPDUMP_PID=$!
else
    TCPDUMP_PID=""
fi

START_NS=$(date +%s%N)
if command -v strace >/dev/null 2>&1; then
    timeout "$TIMEOUT" strace -f -tt -y -s 200 -o "$STRACE_LOG" "$SAMPLE" >/tmp/agent.stdout.log 2>/tmp/agent.stderr.log
    RC=$?
else
    timeout "$TIMEOUT" "$SAMPLE" >/tmp/agent.stdout.log 2>/tmp/agent.stderr.log
    RC=$?
    echo "# strace unavailable (apt install failed — see /tmp/agent.apt.log)" >> "$STRACE_LOG"
fi
END_NS=$(date +%s%N)

[ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null
[ -n "$TCPDUMP_PID" ] && wait "$TCPDUMP_PID" 2>/dev/null

{
    echo "start_ns=$START_NS"
    echo "end_ns=$END_NS"
    echo "exit_code=$RC"
} > "$META_LOG"

echo "AGENT_DONE $RC"

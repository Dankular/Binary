#!/usr/bin/env bash
# Milestone 4 "Windows guest": proves WindowsSandboxProvider's plumbing —
# docker container construction, RDP host-port discovery, the real X.224
# RDP handshake probe (not a plain TCP connect, which dockur/windows's own
# port-forwarding proxy accepts immediately regardless of whether Windows
# is actually ready — see docs/SANDBOX.md) — end to end against the real
# `docker.io/dockurr/windows` image.
#
# Deliberately uses a short --timeout: a full Windows Server 2003 install
# under TCG genuinely completes and answers a real RDP handshake (verified
# manually in this environment — see docs/SANDBOX.md for the exact
# command and measured timing), but re-proving that from scratch here
# would mean this script taking as long as a full install every run. This
# script instead proves everything except that final "install actually
# finished" wait: the container starts, the RDP port is discovered, the
# handshake probe correctly reports "not up yet" (a real, meaningful
# assertion — a plain TCP-connect-only check would wrongly report "up"
# within the first second, which is exactly the bug this probe exists to
# avoid), and cleanup leaves no container behind.
#
# Requires a cached Windows install ISO (see docs/SANDBOX.md for how one
# was obtained and verified in this environment) — set WINDOWS_ISO to its
# path. Skips (not fails) if unset, same convention as other
# environment-dependent scripts in this project.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

if [ -z "${WINDOWS_ISO:-}" ] || [ ! -f "${WINDOWS_ISO:-}" ]; then
    echo "SKIP: WINDOWS_ISO not set to an existing file — see docs/SANDBOX.md for how to obtain one"
    exit 0
fi

command -v docker >/dev/null || { echo "SKIP: docker not installed"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon not reachable"; exit 0; }

echo "== configuring/building =="
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
CLI="$BUILD_DIR/src/cli/compass-cli"

echo "== dummy sample (provider accepts it but doesn't deliver it yet — see docs/SANDBOX.md) =="
: > "$WORK/sample.bin"

echo "== detonating with a short timeout (proves plumbing, not a full install — see header) =="
before_containers="$(docker ps -aq --filter 'name=compass-win-' | wc -l)"
# compass-cli exits 1 whenever completed == false, which WindowsSandboxProvider
# always sets in v1 (even on a fully successful boot — see docs/SANDBOX.md) —
# that's the expected exit code here, not a script failure, so don't let it
# trip `set -e`.
out="$("$CLI" --detonate "$WORK/sample.bin" --windows-iso "$WINDOWS_ISO" --timeout 60 2>&1)" || true
echo "$out" | grep -q "^completed: false" || fail "expected completed: false (v1 never reports a real detonation — see docs/SANDBOX.md):\n$out"
echo "$out" | grep -qE "never answered a real RDP handshake within 60s" \
    || fail "expected the timeout-path error message — got:\n$out"
echo "$out" | grep -qE "recent container log lines:" \
    || fail "expected recent container logs in the error for diagnosability — got:\n$out"

echo "== cleanup: no compass-win-* container left running or stopped =="
after_containers="$(docker ps -aq --filter 'name=compass-win-' | wc -l)"
[ "$after_containers" -eq "$before_containers" ] || fail "a compass-win-* container was left behind (before=$before_containers after=$after_containers)"

echo
echo "ALL WINDOWS SANDBOX SMOKE TESTS PASSED"

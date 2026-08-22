#!/usr/bin/env bash
# Milestone 4 "Dynamic analysis sandbox": proves QemuTcgSandboxProvider
# end to end — compiles a real fixture that makes concrete, checkable
# syscalls (drops a file, opens a TCP connection), detonates it inside a
# disposable QEMU/TCG overlay of the cached Debian guest image, and
# asserts the returned DetonationReport actually contains the specific
# FileEvent/NetworkEvent/SyscallEvent data those syscalls should produce
# — not just that the run "completed".
#
# Requires .cache/debian-12-nocloud-amd64.qcow2 (run linux_guest_probe.sh
# once first to populate it). Boots a full guest OS under software
# emulation, so this is slow (a minute or more) — not run as part of the
# regular smoke test for that reason; run it explicitly when validating
# the sandbox milestone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
CACHE_DIR="${CACHE_DIR:-$ROOT/.cache}"
GUEST_IMAGE="$CACHE_DIR/debian-12-nocloud-amd64.qcow2"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }

[ -f "$GUEST_IMAGE" ] || fail "no cached guest image at $GUEST_IMAGE — run scripts/linux_guest_probe.sh once first"

echo "== configuring/building =="
cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
CLI="$BUILD_DIR/src/cli/compass-cli"

echo "== compiling fixture (drops a file, opens a TCP connection) =="
cat > "$WORK/sample.c" <<'EOF'
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    int fd = open("/tmp/dropped_file.txt", O_WRONLY | O_CREAT, 0644);
    write(fd, "hello\n", 6);
    close(fd);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr);
    connect(s, (struct sockaddr*)&addr, sizeof(addr)); // expected to fail/timeout offline; the syscall itself is what's under test
    close(s);
    return 0;
}
EOF
gcc -O0 -static -o "$WORK/sample" "$WORK/sample.c"

echo "== detonating (boots a disposable TCG guest — this takes a while) =="
out="$("$CLI" --detonate "$WORK/sample" --guest-image "$GUEST_IMAGE" --timeout 15 2>&1)" \
    || fail "compass-cli --detonate exited non-zero:\n$out"

echo "$out" | grep -q "^completed: true" || fail "report did not report completed: true — got:\n$out"

echo "== checking the report actually reflects what the sample did =="
echo "$out" | grep -qE "\[file\].*create.*\/tmp\/dropped_file\.txt" \
    || fail "expected a create FileEvent for /tmp/dropped_file.txt — got:\n$out"
echo "$out" | grep -qE "\[net\].*tcp.*93\.184\.216\.34:80" \
    || fail "expected a tcp NetworkEvent to 93.184.216.34:80 — got:\n$out"
echo "$out" | grep -qE "\[sys\].*openat" || fail "expected an openat SyscallEvent — got:\n$out"
echo "$out" | grep -qE "\[sys\].*connect" || fail "expected a connect SyscallEvent — got:\n$out"

syscall_count="$(echo "$out" | grep -oE '^syscalls: [0-9]+' | awk '{print $2}')"
[ -n "$syscall_count" ] && [ "$syscall_count" -gt 0 ] || fail "syscalls count was 0 or missing — parser regression"

echo
echo "ALL SANDBOX DETONATE TESTS PASSED"

#!/usr/bin/env bash
# Proves the sandbox's Linux-guest path end to end, on top of what
# tcg_probe.sh already proved (bare TCG code execution): downloads an
# official Debian cloud image, boots it under QEMU TCG (no /dev/kvm) from a
# qcow2 overlay (the same snapshot-per-run scheme docs/SANDBOX.md
# specifies), logs in over a unix-socket serial channel, runs a command
# inside the guest, and confirms the output comes back out — the same
# control-channel shape a real in-guest agent will use.
#
# Downloads ~400MB on first run (cached under .cache/, gitignored). Not run
# as part of the regular smoke test for that reason; run it explicitly when
# validating the sandbox milestone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${CACHE_DIR:-$ROOT/.cache}"
WORK="$(mktemp -d)"
mkdir -p "$CACHE_DIR"

cleanup() {
    [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

for bin in qemu-system-x86_64 qemu-img python3 curl sha512sum; do
    command -v "$bin" >/dev/null || { echo "FAIL: $bin not installed"; exit 1; }
done

IMAGE_URL="https://cdimage.debian.org/cdimage/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2"
SUMS_URL="https://cdimage.debian.org/cdimage/cloud/bookworm/latest/SHA512SUMS"
BASE_IMG="$CACHE_DIR/debian-12-nocloud-amd64.qcow2"

if [ ! -f "$BASE_IMG" ]; then
    echo "== downloading Debian cloud image (~400MB, cached after first run) =="
    curl -sSL -o "$BASE_IMG.partial" "$IMAGE_URL"
    mv "$BASE_IMG.partial" "$BASE_IMG"
fi

echo "== verifying checksum against Debian's published SHA512SUMS =="
expected="$(curl -sSL "$SUMS_URL" | grep 'debian-12-nocloud-amd64.qcow2$' | awk '{print $1}')"
actual="$(sha512sum "$BASE_IMG" | awk '{print $1}')"
[ -n "$expected" ] || { echo "FAIL: could not fetch expected checksum"; exit 1; }
[ "$expected" = "$actual" ] || { echo "FAIL: checksum mismatch — re-download and try again"; rm -f "$BASE_IMG"; exit 1; }

echo "== creating disposable overlay (base image never modified) =="
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$WORK/run.qcow2" >/dev/null

echo "== booting under TCG (no KVM) and driving over a serial socket =="
qemu-system-x86_64 \
    -accel tcg,thread=multi -m 2048 -smp 2 -M q35 \
    -drive file="$WORK/run.qcow2",if=virtio,format=qcow2 \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
    -display none -monitor none \
    -chardev socket,id=ser0,path="$WORK/serial.sock",server=on,wait=off \
    -serial chardev:ser0 -no-reboot \
    >"$WORK/qemu.log" 2>&1 &
QEMU_PID=$!

# Give QEMU a moment to create the socket before connecting.
for _ in $(seq 1 20); do
    [ -S "$WORK/serial.sock" ] && break
    sleep 0.5
done

if timeout 130 python3 "$ROOT/tests/fixtures/sandbox_probe/serial_drive.py" "$WORK/serial.sock"; then
    echo
    echo "LINUX GUEST PROBE PASSED: booted a real Debian guest under TCG and ran a command in it over a serial control channel"
else
    echo "FAIL: guest boot/login/command sequence did not complete — see above"
    cat "$WORK/qemu.log" >&2
    exit 1
fi

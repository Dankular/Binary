#!/usr/bin/env bash
# Proves the sandbox milestone's core assumption: QEMU's TCG accelerator
# (pure software CPU emulation) can execute real x86 code in this
# environment with no /dev/kvm and no elevated privileges — i.e. the
# dynamic-analysis sandbox (docs/SANDBOX.md) does not need hypervisor
# infrastructure beyond a plain container.
#
# Boots a 17-byte real-mode payload (tests/fixtures/sandbox_probe/boot.asm)
# that writes "TCG-OK" to the COM1 UART and exits via isa-debug-exit, and
# asserts both actually happened.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v nasm >/dev/null || { echo "FAIL: nasm not installed"; exit 1; }
command -v qemu-system-x86_64 >/dev/null || { echo "FAIL: qemu-system-x86_64 not installed"; exit 1; }

nasm -f bin "$ROOT/tests/fixtures/sandbox_probe/boot.asm" -o "$WORK/boot.img"

set +e
output="$(timeout 15 qemu-system-x86_64 \
    -accel tcg \
    -m 32 \
    -nographic \
    -drive file="$WORK/boot.img",format=raw,if=ide \
    -device isa-debug-exit,iobase=0xf4,iosize=0x01 \
    -no-reboot 2>&1)"
exit_code=$?
set -e

echo "$output" | grep -q "TCG-OK" || {
    echo "FAIL: guest never printed TCG-OK — TCG execution did not happen"
    echo "$output"
    exit 1
}
# isa-debug-exit maps guest exit code E to QEMU process exit code (E<<1)|1;
# our boot sector writes 0x11, so we expect 0x23 = 35.
[ "$exit_code" -eq 35 ] || {
    echo "FAIL: unexpected QEMU exit code $exit_code (expected 35 from isa-debug-exit)"
    exit 1
}

echo "TCG PROBE PASSED: QEMU executed real x86 code via TCG with no KVM in this container"

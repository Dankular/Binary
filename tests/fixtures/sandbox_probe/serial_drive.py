#!/usr/bin/env python3
"""Drives a guest over a QEMU unix-socket serial channel: waits for a login
prompt, logs in, runs one command, checks for a marker in its output, then
shuts the guest down cleanly. Used by scripts/linux_guest_probe.sh as a
stand-in for the real in-guest agent's communication channel (see
docs/SANDBOX.md) — proving guest control over this exact transport works,
not just that the guest boots.
"""
import socket
import sys
import time

MARKER = "COMPASS_TCG_LINUX_GUEST_OK"


def main():
    if len(sys.argv) != 2:
        print("usage: serial_drive.py <unix-socket-path>", file=sys.stderr)
        return 2
    sock_path = sys.argv[1]

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.setblocking(False)

    buf = b""

    def read_for(seconds):
        nonlocal buf
        end = time.time() + seconds
        while time.time() < end:
            try:
                chunk = s.recv(65536)
                if chunk:
                    buf += chunk
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.flush()
            except BlockingIOError:
                time.sleep(0.2)
        return buf

    def send(text):
        s.sendall(text.encode())

    print("=== waiting for login prompt (up to 90s) ===", file=sys.stderr)
    end = time.time() + 90
    seen_login = False
    while time.time() < end:
        read_for(1)
        if b"login:" in buf:
            seen_login = True
            break
    if not seen_login:
        print("=== NEVER SAW LOGIN PROMPT ===", file=sys.stderr)
        return 1

    buf = b""
    send("root\r\n")
    time.sleep(2)
    read_for(3)

    buf = b""
    send(f"echo {MARKER}\r\n")
    time.sleep(2)
    out = read_for(3)

    found = MARKER.encode() in out
    print(
        "\n=== MARKER FOUND: shell command executed inside guest ===" if found
        else "\n=== MARKER NOT FOUND ===",
        file=sys.stderr,
    )

    send("poweroff\r\n")
    read_for(15)
    s.close()
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())

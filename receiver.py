#!/usr/bin/env python3
"""
receiver.py — runs on the VM.

Listens on UDP port 9999. Blocks on recvfrom() so that sock_def_readable
and sys_exit_recvfrom are observable by the tracer as the packet arrives.
"""
import socket

PORT = 9999


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    print(f"Listening on UDP port {PORT}...", flush=True)

    data, addr = sock.recvfrom(4096)
    print(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}: {data!r}", flush=True)
    sock.sendto(data, addr)
    print(f"Echoed {len(data)} bytes back to {addr[0]}:{addr[1]}", flush=True)
    sock.close()


if __name__ == "__main__":
    main()

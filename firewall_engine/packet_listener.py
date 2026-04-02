"""
packet_listener.py — alternative entry point for running the capture engine.
Delegates all logic to CaptureEngine (capture.py is the authoritative module).
"""

import os
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall_engine.capture import CaptureEngine


def start_listener(queue_num: int = 0) -> None:
    if os.geteuid() != 0:
        print("[!] Must be run as root to interface with NFQUEUE and iptables.")
        sys.exit(1)

    engine = CaptureEngine(queue_num=queue_num)
    engine.run()


if __name__ == "__main__":
    start_listener()

"""
AttackClassifier — rule-based heuristic layer.

Works alongside the ML model. Returns the most specific attack type it
can identify, or "None" if traffic looks clean.

Rules (in priority order):
  1. UDP/ICMP Flood — high byte rate from a single source
  2. Port Scan     — > 20 unique destination ports from one source
  3. Brute Force   — > 10 failed TCP connections from one source
  4. DoS           — sustained high packet rate (> 500 pkt/s)
  5. None          — normal traffic
"""

import time
from collections import defaultdict


# Thresholds -----------------------------------------------------------------
PORT_SCAN_THRESHOLD       = 15       # distinct dst_ports before flagging (lab-realistic)
BRUTE_FORCE_THRESHOLD     = 5        # failed connections before flagging
DOS_PACKET_RATE_THRESHOLD = 200      # packets per second (realistic DoS threshold)
FLOOD_BYTE_RATE_THRESHOLD = 500_000  # 500 KB/s (realistic flood threshold)
RATE_WINDOW_SECONDS       = 10       # rolling window for rate calculations
# ---------------------------------------------------------------------------



class AttackClassifier:
    def __init__(self):
        # Per-source history (keyed by src_ip)
        self.ip_recent_rates:   dict[str, list] = defaultdict(list)  # [(ts, rate)]
        self.ip_recent_bytes:   dict[str, list] = defaultdict(list)  # [(ts, bytes)]
        self.ip_ports_accessed: dict[str, list] = defaultdict(list)  # [(ts, port)]
        self.ip_failed_conns:   dict[str, int]  = defaultdict(int)

    def classify(self, flow: dict) -> str:
        """
        Analyse a completed flow dict and return an attack type string.

        Expected flow keys (from CaptureEngine):
          src_ip, dst_port, packet_count, total_bytes, failed_connections,
          protocol, start_time, last_seen
        """
        src_ip     = flow.get("src_ip", "unknown")
        dst_port   = flow.get("dst_port", 0)
        protocol   = flow.get("protocol", "other").upper()
        start_time = flow.get("start_time", 0)
        last_seen  = flow.get("last_seen", flow.get("last_time", 0))
        duration   = max(last_seen - start_time, 0.001)
        pkt_count  = flow.get("packet_count", 0)
        total_bytes= flow.get("total_bytes", 0)
        failed     = flow.get("failed_connections", 0)

        packet_rate = pkt_count  / duration
        byte_rate   = total_bytes / duration
        now         = time.time()

        # ── Update rolling histories ──────────────────────────────────────
        self.ip_recent_rates[src_ip].append((now, packet_rate))
        self.ip_recent_bytes[src_ip].append((now, byte_rate))
        self.ip_ports_accessed[src_ip].append((now, dst_port))
        self.ip_failed_conns[src_ip] += failed

        # Prune old entries outside the rolling window
        cutoff = now - RATE_WINDOW_SECONDS
        self.ip_recent_rates[src_ip]  = [(t, r) for t, r in self.ip_recent_rates[src_ip]  if t > cutoff]
        self.ip_recent_bytes[src_ip]  = [(t, b) for t, b in self.ip_recent_bytes[src_ip]  if t > cutoff]
        self.ip_ports_accessed[src_ip]= [(t, p) for t, p in self.ip_ports_accessed[src_ip] if t > cutoff]

        # ── Compute rolling averages ──────────────────────────────────────
        rates = self.ip_recent_rates[src_ip]
        bytes_ = self.ip_recent_bytes[src_ip]
        unique_ports = len({p for _, p in self.ip_ports_accessed[src_ip]})
        
        avg_pkt_rate  = sum(r for _, r in rates)  / max(len(rates),  1)
        avg_byte_rate = sum(b for _, b in bytes_) / max(len(bytes_), 1)

        # ── Rule evaluation (priority order) ─────────────────────────────
        if protocol in ("UDP", "ICMP") and avg_byte_rate > FLOOD_BYTE_RATE_THRESHOLD:
            return "UDP/ICMP Flood"

        if unique_ports > PORT_SCAN_THRESHOLD:
            return "Port Scan"

        if self.ip_failed_conns[src_ip] > BRUTE_FORCE_THRESHOLD:
            return "Brute Force"

        if avg_pkt_rate > DOS_PACKET_RATE_THRESHOLD:
            return "DoS"

        return "None"

    def reset_ip(self, src_ip: str) -> None:
        """Clear history for a specific IP (call after blocking)."""
        self.ip_recent_rates.pop(src_ip, None)
        self.ip_recent_bytes.pop(src_ip, None)
        self.ip_ports_accessed.pop(src_ip, None)
        self.ip_failed_conns.pop(src_ip, None)

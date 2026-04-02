"""
FlowTracker — groups individual packets into bidirectional network flows.

Each flow is keyed by (src_ip, dst_ip, src_port, dst_port, protocol).
Flows expire after `timeout` seconds of inactivity and are returned
for ML feature extraction.
"""

import time


class FlowTracker:
    def __init__(self, timeout: float = 5.0):
        self.flows: dict = {}
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_flow(self, packet_info: dict) -> None:
        """Incorporate a single packet into a running flow record."""
        key = self._make_key(packet_info)
        now = packet_info["timestamp"]
        flags = packet_info.get("flags", "")

        if key not in self.flows:
            self.flows[key] = {
                # Identifiers
                "src_ip":    packet_info["src_ip"],
                "dst_ip":    packet_info["dst_ip"],
                "src_port":  packet_info["src_port"],
                "dst_port":  packet_info["dst_port"],
                "protocol":  packet_info["protocol"],
                # Timing
                "start_time": now,
                "last_seen":  now,
                # Volume
                "packet_count": 1,
                "total_bytes":  packet_info["size"],
                # TCP flag counters
                "syn_count": 1 if "S" in flags else 0,
                "ack_count": 1 if "A" in flags else 0,
                "fin_count": 1 if "F" in flags else 0,
                "rst_count": 1 if "R" in flags else 0,
                "urg_count": 1 if "U" in flags else 0,
                # Heuristic counters
                "failed_connections": 0,  # RST without prior ACK is a failure indicator
                "unique_dst_ports": {packet_info["dst_port"]},
            }
        else:
            flow = self.flows[key]
            flow["packet_count"] += 1
            flow["total_bytes"]  += packet_info["size"]
            flow["last_seen"]     = now

            if "S" in flags: flow["syn_count"] += 1
            if "A" in flags: flow["ack_count"] += 1
            if "F" in flags: flow["fin_count"] += 1
            if "R" in flags:
                flow["rst_count"] += 1
                # RST without SYN–ACK handshake completion → connection failure
                if flow["syn_count"] > flow["ack_count"]:
                    flow["failed_connections"] += 1
            if "U" in flags: flow["urg_count"] += 1
            flow["unique_dst_ports"].add(packet_info["dst_port"])

    def get_expired_flows(self, current_time: float) -> list:
        """
        Return and remove all flows whose last packet was more than
        `self.timeout` seconds ago.
        """
        expired_keys = [
            k for k, v in self.flows.items()
            if current_time - v["last_seen"] > self.timeout
        ]
        expired = []
        for k in expired_keys:
            flow = self.flows.pop(k)
            # Serialise the set so callers get a plain int count
            flow["unique_dst_ports"] = len(flow["unique_dst_ports"])
            expired.append(flow)
        return expired

    def get_active_count(self) -> int:
        return len(self.flows)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(packet_info: dict) -> tuple:
        return (
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["src_port"],
            packet_info["dst_port"],
            packet_info["protocol"],
        )

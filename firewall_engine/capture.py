import os
import sys

# Ensure the project root is in sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import time
import logging
import threading
import json
from collections import deque
from scapy.all import IP
from netfilterqueue import NetfilterQueue

# Modular imports
from firewall_engine.flow_tracker import FlowTracker
from firewall_engine.ml_engine import MLEngine
from firewall_engine.mitigation import Mitigation
from firewall_engine.attack_classifier import AttackClassifier

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("Capture")

class CaptureEngine:
    def __init__(self, queue_num=0):
        self.queue_num = queue_num
        # Bug 4 fix: lower min_packets so detection kicks in quickly
        self.flow_tracker = FlowTracker(timeout=10.0, min_packets=3)

        # Paths
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        model_path  = os.path.join(self.root_dir, "ml_model", "model.pkl")
        scaler_path = os.path.join(self.root_dir, "ml_model", "scaler.pkl")

        self.log_path   = os.path.join(self.root_dir, "logs", "realtime_flows.json")
        self.stats_path = os.path.join(self.root_dir, "logs", "stats.json")

        # Ensure log dir exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        self.ml_engine  = MLEngine(model_path, scaler_path)
        self.mitigation = Mitigation(block_duration=300)

        # Bug 7 fix: wire in the heuristic AttackClassifier
        self.classifier = AttackClassifier()

        # Stats
        self.total_packets = 0
        self.total_attacks = 0
        self.start_time    = time.time()
        self.recent_logs   = deque(maxlen=200)
        self._lock         = threading.Lock()

    def get_stats(self):
        with self._lock:
            return {
                "uptime_seconds":      int(time.time() - self.start_time),
                "total_flows":         self.total_packets,
                "total_attacks":       self.total_attacks,
                "active_flows":        len(self.flow_tracker.flows),
                "blocked_ips":         len(self.mitigation.blocked_ips),
                "baseline_packet_rate": 0.0,
                "is_learning":         False,
                "engine_status":       "Active"
            }

    def get_latest_results(self, n=100):
        with self._lock:
            return list(self.recent_logs)[-n:]

    def packet_callback(self, packet):
        """CRITICAL: NFQUEUE Callback Logic"""
        with self._lock:
            self.total_packets += 1
            pkt_count = self.total_packets

        payload    = packet.get_payload()
        scapy_pkt  = IP(payload)

        src_ip = scapy_pkt.src
        dst_ip = scapy_pkt.dst
        proto  = scapy_pkt.proto

        # 1. Update Flow Tracker
        flow = self.flow_tracker.update(scapy_pkt)

        # Bug 5 fix: clear expired flows every 100 packets to prevent memory leak
        if pkt_count % 100 == 0:
            self.flow_tracker.clear_expired()
            self._update_stats()

        # Bug 4 fix: only run ML once flow has enough packets for meaningful features
        if flow is None or flow['packet_count'] < self.flow_tracker.min_packets:
            packet.accept()
            return

        # 2. Extract Features
        features = self.flow_tracker.get_features(flow)

        # 3. ML Inference
        score, is_anomaly = self.ml_engine.predict(features)

        # Bug 7 fix: run heuristic classifier for rule-based attack type labelling
        # AttackClassifier.classify() needs a flow dict with compatible keys
        classifier_flow = {
            "src_ip":             src_ip,
            "dst_port":           0,
            "packet_count":       flow['packet_count'],
            "total_bytes":        flow['total_bytes'],
            "failed_connections": 0,
            "protocol":           "TCP" if proto == 6 else "UDP" if proto == 17 else "ICMP" if proto == 1 else "OTHER",
            "start_time":         flow['start_time'],
            "last_seen":          flow['last_time'],
        }
        attack_type = self.classifier.classify(classifier_flow)

        # Bug 9 fix: include attack_type and syn_ratio so routes.py can display them
        log_entry = {
            "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%S"),
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "protocol":       str(proto),
            "prediction":     "ATTACK" if (is_anomaly or attack_type != "None") else "NORMAL",
            "confidence":     round(float(score) if is_anomaly else 0.0, 4),
            "packet_rate":    round(features['packet_rate'], 2),
            "avg_packet_size":round(features['avg_packet_size'], 2),
            "syn_ratio":      round(features['syn_ratio'], 4),
            "attack_type":    attack_type if attack_type != "None" else ("AI Anomaly" if is_anomaly else "None"),
        }

        with self._lock:
            self.recent_logs.append(log_entry)
        self._append_log(log_entry)

        # 4. Decision & Mitigation — trigger on ML anomaly OR heuristic rule
        if is_anomaly or attack_type != "None":
            with self._lock:
                self.total_attacks += 1

            threshold = self.ml_engine.threshold
            packet.drop()
            self.mitigation.block_ip(src_ip, score, threshold,
                                     attack_type if attack_type != "None" else "AI Anomaly")
            logger.info(f"[NFQUEUE] DROP | src: {src_ip} | score: {score:.4f} | type: {log_entry['attack_type']}")
            self._update_stats()
            # Reset heuristic state for this IP after blocking
            self.classifier.reset_ip(src_ip)
            return

        packet.accept()

    def _append_log(self, entry):
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write log: {e}")

    def _update_stats(self):
        stats = {
            "uptime_seconds": int(time.time() - self.start_time),
            "total_packets":  self.total_packets,
            "total_attacks":  self.total_attacks,
            "blocked_ips":    len(self.mitigation.blocked_ips)
        }
        try:
            with open(self.stats_path, "w") as f:
                json.dump(stats, f)
        except Exception as e:
            logger.error(f"Failed to update stats: {e}")

    def run(self):
        if os.geteuid() != 0:
            logger.error("Must be run as root!")
            sys.exit(1)

        self.mitigation.setup_nfqueue(self.queue_num)
        nfqueue = NetfilterQueue()

        try:
            nfqueue.bind(self.queue_num, self.packet_callback)
            logger.info(f"[*] Adaptive AI Firewall active on NFQUEUE {self.queue_num}")
            nfqueue.run()
        except KeyboardInterrupt:
            logger.info("[!] Shutting down...")
        finally:
            self.mitigation.cleanup(self.queue_num)
            nfqueue.unbind()

if __name__ == "__main__":
    engine = CaptureEngine(queue_num=0)
    engine.run()

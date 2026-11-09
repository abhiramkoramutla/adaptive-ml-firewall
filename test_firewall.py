#!/usr/bin/env python3
"""
test_firewall.py — Automated unit tests for the Adaptive AI Firewall.

Tests ML detection, heuristic classification, flow tracking, and REST APIs
WITHOUT needing root or NFQUEUE kernel privileges.

Usage:
    source venv/bin/activate
    python test_firewall.py
    # Or with pytest:
    python -m pytest -v
"""

import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if os.path.join(ROOT, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "backend"))

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

results = []

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    print(f"  {status} {name}" + (f" — {detail}" if detail else ""))
    results.append((name, condition))
    assert condition, f"Assertion failed for: {name} ({detail})"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Test MLEngine loads correctly
# ─────────────────────────────────────────────────────────────────────────────
def test_ml_engine_loading():
    print(f"\n{INFO} === Test 1: MLEngine Model Loading ===")
    from firewall_engine.ml_engine import MLEngine

    model_path  = os.path.join(ROOT, "ml_model", "model.pkl")
    scaler_path = os.path.join(ROOT, "ml_model", "scaler.pkl")
    ml = MLEngine(model_path, scaler_path)

    check("model.pkl exists",  os.path.exists(model_path))
    check("scaler.pkl exists", os.path.exists(scaler_path))
    check("MLEngine model loaded", ml.model is not None)
    check("MLEngine scaler loaded", ml.scaler is not None)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Test ML detection — Normal traffic
# ─────────────────────────────────────────────────────────────────────────────
def test_ml_detection_normal_traffic():
    print(f"\n{INFO} === Test 2: ML Detection — Normal Traffic ===")
    from firewall_engine.ml_engine import MLEngine

    model_path  = os.path.join(ROOT, "ml_model", "model.pkl")
    scaler_path = os.path.join(ROOT, "ml_model", "scaler.pkl")
    ml = MLEngine(model_path, scaler_path)

    NORMAL_FLOWS = [
        # Typical HTTP browsing: low rate, normal sizes
        dict(packet_rate=12, byte_rate=8000, duration=5.0, iat_mean=0.08,
             iat_std=0.02, syn_ratio=0.05, ack_ratio=0.90, fin_ratio=0.05, avg_packet_size=650),
        # Small file transfer
        dict(packet_rate=30, byte_rate=25000, duration=3.0, iat_mean=0.033,
             iat_std=0.01, syn_ratio=0.03, ack_ratio=0.93, fin_ratio=0.04, avg_packet_size=820),
        # SSH session
        dict(packet_rate=5, byte_rate=2000, duration=10.0, iat_mean=0.2,
             iat_std=0.05, syn_ratio=0.02, ack_ratio=0.95, fin_ratio=0.03, avg_packet_size=400),
    ]

    for i, flow_feat in enumerate(NORMAL_FLOWS):
        score, is_anomaly = ml.predict(flow_feat)
        ok = not is_anomaly
        check(f"Normal flow {i+1} classified as NORMAL (score={score:.4f})", ok)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Test ML detection — Attack traffic
# ─────────────────────────────────────────────────────────────────────────────
def test_ml_detection_attack_traffic():
    print(f"\n{INFO} === Test 3: ML Detection — DoS / Flood Attacks ===")
    from firewall_engine.ml_engine import MLEngine

    model_path  = os.path.join(ROOT, "ml_model", "model.pkl")
    scaler_path = os.path.join(ROOT, "ml_model", "scaler.pkl")
    ml = MLEngine(model_path, scaler_path)

    ATTACK_FLOWS = [
        # Classic DoS: extremely high packet rate, tiny packets
        dict(packet_rate=3000, byte_rate=180000, duration=0.5, iat_mean=0.0003,
             iat_std=0.00005, syn_ratio=0.01, ack_ratio=0.02, fin_ratio=0.0, avg_packet_size=60),
        # SYN flood: high syn_ratio, rapid connections
        dict(packet_rate=1500, byte_rate=90000, duration=0.3, iat_mean=0.0007,
             iat_std=0.0001, syn_ratio=0.95, ack_ratio=0.05, fin_ratio=0.0, avg_packet_size=60),
        # High-bandwidth flood
        dict(packet_rate=800, byte_rate=1120000, duration=0.8, iat_mean=0.00125,
             iat_std=0.0002, syn_ratio=0.02, ack_ratio=0.03, fin_ratio=0.0, avg_packet_size=1400),
    ]

    for i, flow_feat in enumerate(ATTACK_FLOWS):
        score, is_anomaly = ml.predict(flow_feat)
        ok = bool(is_anomaly)
        check(f"Attack flow {i+1} classified as ANOMALY (score={score:.4f})", ok)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Test AttackClassifier — heuristic rules
# ─────────────────────────────────────────────────────────────────────────────
def test_attack_classifier_heuristics():
    print(f"\n{INFO} === Test 4: AttackClassifier Heuristic Rules ===")
    from firewall_engine.attack_classifier import AttackClassifier

    clf = AttackClassifier()
    now = time.time()

    def make_flow(src_ip, protocol, pkt_count, total_bytes, start_offset, dst_port=80, failed=0):
        return {
            "src_ip":             src_ip,
            "dst_port":           dst_port,
            "packet_count":       pkt_count,
            "total_bytes":        total_bytes,
            "failed_connections": failed,
            "protocol":           protocol,
            "start_time":         now - start_offset,
            "last_seen":          now,
        }

    # DoS: >200 pkt/s sustained
    dos_flow = make_flow("10.0.0.1", "TCP", 2000, 120000, 5)  # 400 pkt/s
    result = clf.classify(dos_flow)
    check("DoS detected by heuristic", result == "DoS", f"got: {result}")

    # Port scan: >15 unique ports — send multiple flows from same IP
    clf2 = AttackClassifier()
    for port in range(1, 25):  # 24 unique ports
        flow = make_flow("10.0.0.2", "TCP", 1, 60, 0.1, dst_port=port)
        result = clf2.classify(flow)
    check("Port Scan detected after 24 unique ports", result == "Port Scan", f"got: {result}")

    # UDP flood: >500KB/s
    clf3 = AttackClassifier()
    udp_flow = make_flow("10.0.0.3", "UDP", 500, 700000, 1)  # 700 KB/s
    result = clf3.classify(udp_flow)
    check("UDP/ICMP Flood detected", result == "UDP/ICMP Flood", f"got: {result}")

    # Normal traffic: should return "None"
    clf4 = AttackClassifier()
    norm_flow = make_flow("10.0.0.4", "TCP", 20, 14000, 5)  # 4 pkt/s, normal
    result = clf4.classify(norm_flow)
    check("Normal traffic returns None", result == "None", f"got: {result}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Test mitigation whitelist
# ─────────────────────────────────────────────────────────────────────────────
def test_mitigation_whitelist():
    print(f"\n{INFO} === Test 5: Mitigation Whitelist ===")
    from firewall_engine.mitigation import is_protected_ip

    check("127.0.0.1 is protected (loopback)", is_protected_ip("127.0.0.1"))
    check("::1 is protected (IPv6 loopback)",  is_protected_ip("::1"))
    check("192.168.1.100 is NOT protected (LAN attack source should be blockable)",
          not is_protected_ip("192.168.1.100"))
    check("10.0.0.5 is NOT protected (private range must be blockable)",
          not is_protected_ip("10.0.0.5"))
    check("8.8.8.8 is NOT protected (public IP)",      not is_protected_ip("8.8.8.8"))


# ─────────────────────────────────────────────────────────────────────────────
# 6. Test Flow representation & Feature Extraction
# ─────────────────────────────────────────────────────────────────────────────
def test_flow_representation():
    print(f"\n{INFO} === Test 6: Flow Data Structure & Feature Extraction ===")
    from firewall_engine.flow import FlowTracker

    tracker = FlowTracker(timeout=5.0)
    t0 = time.time()
    pkt1 = {
        "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
        "src_port": 54321, "dst_port": 80, "protocol": "TCP",
        "timestamp": t0, "size": 60, "flags": "S"
    }
    pkt2 = {
        "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1",
        "src_port": 54321, "dst_port": 80, "protocol": "TCP",
        "timestamp": t0 + 0.1, "size": 1400, "flags": "A"
    }
    tracker.update_flow(pkt1)
    tracker.update_flow(pkt2)

    key = tracker._make_key(pkt1)
    flow = tracker.flows.get(key)
    check("Flow tracked in dictionary", flow is not None)
    check("Flow tracked packet_count", flow["packet_count"] == 2)
    check("Flow tracked total_bytes", flow["total_bytes"] == 1460)
    check("Flow tracked syn_count", flow["syn_count"] == 1)
    check("Flow tracked ack_count", flow["ack_count"] == 1)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Test Backend REST API Endpoints
# ─────────────────────────────────────────────────────────────────────────────
def test_backend_api_endpoints():
    print(f"\n{INFO} === Test 7: Backend Flask REST Endpoints ===")
    from backend.app import app

    client = app.test_client()

    routes_to_test = [
        ("/", 200),
        ("/api/status", 200),
        ("/api/stats", 200),
        ("/api/logs", 200),
        ("/api/threats", 200),
        ("/api/ml-metrics", 200),
        ("/api/confusion-matrix", 200),
        ("/api/roc-curve", 200),
        ("/api/feature-importance", 200),
        ("/api/anomaly-distribution", 200),
        ("/api/firewall-rules", [200, 403]),
    ]

    for route, expected in routes_to_test:
        resp = client.get(route)
        allowed = [expected] if isinstance(expected, int) else expected
        check(f"Endpoint GET {route} returned expected status", resp.status_code in allowed, f"status: {resp.status_code}")


# ─────────────────────────────────────────────────────────────────────────────
# Standalone CLI execution entrypoint
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_funcs = [
        test_ml_engine_loading,
        test_ml_detection_normal_traffic,
        test_ml_detection_attack_traffic,
        test_attack_classifier_heuristics,
        test_mitigation_whitelist,
        test_flow_representation,
        test_backend_api_endpoints,
    ]

    for fn in test_funcs:
        try:
            fn()
        except AssertionError:
            pass

    print("\n" + "="*60)
    passed = sum(1 for _, ok in results if ok)
    total  = len(results)
    pct    = passed / total * 100 if total else 0

    print(f"  Result: {passed}/{total} tests passed ({pct:.0f}%)")
    if passed == total:
        print(f"  {PASS} All tests passed! Firewall detection logic is working correctly.")
    else:
        failed = [(n, ok) for n, ok in results if not ok]
        print(f"  {FAIL} {len(failed)} test(s) failed:")
        for name, _ in failed:
            print(f"       - {name}")
    print("="*60 + "\n")

    sys.exit(0 if passed == total else 1)

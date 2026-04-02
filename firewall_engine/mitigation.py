import subprocess
import logging
import time
import threading
import ipaddress
import os
import json

logger = logging.getLogger("Mitigation")

# Only protect true loopback — RFC-1918 private IPs (10.x, 192.168.x, 172.16.x)
# are intentionally NOT protected so LAN/VM attack simulations can be blocked.
_ALWAYS_ALLOW = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback only
    ipaddress.ip_network("::1/128"),
]

def is_protected_ip(ip_str):
    try:
        ip_addr = ipaddress.ip_address(ip_str)
        return any(ip_addr in net for net in _ALWAYS_ALLOW)
    except ValueError:
        return True

class Mitigation:
    def __init__(self, block_duration=300):
        self.block_duration = block_duration
        self.blocked_ips = {}  # ip -> expiry_time
        self._lock = threading.Lock()
        
        # Paths
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.blocked_log = os.path.join(self.root_dir, "logs", "blocked_ips.json")
        os.makedirs(os.path.dirname(self.blocked_log), exist_ok=True)
        
        # Start unblocker thread
        self.unblocker_thread = threading.Thread(target=self._unblocker_loop, daemon=True)
        self.unblocker_thread.start()

    def block_ip(self, ip, score, threshold, attack_type):
        if is_protected_ip(ip):
            logger.info(f"[SKIP] Protected IP: {ip}")
            return False

        with self._lock:
            if ip in self.blocked_ips:
                # Update expiry if already blocked
                self.blocked_ips[ip] = time.time() + self.block_duration
                return True

            logger.info(f"[DECISION] IP: {ip}, score: {score:.4f}, threshold: {threshold:.4f}, action: BLOCK (Type: {attack_type})")
            
            # Use -I to insert at top priority
            # Add duplicate protection implicitly by checking our own map first
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                self.blocked_ips[ip] = time.time() + self.block_duration
                logger.info(f"[IPTABLES] Blocked {ip} for {self.block_duration}s")
                self._log_blocked(ip, attack_type, score)
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to block {ip}: {e.stderr.decode()}")
                return False

    def _log_blocked(self, ip, attack_type, score):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ip": ip,
            "attack_type": attack_type,
            "confidence": round(float(score), 4) # Fix: using score as confidence for now
        }
        try:
            with open(self.blocked_log, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write blocked log: {e}")

    def unblock_ip(self, ip):
        with self._lock:
            if ip in self.blocked_ips:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                try:
                    subprocess.run(cmd, check=True, capture_output=True)
                    del self.blocked_ips[ip]
                    logger.info(f"[IPTABLES] Unblocked {ip}")
                    return True
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to unblock {ip}: {e.stderr.decode()}")
                    # Still remove from our list to prevent infinite retries if rule is gone
                    del self.blocked_ips[ip]
                    return False
        return False

    def _unblocker_loop(self):
        while True:
            time.sleep(10)
            now = time.time()
            to_unblock = []
            with self._lock:
                for ip, expiry in self.blocked_ips.items():
                    if now >= expiry:
                        to_unblock.append(ip)
            
            for ip in to_unblock:
                self.unblock_ip(ip)

    def setup_nfqueue(self, queue_num):
        # Insert NFQUEUE rule at the very top (before any DROP rules)
        # Wait, if we insert DROP rules at 1, we should insert NFQUEUE at 1 too?
        # Actually, if we insert NFQUEUE at 1, then DROP at 1, the DROP will be before NFQUEUE.
        # Requirements say: "Ensure rules are inserted at top priority".
        # If we want the DROP to take effect, it must be ABOVE the NFQUEUE rule.
        # But if the packet is already in NFQUEUE, the kernel doesn't process other rules for it yet.
        # The prompt says: "Ensure NFQUEUE callback uses: if attack_detected: packet.drop() else: packet.accept()"
        # This implies the callback ITSELF does the dropping for the CURRENT packet.
        # The iptables DROP rule is for FUTURE packets from same IP.
        cmd = ["iptables", "-I", "INPUT", "1", "-j", "NFQUEUE", "--queue-num", str(queue_num)]
        subprocess.run(cmd, check=True)
        logger.info(f"[IPTABLES] NFQUEUE {queue_num} initialized at position 1")

    def cleanup(self, queue_num):
        subprocess.run(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=False)
        with self._lock:
            for ip in list(self.blocked_ips.keys()):
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
        logger.info("[IPTABLES] Cleanup complete")

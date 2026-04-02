"""
IPTablesController — wraps iptables for IP blocking/unblocking.

Safety: private/loopback/link-local addresses are whitelisted so the
firewall cannot accidentally lock out the local gateway or itself.
"""

import ipaddress
import subprocess
import logging

logger = logging.getLogger(__name__)


# IPs/CIDRs that must never be blocked
_ALWAYS_ALLOW = [
    ipaddress.ip_network("127.0.0.0/8"),    # loopback
    ipaddress.ip_network("10.0.0.0/8"),     # private class A
    ipaddress.ip_network("172.16.0.0/12"),  # private class B
    ipaddress.ip_network("192.168.0.0/16"), # private class C
    ipaddress.ip_network("169.254.0.0/16"), # link-local
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 ULA
]


def _is_protected(ip_str: str) -> bool:
    """Return True if `ip_str` falls within a protected range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _ALWAYS_ALLOW)
    except ValueError:
        return False  # unparseable → allow blocking


class IPTablesController:
    def __init__(self):
        self.blocked_ips: set = set()

    # ------------------------------------------------------------------
    # Blocking
    # ------------------------------------------------------------------

    def block_ip(self, ip_address: str) -> bool:
        """
        Add an INPUT DROP rule for `ip_address`.
        Returns True on success, False if already blocked or protected.
        """
        if _is_protected(ip_address):
            logger.warning("Refused to block protected IP: %s", ip_address)
            return False
        if ip_address in self.blocked_ips:
            return False

        success = self._run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        if success:
            self.blocked_ips.add(ip_address)
            logger.info("Blocked IP: %s", ip_address)
        return success

    def unblock_ip(self, ip_address: str) -> bool:
        """Remove the DROP rule for `ip_address`."""
        if ip_address not in self.blocked_ips:
            # Try anyway — rule may exist from a previous run
            success = self._run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])
            return success
        success = self._run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])
        if success:
            self.blocked_ips.discard(ip_address)
            logger.info("Unblocked IP: %s", ip_address)
        return success

    # ------------------------------------------------------------------
    # NFQUEUE management
    # ------------------------------------------------------------------

    def setup_nfqueue(self, queue_num: int = 0) -> bool:
        """
        Insert the NFQUEUE rule at the top of INPUT so ALL packets are
        intercepted before any DROP rules apply.
        """
        success = self._run([
            "iptables", "-I", "INPUT", "1",
            "-j", "NFQUEUE", "--queue-num", str(queue_num)
        ])
        if success:
            logger.info("NFQUEUE rule inserted (queue %d).", queue_num)
        return success

    def remove_nfqueue(self, queue_num: int = 0) -> bool:
        """Remove the NFQUEUE rule (cleanup on shutdown)."""
        success = self._run([
            "iptables", "-D", "INPUT",
            "-j", "NFQUEUE", "--queue-num", str(queue_num)
        ])
        if success:
            logger.info("NFQUEUE rule removed.")
        return success

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run(cmd: list) -> bool:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("iptables error: %s | stderr: %s", exc, exc.stderr.decode().strip())
            return False
        except FileNotFoundError:
            logger.error("iptables binary not found — is iptables installed?")
            return False

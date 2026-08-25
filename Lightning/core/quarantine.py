"""
=============================================================================
                  LIGHTNING - DYNAMIC QUARANTINE & WHITELIST MANAGER
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import time
import threading
from typing import Dict, Set, List

class QuarantineManager:
    """Manages active IP bans, dynamic quarantine durations, and whitelists."""
    def __init__(self, default_ban_duration: int = 300):
        self.default_ban_duration = default_ban_duration
        self.banned_ips: Dict[str, dict] = {}
        self.whitelisted_ips: Set[str] = {"127.0.0.1", "::1", "localhost"}
        self.lock = threading.Lock()

    def add_whitelist(self, ip: str):
        with self.lock:
            self.whitelisted_ips.add(ip.strip())

    def is_whitelisted(self, ip: str) -> bool:
        with self.lock:
            return ip in self.whitelisted_ips

    def ban_ip(self, ip: str, reason: str = "Malicious Exploit", duration: int = None):
        if self.is_whitelisted(ip):
            return
        
        dur = duration if duration is not None else self.default_ban_duration
        now = time.time()
        with self.lock:
            self.banned_ips[ip] = {
                "banned_at": now,
                "expires_at": now + dur,
                "reason": reason,
                "duration": dur
            }

    def unban_ip(self, ip: str) -> bool:
        with self.lock:
            if ip in self.banned_ips:
                del self.banned_ips[ip]
                return True
        return False

    def is_banned(self, ip: str) -> bool:
        if self.is_whitelisted(ip):
            return False

        now = time.time()
        with self.lock:
            if ip in self.banned_ips:
                if now < self.banned_ips[ip]["expires_at"]:
                    return True
                else:
                    del self.banned_ips[ip]
        return False

    def get_quarantine_list(self) -> List[dict]:
        """Returns a snapshot of all currently quarantined IPs."""
        now = time.time()
        active = []
        with self.lock:
            # Clean expired
            expired = [ip for ip, data in self.banned_ips.items() if now >= data["expires_at"]]
            for ip in expired:
                del self.banned_ips[ip]

            for ip, data in self.banned_ips.items():
                active.append({
                    "ip": ip,
                    "reason": data["reason"],
                    "remaining_seconds": max(0, int(data["expires_at"] - now)),
                    "total_duration": data["duration"]
                })
        return active

"""
=============================================================================
                  LIGHTNING - AUTOMATED THREAT INTELLIGENCE FEEDS
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
Pulls live malicious IP blocklists from public threat intelligence sources
and cross-references incoming traffic against known bad actors.
"""

import os
import sys
import time
import json
import threading
import urllib.request
from typing import Set, Dict, List, Optional

from banner import Colors

# Public, free-to-use threat intelligence feed URLs
THREAT_FEED_SOURCES = {
    "FireHOL Level 1 (Worst IPs)": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "Emerging Threats Compromised IPs": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Blocklist.de All Attackers": "https://lists.blocklist.de/lists/all.txt",
    "CI Army Badguys": "https://cinsscore.com/list/ci-badguys.txt",
    "Stamparm Malicious IPs (Daily)": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
}


class ThreatIntelligenceFeedManager:
    """
    Downloads and manages live IP blocklists from multiple public threat
    intelligence sources. Thread-safe and auto-refreshing.
    """

    def __init__(self, persistence=None, refresh_interval_hours: int = 6):
        self.persistence = persistence
        self.refresh_interval = refresh_interval_hours * 3600
        self.malicious_ips: Set[str] = set()
        self._lock = threading.Lock()
        self.last_refresh_time = 0
        self.feed_stats: Dict[str, int] = {}
        self.total_loaded = 0

    def _fetch_feed(self, name: str, url: str) -> Set[str]:
        """Downloads a single threat feed and extracts IP addresses."""
        ips = set()
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Lightning-ThreatIntel/3.0 (NEXO-TECH BY ALEXANDER)"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read(5 * 1024 * 1024).decode("utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    # Extract just the IP (some feeds have extra columns)
                    parts = line.split()
                    candidate = parts[0] if parts else ""
                    # Basic IPv4 validation
                    octets = candidate.split(".")
                    if len(octets) == 4:
                        try:
                            if all(0 <= int(o) <= 255 for o in octets):
                                ips.add(candidate)
                        except ValueError:
                            continue
        except Exception:
            pass
        return ips

    def refresh_all_feeds(self):
        """Downloads all threat intelligence feeds and merges results."""
        C = Colors
        new_ips: Set[str] = set()
        self.feed_stats = {}

        print(f"\n{C.CYAN}{C.BOLD}[*] LIGHTNING Threat Intelligence Feed Refresh Starting...{C.RESET}")
        print(f"{C.PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")

        for name, url in THREAT_FEED_SOURCES.items():
            try:
                feed_ips = self._fetch_feed(name, url)
                count = len(feed_ips)
                self.feed_stats[name] = count
                new_ips.update(feed_ips)
                status = f"{C.GREEN}✔ {count:>6} IPs" if count > 0 else f"{C.YELLOW}⚠ Failed"
                print(f"{C.WHITE}  [{status}{C.WHITE}] {C.CYAN}{name}{C.RESET}")
            except Exception:
                self.feed_stats[name] = 0
                print(f"{C.WHITE}  [{C.RED}✖ Failed{C.WHITE}] {C.CYAN}{name}{C.RESET}")

        # Remove private/localhost ranges from blocklist
        safe_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
        new_ips -= safe_ips
        new_ips = {ip for ip in new_ips if not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.")}

        with self._lock:
            self.malicious_ips = new_ips
            self.total_loaded = len(new_ips)
            self.last_refresh_time = time.time()

        # Persist to SQLite if available
        if self.persistence:
            for ip in list(new_ips)[:10000]:  # Cap at 10k for DB performance
                try:
                    self.persistence.store_threat_intel_ip(
                        ip=ip, source="aggregated_feeds",
                        threat_type="malicious", confidence=75, ttl_hours=24
                    )
                except Exception:
                    break

        print(f"{C.PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
        print(f"{C.GREEN}{C.BOLD}✔ Threat Intel Loaded: {self.total_loaded:,} known malicious IPs from {len(self.feed_stats)} feeds{C.RESET}")
        print(f"{C.DARK_GRAY}  Next refresh in {self.refresh_interval // 3600} hours{C.RESET}\n")

    def is_known_malicious(self, ip: str) -> bool:
        """Checks if an IP is in the threat intelligence blocklist."""
        with self._lock:
            if ip in self.malicious_ips:
                return True

        # Also check SQLite persistence if available
        if self.persistence:
            try:
                result = self.persistence.is_known_threat_ip(ip)
                return result is not None
            except Exception:
                pass

        return False

    def get_feed_summary(self) -> Dict:
        """Returns a summary of loaded threat intelligence data."""
        return {
            "total_malicious_ips": self.total_loaded,
            "feeds": self.feed_stats,
            "last_refresh": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_refresh_time)) if self.last_refresh_time > 0 else "Never",
            "next_refresh_in": max(0, int(self.refresh_interval - (time.time() - self.last_refresh_time)))
        }

    def start_auto_refresh_loop(self):
        """Runs the feed refresh in a background daemon thread."""
        def _loop():
            while True:
                try:
                    self.refresh_all_feeds()
                except Exception:
                    pass
                time.sleep(self.refresh_interval)

        t = threading.Thread(target=_loop, daemon=True, name="ThreatIntel-Refresh")
        t.start()

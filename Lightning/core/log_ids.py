"""
=============================================================================
                  LIGHTNING - LOG WATCHER & INTRUSION DETECTION (IDS)
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import re
from typing import Optional

from banner import Colors
from core.rules import inspect_text, inspect_user_agent
from core.notifier import SecurityNotifier

# Regex to parse Common Log Format / Combined Log Format (Apache, Nginx, LiteSpeed, Caddy)
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s*(?P<proto>[^"]*)"\s+(?P<status>\d+)\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


class LogWatcherIDS:
    """Tails web server access logs in real time and detects malicious activities."""
    def __init__(self, log_path: str, notifier: SecurityNotifier):
        self.log_path = log_path
        self.notifier = notifier
        self.fuzz_tracker = {}

    def parse_and_inspect_line(self, line: str):
        """Inspects a single log entry against threat intelligence rules."""
        match = LOG_PATTERN.search(line)
        if not match:
            # Fallback simple search
            threat = inspect_text(line)
            if threat:
                cat, desc, sev, snip = threat
                self.notifier.alert_threat(
                    ip="UNKNOWN",
                    method="LOG_ENTRY",
                    path="access.log",
                    category=cat,
                    description=desc,
                    severity=sev,
                    snippet=snip,
                    action="LOGGED & FLAGGED"
                )
            return

        data = match.groupdict()
        ip = data.get("ip", "127.0.0.1")
        method = data.get("method", "GET")
        path = data.get("path", "/")
        status = int(data.get("status", 200))
        ua = data.get("ua", "")

        # 1. Check URI / Query for exploits
        threat = inspect_text(path)
        if threat:
            cat, desc, sev, snip = threat
            self.notifier.alert_threat(
                ip=ip,
                method=method,
                path=path,
                category=cat,
                description=desc,
                severity=sev,
                snippet=snip,
                action="FLAGGED BY IDS"
            )
            return

        # 2. Check User-Agent
        if ua:
            ua_threat = inspect_user_agent(ua)
            if ua_threat:
                cat, desc, sev, snip = ua_threat
                self.notifier.alert_threat(
                    ip=ip,
                    method=method,
                    path=path,
                    category=cat,
                    description=desc,
                    severity=sev,
                    snippet=snip,
                    action="FLAGGED BY IDS"
                )
                return

        # 3. Track 404 Directory Fuzzing Bursts
        if status == 404:
            now = time.time()
            timestamps = self.fuzz_tracker.get(ip, [])
            timestamps = [t for t in timestamps if now - t < 15]
            timestamps.append(now)
            self.fuzz_tracker[ip] = timestamps

            if len(timestamps) >= 10:
                self.notifier.alert_threat(
                    ip=ip,
                    method=method,
                    path=path,
                    category="Directory Fuzzing / Brute-Force",
                    description=f"{len(timestamps)} consecutive 404 errors in 15 seconds",
                    severity="HIGH",
                    snippet=f"Target path: {path}",
                    action="FLAGGED SCANNER ACTIVITY"
                )
                self.fuzz_tracker[ip] = []

    def start_tailing(self):
        """Continuously tails and inspects the log file."""
        C = Colors
        if not os.path.exists(self.log_path):
            print(f"{C.RED}[!] Log file not found: {self.log_path}{C.RESET}")
            print(f"{C.YELLOW}[*] Creating an empty log file to start monitoring...{C.RESET}")
            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write("# LIGHTNING Security Log Watcher - Initialized\n")

        print(f"\n{C.GREEN}{C.BOLD}⚡ LIGHTNING REAL-TIME LOG IDS ACTIVE ⚡{C.RESET}")
        print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
        print(f"{C.WHITE}  • Watching Log File    : {C.YELLOW}{self.log_path}{C.RESET}")
        print(f"{C.WHITE}  • Threat Rules         : {C.PURPLE}SQLi, XSS, RCE, LFI, Scanners, 404 Fuzzing{C.RESET}")
        print(f"{C.WHITE}  • Created By           : {C.GREEN}{C.BOLD}NEXO-TECH BY ALEXANDER{C.RESET}")
        print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")

        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            # Go to end of file
            f.seek(0, os.SEEK_END)
            try:
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.parse_and_inspect_line(line)
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}[*] Pausing Log IDS Watcher...{C.RESET}")

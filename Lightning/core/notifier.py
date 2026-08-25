"""
=============================================================================
                  LIGHTNING - REAL-TIME NOTIFICATION & ALERT ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import datetime
import threading
import json
import urllib.request
from typing import Optional

# Ensure UTF-8 console output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from banner import Colors

# Audio alert support
def trigger_audio_alert(severity: str = "HIGH"):
    """Plays an alert beep based on severity if sound is enabled."""
    def _play():
        try:
            if sys.platform == "win32":
                import winsound
                if severity == "CRITICAL":
                    winsound.Beep(1200, 150)
                    time.sleep(0.05)
                    winsound.Beep(1800, 250)
                elif severity == "HIGH":
                    winsound.Beep(1000, 180)
                else:
                    winsound.Beep(750, 100)
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()
        except Exception:
            pass

    threading.Thread(target=_play, daemon=True).start()


class ThreatStats:
    """Thread-safe statistics aggregator for security metrics."""
    def __init__(self):
        self.lock = threading.Lock()
        self.total_requests = 0
        self.total_blocked = 0
        self.total_warnings = 0
        self.attacks_by_category = {}
        self.attacker_ips = {}
        self.start_time = time.time()

    def record_attack(self, ip: str, category: str, blocked: bool = True):
        with self.lock:
            self.total_requests += 1
            if blocked:
                self.total_blocked += 1
            else:
                self.total_warnings += 1
            
            self.attacks_by_category[category] = self.attacks_by_category.get(category, 0) + 1
            self.attacker_ips[ip] = self.attacker_ips.get(ip, 0) + 1

    def record_clean(self):
        with self.lock:
            self.total_requests += 1

    def get_summary(self):
        with self.lock:
            elapsed = int(time.time() - self.start_time)
            hours, rem = divmod(elapsed, 3600)
            mins, secs = divmod(rem, 60)
            uptime_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
            return {
                "uptime": uptime_str,
                "total": self.total_requests,
                "blocked": self.total_blocked,
                "warnings": self.total_warnings,
                "top_attackers": sorted(self.attacker_ips.items(), key=lambda x: x[1], reverse=True)[:5],
                "categories": self.attacks_by_category
            }


class SecurityNotifier:
    """Handles terminal outputs, colored alert boxes, disk logging, webhooks, and Web SOC feed."""
    def __init__(self, 
                 log_file: str = "lightning_security.log", 
                 sound_enabled: bool = True,
                 webhook_url: Optional[str] = None):
        self.log_file = log_file
        self.sound_enabled = sound_enabled
        self.webhook_url = webhook_url
        self.stats = ThreatStats()
        self._print_lock = threading.Lock()

    def _log_to_file(self, text: str):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass

    def _dispatch_webhook(self, payload_dict: dict):
        """Asynchronously dispatches a webhook notification (Discord/Slack/Custom)."""
        if not self.webhook_url:
            return

        def _send():
            try:
                data = json.dumps(payload_dict).encode("utf-8")
                req = urllib.request.Request(
                    self.webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json", "User-Agent": "Lightning-Notifier/2.5"}
                )
                urllib.request.urlopen(req, timeout=4)
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True).start()

    def alert_threat(self, ip: str, method: str, path: str, category: str, description: str, severity: str, snippet: str, action: str = "BLOCKED (403 Forbidden)"):
        """Displays an eye-catching, high-contrast security threat alert in terminal and updates Web SOC."""
        C = Colors
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.stats.record_attack(ip, category, blocked="BLOCKED" in action.upper() or "FLAGGED" in action.upper())

        # Update Web SOC Live Stream
        try:
            from core.soc_dashboard import SOCHandler
            SOCHandler.record_event(ip=ip, method=method, path=path, category=category, action=action)
        except Exception:
            pass

        # Record to SQLite Persistence
        try:
            from core.persistence import PersistenceEngine
            pe = PersistenceEngine()
            pe.record_threat(
                ip=ip, method=method, path=path,
                category=category, description=description,
                severity=severity, snippet=snippet, action=action
            )
        except Exception:
            pass

        # Determine color palette based on severity
        if severity == "CRITICAL":
            badge_color = f"{C.BG_RED}{C.WHITE}{C.BOLD}"
            border_color = C.RED
            title_tag = "⚡ [CRITICAL SECURITY THREAT DETECTED] ⚡"
        elif severity == "HIGH":
            badge_color = f"{C.RED}{C.BOLD}"
            border_color = C.RED
            title_tag = "⚠️  [HIGH-RISK ATTACK INTERCEPTED] ⚠️"
        elif severity == "MEDIUM":
            badge_color = f"{C.YELLOW}{C.BOLD}"
            border_color = C.YELLOW
            title_tag = "🔔 [SUSPICIOUS ACTIVITY FLAGGED] 🔔"
        else:
            badge_color = f"{C.BLUE}{C.BOLD}"
            border_color = C.BLUE
            title_tag = "ℹ️  [SECURITY EVENT DETECTED] ℹ️"

        # Audio cue
        if self.sound_enabled:
            trigger_audio_alert(severity)

        # Truncate snippet for clean display
        safe_snippet = snippet.replace("\r", " ").replace("\n", " ")
        if len(safe_snippet) > 75:
            safe_snippet = safe_snippet[:72] + "..."

        with self._print_lock:
            print(f"\n{border_color}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
            print(f"{border_color}┃ {badge_color} {title_tag.center(68)} {C.RESET}{border_color} ┃{C.RESET}")
            print(f"{border_color}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}TIMESTAMP  :{C.RESET} {C.WHITE}{now_str:<55}{border_color}┃{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}ATTACKER IP:{C.RESET} {C.YELLOW}{C.BOLD}{ip:<55}{border_color}┃{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}HTTP TARGET:{C.RESET} {C.CYAN}{method} {path[:50]:<48}{border_color}┃{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}CATEGORY   :{C.RESET} {C.PURPLE}{C.BOLD}{category:<55}{border_color}┃{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}TRIGGER    :{C.RESET} {C.WHITE}{description:<55}{border_color}┃{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}PAYLOAD    :{C.RESET} {C.RED}{safe_snippet:<55}{border_color}┃{C.RESET}")
            print(f"{border_color}┃ {C.DARK_GRAY}ACTION     :{C.RESET} {C.GREEN}{C.BOLD}{action:<55}{border_color}┃{C.RESET}")
            print(f"{border_color}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

        # Write clean audit log
        log_entry = f"[{now_str}] [{severity}] [{ip}] [{method} {path}] [{category} - {description}] PAYLOAD: {snippet} -> {action}"
        self._log_to_file(log_entry)

        # Webhook Notification
        self._dispatch_webhook({
            "content": f"⚡ **LIGHTNING Security Alert** [{severity}]\n**Target:** `{method} {path}`\n**Attacker IP:** `{ip}`\n**Threat:** `{category} - {description}`\n**Action:** `{action}`"
        })

    def alert_rate_limit(self, ip: str, req_count: int, window_sec: int):
        """Alerts when an IP triggers the DDoS / Rate Limit threshold."""
        C = Colors
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.stats.record_attack(ip, "Rate Limiting / DoS Flood", blocked=True)

        try:
            from core.soc_dashboard import SOCHandler
            SOCHandler.record_event(ip=ip, method="BURST_FLOOD", path="/", category="Anti-DDoS Rate Limit", action="IP BANNED (429)")
        except Exception:
            pass

        if self.sound_enabled:
            trigger_audio_alert("HIGH")

        with self._print_lock:
            print(f"\n{C.RED}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
            print(f"{C.RED}┃ {C.BG_RED}{C.WHITE}{C.BOLD}        ⛔ [RATE LIMIT EXCEEDED - IP TEMPORARILY BANNED] ⛔        {C.RESET}{C.RED} ┃{C.RESET}")
            print(f"{C.RED}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
            print(f"{C.RED}┃ {C.DARK_GRAY}TIMESTAMP  :{C.RESET} {C.WHITE}{now_str:<55}{C.RED}┃{C.RESET}")
            print(f"{C.RED}┃ {C.DARK_GRAY}ATTACKER IP:{C.RESET} {C.YELLOW}{C.BOLD}{ip:<55}{C.RED}┃{C.RESET}")
            print(f"{C.RED}┃ {C.DARK_GRAY}BURST RATE :{C.RESET} {C.RED}{req_count} requests in {window_sec}s (Flooding threshold breached){' ' * (22 - len(str(req_count)))}{C.RED}┃{C.RESET}")
            print(f"{C.RED}┃ {C.DARK_GRAY}ACTION     :{C.RESET} {C.RED}{C.BOLD}BANNED & DROPPED (HTTP 429 Too Many Requests){' ' * 10}{C.RED}┃{C.RESET}")
            print(f"{C.RED}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

        self._log_to_file(f"[{now_str}] [RATE_LIMIT] [{ip}] Flooded {req_count} reqs in {window_sec}s -> BANNED")

    def alert_integrity_issue(self, title: str, details: str, severity: str = "HIGH"):
        """Alerts for website defacement, SSL expiration, or sensitive file exposure."""
        C = Colors
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.sound_enabled and severity in ("CRITICAL", "HIGH"):
            trigger_audio_alert(severity)

        color = C.RED if severity in ("CRITICAL", "HIGH") else C.YELLOW

        with self._print_lock:
            print(f"\n{color}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
            print(f"{color}┃ {C.BOLD}⚠️  INTEGRITY ALERT: {title[:48]:<48} ┃{C.RESET}")
            print(f"{color}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
            print(f"{color}┃ {C.DARK_GRAY}TIMESTAMP:{C.RESET} {C.WHITE}{now_str:<57}{color}┃{C.RESET}")
            print(f"{color}┃ {C.DARK_GRAY}SEVERITY :{C.RESET} {color}{C.BOLD}{severity:<57}{color}┃{C.RESET}")
            print(f"{color}┃ {C.DARK_GRAY}DETAILS  :{C.RESET} {C.WHITE}{details[:57]:<57}{color}┃{C.RESET}")
            print(f"{color}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

        self._log_to_file(f"[{now_str}] [INTEGRITY_{severity}] {title}: {details}")

    def log_clean_traffic(self, ip: str, method: str, path: str, status_code: int = 200):
        """Displays formatted clean traffic passing through the shield."""
        C = Colors
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        self.stats.record_clean()
        with self._print_lock:
            print(f"{C.DARK_GRAY}[{now_str}]{C.RESET} {C.GREEN}✔ SECURE{C.RESET} | {C.CYAN}{ip:<15}{C.RESET} | {C.WHITE}{method:<5} {path:<40}{C.RESET} | {C.GREEN}HTTP {status_code}{C.RESET}")

    def print_live_dashboard(self):
        """Prints a real-time status summary widget."""
        C = Colors
        summary = self.stats.get_summary()
        with self._print_lock:
            print(f"\n{C.CYAN}┌─────────────── ⚡ LIGHTNING LIVE DEFENSE STATS ⚡ ───────────────┐{C.RESET}")
            print(f"{C.CYAN}│{C.RESET} Uptime: {C.WHITE}{summary['uptime']:<10}{C.RESET} │ Inspected: {C.WHITE}{summary['total']:<8}{C.RESET} │ Blocked Attacks: {C.RED}{C.BOLD}{summary['blocked']:<6}{C.RESET} {C.CYAN}│{C.RESET}")
            if summary['categories']:
                print(f"{C.CYAN}├──────────────────────────────────────────────────────────────────┤{C.RESET}")
                print(f"{C.CYAN}│ {C.YELLOW}Top Attack Vectors Caught:{C.RESET}{' ' * 40}{C.CYAN}│{C.RESET}")
                for cat, count in list(summary['categories'].items())[:4]:
                    print(f"{C.CYAN}│{C.RESET}  • {C.PURPLE}{cat:<38}{C.RESET} : {C.RED}{count:>5} blocked{C.RESET}     {C.CYAN}│{C.RESET}")
            print(f"{C.CYAN}└──────────────────────────────────────────────────────────────────┘{C.RESET}\n")

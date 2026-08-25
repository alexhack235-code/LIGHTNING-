"""
=============================================================================
                  LIGHTNING - LIVE WEBSITE SENTINEL & INTEGRITY MONITOR
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import hashlib
import ssl
import socket
import urllib.request
import urllib.parse
import datetime
from typing import Optional, Dict

from banner import Colors
from core.notifier import SecurityNotifier

SENSITIVE_ENDPOINTS = [
    "/.env",
    "/.env.local",
    "/.git/HEAD",
    "/.git/config",
    "/wp-config.php",
    "/config.json",
    "/phpinfo.php",
    "/backup.sql",
    "/backup.zip",
    "/admin.php",
    "/server-status"
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Enforces HTTPS connections and prevents SSL stripping"),
    ("Content-Security-Policy", "Restricts resource loading and mitigates XSS"),
    ("X-Frame-Options", "Prevents clickjacking attacks via iframe framing"),
    ("X-Content-Type-Options", "Prevents MIME-type sniffing vulnerabilities"),
    ("Referrer-Policy", "Controls referrer information disclosure"),
    ("Permissions-Policy", "Controls browser features and sensor permissions")
]


class WebsiteSentinel:
    """Monitors live website status, defacement, SSL certificates, and security posture."""
    def __init__(self, target_url: str, notifier: SecurityNotifier, check_interval: int = 30):
        self.target_url = target_url
        self.notifier = notifier
        self.check_interval = check_interval
        self.baseline_hash: Optional[str] = None
        self.last_status: Optional[int] = None
        self.parsed = urllib.parse.urlparse(target_url)
        self.is_https = self.parsed.scheme.lower() == "https"
        self.hostname = self.parsed.hostname or "127.0.0.1"
        self.port = self.parsed.port or (443 if self.is_https else 80)

    def check_ssl_certificate(self) -> Optional[Dict]:
        """Inspects target SSL certificate expiration and details."""
        if not self.is_https:
            return None
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    expire_str = cert.get('notAfter')
                    expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    remaining_days = (expire_date - datetime.datetime.utcnow()).days
                    
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    org_name = issuer.get('organizationName', 'Unknown CA')
                    
                    return {
                        "issuer": org_name,
                        "expire_date": expire_str,
                        "days_remaining": remaining_days
                    }
        except Exception as e:
            return {"error": str(e)}

    def check_sensitive_files(self):
        """Scans for accidentally exposed critical files."""
        C = Colors
        exposed = []
        base = self.target_url.rstrip("/")
        
        for path in SENSITIVE_ENDPOINTS:
            url = f"{base}{path}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Lightning-Security-Sentinel/2.5 (NEXO-TECH BY ALEXANDER)"}
                )
                with urllib.request.urlopen(req, timeout=4) as resp:
                    if resp.status == 200:
                        content_sample = resp.read(200).decode("utf-8", errors="ignore")
                        # Basic validation to rule out generic 200 catch-alls
                        if path.startswith("/.git") and "ref:" in content_sample:
                            exposed.append((path, "Git Repository Metadata Exposed"))
                        elif path.startswith("/.env") and ("=" in content_sample or "APP_" in content_sample or "DB_" in content_sample):
                            exposed.append((path, "Environment Secrets Exposed (.env)"))
                        elif "phpinfo" in path and "PHP Version" in content_sample:
                            exposed.append((path, "PHPInfo Configuration Leak"))
                        elif resp.status == 200 and len(content_sample) > 0:
                            exposed.append((path, f"Exposed Endpoint (HTTP 200)"))
            except Exception:
                pass

        for path, reason in exposed:
            self.notifier.alert_threat(
                ip=self.hostname,
                method="INTEGRITY_SCAN",
                path=path,
                category="Information Disclosure",
                description=reason,
                severity="CRITICAL",
                snippet=f"Sensitive endpoint publicly accessible at {base}{path}",
                action="URGENT: Block access to this path immediately"
            )

    def run_single_check(self) -> Dict:
        """Performs a comprehensive integrity and health check."""
        results = {
            "status": None,
            "latency_ms": 0,
            "hash": None,
            "tampered": False,
            "ssl": None,
            "missing_headers": []
        }

        # 1. Fetch live page
        start_t = time.time()
        try:
            req = urllib.request.Request(
                self.target_url,
                headers={"User-Agent": "Lightning-Sentinel/2.5 (NEXO-TECH BY ALEXANDER)"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                latency = int((time.time() - start_t) * 1000)
                body = resp.read()
                results["status"] = resp.status
                results["latency_ms"] = latency
                
                # Compute content checksum
                cur_hash = hashlib.sha256(body).hexdigest()
                results["hash"] = cur_hash

                if self.baseline_hash is None:
                    self.baseline_hash = cur_hash
                elif cur_hash != self.baseline_hash:
                    results["tampered"] = True
                    self.notifier.alert_integrity_issue(
                        title="Website Content Changed / Possible Defacement",
                        details=f"SHA256 Hash changed from {self.baseline_hash[:12]}... to {cur_hash[:12]}...",
                        severity="HIGH"
                    )

                # Check security headers
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                for h_name, desc in SECURITY_HEADERS:
                    if h_name.lower() not in resp_headers:
                        results["missing_headers"].append((h_name, desc))

        except urllib.error.HTTPError as e:
            results["status"] = e.code
            results["latency_ms"] = int((time.time() - start_t) * 1000)
        except Exception as e:
            results["error"] = str(e)
            self.notifier.alert_integrity_issue(
                title="Website Down or Unreachable",
                details=f"Failed to connect to {self.target_url}: {str(e)}",
                severity="CRITICAL"
            )

        # 2. SSL Check
        if self.is_https:
            ssl_info = self.check_ssl_certificate()
            results["ssl"] = ssl_info
            if ssl_info and "days_remaining" in ssl_info:
                if ssl_info["days_remaining"] < 15:
                    self.notifier.alert_integrity_issue(
                        title="SSL Certificate Expiring Soon",
                        details=f"Cert expires in {ssl_info['days_remaining']} days ({ssl_info['expire_date']})",
                        severity="HIGH"
                    )

        return results

    def start_monitoring_loop(self):
        """Runs the continuous sentinel monitoring loop."""
        C = Colors
        print(f"\n{C.GREEN}{C.BOLD}⚡ LIGHTNING LIVE WEBSITE SENTINEL ACTIVE ⚡{C.RESET}")
        print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
        print(f"{C.WHITE}  • Target Website       : {C.YELLOW}{self.target_url}{C.RESET}")
        print(f"{C.WHITE}  • Sentinel Host        : {C.CYAN}{self.hostname}:{self.port}{C.RESET}")
        print(f"{C.WHITE}  • Interval             : {C.WHITE}Every {self.check_interval} seconds{C.RESET}")
        print(f"{C.WHITE}  • Defacement Shield    : {C.GREEN}ACTIVE (SHA-256 DOM Integrity){C.RESET}")
        print(f"{C.WHITE}  • Created By           : {C.GREEN}{C.BOLD}NEXO-TECH BY ALEXANDER{C.RESET}")
        print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")

        # Initial sensitive file leak check
        print(f"{C.CYAN}[*] Running initial sensitive file leak scan...{C.RESET}")
        self.check_sensitive_files()
        print(f"{C.GREEN}[+] Initial reconnaissance scan complete.{C.RESET}\n")

        check_count = 0
        try:
            while True:
                check_count += 1
                res = self.run_single_check()
                now_str = datetime.datetime.now().strftime("%H:%M:%S")

                if res.get("status") == 200:
                    status_badge = f"{C.BG_GREEN}{C.BLACK}{C.BOLD} ONLINE (200) {C.RESET}"
                elif res.get("status"):
                    status_badge = f"{C.BG_YELLOW}{C.BLACK}{C.BOLD} HTTP {res['status']} {C.RESET}"
                else:
                    status_badge = f"{C.BG_RED}{C.WHITE}{C.BOLD} OFFLINE {C.RESET}"

                tamper_status = f"{C.RED}MODIFIED!{C.RESET}" if res.get("tampered") else f"{C.GREEN}INTACT{C.RESET}"
                latency = f"{res.get('latency_ms', 0)}ms"

                print(f"{C.DARK_GRAY}[{now_str}]{C.RESET} {status_badge} │ Latency: {C.CYAN}{latency:<7}{C.RESET} │ Integrity: {tamper_status} │ Checks: #{check_count}")

                # Periodically re-check sensitive files every 20 loops
                if check_count % 20 == 0:
                    self.check_sensitive_files()

                time.sleep(self.check_interval)

        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[*] Pausing Live Website Sentinel...{C.RESET}")

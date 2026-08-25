"""
=============================================================================
                  LIGHTNING - ACTIVE WAF & MULTI-LAYER REVERSE PROXY SHIELD
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import socket
import urllib.parse
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Dict, Set, Optional

from banner import Colors
from core.rules import inspect_text, inspect_user_agent
from core.notifier import SecurityNotifier
from core.api_shield import APIShield
from core.dlp import DataLossPreventionEngine
from core.honeypot import HoneypotEngine
from core.anti_bot import AntiBotArmor, COOKIE_NAME
from core.malware_scanner import MalwareUploadScanner
from core.virtual_patching import VirtualPatchingEngine
from core.geo_intelligence import GeoIntelligence
from core.heuristic_scorer import BehavioralScorer
from core.quarantine import QuarantineManager

BLOCKED_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden - Intercepted by LIGHTNING</title>
    <style>
        body {{
            background-color: #0b0f17;
            color: #c9d1d9;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            text-align: center;
            padding: 60px 20px;
            margin: 0;
        }}
        .container {{
            max-width: 650px;
            margin: 0 auto;
            background: #161e2e;
            border: 1px solid #ef4444;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(239, 68, 68, 0.2);
        }}
        h1 {{
            color: #ef4444;
            font-size: 2.2rem;
            margin-bottom: 10px;
        }}
        .badge {{
            display: inline-block;
            background: #b91c1c;
            color: #ffffff;
            font-weight: bold;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.9rem;
            letter-spacing: 1px;
            margin-bottom: 20px;
        }}
        p {{
            color: #94a3b8;
            font-size: 1.05rem;
            line-height: 1.6;
        }}
        .details {{
            background: #0b0f17;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 15px;
            margin: 25px 0;
            text-align: left;
            font-family: monospace;
            font-size: 0.95rem;
            color: #38bdf8;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 0.85rem;
            color: #10b981;
            border-top: 1px solid #334155;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="badge">⚡ THREAT DETECTED & DROPPED</div>
        <h1>403 Forbidden</h1>
        <p>Your request was intercepted and dropped by the <strong>LIGHTNING Multi-Layer Defense System</strong> because it matched an active cyber exploit signature or security policy violation.</p>
        <div class="details">
            <div><strong>Incident IP:</strong> {client_ip}</div>
            <div><strong>Threat Classification:</strong> {threat_type}</div>
            <div><strong>Target URI:</strong> {target_uri}</div>
            <div><strong>Timestamp:</strong> {timestamp}</div>
        </div>
        <p style="font-size: 0.85rem; color: #94a3b8;">If you believe this was an error, contact the server administrator with the Incident IP above.</p>
        <div class="footer">
            ⚡ Protected by <strong>LIGHTNING DEFENSE SYSTEM</strong><br>
            <em>CREATED BY NEXO-TECH BY ALEXANDER</em>
        </div>
    </div>
</body>
</html>
"""


class RateLimiter:
    """Sliding-window IP rate limiter to detect and mitigate DoS floods."""
    def __init__(self, max_requests: int = 60, time_window: int = 10, ban_duration: int = 180):
        self.max_requests = max_requests
        self.time_window = time_window
        self.ban_duration = ban_duration
        self.requests: Dict[str, list] = {}
        self.lock = threading.Lock()

    def is_allowed(self, ip: str) -> tuple[bool, int]:
        now = time.time()
        with self.lock:
            timestamps = self.requests.get(ip, [])
            timestamps = [t for t in timestamps if now - t < self.time_window]
            timestamps.append(now)
            self.requests[ip] = timestamps

            if len(timestamps) > self.max_requests:
                return False, len(timestamps)
            return True, len(timestamps)


class WAFProxyHandler(BaseHTTPRequestHandler):
    """Next-Gen Multi-Layer HTTP Request Handler."""
    backend_url: str = "http://127.0.0.1:80"
    notifier: SecurityNotifier = None
    rate_limiter: RateLimiter = None
    quarantine: QuarantineManager = None
    api_shield: Optional[APIShield] = None
    dlp_engine: Optional[DataLossPreventionEngine] = None
    honeypot: Optional[HoneypotEngine] = None
    anti_bot: Optional[AntiBotArmor] = None
    malware_scanner: Optional[MalwareUploadScanner] = None
    virtual_patch: Optional[VirtualPatchingEngine] = None
    geo_intel: Optional[GeoIntelligence] = None
    heuristic: Optional[BehavioralScorer] = None
    threat_feeds: Optional[object] = None

    def log_message(self, format, *args):
        return

    def get_client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _block_request(self, ip: str, category: str, description: str, severity: str, snippet: str):
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        if self.quarantine:
            self.quarantine.ban_ip(ip, reason=f"{category} - {description}")

        self.notifier.alert_threat(
            ip=ip,
            method=self.command,
            path=self.path,
            category=category,
            description=description,
            severity=severity,
            snippet=snippet,
            action="BLOCKED (403 Forbidden)"
        )
        
        response_body = BLOCKED_HTML_TEMPLATE.format(
            client_ip=ip,
            threat_type=f"{category} ({description})",
            target_uri=self.path,
            timestamp=now_str
        ).encode("utf-8")

        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Protected-By", "LIGHTNING by NEXO-TECH BY ALEXANDER")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(response_body)
        except Exception:
            pass

    def _serve_captcha(self, ip: str):
        """Serves the interactive Proof-of-Work / Anti-Bot challenge."""
        html_content, ans = self.anti_bot.generate_challenge(ip, self.path)
        body = html_content.encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Protected-By", "LIGHTNING Anti-Bot Shield")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def inspect_and_filter(self) -> bool:
        client_ip = self.get_client_ip()

        # Handle Anti-Bot CAPTCHA Submission Endpoint
        if self.path == "/__lightning_verify__" and self.command == "POST":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8", errors="ignore")
            params = urllib.parse.parse_qs(post_body)
            answer = params.get("answer", [""])[0]
            sig = params.get("sig", [""])[0]
            ts = params.get("ts", [""])[0]
            redirect_to = urllib.parse.unquote(params.get("redirect", ["/"])[0])

            if self.anti_bot and self.anti_bot.verify_answer(client_ip, answer, sig, ts):
                token = self.anti_bot.generate_token(client_ip)
                self.send_response(302)
                self.send_header("Set-Cookie", f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax")
                self.send_header("Location", redirect_to if redirect_to else "/")
                self.end_headers()
                return False
            else:
                self._block_request(client_ip, "Anti-Bot Verification", "Failed human verification challenge", "MEDIUM", "Incorrect CAPTCHA")
                return False

        # 1. Check Active Quarantine / Blacklist
        if self.quarantine and self.quarantine.is_banned(client_ip):
            self._block_request(client_ip, "Quarantined IP", "IP banned due to prior exploit activity", "HIGH", "Blocked Client")
            return False

        # 1b. Check Live Threat Intelligence Blocklists
        if self.threat_feeds and hasattr(self.threat_feeds, "is_known_malicious") and self.threat_feeds.is_known_malicious(client_ip):
            self._block_request(client_ip, "Threat Intelligence Match", "IP listed on global malicious actor blocklists", "CRITICAL", f"Known Bad Actor: {client_ip}")
            return False

        # 2. Check Geo-Fencing & Tor Intelligence
        if self.geo_intel:
            geo_threat = self.geo_intel.inspect_client(client_ip, self.headers)
            if geo_threat:
                desc, sev, snip = geo_threat
                self._block_request(client_ip, "Geo-Fencing & Network Policy", desc, sev, snip)
                return False

        # 3. Check Honeypot Decoy Traps
        if self.honeypot and self.honeypot.is_honeypot_hit(self.path):
            trap_name, reason = self.honeypot.trigger_trap(client_ip, self.path)
            self._block_request(client_ip, "Honeypot Decoy Breach", f"{trap_name} triggered", "CRITICAL", f"Probed trap: {self.path}")
            return False

        # 4. Anti-DDoS Rate Limit Check
        allowed, count = self.rate_limiter.is_allowed(client_ip)
        if not allowed:
            if self.quarantine:
                self.quarantine.ban_ip(client_ip, "Rate Limit DDoS Flooding", duration=180)
            self.notifier.alert_rate_limit(client_ip, count, self.rate_limiter.time_window)
            self.send_response(429)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Retry-After", "180")
            self.send_header("X-Protected-By", "LIGHTNING by NEXO-TECH BY ALEXANDER")
            self.end_headers()
            try:
                self.wfile.write(b"429 Too Many Requests - Flooding Mitigated by LIGHTNING Shield\n")
            except Exception:
                pass
            return False

        # 5. User-Agent Scanner Inspection
        user_agent = self.headers.get("User-Agent", "")
        ua_threat = inspect_user_agent(user_agent)
        if ua_threat:
            cat, desc, sev, snip = ua_threat
            self._block_request(client_ip, cat, desc, sev, snip)
            return False

        # 6. Read Request Body
        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = b""
        body_str = ""
        if 0 < content_len <= 15 * 1024 * 1024:
            body_bytes = self.rfile.read(content_len)
            self._body_data = body_bytes
            try:
                body_str = body_bytes.decode("utf-8", errors="ignore")
            except Exception:
                pass
        else:
            self._body_data = b""

        # 7. Web Shell & Malicious Upload Scanner
        if self.malware_scanner and "multipart/form-data" in self.headers.get("Content-Type", "").lower():
            malware_threat = self.malware_scanner.scan_multipart_body(body_bytes)
            if malware_threat:
                cat, desc, sev, snip = malware_threat
                self._block_request(client_ip, cat, desc, sev, snip)
                return False

        # 8. Virtual Patching & Zero-Day Exploit Check (Log4Shell, Spring4Shell, CVEs)
        if self.virtual_patch:
            cve_threat = self.virtual_patch.inspect_cve(self.path + " " + body_str)
            if cve_threat:
                cat, desc, sev, snip = cve_threat
                self._block_request(client_ip, cat, desc, sev, snip)
                return False

        # 9. API Shield (JWT alg=none, GraphQL Depth, BOLA)
        if self.api_shield:
            api_threat = self.api_shield.validate_api_request(client_ip, self.path, self.headers, body_str)
            if api_threat:
                cat, desc, sev, snip = api_threat
                self._block_request(client_ip, cat, desc, sev, snip)
                return False

        # 10. General Web Threat Rules (SQLi, NoSQL, XSS, RCE, LFI, .env)
        uri_threat = inspect_text(self.path)
        if uri_threat:
            cat, desc, sev, snip = uri_threat
            self._block_request(client_ip, cat, desc, sev, snip)
            return False

        # 11. Request Headers Threat Check
        for h_name, h_val in self.headers.items():
            if h_name.lower() in ("user-agent", "host", "authorization", "cookie"):
                continue
            h_threat = inspect_text(h_val)
            if h_threat:
                cat, desc, sev, snip = h_threat
                self._block_request(client_ip, cat, f"Header [{h_name}]: {desc}", sev, snip)
                return False

        # 12. Body Threat Check
        if body_str:
            b_threat = inspect_text(body_str)
            if b_threat:
                cat, desc, sev, snip = b_threat
                self._block_request(client_ip, cat, f"Body: {desc}", sev, snip)
                return False

        # 13. Behavioral Risk Scoring & Anti-Bot Challenge
        if self.heuristic and self.anti_bot:
            cookie_header = self.headers.get("Cookie", "")
            if not self.anti_bot.is_verified(client_ip, cookie_header):
                risk_score, reason = self.heuristic.evaluate_request(client_ip, self.command, self.path, self.headers)
                if risk_score >= 70:
                    self._block_request(client_ip, "Behavioral Anomaly Engine", f"High Risk Threat Score ({risk_score}/100) - {reason}", "HIGH", "High Risk Client")
                    return False
                elif risk_score >= 35:
                    self._serve_captcha(client_ip)
                    return False

        return True

    def _proxy_request(self):
        if not self.inspect_and_filter():
            return

        client_ip = self.get_client_ip()
        backend = self.backend_url.rstrip("/")
        path = self.path if self.path.startswith("/") else "/" + self.path
        target_url = f"{backend}{path}"

        headers = {}
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length"):
                headers[k] = v
        headers["X-Forwarded-For"] = client_ip
        headers["X-Forwarded-Proto"] = "http"

        req_body = getattr(self, "_body_data", None) or None
        
        try:
            req = urllib.request.Request(
                target_url,
                data=req_body if self.command in ("POST", "PUT", "PATCH") else None,
                headers=headers,
                method=self.command
            )
            
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_data = resp.read()
                status_code = resp.status
                resp_headers = resp.headers

                # Data Loss Prevention (DLP) Response Scrubbing
                if self.dlp_engine:
                    try:
                        resp_text = resp_data.decode("utf-8", errors="ignore")
                        sanitized_text, dlp_threat = self.dlp_engine.inspect_and_scrub(resp_text)
                        if dlp_threat:
                            cat, desc, sev, snip = dlp_threat
                            self.notifier.alert_threat(
                                ip=client_ip,
                                method=self.command,
                                path=self.path,
                                category=cat,
                                description=f"OUTBOUND DATA LEAK PREVENTED: {desc}",
                                severity=sev,
                                snippet=snip,
                                action="SCRUBBED & MASKED BY DLP"
                            )
                        resp_data = sanitized_text.encode("utf-8")
                    except Exception:
                        pass

                self.send_response(status_code)
                for h_key, h_val in resp_headers.items():
                    if h_key.lower() not in ("transfer-encoding", "content-length", "server"):
                        self.send_header(h_key, h_val)
                
                # Inject Hardening Headers
                self.send_header("X-Protected-By", "LIGHTNING by NEXO-TECH BY ALEXANDER")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                self.send_header("X-XSS-Protection", "1; mode=block")
                self.send_header("Content-Length", str(len(resp_data)))
                self.end_headers()
                self.wfile.write(resp_data)
                
                self.notifier.log_clean_traffic(client_ip, self.command, self.path, status_code)

        except urllib.error.HTTPError as e:
            err_data = e.read()
            self.send_response(e.code)
            for h_key, h_val in e.headers.items():
                if h_key.lower() not in ("transfer-encoding", "content-length"):
                    self.send_header(h_key, h_val)
            self.send_header("X-Protected-By", "LIGHTNING by NEXO-TECH BY ALEXANDER")
            self.send_header("Content-Length", str(len(err_data)))
            self.end_headers()
            self.wfile.write(err_data)
            self.notifier.log_clean_traffic(client_ip, self.command, self.path, e.code)

        except Exception as e:
            err_msg = f"<html><body style='background:#0b0f17;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h2>⚡ 502 Bad Gateway</h2><p>LIGHTNING Shield could not connect to backend server: <code>{self.backend_url}</code></p><p style='color:#64748b;'>Error: {str(e)}</p><hr style='border:1px solid #1e293b;'><p style='color:#38bdf8;'>LIGHTNING DEFENSE SYSTEM by NEXO-TECH BY ALEXANDER</p></body></html>".encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(err_msg)))
            self.send_header("X-Protected-By", "LIGHTNING by NEXO-TECH BY ALEXANDER")
            self.end_headers()
            try:
                self.wfile.write(err_msg)
            except Exception:
                pass

    def do_GET(self): self._proxy_request()
    def do_POST(self): self._proxy_request()
    def do_PUT(self): self._proxy_request()
    def do_DELETE(self): self._proxy_request()
    def do_HEAD(self): self._proxy_request()
    def do_OPTIONS(self): self._proxy_request()
    def do_PATCH(self): self._proxy_request()


class ThreadedHTTPServer(HTTPServer):
    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread, args=(request, client_address), daemon=True)
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def run_waf_shield(proxy_host: str, 
                   proxy_port: int, 
                   backend_url: str, 
                   notifier: SecurityNotifier, 
                   max_reqs: int = 60, 
                   time_window: int = 10, 
                   blacklist: list = None,
                   api_shield: Optional[APIShield] = None,
                   enable_dlp: bool = True,
                   enable_honeypots: bool = True,
                   quarantine: Optional[QuarantineManager] = None,
                   anti_bot: Optional[AntiBotArmor] = None,
                   malware_scanner: Optional[MalwareUploadScanner] = None,
                   virtual_patch: Optional[VirtualPatchingEngine] = None,
                   geo_intel: Optional[GeoIntelligence] = None,
                   heuristic: Optional[BehavioralScorer] = None):
    """Launches the full comprehensive LIGHTNING WAF Shield."""
    C = Colors
    WAFProxyHandler.backend_url = backend_url
    WAFProxyHandler.notifier = notifier
    WAFProxyHandler.rate_limiter = RateLimiter(max_requests=max_reqs, time_window=time_window)
    WAFProxyHandler.quarantine = quarantine or QuarantineManager()
    WAFProxyHandler.api_shield = api_shield
    WAFProxyHandler.dlp_engine = DataLossPreventionEngine(mask_leaks=True) if enable_dlp else None
    WAFProxyHandler.honeypot = HoneypotEngine(auto_ban=True) if enable_honeypots else None
    WAFProxyHandler.anti_bot = anti_bot or AntiBotArmor()
    WAFProxyHandler.malware_scanner = malware_scanner or MalwareUploadScanner()
    WAFProxyHandler.virtual_patch = virtual_patch or VirtualPatchingEngine()
    WAFProxyHandler.geo_intel = geo_intel or GeoIntelligence()
    WAFProxyHandler.heuristic = heuristic or BehavioralScorer()

    server_address = (proxy_host, proxy_port)
    try:
        httpd = ThreadedHTTPServer(server_address, WAFProxyHandler)
    except Exception as e:
        print(f"\n{C.RED}[!] Failed to bind LIGHTNING Shield to {proxy_host}:{proxy_port}: {e}{C.RESET}")
        return

    print(f"\n{C.GREEN}{C.BOLD}⚡ LIGHTNING ULTIMATE DEFENSE SHIELD ACTIVATED ⚡{C.RESET}")
    print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"{C.WHITE}  • Proxy Shield Address : {C.YELLOW}http://{proxy_host}:{proxy_port}{C.RESET}")
    print(f"{C.WHITE}  • Forwarding Safe Traffic: {C.GREEN}{backend_url}{C.RESET}")
    print(f"{C.WHITE}  • Virtual Patching     : {C.PURPLE}ACTIVE (Log4Shell, Spring4Shell, CVEs){C.RESET}")
    print(f"{C.WHITE}  • Malware Upload Scan  : {C.CYAN}ACTIVE (Webshell & Binary Filter){C.RESET}")
    print(f"{C.WHITE}  • Anti-Bot Armor       : {C.BLUE}ACTIVE (Interactive CAPTCHA & PoW){C.RESET}")
    print(f"{C.WHITE}  • Geo-Fencing & Tor    : {C.YELLOW}ACTIVE (IP Intelligence & Proxy Drop){C.RESET}")
    print(f"{C.WHITE}  • Heuristic Scorer     : {C.MAGENTA}ACTIVE (Behavioral Risk Engine){C.RESET}")
    print(f"{C.WHITE}  • Data Loss Prevention : {C.GREEN}{'ACTIVE (Secret Redaction)' if enable_dlp else 'DISABLED'}{C.RESET}")
    print(f"{C.WHITE}  • Honeypot Decoy Traps : {C.RED}{'ACTIVE (Auto-Ban Enabled)' if enable_honeypots else 'DISABLED'}{C.RESET}")
    print(f"{C.WHITE}  • Created By           : {C.GREEN}{C.BOLD}NEXO-TECH BY ALEXANDER{C.RESET}")
    print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    print(f"{C.DARK_GRAY}  [Press Ctrl+C at any time to pause or return to main menu]{C.RESET}\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[*] Shutting down LIGHTNING WAF Shield...{C.RESET}")
        httpd.server_close()

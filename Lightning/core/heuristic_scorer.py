"""
=============================================================================
                  LIGHTNING - BEHAVIORAL RISK SCORING & HEURISTIC ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import time
import math
from typing import Dict, Tuple

class BehavioralScorer:
    """Calculates dynamic Threat Risk Scores (0-100) for incoming clients."""
    def __init__(self):
        self.ip_scores: Dict[str, dict] = {}
        self.SENSITIVE_PATHS = ["/admin", "/config", "/wp-admin", "/etc/passwd", "/.git", "/.env"]
        self.SUSPICIOUS_EXTS = [".bak", ".old", ".orig", ".swp", ".sql"]
        
    def get_client_profile(self, ip: str) -> dict:
        now = time.time()
        
        # Initialize profile if not present
        if ip not in self.ip_scores:
            self.ip_scores[ip] = {
                "score": 0,
                "requests": 0,
                "error_404_count": 0,
                "last_seen": now,
                "reasons": [],
                "user_agents": set(),
                "sensitive_paths": [],
                "request_timestamps": [],
                "paths_accessed": [],
                "admin_paths_accessed": 0,
                "robots_txt_accessed": False
            }
        else:
            # Score decay: half-life of 30 minutes (1800 seconds)
            profile = self.ip_scores[ip]
            time_diff = now - profile.get("last_seen", now)
            if time_diff > 0:
                decay_factor = 0.5 ** (time_diff / 1800.0)
                profile["score"] = profile["score"] * decay_factor
            
            # Clean up old request timestamps (keep only last 10 seconds for rate limit check)
            profile["request_timestamps"] = [ts for ts in profile.get("request_timestamps", []) if now - ts <= 10]

        return self.ip_scores[ip]

    def record_404(self, ip: str):
        profile = self.get_client_profile(ip)
        profile["error_404_count"] += 1
        profile["score"] = min(100.0, profile["score"] + 15.0)
        profile["reasons"].append("Excessive 404 Errors (Fuzzing behavior)")
        profile["last_seen"] = time.time()

    def record_sensitive_path_access(self, ip: str, path: str):
        profile = self.get_client_profile(ip)
        profile["sensitive_paths"].append(path)
        if any(admin_kw in path.lower() for admin_kw in ["admin", "config", "setup"]):
            profile["admin_paths_accessed"] += 1
            if profile["admin_paths_accessed"] > 1:
                profile["score"] = min(100.0, profile["score"] + 30.0)
                profile["reasons"].append("Accessing multiple admin paths sequentially")
        else:
            if len(set(profile["sensitive_paths"])) > 1:
                profile["score"] = min(100.0, profile["score"] + 20.0)
                profile["reasons"].append("Accessing multiple sensitive paths sequentially")
        profile["last_seen"] = time.time()

    def record_user_agent_change(self, ip: str, new_ua: str):
        profile = self.get_client_profile(ip)
        if new_ua and new_ua not in profile["user_agents"]:
            if len(profile["user_agents"]) > 0:
                profile["score"] = min(100.0, profile["score"] + 35.0)
                profile["reasons"].append("Rotating User-Agents from same IP")
            profile["user_agents"].add(new_ua)
        profile["last_seen"] = time.time()

    def get_risk_level(self, ip: str) -> str:
        profile = self.get_client_profile(ip)
        score = profile["score"]
        if score >= 85:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        return "LOW"

    def should_auto_ban(self, ip: str) -> bool:
        return self.get_client_profile(ip)["score"] >= 85

    def cleanup_stale_profiles(self):
        now = time.time()
        # Remove profiles older than 1 hour (3600 seconds)
        stale_ips = [ip for ip, prof in self.ip_scores.items() if now - prof.get("last_seen", now) > 3600]
        for ip in stale_ips:
            del self.ip_scores[ip]

    def evaluate_request(self, ip: str, method: str, path: str, headers: dict) -> Tuple[int, str]:
        """
        Evaluates HTTP metadata and assigns a Risk Score from 0 to 100.
        Returns: (Score, Primary_Reason)
        """
        profile = self.get_client_profile(ip)
        now = time.time()
        profile["requests"] += 1
        profile["last_seen"] = now
        profile["request_timestamps"].append(now)
        profile["paths_accessed"].append(path)
        
        base_score = 0
        reasons = set()

        # Helper to get case-insensitive headers
        def get_header(key: str) -> str:
            for k, v in headers.items():
                if k.lower() == key.lower():
                    return str(v)
            return ""

        ua = get_header("User-Agent")
        accept = get_header("Accept")
        lang = get_header("Accept-Language")
        encoding = get_header("Accept-Encoding")
        referer = get_header("Referer")
        content_type = get_header("Content-Type")
        host = get_header("Host")
        xff = get_header("X-Forwarded-For")
        connection = get_header("Connection")

        # Record UA
        self.record_user_agent_change(ip, ua)

        # 1. Header Anomalies (per request)
        if not ua:
            base_score += 35
            reasons.add("Missing/empty User-Agent")
        else:
            headless_sigs = ["headless", "phantomjs", "selenium", "playwright", "puppeteer", "htmlunit", "jsdom", "splash"]
            if any(sig in ua.lower() for sig in headless_sigs):
                base_score += 55
                reasons.add(f"Headless browser signatures detected ({ua[:30]})")

        if not accept:
            base_score += 15
            reasons.add("Missing Accept header")
            
        if not lang:
            base_score += 10
            reasons.add("Missing Accept-Language")
            
        if not encoding:
            base_score += 10
            reasons.add("Missing Accept-Encoding")

        if path != "/" and not referer:
            base_score += 5
            reasons.add("Missing Referer on non-entry pages")

        if method.upper() in ("TRACE", "TRACK", "DEBUG", "CONNECT", "PROPFIND"):
            base_score += 40
            reasons.add(f"Suspicious HTTP methods: {method}")

        if method.upper() == "GET" and content_type:
            base_score += 20
            reasons.add("Unusual Content-Type for GET requests")

        if xff:
            internal_prefixes = ("10.", "192.168.", "172.16.", "127.")
            if any(ip_str.strip().startswith(internal_prefixes) for ip_str in xff.split(",")):
                base_score += 15
                reasons.add("X-Forwarded-For with internal IPs")

        host_raw = headers.get("Host") or headers.get("host")
        if isinstance(host_raw, list) or (isinstance(host_raw, str) and "," in host_raw):
            base_score += 25
            reasons.add("Multiple Host headers")

        if len(path) > 2048:
            base_score += 20
            reasons.add("Very long URLs (>2048 chars)")

        for k, v in headers.items():
            if len(str(v)) > 4096:
                base_score += 20
                reasons.add("Very long header values (>4096 chars)")
                break

        # Mismatched TLS SNI vs Host header (Assuming passed in headers)
        tls_sni = get_header("X-TLS-SNI")
        if tls_sni and host and tls_sni.lower() != host.lower().split(":")[0]:
            base_score += 30
            reasons.add("Mismatched TLS SNI vs Host header")

        # Non-standard HTTP version strings (Assuming passed in headers)
        http_version = get_header("X-HTTP-Version")
        if http_version and http_version not in ("HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/2", "HTTP/3"):
            base_score += 15
            reasons.add("Non-standard HTTP version strings")

        if connection.lower() in ("close, keep-alive", "keep-alive, close"):
            base_score += 10
            reasons.add("Connection header manipulation")

        # Fingerprinting Checks
        if "chrome" in ua.lower() and accept and "application/signed-exchange" not in accept.lower():
            base_score += 20
            reasons.add("Browser consistency check failed (Chrome UA without matching Accept)")

        # 2. Behavioral Patterns
        if len(profile["request_timestamps"]) > 30:
            base_score += 25
            reasons.add("Rapid request rate (>30 req/10s)")

        if path.lower() == "/robots.txt":
            profile["robots_txt_accessed"] = True
        elif profile["robots_txt_accessed"] and path in self.SENSITIVE_PATHS:
            base_score += 20
            reasons.add("Accessing robots.txt then disallowed paths")

        if any(path.endswith(ext) for ext in self.SUSPICIOUS_EXTS):
            base_score += 20
            reasons.add("Requesting non-existent file extensions")

        if method.upper() == "POST" and not content_type:
            base_score += 15
            reasons.add("POST requests without proper Content-Type")

        # Submitting forms extremely fast (< 2 seconds after page load)
        if method.upper() == "POST" and len(profile["request_timestamps"]) >= 2:
            time_since_last = now - profile["request_timestamps"][-2]
            if time_since_last < 2.0:
                base_score += 25
                reasons.add("Submitting forms extremely fast (< 2 seconds after page load)")

        # Cookie replay/manipulation detected (Simulated logic using duplicate identical request patterns or malformed cookies)
        cookie = get_header("Cookie")
        if cookie and ("=" not in cookie or ";" * 3 in cookie):
            base_score += 25
            reasons.add("Cookie replay/manipulation detected")

        # Request payload entropy analysis
        entropy_header = get_header("X-Payload-Entropy")
        if entropy_header:
            try:
                if float(entropy_header) > 7.5:
                    base_score += 15
                    reasons.add("Request payload entropy analysis (high entropy)")
            except ValueError:
                pass

        # Systematic port/path scanning patterns
        if profile["requests"] > 5 and len(set(profile["paths_accessed"][-5:])) == 5:
            if not referer:
                base_score += 40
                reasons.add("Systematic port/path scanning patterns")

        # Sequential parameter fuzzing check (basic heuristic)
        if "?" in path and len(profile["paths_accessed"]) >= 3:
            prev_paths = [p for p in profile["paths_accessed"][-3:] if "?" in p]
            if len(prev_paths) >= 3:
                base_path = path.split("?")[0]
                if all(p.startswith(base_path) for p in prev_paths) and len(set(prev_paths)) > 1:
                    base_score += 30
                    reasons.add("Sequential parameter fuzzing")

        # Update profile score and reasons
        profile["score"] = min(100.0, base_score + profile["score"])
        
        for r in reasons:
            if r not in profile["reasons"]:
                profile["reasons"].append(r)

        # Placeholder integration notes
        # TLS JA3/JA4 hash anomaly detection (placeholder for future)
        # HTTP/2 frame ordering anomaly (placeholder)
        # Request payload entropy analysis (placeholder)

        total_score = int(profile["score"])
        primary_reason = ", ".join(profile["reasons"][-3:]) if profile["reasons"] else "Normal Behavioral Profile"
        
        return total_score, primary_reason

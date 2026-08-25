"""
=============================================================================
                  LIGHTNING - BEHAVIORAL RISK SCORING & HEURISTIC ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import time
from typing import Dict, Tuple

class BehavioralScorer:
    """Calculates dynamic Threat Risk Scores (0-100) for incoming clients."""
    def __init__(self):
        self.ip_scores: Dict[str, dict] = {}

    def get_client_profile(self, ip: str) -> dict:
        now = time.time()
        if ip not in self.ip_scores or now - self.ip_scores[ip].get("last_seen", 0) > 300:
            self.ip_scores[ip] = {
                "score": 0,
                "requests": 0,
                "error_404_count": 0,
                "last_seen": now,
                "reasons": []
            }
        return self.ip_scores[ip]

    def record_404(self, ip: str):
        profile = self.get_client_profile(ip)
        profile["error_404_count"] += 1
        profile["score"] = min(100, profile["score"] + 15)
        profile["reasons"].append("Excessive 404 Errors (Fuzzing behavior)")

    def evaluate_request(self, ip: str, method: str, path: str, headers: dict) -> Tuple[int, str]:
        """
        Evaluates HTTP metadata and assigns a Risk Score from 0 to 100.
        Returns: (Score, Primary_Reason)
        """
        profile = self.get_client_profile(ip)
        profile["requests"] += 1
        profile["last_seen"] = time.time()
        
        base_score = 0
        reasons = []

        # 1. Check Missing Standard Browser Headers
        ua = headers.get("User-Agent") or headers.get("user-agent", "")
        accept = headers.get("Accept") or headers.get("accept", "")
        lang = headers.get("Accept-Language") or headers.get("accept-language", "")

        if not ua:
            base_score += 35
            reasons.append("Missing User-Agent Header")
        elif any(b in ua.lower() for b in ("headless", "phantomjs", "selenium", "playwright", "puppeteer")):
            base_score += 55
            reasons.append(f"Automated Headless Browser Detected ({ua[:30]})")

        if not accept:
            base_score += 15
            reasons.append("Missing Accept Header")

        if not lang and method != "HEAD":
            base_score += 10
            reasons.append("Missing Accept-Language Header")

        # 2. Check Suspicious HTTP Methods (e.g. TRACE, TRACK, CONNECT, DEBUG)
        if method.upper() in ("TRACE", "TRACK", "DEBUG"):
            base_score += 40
            reasons.append(f"Suspicious HTTP Method ({method})")

        # 3. Add accumulated behavioral score
        total_score = min(100, base_score + profile["score"])
        primary_reason = ", ".join(reasons) if reasons else "Normal Behavioral Profile"
        
        return total_score, primary_reason

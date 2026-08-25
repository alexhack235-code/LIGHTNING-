"""
=============================================================================
                  LIGHTNING - IP GEOLOCATION, GEO-FENCING & TOR INTELLIGENCE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import socket
import urllib.request
import json
import threading
from typing import Dict, Optional, Tuple, Set

# Known malicious Tor Exit Node / Anonymous Proxy IP ranges (Simulated cache + dynamic lookup)
TOR_INDICATOR_HEADERS = [
    "x-tor-exit-node",
    "cf-connecting-ip-tor",
    "x-anonymizing-proxy",
    "x-forwarded-tor"
]

class GeoIntelligence:
    """Provides IP Geolocation, Geo-Fencing, and Tor/Proxy Detection."""
    def __init__(self, 
                 blocked_countries: Optional[list] = None, 
                 allowed_countries: Optional[list] = None, 
                 block_tor: bool = True):
        self.blocked_countries = set(c.upper() for c in (blocked_countries or []))
        self.allowed_countries = set(c.upper() for c in (allowed_countries or []))
        self.block_tor = block_tor
        self.cache: Dict[str, dict] = {}
        self.lock = threading.Lock()

    def is_private_or_loopback(self, ip: str) -> bool:
        """Identifies local, private RFC1918, or loopback IPs."""
        return (
            ip.startswith("127.") or 
            ip.startswith("10.") or 
            ip.startswith("192.168.") or 
            ip.startswith("172.16.") or 
            ip == "::1" or 
            ip == "localhost"
        )

    def lookup_ip(self, ip: str) -> dict:
        """Retrieves Geolocation and Network intelligence for a client IP."""
        if self.is_private_or_loopback(ip):
            return {"country": "LOCAL", "country_name": "Local Network / Loopback", "is_tor": False, "isp": "Private LAN"}

        with self.lock:
            if ip in self.cache:
                return self.cache[ip]

        # Fast free IP geolocation API lookup with timeout
        info = {"country": "XX", "country_name": "Unknown", "is_tor": False, "isp": "Unknown ISP"}
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,proxy"
            req = urllib.request.Request(url, headers={"User-Agent": "Lightning-Geo/2.5"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    info["country"] = data.get("countryCode", "XX").upper()
                    info["country_name"] = data.get("country", "Unknown")
                    info["isp"] = data.get("isp", "Unknown")
                    info["is_tor"] = bool(data.get("proxy", False))
        except Exception:
            pass

        with self.lock:
            self.cache[ip] = info

        return info

    def inspect_client(self, ip: str, headers: dict) -> Optional[Tuple[str, str, str]]:
        """
        Inspects client IP and headers for Geo-Fencing or Tor/Proxy violations.
        Returns: (Reason, Severity, Snippet) or None.
        """
        # 1. Check Tor Indicator Headers
        if self.block_tor:
            for h in TOR_INDICATOR_HEADERS:
                if h in headers:
                    return ("Tor Anonymous Exit Node Intercepted", "HIGH", f"Header: {h}")

        # 2. Skip local LAN IPs for Geo-Fencing
        if self.is_private_or_loopback(ip):
            return None

        geo = self.lookup_ip(ip)
        cc = geo.get("country", "XX")

        # 3. Check Tor Proxy Flag from Geo-Lookup
        if self.block_tor and geo.get("is_tor"):
            return ("Anonymous Proxy / Tor Relay Blocked", "HIGH", f"IP: {ip} (Proxy Detected)")

        # 4. Check Geo-Fencing Blocklist
        if self.blocked_countries and cc in self.blocked_countries:
            return (f"Geo-Fencing Policy: Blocked Country ({cc} - {geo.get('country_name')})", "HIGH", f"Origin: {cc}")

        # 5. Check Geo-Fencing Allowlist
        if self.allowed_countries and cc not in self.allowed_countries and cc != "LOCAL":
            return (f"Geo-Fencing Policy: Country ({cc}) not in Allowed List", "HIGH", f"Origin: {cc}")

        return None

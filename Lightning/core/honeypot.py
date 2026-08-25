"""
=============================================================================
                  LIGHTNING - ACTIVE HONEYPOT & DECOY TRAP ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

from typing import Set, Optional, Tuple

HONEYPOT_ROUTES = {
    "/admin_login.php": "Fake Admin Portal Trap",
    "/wp-admin/install.php": "WordPress Installer Decoy",
    "/phpmyadmin/index.php": "phpMyAdmin Decoy Trap",
    "/api/v1/internal/admin": "Internal Admin API Decoy",
    "/actuator/heapdump": "Spring Actuator Exploit Decoy",
    "/debug/vars": "Go Debug Endpoints Decoy",
    "/solr/admin/info/system": "Apache Solr RCE Trap",
    "/.aws/credentials": "AWS Credentials Decoy Trap",
    "/.env.backup": "Environment Backup Decoy Trap",
}

class HoneypotEngine:
    """Decoy trap engine to catch and auto-blacklist aggressive scanners."""
    def __init__(self, auto_ban: bool = True):
        self.auto_ban = auto_ban
        self.trapped_ips: Set[str] = set()

    def is_honeypot_hit(self, path: str) -> Optional[Tuple[str, str]]:
        """Checks if a request path hit a configured honeypot trap."""
        clean_path = path.split("?")[0].rstrip("/")
        for trap_path, trap_name in HONEYPOT_ROUTES.items():
            if clean_path == trap_path or clean_path == trap_path.rstrip("/"):
                return trap_name, trap_path
        return None

    def trigger_trap(self, ip: str, path: str) -> Tuple[str, str]:
        """Records a honeypot breach and flags the IP for permanent blacklist."""
        trap_info = self.is_honeypot_hit(path)
        trap_name = trap_info[0] if trap_info else "General Decoy Trap"
        if self.auto_ban:
            self.trapped_ips.add(ip)
        return trap_name, f"Attacker probed active Honeypot decoy: {path}"

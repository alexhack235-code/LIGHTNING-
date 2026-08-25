"""
=============================================================================
                  LIGHTNING - ADVANCED CONFIGURATION & SETUP WIZARD
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import json
import urllib.parse
from banner import Colors

CONFIG_FILE = "lightning_config.json"

DEFAULT_CONFIG = {
    "website_url": "http://127.0.0.1:3000",
    "target_ip": "127.0.0.1",
    "target_port": 3000,
    "shield_proxy_port": 8080,
    "sound_alerts": True,
    "rate_limit_max": 60,
    "rate_limit_window": 10,
    "blacklist_ips": [],
    "log_file": "lightning_security.log",
    
    # API Shield Settings
    "api_enabled": True,
    "api_base_path": "/api",
    "api_key_header": "X-API-Key",
    "api_keys": ["test-client-key-123"],
    "graphql_depth_limit": 5,
    "jwt_enforce": True,

    # Database Rule & Sentinel Settings
    "db_monitoring_enabled": True,
    "db_engine": "mysql",
    "db_host": "127.0.0.1",
    "db_port": 3306,
    "db_name": "production_db",
    "db_audit_log": "mysql_audit.log",

    # Advanced Defense Layers
    "enable_dlp": True,
    "enable_honeypots": True,
    "webhook_url": ""
}


def load_config() -> dict:
    """Loads configuration from JSON file or returns defaults."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(saved)
                return config
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Saves configuration to JSON file."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Failed to save config: {e}")


def interactive_wizard() -> dict:
    """Prompts the user interactively to configure Website, API, Database, and Shield."""
    C = Colors
    config = load_config()

    print(f"\n{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
    print(f"{C.CYAN}┃       ⚡ LIGHTNING - COMPREHENSIVE SECURITY SETUP WIZARD ⚡        ┃{C.RESET}")
    print(f"{C.CYAN}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
    print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

    print(f"{C.WHITE}Please configure your Website, API endpoints, and Database rules.{C.RESET}")
    print(f"{C.DARK_GRAY}(Press ENTER to accept the current value shown in brackets){C.RESET}\n")

    # --- SECTION 1: PRIMARY WEB TARGET ---
    print(f"{C.CYAN}{C.BOLD}─── [1/4] PRIMARY WEB TARGET ───{C.RESET}")
    while True:
        prompt = f"{C.YELLOW}[?] Target Website URL [{config['website_url']}]: {C.RESET}"
        user_url = input(prompt).strip()
        if not user_url:
            break
        if not user_url.startswith("http://") and not user_url.startswith("https://"):
            user_url = "http://" + user_url
        
        parsed = urllib.parse.urlparse(user_url)
        if parsed.hostname:
            config["website_url"] = user_url
            config["target_ip"] = parsed.hostname
            if parsed.port:
                config["target_port"] = parsed.port
            elif parsed.scheme == "https":
                config["target_port"] = 443
            else:
                config["target_port"] = 80
            break
        else:
            print(f"{C.RED}[!] Invalid URL. Please enter a valid URL (e.g. http://127.0.0.1:3000 or https://mysite.com){C.RESET}")

    prompt = f"{C.YELLOW}[?] Target Server Host/IP [{config['target_ip']}]: {C.RESET}"
    user_ip = input(prompt).strip()
    if user_ip:
        config["target_ip"] = user_ip

    prompt = f"{C.YELLOW}[?] Target Server Port [{config['target_port']}]: {C.RESET}"
    user_port = input(prompt).strip()
    if user_port and user_port.isdigit():
        config["target_port"] = int(user_port)

    prompt = f"{C.YELLOW}[?] LIGHTNING WAF Shield Port [{config['shield_proxy_port']}]: {C.RESET}"
    user_proxy_port = input(prompt).strip()
    if user_proxy_port and user_proxy_port.isdigit():
        config["shield_proxy_port"] = int(user_proxy_port)

    # --- SECTION 2: API GATEWAY & AUTH SETTINGS ---
    print(f"\n{C.CYAN}{C.BOLD}─── [2/4] API GATEWAY & AUTHENTICATION ───{C.RESET}")
    prompt = f"{C.YELLOW}[?] API Base Route Prefix [{config['api_base_path']}]: {C.RESET}"
    user_api_path = input(prompt).strip()
    if user_api_path:
        config["api_base_path"] = user_api_path

    prompt = f"{C.YELLOW}[?] API Key Header Name [{config['api_key_header']}]: {C.RESET}"
    user_key_header = input(prompt).strip()
    if user_key_header:
        config["api_key_header"] = user_key_header

    prompt = f"{C.YELLOW}[?] Enforce JWT Inspection (Bypasses, alg=none)? (y/n) [{'y' if config['jwt_enforce'] else 'n'}]: {C.RESET}"
    user_jwt = input(prompt).strip().lower()
    if user_jwt:
        config["jwt_enforce"] = user_jwt.startswith("y")

    # --- SECTION 3: DATABASE MONITORING & QUERY RULES ---
    print(f"\n{C.CYAN}{C.BOLD}─── [3/4] DATABASE MONITORING & QUERY RULES ───{C.RESET}")
    prompt = f"{C.YELLOW}[?] Database Engine (mysql / postgres / sqlite / mongodb / redis) [{config['db_engine']}]: {C.RESET}"
    user_db_eng = input(prompt).strip().lower()
    if user_db_eng in ("mysql", "postgres", "sqlite", "mongodb", "redis"):
        config["db_engine"] = user_db_eng

    if config["db_engine"] != "sqlite":
        prompt = f"{C.YELLOW}[?] Database Host IP [{config['db_host']}]: {C.RESET}"
        user_db_host = input(prompt).strip()
        if user_db_host:
            config["db_host"] = user_db_host

        default_port = 3306 if config["db_engine"] == "mysql" else (5432 if config["db_engine"] == "postgres" else (27017 if config["db_engine"] == "mongodb" else 6379))
        prompt = f"{C.YELLOW}[?] Database Port [{config.get('db_port', default_port)}]: {C.RESET}"
        user_db_p = input(prompt).strip()
        if user_db_p and user_db_p.isdigit():
            config["db_port"] = int(user_db_p)

    prompt = f"{C.YELLOW}[?] Database Name [{config['db_name']}]: {C.RESET}"
    user_db_name = input(prompt).strip()
    if user_db_name:
        config["db_name"] = user_db_name

    # --- SECTION 4: HONEYPOTS, DLP & ALERTS ---
    print(f"\n{C.CYAN}{C.BOLD}─── [4/4] HONEYPOTS, DLP & ALERTS ───{C.RESET}")
    prompt = f"{C.YELLOW}[?] Enable Active Honeypot Decoy Traps & Auto-Bans? (y/n) [{'y' if config['enable_honeypots'] else 'n'}]: {C.RESET}"
    user_hp = input(prompt).strip().lower()
    if user_hp:
        config["enable_honeypots"] = user_hp.startswith("y")

    prompt = f"{C.YELLOW}[?] Enable Outgoing Data Loss Prevention (DLP Secret Scrubber)? (y/n) [{'y' if config['enable_dlp'] else 'n'}]: {C.RESET}"
    user_dlp = input(prompt).strip().lower()
    if user_dlp:
        config["enable_dlp"] = user_dlp.startswith("y")

    prompt = f"{C.YELLOW}[?] Discord / Slack / Webhook Alert URL (Optional) [{config.get('webhook_url', '')}]: {C.RESET}"
    user_webhook = input(prompt).strip()
    if user_webhook:
        config["webhook_url"] = user_webhook

    prompt = f"{C.YELLOW}[?] Terminal Audio Alert Sounds? (y/n) [{'y' if config['sound_alerts'] else 'n'}]: {C.RESET}"
    user_sound = input(prompt).strip().lower()
    if user_sound:
        config["sound_alerts"] = user_sound.startswith("y")

    save_config(config)
    print(f"\n{C.GREEN}{C.BOLD}✔ Configuration updated and saved to {CONFIG_FILE}!{C.RESET}\n")
    return config

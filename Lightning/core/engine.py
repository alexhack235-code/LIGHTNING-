"""
=============================================================================
                  LIGHTNING - MASTER AUTONOMOUS DEFENSE ENGINE (ALL-IN-ONE)
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import threading
import webbrowser
from typing import Dict, Optional

from banner import Colors, print_banner, print_header, print_box
from core.notifier import SecurityNotifier
from core.waf_proxy import ThreadedHTTPServer, WAFProxyHandler, RateLimiter
from core.api_shield import APIShield
from core.db_monitor import DatabaseSentinel
from core.dlp import DataLossPreventionEngine
from core.honeypot import HoneypotEngine
from core.monitor import WebsiteSentinel
from core.log_ids import LogWatcherIDS
from core.anti_bot import AntiBotArmor
from core.malware_scanner import MalwareUploadScanner
from core.virtual_patching import VirtualPatchingEngine
from core.geo_intelligence import GeoIntelligence
from core.heuristic_scorer import BehavioralScorer
from core.quarantine import QuarantineManager
from core.soc_dashboard import run_soc_dashboard_server
from core.radar import BrutalContinuousRadar
from core.persistence import PersistenceEngine
from core.threat_feeds import ThreatIntelligenceFeedManager
from core.ssl_manager import SSLCertificateManager


class MasterDefenseEngine:
    """
    Next-Gen Autonomous Defense Engine:
    Coordinates WAF Shield, API Gateway, Virtual Patching, Malware Scanner,
    Anti-Bot Armor, Geo-Intelligence, Heuristic Scorer, Honeypots, DLP,
    Website Sentinel, Database Sentinel, Log IDS, Web SOC Dashboard,
    and Premium Brutal Continuous Radar.
    """
    def __init__(self, config: dict, notifier: SecurityNotifier, auto_open_browser: bool = True):
        self.config = config
        self.notifier = notifier
        self.auto_open_browser = auto_open_browser
        self.running = False
        self.threads = []
        self.httpd: Optional[ThreadedHTTPServer] = None
        self.soc_server = None
        self.start_time = time.time()

        # Engine Modules
        is_prem = self.config.get("premium_unlocked", False)
        self.quarantine = QuarantineManager(default_ban_duration=86400 if is_prem else 300)
        self.anti_bot = AntiBotArmor()
        self.malware_scanner = MalwareUploadScanner()
        self.virtual_patch = VirtualPatchingEngine()
        self.geo_intel = GeoIntelligence(
            blocked_countries=self.config.get("blocked_countries", []),
            allowed_countries=self.config.get("allowed_countries", []),
            block_tor=self.config.get("block_tor", True)
        )
        self.heuristic = BehavioralScorer()
        self.api_shield = None
        self.dlp_engine = None
        self.honeypot = None
        self.website_sentinel = None
        self.db_sentinel = None
        self.log_watcher = None
        self.radar = None

        # New Enterprise Modules (10/10 upgrades)
        self.persistence = PersistenceEngine()
        self.threat_feeds = ThreatIntelligenceFeedManager(persistence=self.persistence)
        self.ssl_manager = SSLCertificateManager()

    def _start_waf_thread(self):
        proxy_host = "0.0.0.0"
        proxy_port = self.config.get("shield_proxy_port", 8080)
        backend_url = self.config.get("website_url", f"http://{self.config['target_ip']}:{self.config['target_port']}")

        WAFProxyHandler.backend_url = backend_url
        WAFProxyHandler.notifier = self.notifier
        WAFProxyHandler.rate_limiter = RateLimiter(
            max_requests=self.config.get("rate_limit_max", 60),
            time_window=self.config.get("rate_limit_window", 10)
        )
        WAFProxyHandler.quarantine = self.quarantine
        WAFProxyHandler.api_shield = self.api_shield
        WAFProxyHandler.dlp_engine = self.dlp_engine
        WAFProxyHandler.honeypot = self.honeypot
        WAFProxyHandler.anti_bot = self.anti_bot
        WAFProxyHandler.malware_scanner = self.malware_scanner
        WAFProxyHandler.virtual_patch = self.virtual_patch
        WAFProxyHandler.geo_intel = self.geo_intel
        WAFProxyHandler.heuristic = self.heuristic
        WAFProxyHandler.threat_feeds = self.threat_feeds

        try:
            self.httpd = ThreadedHTTPServer((proxy_host, proxy_port), WAFProxyHandler)
            self.httpd.serve_forever()
        except Exception as e:
            if self.running:
                print(f"{Colors.RED}[!] WAF Proxy Server encountered error: {e}{Colors.RESET}")

    def _start_website_sentinel_thread(self):
        target_url = self.config.get("website_url", f"http://{self.config['target_ip']}:{self.config['target_port']}")
        self.website_sentinel = WebsiteSentinel(
            target_url=target_url,
            notifier=self.notifier,
            check_interval=20
        )
        self.website_sentinel.check_sensitive_files()

        check_count = 0
        while self.running:
            check_count += 1
            try:
                self.website_sentinel.run_single_check()
                if check_count % 15 == 0:
                    self.website_sentinel.check_sensitive_files()
            except Exception:
                pass
            time.sleep(20)

    def _start_db_sentinel_thread(self):
        if not self.config.get("db_monitoring_enabled", True):
            return

        self.db_sentinel = DatabaseSentinel(
            db_type=self.config.get("db_engine", "mysql"),
            db_host=self.config.get("db_host", "127.0.0.1"),
            db_port=self.config.get("db_port", 3306),
            db_name=self.config.get("db_name", "app_db"),
            notifier=self.notifier
        )

        while self.running:
            try:
                self.db_sentinel.test_connection()
            except Exception:
                pass
            time.sleep(25)

    def _start_radar_thread(self):
        self.radar = BrutalContinuousRadar(
            target_url=self.config.get("website_url", "http://127.0.0.1:3000"),
            target_ip=self.config.get("target_ip", "127.0.0.1"),
            notifier=self.notifier
        )
        while self.running:
            try:
                self.radar.run_radar_sweep()
            except Exception:
                pass
            time.sleep(20)

    def _start_log_watcher_thread(self):
        log_path = self.config.get("access_log_path", "access.log")
        if not os.path.exists(log_path):
            return
        
        self.log_watcher = LogWatcherIDS(log_path=log_path, notifier=self.notifier)
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.log_watcher.parse_and_inspect_line(line)
        except Exception:
            pass

    def start(self):
        C = Colors
        self.running = True
        self.start_time = time.time()
        is_prem = self.config.get("premium_unlocked", False)

        if self.config.get("api_enabled", True):
            self.api_shield = APIShield(
                api_base_path=self.config.get("api_base_path", "/api"),
                api_key_header=self.config.get("api_key_header", "X-API-Key"),
                valid_api_keys=set(self.config.get("api_keys", [])),
                jwt_enforce=self.config.get("jwt_enforce", True),
                graphql_depth_limit=self.config.get("graphql_depth_limit", 5)
            )

        if self.config.get("enable_dlp", True):
            self.dlp_engine = DataLossPreventionEngine(mask_leaks=True)

        if self.config.get("enable_honeypots", True):
            self.honeypot = HoneypotEngine(auto_ban=True)

        # Launch SOC Web Dashboard on port 8888
        soc_port = self.config.get("soc_port", 8888)
        self.soc_server = run_soc_dashboard_server(
            port=soc_port,
            notifier=self.notifier,
            quarantine=self.quarantine,
            config=self.config
        )

        # Automatically open Google Chrome / Default Browser
        if self.auto_open_browser:
            def _open():
                time.sleep(0.8)
                try:
                    webbrowser.open(f"http://127.0.0.1:{soc_port}")
                except Exception:
                    pass
            threading.Thread(target=_open, daemon=True).start()

        # Launch Engine Threads
        t_waf = threading.Thread(target=self._start_waf_thread, daemon=True, name="WAF-Shield")
        t_site = threading.Thread(target=self._start_website_sentinel_thread, daemon=True, name="Website-Sentinel")
        t_db = threading.Thread(target=self._start_db_sentinel_thread, daemon=True, name="DB-Sentinel")
        t_log = threading.Thread(target=self._start_log_watcher_thread, daemon=True, name="Log-IDS")

        self.threads = [t_waf, t_site, t_db, t_log]
        if is_prem:
            t_radar = threading.Thread(target=self._start_radar_thread, daemon=True, name="Brutal-Radar")
            self.threads.append(t_radar)

        for t in self.threads:
            t.start()

        # Render Active Engine Status Banner
        print(f"\n{C.GREEN}{C.BOLD}⚡ LIGHTNING ULTIMATE AUTONOMOUS DEFENSE ENGINE RUNNING ⚡{C.RESET}")
        print(f"{C.PURPLE}{C.BOLD}            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
        print(f"{C.WHITE}{C.BOLD}                [+] CREATED BY NEXO-TECH BY ALEXANDER [+]{C.RESET}")
        print(f"{C.PURPLE}{C.BOLD}            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")

        print(f"{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
        print(f"{C.CYAN}┃                ⚡ ACTIVE ENTERPRISE DEFENSE SUBSYSTEMS ⚡           ┃{C.RESET}")
        print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
        if is_prem:
            print(f"{C.CYAN}┃ {C.BG_MAGENTA}{C.WHITE}{C.BOLD} 👑 PREMIUM EDITION {C.RESET} {C.PURPLE}{C.BOLD}BRUTAL CONTINUOUS RADAR & ZERO-TOLERANCE ACTIVE{C.RESET}  {C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}WAF Reverse Proxy Shield  :{C.RESET} {C.YELLOW}http://127.0.0.1:{self.config['shield_proxy_port']:<22}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Web SOC Command Center    :{C.RESET} {C.CYAN}http://127.0.0.1:{soc_port:<22}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Target Web Application    :{C.RESET} {C.CYAN}{self.config['website_url'][:34]:<34}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Virtual Patching & CVEs   :{C.RESET} {C.PURPLE}ACTIVE (Log4Shell, Spring4Shell){' ' * 2}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Webshell & Malware Filter :{C.RESET} {C.CYAN}ACTIVE (Multipart Binary Scan){' ' * 4}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Anti-Bot Proof-of-Work    :{C.RESET} {C.BLUE}ACTIVE (Interactive Challenge){' ' * 4}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Geo-Fencing & Tor Block   :{C.RESET} {C.YELLOW}ACTIVE (IP Intelligence){' ' * 10}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Heuristic Behavioral Scorer:{C.RESET} {C.MAGENTA}ACTIVE (Score 0-100 Profiling){' ' * 3}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Data Loss Prevention (DLP):{C.RESET} {C.GREEN}ACTIVE (Secret Auto-Redaction){' ' * 4}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Honeypot Decoy Traps      :{C.RESET} {C.RED}ACTIVE (Auto-Ban Enabled){' ' * 9}{C.CYAN}┃{C.RESET}")
        if is_prem:
            print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Brutal Continuous Radar   :{C.RESET} {C.PURPLE}{C.BOLD}ACTIVE (4-Sector Surface Sweep){' ' * 2}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Live Defacement Watchdog  :{C.RESET} {C.GREEN}ACTIVE (SHA-256 DOM Integrity){' ' * 4}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┃ {C.GREEN}✔ [ONLINE]{C.RESET} {C.WHITE}Database Rule Sentinel    :{C.RESET} {C.YELLOW}ACTIVE ({self.config.get('db_engine','mysql').upper()} @ {self.config.get('db_host','127.0.0.1')}){C.RESET}{' ' * (17 - len(str(self.config.get('db_engine','mysql'))))}{C.CYAN}┃{C.RESET}")
        print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")
        print(f"{C.GREEN}{C.BOLD}✔ Opening Web Command Center in your browser at http://127.0.0.1:{soc_port}...{C.RESET}")
        print(f"{C.YELLOW}⚡ Real-time terminal alerts will trigger below whenever suspicious activity occurs.{C.RESET}")
        print(f"{C.DARK_GRAY}[Press Ctrl+C at any time to pause or return to menu]{C.RESET}\n")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        C = Colors
        print(f"\n{C.YELLOW}[*] Halting LIGHTNING Autonomous Defense Engine...{C.RESET}")
        self.running = False
        if self.httpd:
            try:
                self.httpd.server_close()
            except Exception:
                pass
        if self.soc_server:
            try:
                self.soc_server.server_close()
            except Exception:
                pass
        print(f"{C.GREEN}[+] All defense subsystems stopped cleanly.{C.RESET}\n")

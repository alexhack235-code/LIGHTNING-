"""
=============================================================================
                  LIGHTNING - MAIN CONTROL CENTER & AUTONOMOUS ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import webbrowser

from banner import Colors, print_banner, print_header, print_box
from config import load_config, save_config, interactive_wizard
from core.notifier import SecurityNotifier
from core.engine import MasterDefenseEngine
from core.premium import PremiumAuth, print_premium_banner
from core.radar import BrutalContinuousRadar
from core.soc_dashboard import run_soc_dashboard_server
from core.waf_proxy import run_waf_shield
from core.api_shield import APIShield
from core.db_monitor import DatabaseSentinel
from core.monitor import WebsiteSentinel
from core.scanner import run_security_audit
from core.log_ids import LogWatcherIDS


def view_logs(log_file: str):
    """Displays recent entries of the security audit log with color formatting."""
    C = Colors
    if not os.path.exists(log_file):
        print(f"\n{C.YELLOW}[*] No security log records found yet at {log_file}.{C.RESET}")
        return

    print_header(f"LIGHTNING AUDIT LOG - {log_file}")
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        if not lines:
            print(f"{C.DARK_GRAY}Log file is currently empty.{C.RESET}")
            return
        
        for line in lines[-40:]:
            line = line.strip()
            if "CRITICAL" in line or "BLOCKED" in line or "DLP" in line:
                print(f"{C.RED}{line}{C.RESET}")
            elif "HIGH" in line or "RATE_LIMIT" in line or "HONEYPOT" in line:
                print(f"{C.YELLOW}{line}{C.RESET}")
            elif "INTEGRITY" in line or "DB_QUERY" in line or "RADAR" in line:
                print(f"{C.PURPLE}{line}{C.RESET}")
            else:
                print(f"{C.CYAN}{line}{C.RESET}")


def display_menu(config: dict, is_premium: bool):
    """Displays the main interactive dashboard menu."""
    C = Colors
    tier_badge = f"{C.BG_MAGENTA}{C.WHITE}{C.BOLD} 👑 PREMIUM EDITION UNLOCKED {C.RESET}" if is_premium else f"{C.DARK_GRAY}[ STANDARD EDITION ]{C.RESET}"
    soc_port = config.get("soc_port", 8888)

    print(f"{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
    print(f"{C.CYAN}┃                 ⚡ LIGHTNING UNIFIED DEFENSE CENTER ⚡              ┃{C.RESET}")
    print(f"{C.CYAN}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.DARK_GRAY}LICENSE TIER   : {tier_badge}{' ' * (44 - (28 if is_premium else 20))}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.DARK_GRAY}TARGET WEB     : {C.YELLOW}{config['website_url'][:48]:<48}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.DARK_GRAY}WAF SHIELD GATE: {C.GREEN}http://127.0.0.1:{config['shield_proxy_port']:<38}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.DARK_GRAY}WEB SOC GUI    : {C.CYAN}http://127.0.0.1:{soc_port:<38}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}{C.BOLD}MASTER AUTONOMOUS ENGINE (ALL-IN-ONE):{C.RESET}{' ' * 29}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.GREEN}{C.BOLD}[1] ⚡ LAUNCH ALL-IN-ONE DEFENSE ENGINE (RECOMMENDED){C.RESET}             {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}      {C.DARK_GRAY}(Starts WAF + API Guard + DB Watcher + SOC Dashboard at once){C.RESET} {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.CYAN}{C.BOLD}GRAPHICAL WEB INTERFACE & RADAR:{C.RESET}{' ' * 35}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}{C.BOLD}[W] 🌐 Open Crazy Clean Web SOC Dashboard in Browser{C.RESET} (Port {soc_port})  {C.CYAN}┃{C.RESET}")
    if is_premium:
        print(f"{C.CYAN}┃{C.RESET}  {C.PURPLE}{C.BOLD}[P] 👑 Launch Brutal Continuous Threat Radar (Active){C.RESET}               {C.CYAN}┃{C.RESET}")
    else:
        print(f"{C.CYAN}┃{C.RESET}  {C.YELLOW}[P] 🔒 Unlock LIGHTNING PREMIUM // Brutal Continuous Radar{C.RESET}         {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}{C.BOLD}INDIVIDUAL TOOLS & AUDITS:{C.RESET}{' ' * 42}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[2]{C.RESET} Run Security & Open Port Vulnerability Audit (Score A-F)       {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[3]{C.RESET} Launch Live Website Threat & Integrity Sentinel (Uptime/SSL)   {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[4]{C.RESET} Start Database Security & Query Rule Sentinel (SQL/NoSQL)      {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[5]{C.RESET} Start Server Access Log Intrusion Detection (IDS)              {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[6]{C.RESET} Reconfigure Web, API, Database & Alert Settings                {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[7]{C.RESET} View Threat Intelligence Audit Log                             {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.CYAN}[8]{C.RESET} Launch Advanced Attack Simulator & Test Suite                   {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.GREEN}[T]{C.RESET} 🧪 Run 13-Module Automated Unit Test Suite                     {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.BLUE}[I]{C.RESET} 🌍 Sync Live Global Threat Intelligence IP Blocklists          {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.YELLOW}[S]{C.RESET} 🔒 SSL/TLS Certificate Manager (HTTPS Proxy)                   {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃{C.RESET}  {C.RED}[0]{C.RESET} Exit LIGHTNING                                                 {C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")


def main():
    C = Colors
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()

    config = load_config()
    if not os.path.exists("lightning_config.json"):
        print(f"{C.GREEN}[+] Welcome to LIGHTNING! Let's set up your initial target configuration.{C.RESET}")
        config = interactive_wizard()

    is_premium = config.get("premium_unlocked", False)

    notifier = SecurityNotifier(
        log_file=config.get("log_file", "lightning_security.log"),
        sound_enabled=config.get("sound_alerts", True),
        webhook_url=config.get("webhook_url", None)
    )

    if "--all" in sys.argv or "--engine" in sys.argv:
        engine = MasterDefenseEngine(config=config, notifier=notifier)
        engine.start()
        return

    while True:
        display_menu(config, is_premium)
        choice = input(f"{C.YELLOW}{C.BOLD}[?] Select an option (Default [1]): {C.RESET}").strip()
        if not choice:
            choice = "1"

        if choice == "1":
            print_header("LAUNCHING MASTER AUTONOMOUS DEFENSE ENGINE")
            engine = MasterDefenseEngine(config=config, notifier=notifier)
            engine.start()
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice.upper() == "W":
            soc_port = config.get("soc_port", 8888)
            print(f"\n{C.CYAN}{C.BOLD}[*] Launching Web SOC Command Center on http://127.0.0.1:{soc_port}...{C.RESET}")
            run_soc_dashboard_server(port=soc_port, notifier=notifier, config=config)
            print(f"{C.GREEN}✔ Web SOC Dashboard is LIVE! Opening in default browser...{C.RESET}\n")
            try:
                webbrowser.open(f"http://127.0.0.1:{soc_port}")
            except Exception:
                pass
            input(f"{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice.upper() == "P":
            if not is_premium:
                if PremiumAuth.prompt_unlock():
                    is_premium = True
                    config["premium_unlocked"] = True
                    save_config(config)
                    print_premium_banner()
                    radar = BrutalContinuousRadar(
                        target_url=config.get("website_url", "http://127.0.0.1:3000"),
                        target_ip=config.get("target_ip", "127.0.0.1"),
                        notifier=notifier
                    )
                    radar.start_radar_loop(interval=15)
            else:
                print_premium_banner()
                radar = BrutalContinuousRadar(
                    target_url=config.get("website_url", "http://127.0.0.1:3000"),
                    target_ip=config.get("target_ip", "127.0.0.1"),
                    notifier=notifier
                )
                radar.start_radar_loop(interval=15)
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "2":
            print_header("SECURITY & OPEN PORT VULNERABILITY AUDIT")
            run_security_audit(
                target_url=config.get("website_url", f"http://{config['target_ip']}:{config['target_port']}"),
                target_ip=config.get("target_ip", "127.0.0.1"),
                target_port=config.get("target_port", 80)
            )
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "3":
            print_header("LAUNCHING LIVE WEBSITE SENTINEL")
            sentinel = WebsiteSentinel(
                target_url=config.get("website_url", f"http://{config['target_ip']}:{config['target_port']}"),
                notifier=notifier,
                check_interval=15
            )
            sentinel.start_monitoring_loop()
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "4":
            print_header("DATABASE SECURITY & QUERY RULE SENTINEL")
            db_sentinel = DatabaseSentinel(
                db_type=config.get("db_engine", "mysql"),
                db_host=config.get("db_host", "127.0.0.1"),
                db_port=config.get("db_port", 3306),
                db_name=config.get("db_name", "app_db"),
                notifier=notifier
            )
            db_sentinel.start_db_audit_loop(check_interval=15)
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "5":
            print_header("SERVER ACCESS LOG IDS WATCHER")
            log_path = input(f"{C.YELLOW}[?] Enter access log file path [access.log]: {C.RESET}").strip() or "access.log"
            watcher = LogWatcherIDS(log_path=log_path, notifier=notifier)
            watcher.start_tailing()
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "6":
            config = interactive_wizard()
            config["premium_unlocked"] = is_premium
            save_config(config)
            notifier.sound_enabled = config.get("sound_alerts", True)
            notifier.log_file = config.get("log_file", "lightning_security.log")
            notifier.webhook_url = config.get("webhook_url", None)

        elif choice == "7":
            view_logs(config.get("log_file", "lightning_security.log"))
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "8":
            import simulate_attacks
            simulate_attacks.main()
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice.upper() == "T":
            print_header("RUNNING 13-MODULE AUTOMATED TEST SUITE")
            from tests.test_lightning import run_tests
            run_tests()
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice.upper() == "I":
            print_header("SYNCING GLOBAL THREAT INTELLIGENCE FEEDS")
            from core.threat_feeds import ThreatIntelligenceFeedManager
            from core.persistence import PersistenceEngine
            pe = PersistenceEngine()
            tf = ThreatIntelligenceFeedManager(persistence=pe)
            tf.refresh_all_feeds()
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice.upper() == "S":
            print_header("SSL/TLS CERTIFICATE MANAGER")
            from core.ssl_manager import SSLCertificateManager
            sm = SSLCertificateManager()
            sm.print_cert_status()
            if not sm.certs_exist():
                gen = input(f"\n{C.YELLOW}[?] Generate self-signed SSL certificate now? (y/n) [y]: {C.RESET}").strip().lower()
                if gen in ("", "y", "yes"):
                    if sm.generate_self_signed_cert():
                        print(f"{C.GREEN}✔ Certificate generated successfully!{C.RESET}")
                    else:
                        print(f"{C.RED}✖ Failed to generate certificate. Install OpenSSL.{C.RESET}")
            input(f"\n{C.DARK_GRAY}Press Enter to return to main menu...{C.RESET}")

        elif choice == "0":
            print(f"\n{C.CYAN}⚡ Thank you for using LIGHTNING.{C.RESET}")
            print(f"{C.GREEN}{C.BOLD}CREATED BY NEXO-TECH BY ALEXANDER. Stay Secure! ⚡{C.RESET}\n")
            sys.exit(0)

        else:
            print(f"{C.RED}[!] Invalid selection. Please enter a valid option.{C.RESET}")
            time.sleep(1)


if __name__ == "__main__":
    main()

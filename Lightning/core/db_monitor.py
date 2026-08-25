"""
=============================================================================
                  LIGHTNING - DATABASE SECURITY & QUERY RULE SENTINEL
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import socket
import datetime
import threading
from typing import Optional, Dict

from banner import Colors
from core.rules import inspect_db_query
from core.notifier import SecurityNotifier

class DatabaseSentinel:
    """Monitors Database Health, Rule Compliance, and Query Safety."""
    def __init__(self, 
                 db_type: str = "sqlite",
                 db_host: str = "127.0.0.1",
                 db_port: int = 3306,
                 db_name: str = "app_db",
                 audit_log_path: Optional[str] = None,
                 notifier: Optional[SecurityNotifier] = None):
        self.db_type = db_type.lower()
        self.db_host = db_host
        self.db_port = db_port
        self.db_name = db_name
        self.audit_log_path = audit_log_path
        self.notifier = notifier
        self.running = False

    def test_connection(self) -> Dict:
        """Tests TCP socket reachability and ping latency for the database server."""
        start_t = time.time()
        try:
            if self.db_type == "sqlite":
                # Check if SQLite file is accessible
                exists = os.path.exists(self.db_name) if self.db_name else True
                return {"status": "ONLINE", "latency_ms": 0, "type": "SQLite (Local File)", "path": self.db_name}

            with socket.create_connection((self.db_host, self.db_port), timeout=3) as sock:
                latency = int((time.time() - start_t) * 1000)
                return {"status": "ONLINE", "latency_ms": latency, "type": self.db_type.upper(), "host": f"{self.db_host}:{self.db_port}"}
        except Exception as e:
            return {"status": "OFFLINE", "error": str(e), "type": self.db_type.upper(), "host": f"{self.db_host}:{self.db_port}"}

    def inspect_query_string(self, query: str, client_ip: str = "127.0.0.1") -> Optional[tuple]:
        """Inspects an executed SQL / DB query against the Database Rule Engine."""
        threat = inspect_db_query(query)
        if threat and self.notifier:
            cat, desc, sev, snip = threat
            self.notifier.alert_threat(
                ip=client_ip,
                method="DB_QUERY",
                path=f"[{self.db_type.upper()}] {self.db_name}",
                category=cat,
                description=desc,
                severity=sev,
                snippet=snip,
                action="DB RULE VIOLATION DETECTED"
            )
            return threat
        return None

    def start_db_audit_loop(self, check_interval: int = 15):
        """Continuously monitors database connectivity and query audit logs."""
        C = Colors
        self.running = True
        print(f"\n{C.GREEN}{C.BOLD}⚡ LIGHTNING DATABASE SECURITY SENTINEL ACTIVE ⚡{C.RESET}")
        print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
        print(f"{C.WHITE}  • Database Engine      : {C.YELLOW}{self.db_type.upper()}{C.RESET}")
        print(f"{C.WHITE}  • Target Host/Port     : {C.CYAN}{self.db_host}:{self.db_port}{C.RESET}")
        print(f"{C.WHITE}  • Target Database      : {C.WHITE}{self.db_name}{C.RESET}")
        print(f"{C.WHITE}  • Database Rule Engine : {C.GREEN}ACTIVE (Drop, Truncate, PrivEsc, Bulk Dump){C.RESET}")
        print(f"{C.WHITE}  • Created By           : {C.GREEN}{C.BOLD}NEXO-TECH BY ALEXANDER{C.RESET}")
        print(f"{C.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")

        check_num = 0
        try:
            while self.running:
                check_num += 1
                conn = self.test_connection()
                now_str = datetime.datetime.now().strftime("%H:%M:%S")

                if conn.get("status") == "ONLINE":
                    status_tag = f"{C.BG_GREEN}{C.BLACK}{C.BOLD} DB CONNECTED {C.RESET}"
                    lat_str = f"{conn.get('latency_ms', 0)}ms"
                else:
                    status_tag = f"{C.BG_RED}{C.WHITE}{C.BOLD} DB OFFLINE {C.RESET}"
                    lat_str = "TIMEOUT"
                    if self.notifier:
                        self.notifier.alert_integrity_issue(
                            title=f"Database Server Connection Lost ({self.db_type.upper()})",
                            details=f"Cannot reach {self.db_host}:{self.db_port} - {conn.get('error', '')}",
                            severity="CRITICAL"
                        )

                print(f"{C.DARK_GRAY}[{now_str}]{C.RESET} {status_tag} │ Engine: {C.YELLOW}{self.db_type.upper():<8}{C.RESET} │ Latency: {C.CYAN}{lat_str:<8}{C.RESET} │ Heartbeat: #{check_num}")
                time.sleep(check_interval)

        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[*] Pausing Database Sentinel...{C.RESET}")

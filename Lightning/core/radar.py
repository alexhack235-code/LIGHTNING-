"""
=============================================================================
                  LIGHTNING - BRUTAL CONTINUOUS RADAR SCANNER
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import socket
import urllib.request
import urllib.parse
import threading
from typing import Dict, List, Optional, Tuple

from banner import Colors
from core.notifier import SecurityNotifier

# Radar Port Sectors
RADAR_PORT_SECTORS = {
    "Sector Alpha (Cloud & Container Daemons)": [
        (2375, "Docker Unencrypted Daemon API", "CRITICAL"),
        (2379, "etcd Distributed Key-Value Store", "CRITICAL"),
        (6443, "Kubernetes API Server", "HIGH"),
        (8500, "HashiCorp Consul Service Mesh", "HIGH"),
        (15672, "RabbitMQ Management Console", "MEDIUM"),
        (9000, "Portainer Container Manager", "HIGH"),
    ],
    "Sector Bravo (Databases, Caches & NoSQL)": [
        (3306, "MySQL Relational Database", "MEDIUM"),
        (5432, "PostgreSQL Database Server", "MEDIUM"),
        (6379, "Redis In-Memory Cache (Unauthenticated Risk)", "CRITICAL"),
        (9200, "Elasticsearch REST Search Cluster", "CRITICAL"),
        (11211, "Memcached Cache Server", "HIGH"),
        (27017, "MongoDB NoSQL Database", "CRITICAL"),
    ],
    "Sector Charlie (Management, Remote & Legacy)": [
        (21, "FTP Unencrypted File Server", "HIGH"),
        (22, "SSH Remote Secure Shell", "LOW"),
        (23, "Telnet Plaintext Terminal", "CRITICAL"),
        (3389, "Windows RDP Remote Desktop", "HIGH"),
        (5900, "VNC Remote Framebuffer Desktop", "HIGH"),
    ]
}

# Radar Secret Endpoints
RADAR_ENDPOINT_TARGETS = [
    ("/actuator/env", "Spring Boot Environment Secrets Leak", "CRITICAL"),
    ("/actuator/heapdump", "Spring Boot Memory Heapdump Exposure", "CRITICAL"),
    ("/swagger-ui.html", "Interactive Swagger API Documentation", "MEDIUM"),
    ("/v2/api-docs", "Swagger OpenAPI Full API Schema Dump", "HIGH"),
    ("/graphql", "GraphQL Query Endpoint", "LOW"),
    ("/metrics", "Prometheus Server Internal Metrics", "MEDIUM"),
    ("/debug/pprof/", "Go Language Runtime Profile Leak", "HIGH"),
    ("/server-status", "Apache Server Real-Time Status Leak", "HIGH"),
    ("/.env", "Full Production Environment Credentials", "CRITICAL"),
    ("/.git/config", "Version Control Repository Metadata", "CRITICAL"),
    ("/api/internal/users", "Unauthenticated Internal User API", "CRITICAL"),
    ("/backup.sql", "Raw Database SQL Backup File", "CRITICAL"),
]

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class BrutalContinuousRadar:
    """Continuous Threat Hunting Radar that sweeps cloud, database, and API surfaces."""
    def __init__(self, target_url: str, target_ip: str, notifier: SecurityNotifier):
        self.target_url = target_url.rstrip("/")
        self.target_ip = target_ip
        self.notifier = notifier
        self.running = False
        self.sweep_count = 0
        self.discovered_exposures = set()

    def _test_tcp_port(self, port: int, timeout: float = 1.0) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((self.target_ip, port)) == 0
        except Exception:
            return False

    def _probe_endpoint(self, path: str) -> Optional[Tuple[str, str, str]]:
        url = f"{self.target_url}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Lightning-Brutal-Radar/3.0 (NEXO-TECH BY ALEXANDER)"}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    content = resp.read(200).decode("utf-8", errors="ignore")
                    if len(content) > 10:
                        return (path, f"Exposed sensitive route ({resp.status} OK)", "CRITICAL")
        except Exception:
            pass
        return None

    def run_radar_sweep(self):
        """Executes a single comprehensive radar sweep cycle."""
        C = Colors
        self.sweep_count += 1
        now_str = time.strftime("%H:%M:%S")

        # 1. Sweep Port Sectors
        for sector_name, ports in RADAR_PORT_SECTORS.items():
            for port, desc, severity in ports:
                if self._test_tcp_port(port):
                    exposure_key = f"port:{port}"
                    if exposure_key not in self.discovered_exposures:
                        self.discovered_exposures.add(exposure_key)
                        self.notifier.alert_threat(
                            ip=self.target_ip,
                            method="RADAR_SWEEP",
                            path=f"Port {port} ({desc})",
                            category="Attack Surface Discovery",
                            description=f"Exposed {sector_name}",
                            severity=severity,
                            snippet=f"TCP Port {port} is OPEN & ACCESSIBLE",
                            action="FLAGGED BY RADAR"
                        )

        # 2. Sweep Secret Endpoints
        for path, desc, severity in RADAR_ENDPOINT_TARGETS:
            res = self._probe_endpoint(path)
            if res:
                exposure_key = f"endpoint:{path}"
                if exposure_key not in self.discovered_exposures:
                    self.discovered_exposures.add(exposure_key)
                    self.notifier.alert_threat(
                        ip=self.target_ip,
                        method="RADAR_PROBE",
                        path=path,
                        category="Internal Asset Exposure",
                        description=desc,
                        severity=severity,
                        snippet=f"Live endpoint: {self.target_url}{path}",
                        action="URGENT: RESTRICT ACCESS"
                    )

    def start_radar_loop(self, interval: int = 25):
        """Runs the continuous radar sweeping loop with terminal visual telemetry."""
        C = Colors
        self.running = True

        print(f"\n{C.PURPLE}{C.BOLD}⚡ LIGHTNING BRUTAL CONTINUOUS RADAR ENGAGED ⚡{C.RESET}")
        print(f"{C.PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
        print(f"{C.WHITE}  • Target Scope         : {C.YELLOW}{self.target_url} ({self.target_ip}){C.RESET}")
        print(f"{C.WHITE}  • Radar Mode           : {C.RED}{C.BOLD}BRUTAL THREAT HUNTER // ZERO-TOLERANCE{C.RESET}")
        print(f"{C.WHITE}  • Continuous Sweep     : {C.CYAN}Every {interval} seconds across 4 sectors{C.RESET}")
        print(f"{C.WHITE}  • Surface Intelligence : {C.GREEN}ACTIVE (Cloud, DB, Container, API Secret Radar){C.RESET}")
        print(f"{C.WHITE}  • Created By           : {C.GREEN}{C.BOLD}NEXO-TECH BY ALEXANDER{C.RESET}")
        print(f"{C.PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")

        try:
            while self.running:
                for i in range(15):
                    spin = SPINNER[i % len(SPINNER)]
                    now_str = time.strftime("%H:%M:%S")
                    sys.stdout.write(f"\r{C.PURPLE}[{now_str}] {C.CYAN}{spin} [ ⚡ RADAR SWEEPING SECTORS ⚡ ]{C.RESET} Target: {C.YELLOW}{self.target_ip}{C.RESET} │ Sweep #{self.sweep_count} │ Surface Alerts: {C.RED}{len(self.discovered_exposures)}{C.RESET}  ")
                    sys.stdout.flush()
                    time.sleep(0.15)

                self.run_radar_sweep()
                now_str = time.strftime("%H:%M:%S")
                print(f"\r{C.DARK_GRAY}[{now_str}]{C.RESET} {C.GREEN}✔ RADAR SWEEP #{self.sweep_count} COMPLETED{C.RESET} │ Surface Exposures Monitored: {C.YELLOW}{len(self.discovered_exposures)}{C.RESET} │ Target Responding OK     ")
                time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[*] Pausing Brutal Continuous Radar...{C.RESET}")
            self.running = False

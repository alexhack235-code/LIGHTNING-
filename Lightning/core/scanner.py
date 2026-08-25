"""
=============================================================================
                  LIGHTNING - SECURITY AUDIT & PORT SCANNER
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import socket
import ssl
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple

from banner import Colors

COMMON_PORTS = [
    (21, "FTP", "File Transfer Protocol (often insecure if unencrypted)"),
    (22, "SSH", "Secure Shell Remote Access"),
    (23, "Telnet", "Unencrypted Remote Terminal (High Risk)"),
    (25, "SMTP", "Mail Transfer Protocol"),
    (53, "DNS", "Domain Name System"),
    (80, "HTTP", "Standard Web Server"),
    (443, "HTTPS", "Encrypted Web Server (SSL/TLS)"),
    (3000, "Node.js / React", "Common Web App Development Server"),
    (3306, "MySQL", "MySQL Database Server (Should not be publicly exposed)"),
    (3389, "RDP", "Windows Remote Desktop"),
    (5000, "Flask / FastAPI", "Python Web Framework Port"),
    (5432, "PostgreSQL", "PostgreSQL Database Server"),
    (6379, "Redis", "Redis Cache / Data Store (High Risk if unauthenticated)"),
    (8000, "HTTP-Alt / Django", "Alternative Web Server"),
    (8080, "HTTP-Proxy / Tomcat", "Common Web Proxy / Java App Server"),
    (8443, "HTTPS-Alt", "Alternative HTTPS Port"),
    (9200, "Elasticsearch", "Elasticsearch REST API"),
    (27017, "MongoDB", "MongoDB NoSQL Database"),
]

def scan_port(host: str, port: int, timeout: float = 1.2) -> bool:
    """Tests if a specific TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def run_security_audit(target_url: str, target_ip: str, target_port: int = 80):
    """Performs an extensive security audit on the target website and IP."""
    C = Colors
    print(f"\n{C.CYAN}{C.BOLD}⚡ INITIATING LIGHTNING COMPREHENSIVE SECURITY AUDIT ⚡{C.RESET}")
    print(f"{C.DARK_GRAY}Target: {target_url} | Host IP: {target_ip} | Primary Port: {target_port}{C.RESET}")
    print(f"{C.PURPLE}Created by NEXO-TECH BY ALEXANDER{C.RESET}\n")

    score = 100
    findings = []

    # 1. Port Scanning
    print(f"{C.YELLOW}[*] Scanning {len(COMMON_PORTS)} critical service and database ports on {target_ip}...{C.RESET}")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, target_ip, p): (p, name, desc) for p, name, desc in COMMON_PORTS}
        for future in futures:
            p, name, desc = futures[future]
            if future.result():
                open_ports.append((p, name, desc))

    if open_ports:
        print(f"{C.GREEN}[+] Discovered {len(open_ports)} open port(s):{C.RESET}")
        for p, name, desc in open_ports:
            risk_color = C.RED if p in (21, 23, 3306, 5432, 6379, 27017, 9200) else C.CYAN
            print(f"    • Port {p:<5} ({name:<18}) - {risk_color}{desc}{C.RESET}")
            if p in (3306, 5432, 6379, 27017, 9200):
                score -= 15
                findings.append((f"Database / Internal Service Port {p} ({name}) is publicly exposed!", "CRITICAL"))
            elif p in (21, 23):
                score -= 10
                findings.append((f"Legacy unencrypted protocol open on Port {p} ({name})", "HIGH"))
    else:
        print(f"{C.GREEN}[✔] No unshielded management or database ports exposed directly.{C.RESET}")

    # 2. HTTP Security Headers Audit
    print(f"\n{C.YELLOW}[*] Inspecting HTTP Security Headers on {target_url}...{C.RESET}")
    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "Mozilla/5.0 (Lightning-Audit/2.5 by NEXO-TECH BY ALEXANDER)"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            # Check Server Banner Leak
            if "server" in headers:
                server_val = headers["server"]
                score -= 5
                findings.append((f"Information Leak: 'Server' banner exposed: {server_val}", "MEDIUM"))
            
            # Check X-Powered-By Leak
            if "x-powered-by" in headers:
                powered_val = headers["x-powered-by"]
                score -= 5
                findings.append((f"Information Leak: 'X-Powered-By' header exposed: {powered_val}", "MEDIUM"))

            # Check Strict-Transport-Security (HSTS)
            if "strict-transport-security" not in headers:
                score -= 10
                findings.append(("Missing 'Strict-Transport-Security' (HSTS) header", "HIGH"))
            
            # Check Content-Security-Policy (CSP)
            if "content-security-policy" not in headers:
                score -= 15
                findings.append(("Missing 'Content-Security-Policy' (CSP) header - Vulnerable to XSS/Injection", "HIGH"))

            # Check X-Frame-Options
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                score -= 10
                findings.append(("Missing 'X-Frame-Options' header - Vulnerable to Clickjacking", "MEDIUM"))

            # Check X-Content-Type-Options
            if "x-content-type-options" not in headers:
                score -= 5
                findings.append(("Missing 'X-Content-Type-Options: nosniff' header - MIME-sniffing risk", "LOW"))

    except Exception as e:
        print(f"{C.RED}[!] Could not complete HTTP header inspection: {e}{C.RESET}")
        score -= 20
        findings.append((f"Web server failed connection test: {e}", "HIGH"))

    # Determine Grade
    score = max(0, score)
    if score >= 90:
        grade = "A+"
        grade_color = C.GREEN
    elif score >= 80:
        grade = "A"
        grade_color = C.GREEN
    elif score >= 70:
        grade = "B"
        grade_color = C.YELLOW
    elif score >= 55:
        grade = "C"
        grade_color = C.YELLOW
    elif score >= 40:
        grade = "D"
        grade_color = C.RED
    else:
        grade = "F"
        grade_color = C.RED

    # Print Final Audit Summary Box
    print(f"\n{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
    print(f"{C.CYAN}┃                ⚡ LIGHTNING SECURITY AUDIT REPORT ⚡                ┃{C.RESET}")
    print(f"{C.CYAN}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}SECURITY SCORE : {grade_color}{C.BOLD}{score}/100 (GRADE: {grade}){C.RESET}{' ' * (37 - len(str(score)) - len(grade))}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}OPEN PORTS     : {C.YELLOW}{len(open_ports)} detected{' ' * (45 - len(str(len(open_ports))))}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}VULNERABILITIES: {C.RED if findings else C.GREEN}{len(findings)} finding(s){' ' * (44 - len(str(len(findings))))}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    if findings:
        print(f"{C.CYAN}┃ {C.YELLOW}{C.BOLD}Security Findings & Recommendations:{C.RESET}{' ' * 32}{C.CYAN}┃{C.RESET}")
        for item, sev in findings:
            sev_tag = f"{C.RED}[{sev}]{C.RESET}" if sev in ("CRITICAL", "HIGH") else f"{C.YELLOW}[{sev}]{C.RESET}"
            print(f"{C.CYAN}┃{C.RESET}  • {sev_tag} {C.WHITE}{item[:52]:<52}{C.RESET} {C.CYAN}┃{C.RESET}")
    else:
        print(f"{C.CYAN}┃ {C.GREEN}✔ Target has outstanding baseline security posture!{' ' * 16}┃{C.RESET}")
    print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

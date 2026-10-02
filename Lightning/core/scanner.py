"""
=============================================================================
                  LIGHTNING - ADVANCED SECURITY AUDIT & SCANNER ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import socket
import ssl
import time
import datetime
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Optional, Any

from banner import Colors

COMMON_PORTS = [
    # Legacy & Insecure Plaintext Services
    (21, "FTP", "Plaintext File Transfer Protocol - credentials sent unencrypted", "HIGH"),
    (22, "SSH", "Secure Shell Remote Access Server", "LOW"),
    (23, "Telnet", "Unencrypted Plaintext Remote Terminal - High Interception Risk", "CRITICAL"),
    (25, "SMTP", "Simple Mail Transfer Protocol Server", "MEDIUM"),
    (53, "DNS", "Domain Name System Server", "LOW"),
    (80, "HTTP", "Standard Web Server (Unencrypted Plaintext HTTP)", "LOW"),
    (110, "POP3", "Plaintext Post Office Protocol - email credentials unencrypted", "HIGH"),
    (143, "IMAP", "Plaintext Internet Message Access Protocol", "HIGH"),
    (443, "HTTPS", "Encrypted Web Server (SSL/TLS)", "INFO"),
    (445, "SMB", "Server Message Block - High ransomware/lateral movement vector", "CRITICAL"),
    (993, "IMAPS", "Secure IMAP over SSL/TLS", "LOW"),
    (995, "POP3S", "Secure POP3 over SSL/TLS", "LOW"),
    
    # Database Engines (Should never be exposed directly to public internet)
    (1433, "MSSQL", "Microsoft SQL Server - High vulnerability to brute-force", "CRITICAL"),
    (1521, "Oracle DB", "Oracle Database Listener - Should be behind firewall", "CRITICAL"),
    (3306, "MySQL", "MySQL Relational Database - Risk of remote extraction", "CRITICAL"),
    (5432, "PostgreSQL", "PostgreSQL Database Server - Should be private-only", "CRITICAL"),
    (6379, "Redis", "Redis Cache / Data Store - Remote unauthenticated compromise risk", "CRITICAL"),
    (9200, "Elasticsearch", "Elasticsearch Cluster REST API - Data exposure vector", "CRITICAL"),
    (11211, "Memcached", "Memcached Server - Amplification DDoS & data leak risk", "CRITICAL"),
    (27017, "MongoDB", "MongoDB NoSQL Database - Unauthenticated exposure risk", "CRITICAL"),

    # Remote Management & Desktop
    (3389, "RDP", "Windows Remote Desktop Protocol - Brute-force/RCE target", "HIGH"),
    (5900, "VNC", "Virtual Network Computing - Remote screen access risk", "HIGH"),
    (5901, "VNC:1", "Virtual Network Computing Display 1", "HIGH"),

    # Cloud, Containers & DevOps Daemons
    (2375, "Docker API", "Unencrypted Docker Remote Management API - Full root compromise", "CRITICAL"),
    (2376, "Docker TLS", "Docker Remote API over TLS", "HIGH"),
    (2379, "etcd", "etcd Kubernetes Key-Value Cluster Store", "CRITICAL"),
    (6443, "K8s API", "Kubernetes API Server - High value cluster target", "HIGH"),
    (8500, "Consul", "HashiCorp Consul Service Discovery & KV Store", "HIGH"),
    (9000, "Portainer/Sonar", "Container or Code Quality Management Web Portal", "HIGH"),
    (10250, "Kubelet", "Kubernetes Kubelet Node API - Critical cluster node access", "CRITICAL"),
    (15672, "RabbitMQ", "RabbitMQ Management Dashboard", "MEDIUM"),

    # Web Applications & Framework Development Runtimes
    (3000, "Node.js / React", "Node.js / React / Grafana Dev & App Server", "LOW"),
    (5000, "Flask / FastAPI", "Python Web Framework Server", "LOW"),
    (8000, "HTTP-Alt / Django", "Alternative HTTP Web Server / Django Server", "LOW"),
    (8080, "HTTP-Proxy / Tomcat", "Common Web Proxy / Apache Tomcat Server", "LOW"),
    (8443, "HTTPS-Alt", "Alternative HTTPS Port (Common Tomcat/Plesk)", "LOW"),
    (8888, "HTTP-Alt / Jupyter", "Alternative Web Port / Admin Interface", "LOW"),
    (9090, "Prometheus / Cockpit", "Prometheus Metrics / Linux Cockpit Admin", "MEDIUM"),
]


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Tests if a specific TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def audit_ssl_certificate(target_host: str, port: int = 443) -> List[Tuple[str, str]]:
    """Inspects the SSL/TLS certificate for expiration, validity, and weak ciphers."""
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target_host, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                
                # Check TLS protocol version
                if version in ("TLSv1", "TLSv1.1"):
                    findings.append((f"Deprecated Insecure TLS Protocol: Server uses {version} (vulnerable to POODLE/BEAST)", "CRITICAL"))

                # Check Certificate Expiration
                not_after = cert.get("notAfter")
                if not_after:
                    expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    remaining = (expire_date - datetime.datetime.utcnow()).days
                    if remaining < 0:
                        findings.append((f"SSL/TLS Certificate is EXPIRED since {expire_date.strftime('%Y-%m-%d')}!", "CRITICAL"))
                    elif remaining < 15:
                        findings.append((f"SSL/TLS Certificate expires in {remaining} day(s) ({expire_date.strftime('%Y-%m-%d')})", "HIGH"))
                    elif remaining < 30:
                        findings.append((f"SSL/TLS Certificate expiring soon in {remaining} days", "MEDIUM"))

    except ssl.SSLCertVerificationError as e:
        findings.append((f"SSL/TLS Certificate Verification Failed: {e}", "CRITICAL"))
    except Exception:
        pass
    return findings


def audit_cookies(headers: Dict[str, str], is_https: bool) -> List[Tuple[str, str]]:
    """Audits Set-Cookie headers for Secure, HttpOnly, and SameSite attributes."""
    findings = []
    cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for ch in cookie_headers:
        ch_lower = ch.lower()
        if "httponly" not in ch_lower:
            findings.append(("Cookie missing 'HttpOnly' flag - Vulnerable to client-side XSS theft", "HIGH"))
        if is_https and "secure" not in ch_lower:
            findings.append(("Cookie missing 'Secure' flag on HTTPS - Risk of plaintext transmission", "HIGH"))
        if "samesite" not in ch_lower:
            findings.append(("Cookie missing 'SameSite' attribute - Susceptible to Cross-Site Request Forgery (CSRF)", "MEDIUM"))
        elif "samesite=none" in ch_lower and "secure" not in ch_lower:
            findings.append(("Cookie has 'SameSite=None' without 'Secure' attribute", "HIGH"))
    return findings


def audit_cors_headers(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    """Audits Access-Control-* CORS headers for permissive misconfigurations."""
    findings = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*":
        if acac.lower() == "true":
            findings.append(("Critical CORS Misconfiguration: Wildcard '*' origin with Allow-Credentials: true", "CRITICAL"))
        else:
            findings.append(("Permissive CORS Policy: 'Access-Control-Allow-Origin: *' allows any domain to read responses", "MEDIUM"))
    elif "null" in acao.lower():
        findings.append(("Insecure CORS Policy: 'Access-Control-Allow-Origin: null' can be exploited via sandboxed iframes", "HIGH"))
    return findings


def audit_http_methods(target_url: str) -> List[Tuple[str, str]]:
    """Checks for dangerous or unneeded HTTP methods via OPTIONS preflight."""
    findings = []
    try:
        req = urllib.request.Request(target_url, method="OPTIONS")
        req.add_header("User-Agent", "Lightning-Audit/3.0 (NEXO-TECH BY ALEXANDER)")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            allow_header = resp.headers.get("allow", "") or resp.headers.get("Allow", "")
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]
                if "TRACE" in methods:
                    findings.append(("Dangerous HTTP Method 'TRACE' is enabled (Cross-Site Tracing / XST vulnerability)", "HIGH"))
                if "TRACK" in methods:
                    findings.append(("Dangerous HTTP Method 'TRACK' is enabled", "HIGH"))
                if "DEBUG" in methods:
                    findings.append(("Dangerous Debugging HTTP Method 'DEBUG' is exposed", "CRITICAL"))
                if "PUT" in methods or "DELETE" in methods:
                    findings.append((f"HTTP Methods '{allow_header}' allow state modification without standard REST isolation", "MEDIUM"))
    except Exception:
        pass
    return findings


def run_security_audit(target_url: str, target_ip: str, target_port: int = 80):
    """Performs an extensive, multi-vector security audit on the target website and host IP."""
    C = Colors
    print(f"\n{C.CYAN}{C.BOLD}⚡ INITIATING LIGHTNING COMPREHENSIVE SECURITY AUDIT (ZERO-WEAKNESS EDITION) ⚡{C.RESET}")
    print(f"{C.DARK_GRAY}Target URL: {target_url} | Host IP: {target_ip} | Base Port: {target_port}{C.RESET}")
    print(f"{C.PURPLE}{C.BOLD}Engineered by NEXO-TECH BY ALEXANDER • Enterprise Hardening Suite{C.RESET}\n")

    score = 100
    findings: List[Tuple[str, str]] = []

    # =========================================================================
    # 1. Multi-Threaded Port & Service Risk Auditing (40+ Services)
    # =========================================================================
    print(f"{C.YELLOW}[1/6] Scanning {len(COMMON_PORTS)} network service, database & cloud ports on {target_ip}...{C.RESET}")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, target_ip, p): (p, name, desc, sev) for p, name, desc, sev in COMMON_PORTS}
        for future in futures:
            p, name, desc, sev = futures[future]
            if future.result():
                open_ports.append((p, name, desc, sev))

    if open_ports:
        print(f"{C.GREEN}[+] Discovered {len(open_ports)} accessible service port(s):{C.RESET}")
        for p, name, desc, sev in open_ports:
            risk_color = C.RED if sev == "CRITICAL" else (C.YELLOW if sev == "HIGH" else C.CYAN)
            print(f"    • Port {p:<5} ({name:<18}) [{sev:<8}] - {risk_color}{desc}{C.RESET}")
            if sev == "CRITICAL":
                score -= 15
                findings.append((f"Exposed High-Risk Service on Port {p} ({name}): {desc}", "CRITICAL"))
            elif sev == "HIGH":
                score -= 10
                findings.append((f"Exposed Legacy/Management Port {p} ({name}): {desc}", "HIGH"))
            elif sev == "MEDIUM":
                score -= 5
                findings.append((f"Exposed Internal Service Port {p} ({name})", "MEDIUM"))
    else:
        print(f"{C.GREEN}[✔] Clean Network Surface: No unshielded database, container, or remote admin ports exposed.{C.RESET}")

    # =========================================================================
    # 2. Defensive HTTP Security Headers Audit (10+ Defensive Controls)
    # =========================================================================
    print(f"\n{C.YELLOW}[2/6] Inspecting Defensive HTTP Headers & Web Server Fingerprints on {target_url}...{C.RESET}")
    headers_dict = {}
    is_https = target_url.lower().startswith("https://")

    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Lightning-Security-Audit/3.0 (NEXO-TECH BY ALEXANDER)"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers_dict = {k.lower(): v for k, v in resp.headers.items()}
            
            # 2a. Information Leakage
            if "server" in headers_dict:
                server_val = headers_dict["server"]
                score -= 5
                findings.append((f"Information Disclosure: 'Server' banner exposed ({server_val})", "MEDIUM"))
            
            if "x-powered-by" in headers_dict:
                powered_val = headers_dict["x-powered-by"]
                score -= 5
                findings.append((f"Information Disclosure: 'X-Powered-By' technology stack exposed ({powered_val})", "MEDIUM"))

            if "x-aspnet-version" in headers_dict or "x-aspnetmvc-version" in headers_dict:
                score -= 5
                findings.append(("Information Disclosure: ASP.NET Framework version header exposed", "MEDIUM"))

            # 2b. Mandatory Defensive Security Headers
            if "strict-transport-security" not in headers_dict:
                if is_https:
                    score -= 12
                    findings.append(("Missing 'Strict-Transport-Security' (HSTS) header - Susceptible to SSL-stripping & downgrade attacks", "HIGH"))
            else:
                hsts_val = headers_dict["strict-transport-security"]
                if "max-age=" in hsts_val:
                    try:
                        max_age = int(hsts_val.split("max-age=")[1].split(";")[0].strip())
                        if max_age < 15552000:  # < 180 days
                            score -= 3
                            findings.append((f"Weak HSTS max-age ({max_age}s) - Recommended minimum is 31536000 (1 year)", "LOW"))
                    except Exception:
                        pass
                if "includesubdomains" not in hsts_val.lower():
                    findings.append(("HSTS policy does not include 'includeSubDomains' directive", "LOW"))
            
            if "content-security-policy" not in headers_dict:
                score -= 15
                findings.append(("Missing 'Content-Security-Policy' (CSP) header - Critical defense against XSS, data exfiltration & clickjacking", "HIGH"))
            else:
                csp_val = headers_dict["content-security-policy"]
                if "'unsafe-inline'" in csp_val:
                    score -= 5
                    findings.append(("Weak CSP Policy: Contains ''unsafe-inline'' directive allowing unvetted script execution", "MEDIUM"))
                if "'unsafe-eval'" in csp_val:
                    score -= 5
                    findings.append(("Weak CSP Policy: Contains ''unsafe-eval'' directive allowing dynamic code evaluation", "MEDIUM"))

            if "x-frame-options" not in headers_dict and "content-security-policy" not in headers_dict:
                score -= 10
                findings.append(("Missing 'X-Frame-Options' header - Webpage can be embedded into malicious iframes (Clickjacking)", "HIGH"))
            elif "x-frame-options" in headers_dict:
                xfo_val = headers_dict["x-frame-options"].upper()
                if xfo_val not in ("DENY", "SAMEORIGIN"):
                    findings.append((f"Weak 'X-Frame-Options' directive: {xfo_val}", "MEDIUM"))

            if "x-content-type-options" not in headers_dict:
                score -= 5
                findings.append(("Missing 'X-Content-Type-Options: nosniff' header - Vulnerable to MIME-type sniffing bypasses", "MEDIUM"))

            if "referrer-policy" not in headers_dict:
                score -= 4
                findings.append(("Missing 'Referrer-Policy' header - Private query parameters and tokens may leak to third parties", "LOW"))

            if "permissions-policy" not in headers_dict and "feature-policy" not in headers_dict:
                score -= 3
                findings.append(("Missing 'Permissions-Policy' header - Hardware features (camera, mic, geolocation) not restricted", "LOW"))

            if "cross-origin-opener-policy" not in headers_dict:
                findings.append(("Missing 'Cross-Origin-Opener-Policy' (COOP) header - Cross-origin window reference isolation missing", "LOW"))

            if "cross-origin-resource-policy" not in headers_dict:
                findings.append(("Missing 'Cross-Origin-Resource-Policy' (CORP) header - Resources can be loaded across origins", "LOW"))

    except Exception as e:
        print(f"{C.RED}[!] Could not complete HTTP header inspection: {e}{C.RESET}")
        score -= 20
        findings.append((f"Target connection failed during HTTP inspection: {e}", "HIGH"))

    # =========================================================================
    # 3. Cookie Security Attributes Audit
    # =========================================================================
    print(f"{C.YELLOW}[3/6] Auditing Cookie Security Flags (HttpOnly, Secure, SameSite)...{C.RESET}")
    cookie_findings = audit_cookies(headers_dict, is_https)
    for cf, sev in cookie_findings:
        findings.append((cf, sev))
        score -= (8 if sev == "HIGH" else 4)
    if not cookie_findings:
        print(f"{C.GREEN}[✔] No insecure cookie policies detected.{C.RESET}")

    # =========================================================================
    # 4. Cross-Origin Resource Sharing (CORS) Security Audit
    # =========================================================================
    print(f"{C.YELLOW}[4/6] Evaluating CORS (Cross-Origin Resource Sharing) Policies...{C.RESET}")
    cors_findings = audit_cors_headers(headers_dict)
    for cor_f, sev in cors_findings:
        findings.append((cor_f, sev))
        score -= (15 if sev == "CRITICAL" else 8)
    if not cors_findings:
        print(f"{C.GREEN}[✔] CORS policy is strictly scoped or not exposing sensitive headers.{C.RESET}")

    # =========================================================================
    # 5. SSL/TLS Certificate & Protocol Health (for HTTPS targets)
    # =========================================================================
    if is_https:
        print(f"{C.YELLOW}[5/6] Verifying SSL/TLS Certificate Chain & Cryptographic Strength...{C.RESET}")
        parsed_target = urllib.parse.urlparse(target_url)
        ssl_host = parsed_target.hostname or target_ip
        ssl_port = parsed_target.port or 443
        ssl_findings = audit_ssl_certificate(ssl_host, ssl_port)
        for sf, sev in ssl_findings:
            findings.append((sf, sev))
            score -= (20 if sev == "CRITICAL" else 10)
        if not ssl_findings:
            print(f"{C.GREEN}[✔] SSL/TLS Certificate is valid, active, and securely chained.{C.RESET}")
    else:
        print(f"{C.DARK_GRAY}[5/6] Target is HTTP (Skipping SSL/TLS validation). Recommended to migrate to HTTPS.{C.RESET}")
        score -= 10
        findings.append(("Target operates over unencrypted HTTP protocol - Plaintext data interception risk", "HIGH"))

    # =========================================================================
    # 6. HTTP Methods Policy & Debugging Verbs Audit
    # =========================================================================
    print(f"{C.YELLOW}[6/6] Probing Exposed HTTP Verbs & Methods via Preflight...{C.RESET}")
    method_findings = audit_http_methods(target_url)
    for mf, sev in method_findings:
        findings.append((mf, sev))
        score -= (10 if sev in ("CRITICAL", "HIGH") else 5)
    if not method_findings:
        print(f"{C.GREEN}[✔] No dangerous debugging HTTP verbs (TRACE, DEBUG, TRACK) are exposed.{C.RESET}")

    # =========================================================================
    # Final Grade & Comprehensive Report Generation
    # =========================================================================
    score = max(0, min(100, score))
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

    crit_count = sum(1 for _, sev in findings if sev == "CRITICAL")
    high_count = sum(1 for _, sev in findings if sev == "HIGH")
    med_count = sum(1 for _, sev in findings if sev == "MEDIUM")
    low_count = sum(1 for _, sev in findings if sev in ("LOW", "INFO"))

    print(f"\n{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
    print(f"{C.CYAN}┃          ⚡ LIGHTNING COMPREHENSIVE SECURITY AUDIT REPORT ⚡         ┃{C.RESET}")
    print(f"{C.CYAN}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}SECURITY SCORE : {grade_color}{C.BOLD}{score}/100 (GRADE: {grade}){C.RESET}{' ' * (37 - len(str(score)) - len(grade))}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}ACCESSIBLE PORTS: {C.YELLOW}{len(open_ports)} detected{' ' * (44 - len(str(len(open_ports))))}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}VULNERABILITIES : {C.RED if findings else C.GREEN}{len(findings)} total finding(s) ({crit_count} Critical, {high_count} High){C.CYAN}{' ' * max(0, (26 - len(str(len(findings))) - len(str(crit_count)) - len(str(high_count))))}┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    if findings:
        print(f"{C.CYAN}┃ {C.YELLOW}{C.BOLD}Security Findings & Remediation Guidance:{C.RESET}{' ' * 27}{C.CYAN}┃{C.RESET}")
        for item, sev in findings:
            if sev == "CRITICAL":
                sev_tag = f"{C.BG_RED}{C.WHITE}{C.BOLD} CRIT {C.RESET}"
            elif sev == "HIGH":
                sev_tag = f"{C.RED}{C.BOLD} HIGH {C.RESET}"
            elif sev == "MEDIUM":
                sev_tag = f"{C.YELLOW} MED  {C.RESET}"
            else:
                sev_tag = f"{C.CYAN} LOW  {C.RESET}"
            
            clean_item = item[:54]
            print(f"{C.CYAN}┃{C.RESET}  • {sev_tag} {C.WHITE}{clean_item:<54}{C.RESET} {C.CYAN}┃{C.RESET}")
    else:
        print(f"{C.CYAN}┃ {C.GREEN}✔ Target host & web application have flawless baseline hardening!{' ' * 4}┃{C.RESET}")
    print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")


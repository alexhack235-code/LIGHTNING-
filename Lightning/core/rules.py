"""
=============================================================================
                  LIGHTNING - ADVANCED THREAT DETECTION & RULE ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import re
import urllib.parse
from typing import Tuple, Optional, List, Dict

# Attack Categories & Threat Signatures (Web, API & Database)
ATTACK_SIGNATURES: Dict[str, List[Tuple[str, str, str]]] = {
    "SQL Injection (SQLi)": [
        (r"(?i)(\bUNION\b\s+(?:ALL\s+)?SELECT\b)", "UNION SELECT extraction attempt", "CRITICAL"),
        (r"(?i)(\bSELECT\b[\s\S]+\bFROM\b[\s\S]+\bWHERE\b)", "SQL Data query extraction", "HIGH"),
        (r"(?i)('\s*OR\s*['\"\d]+\s*=\s*['\"\d]+)", "Classic boolean OR SQL bypass", "CRITICAL"),
        (r"(?i)(\bOR\s+1\s*=\s*1\b|\bAND\s+1\s*=\s*1\b)", "Tautology SQL injection", "CRITICAL"),
        (r"(?i)(\bSLEEP\s*\(\s*\d+\s*\)|\bBENCHMARK\s*\(\s*\d+)", "Time-based blind SQL injection", "CRITICAL"),
        (r"(?i)(\bINFORMATION_SCHEMA\b|\bSYS\.TABLES\b|\bPG_CATALOG\b)", "Database schema reconnaissance", "HIGH"),
        (r"(?i)(--\s*$|/\*.*?\*/|;\s*DROP\s+TABLE|;\s*DELETE\s+FROM)", "SQL query termination / destructive payload", "CRITICAL"),
        (r"(?i)(\bWAITFOR\s+DELAY\s+'[\d:]+')", "MSSQL Time-based injection", "CRITICAL"),
        (r"(?i)(\bLOAD_FILE\s*\(|\bINTO\s+OUTFILE\b)", "SQL Local file read/write attempt", "CRITICAL"),
        (r"(?i)(\bEXTRACTVALUE\s*\(|\bUPDATEXML\s*\()", "Error-based XML SQL injection", "CRITICAL"),
        (r"(?i)(\bxp_cmdshell\b|\bsp_executesql\b)", "MSSQL Dangerous procedure execution", "CRITICAL"),
    ],

    "NoSQL Injection (MongoDB / Document DB)": [
        (r"(?i)(\$gt|\$gte|\$ne|\$nin|\$in|\$where|\$regex|\$exists|\$expr|\$jsonSchema)", "MongoDB operator injection", "CRITICAL"),
        (r"(?i)(this\.[a-zA-Z0-9_]+\s*==|return\s+true\s*;)", "MongoDB JavaScript $where clause injection", "CRITICAL"),
    ],
    
    "Cross-Site Scripting (XSS)": [
        (r"(?i)(<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>)", "Script tag injection", "CRITICAL"),
        (r"(?i)(<\s*script[^>]*>)", "Unclosed script tag injection", "HIGH"),
        (r"(?i)(javascript\s*:[\s\S]*)", "JavaScript pseudo-protocol payload", "CRITICAL"),
        (r"(?i)(\bon(?:error|load|mouseover|click|focus|blur|submit|keydown|mousein)\s*=\s*['\"].*?['\"])", "Inline event handler XSS", "HIGH"),
        (r"(?i)(<\s*(?:img|iframe|svg|body|embed|object|input|video|audio)[^>]+on\w+\s*=)", "HTML tag with malicious event handler", "HIGH"),
        (r"(?i)(document\.(?:cookie|location|domain|write))", "DOM tampering / Cookie theft vector", "HIGH"),
        (r"(?i)(\beval\s*\(|\bFunction\s*\(|\bwindow\.setTimeout\s*\()", "Dynamic script execution (eval)", "HIGH"),
        (r"(?i)(<\s*svg[^>]*onload\s*=)", "SVG onload vector", "HIGH"),
        (r"(?i)(data:text/html[\s\S]*base64)", "Data URI XSS injection", "HIGH"),
    ],
    
    "Remote Code Execution (RCE) / Command Injection": [
        (r"(?i)(;\s*(?:cat|ls|dir|whoami|id|uname|netstat|tasklist|powershell|cmd|sh|bash)\b)", "Shell command chaining (;)", "CRITICAL"),
        (r"(?i)(\|\s*(?:cat|ls|dir|whoami|id|uname|powershell|cmd|sh|bash)\b)", "Shell command piping (|)", "CRITICAL"),
        (r"(?i)(`\s*(?:cat|ls|dir|whoami|id|powershell|cmd|sh|bash).*?`)", "Backtick command substitution", "CRITICAL"),
        (r"(?i)(\$\(\s*(?:cat|ls|dir|whoami|id|powershell|sh|bash).*?\))", "Command substitution $()", "CRITICAL"),
        (r"(?i)(\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\()", "PHP Dangerous system execution functions", "CRITICAL"),
        (r"(?i)(powershell(?:\.exe)?\s+(?:-[eE]n?c?|-c(?:ommand)?))", "PowerShell execution attempt", "CRITICAL"),
        (r"(?i)(\bwget\b|\bcurl\b)[\s\S]*?(?:\|\s*(?:bash|sh|cmd|powershell))", "Remote script download and execution", "CRITICAL"),
        (r"(?i)(\b(?:/bin/bash|/bin/sh|cmd\.exe|powershell\.exe)\b)", "Direct shell invocation", "CRITICAL"),
    ],
    
    "Path Traversal / Local File Inclusion (LFI)": [
        (r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e\/)", "Directory traversal sequence (../)", "CRITICAL"),
        (r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/etc/group)", "Linux sensitive configuration access", "CRITICAL"),
        (r"(?i)(c:\\windows\\system32|c:/windows/win\.ini|c:\\boot\.ini)", "Windows system file access", "CRITICAL"),
        (r"(?i)(php://filter|php://input|data://text/plain|file://|expect://)", "PHP wrapper exploitation", "CRITICAL"),
        (r"(?i)(/proc/self/(?:environ|status|cmdline|fd/\d+))", "Linux /proc filesystem inspection", "CRITICAL"),
    ],
    
    "Server-Side Request Forgery (SSRF)": [
        (r"(?i)(169\.254\.169\.254|metadata\.google\.internal)", "Cloud Metadata endpoint access", "CRITICAL"),
        (r"(?i)(http://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)(?::\d+)?)", "Internal loopback target probing", "HIGH"),
        (r"(?i)(http://10\.\d{1,3}\.\d{1,3}\.\d{1,3}|http://192\.168\.\d{1,3}\.\d{1,3}|http://172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})", "Private RFC1918 network probing", "HIGH"),
    ],
    
    "API & Token Exploitation (JWT / GraphQL / BOLA)": [
        (r"(?i)(\"alg\"\s*:\s*\"none\"|'alg'\s*:\s*'none')", "JWT Algorithm 'none' Signature Bypass", "CRITICAL"),
        (r"(?i)(__schema|__type|__typename\b.*fields)", "GraphQL Schema Introspection Probe", "HIGH"),
        (r"(?i)(\bquery\b[\s\S]*\{\s*(?:users|accounts|admins|keys|passwords)[\s\S]*\})", "GraphQL Unauthorized Data Query", "HIGH"),
        (r"(?i)(/api/v\d+/(?:users|accounts|orders)/\d+/(?:delete|update|role|promote))", "API Broken Object Level Auth (BOLA) probe", "HIGH"),
    ],

    "Sensitive File & Environment Reconnaissance": [
        (r"(?i)(\.env|\.environment|\.env\.local|\.env\.production)", "Environment file probing (.env)", "HIGH"),
        (r"(?i)(\.git/(?:config|HEAD|index)|\.svn/entries|\.hg/)", "Version control repository exposure", "CRITICAL"),
        (r"(?i)(wp-config\.php|configuration\.php|settings\.py|database\.yml)", "Web framework database config probing", "CRITICAL"),
        (r"(?i)(\.aws/credentials|\.ssh/id_rsa|\.ssh/id_dsa|\.id_rsa)", "SSH/AWS cloud key access attempt", "CRITICAL"),
        (r"(?i)(/(?:phpmyadmin|pma|adminer|webadmin)/)", "Database management portal probing", "MEDIUM"),
        (r"(?i)(/(?:dump|backup|db|database|site)\.(?:sql|tar|zip|gz|bak))", "Database / Site backup archive probing", "HIGH"),
    ]
}

# Malicious Scanner User Agents
BAD_USER_AGENTS = [
    (r"(?i)\bsqlmap\b", "SQLMap Automated Injection Tool", "CRITICAL"),
    (r"(?i)\bnikto\b", "Nikto Web Vulnerability Scanner", "HIGH"),
    (r"(?i)\bdirbuster\b", "DirBuster Directory Fuzzer", "HIGH"),
    (r"(?i)\bgobuster\b", "Gobuster Content Discovery", "HIGH"),
    (r"(?i)\bwfuzz\b", "Wfuzz Web Fuzzer", "HIGH"),
    (r"(?i)\bffuf\b", "FFUF Fast Web Fuzzer", "HIGH"),
    (r"(?i)\bmasscan\b", "Masscan Fast Port Scanner", "MEDIUM"),
    (r"(?i)\bnmap\b", "Nmap Network Scanner", "HIGH"),
    (r"(?i)\bhydra\b", "THC-Hydra Password Cracker", "CRITICAL"),
    (r"(?i)\bacunetix\b", "Acunetix Vulnerability Scanner", "HIGH"),
    (r"(?i)\bhavij\b", "Havij SQL Injection Tool", "CRITICAL"),
    (r"(?i)\bmetasploit\b", "Metasploit Penetration Testing Framework", "CRITICAL"),
    (r"(?i)\bnessus\b", "Nessus Vulnerability Scanner", "HIGH"),
    (r"(?i)\bburpcollaborator\b", "Burp Suite Collaborator Interaction", "HIGH"),
    (r"(?i)\bpostmanruntime/|python-requests/|curl/|libwww-perl|Go-http-client|zgrab", "Automated Script / Bot Crawl", "LOW"),
]

# Database Security & Integrity Rules (For DB Queries & Logs)
DATABASE_RULES = [
    (r"(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW|INDEX)\b", "Destructive Object Drop Attempt", "CRITICAL"),
    (r"(?i)\bTRUNCATE\s+TABLE\b", "Destructive Table Truncation", "CRITICAL"),
    (r"(?i)\bGRANT\s+ALL\s+PRIVILEGES\b", "Unauthorized Privilege Escalation", "CRITICAL"),
    (r"(?i)\bALTER\s+USER\b[\s\S]+\bIDENTIFIED\s+BY\b", "Database User Password Modification", "CRITICAL"),
    (r"(?i)\bEXEC(?:UTE)?\s+xp_cmdshell\b", "SQL OS Command Execution", "CRITICAL"),
    (r"(?i)\bLOAD\s+DATA\s+LOCAL\s+INFILE\b", "Arbitrary Client File Read via SQL", "CRITICAL"),
    (r"(?i)\bSELECT\b[\s\S]+\bFROM\s+information_schema\.columns\b", "Full Database Schema Enumeration", "HIGH"),
    (r"(?i)\bSELECT\b[\s\S]+\bFROM\s+users\b(?:\s+LIMIT\s+\d{4,})?", "Mass User Record Bulk Extraction", "HIGH"),
]

# Data Loss Prevention (DLP) Regex Rules (For Response Scrubbing)
DLP_RULES = [
    (r"(?i)(AKIA[0-9A-Z]{16})", "AWS Access Key ID Leak", "CRITICAL"),
    (r"(?i)(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)", "Private Encryption Key Leak", "CRITICAL"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "Credit Card PAN (Visa/Mastercard/Amex) Leak", "CRITICAL"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "Social Security Number (SSN) Leak", "CRITICAL"),
    (r"(?i)(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})", "GitHub Access Token Leak", "CRITICAL"),
    (r"(?i)(ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)", "Unencrypted Raw JWT Secret in Body", "MEDIUM"),
]


def decode_payload(raw_str: str) -> str:
    """Recursively decodes URL, hex, or base64 encoded strings."""
    if not raw_str:
        return ""
    current = raw_str
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
        except Exception:
            break
    return current


def inspect_text(text: str) -> Optional[Tuple[str, str, str, str]]:
    """Inspects text against general web and API threat signatures."""
    if not text:
        return None
    decoded_text = decode_payload(text)
    for category, rules in ATTACK_SIGNATURES.items():
        for pattern, description, severity in rules:
            match = re.search(pattern, decoded_text)
            if match:
                snippet = match.group(0)[:80]
                return (category, description, severity, snippet)
    return None


def inspect_user_agent(user_agent: str) -> Optional[Tuple[str, str, str, str]]:
    """Checks User-Agent against malicious scanners."""
    if not user_agent:
        return None
    for pattern, description, severity in BAD_USER_AGENTS:
        if re.search(pattern, user_agent):
            return ("Malicious / Automated Scanner", description, severity, user_agent[:60])
    return None


def inspect_db_query(query: str) -> Optional[Tuple[str, str, str, str]]:
    """Inspects a database query against database security rules."""
    if not query:
        return None
    for pattern, description, severity in DATABASE_RULES:
        match = re.search(pattern, query)
        if match:
            snippet = match.group(0)[:80]
            return ("Database Security Violation", description, severity, snippet)
    return None


def inspect_dlp(content: str) -> Optional[Tuple[str, str, str, str]]:
    """Inspects response content for leaked secrets, keys, or sensitive customer data."""
    if not content:
        return None
    for pattern, description, severity in DLP_RULES:
        match = re.search(pattern, content)
        if match:
            snippet = match.group(0)[:60]
            return ("Data Loss Prevention (DLP)", description, severity, snippet)
    return None

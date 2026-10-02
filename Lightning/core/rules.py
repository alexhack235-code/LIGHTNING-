"""
=============================================================================
                  LIGHTNING - ADVANCED THREAT DETECTION & RULE ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import re
import urllib.parse
import html
import base64
from typing import Tuple, Optional, List, Dict, Pattern

# Attack Categories & Threat Signatures (Web, API & Database)
ATTACK_SIGNATURES: Dict[str, List[Tuple[Pattern, str, str]]] = {
    "SQL Injection (SQLi)": [
        (re.compile(r"(?i)(\bUNION\b\s+(?:ALL\s+)?SELECT\b)"), "UNION SELECT extraction attempt", "CRITICAL"),
        (re.compile(r"(?i)(\bSELECT\b[\s\S]+\bFROM\b[\s\S]+\bWHERE\b)"), "SQL Data query extraction", "HIGH"),
        (re.compile(r"(?i)('\s*OR\s*['\"\d]+\s*=\s*['\"\d]+)"), "Classic boolean OR SQL bypass", "CRITICAL"),
        (re.compile(r"(?i)(\bOR\s+1\s*=\s*1\b|\bAND\s+1\s*=\s*1\b)"), "Tautology SQL injection", "CRITICAL"),
        (re.compile(r"(?i)(\bSLEEP\s*\(\s*\d+\s*\)|\bBENCHMARK\s*\(\s*\d+)"), "Time-based blind SQL injection", "CRITICAL"),
        (re.compile(r"(?i)(\bINFORMATION_SCHEMA\b|\bSYS\.TABLES\b|\bPG_CATALOG\b)"), "Database schema reconnaissance", "HIGH"),
        (re.compile(r"(?i)(--\s*$|/\*.*?\*/|;\s*DROP\s+TABLE|;\s*DELETE\s+FROM)"), "SQL query termination / destructive payload", "CRITICAL"),
        (re.compile(r"(?i)(\bWAITFOR\s+DELAY\s+'[\d:]+')"), "MSSQL Time-based injection", "CRITICAL"),
        (re.compile(r"(?i)(\bLOAD_FILE\s*\(|\bINTO\s+OUTFILE\b)"), "SQL Local file read/write attempt", "CRITICAL"),
        (re.compile(r"(?i)(\bEXTRACTVALUE\s*\(|\bUPDATEXML\s*\()"), "Error-based XML SQL injection", "CRITICAL"),
        (re.compile(r"(?i)(\bxp_cmdshell\b|\bsp_executesql\b)"), "MSSQL Dangerous procedure execution", "CRITICAL"),
        (re.compile(r"(?i)(;\s*SELECT\b)"), "Stacked queries", "CRITICAL"),
        (re.compile(r"(?i)(0x[0-9a-fA-F]+)"), "Hex-encoded payload", "HIGH"),
        (re.compile(r"(?i)(\bHAVING\b|\bGROUP\s+BY\b)"), "HAVING/GROUP BY blind detection", "HIGH"),
        (re.compile(r"(?i)(/\*!\d*UNION\*/)"), "Comment-based evasion", "CRITICAL"),
        (re.compile(r"(?i)(\bCHAR\s*\(|\bCONCAT\s*\()"), "CHAR/CONCAT extraction", "HIGH"),
        (re.compile(r"(?i)(\bORDER\s+BY\s+\d+)"), "ORDER BY column enumeration", "HIGH"),
        (re.compile(r"(?i)(\bIF\s*\(|\bCASE\s+WHEN\b)"), "Conditional injection (IF/CASE WHEN)", "CRITICAL"),
        (re.compile(r"(?i)(\bMAKE_SET\s*\(|\bELT\s*\()"), "MAKE_SET/ELT function obfuscation", "CRITICAL"),
    ],

    "NoSQL Injection (MongoDB / Document DB)": [
        (re.compile(r"(?i)(\$gt|\$gte|\$ne|\$nin|\$in|\$where|\$regex|\$exists|\$expr|\$jsonSchema)"), "MongoDB operator injection", "CRITICAL"),
        (re.compile(r"(?i)(this\.[a-zA-Z0-9_]+\s*==|return\s+true\s*;)"), "MongoDB JavaScript $where clause injection", "CRITICAL"),
    ],
    
    "Cross-Site Scripting (XSS)": [
        (re.compile(r"(?i)(<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>)"), "Script tag injection", "CRITICAL"),
        (re.compile(r"(?i)(<\s*script[^>]*>)"), "Unclosed script tag injection", "HIGH"),
        (re.compile(r"(?i)(javascript\s*:[\s\S]*)"), "JavaScript pseudo-protocol payload", "CRITICAL"),
        (re.compile(r"(?i)(\bon(?:error|load|mouseover|click|focus|blur|submit|keydown|mousein)\s*=\s*['\"].*?['\"])"), "Inline event handler XSS", "HIGH"),
        (re.compile(r"(?i)(<\s*(?:img|iframe|svg|body|embed|object|input|video|audio)[^>]+on\w+\s*=)"), "HTML tag with malicious event handler", "HIGH"),
        (re.compile(r"(?i)(document\.(?:cookie|location|domain|write))"), "DOM tampering / Cookie theft vector", "HIGH"),
        (re.compile(r"(?i)(\beval\s*\(|\bFunction\s*\(|\bwindow\.setTimeout\s*\()"), "Dynamic script execution (eval)", "HIGH"),
        (re.compile(r"(?i)(<\s*svg[^>]*onload\s*=)"), "SVG onload vector", "HIGH"),
        (re.compile(r"(?i)(data:text/html[\s\S]*base64)"), "Data URI XSS injection", "HIGH"),
        (re.compile(r"(?i)(<\s*details\s+open\s+ontoggle\s*=)"), "Details ontoggle XSS", "HIGH"),
        (re.compile(r"(?i)(<\s*marquee\s+onstart\s*=)"), "Marquee onstart XSS", "HIGH"),
        (re.compile(r"(?i)(<\s*math[^>]*>)"), "MathML XSS", "HIGH"),
        (re.compile(r"(?i)(\$\{[^}]+\})"), "Template literal injection", "HIGH"),
        (re.compile(r"(?i)(constructor\.constructor)"), "Constructor XSS bypass", "HIGH"),
        (re.compile(r"(?i)(\bimport\s*\()"), "Dynamic import XSS", "HIGH"),
        (re.compile(r"(?i)(<\s*base\s+href\s*=)"), "Base href hijacking", "HIGH"),
        (re.compile(r"(?i)(<\s*template[^>]*>)"), "Template abuse XSS", "HIGH"),
        (re.compile(r"(?i)(<\s*use\s+href\s*=)"), "SVG use tag XSS", "HIGH"),
        (re.compile(r"(?i)(expression\s*\()"), "CSS expression XSS", "HIGH"),
        (re.compile(r"(?i)(@import\s+url\s*\()"), "CSS @import injection", "HIGH"),
        (re.compile(r"(?i)(<\s*meta\s+http-equiv\s*=\s*['\"]?refresh['\"]?)"), "Meta refresh injection", "HIGH"),
        (re.compile(r"(?i)(\bsrcdoc\s*=)"), "Iframe srcdoc XSS", "HIGH"),
    ],
    
    "Remote Code Execution (RCE) / Command Injection": [
        (re.compile(r"(?i)(;\s*(?:cat|ls|dir|whoami|id|uname|netstat|tasklist|powershell|cmd|sh|bash)\b)"), "Shell command chaining (;)", "CRITICAL"),
        (re.compile(r"(?i)(\|\s*(?:cat|ls|dir|whoami|id|uname|powershell|cmd|sh|bash)\b)"), "Shell command piping (|)", "CRITICAL"),
        (re.compile(r"(?i)(`\s*(?:cat|ls|dir|whoami|id|powershell|cmd|sh|bash).*?`)"), "Backtick command substitution", "CRITICAL"),
        (re.compile(r"(?i)(\$\(\s*(?:cat|ls|dir|whoami|id|powershell|sh|bash).*?\))"), "Command substitution $()", "CRITICAL"),
        (re.compile(r"(?i)(\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\()"), "PHP Dangerous system execution functions", "CRITICAL"),
        (re.compile(r"(?i)(powershell(?:\.exe)?\s+(?:-[eE]n?c?|-c(?:ommand)?))"), "PowerShell execution attempt", "CRITICAL"),
        (re.compile(r"(?i)(\bwget\b|\bcurl\b)[\s\S]*?(?:\|\s*(?:bash|sh|cmd|powershell))"), "Remote script download and execution", "CRITICAL"),
        (re.compile(r"(?i)(\b(?:/bin/bash|/bin/sh|cmd\.exe|powershell\.exe)\b)"), "Direct shell invocation", "CRITICAL"),
        (re.compile(r"(?i)(os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\()"), "Python command injection", "CRITICAL"),
        (re.compile(r"(?i)(Runtime\.getRuntime\(\)\.exec\s*\()"), "Java Runtime.exec", "CRITICAL"),
        (re.compile(r"(?i)(__import__\s*\()"), "Python __import__ execution", "CRITICAL"),
        (re.compile(r"(?i)(eval\s*\(\s*compile\s*\()"), "Python eval(compile)", "CRITICAL"),
        (re.compile(r"(?i)(child_process\.(?:exec|spawn|execSync)\s*\()"), "Node.js child_process injection", "CRITICAL"),
        (re.compile(r"(?i)(\bsystem\s*\()"), "Ruby system() injection", "CRITICAL"),
        (re.compile(r"(?i)(qx\s*\{)"), "Perl qx{} injection", "CRITICAL"),
        (re.compile(r"(?i)([\n\r]+\s*(?:cat|ls|dir|whoami|id|uname|powershell|cmd|sh|bash)\b)"), "Newline command injection", "CRITICAL"),
        (re.compile(r"(?i)(\$IFS)"), "Environment variable injection IFS", "CRITICAL"),
        (re.compile(r"(?i)(\{[a-zA-Z0-9_-]+,[a-zA-Z0-9_-]+\})"), "Brace expansion injection", "CRITICAL"),
        (re.compile(r"(?i)(<<\s*[A-Z]+[\s\S]*?[A-Z]+)"), "Heredoc injection", "CRITICAL"),
    ],
    
    "Path Traversal / Local File Inclusion (LFI)": [
        (re.compile(r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e\/)"), "Directory traversal sequence (../)", "CRITICAL"),
        (re.compile(r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/etc/group)"), "Linux sensitive configuration access", "CRITICAL"),
        (re.compile(r"(?i)(c:\\windows\\system32|c:/windows/win\.ini|c:\\boot\.ini)"), "Windows system file access", "CRITICAL"),
        (re.compile(r"(?i)(php://filter|php://input|data://text/plain|file://|expect://)"), "PHP wrapper exploitation", "CRITICAL"),
        (re.compile(r"(?i)(/proc/self/(?:environ|status|cmdline|fd/\d+))"), "Linux /proc filesystem inspection", "CRITICAL"),
        (re.compile(r"(\.\.\.\.//|\.\.%252f|\.\.%c0%af|\.\.\\%00)"), "Advanced Directory traversal sequences", "CRITICAL"),
        (re.compile(r"(\\\\\\?\\)"), "Windows UNC Path Traversal prefix", "CRITICAL"),
        (re.compile(r"(?i)(::\$DATA)"), "Windows IIS ADS ::$DATA stream", "CRITICAL"),
        (re.compile(r"(\.\.;/)"), "Tomcat path traversal bypass", "CRITICAL"),
        (re.compile(r"(?i)(jar:)"), "Java JAR protocol LFI", "CRITICAL"),
    ],
    
    "Server-Side Request Forgery (SSRF)": [
        (re.compile(r"(?i)(169\.254\.169\.254|metadata\.google\.internal)"), "Cloud Metadata endpoint access", "CRITICAL"),
        (re.compile(r"(?i)(http://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)(?::\d+)?)"), "Internal loopback target probing", "HIGH"),
        (re.compile(r"(?i)(http://10\.\d{1,3}\.\d{1,3}\.\d{1,3}|http://192\.168\.\d{1,3}\.\d{1,3}|http://172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})"), "Private RFC1918 network probing", "HIGH"),
        (re.compile(r"(?i)(\[::\]|0x7f000001|2130706433)"), "Obfuscated IP SSRF", "CRITICAL"),
        (re.compile(r"(?i)(gopher://|dict://|file:///)"), "SSRF dangerous protocols", "CRITICAL"),
        (re.compile(r"(?i)(@[a-zA-Z0-9.-]+/)"), "SSRF URL authority bypass (@)", "HIGH"),
    ],
    
    "API & Token Exploitation (JWT / GraphQL / BOLA)": [
        (re.compile(r"(?i)(\"alg\"\s*:\s*\"none\"|'alg'\s*:\s*'none')"), "JWT Algorithm 'none' Signature Bypass", "CRITICAL"),
        (re.compile(r"(?i)(__schema|__type|__typename\b.*fields)"), "GraphQL Schema Introspection Probe", "HIGH"),
        (re.compile(r"(?i)(\bquery\b[\s\S]*\{\s*(?:users|accounts|admins|keys|passwords)[\s\S]*\})"), "GraphQL Unauthorized Data Query", "HIGH"),
        (re.compile(r"(?i)(/api/v\d+/(?:users|accounts|orders)/\d+/(?:delete|update|role|promote))"), "API Broken Object Level Auth (BOLA) probe", "HIGH"),
        (re.compile(r"(?i)(__proto__|constructor\.prototype)"), "Prototype pollution", "CRITICAL"),
        (re.compile(r"(?i)(\bisAdmin\s*=\s*true\b|\brole\s*=\s*['\"]?admin['\"]?)"), "Mass assignment / privilege escalation", "HIGH"),
    ],

    "Sensitive File & Environment Reconnaissance": [
        (re.compile(r"(?i)(\.env|\.environment|\.env\.local|\.env\.production)"), "Environment file probing (.env)", "HIGH"),
        (re.compile(r"(?i)(\.git/(?:config|HEAD|index)|\.svn/entries|\.hg/)"), "Version control repository exposure", "CRITICAL"),
        (re.compile(r"(?i)(wp-config\.php|configuration\.php|settings\.py|database\.yml)"), "Web framework database config probing", "CRITICAL"),
        (re.compile(r"(?i)(\.aws/credentials|\.ssh/id_rsa|\.ssh/id_dsa|\.id_rsa)"), "SSH/AWS cloud key access attempt", "CRITICAL"),
        (re.compile(r"(?i)(/(?:phpmyadmin|pma|adminer|webadmin)/)"), "Database management portal probing", "MEDIUM"),
        (re.compile(r"(?i)(/(?:dump|backup|db|database|site)\.(?:sql|tar|zip|gz|bak))"), "Database / Site backup archive probing", "HIGH"),
    ],

    "Other Vulnerabilities (CRLF, Smuggling, XXE, SSTI, LDAP, XPath, Redirects)": [
        (re.compile(r"(%0d%0a|\r\n)"), "CRLF injection", "HIGH"),
        (re.compile(r"(?i)(Transfer-Encoding:\s*chunked)"), "HTTP Request Smuggling", "CRITICAL"),
        (re.compile(r"(?i)(<!ENTITY\s+.*?(?:SYSTEM|PUBLIC)\s+['\"].*?['\"]>|<!DOCTYPE\s+.*?>)"), "XXE injection", "CRITICAL"),
        (re.compile(r"(?i)(\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|#\{.*?\})"), "Server-Side Template Injection (SSTI)", "CRITICAL"),
        (re.compile(r"(?i)(\(\s*&\s*\([a-z]+=[^\)]+\)\s*\([a-z]+=|\*\))"), "LDAP injection", "CRITICAL"),
        (re.compile(r"(?i)(//[a-zA-Z0-9_]+\[@[a-zA-Z0-9_]+=[^\]]+\])"), "XPath injection", "CRITICAL"),
        (re.compile(r"(?i)(http[s]?://(?![a-zA-Z0-9_.-]*yourdomain\.com)[a-zA-Z0-9_.-]+)"), "Open redirect probe", "MEDIUM"),
        (re.compile(r"(?i)(Origin:\s*http://null|Origin:\s*https?://evil\.com)"), "CORS misconfiguration probe", "MEDIUM"),
        (re.compile(r"(?i)(Sec-WebSocket-Key:)"), "WebSocket hijacking probe", "MEDIUM"),
    ]
}

# Malicious Scanner User Agents
BAD_USER_AGENTS: List[Tuple[Pattern, str, str]] = [
    (re.compile(r"(?i)\bsqlmap\b"), "SQLMap Automated Injection Tool", "CRITICAL"),
    (re.compile(r"(?i)\bnikto\b"), "Nikto Web Vulnerability Scanner", "HIGH"),
    (re.compile(r"(?i)\bdirbuster\b"), "DirBuster Directory Fuzzer", "HIGH"),
    (re.compile(r"(?i)\bgobuster\b"), "Gobuster Content Discovery", "HIGH"),
    (re.compile(r"(?i)\bwfuzz\b"), "Wfuzz Web Fuzzer", "HIGH"),
    (re.compile(r"(?i)\bffuf\b"), "FFUF Fast Web Fuzzer", "HIGH"),
    (re.compile(r"(?i)\bmasscan\b"), "Masscan Fast Port Scanner", "MEDIUM"),
    (re.compile(r"(?i)\bnmap\b"), "Nmap Network Scanner", "HIGH"),
    (re.compile(r"(?i)\bhydra\b"), "THC-Hydra Password Cracker", "CRITICAL"),
    (re.compile(r"(?i)\bacunetix\b"), "Acunetix Vulnerability Scanner", "HIGH"),
    (re.compile(r"(?i)\bhavij\b"), "Havij SQL Injection Tool", "CRITICAL"),
    (re.compile(r"(?i)\bmetasploit\b"), "Metasploit Penetration Testing Framework", "CRITICAL"),
    (re.compile(r"(?i)\bnessus\b"), "Nessus Vulnerability Scanner", "HIGH"),
    (re.compile(r"(?i)\bburpcollaborator\b"), "Burp Suite Collaborator Interaction", "HIGH"),
    (re.compile(r"(?i)\bpostmanruntime/|python-requests/|curl/|libwww-perl|Go-http-client|zgrab"), "Automated Script / Bot Crawl", "LOW"),
    (re.compile(r"(?i)\b(?:nuclei|jaeles|subfinder|amass|dirsearch|feroxbuster|httprobe|whatweb|arjun|paramspider|xsstrike|dalfox|commix|tplmap|ysoserial|burpsuite|owasp-zap|w3af|arachni|skipfish|wapiti)\b"), "Advanced web scanner / vulnerability probe", "HIGH"),
]

# Database Security & Integrity Rules (For DB Queries & Logs)
DATABASE_RULES: List[Tuple[Pattern, str, str]] = [
    (re.compile(r"(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW|INDEX)\b"), "Destructive Object Drop Attempt", "CRITICAL"),
    (re.compile(r"(?i)\bTRUNCATE\s+TABLE\b"), "Destructive Table Truncation", "CRITICAL"),
    (re.compile(r"(?i)\bGRANT\s+ALL\s+PRIVILEGES\b"), "Unauthorized Privilege Escalation", "CRITICAL"),
    (re.compile(r"(?i)\bALTER\s+USER\b[\s\S]+\bIDENTIFIED\s+BY\b"), "Database User Password Modification", "CRITICAL"),
    (re.compile(r"(?i)\bEXEC(?:UTE)?\s+xp_cmdshell\b"), "SQL OS Command Execution", "CRITICAL"),
    (re.compile(r"(?i)\bLOAD\s+DATA\s+LOCAL\s+INFILE\b"), "Arbitrary Client File Read via SQL", "CRITICAL"),
    (re.compile(r"(?i)\bSELECT\b[\s\S]+\bFROM\s+information_schema\.columns\b"), "Full Database Schema Enumeration", "HIGH"),
    (re.compile(r"(?i)\bSELECT\b[\s\S]+\bFROM\s+users\b(?:\s+LIMIT\s+\d{4,})?"), "Mass User Record Bulk Extraction", "HIGH"),
    (re.compile(r"(?i)\bALTER\s+TABLE\b"), "Alter table schema manipulation", "HIGH"),
    (re.compile(r"(?i)\bCREATE\s+USER\b"), "Create new database user", "CRITICAL"),
    (re.compile(r"(?i)\bREVOKE\b"), "Revoke privileges", "HIGH"),
    (re.compile(r"(?i)\bBACKUP\s+DATABASE\b"), "Database backup command", "HIGH"),
    (re.compile(r"(?i)\bRESTORE\b"), "Database restore command", "HIGH"),
    (re.compile(r"(?i)\bDBCC\b"), "MSSQL DBCC command execution", "HIGH"),
    (re.compile(r"(?i)\b(?:pg_dump|mongodump)\b"), "Database dump utility usage", "CRITICAL"),
    (re.compile(r"(?i)\bFLUSH\s+PRIVILEGES\b"), "Flush privileges execution", "CRITICAL"),
    (re.compile(r"(?i)\bSET\s+GLOBAL\b"), "Set global configuration modification", "CRITICAL"),
    (re.compile(r"(?i)\bSHOW\s+VARIABLES\b"), "Show database variables/configuration", "HIGH"),
    (re.compile(r"(?i)\bINTO\s+DUMPFILE\b"), "SQL write to dumpfile", "CRITICAL"),
]

# Data Loss Prevention (DLP) Regex Rules (For Response Scrubbing)
DLP_RULES: List[Tuple[Pattern, str, str]] = [
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "AWS Access Key ID Leak", "CRITICAL"),
    (re.compile(r"(?i)(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"), "Private Encryption Key Leak", "CRITICAL"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "Credit Card PAN (Visa/Mastercard/Amex) Leak", "CRITICAL"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "Social Security Number (SSN) Leak", "CRITICAL"),
    (re.compile(r"(?i)(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"), "GitHub Access Token Leak", "CRITICAL"),
    (re.compile(r"(?i)(ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)"), "Unencrypted Raw JWT Secret in Body", "MEDIUM"),
    (re.compile(r"(?i)[\"'](?:gcp_private_key|private_key)[\"']\s*:\s*[\"']-----BEGIN PRIVATE KEY-----"), "Google Cloud service account keys", "CRITICAL"),
    (re.compile(r"(?i)(AccountKey=[a-zA-Z0-9+/=]+;?|DefaultEndpointsProtocol=https;AccountName=)"), "Azure connection strings", "CRITICAL"),
    (re.compile(r"(?i)(xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})"), "Slack webhooks/tokens", "CRITICAL"),
    (re.compile(r"(?i)([a-zA-Z0-9_]{24}\.[a-zA-Z0-9_]{6}\.[a-zA-Z0-9_-]{27})"), "Discord bot tokens", "CRITICAL"),
    (re.compile(r"(?i)(sk_live_[0-9a-zA-Z]{24})"), "Stripe API keys", "CRITICAL"),
    (re.compile(r"(?i)(SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43})"), "SendGrid keys", "CRITICAL"),
    (re.compile(r"(?i)(SK[0-9a-fA-F]{32})"), "Twilio keys", "CRITICAL"),
    (re.compile(r"(?i)(mongodb(?:\+srv)?://[^\s]+|postgres(?:ql)?://[^\s]+|mysql://[^\s]+|mssql://[^\s]+)"), "Database connection strings", "CRITICAL"),
    (re.compile(r"(?i)(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2[a-z]*\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+\$[a-zA-Z0-9+/]+)"), "Bcrypt/Argon2 hashes", "CRITICAL"),
    (re.compile(r"(?i)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:,|\n|\r)){5,}"), "PII Emails bulk leak", "CRITICAL"),
    (re.compile(r"(?i)(\+?\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}(?:,|\n|\r)){5,}"), "PII Phone numbers bulk leak", "CRITICAL"),
    (re.compile(r"(?i)([a-zA-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16})"), "IBAN numbers", "CRITICAL"),
]

def decode_payload(raw_str: str) -> str:
    """Recursively decodes URL, hex, or base64 encoded strings."""
    if not raw_str:
        return ""
    current = raw_str
    
    def decode_step(s: str) -> str:
        s_url = urllib.parse.unquote(s)
        s_url = urllib.parse.unquote(s_url)
        s_html = html.unescape(s_url)
        s_hex = re.sub(r'(?i)0x([0-9a-f]{2})', lambda m: chr(int(m.group(1), 16)), s_html)
        s_uni = re.sub(r'(?i)\\u([0-9a-f]{4})', lambda m: chr(int(m.group(1), 16)), s_hex)
        try:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', s_uni) and len(s_uni) % 4 == 0:
                s_b64 = base64.b64decode(s_uni).decode('utf-8', errors='ignore')
                s_uni = s_b64
        except Exception:
            pass
        return s_uni
        
    for _ in range(3):
        try:
            decoded = decode_step(current)
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
            match = pattern.search(decoded_text)
            if match:
                snippet = match.group(0)[:80]
                return (category, description, severity, snippet)
    return None

def inspect_user_agent(user_agent: str) -> Optional[Tuple[str, str, str, str]]:
    """Checks User-Agent against malicious scanners."""
    if not user_agent:
        return None
    for pattern, description, severity in BAD_USER_AGENTS:
        if pattern.search(user_agent):
            return ("Malicious / Automated Scanner", description, severity, user_agent[:60])
    return None

def inspect_db_query(query: str) -> Optional[Tuple[str, str, str, str]]:
    """Inspects a database query against database security rules."""
    if not query:
        return None
    for pattern, description, severity in DATABASE_RULES:
        match = pattern.search(query)
        if match:
            snippet = match.group(0)[:80]
            return ("Database Security Violation", description, severity, snippet)
    return None

def inspect_dlp(content: str) -> Optional[Tuple[str, str, str, str]]:
    """Inspects response content for leaked secrets, keys, or sensitive customer data."""
    if not content:
        return None
    for pattern, description, severity in DLP_RULES:
        match = pattern.search(content)
        if match:
            snippet = match.group(0)[:60]
            return ("Data Loss Prevention (DLP)", description, severity, snippet)
    return None

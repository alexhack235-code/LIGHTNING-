"""
=============================================================================
                  LIGHTNING - VIRTUAL PATCHING & ZERO-DAY SHIELD
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import os
import json
import re
from typing import Tuple, Optional, List, Dict

# Virtual Patches for famous Critical CVEs
CVE_VIRTUAL_PATCHES = [
    # Log4Shell / Log4j (CVE-2021-44228 / CVE-2021-45046)
    (r"(?i)(\$\{[\w\s:.-]*j[\w\s:.-]*n[\w\s:.-]*d[\w\s:.-]*i[\w\s:.-]*:(?:ldap|rmi|dns|corba|iiop|nis|http)://)", "Log4Shell (CVE-2021-44228) JNDI Injection Exploit", "CRITICAL"),
    
    # Spring4Shell (CVE-2022-22965)
    (r"(?i)(class\.module\.classLoader[\w\s.]*|\.classLoader\.)", "Spring4Shell (CVE-2022-22965) ClassLoader Exploitation", "CRITICAL"),
    
    # Apache Commons Text RCE (CVE-2022-42889 - Text4Shell)
    (r"(?i)(\$\{(?:script|dns|url|base64Decoder|script:javascript)\s*:)", "Text4Shell (CVE-2022-42889) Dynamic Script Evaluation", "CRITICAL"),
    
    # PHP-CGI Argument Injection (CVE-2024-4577 / CVE-2012-1823)
    (r"(?i)(%ADd\s*\+?allow_url_include|%ADd\s*\+?auto_prepend_file|-d\s+allow_url_include)", "PHP-CGI Argument Injection (CVE-2024-4577)", "CRITICAL"),
    
    # Shellshock (CVE-2014-6271)
    (r"(\(\s*\)\s*\{\s*[:;]\s*\}\s*;)", "Shellshock Bash Vulnerability (CVE-2014-6271)", "CRITICAL"),
    
    # Confluence OGNL Injection (CVE-2022-26134 / CVE-2021-26084)
    (r"(?i)(\$\{[\s\S]*?(?:com\.opensymphony|ognl\.OgnlContext)[\s\S]*?\})", "Confluence OGNL Remote Code Execution Exploit", "CRITICAL"),
    
    # Citrix Bleed / Gateway Buffer Overflow (CVE-2023-4966)
    (r"(?i)(/oauth/v1/user/authid\b.*?\b[a-zA-Z0-9_-]{64,})", "Citrix Bleed Session Hijack Probe (CVE-2023-4966)", "CRITICAL"),
    
    # WordPress xmlrpc.php Brute-Force & Denial-of-Service
    (r"(?i)(<methodCall>\s*<methodName>\s*(?:system\.multicall|wp\.getUsersBlogs|pingback\.ping)\b)", "WordPress XML-RPC Amplification / Brute-Force", "HIGH")
]

CUSTOM_RULES_FILE = "custom_rules.json"


class VirtualPatchingEngine:
    """Provides instant virtual patches for critical industry CVEs and hot-reloading custom rules."""
    def __init__(self):
        self.custom_rules: List[Tuple[str, str, str]] = []
        self.last_load_time = 0
        self._ensure_custom_rules_file()
        self.reload_custom_rules()

    def _ensure_custom_rules_file(self):
        """Creates a starter custom_rules.json if not present."""
        if not os.path.exists(CUSTOM_RULES_FILE):
            try:
                sample = {
                    "description": "LIGHTNING Custom Zero-Day Rules - Add your custom regex patterns here for zero-downtime hot-reloading",
                    "rules": [
                        {
                            "name": "Custom Admin Token Probe",
                            "pattern": "(?i)secret_internal_debug_key",
                            "severity": "HIGH",
                            "description": "Probing custom internal debug parameters"
                        }
                    ]
                }
                with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
                    json.dump(sample, f, indent=4)
            except Exception:
                pass

    def reload_custom_rules(self):
        """Hot-reloads user-defined custom rules from custom_rules.json."""
        if not os.path.exists(CUSTOM_RULES_FILE):
            return
        
        try:
            mtime = os.path.getmtime(CUSTOM_RULES_FILE)
            if mtime > self.last_load_time:
                with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    rules_list = []
                    for r in data.get("rules", []):
                        rules_list.append((r.get("pattern", ""), r.get("description", r.get("name", "Custom Rule")), r.get("severity", "HIGH")))
                    self.custom_rules = rules_list
                    self.last_load_time = mtime
        except Exception:
            pass

    def inspect_cve(self, text: str) -> Optional[Tuple[str, str, str, str]]:
        """Inspects request payload against critical CVE virtual patches and hot-reloaded custom rules."""
        if not text:
            return None

        # Check CVE Virtual Patches
        for pattern, description, severity in CVE_VIRTUAL_PATCHES:
            match = re.search(pattern, text)
            if match:
                snippet = match.group(0)[:80]
                return ("Virtual Patch / Zero-Day Exploit", description, severity, snippet)

        # Check Hot-Reloaded Custom Rules
        self.reload_custom_rules()
        for pattern, description, severity in self.custom_rules:
            if pattern:
                try:
                    match = re.search(pattern, text)
                    if match:
                        snippet = match.group(0)[:80]
                        return ("Custom Zero-Day Rule", description, severity, snippet)
                except Exception:
                    pass

        return None

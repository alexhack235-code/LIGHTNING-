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

# Virtual Patches for famous Critical CVEs (pre-compiled regex)
CVE_VIRTUAL_PATCHES = [
    # Existing CVEs
    (re.compile(r"(?i)(\$\{[\w\s:.-]*j[\w\s:.-]*n[\w\s:.-]*d[\w\s:.-]*i[\w\s:.-]*:(?:ldap|rmi|dns|corba|iiop|nis|http)://)"), "Log4Shell (CVE-2021-44228) JNDI Injection Exploit", "CRITICAL"),
    (re.compile(r"(?i)(class\.module\.classLoader[\w\s.]*|\.classLoader\.)"), "Spring4Shell (CVE-2022-22965) ClassLoader Exploitation", "CRITICAL"),
    (re.compile(r"(?i)(\$\{(?:script|dns|url|base64Decoder|script:javascript)\s*:)"), "Text4Shell (CVE-2022-42889) Dynamic Script Evaluation", "CRITICAL"),
    (re.compile(r"(?i)(%ADd\s*\+?allow_url_include|%ADd\s*\+?auto_prepend_file|-d\s+allow_url_include)"), "PHP-CGI Argument Injection (CVE-2024-4577)", "CRITICAL"),
    (re.compile(r"(\(\s*\)\s*\{\s*[:;]\s*\}\s*;)"), "Shellshock Bash Vulnerability (CVE-2014-6271)", "CRITICAL"),
    (re.compile(r"(?i)(\$\{[\s\S]*?(?:com\.opensymphony|ognl\.OgnlContext)[\s\S]*?\})"), "Confluence OGNL Remote Code Execution Exploit", "CRITICAL"),
    (re.compile(r"(?i)(/oauth/v1/user/authid\b.*?\b[a-zA-Z0-9_-]{64,})"), "Citrix Bleed Session Hijack Probe (CVE-2023-4966)", "CRITICAL"),
    (re.compile(r"(?i)(<methodCall>\s*<methodName>\s*(?:system\.multicall|wp\.getUsersBlogs|pingback\.ping)\b)"), "WordPress XML-RPC Amplification / Brute-Force", "HIGH"),
    
    # Newly Added Critical CVEs
    (re.compile(r"(?i)(/api/v1/|/guestaccess\.aspx).*?(X-siLock-Transaction)"), "MOVEit Transfer SQLi (CVE-2023-34362)", "CRITICAL"),
    (re.compile(r"(?i)(%\{[\s\S]*?(?:#_memberAccess|#context|ognl|multipart/form-data|#cmd|#_=|java\.lang))"), "Apache Struts RCE (CVE-2017-5638)", "CRITICAL"),
    (re.compile(r"(?i)(/user/register).*?(#post_render|#lazy_builder)"), "Drupalgeddon (CVE-2018-7600)", "CRITICAL"),
    (re.compile(r"(?i)(routestring=ajax/render/widget_php)"), "vBulletin Pre-Auth RCE (CVE-2019-16759)", "CRITICAL"),
    (re.compile(r"(?i)(/tmui/login\.jsp/\.\.;/tmui/)"), "F5 BIG-IP (CVE-2020-5902)", "CRITICAL"),
    (re.compile(r"(?i)(/ui/vropspluginui/rest/services/)"), "VMware vCenter (CVE-2021-21972)", "CRITICAL"),
    (re.compile(r"(?i)(/autodiscover/autodiscover\.json).*?(X-BEResource)"), "ProxyShell/ProxyLogon (CVE-2021-34473)", "CRITICAL"),
    (re.compile(r"(?i)(\.%2e/|%%32%65/)"), "Apache Path Traversal (CVE-2021-41773/42013)", "CRITICAL"),
    (re.compile(r"(?i)(/rest/api/latest/projects/).*?(archive)"), "Atlassian Bitbucket (CVE-2022-36804)", "CRITICAL"),
    (re.compile(r"(?i)(Forwarded: for=\"\[127\.0\.0\.1\]\"|User-Agent: Report Runner)"), "Fortinet Auth Bypass (CVE-2022-40684)", "CRITICAL"),
    (re.compile(r"(?i)(/goanywhere/lic/accept)"), "GoAnywhere RCE (CVE-2023-0669)", "CRITICAL"),
    (re.compile(r"(?i)(/app\?service=page/SetupCompleted)"), "PaperCut RCE (CVE-2023-27350)", "CRITICAL"),
    (re.compile(r"(?i)(/app/rest/users/id:1/tokens/)"), "JetBrains TeamCity (CVE-2023-42793)", "CRITICAL"),
    (re.compile(r"(?i)(/webui/).*?(curl_cmd)"), "Cisco IOS XE (CVE-2023-20198)", "CRITICAL"),
    (re.compile(r"(?i)(SetupWizard.*?(\.\./|\.\.\\))"), "ConnectWise ScreenConnect (CVE-2024-1709)", "CRITICAL"),
    (re.compile(r"(?i)(/cli\?remoting=false).*?(@)"), "Jenkins CLI (CVE-2024-23897)", "CRITICAL"),
    (re.compile(r"(?i)(/mifs/aad/api/v2/)"), "Ivanti EPMM (CVE-2023-35078)", "CRITICAL"),
    (re.compile(r"(?i)(ExceptionResponse.*?ClassInfo)"), "Apache ActiveMQ RCE (CVE-2023-46604)", "CRITICAL"),
    (re.compile(r"(?i)(/setup/setupadministrator\.action)"), "Atlassian Confluence (CVE-2023-22515)", "CRITICAL"),
    (re.compile(r"(?i)(/AHT/AhtApiService\.asmx)"), "Progress WS_FTP (CVE-2023-40044)", "CRITICAL")
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
            match = pattern.search(text)
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

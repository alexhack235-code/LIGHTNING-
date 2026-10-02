"""
=============================================================================
                  LIGHTNING - DATA LOSS PREVENTION (DLP) ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import re
from typing import Tuple, Optional
from banner import Colors

# Massively Upgraded DLP Patterns
# Format: (Regex Pattern, Description, Severity)
ENHANCED_DLP_RULES = [
    # Cloud Provider Keys
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "HIGH"),
    (r"(?i)aws_secret[a-z0-9_]*['\"=\s:]+[a-zA-Z0-9/+]{40}", "AWS Secret Key", "CRITICAL"),
    (r"\"type\":\s*\"service_account\"", "Google Cloud Service Account", "HIGH"),
    (r"AIza[0-9A-Za-z-_]{35}", "Google API Key", "HIGH"),
    (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]+", "Azure Connection String", "CRITICAL"),
    (r"AccountKey=[a-zA-Z0-9+/=]+", "Azure Storage Key", "HIGH"),
    (r"dop_v1_[a-f0-9]{64}", "DigitalOcean Token", "HIGH"),
    (r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "Heroku API Key", "HIGH"),

    # Platform Tokens
    (r"gh[pousr]_[0-9a-zA-Z]{36}", "GitHub PAT", "CRITICAL"),
    (r"github_pat_[a-zA-Z0-9_]+", "GitHub Fine-Grained PAT", "CRITICAL"),
    (r"glpat-[0-9a-zA-Z-_]{20}", "GitLab Token", "HIGH"),
    (r"xox[bpaqr]-[0-9a-zA-Z]+", "Slack Token", "HIGH"),
    (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "Slack Webhook", "HIGH"),
    (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", "Discord Bot Token", "HIGH"),
    (r"discord\.com/api/webhooks/\d+/[a-zA-Z0-9-_]+", "Discord Webhook", "HIGH"),
    (r"[sr]k_live_[0-9a-zA-Z]{24,}", "Stripe Key", "CRITICAL"),
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", "HIGH"),
    (r"AC[a-z0-9]{32}", "Twilio Account SID", "HIGH"),
    (r"SG\.[\w-]+\.[\w-]+", "SendGrid Key", "HIGH"),
    (r"key-[0-9a-zA-Z]{32}", "Mailgun Key", "HIGH"),
    (r"npm_[A-Za-z0-9]{36}", "NPM Token", "HIGH"),
    (r"pypi-[A-Za-z0-9-_]{100,}", "PyPI Token", "HIGH"),

    # Cryptographic Material
    (r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----", "Private Key", "CRITICAL"),
    (r"-----BEGIN CERTIFICATE-----", "X.509 Certificate", "MEDIUM"),
    (r"(?i)pfx_password\s*[:=]\s*[\"'][^\"']+[\"']", "PFX/P12 Password", "HIGH"),
    (r"ssh-rsa\s+[A-Za-z0-9+/=]+", "SSH Known Hosts Data", "MEDIUM"),

    # PII Data
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b", "Credit Card Number", "CRITICAL"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "Social Security Number (SSN)", "CRITICAL"),
    (r"\b[A-Z]{2}[0-9]{6}[A-D]\b", "National Insurance Number (UK)", "HIGH"),
    (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "Email Address", "LOW"),
    (r"\+?[1-9]\d{1,14}", "Phone Number", "LOW"),
    (r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}\b", "IBAN Number", "HIGH"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP Address", "LOW"),
    (r"\b[A-Z0-9]{8,9}\b", "Passport Number", "HIGH"),

    # Database Credentials
    (r"mysql://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_.-]+", "MySQL Credentials", "CRITICAL"),
    (r"postgres(?:ql)?://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_.-]+", "PostgreSQL Credentials", "CRITICAL"),
    (r"mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_.-]+", "MongoDB Credentials", "CRITICAL"),
    (r"redis://[a-zA-Z0-9_]*:[^@]+@[a-zA-Z0-9_.-]+", "Redis Credentials", "CRITICAL"),
    (r"Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+", "MSSQL Credentials", "CRITICAL"),
    (r"sqlite3?://", "SQLite Path with Credentials", "HIGH"),

    # Other Secrets
    (r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token", "HIGH"),
    (r"(?i)api[_-]?key[\"':=\s]+[A-Za-z0-9-_]{20,}", "Generic API Key", "HIGH"),
    (r"(?i)password[\"':=\s]+[^\s\"']{8,}", "Generic Password", "HIGH"),
    (r"Bearer [A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+", "Bearer Token", "HIGH"),
    (r"Basic [A-Za-z0-9+/=]{10,}", "Basic Auth Token", "HIGH"),
    (r"\$2[aby]\$\d{1,2}\$[./A-Za-z0-9]{53}", "Bcrypt Hash", "HIGH"),
    (r"https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)", "Internal URL Leak", "MEDIUM")
]

class DataLossPreventionEngine:
    """Inspects outgoing HTTP responses to prevent secret & credential leaks."""
    def __init__(self, mask_leaks: bool = True):
        self.mask_leaks = mask_leaks

    def inspect_and_scrub(self, response_body: str) -> Tuple[str, Optional[Tuple[str, str, str, str]]]:
        """
        Inspects response body for sensitive data leaks.
        Returns: (Sanitized_Body, Threat_Tuple_Or_None)
        """
        if not response_body:
            return response_body, None

        detected_threat = None
        scrubbed = response_body
        
        # Check for bulk email leaks (>5)
        email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        emails_found = re.findall(email_pattern, scrubbed)
        if len(emails_found) > 5 and not detected_threat:
            detected_threat = ("Data Loss Prevention (DLP)", "Bulk Email Address Leak", "HIGH", str(emails_found[0])[:40])

        for pattern, description, severity in ENHANCED_DLP_RULES:
            match = re.search(pattern, scrubbed)
            if match:
                snippet = match.group(0)
                if not detected_threat:
                    # Ignore single low severity matches for threat reporting if needed, 
                    # but we'll report the first match to keep it simple.
                    detected_threat = ("Data Loss Prevention (DLP)", description, severity, snippet[:40])
                
                if self.mask_leaks:
                    # Mask the sensitive secret
                    if "Credit Card" in description or "SSN" in description or "National Insurance" in description:
                        masked = snippet[:4] + "-XXXX-XXXX-" + snippet[-4:] if len(snippet) > 8 else "[REDACTED_PII]"
                    elif "Key" in description or "Token" in description or "Credentials" in description:
                        masked = snippet[:4] + "*" * (len(snippet) - 8) + snippet[-4:] if len(snippet) > 8 else "[REDACTED_SECRET]"
                    else:
                        masked = "[REDACTED_BY_LIGHTNING_DLP]"
                    
                    scrubbed = re.sub(pattern, masked, scrubbed)

        return scrubbed, detected_threat

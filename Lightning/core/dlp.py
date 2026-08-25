"""
=============================================================================
                  LIGHTNING - DATA LOSS PREVENTION (DLP) ENGINE
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import re
from typing import Tuple, Optional
from core.rules import DLP_RULES
from banner import Colors

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

        for pattern, description, severity in DLP_RULES:
            match = re.search(pattern, scrubbed)
            if match:
                snippet = match.group(0)
                if not detected_threat:
                    detected_threat = ("Data Loss Prevention (DLP)", description, severity, snippet[:40])
                
                if self.mask_leaks:
                    # Mask the sensitive secret
                    if "Credit Card" in description:
                        masked = snippet[:4] + "-XXXX-XXXX-" + snippet[-4:]
                    elif "Key" in description or "Token" in description:
                        masked = snippet[:4] + "*" * (len(snippet) - 8) + snippet[-4:] if len(snippet) > 8 else "[REDACTED_SECRET]"
                    else:
                        masked = "[REDACTED_BY_LIGHTNING_DLP]"
                    
                    scrubbed = re.sub(pattern, masked, scrubbed)

        return scrubbed, detected_threat

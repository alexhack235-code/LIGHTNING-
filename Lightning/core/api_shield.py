"""
=============================================================================
                  LIGHTNING - ADVANCED API DEFENDER & GATEWAY SHIELD
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import time
import json
import base64
import re
from typing import Dict, Tuple, Optional, Set
from banner import Colors

class APIShield:
    """Enterprise API Gateway Security Layer."""
    def __init__(self, 
                 api_base_path: str = "/api",
                 api_key_header: str = "X-API-Key",
                 valid_api_keys: Optional[Set[str]] = None,
                 jwt_enforce: bool = False,
                 graphql_depth_limit: int = 5):
        self.api_base_path = api_base_path.rstrip("/")
        self.api_key_header = api_key_header.lower()
        self.valid_api_keys = valid_api_keys or set()
        self.jwt_enforce = jwt_enforce
        self.graphql_depth_limit = graphql_depth_limit

        # Rate limiting per API Key / Client
        self.key_buckets: Dict[str, list] = {}
        self.bola_tracker: Dict[str, list] = {}

    def is_api_route(self, path: str) -> bool:
        """Determines if the target path is an API endpoint."""
        return path.startswith(self.api_base_path) or "/graphql" in path

    def inspect_jwt(self, auth_header: str) -> Optional[Tuple[str, str, str]]:
        """
        Validates JWT token header for dangerous exploits (e.g. alg=none, missing sig).
        Returns (Issue, Severity, Snippet) or None.
        """
        if not auth_header:
            return None
        
        token = auth_header
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

        parts = token.split(".")
        if len(parts) >= 2:
            try:
                # Add base64 padding
                header_raw = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                header_json = json.loads(base64.urlsafe_b64decode(header_raw.encode()).decode("utf-8", errors="ignore"))
                
                # Check for alg = none attack
                alg = str(header_json.get("alg", "")).lower()
                if alg == "none":
                    return ("JWT 'alg: none' Authentication Bypass Exploit", "CRITICAL", f"Header: {header_json}")
                
                # Check for missing signature when required
                if len(parts) == 2 or (len(parts) == 3 and not parts[2]):
                    return ("JWT Missing Cryptographic Signature", "HIGH", f"Alg: {alg}")

            except Exception:
                pass
        return None

    def inspect_graphql(self, body_str: str) -> Optional[Tuple[str, str, str]]:
        """
        Analyzes GraphQL query depth and introspection.
        Returns (Issue, Severity, Snippet) or None.
        """
        if not body_str:
            return None

        # Check GraphQL Introspection
        if "__schema" in body_str or "__type" in body_str:
            return ("GraphQL Unauthorized Introspection Probe", "HIGH", body_str[:60])

        # Check Query Depth (Nested brackets abuse)
        depth = 0
        max_depth = 0
        for char in body_str:
            if char == '{':
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            elif char == '}':
                depth = max(0, depth - 1)

        if max_depth > self.graphql_depth_limit:
            return (f"GraphQL Deep Nested Query DoS (Depth: {max_depth} > Limit: {self.graphql_depth_limit})", "HIGH", f"Query depth {max_depth}")

        return None

    def check_bola(self, ip: str, path: str) -> Optional[Tuple[str, str, str]]:
        """
        Tracks rapid iteration across consecutive resource IDs (Broken Object Level Authorization probe).
        """
        id_match = re.search(r"/api/(?:v\d+/)?([a-zA-Z_-]+)/(\d+)", path)
        if id_match:
            resource, res_id = id_match.groups()
            key = f"{ip}:{resource}"
            now = time.time()
            
            history = self.bola_tracker.get(key, [])
            history = [(t, i) for t, i in history if now - t < 10]
            history.append((now, res_id))
            self.bola_tracker[key] = history

            # Check if client requested > 6 distinct IDs in 10s
            unique_ids = set(i for t, i in history)
            if len(unique_ids) >= 7:
                return (f"BOLA / ID Enumeration Attack on resource '{resource}'", "HIGH", f"Tested IDs: {list(unique_ids)[:5]}...")

        return None

    def validate_api_request(self, ip: str, path: str, headers: dict, body_str: str) -> Optional[Tuple[str, str, str, str]]:
        """
        Comprehensive API inspection.
        Returns (Category, Description, Severity, Snippet) or None.
        """
        if not self.is_api_route(path):
            return None

        # 1. JWT Inspection
        auth_header = headers.get("Authorization") or headers.get("authorization", "")
        if auth_header:
            jwt_issue = self.inspect_jwt(auth_header)
            if jwt_issue:
                desc, sev, snip = jwt_issue
                return ("API Security / JWT Exploit", desc, sev, snip)

        # 2. BOLA Inspection
        bola_issue = self.check_bola(ip, path)
        if bola_issue:
            desc, sev, snip = bola_issue
            return ("API Authorization (BOLA)", desc, sev, snip)

        # 3. GraphQL Inspection
        if "/graphql" in path or "graphql" in headers.get("content-type", "").lower():
            gql_issue = self.inspect_graphql(body_str)
            if gql_issue:
                desc, sev, snip = gql_issue
                return ("API Security / GraphQL Abuse", desc, sev, snip)

        # 4. Enforce Valid API Key if configured
        if self.valid_api_keys:
            client_key = headers.get(self.api_key_header)
            if not client_key or client_key not in self.valid_api_keys:
                return ("API Authentication Violation", f"Missing or Invalid {self.api_key_header}", "HIGH", f"Provided Key: {client_key}")

        return None

"""
=============================================================================
                  LIGHTNING - DASHBOARD AUTHENTICATION GUARD
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
Secures the Web SOC Command Center with session-based token authentication
so only authorized users can view the dashboard.
"""

import os
import sys
import time
import hashlib
import hmac
import json
import secrets
from typing import Optional, Dict

# Default dashboard credentials (user should change via config)
DEFAULT_DASHBOARD_USER = "admin"
DEFAULT_DASHBOARD_PASS_HASH = hashlib.sha256("lightning".encode()).hexdigest()

# Active sessions store (token -> expiry timestamp)
_active_sessions: Dict[str, float] = {}
SESSION_TTL = 3600 * 8  # 8 hours


def set_dashboard_credentials(username: str, password_hash: str):
    """Updates the dashboard login credentials."""
    global DEFAULT_DASHBOARD_USER, DEFAULT_DASHBOARD_PASS_HASH
    DEFAULT_DASHBOARD_USER = username
    DEFAULT_DASHBOARD_PASS_HASH = password_hash


def verify_login(username: str, password: str) -> Optional[str]:
    """Verifies credentials and returns a session token if valid."""
    pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if username == DEFAULT_DASHBOARD_USER and pw_hash == DEFAULT_DASHBOARD_PASS_HASH:
        token = secrets.token_hex(32)
        _active_sessions[token] = time.time() + SESSION_TTL
        # Cleanup expired sessions
        now = time.time()
        expired = [t for t, exp in _active_sessions.items() if exp < now]
        for t in expired:
            del _active_sessions[t]
        return token
    return None


def verify_session(token: str) -> bool:
    """Checks if a session token is valid and not expired."""
    if not token:
        return False
    expiry = _active_sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        del _active_sessions[token]
        return False
    return True


def extract_session_token(cookie_header: str) -> Optional[str]:
    """Extracts the LIGHTNING_SESSION token from a Cookie header string."""
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("LIGHTNING_SESSION="):
            return part.split("=", 1)[1].strip()
    return None


def get_login_page_html() -> str:
    """Returns the cyberpunk-themed login page HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ LIGHTNING | Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060913;
            --cyan: #38bdf8;
            --purple: #a855f7;
            --red: #f43f5e;
            --green: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-base);
            color: #f8fafc;
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background-image:
                radial-gradient(circle at 30% 20%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 70% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 40%),
                linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
        }
        .login-card {
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(51, 65, 85, 0.5);
            border-radius: 24px;
            padding: 50px 44px;
            width: 100%;
            max-width: 420px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.4);
        }
        .brand-icon {
            font-size: 3rem;
            margin-bottom: 10px;
            animation: pulse-glow 2s infinite ease-in-out;
        }
        .brand-title {
            font-size: 1.6rem;
            font-weight: 900;
            background: linear-gradient(135deg, #38bdf8 0%, #a855f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 1.5px;
            margin-bottom: 6px;
        }
        .author-badge {
            background: rgba(168, 85, 247, 0.15);
            border: 1px solid rgba(168, 85, 247, 0.4);
            color: #d8b4fe;
            padding: 3px 10px;
            border-radius: 14px;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            display: inline-block;
            margin-bottom: 30px;
        }
        .field-group {
            margin-bottom: 18px;
            text-align: left;
        }
        .field-group label {
            display: block;
            font-size: 0.8rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
            font-weight: 600;
        }
        .field-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid rgba(51, 65, 85, 0.6);
            border-radius: 12px;
            color: #f8fafc;
            font-size: 1rem;
            font-family: 'Outfit', sans-serif;
            outline: none;
            transition: border-color 0.3s;
        }
        .field-group input:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.1);
        }
        .login-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #38bdf8 0%, #a855f7 100%);
            color: #fff;
            border: none;
            border-radius: 14px;
            font-size: 1.05rem;
            font-weight: 700;
            cursor: pointer;
            letter-spacing: 0.5px;
            margin-top: 8px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(56, 189, 248, 0.35);
        }
        .error-msg {
            color: var(--red);
            font-size: 0.85rem;
            margin-top: 14px;
            font-weight: 600;
            min-height: 1.2em;
        }
        .hint {
            color: #64748b;
            font-size: 0.75rem;
            margin-top: 20px;
        }
        @keyframes pulse-glow {
            0%, 100% { transform: scale(1); filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.4)); }
            50% { transform: scale(1.06); filter: drop-shadow(0 0 16px rgba(168, 85, 247, 0.8)); }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="brand-icon">⚡</div>
        <div class="brand-title">LIGHTNING SOC</div>
        <div class="author-badge">CREATED BY NEXO-TECH BY ALEXANDER</div>

        <form method="POST" action="/__lightning_login__">
            <div class="field-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter username" autocomplete="username" required autofocus />
            </div>
            <div class="field-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password" autocomplete="current-password" required />
            </div>
            <button class="login-btn" type="submit">⚡ Authenticate & Enter</button>
        </form>
        <div class="error-msg" id="err">__ERROR_PLACEHOLDER__</div>
        <div class="hint">Default: admin / lightning — change in Settings (Option 6)</div>
    </div>
</body>
</html>"""

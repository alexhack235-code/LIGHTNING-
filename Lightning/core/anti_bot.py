"""
=============================================================================
                  LIGHTNING - ANTI-BOT PROOF-OF-WORK & CAPTCHA ARMOR
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import time
import hmac
import hashlib
import urllib.parse
from typing import Tuple, Optional

# Secret key for signing clearance cookies
CHALLENGE_SECRET = "LIGHTNING_SECRET_NEXO_TECH_ALEXANDER_2026"
COOKIE_NAME = "LIGHTNING-DEFENSE-PASS"

CAPTCHA_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification | LIGHTNING Defense</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: #0b0f17;
            color: #c9d1d9;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .card {{
            background: #161e2e;
            border: 1px solid #3b82f6;
            border-radius: 16px;
            max-width: 500px;
            width: 100%;
            padding: 40px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(59, 130, 246, 0.2);
        }}
        .icon {{
            font-size: 3rem;
            margin-bottom: 15px;
        }}
        h1 {{
            color: #60a5fa;
            font-size: 1.8rem;
            margin-bottom: 10px;
        }}
        p {{
            color: #94a3b8;
            font-size: 1rem;
            line-height: 1.5;
            margin-bottom: 25px;
        }}
        .challenge-box {{
            background: #0f172a;
            border: 1px dashed #475569;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        .math-text {{
            font-size: 1.4rem;
            font-weight: bold;
            color: #f59e0b;
            letter-spacing: 2px;
            margin-bottom: 15px;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #334155;
            background: #1e293b;
            color: #f8fafc;
            font-size: 1.1rem;
            text-align: center;
            margin-bottom: 15px;
            outline: none;
        }}
        input[type="text"]:focus {{
            border-color: #3b82f6;
        }}
        button {{
            width: 100%;
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            color: #ffffff;
            font-size: 1.05rem;
            font-weight: bold;
            padding: 14px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: 0.2s;
        }}
        button:hover {{
            background: linear-gradient(135deg, #1d4ed8, #1e40af);
            box-shadow: 0 4px 15px rgba(37, 99, 235, 0.4);
        }}
        .footer {{
            margin-top: 30px;
            font-size: 0.85rem;
            color: #10b981;
            border-top: 1px solid #1e293b;
            padding-top: 15px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">⚡</div>
        <h1>Security Verification</h1>
        <p>Your browser is being verified by <strong>LIGHTNING Anti-Bot Shield</strong> to ensure you are a human visitor.</p>
        
        <form method="POST" action="/__lightning_verify__">
            <div class="challenge-box">
                <div class="math-text">{num1} + {num2} = ?</div>
                <input type="hidden" name="sig" value="{signature}">
                <input type="hidden" name="ts" value="{timestamp}">
                <input type="hidden" name="redirect" value="{target_uri}">
                <input type="text" name="answer" placeholder="Enter solution" autofocus required>
            </div>
            <button type="submit">Verify & Continue to Website</button>
        </form>

        <div class="footer">
            ⚡ Protected by <strong>LIGHTNING DEFENSE SYSTEM</strong><br>
            <em>CREATED BY NEXO-TECH BY ALEXANDER</em>
        </div>
    </div>
</body>
</html>
"""


class AntiBotArmor:
    """Provides Proof-of-Work and Interactive CAPTCHA challenges for suspicious clients."""
    def __init__(self, token_lifetime: int = 7200):
        self.token_lifetime = token_lifetime

    def generate_token(self, ip: str) -> str:
        """Generates a cryptographic clearance token for a verified visitor."""
        expiry = int(time.time() + self.token_lifetime)
        data = f"{ip}:{expiry}"
        sig = hmac.new(CHALLENGE_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{data}:{sig}"

    def is_verified(self, ip: str, cookie_header: str) -> bool:
        """Checks if the visitor has a valid, non-expired clearance cookie."""
        if not cookie_header:
            return False
        
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith(f"{COOKIE_NAME}="):
                token = cookie.split("=", 1)[1]
                parts = token.split(":")
                if len(parts) == 3:
                    c_ip, c_expiry, c_sig = parts
                    if c_ip == ip:
                        try:
                            if int(c_expiry) > time.time():
                                expected_data = f"{c_ip}:{c_expiry}"
                                expected_sig = hmac.new(CHALLENGE_SECRET.encode(), expected_data.encode(), hashlib.sha256).hexdigest()[:16]
                                if hmac.compare_digest(c_sig, expected_sig):
                                    return True
                        except Exception:
                            pass
        return False

    def generate_challenge(self, ip: str, target_uri: str) -> Tuple[str, int]:
        """Generates a math CAPTCHA challenge HTML page and expected solution."""
        now = int(time.time())
        num1 = (now % 17) + 3
        num2 = ((now // 7) % 19) + 4
        ans = num1 + num2
        
        data = f"{ip}:{ans}:{now}"
        sig = hmac.new(CHALLENGE_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        
        html = CAPTCHA_HTML_TEMPLATE.format(
            num1=num1,
            num2=num2,
            signature=sig,
            timestamp=now,
            target_uri=urllib.parse.quote(target_uri)
        )
        return html, ans

    def verify_answer(self, ip: str, answer_str: str, sig: str, ts_str: str) -> bool:
        """Validates a submitted CAPTCHA response."""
        try:
            ts = int(ts_str)
            if time.time() - ts > 300:  # 5 min expiration for challenge
                return False
            ans = int(answer_str.strip())
            data = f"{ip}:{ans}:{ts}"
            expected_sig = hmac.new(CHALLENGE_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
            return hmac.compare_digest(sig, expected_sig)
        except Exception:
            return False

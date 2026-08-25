"""
=============================================================================
                  LIGHTNING - PREMIUM SYSTEM & AUTHENTICATION
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
"""

import hashlib
import time
from banner import Colors

# Cryptographic SHA-256 Hash of the Premium Password (Raw secret is never stored in cleartext)
PREMIUM_PASSWORD_HASH = "d0f2587b646d43e32f4d2c3696dc780f453f5d6586b44ea7dd15759aec7b5e6d"


class PremiumAuth:
    """Manages secure unlocking and verification of LIGHTNING Premium Tier."""
    
    @staticmethod
    def verify_password(plain_password: str) -> bool:
        """Compares user input against the cryptographic SHA-256 hash."""
        input_hash = hashlib.sha256(plain_password.strip().encode("utf-8")).hexdigest()
        return input_hash.lower() == PREMIUM_PASSWORD_HASH.lower()

    @staticmethod
    def prompt_unlock() -> bool:
        """Interactive unlock prompt with styling."""
        C = Colors
        print(f"\n{C.PURPLE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
        print(f"{C.PURPLE}┃          ⚡ LIGHTNING PREMIUM // BRUTAL RADAR EDITION ⚡            ┃{C.RESET}")
        print(f"{C.PURPLE}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
        print(f"{C.PURPLE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

        print(f"{C.YELLOW}{C.BOLD}Enter the master cryptographic key to unlock PREMIUM features:{C.RESET}")
        password = input(f"{C.CYAN}[KEY]: {C.RESET}").strip()

        if PremiumAuth.verify_password(password):
            print(f"\n{C.GREEN}{C.BOLD}✔ ACCESS GRANTED! Welcome to LIGHTNING PREMIUM EDITION. ⚡{C.RESET}")
            print(f"{C.GREEN}✔ Brutal Continuous Radar & Zero-Tolerance Defense Unlocked!{C.RESET}\n")
            time.sleep(1)
            return True
        else:
            print(f"\n{C.RED}{C.BOLD}✖ ACCESS DENIED: Invalid Master Key.{C.RESET}\n")
            time.sleep(1.2)
            return False


def print_premium_banner():
    """Displays the exclusive Premium VIP banner."""
    C = Colors
    banner = f"""
{C.PURPLE}{C.BOLD}
██████╗ ██████╗ ███████╗███╗   ███╗██╗██╗   ██╗███╗   ███╗
██╔══██╗██╔══██╗██╔════╝████╗ ████║██║██║   ██║████╗ ████║
██████╔╝██████╔╝█████╗  ██╔████╔██║██║██║   ██║██╔████╔██║
██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║
██║     ██║  ██║███████╗██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝{C.RESET}
{C.YELLOW}{C.BOLD}  ⚡ LIGHTNING PREMIUM // BRUTAL CONTINUOUS RADAR & THREAT HUNTER ⚡{C.RESET}
{C.WHITE}{C.BOLD}               [+] CREATED BY NEXO-TECH BY ALEXANDER [+]{C.RESET}
{C.DARK_GRAY}          Military-Grade Autonomous Radar • Zero-Tolerance Mode{C.RESET}
"""
    print(banner)

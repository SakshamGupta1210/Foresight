"""
Comprehensive Unit & Integration Tests for FORESIGHT
Tests:
1. Deterministic Security Heuristics (Spoofing, TLD, IP, Punycode, Extensions)
2. Risk Engine Classification & Explainability
3. Universal Dynamic QR Code Decoding
4. User Authentication & Password Hashing (PBKDF2-HMAC-SHA256)
5. Session Token Validation & Expiry
6. User Personal Scan History & Strict Data Isolation (User A vs User B)
7. Dashboard Metric Aggregations
8. Global 24h Real Unique Access Monitoring & Cybercell Incident Reporting
"""

import sys
import os
import io
import uuid
import unittest
import qrcode

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analyzer.heuristics import analyze_heuristics, calculate_levenshtein, check_domain_spoofing
from backend.analyzer.risk_engine import evaluate_destination
from backend.qr_decoder import decode_qr_image
from backend.storage.access_tracker import (
    init_db,
    create_user,
    authenticate_user,
    get_user_by_token,
    delete_session,
    save_user_scan,
    get_user_scans,
    get_user_scan_by_id,
    get_user_dashboard_stats,
    record_access,
    get_incident_by_id
)

class TestForesightHeuristics(unittest.TestCase):

    def test_levenshtein_distance(self):
        self.assertEqual(calculate_levenshtein("paypal", "paypa1"), 1)
        self.assertEqual(calculate_levenshtein("google", "goog1e"), 1)
        self.assertEqual(calculate_levenshtein("amazon", "amazon"), 0)

    def test_official_domains(self):
        h = analyze_heuristics("https://en.wikipedia.org/wiki/Cybersecurity")
        self.assertTrue(h["is_valid"])
        self.assertLess(h["penalties"], 20)

    def test_raw_ip_detection(self):
        h = analyze_heuristics("http://192.168.1.1/router-login")
        self.assertTrue(any(f["type"] == "raw_ip" for f in h["findings"]))
        self.assertGreaterEqual(h["penalties"], 35)

    def test_typosquatting_brand_spoof(self):
        spoof = check_domain_spoofing("paypa1.com", [], "paypa1.com")
        self.assertTrue(spoof["spoof_detected"])
        self.assertEqual(spoof["type"], "typosquatting")

        h = analyze_heuristics("https://paypa1.com/signin")
        self.assertTrue(any("mimics legitimate brand" in r for r in h["reasons"]))
        self.assertGreaterEqual(h["penalties"], 50)

    def test_subdomain_deception(self):
        spoof = check_domain_spoofing("attacker-site.com", ["paypal", "security"], "paypal.security.attacker-site.com")
        self.assertTrue(spoof["spoof_detected"])
        self.assertEqual(spoof["type"], "subdomain_deception")

    def test_punycode_detection(self):
        h = analyze_heuristics("https://xn--apple-qsa.com/id")
        self.assertTrue(any(f["type"] == "punycode" for f in h["findings"]))

    def test_credential_embedding(self):
        h = analyze_heuristics("https://user:password@malicious.com")
        self.assertTrue(any(f["type"] == "credential_disguise" for f in h["findings"]))

    def test_dangerous_extension(self):
        h = analyze_heuristics("https://example.com/invoice.exe")
        self.assertTrue(any(f["type"] == "dangerous_extension" for f in h["findings"]))


class TestRiskEngine(unittest.TestCase):

    def test_safe_classification(self):
        result = evaluate_destination("https://www.wikipedia.org", follow_redirects=False)
        self.assertEqual(result["status"], "SAFE")
        self.assertLess(result["score"], 30)
        self.assertTrue(len(result["reasons"]) > 0)

    def test_dangerous_classification(self):
        result = evaluate_destination("http://paypa1-account-update.xyz/verify-banking-login.exe", follow_redirects=False)
        self.assertEqual(result["status"], "DANGEROUS")
        self.assertGreaterEqual(result["score"], 70)
        self.assertTrue(any("mimics" in r or "typosquatting" in r or "executable" in r for r in result["reasons"]))

    def test_suspicious_classification(self):
        result = evaluate_destination("http://special-promo-event.buzz", follow_redirects=False)
        self.assertIn(result["status"], ["SUSPICIOUS", "DANGEROUS"])
        self.assertGreaterEqual(result["score"], 30)


class TestUniversalQRDecoder(unittest.TestCase):

    def test_decode_any_arbitrary_qr_code(self):
        random_url = f"https://dynamic-test-portal-{uuid.uuid4().hex}.org/account"
        qr_img = qrcode.make(random_url)
        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        image_bytes = buf.getvalue()

        success, decoded_url, method = decode_qr_image(image_bytes)
        self.assertTrue(success)
        self.assertEqual(decoded_url, random_url)

        analysis = evaluate_destination(decoded_url, follow_redirects=False)
        self.assertEqual(analysis["original_url"], random_url)
        self.assertIn("score", analysis)
        self.assertIn("reasons", analysis)


class TestAuthenticationAndDataSeparation(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_registration_and_validation(self):
        uid = uuid.uuid4().hex[:6]
        name = "Alice Security"
        email = f"alice_{uid}@foresight.test"
        password = "SecurePassword123"

        # Valid registration
        user, token = create_user(name, email, password)
        self.assertEqual(user["name"], name)
        self.assertEqual(user["email"], email)
        self.assertTrue(len(token) > 20)

        # Duplicate email should raise ValueError
        with self.assertRaises(ValueError):
            create_user("Another Alice", email, "DifferentPassword123")

        # Short password
        with self.assertRaises(ValueError):
            create_user("Bob", f"bob_{uid}@foresight.test", "123")

        # Invalid email
        with self.assertRaises(ValueError):
            create_user("Charlie", "invalid-email-string", "ValidPassword123")

    def test_login_and_session(self):
        uid = uuid.uuid4().hex[:6]
        email = f"user_{uid}@foresight.test"
        password = "MyPassword@2026"

        create_user("Auth Tester", email, password)

        # Correct login
        user, token = authenticate_user(email, password)
        self.assertEqual(user["email"], email)

        # Token verification
        user_from_token = get_user_by_token(token)
        self.assertIsNotNone(user_from_token)
        self.assertEqual(user_from_token["id"], user["id"])

        # Wrong password
        with self.assertRaises(ValueError):
            authenticate_user(email, "WrongPassword")

        # Non-existent email
        with self.assertRaises(ValueError):
            authenticate_user("nonexistent@foresight.test", password)

        # Logout deletes token
        delete_session(token)
        self.assertIsNone(get_user_by_token(token))

    def test_strict_user_data_isolation(self):
        # Create User A
        uid_a = uuid.uuid4().hex[:6]
        user_a, token_a = create_user("User Alpha", f"alpha_{uid_a}@test.com", "PasswordAlpha123")

        # Create User B
        uid_b = uuid.uuid4().hex[:6]
        user_b, token_b = create_user("User Beta", f"beta_{uid_b}@test.com", "PasswordBeta123")

        # User A saves 2 scans
        scan_a1 = save_user_scan(user_a["id"], {
            "original_url": "https://alpha-site-1.com",
            "final_url": "https://alpha-site-1.com",
            "domain": "alpha-site-1.com",
            "score": 10,
            "status": "SAFE",
            "reasons": ["Standard verified domain"],
            "redirects": {"hops": []},
            "heuristics": {"findings": []}
        })
        scan_a2 = save_user_scan(user_a["id"], {
            "original_url": "https://alpha-site-2.com",
            "final_url": "https://alpha-site-2.com",
            "domain": "alpha-site-2.com",
            "score": 85,
            "status": "DANGEROUS",
            "reasons": ["Credential phishing detected"],
            "redirects": {"hops": []},
            "heuristics": {"findings": []}
        })

        # User B saves 1 scan
        scan_b1 = save_user_scan(user_b["id"], {
            "original_url": "https://beta-site-1.com",
            "final_url": "https://beta-site-1.com",
            "domain": "beta-site-1.com",
            "score": 45,
            "status": "SUSPICIOUS",
            "reasons": ["Unusual redirect behavior"],
            "redirects": {"hops": []},
            "heuristics": {"findings": []}
        })

        # User A should see ONLY their 2 scans
        scans_a = get_user_scans(user_a["id"])
        self.assertEqual(len(scans_a), 2)
        urls_a = [s["original_url"] for s in scans_a]
        self.assertIn("https://alpha-site-1.com", urls_a)
        self.assertIn("https://alpha-site-2.com", urls_a)
        self.assertNotIn("https://beta-site-1.com", urls_a)

        # User B should see ONLY their 1 scan
        scans_b = get_user_scans(user_b["id"])
        self.assertEqual(len(scans_b), 1)
        self.assertEqual(scans_b[0]["original_url"], "https://beta-site-1.com")
        self.assertNotIn("https://alpha-site-1.com", [s["original_url"] for s in scans_b])

        # Cross-user access check: User B CANNOT view User A's scan details by ID
        unauthorized_scan = get_user_scan_by_id(user_b["id"], scan_a1["scan_id"])
        self.assertIsNone(unauthorized_scan, "User B must not be able to retrieve User A's scan by scan_id")

        # Dashboard stats check
        stats_a = get_user_dashboard_stats(user_a["id"])
        self.assertEqual(stats_a["total_scans"], 2)
        self.assertEqual(stats_a["safe_scans"], 1)
        self.assertEqual(stats_a["dangerous_scans"], 1)
        self.assertEqual(stats_a["suspicious_scans"], 0)


class TestAccessTrackerRealActivity(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_real_access_threshold_trigger(self):
        test_url = f"https://threshold-test-{uuid.uuid4().hex}.org/landing"
        mock_analysis = {
            "score": 75,
            "status": "DANGEROUS",
            "final_url": test_url,
            "reasons": ["High risk test signal"],
            "redirects": {"hop_count": 0, "destination_drift": False}
        }

        # First 99 accesses do NOT trigger
        for i in range(1, 100):
            client = f"client_{i}_{uuid.uuid4().hex[:6]}"
            res = record_access(test_url, client, analysis_result=mock_analysis)
            self.assertEqual(res["unique_accesses_24h"], i)
            self.assertFalse(res["threshold_met"])

        # 100th access triggers incident
        client_100 = f"client_100_{uuid.uuid4().hex[:6]}"
        res_100 = record_access(test_url, client_100, analysis_result=mock_analysis)
        self.assertEqual(res_100["unique_accesses_24h"], 100)
        self.assertTrue(res_100["threshold_met"])
        self.assertIsNotNone(res_100["incident_report"])
        self.assertTrue(res_100["incident_report"]["incident_id"].startswith("CC-INC-2026-"))


if __name__ == "__main__":
    unittest.main()

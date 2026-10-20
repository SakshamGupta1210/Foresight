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
    delete_user_scan,
    clear_user_scans,
    change_user_password,
    get_user_dashboard_stats,
    record_access,
    get_incident_by_id
)
from fastapi.testclient import TestClient
from backend.main import app

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


class TestPaymentAndAlternativePayloads(unittest.TestCase):

    def test_valid_upi_qr(self):
        upi_payload = "upi://pay?pa=merchant.store@okhdfcbank&pn=Super%20Mart&am=450.00&cu=INR"
        res = evaluate_destination(upi_payload, follow_redirects=False)
        self.assertEqual(res["status"], "SAFE")
        self.assertLess(res["score"], 30)
        self.assertTrue(res["is_payment"])
        self.assertEqual(res["payload_type"], "UPI")
        self.assertEqual(res["payment_details"]["payee_address"], "merchant.store@okhdfcbank")
        self.assertEqual(res["payment_details"]["payee_name"], "Super Mart")
        self.assertTrue(res["payment_details"]["is_fixed_amount"])
        self.assertTrue(any("Super Mart" in r for r in res["reasons"]))

    def test_malformed_upi_missing_pa(self):
        bad_upi = "upi://pay?pn=UnknownStore&am=100.00"
        res = evaluate_destination(bad_upi, follow_redirects=False)
        self.assertIn(res["status"], ["SUSPICIOUS", "DANGEROUS"])
        self.assertGreaterEqual(res["score"], 30)
        self.assertTrue(any("Missing mandatory payee address" in r for r in res["reasons"]))

    def test_deceptive_payee_name_upi(self):
        deceptive_upi = "upi://pay?pa=scam@upi&pn=Police%20Cybercell%20Penalty%20Fine&am=5000"
        res = evaluate_destination(deceptive_upi, follow_redirects=False)
        self.assertIn(res["status"], ["SUSPICIOUS", "DANGEROUS"])
        self.assertGreaterEqual(res["score"], 40)
        self.assertTrue(any("Coercive or deceptive payee name" in r for r in res["reasons"]))

    def test_plain_text_payload(self):
        text_payload = "Room 302 Confirmed Booking Reference 88412"
        res = evaluate_destination(text_payload, follow_redirects=False)
        self.assertEqual(res["status"], "SAFE")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["payload_type"], "TEXT")
        self.assertFalse(res["is_payment"])

    def test_contact_vcard_payload(self):
        vcard_payload = "BEGIN:VCARD\nVERSION:3.0\nFN:Inspector Sharma\nTEL:+919876543210\nEND:VCARD"
        res = evaluate_destination(vcard_payload, follow_redirects=False)
        self.assertEqual(res["status"], "SAFE")
        self.assertLess(res["score"], 30)
        self.assertEqual(res["payload_type"], "CONTACT")

    def test_wifi_payload(self):
        wifi_payload = "WIFI:S:GuestAccess;T:WPA;P:Welcome2026;;"
        res = evaluate_destination(wifi_payload, follow_redirects=False)
        self.assertEqual(res["status"], "SAFE")
        self.assertLess(res["score"], 30)
        self.assertEqual(res["payload_type"], "WIFI")


class TestHttpVsHttpsScoring(unittest.TestCase):

    def test_legitimate_http_website_not_falsely_suspicious(self):
        # A normal HTTP site without phishing/fraud indicators should NOT be marked SUSPICIOUS (score < 30)
        res = evaluate_destination("http://example.com", follow_redirects=False)
        self.assertEqual(res["status"], "SAFE")
        self.assertLess(res["score"], 30)
        self.assertTrue(any("Unencrypted transport" in r for r in res["reasons"]))

    def test_legitimate_https_website(self):
        res = evaluate_destination("https://example.com", follow_redirects=False)
        self.assertEqual(res["status"], "SAFE")
        self.assertLess(res["score"], 30)


class TestSSRFPrevention(unittest.TestCase):

    def test_ssrf_loopback_blocked(self):
        res = evaluate_destination("http://127.0.0.1:8000/api/admin", follow_redirects=True)
        self.assertIn(res["status"], ["SUSPICIOUS", "DANGEROUS"])
        self.assertGreaterEqual(res["score"], 30)
        self.assertTrue(any("SSRF" in r or "private" in r or "internal" in r.lower() for r in res["reasons"]))

    def test_ssrf_metadata_ip_blocked(self):
        res = evaluate_destination("http://169.254.169.254/latest/meta-data", follow_redirects=True)
        self.assertIn(res["status"], ["SUSPICIOUS", "DANGEROUS"])
        self.assertGreaterEqual(res["score"], 30)
        self.assertTrue(any("SSRF" in r or "internal" in r.lower() or "blocked" in r.lower() for r in res["reasons"]))


class TestHistoryDeletionAndOwnership(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_delete_single_scan_and_ownership(self):
        uid_a = uuid.uuid4().hex[:6]
        user_a, _ = create_user("Deleter A", f"del_a_{uid_a}@test.com", "Password123")
        uid_b = uuid.uuid4().hex[:6]
        user_b, _ = create_user("Deleter B", f"del_b_{uid_b}@test.com", "Password123")

        scan = save_user_scan(user_a["id"], {
            "original_url": "https://delete-me.org",
            "final_url": "https://delete-me.org",
            "domain": "delete-me.org",
            "score": 15,
            "status": "SAFE"
        })

        # User B CANNOT delete User A's scan
        deleted_by_b = delete_user_scan(user_b["id"], scan["scan_id"])
        self.assertFalse(deleted_by_b)

        # Scan still exists for User A
        self.assertIsNotNone(get_user_scan_by_id(user_a["id"], scan["scan_id"]))

        # User A CAN delete their own scan
        deleted_by_a = delete_user_scan(user_a["id"], scan["scan_id"])
        self.assertTrue(deleted_by_a)

        # Scan no longer exists
        self.assertIsNone(get_user_scan_by_id(user_a["id"], scan["scan_id"]))

    def test_clear_all_scans_isolation(self):
        uid_a = uuid.uuid4().hex[:6]
        user_a, _ = create_user("Clearer A", f"clr_a_{uid_a}@test.com", "Password123")
        uid_b = uuid.uuid4().hex[:6]
        user_b, _ = create_user("Clearer B", f"clr_b_{uid_b}@test.com", "Password123")

        save_user_scan(user_a["id"], {"original_url": "https://a1.org", "score": 10, "status": "SAFE"})
        save_user_scan(user_a["id"], {"original_url": "https://a2.org", "score": 20, "status": "SAFE"})
        save_user_scan(user_b["id"], {"original_url": "https://b1.org", "score": 30, "status": "SUSPICIOUS"})

        # User A clears their scans
        cleared_count = clear_user_scans(user_a["id"])
        self.assertEqual(cleared_count, 2)
        self.assertEqual(len(get_user_scans(user_a["id"])), 0)

        # User B's scan remains untouched
        scans_b = get_user_scans(user_b["id"])
        self.assertEqual(len(scans_b), 1)
        self.assertEqual(scans_b[0]["original_url"], "https://b1.org")


class TestChangePassword(unittest.TestCase):

    def setUp(self):
        init_db()

    def test_change_password_flow(self):
        uid = uuid.uuid4().hex[:6]
        email = f"pwd_user_{uid}@test.com"
        old_pwd = "OldPassword123"
        new_pwd = "NewPassword456"

        user, _ = create_user("Password Changer", email, old_pwd)

        # Wrong current password should fail
        with self.assertRaises(ValueError):
            change_user_password(user["id"], "IncorrectOldPwd", new_pwd)

        # Too short new password should fail
        with self.assertRaises(ValueError):
            change_user_password(user["id"], old_pwd, "123")

        # Correct current password succeeds
        res = change_user_password(user["id"], old_pwd, new_pwd)
        self.assertTrue(res)

        # Old password no longer authenticates
        with self.assertRaises(ValueError):
            authenticate_user(email, old_pwd)

        # New password authenticates successfully
        u_auth, tok = authenticate_user(email, new_pwd)
        self.assertEqual(u_auth["id"], user["id"])
        self.assertTrue(len(tok) > 20)


class TestEndpointsAndStaticFiles(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_static_files_return_200(self):
        resp_css = self.client.get("/static/css/styles.css")
        self.assertEqual(resp_css.status_code, 200)
        self.assertIn("text/css", resp_css.headers.get("content-type", ""))

        resp_guard = self.client.get("/static/js/auth-guard.js")
        self.assertEqual(resp_guard.status_code, 200)

    def test_api_auth_required_endpoints(self):
        # Protected endpoints return 401 without Bearer token
        r1 = self.client.get("/api/auth/me")
        self.assertEqual(r1.status_code, 401)

        r2 = self.client.get("/api/user/scans")
        self.assertEqual(r2.status_code, 401)

        r3 = self.client.delete("/api/user/scans/SCN-FAKE123")
        self.assertEqual(r3.status_code, 401)

        r4 = self.client.delete("/api/user/scans")
        self.assertEqual(r4.status_code, 401)

        r5 = self.client.post("/api/auth/change-password", json={"current_password": "a", "new_password": "b"})
        self.assertEqual(r5.status_code, 401)


if __name__ == "__main__":
    unittest.main()

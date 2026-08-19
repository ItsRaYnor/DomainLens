import os
import tempfile
import unittest
from unittest.mock import patch


class CipherOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        os.environ["DOMAINLENS_DB"] = os.path.join(cls.tempdir.name, "order.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import importlib
        import app

        cls.app = importlib.reload(app)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()
        for key in ("DOMAINLENS_DB", "DOMAINLENS_DISABLE_SCHEDULER"):
            os.environ.pop(key, None)

    def test_not_applicable_without_phase_out(self):
        accepted = [
            {"name": "ECDHE-ECDSA-AES256-GCM-SHA384", "protocol": "TLSv1.2"},
            {"name": "ECDHE-ECDSA-AES128-CCM", "protocol": "TLSv1.2"},
            {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3"},
        ]
        result = self.app.check_cipher_order("example.com", accepted=accepted)
        self.assertFalse(result["applicable"])
        self.assertTrue(result["pass"])

    def test_detects_preference_for_phase_out(self):
        """internet.nl-style: server ranks CBC-SHA384 above AES-CCM."""
        accepted = [
            {"name": "ECDHE-ECDSA-AES256-SHA384", "protocol": "TLSv1.2"},
            {"name": "ECDHE-ECDSA-AES128-CCM", "protocol": "TLSv1.2"},
            {"name": "ECDHE-ECDSA-AES256-GCM-SHA384", "protocol": "TLSv1.2"},
        ]

        def fake_negotiate(domain, port, cipher_list, timeout=5):
            # Simulate server order: GCM > SHA384 > CCM
            # Pairwise offer is "strong:weak" — pick the higher server-ranked one.
            names = [p for p in cipher_list.split(":") if p and not p.startswith("@")]
            rank = {
                "ECDHE-ECDSA-AES256-GCM-SHA384": 0,
                "ECDHE-ECDSA-AES256-SHA384": 1,
                "ECDHE-ECDSA-AES128-CCM": 2,
            }
            chosen = sorted(names, key=lambda n: rank.get(n, 99))[0]
            bits = 256 if "256" in chosen else 128
            return (chosen, "TLSv1.2", bits)

        with patch.object(self.app, "_negotiate_tls12_ciphers", side_effect=fake_negotiate):
            result = self.app.check_cipher_order("cdn.example.com", accepted=accepted)

        self.assertTrue(result["applicable"])
        self.assertFalse(result["pass"])
        self.assertEqual(result["server_preferred"], "ECDHE-ECDSA-AES256-SHA384")
        self.assertEqual(
            result["server_preferred_iana"],
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        )
        self.assertEqual(result["server_preferred_level"], "phased_out")
        self.assertEqual(result["expected_preferred"], "ECDHE-ECDSA-AES128-CCM")
        self.assertEqual(
            result["expected_preferred_iana"],
            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        )

    def test_pass_when_server_ranks_sufficient_first(self):
        accepted = [
            {"name": "ECDHE-ECDSA-AES256-SHA384", "protocol": "TLSv1.2"},
            {"name": "ECDHE-ECDSA-AES128-CCM", "protocol": "TLSv1.2"},
        ]

        def fake_negotiate(domain, port, cipher_list, timeout=5):
            # Server order: CCM > SHA384 — always prefer Sufficient.
            names = [p for p in cipher_list.split(":") if p and not p.startswith("@")]
            if "ECDHE-ECDSA-AES128-CCM" in names:
                return ("ECDHE-ECDSA-AES128-CCM", "TLSv1.2", 128)
            return (names[0], "TLSv1.2", 256)

        with patch.object(self.app, "_negotiate_tls12_ciphers", side_effect=fake_negotiate):
            result = self.app.check_cipher_order("example.com", accepted=accepted)

        self.assertTrue(result["applicable"])
        self.assertTrue(result["pass"])

    def test_full_list_offer_alone_would_miss_inversion(self):
        """GCM-first servers still fail if phase-out ranks above CCM."""
        accepted = [
            {"name": "ECDHE-ECDSA-AES256-SHA384", "protocol": "TLSv1.2"},
            {"name": "ECDHE-ECDSA-AES128-CCM", "protocol": "TLSv1.2"},
            {"name": "ECDHE-ECDSA-AES256-GCM-SHA384", "protocol": "TLSv1.2"},
        ]

        def fake_negotiate(domain, port, cipher_list, timeout=5):
            names = [p for p in cipher_list.split(":") if p and not p.startswith("@")]
            rank = {
                "ECDHE-ECDSA-AES256-GCM-SHA384": 0,
                "ECDHE-ECDSA-AES256-SHA384": 1,
                "ECDHE-ECDSA-AES128-CCM": 2,
            }
            chosen = sorted(names, key=lambda n: rank.get(n, 99))[0]
            bits = 256 if "256" in chosen else 128
            return (chosen, "TLSv1.2", bits)

        with patch.object(self.app, "_negotiate_tls12_ciphers", side_effect=fake_negotiate):
            result = self.app.check_cipher_order("cdn.example.com", accepted=accepted)

        # Full-list negotiation would pick GCM (pass), but pairwise finds the inversion.
        self.assertFalse(result["pass"])
        self.assertEqual(result["server_preferred_iana"], "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384")
        self.assertEqual(result["expected_preferred_iana"], "TLS_ECDHE_ECDSA_WITH_AES_128_CCM")


if __name__ == "__main__":
    unittest.main()

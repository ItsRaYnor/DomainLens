import datetime
import os
import socket
import ssl
import tempfile
import threading
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import ncsc_tls
import recommendations


class OcspStaplingProbeTests(unittest.TestCase):
    """The probe tested a stdlib ssl.SSLContext for set_ocsp_client_callback,
    which is a pyOpenSSL method that stdlib ssl does not have. The guard was
    never true, so the function returned False without opening a connection —
    and every scanned domain was reported as having stapling disabled,
    whether it did or not.
    """

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
        import app
        cls.app = app
        cls._start_server()

    @classmethod
    def _start_server(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                           critical=False)
            .sign(key, hashes.SHA256())
        )
        cls._dir = tempfile.mkdtemp()
        cert_path = os.path.join(cls._dir, "cert.pem")
        key_path = os.path.join(cls._dir, "key.pem")
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        cls._srv = socket.socket()
        cls._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls._srv.bind(("127.0.0.1", 0))
        cls._srv.listen(16)
        cls.port = cls._srv.getsockname()[1]

        def serve():
            while True:
                try:
                    raw, _ = cls._srv.accept()
                except OSError:
                    return
                try:
                    wrapped = ctx.wrap_socket(raw, server_side=True)
                    wrapped.close()
                except Exception:
                    pass

        cls._thread = threading.Thread(target=serve, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        try:
            cls._srv.close()
        except Exception:
            pass

    def test_server_without_stapling_returns_false_not_none(self):
        """The distinction that matters: a definite "no staple" is a usable
        answer, an unreachable probe is not."""
        result = self.app._check_ocsp_stapling("localhost", self.port, timeout=5)
        self.assertIs(result, False)

    def test_unreachable_host_is_undetermined(self):
        result = self.app._check_ocsp_stapling("127.0.0.1", 1, timeout=1)
        self.assertIsNone(result)

    def test_missing_pyopenssl_is_undetermined_not_false(self):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "OpenSSL" or name.startswith("OpenSSL."):
                raise ImportError("no pyOpenSSL")
            return real_import(name, *args, **kwargs)

        with mock.patch.object(builtins, "__import__", side_effect=fake_import):
            result = self.app._check_ocsp_stapling("localhost", self.port, timeout=2)
        self.assertIsNone(result)


class OcspReportingTests(unittest.TestCase):
    """An unverifiable claim is worse than an absent one, so only a definite
    False may produce advice."""

    def _advice(self, state):
        # A certificate that names a responder, so the question is only
        # whether stapling happened.
        recs = recommendations._tls({"tls_deep": {
            "success": True, "ocsp_stapling": state,
            "certificate": {"ocsp_uris": ["http://ocsp.example"]},
        }})
        return [r for r in recs if "OCSP" in r["title"]]

    def test_absent_stapling_is_reported(self):
        self.assertEqual(len(self._advice(False)), 1)

    def test_present_stapling_is_not_reported(self):
        self.assertEqual(self._advice(True), [])

    def test_undetermined_stapling_is_not_reported(self):
        self.assertEqual(self._advice(None), [])

    def test_ncsc_ignores_an_undetermined_result(self):
        assessment = ncsc_tls.assess({
            "ssl": {"success": True},
            "tls_deep": {"success": True, "ocsp_stapling": None},
        })
        ids = [f.get("id") for f in (assessment.get("findings") or [])]
        self.assertNotIn("ocsp-stapling", ids)


if __name__ == "__main__":
    unittest.main()


class OcspApplicabilityTests(unittest.TestCase):
    """Let's Encrypt removed the OCSP URI from its certificates in 2025 and
    retired its responders. A certificate with no responder has nothing to
    staple, so "enable OCSP stapling" is an instruction no server can carry
    out — the same class of unactionable advice as recommending COEP to a site
    that embeds third-party images.
    """

    def _advice(self, certificate, stapling=False):
        recs = recommendations._tls({"tls_deep": {
            "success": True, "ocsp_stapling": stapling, "certificate": certificate,
        }})
        return [r for r in recs if "OCSP" in r["title"]]

    def test_a_certificate_with_a_responder_still_gets_the_advice(self):
        items = self._advice({"ocsp_uris": ["http://r3.o.lencr.org"], "issuer_org": "Sectigo"})
        self.assertEqual(items[0]["title"], "OCSP stapling disabled")
        self.assertEqual(items[0]["severity"], "low")

    def test_a_certificate_without_a_responder_is_told_it_cannot(self):
        items = self._advice({"ocsp_uris": [], "issuer_org": "Let's Encrypt"})
        self.assertEqual(items[0]["title"], "OCSP stapling not applicable to this certificate")
        self.assertEqual(items[0]["severity"], "info")
        self.assertIn("Nothing to do", items[0]["fix"])

    def test_the_issuer_is_named_so_the_reason_is_checkable(self):
        items = self._advice({"ocsp_uris": [], "issuer_org": "Let's Encrypt"})
        self.assertIn("Let's Encrypt", items[0]["problem"])

    def test_stapling_present_says_nothing_either_way(self):
        self.assertEqual(self._advice({"ocsp_uris": []}, stapling=True), [])
        self.assertEqual(self._advice({"ocsp_uris": ["http://o"]}, stapling=True), [])

    def test_an_undetermined_probe_still_says_nothing(self):
        self.assertEqual(self._advice({"ocsp_uris": ["http://o"]}, stapling=None), [])

    def test_a_scan_predating_the_field_makes_no_claim(self):
        # Older stored scans have no ocsp_uris key at all. Guessing which way
        # it went would put a claim in the report that was never measured.
        self.assertEqual(self._advice({"issuer_org": "Whoever"}), [])

    def test_the_cdn_is_named_as_the_place_to_change_it(self):
        items = self._advice({"ocsp_uris": ["http://o"], "issuer_org": "Sectigo"})
        self.assertIn("CDN", items[0]["fix"])

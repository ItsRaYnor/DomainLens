"""Probes that do not depend on each other no longer wait for each other.

Three parts of a scan asked one question at a time although no answer
depended on the one before: around thirty DKIM selectors, up to five
openssl signature-hash probes per address, and the CORS, OPTIONS and
soft-404 requests of the web-exposure check. Each test lets a probe finish
only once a second one is running alongside it; one at a time, the first
probe gives up waiting and the test fails.

They also check the report did not change with it: the same results, in
the same order.
"""

import os
import threading
import unittest
from unittest import mock

import security_checks


class _Meeting:
    """The first `parties` calls each wait until all of them have arrived."""

    def __init__(self, parties=2, seconds=3):
        self._barrier = threading.Barrier(parties, timeout=seconds)
        self._lock = threading.Lock()
        self._left = parties
        self.met = True

    def arrive(self):
        with self._lock:
            if self._left <= 0:
                return
            self._left -= 1
        try:
            self._barrier.wait()
        except threading.BrokenBarrierError:
            self.met = False


def _app():
    os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
    import app
    return app


class DkimTests(unittest.TestCase):
    def test_selectors_are_looked_up_side_by_side_and_reported_in_order(self):
        app = _app()
        meeting = _Meeting()
        keys = {"b._domainkey.example.org": ['"v=DKIM1; k=rsa; p=BBB"'],
                "d._domainkey.example.org": ['"v=DKIM1; k=rsa; p=DDD"']}

        def resolve(name, rtype):
            meeting.arrive()
            return keys.get(name, [])

        with mock.patch.object(app, "_resolve", side_effect=resolve):
            result = app.check_dkim("example.org", selectors=["a", "b", "c", "d"])
        self.assertTrue(meeting.met, "the DKIM selectors were still asked one at a time")
        self.assertEqual(["b", "d"], [s["selector"] for s in result["selectors"]])
        self.assertTrue(result["pass"])


class SignatureHashTests(unittest.TestCase):
    def test_probes_run_side_by_side_and_each_address_keeps_its_own_answers(self):
        app = _app()
        meeting = _Meeting()
        endpoints = [{"family": "IPv4", "address": "192.0.2.10"},
                     {"family": "IPv6", "address": "2001:db8::10"}]

        def probe(domain, port, host, sigalgs, timeout=8):
            meeting.arrive()
            if host == "2001:db8::10" and sigalgs.startswith("ECDSA+SHA1"):
                return "SHA1"
            if "SHA256" in sigalgs:
                return "SHA256"
            return None

        with mock.patch.object(app, "_test_protocol", return_value={"supported": True}), \
                mock.patch.object(app, "_openssl_peer_signing_digest", side_effect=probe):
            result = app.check_tls_signature_hashes("example.org", endpoints=endpoints)
        self.assertTrue(meeting.met, "the signature-hash probes were still run one at a time")
        self.assertEqual(["192.0.2.10", "2001:db8::10"], [row["address"] for row in result["by_address"]])
        self.assertEqual([], result["by_address"][0]["insufficient"])
        self.assertEqual(["SHA1"], result["by_address"][1]["insufficient"])
        self.assertEqual(["SHA1", "SHA256"], [a["hash"] for a in result["by_address"][1]["accepted"]])
        self.assertFalse(result["pass"])


class WebExposureTests(unittest.TestCase):
    def test_cors_and_options_do_not_wait_for_each_other(self):
        meeting = _Meeting()
        evil_seen = {}

        def get(url, timeout=8, allow_redirects=True, headers=None, method="GET"):
            resp = mock.Mock()
            resp.raw.headers = {}
            resp.headers = {}
            if method == "OPTIONS":
                meeting.arrive()
                resp.headers = {"Allow": "GET, TRACE"}
            elif headers and "Origin" in headers:
                meeting.arrive()
                evil_seen["origin"] = headers["Origin"]
                resp.headers = {"Access-Control-Allow-Origin": headers["Origin"]}
            return resp

        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
                mock.patch.object(security_checks, "_get", side_effect=get), \
                mock.patch.object(security_checks, "_probe_path", return_value=None), \
                mock.patch.object(security_checks, "_get_soft_404_baseline", return_value=None), \
                mock.patch.object(security_checks, "_probe_admin", return_value=None):
            result = security_checks.check_web_exposure("example.org")
        self.assertTrue(meeting.met, "CORS and OPTIONS were still asked one after the other")
        self.assertTrue(result["success"])
        self.assertTrue(result["cors"]["reflects_origin"])
        self.assertTrue(result["methods"]["trace_enabled"])

    def test_admin_probes_are_still_compared_against_the_baseline(self):
        baseline = {"status": 200, "length": 1234}
        seen = []

        def admin(base, path, got_baseline):
            seen.append(got_baseline)
            return None

        resp = mock.Mock()
        resp.raw.headers = {}
        resp.headers = {}
        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
                mock.patch.object(security_checks, "_get", return_value=resp), \
                mock.patch.object(security_checks, "_probe_path", return_value=None), \
                mock.patch.object(security_checks, "_get_soft_404_baseline", return_value=baseline), \
                mock.patch.object(security_checks, "_probe_admin", side_effect=admin):
            security_checks.check_web_exposure("example.org")
        self.assertTrue(seen)
        self.assertTrue(all(b is baseline for b in seen))


if __name__ == "__main__":
    unittest.main()

"""Registration data comes from RDAP and the registries' own WHOIS only.

The general WHOIS text parser (python-whois, with the whois command in the
image) ran beside RDAP on every lookup: a dependency and a subprocess with
the domain name in it, for a parse the code itself said read most layouts
wrong. RDAP and whois_port43 give the same data structured. What older code
read from the text parse -- the expiry date behind "Domain expires soon",
the registrar, the abuse address for a takedown -- now comes from that one
registration result, and the expiry advice no longer breaks on a date
without a time zone.
"""

import os
import pathlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent

RDAP = {"success": True, "source": "rdap", "domain": "example.org", "status": ["active"], "dnssec": True,
        "nameservers": ["ns1.example.net"], "registered": "2001-02-03", "updated": "2026-01-01",
        "expires": "2027-02-03", "registrar": {"name": "Example Registrar", "abuse_email": "abuse@example.net"},
        "reseller": None, "registrant": {"withheld": True}}


_tempdir = None


def setUpModule():
    import tempfile
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "whois.db")


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _app():
    os.environ.setdefault("DOMAINLENS_DISABLE_SCHEDULER", "1")
    import app
    return app


class LookupTests(unittest.TestCase):
    def test_rdap_alone_answers_and_fills_the_flat_fields(self):
        app = _app()
        with mock.patch.object(app.rdap, "lookup", return_value=dict(RDAP)), \
                mock.patch.object(app.whois_port43, "lookup") as port43:
            result = app.lookup_whois("example.org")
        port43.assert_not_called()
        self.assertTrue(result["success"])
        self.assertEqual("registration", result["data_from"])
        self.assertEqual({"domain_name": "example.org", "registrar": "Example Registrar",
                          "registrar_abuse_contact_email": "abuse@example.net", "creation_date": "2001-02-03",
                          "updated_date": "2026-01-01", "expiration_date": "2027-02-03",
                          "name_servers": ["ns1.example.net"], "status": ["active"], "dnssec": True},
                         result["data"])

    def test_a_free_domain_is_an_answer_not_a_fallback(self):
        app = _app()
        free = {"success": False, "state": "measured", "registered": False,
                "error": "The registry has no registration for this domain"}
        with mock.patch.object(app.rdap, "lookup", return_value=free), \
                mock.patch.object(app.whois_port43, "lookup") as port43:
            result = app.lookup_whois("example.org")
        port43.assert_not_called()
        self.assertTrue(result["success"])
        self.assertEqual({}, result["data"])
        self.assertFalse(result["rdap"]["registered"])

    def test_no_answer_anywhere_is_not_measured(self):
        app = _app()
        with mock.patch.object(app.rdap, "lookup", return_value={"success": False, "state": "unmeasured",
                                                                  "error": "RDAP request failed: Timeout"}), \
                mock.patch.object(app.whois_port43, "lookup", return_value={"success": False,
                                                                            "error": "No answer"}):
            result = app.lookup_whois("example.org")
        self.assertFalse(result["success"])
        self.assertEqual("RDAP request failed: Timeout", result["error"])

    def test_a_withheld_holder_gives_no_organisation(self):
        import rdap
        self.assertNotIn("org", rdap.as_whois_data(RDAP))
        named = dict(RDAP, registrant={"withheld": False, "name": "Example BV"})
        self.assertEqual("Example BV", rdap.as_whois_data(named)["org"])


class ExpiryAdviceTests(unittest.TestCase):
    def test_a_date_without_a_time_zone_still_warns(self):
        """RDAP gives "2026-11-02": compared with an aware now it raised
        TypeError, which the advice did not catch."""
        import recommendations
        soon = (datetime.now(timezone.utc) + timedelta(days=6)).date().isoformat()
        out = recommendations._whois({"whois": {"data": {"expiration_date": soon}}})
        self.assertEqual("Domain expires soon", out[0]["title"])


class NoTextParserTests(unittest.TestCase):
    def test_python_whois_is_gone_from_the_code_the_lock_and_the_image(self):
        self.assertNotIn("import whois\n", ROOT.joinpath("app.py").read_text(encoding="utf-8"))
        for name in ("requirements.in", "requirements.txt"):
            self.assertNotIn("python-whois", ROOT.joinpath(name).read_text(encoding="utf-8").lower(), name)
        docker = ROOT.joinpath("Dockerfile").read_text(encoding="utf-8")
        install = docker[docker.index("apt-get install"):docker.index("rm -rf /var/lib/apt/lists")]
        self.assertNotIn("whois", install)

    def test_the_view_does_not_show_the_registration_twice(self):
        js = ROOT.joinpath("static", "js", "whois_view.js").read_text(encoding="utf-8")
        self.assertIn("result.data_from === 'registration' ? ''", js)


if __name__ == "__main__":
    unittest.main()

"""The Spamhaus PBL is policy, not a listing.

Looking up a home connection's address showed "Listed on 1 blocklist(s):
zen.dq.spamhaus.net" in red. ZEN had answered 127.0.0.11, the PBL: a range
that should not send mail straight to other servers, which is what nearly
every home and office connection is, by its provider's own say. A monitor
would have raised a critical "now listed on a DNS blacklist" for it. Only
the overview tile knew the difference. For a sending mail server it still
matters, and the mail analysis says so, at medium.
"""

import pathlib
import unittest
from unittest import mock

import mail_test
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _answer(*codes):
    return [mock.Mock(to_text=mock.Mock(return_value=c)) for c in codes]


class PolicyTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.app_module._dnsbl_alive_cache.clear()

    def _check(self, zen_codes):
        import dns.resolver

        def resolve(name, rdtype):
            if name.startswith("2.0.0.127."):
                return _answer("127.0.0.2")
            if ".zen.dq.spamhaus.net" in name:
                return _answer(*zen_codes)
            raise dns.resolver.NXDOMAIN()

        with mock.patch.object(self.app_module, "_spamhaus_dqs_key", return_value="testkey"), \
             mock.patch("dns.resolver.resolve", side_effect=resolve):
            return self.app_module.check_blacklist("192.0.2.10")

    def test_the_pbl_alone_is_not_a_listing(self):
        result = self._check(["127.0.0.11"])
        self.assertFalse(result["is_listed"])
        self.assertEqual([], result["listed"])
        self.assertEqual(["zen.dq.spamhaus.net"], result["policy"])
        self.assertEqual(len(result["clean"]) + 1, result["measured"])
        import overview
        self.assertEqual("pass", overview.blacklist({"blacklist": result})["state"])

    def test_a_reputation_code_beside_the_pbl_is_a_listing_by_that_code(self):
        result = self._check(["127.0.0.11", "127.0.0.4"])
        self.assertTrue(result["is_listed"])
        self.assertEqual(["zen.dq.spamhaus.net"], result["listed"])
        self.assertEqual("127.0.0.4", result["codes"]["zen.dq.spamhaus.net"])

    def test_the_pages_say_it_is_not_a_reputation_listing(self):
        for path in ("lookup.js", "app.js"):
            js = (ROOT / "static" / "js" / path).read_text(encoding="utf-8")
            self.assertIn("It is not a reputation listing.", js, path)
            self.assertIn(".policy || []", js, path)


class MailTests(unittest.TestCase):
    def test_mail_sent_straight_from_an_end_user_range_is_medium(self):
        from test_mail_test import FakeLookups, _message, _public, _titles
        lookups = FakeLookups(listed={"listed": [], "policy": ["zen.dq.spamhaus.net"], "spamhaus_dqs": True})
        with mock.patch.object(mail_test, "_public", _public):
            result = mail_test.analyse(_message(), lookups=lookups)
        severity = {f["title"]: f["severity"] for f in result["findings"]}
        self.assertEqual("medium", severity.get("The message was sent from an end-user address"))
        self.assertNotIn("The sending address is on a blocklist", _titles(result))

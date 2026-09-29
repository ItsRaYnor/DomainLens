"""Overview tiles that were red for something that was not the domain's defect.

A scan of a site behind a CDN, with mail at a hosted provider and weak-auth
not run, showed three red tiles: Weak auth (never ran), Blacklist (a shared
CDN edge address, and one Spamhaus XBL listing counted twice) and IPv6 Mail
(the provider's MX hosts). The findings list already treated two of them as
context; the tiles contradicted it.
"""

import unittest
from unittest import mock

import overview
from enterprise_harness import EnterpriseAppTestCase

_EDGE = "203.0.113.10"


def _scan(**extra):
    base = {
        "domain": "example.com", "apex_domain": "example.com",
        "dns": {"A": [_EDGE], "MX": ["10 mx.mailhost.example.", "20 mx2.mailhost.example."]},
    }
    base.update(extra)
    return base


class WeakAuthTileTests(unittest.TestCase):
    def test_a_scan_that_did_not_run_it_has_no_tile(self):
        """The missing result compared as "not false" and showed Fail."""
        self.assertIsNone(overview.weak_auth(_scan()))

    def test_skipped_is_not_tested_rather_than_a_verdict(self):
        tile = overview.weak_auth(_scan(weak_auth={"skipped": True, "detail": "not verified"}))
        self.assertEqual("not_tested", tile["state"])

    def test_found_credentials_fail_and_none_found_pass(self):
        self.assertEqual("fail", overview.weak_auth(
            _scan(weak_auth={"weak_credentials_found": True}))["state"])
        self.assertEqual("pass", overview.weak_auth(
            _scan(weak_auth={"weak_credentials_found": False}))["state"])


class BlacklistTileTests(unittest.TestCase):
    def _listed(self, listed, codes, **extra):
        return _scan(blacklist={"ip": _EDGE, "is_listed": True, "listed": listed,
                                "codes": codes}, **extra)

    def test_a_shared_cdn_edge_is_context_not_a_failure(self):
        """Hundreds of sites share the address and it sends none of this
        domain's mail; only the CDN can have it delisted."""
        tile = overview.blacklist(self._listed(
            ["zen.dq.spamhaus.net"], {"zen.dq.spamhaus.net": "127.0.0.4"},
            cdn={"id": "bunny", "name": "BunnyCDN"}))
        self.assertEqual("context", tile["state"])
        self.assertIn("BunnyCDN", tile["note"])

    def test_the_domains_own_listed_server_still_fails(self):
        tile = overview.blacklist(self._listed(
            ["zen.dq.spamhaus.net"], {"zen.dq.spamhaus.net": "127.0.0.2"}))
        self.assertEqual("fail", tile["state"])

    def test_cbl_and_zen_xbl_are_one_listing(self):
        """CBL is published as part of the XBL; ZEN answering 127.0.0.4 is
        the same listing, and the tile named it twice."""
        data = {"listed": ["cbl.abuseat.org", "zen.dq.spamhaus.net"],
                "codes": {"cbl.abuseat.org": "127.0.0.2", "zen.dq.spamhaus.net": "127.0.0.4"}}
        self.assertEqual(["zen.dq.spamhaus.net"], overview.distinct_listings(data))

    def test_cbl_and_a_zen_sbl_listing_stay_two(self):
        data = {"listed": ["cbl.abuseat.org", "zen.dq.spamhaus.net"],
                "codes": {"cbl.abuseat.org": "127.0.0.2", "zen.dq.spamhaus.net": "127.0.0.2"}}
        self.assertEqual(2, len(overview.distinct_listings(data)))

    def test_a_pbl_only_listing_is_not_a_reputation_problem(self):
        tile = overview.blacklist(self._listed(
            ["zen.dq.spamhaus.net"], {"zen.dq.spamhaus.net": "127.0.0.11"}))
        self.assertEqual("context", tile["state"])

    def test_a_listing_without_its_address_is_still_shown(self):
        """Missing context is no reason to drop a listing from view."""
        tile = overview.blacklist({"blacklist": {"is_listed": True, "listed": ["x.invalid"]}})
        self.assertEqual("fail", tile["state"])

    def test_not_listed_passes_and_a_failed_lookup_shows_nothing(self):
        self.assertEqual("pass", overview.blacklist(
            _scan(blacklist={"ip": _EDGE, "is_listed": False}))["state"])
        self.assertIsNone(overview.blacklist(
            _scan(blacklist={"error": "timeout", "is_listed": False})))


class BlacklistFindingTests(unittest.TestCase):
    def test_the_finding_says_what_the_tile_says(self):
        """The tile named the shared CDN edge; the finding still listed
        cbl.abuseat.org and zen as two listings with no mention of the CDN."""
        import recommendations
        results = _scan(cdn={"id": "bunny", "name": "BunnyCDN"}, blacklist={
            "ip": _EDGE, "is_listed": True,
            "listed": ["cbl.abuseat.org", "zen.dq.spamhaus.net"],
            "codes": {"cbl.abuseat.org": "127.0.0.2", "zen.dq.spamhaus.net": "127.0.0.4"}})
        finding = next(r for r in recommendations.generate(results) if r["category"] == "Network")
        self.assertEqual(overview.blacklist(results)["note"], finding["problem"])
        self.assertNotIn("cbl.abuseat.org", finding["problem"])


class Ipv6MailTileTests(unittest.TestCase):
    def test_a_providers_mx_without_ipv6_is_context(self):
        """The owner cannot add AAAA records to their provider's MX hosts."""
        tile = overview.ipv6_mail(_scan(ipv6={"mail_pass": False}))
        self.assertEqual("context", tile["state"])
        self.assertIn("mailhost.example", tile["note"])

    def test_the_domains_own_mx_without_ipv6_fails(self):
        tile = overview.ipv6_mail(_scan(ipv6={"mail_pass": False, "mx_hosts": ["mail.example.com"]}))
        self.assertEqual("fail", tile["state"])

    def test_no_mx_means_no_tile(self):
        """No mail is received, so there is nothing to reach over IPv6."""
        self.assertIsNone(overview.ipv6_mail(_scan(ipv6={"mail_pass": False, "mx_hosts": []})))

    def test_ipv6_on_the_mx_passes(self):
        self.assertEqual("pass", overview.ipv6_mail(_scan(ipv6={"mail_pass": True}))["state"])


class TileNoteRenderingTests(unittest.TestCase):
    """No JS runtime here, so this reads the source, like test_ui_buttons."""

    def test_the_reason_is_in_the_tile_not_only_in_a_tooltip(self):
        """A phone has no hover: the orange tiles showed "Context" and no
        reason, which reads as a vaguer red."""
        import pathlib
        src = pathlib.Path(__file__).resolve().parent.parent.joinpath(
            "static", "js", "app.js").read_text(encoding="utf-8")
        body = src[src.index("function renderScoreOverview"):src.index("// ===== WHOIS")]
        self.assertIn("note.className = 'score-note'", body)
        self.assertIn("note.textContent = c.note", body)


class ChecksRecordWhatTheTilesNeedTests(EnterpriseAppTestCase):
    def test_the_blacklist_check_keeps_the_answer_per_listed_zone(self):
        """Without the answer, a ZEN hit cannot be told apart as SBL, XBL or PBL."""
        hit = mock.Mock()
        hit.to_text.return_value = "127.0.0.4"
        app = self.app_module

        def resolve(name, rtype, *args, **kwargs):
            if name.endswith("cbl.abuseat.org"):
                return [hit]
            raise app.dns.resolver.NXDOMAIN()

        with mock.patch.object(app, "_safe_resolve_ip", return_value=_EDGE), \
             mock.patch.object(app.dns.resolver, "resolve", side_effect=resolve):
            result = app.check_blacklist("example.com")
        self.assertEqual({"cbl.abuseat.org": "127.0.0.4"}, result["codes"])

    def test_the_ipv6_check_names_the_mx_hosts_and_skips_a_null_mx(self):
        answers = {("example.com", "MX"): ["0 ."], ("example.com", "AAAA"): []}
        with mock.patch.object(self.app_module, "_resolve",
                               side_effect=lambda name, rtype: answers.get((name, rtype), [])):
            result = self.app_module.check_ipv6("example.com")
        self.assertEqual([], result["mx_hosts"])

    def test_a_saved_scan_gets_the_tile_states_when_opened(self):
        """Scans saved before these states existed show the same tiles."""
        self.login_as("viewer")
        scan_id = self.db.save_scan("example.com", _scan(ipv6={"mail_pass": False}))
        data = self.client.get(f"/api/history/{scan_id}").get_json()["data"]
        self.assertEqual("context", data["overview"]["ipv6_mail"]["state"])
        self.assertIsNone(data["overview"]["weak_auth"])


if __name__ == "__main__":
    unittest.main()

"""Mail tiles that showed Fail for a domain that deliberately has no mail.

A parked domain done right -- null MX, `v=spf1 -all`, DMARC reject and its
DKIM keys revoked -- showed DKIM, MTA-STS and TLS-RPT as red tiles, and the
advice told it to publish MTA-STS and TLS-RPT: protection for inbound mail
on a domain that has said, in DNS, that none arrives. The DKIM tile was red
with no advice item at all to explain it.

These are now "not applicable", with the reason on the tile, and the advice
the operator could not act on is gone. A domain that does receive mail is
told exactly what it was told before.
"""

import pathlib
import unittest

import overview
import recommendations

JS = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text(encoding="utf-8")

PARKED = {
    "domain": "example.com",
    "dns": {"MX": ["0 ."]},
    "spf": {"state": "measured", "found": True, "record": "v=spf1 -all", "strict": True, "pass": True},
    "dmarc": {"state": "measured", "found": True, "policy": "reject", "pass": True},
    "dkim": {"state": "measured", "found": True, "pass": False,
             "selectors": [{"selector": "default", "record": "v=DKIM1; p=", "revoked": True}]},
    "mta_sts": {"state": "measured", "found": False, "pass": False},
    "tlsrpt": {"state": "measured", "found": False, "pass": False},
}


def _mailing(**changes):
    scan = {k: (dict(v) if isinstance(v, dict) else v) for k, v in PARKED.items()}
    scan["dns"] = {"MX": ["10 mx.example.com."]}
    scan["spf"] = dict(PARKED["spf"], record="v=spf1 include:_spf.example.net -all")
    scan.update(changes)
    return scan


class DomainWithoutMailTests(unittest.TestCase):
    def test_mta_sts_and_tls_rpt_do_not_apply_to_a_null_mx(self):
        states = overview.tile_states(PARKED)
        for key in ("mta_sts", "tlsrpt"):
            self.assertEqual("not_applicable", states[key]["state"])
            self.assertIn("null MX", states[key]["note"])

    def test_no_advice_to_protect_mail_that_never_arrives(self):
        titles = [r["title"] for r in recommendations.generate(PARKED)]
        self.assertFalse([t for t in titles if "MTA-STS" in t or "TLS-RPT" in t], titles)

    def test_revoked_dkim_keys_on_a_domain_that_sends_nothing_are_not_a_failure(self):
        tile = overview.dkim(PARKED)
        self.assertEqual("not_applicable", tile["state"])
        self.assertIn("v=spf1 -all", tile["note"])


class DomainWithMailTests(unittest.TestCase):
    """The half that must not change: real mail keeps its findings."""

    def test_missing_mta_sts_still_fails_and_is_advised(self):
        scan = _mailing()
        self.assertEqual("fail", overview.mta_sts(scan)["state"])
        titles = [r["title"] for r in recommendations.generate(scan)]
        self.assertIn("MTA-STS not configured", titles)
        self.assertIn("TLS-RPT not configured", titles)

    def test_only_revoked_keys_on_a_sending_domain_is_context_not_a_pass(self):
        """The selector in use may not be on the list that was tried."""
        tile = overview.dkim(_mailing())
        self.assertEqual("context", tile["state"])
        self.assertIn("DKIM-Signature", tile["note"])

    def test_no_key_found_is_not_tested_rather_than_failed(self):
        """Only a fixed list of selector names can be asked."""
        tile = overview.dkim(_mailing(dkim={"state": "measured", "found": False, "pass": False}))
        self.assertEqual("not_tested", tile["state"])

    def test_a_valid_key_passes(self):
        dkim = {"state": "measured", "found": True, "pass": True,
                "selectors": [{"selector": "s1", "record": "v=DKIM1; p=MIIB", "revoked": False}]}
        self.assertEqual("pass", overview.dkim(_mailing(dkim=dkim))["state"])


class TileWiringTests(unittest.TestCase):
    def test_the_tiles_take_the_server_state(self):
        for label, key in (("DKIM", "dkim"), ("MTA-STS", "mta_sts"), ("TLS-RPT", "tlsrpt")):
            self.assertIn(f"fromOverview('{label}', '{key}'", JS)
        self.assertIn("not_applicable: ['badge-info', 'Not applicable']", JS)


if __name__ == "__main__":
    unittest.main()

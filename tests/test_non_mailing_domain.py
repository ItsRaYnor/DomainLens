"""SPF and DMARC advice for a domain that receives no mail.

Prompted by a real domain: a blacklist hit on its web address, no mail of its
own, and nothing published to say so. A domain nobody sends from is still
worth forging, and `v=spf1 -all` with `p=reject` is what makes that forgery
fail at the receiver rather than land in an inbox.

The load-bearing constraint is what this must NOT do. MX says whether a
domain *receives* mail; it says nothing about sending, and plenty of domains
send without one. Telling an operator with working mail to publish `-all`
would stop their post -- advice they cannot follow without breaking their own
site, which the reporting rules put out of bounds.
"""

import unittest

import recommendations


NO_SPF = {"found": False}
NO_DMARC = {"found": False}
LOCKED_SPF = {"found": True, "record": "v=spf1 -all", "strict": True}
LOCKED_DMARC = {"found": True, "policy": "reject"}


def _findings(mx, spf=NO_SPF, dmarc=NO_DMARC):
    results = {"spf": dict(spf), "dmarc": dict(dmarc)}
    if mx is not None:
        results["dns"] = {"MX": mx}
    return recommendations._non_mailing_domain(results)


def _titles(findings):
    return [f["title"] for f in findings]


class DomainsThatDoReceiveMailAreLeftAloneTests(unittest.TestCase):
    """The half that matters most: a wrong finding here breaks someone's
    mail."""

    def test_a_domain_with_a_real_mx_gets_no_advice_from_this_check(self):
        findings = _findings(["10 mail.example.com."],
                             spf={"found": True, "record": "v=spf1 include:x ~all"},
                             dmarc={"found": True, "policy": "none"})
        self.assertEqual([], findings)

    def test_several_mx_records_are_still_a_mail_domain(self):
        self.assertEqual([], _findings([
            "10 mx1.example.com.", "20 mx2.example.com."]))

    def test_a_mail_domain_is_left_alone_even_with_no_spf_at_all(self):
        """The ordinary SPF advice covers this; what must not appear is the
        "publish -all" version, which would refuse its legitimate senders."""
        findings = _findings(["10 mail.example.com."], spf=NO_SPF, dmarc=NO_DMARC)
        self.assertEqual([], findings)

    def test_an_unmeasured_mx_produces_nothing(self):
        """No MX key at all means the check did not run, which is not the
        same as a domain having no MX. Concluding "receives no mail" from a
        check that never happened is how you tell someone to publish -all on
        a live mail domain."""
        self.assertEqual([], recommendations._non_mailing_domain(
            {"spf": NO_SPF, "dmarc": NO_DMARC}))


class NullMxDomainsTests(unittest.TestCase):
    """RFC 7505 null MX -- a single `0 .` -- is the operator stating outright
    that the domain receives no mail. That justifies naming the gap."""

    def test_a_null_mx_domain_without_spf_is_told_to_publish_minus_all(self):
        findings = _findings(["0 ."])
        spf = [f for f in findings if "SPF" in f["title"]][0]
        self.assertIn("v=spf1 -all", spf["fix"])

    def test_a_null_mx_domain_without_dmarc_is_told_to_publish_reject(self):
        findings = _findings(["0 ."])
        dmarc = [f for f in findings if "DMARC" in f["title"]][0]
        self.assertIn("p=reject", dmarc["fix"])

    def test_a_permissive_spf_on_a_null_mx_domain_is_named(self):
        """The inconsistency worth reporting: it says it receives nothing
        while still authorising senders."""
        findings = _findings(["0 ."],
                             spf={"found": True, "record": "v=spf1 include:_spf.google.com ~all"})
        titles = _titles(findings)
        self.assertTrue(any("still allows senders" in t for t in titles), titles)

    def test_a_dmarc_of_none_on_a_null_mx_domain_is_named(self):
        findings = _findings(["0 ."], dmarc={"found": True, "policy": "none"})
        titles = _titles(findings)
        self.assertTrue(any("p=none" in t for t in titles), titles)

    def test_a_domain_already_locked_down_gets_nothing(self):
        """Advice that is already followed is noise."""
        self.assertEqual([], _findings(["0 ."], spf=LOCKED_SPF, dmarc=LOCKED_DMARC))

    def test_the_advice_states_the_condition_it_depends_on(self):
        """Whether a domain sends is the operator's knowledge, not ours. The
        fix has to say so, or someone with a newsletter follows it and stops
        their own mail."""
        findings = _findings(["0 ."])
        spf = [f for f in findings if "SPF" in f["title"]][0]
        self.assertIn("Only do this if no service", spf["fix"])


class DomainsWithNoMxAtAllTests(unittest.TestCase):
    """No MX still permits implicit delivery to A/AAAA under RFC 5321."""

    def test_no_mx_does_not_claim_the_domain_receives_no_mail(self):
        """Only an explicit null MX supports no-mail remediation."""
        self.assertEqual([], _findings([]))

    def test_no_mx_with_locked_policies_stays_silent(self):
        self.assertEqual([], _findings([], spf=LOCKED_SPF, dmarc=LOCKED_DMARC))


class WiringTests(unittest.TestCase):
    def test_the_check_runs_as_part_of_a_scan(self):
        results = {"domain": "example.com", "dns": {"MX": ["0 ."]},
                   "spf": NO_SPF, "dmarc": NO_DMARC}
        titles = [r["title"] for r in recommendations.generate(results)]
        self.assertTrue(any("receives no mail" in t for t in titles), titles)
        self.assertEqual(1, sum("SPF" in t for t in titles), titles)
        self.assertEqual(1, sum("DMARC" in t for t in titles), titles)

    def test_it_is_filed_under_email(self):
        for finding in _findings(["0 ."]):
            self.assertEqual("Email", finding["category"])


if __name__ == "__main__":
    unittest.main()

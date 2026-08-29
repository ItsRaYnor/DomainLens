"""Checking whether a record has rolled out meant running the lookup once per
resolver by hand and eyeballing the answers. The comparison is the part worth
automating, and it is also the part that is easy to get wrong.

The trap these pin down: a resolver that did not answer is not a resolver
that disagrees. Counting a timeout as "not propagated yet" sends someone
chasing a rollout that already finished, and the operator has no way to tell
the two apart from the verdict alone.
"""

import unittest
from unittest import mock

import dns_tools


def _answer(resolver, records, rcode="NOERROR", ttl=300):
    return {"name": "example.com", "type": "A", "resolver": resolver,
            "records": list(records), "ttl": ttl, "rcode": rcode,
            "error": None, "detail": None, "elapsed_ms": 5}


def _failure(resolver, message="timed out"):
    return {"name": "example.com", "type": "A", "resolver": resolver,
            "records": [], "ttl": None, "rcode": None,
            "error": message, "detail": None, "elapsed_ms": None}


class CustomResolverParsingTests(unittest.TestCase):
    """Operators type these into a settings textarea, so the parser meets
    trailing spaces, comments and typos rather than clean input."""

    def test_a_label_with_several_addresses(self):
        parsed = dns_tools.parse_custom_resolvers(["Office = 10.0.0.1, 10.0.0.2"])
        self.assertEqual({"office": ["10.0.0.1", "10.0.0.2"]}, parsed)

    def test_a_bare_address_names_itself(self):
        """Typing just an address is a reasonable thing to do and should not
        be rejected for missing a label."""
        self.assertEqual({"1.1.1.1": ["1.1.1.1"]},
                         dns_tools.parse_custom_resolvers(["1.1.1.1"]))

    def test_comments_and_blank_lines_are_skipped(self):
        self.assertEqual({}, dns_tools.parse_custom_resolvers(["", "  ", "# note"]))

    def test_a_hostname_is_not_accepted_as_an_address(self):
        """Only literal IPs: a name would have to be resolved first, and by
        whom is exactly the question this feature exists to answer."""
        self.assertEqual({}, dns_tools.parse_custom_resolvers(["ns = ns1.example.com"]))

    def test_one_bad_line_does_not_discard_the_good_ones(self):
        """This runs on the way into every lookup; a typo in settings must
        not take the DNS page down with it."""
        parsed = dns_tools.parse_custom_resolvers(["bad = nope", "Office = 10.0.0.1"])
        self.assertEqual({"office": ["10.0.0.1"]}, parsed)

    def test_a_custom_label_cannot_shadow_a_built_in_resolver(self):
        """Otherwise "google" in settings would silently redirect a lookup
        everyone reads as going to Google."""
        parsed = dns_tools.parse_custom_resolvers(["google = 10.0.0.1"])
        self.assertEqual({}, parsed)


class PropagationVerdictTests(unittest.TestCase):
    def _run(self, answers, resolvers=None):
        by_key = {a["resolver"]: a for a in answers}
        with mock.patch.object(dns_tools, "query", side_effect=lambda n, t, k: by_key[k]):
            return dns_tools.propagation(
                "example.com", "A", resolvers or sorted(by_key))

    def test_identical_answers_are_propagated(self):
        result = self._run([_answer("google", ["1.2.3.4"]),
                            _answer("quad9", ["1.2.3.4"])])
        self.assertEqual("propagated", result["verdict"])
        self.assertEqual(2, result["answered"])

    def test_differing_answers_are_inconsistent(self):
        result = self._run([_answer("google", ["1.2.3.4"]),
                            _answer("quad9", ["5.6.7.8"])])
        self.assertEqual("inconsistent", result["verdict"])
        self.assertEqual(2, len(result["groups"]))

    def test_record_order_is_not_a_difference(self):
        """Round-robin resolvers rotate an RRset deliberately. Comparing
        unsorted lists would report a rollout in progress on every second
        lookup of a perfectly settled record."""
        result = self._run([_answer("google", ["1.2.3.4", "5.6.7.8"]),
                            _answer("quad9", ["5.6.7.8", "1.2.3.4"])])
        self.assertEqual("propagated", result["verdict"])

    def test_a_timeout_is_never_counted_as_disagreement(self):
        """The whole point: our failure to reach a resolver says nothing
        about whether the record rolled out."""
        result = self._run([_answer("google", ["1.2.3.4"]),
                            _answer("quad9", ["1.2.3.4"]),
                            _failure("cloudflare")])
        self.assertEqual("propagated", result["verdict"])
        self.assertEqual(["cloudflare"], result["unreachable"])
        self.assertEqual(2, result["answered"])

    def test_one_lonely_answer_is_unknown_not_propagated(self):
        """Nothing was compared, so "propagated" would be a claim we did not
        establish."""
        result = self._run([_answer("google", ["1.2.3.4"]), _failure("quad9")])
        self.assertEqual("unknown", result["verdict"])

    def test_every_resolver_failing_is_unknown(self):
        result = self._run([_failure("google"), _failure("quad9")])
        self.assertEqual("unknown", result["verdict"])
        self.assertEqual(0, result["answered"])

    def test_a_differing_rcode_is_a_difference(self):
        """NXDOMAIN at one resolver and an answer at another is the classic
        half-rolled-out state, even though both "answered"."""
        result = self._run([_answer("google", [], rcode="NXDOMAIN"),
                            _answer("quad9", ["1.2.3.4"])])
        self.assertEqual("inconsistent", result["verdict"])

    def test_agreeing_that_a_name_does_not_exist_is_propagated(self):
        """A deletion rolls out too, and it is the same question."""
        result = self._run([_answer("google", [], rcode="NXDOMAIN"),
                            _answer("quad9", [], rcode="NXDOMAIN")])
        self.assertEqual("propagated", result["verdict"])

    def test_the_groups_name_which_resolvers_said_what(self):
        """A verdict of "inconsistent" is only actionable if you can see
        which resolver is still serving the old record."""
        result = self._run([_answer("google", ["1.2.3.4"]),
                            _answer("quad9", ["5.6.7.8"])])
        by_records = {tuple(g["records"]): g["resolvers"] for g in result["groups"]}
        self.assertEqual(["google"], by_records[("1.2.3.4",)])
        self.assertEqual(["quad9"], by_records[("5.6.7.8",)])

    def test_a_raising_resolver_is_unreachable_not_an_exception(self):
        """One broken resolver must not abort the comparison of the rest."""
        def boom(name, rtype, key):
            if key == "quad9":
                raise OSError("socket exploded")
            return _answer(key, ["1.2.3.4"])
        with mock.patch.object(dns_tools, "query", side_effect=boom):
            result = dns_tools.propagation(
                "example.com", "A", ["google", "quad9", "cloudflare"])
        self.assertEqual("propagated", result["verdict"])
        self.assertEqual(["quad9"], result["unreachable"])


class PropagationInputTests(unittest.TestCase):
    """The resolver list arrives from a request, so it is checked, not
    trusted."""

    def test_an_unknown_resolver_is_refused(self):
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.propagation("example.com", "A", ["not-a-resolver"])

    def test_an_address_is_not_accepted_as_a_resolver_name(self):
        """The fixed-list contract: without this the endpoint becomes a way
        to probe port 53 on any host the server can reach."""
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.propagation("example.com", "A", ["10.0.0.5"])

    def test_a_configured_custom_resolver_is_accepted(self):
        custom = {"office": ["10.0.0.1"]}
        with mock.patch.object(dns_tools, "_query_addresses",
                               return_value=_answer("office", ["1.2.3.4"])), \
             mock.patch.object(dns_tools, "query",
                               return_value=_answer("google", ["1.2.3.4"])):
            result = dns_tools.propagation(
                "example.com", "A", ["office", "google"], custom=custom)
        self.assertEqual("propagated", result["verdict"])

    def test_a_custom_resolver_is_queried_by_its_configured_addresses(self):
        custom = {"office": ["10.0.0.1", "10.0.0.2"]}
        with mock.patch.object(dns_tools, "_query_addresses",
                               return_value=_answer("office", ["1.2.3.4"])) as direct, \
             mock.patch.object(dns_tools, "query",
                               return_value=_answer("google", ["1.2.3.4"])):
            dns_tools.propagation("example.com", "A", ["office", "google"], custom=custom)
        self.assertEqual(["10.0.0.1", "10.0.0.2"], direct.call_args[0][3])

    def test_an_empty_selection_is_refused(self):
        with self.assertRaises(dns_tools.LookupError_):
            dns_tools.propagation("example.com", "A", [])

    def test_an_invalid_name_is_refused_before_any_query(self):
        """Validation runs first, so a refused request costs no traffic.
        An over-long name is used rather than one with a space: DNS labels
        may legally contain arbitrary bytes and query() has always accepted
        those, which is not something to change from here."""
        with mock.patch.object(dns_tools, "query") as q:
            with self.assertRaises(dns_tools.LookupError_):
                dns_tools.propagation("a" * 300 + ".example.com", "A", ["google"])
        q.assert_not_called()

    def test_an_unsupported_record_type_is_refused(self):
        """ANY and zone transfers are deliberately not offered, and the
        propagation path must not become a way around that."""
        for rtype in ("ANY", "AXFR"):
            with self.subTest(rtype=rtype):
                with self.assertRaises(dns_tools.LookupError_):
                    dns_tools.propagation("example.com", rtype, ["google"])


if __name__ == "__main__":
    unittest.main()

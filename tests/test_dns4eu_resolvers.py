"""DNS lookups start in the EU, and propagation still compares the big networks.

The DNS tool offered Cloudflare, Google and Quad9 only -- two in the US, one
in Switzerland -- and, sorted alphabetically, a lookup started on
"authoritative" without anyone choosing it. DNS4EU, the EU's public
resolver, is now there in all five variants, with its unfiltered variant
the default: a filtered one answers a blocked name with a block, which a
lookup would show as the name's records. Propagation compares DNS4EU with
Cloudflare, Google, Quad9 and the zone's own nameservers.
"""

import pathlib
import unittest
from unittest import mock

import dns_tools
from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent

# From joindns4.eu/for-public: every variant, primary and secondary.
DNS4EU = {
    "dns4eu-unfiltered": ["86.54.11.100", "86.54.11.200"],
    "dns4eu-protective": ["86.54.11.1", "86.54.11.201"],
    "dns4eu-child": ["86.54.11.12", "86.54.11.212"],
    "dns4eu-noads": ["86.54.11.13", "86.54.11.213"],
    "dns4eu-child-noads": ["86.54.11.11", "86.54.11.211"],
}


class ResolverListTests(unittest.TestCase):
    def test_every_dns4eu_variant_is_offered_at_its_published_addresses(self):
        for key, addresses in DNS4EU.items():
            self.assertEqual(addresses, dns_tools.RESOLVERS[key], key)

    def test_a_lookup_starts_on_the_unfiltered_eu_resolver(self):
        self.assertEqual("dns4eu-unfiltered", dns_tools.DEFAULT_RESOLVER)
        self.assertEqual("EU", dns_tools.RESOLVER_REGION[dns_tools.DEFAULT_RESOLVER])

    def test_every_public_resolver_says_where_it_is_run(self):
        public = [k for k, v in dns_tools.RESOLVERS.items() if isinstance(v, list)]
        self.assertEqual(sorted(public), sorted(dns_tools.RESOLVER_REGION))

    def test_propagation_compares_the_eu_with_the_big_networks_and_no_filter(self):
        asked = []

        def fake(name, rtype, key):
            asked.append(key)
            return {"name": name, "type": rtype, "resolver": key, "records": ["192.0.2.1"],
                    "ttl": 300, "rcode": "NOERROR", "error": None, "detail": None, "elapsed_ms": 5}

        with mock.patch.object(dns_tools, "query", side_effect=fake):
            result = dns_tools.propagation("example.com", "A")
        self.assertEqual(["dns4eu-unfiltered", "cloudflare", "google", "quad9", "authoritative"], sorted(
            asked, key=dns_tools.PROPAGATION_DEFAULT.index))
        self.assertEqual("propagated", result["verdict"])


class PageTests(EnterpriseAppTestCase):
    def test_the_options_put_the_eu_first_and_name_the_defaults(self):
        self.login_as("user")
        data = self.client.get("/api/dns/options").get_json()
        self.assertEqual(["system", "dns4eu-unfiltered"], data["resolvers"][:2])
        self.assertEqual("dns4eu-unfiltered", data["default_resolver"])
        self.assertEqual(dns_tools.PROPAGATION_DEFAULT, data["propagation_default"])
        self.assertEqual("US", data["regions"]["google"])

    def test_the_page_selects_the_default_and_ticks_only_the_usual_set(self):
        js = (ROOT / "static" / "js" / "lookup.js").read_text(encoding="utf-8")
        self.assertIn("$('dnsLookupResolver').value = data.default_resolver;", js)
        self.assertIn("dnsPropDefault.includes(r) || dnsCustomResolvers.includes(r) ? ' checked' : ''", js)


class LayoutTests(unittest.TestCase):
    """Ten bare checkboxes named by key ("dns4eu-child-noads (EU)") ran on in
    one jumble. They are grouped by where the resolver is run, each a chip
    with a plain name, the group name beside its chips on a wide screen and
    above them on a phone."""

    JS = (ROOT / "static" / "js" / "lookup.js").read_text(encoding="utf-8")
    CSS = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")

    def test_resolvers_are_grouped_by_where_they_run(self):
        for group in ("{ name: 'DNS4EU', region: 'EU'", "{ name: 'Outside the EU'", "{ name: 'Direct'", "{ name: 'Your own'"):
            self.assertIn(group, self.JS)
        self.assertIn("'dns4eu-child-noads': ['Child protection + no ads'", self.JS)
        self.assertIn('<optgroup label="${esc(g.name)}">', self.JS)

    def test_each_resolver_is_a_chip_and_a_phone_stacks_the_groups(self):
        self.assertIn(".prop-chip:has(input:checked)", self.CSS)
        phone = self.CSS[self.CSS.index(".prop-hint {"):]
        self.assertIn(".prop-group { grid-template-columns: minmax(0, 1fr);", phone[:600])

    def test_the_group_headings_of_a_list_are_translated(self):
        translate = (ROOT / "static" / "js" / "translate.js").read_text(encoding="utf-8")
        self.assertIn("const ATTRS = ['placeholder', 'title', 'aria-label', 'alt', 'label'];", translate)


if __name__ == "__main__":
    unittest.main()

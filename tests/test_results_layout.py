"""The scan results are found where the checks are chosen.

Weak authentication and the active vulnerability scan were chosen under
"Security Audit" but shown under "Web"; the own-infrastructure tests (open
relay, open resolver) had no results card at all, so a relay that refused
was never shown as measured; IPv6 was chosen under "Domain" and shown under
"Network". On a phone the result tabs stood one per line and filled the
first screen, and the cipher tables scrolled sideways.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HTML = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "style.css").read_text(encoding="utf-8")


def _tab(name):
    return HTML.split(f'id="tab-{name}"', 1)[1].split('class="tab-content"', 1)[0]


def _group(name):
    after = HTML.split(f'data-group="{name}"', 1)[1]
    return re.split(r'<div class="check-group[ "]', after, maxsplit=1)[0]


class PlacementTests(unittest.TestCase):
    def test_the_active_tests_are_shown_with_the_security_audit(self):
        security = _tab("security")
        for source in ("weak_auth", "active_scan", "own_infra", "js_scan"):
            self.assertIn(f'data-source="{source}"', security)
            self.assertNotIn(f'data-source="{source}"', _tab("web"))

    def test_the_own_infrastructure_tests_have_a_card(self):
        self.assertIn('id="ownInfraContent"', HTML)
        self.assertIn("renderOwnInfra(data.own_infra);", JS)

    def test_ipv6_is_chosen_where_it_is_shown(self):
        self.assertIn('value="ipv6"', _group("network"))
        self.assertNotIn('value="ipv6"', _group("domain"))
        self.assertIn('data-source="ipv6"', _tab("network"))

    def test_the_active_tests_heading_hides_when_none_ran(self):
        self.assertIn("activeHead.classList.toggle('not-run', !['weak_auth', 'active_scan', 'own_infra'].some(k => checkRan(data, k)));", JS)


class PhoneTests(unittest.TestCase):
    def test_tabs_are_chips_that_flow(self):
        self.assertIn(".tab-group { flex: 0 1 auto; flex-direction: row; flex-wrap: wrap; gap: .4rem; }", CSS)

    def test_cipher_tables_become_cards(self):
        # One table since the TLS and NCSC lists were merged into it.
        self.assertEqual(1, JS.count("cipher-table stack-table"))


if __name__ == "__main__":
    unittest.main()

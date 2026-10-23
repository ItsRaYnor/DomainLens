"""Known vulnerable software versions, matched against what a server shows.

PHP2Shell (CVE-2026-109618, CVE-2026-109619) was fixed in 8.5.12, 8.4.27,
8.3.36 and 8.2.35 and exploited the same day. A scan saw "X-Powered-By:
PHP/8.2.7" and called it only a version leak; there was no way to see
across the organisation which sites still ran an unfixed PHP. Now the
version shown is compared with the fix -- vulnerable, has the fix, or
cannot tell (hidden, or a distribution build whose package may carry the
fix) -- in every scan, and for the whole portfolio on one page. Nothing is
sent but an ordinary request for the home page.
"""

import json
import pathlib
import shutil
import subprocess
import unittest
from unittest import mock

import security_checks
import software_advisories as sa
from enterprise_harness import EnterpriseAppTestCase

PHP2SHELL = sa.builtin_rules()[0]
ONLY_BUILTIN = [PHP2SHELL]


def _verdict(raw):
    return sa.verdict(PHP2SHELL, sa.parse_version(PHP2SHELL, [raw]))[0]


class VerdictTests(unittest.TestCase):
    def test_versions_against_the_fix(self):
        cases = {
            "PHP/8.2.7": "vulnerable", "PHP/8.4.26": "vulnerable", "PHP/8.5.11": "vulnerable",
            "PHP/8.2.35": "fixed", "PHP/8.3.36": "fixed", "PHP/8.4.30": "fixed", "PHP/8.5.12": "fixed",
            "PHP/7.4.33": "vulnerable",  # a branch that gets no fixes at all
            "PHP/8.1.2-1ubuntu2.18": "cannot_tell",  # the distribution may have put the fix in
            "PHP/8.2.7-1~deb12u1": "cannot_tell",
            "PHP/8.3": "cannot_tell",  # no patch release shown
        }
        for raw, expected in cases.items():
            self.assertEqual(expected, _verdict(raw), raw)

    def test_the_version_is_read_from_the_server_header_too(self):
        found = sa.match({"server": "Apache/2.4.57 (Unix) PHP/8.3.10"}, rules=ONLY_BUILTIN)
        self.assertEqual(("vulnerable", "PHP/8.3.10"), (found[0]["verdict"], found[0]["version"]))

    def test_php_without_a_version_cannot_be_told_and_no_php_is_not_applicable(self):
        self.assertEqual("cannot_tell", sa.match({"server": "nginx"}, "PHPSESSID=x; path=/", rules=ONLY_BUILTIN)[0]["verdict"])
        self.assertEqual([], sa.match({"server": "nginx"}, "", rules=ONLY_BUILTIN))


class ScanTests(unittest.TestCase):
    def _info(self, headers):
        resp = mock.Mock(headers=headers, text="<html></html>", history=[], url="https://example.org/")
        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
             mock.patch.object(security_checks, "_get", return_value=resp), \
             mock.patch.object(sa, "active_rules", return_value=ONLY_BUILTIN):
            return security_checks.check_info_disclosure("example.org")

    def test_a_vulnerable_version_is_a_critical_finding(self):
        info = self._info({"X-Powered-By": "PHP/8.2.7"})
        findings = security_checks.audit_findings({"info_disclosure": info})
        hit = [f for f in findings if "PHP2Shell" in f["title"]]
        self.assertEqual("critical", hit[0]["severity"])
        self.assertIn("CVE-2026-109618", hit[0]["title"])

    def test_a_hidden_version_is_information_not_a_defect(self):
        info = self._info({"Server": "nginx", "Set-Cookie": "PHPSESSID=abc"})
        findings = security_checks.audit_findings({"info_disclosure": info})
        hit = [f for f in findings if "PHP2Shell" in f["title"]]
        self.assertEqual("info", hit[0]["severity"])

    def test_a_fixed_version_says_nothing(self):
        info = self._info({"X-Powered-By": "PHP/8.4.27"})
        findings = security_checks.audit_findings({"info_disclosure": info})
        self.assertFalse([f for f in findings if "PHP2Shell" in f["title"]])


class FleetTests(unittest.TestCase):
    def test_a_redirect_into_the_own_network_is_not_followed(self):
        """The server asks on someone's behalf; a redirect to 127.0.0.1 or
        a private address would aim it at its own network."""
        first = mock.Mock(status_code=302, headers={"location": "http://127.0.0.1/admin", "X-Powered-By": "PHP/8.2.7"})
        with mock.patch("requests.get", return_value=first) as get:
            result = sa.check_host("example.org", safe=lambda host: host not in ("127.0.0.1",), rules=ONLY_BUILTIN)
        self.assertEqual(1, get.call_count)
        self.assertEqual("vulnerable", result["advisories"][0]["verdict"])

    def test_no_answer_is_unmeasured(self):
        with mock.patch("requests.get", side_effect=OSError("down")):
            result = sa.check_host("example.org", safe=lambda host: True, rules=ONLY_BUILTIN)
        self.assertEqual("unmeasured", result["state"])

    def test_only_www_with_an_address_is_still_checked(self):
        answer = mock.Mock(status_code=200, headers={"X-Powered-By": "PHP/8.2.7"})
        with mock.patch("requests.get", return_value=answer) as get:
            result = sa.check_host("example.org", rules=ONLY_BUILTIN,
                                   address=lambda host: "public" if host.startswith("www.") else "none")
        self.assertEqual(["https://www.example.org/"], [c[0][0] for c in get.call_args_list])
        self.assertEqual("vulnerable", result["advisories"][0]["verdict"])

    def test_a_failed_dns_lookup_is_unmeasured_not_no_website(self):
        """DNS that gives no answer says nothing about the site; reading it
        as "no website" would present a failed lookup as a fact."""
        with mock.patch("requests.get") as get:
            result = sa.check_host("example.org", rules=ONLY_BUILTIN, address=lambda host: "failed")
        get.assert_not_called()
        self.assertEqual("unmeasured", result["state"])
        self.assertIn("DNS lookup gave no answer", result["error"])

    def test_what_was_looked_up_and_asked_is_kept_for_the_details(self):
        """A result without the way to it could not be checked by hand: was
        https tried, did www. have an address, which hop said what."""
        answer = mock.Mock(status_code=200, headers={"Server": "nginx"})
        with mock.patch("requests.get", side_effect=[OSError("refused"), answer]):
            result = sa.check_host("example.org", rules=ONLY_BUILTIN, address=lambda host: "public")
        self.assertEqual([{"url": "https://example.org/", "error": "OSError"},
                          {"url": "http://example.org/", "error": None}], result["attempts"])
        self.assertEqual([{"host": "example.org", "address": "public"}], result["lookups"])
        self.assertEqual([("http://example.org/", 200, "nginx", True)],
                         [(h["url"], h["status"], h["server"], h["own"]) for h in result["hops"]])
        gone = sa.check_host("example.org", rules=ONLY_BUILTIN, address=lambda host: "none")
        self.assertEqual([("example.org", "none"), ("www.example.org", "none")],
                         [(l["host"], l["address"]) for l in gone["lookups"]])

    def test_only_the_home_page_is_asked_for(self):
        resp = mock.Mock(status_code=200, headers={"X-Powered-By": "PHP/8.5.12"})
        with mock.patch("requests.get", return_value=resp) as get:
            sa.check_host("example.org", safe=lambda host: True, rules=ONLY_BUILTIN)
        self.assertEqual("https://example.org/", get.call_args[0][0])
        self.assertFalse(get.call_args[1]["allow_redirects"])


def _answer(status, headers, url=None):
    from requests.structures import CaseInsensitiveDict
    return mock.Mock(status_code=status, headers=CaseInsensitiveDict(headers), text="<html></html>", url=url)


def _cross_domain_scan(final_headers):
    """The scan of example.org, whose own server redirects to example.net."""
    first = _answer(301, {"Server": "Apache", "Location": "https://example.net/"}, url="https://example.org/")
    final = _answer(200, final_headers, url="https://example.net/")
    final.history = [first]
    with mock.patch.object(security_checks, "_safe_host", return_value=True), \
         mock.patch.object(security_checks, "_get", return_value=final), \
         mock.patch.object(sa, "active_rules", return_value=ONLY_BUILTIN):
        info = security_checks.check_info_disclosure("example.org")
    return info, security_checks.audit_findings({"info_disclosure": info})


class RedirectTests(unittest.TestCase):
    """example.org's own server (Apache, no PHP shown) redirects to
    example.net, whose nginx shows PHP/8.3.36. The check merged every hop and
    reported example.org as "has the fix PHP/8.3.36" with server "Apache
    nginx": another domain's measurement under this domain's name. A version
    on another server says nothing about this one, in either direction."""

    def _check(self, answers):
        with mock.patch("requests.get", side_effect=answers) as get:
            result = sa.check_host("example.org", safe=lambda host: True, rules=ONLY_BUILTIN)
        return result, [c[0][0] for c in get.call_args_list]

    def test_a_redirect_to_another_domain_is_measured_as_that_domain_not_this_one(self):
        result, asked = self._check([
            _answer(301, {"Server": "Apache", "Location": "https://example.net/home/"}),
            _answer(200, {"Server": "nginx", "X-Powered-By": "PHP/8.2.7"}),
        ])
        self.assertEqual(["https://example.org/", "https://example.net/home/"], asked)
        self.assertEqual([], result["advisories"])
        self.assertEqual(("Apache", None, "https://example.org/", 301),
                         (result["server"], result["powered_by"], result["url"], result["status"]))
        to = result["redirect"]
        self.assertEqual(("example.net", "nginx", "PHP/8.2.7", "https://example.net/home/"),
                         (to["domain"], to["server"], to["powered_by"], to["url"]))
        self.assertEqual("vulnerable", to["advisories"][0]["verdict"])
        self.assertEqual([True, False], [h["own"] for h in result["hops"]])

    def test_the_version_on_the_redirect_itself_is_this_domains(self):
        result, _ = self._check([
            _answer(301, {"Server": "Apache", "X-Powered-By": "PHP/8.2.7", "Location": "https://example.net/"}),
            _answer(200, {"Server": "nginx", "X-Powered-By": "PHP/8.4.27"}),
        ])
        own = result["advisories"][0]
        self.assertEqual(("vulnerable", "PHP/8.2.7"), (own["verdict"], own["version"]))
        self.assertEqual("fixed", result["redirect"]["advisories"][0]["verdict"])

    def test_https_and_www_on_the_own_name_stay_this_domains(self):
        result, _ = self._check([
            _answer(301, {"Server": "Apache", "Location": "https://www.example.org/"}),
            _answer(200, {"Server": "nginx", "X-Powered-By": "PHP/8.2.7"}),
        ])
        self.assertIsNone(result["redirect"])
        self.assertEqual("vulnerable", result["advisories"][0]["verdict"])
        self.assertEqual("https://www.example.org/", result["url"])

    def test_the_scan_keeps_the_other_domains_server_apart(self):
        """The scan reported example.net's PHP as example.org's own version
        and own leak: a finding the operator of example.org cannot fix on
        their server, under a title that says it is theirs."""
        info, findings = _cross_domain_scan({"Server": "nginx", "X-Powered-By": "PHP/8.2.7"})
        self.assertEqual({"Server": "Apache"}, info["disclosed_headers"])
        self.assertEqual([], info["advisories"])
        self.assertEqual(("example.net", "PHP/8.2.7"), (info["redirect"]["domain"], info["redirect"]["powered_by"]))
        titles = [f["title"] for f in findings]
        self.assertNotIn("Version leaked in X-Powered-By", titles)
        self.assertFalse([t for t in titles if t.endswith("the PHP version shown is vulnerable")])
        hit = [f for f in findings if "example.net, where this domain redirects" in f["title"]]
        self.assertEqual("critical", hit[0]["severity"])
        self.assertIn("For whoever runs example.net", hit[0]["fix"])

    def test_a_hidden_version_on_the_other_domain_is_not_this_domains_finding(self):
        info, findings = _cross_domain_scan({"Server": "nginx", "Set-Cookie": "PHPSESSID=x"})
        self.assertEqual("cannot_tell", info["redirect"]["advisories"][0]["verdict"])
        self.assertFalse([f for f in findings if "PHP2Shell" in f["title"]])


class CsvTests(unittest.TestCase):
    """The check's table went nowhere: leaving the page lost it, while the
    teams that patch need the list. Its cells come from servers that are not
    ours, so a Server header written as a formula must not run in Excel."""

    def test_one_row_per_domain_and_outcome(self):
        import csv
        import io
        results = [
            {"domain": "a.example.org", "state": "measured", "powered_by": "PHP/8.2.7", "server": "Apache",
             "url": "https://a.example.org/", "advisories": sa.match({"x-powered-by": "PHP/8.2.7"}, rules=ONLY_BUILTIN)},
            {"domain": "b.example.org", "state": "measured", "server": "nginx", "advisories": []},
            {"domain": "c.example.org", "state": "unmeasured", "error": "No response", "advisories": []},
        ]
        rows = list(csv.DictReader(io.StringIO(sa.to_csv(results))))
        self.assertEqual(["vulnerable", "not_seen", "no_response"], [r["result"] for r in rows])
        self.assertEqual("CVE-2026-109618 CVE-2026-109619", rows[0]["cves"])

    def test_a_redirect_target_gets_rows_of_its_own(self):
        """The teams patch the server a row names. A row with example.net's
        PHP under example.org would send them to the wrong server."""
        import csv
        import io
        results = [{"domain": "example.org", "state": "measured", "server": "Apache", "advisories": [],
                    "url": "https://example.org/",
                    "redirect": {"domain": "example.net", "server": "nginx", "powered_by": "PHP/8.2.7",
                                 "url": "https://example.net/",
                                 "advisories": sa.match({"x-powered-by": "PHP/8.2.7"}, rules=ONLY_BUILTIN)}}]
        rows = list(csv.DictReader(io.StringIO(sa.to_csv(results))))
        self.assertEqual([("example.org", "example.org", "not_seen", "Apache", ""),
                          ("example.org", "example.net", "vulnerable", "nginx", "PHP/8.2.7")],
                         [(r["domain"], r["measured_on"], r["result"], r["server"], r["x_powered_by"]) for r in rows])

    def test_no_website_and_not_checked_are_their_own_results(self):
        import csv
        import io
        results = [{"domain": "a.example.org", "state": "no_address", "error": "No address"},
                   {"domain": "b.example.org", "state": "not_checked", "error": "Inside"}]
        rows = list(csv.DictReader(io.StringIO(sa.to_csv(results))))
        self.assertEqual(["no_address", "not_checked"], [r["result"] for r in rows])

    def test_a_header_written_as_a_formula_is_defused(self):
        out = sa.to_csv([{"domain": "a.example.org", "state": "measured", "server": '=HYPERLINK("http://x")',
                          "advisories": []}])
        self.assertIn("'=HYPERLINK", out)


class ExportPageTests(EnterpriseAppTestCase):
    def test_the_export_answers_with_a_csv_file(self):
        self.login_as("user")
        resp = self.client.post("/api/advisories/csv", json={"results": [
            {"domain": "a.example.org", "state": "measured", "advisories": []}]})
        self.assertEqual("text/csv", resp.mimetype)
        self.assertIn("domainlens-versions-", resp.headers["Content-Disposition"])
        self.assertIn("a.example.org,not_seen", resp.get_data(as_text=True))

    def test_the_page_lists_the_advisory_and_the_endpoint_takes_ten_at_a_time(self):
        self.login_as("user")
        html = self.client.get("/tools/versions").get_data(as_text=True)
        self.assertIn("CVE-2026-109618", html)
        self.assertIn('href="/tools/versions"', html)
        seen = []
        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
             mock.patch.object(sa, "check_host", side_effect=lambda d, **kw: seen.append(d) or {"domain": d}):
            self.client.post("/api/advisories/check", json={"domains": [f"site{n}.example.org" for n in range(15)]})
        self.assertEqual(10, len(seen))

    def test_a_domain_that_points_inside_is_not_asked_and_says_so(self):
        self.login_as("user")
        with mock.patch.object(security_checks, "_resolve", return_value=["10.0.0.5"]), \
             mock.patch("requests.get") as get:
            data = self.client.post("/api/advisories/check", json={"domains": ["intranet.example.org"]}).get_json()
        get.assert_not_called()
        self.assertEqual(["not_checked"], [r["state"] for r in data["results"]])

    def test_a_domain_without_an_address_comes_back_instead_of_vanishing(self):
        """A domain whose DNS has no address was dropped before the check:
        the page showed nothing for it, as if it had never been asked about,
        while the answer -- there is no website -- was known."""
        self.login_as("user")
        with mock.patch.object(security_checks, "_resolve", return_value=security_checks._DnsRecords()), \
             mock.patch("requests.get") as get:
            data = self.client.post("/api/advisories/check", json={"domains": ["gone.example.org"]}).get_json()
        get.assert_not_called()
        self.assertEqual([("gone.example.org", "no_address")], [(r["domain"], r["state"]) for r in data["results"]])


class VersionScopeTests(EnterpriseAppTestCase):
    """Choosing an organisation unit used to be impossible: the only portfolio
    scope was every held domain with a website, so a check of one company
    also asked for the sites of the others."""

    def setUp(self):
        super().setUp()
        self.login_as("user")

    def _unit(self, name, parent=None):
        import domain_portfolio
        return domain_portfolio.ensure_group(name, parent_id=parent)

    def _add(self, domain, unit_id=None, lifecycle=None, web=None):
        body = {"text": domain}
        if unit_id is not None:
            body["unit_id"] = unit_id
        if lifecycle:
            body["lifecycle"] = lifecycle
        resp = self.client.post("/api/portfolio/import", json=body)
        self.assertEqual(201, resp.status_code, resp.get_data(as_text=True))
        if web is not None:
            with self.db._connect() as conn:
                conn.execute("UPDATE portfolio_domains SET uses_web = ? WHERE domain = ?", (web, domain))

    def _sites(self, unit=None):
        url = "/api/advisories/sites" if unit is None else f"/api/advisories/sites?unit={unit}"
        resp = self.client.get(url)
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        return resp.get_json()

    def test_the_whole_portfolio_leaves_out_what_is_not_a_held_website(self):
        self._add("held.example")
        self._add("unknown-web.example")
        self._add("noweb.example", web="no")
        self._add("wanted.example", lifecycle="claim")
        self._add("lapsing.example", lifecycle="cancel")
        self.assertEqual(["held.example", "unknown-web.example"], self._sites()["domains"])

    def test_a_parent_unit_includes_the_units_under_it_and_not_its_sibling(self):
        company = self._unit("North")
        shop = self._unit("Shop", company)
        other = self._unit("South")
        self._add("north.example", unit_id=company)
        self._add("shop.example", unit_id=shop)
        self._add("south.example", unit_id=other)
        self._add("loose.example")
        self.assertEqual(["north.example", "shop.example"], self._sites(company)["domains"])

    def test_the_old_group_parameter_still_limits_the_list(self):
        """`?group=` was accepted by the portfolio export but ignored here,
        so the same link checked the whole portfolio instead of one unit."""
        unit = self._unit("North")
        self._add("north.example", unit_id=unit)
        self._add("south.example")
        resp = self.client.get(f"/api/advisories/sites?group={unit}")
        self.assertEqual(["north.example"], resp.get_json()["domains"])

    def test_the_unit_list_comes_on_its_own_in_tree_order(self):
        """Filling the dropdown used to compute the whole portfolio's site
        list as well, only to throw it away."""
        company = self._unit("North")
        self._unit("Shop", company)
        self._unit("South")
        self._add("north.example", unit_id=company)
        resp = self.client.get("/api/advisories/units")
        self.assertEqual(200, resp.status_code)
        body = resp.get_json()
        self.assertEqual(["units"], list(body))
        self.assertEqual(["North", "North › Shop", "South"], [u["path"] for u in body["units"]])
        self.assertEqual({"id", "path"}, set(body["units"][0]))

    def test_an_unknown_unit_is_refused_rather_than_returning_everything(self):
        self._add("held.example")
        resp = self.client.get("/api/advisories/sites?unit=99999")
        self.assertEqual(404, resp.status_code)
        self.assertNotIn("held.example", resp.get_data(as_text=True))

    def test_a_unit_that_is_not_a_number_is_refused(self):
        self.assertEqual(400, self.client.get("/api/advisories/sites?unit=north").status_code)

    def test_the_portfolio_export_refuses_an_unknown_unit_instead_of_an_empty_file(self):
        """The export answered a unit that does not exist with a CSV of only
        headers, which reads as "this unit has no domains"."""
        self._add("held.example")
        resp = self.client.get("/api/portfolio/csv?unit=99999")
        self.assertEqual(404, resp.status_code)
        self.assertNotIn("held.example", resp.get_data(as_text=True))


_VERSIONS_JS = pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "versions.js"

# Just enough of a page for versions.js: $, requestJson, toast and a few
# elements. The scenario below the source prints its result as JSON.
_DOM_STUB = r"""
function makeEl(tag) {
    return { tagName: (tag || 'div').toUpperCase(), value: '', label: '', textContent: '',
        dataset: {}, attrs: {}, children: [], listeners: {},
        classList: { toggle() {}, add() {}, remove() {} },
        addEventListener(type, fn) { this.listeners[type] = fn; },
        setAttribute(k, v) { this.attrs[k] = v; },
        appendChild(c) { this.children.push(c); return c; },
        insertBefore(c, ref) {
            const i = this.children.indexOf(ref);
            this.children.splice(i < 0 ? this.children.length : i, 0, c);
            return c;
        },
        querySelector() { return this.children.find(c => c.value === 'paste') || null; } };
}
const els = {};
const $ = id => (els[id] = els[id] || makeEl());
const document = { createElement: makeEl, addEventListener() {} };
let requestJson = async () => ({});
let toast = () => {};
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class VersionPageTests(unittest.TestCase):
    """The page itself, run in Node: what it asks the server for."""

    def _run(self, scenario):
        script = _DOM_STUB + _VERSIONS_JS.read_text(encoding="utf-8") + "\n" + scenario
        done = subprocess.run(["node", "-"], input=script, capture_output=True,
                              text=True, encoding="utf-8", timeout=30)
        self.assertEqual(0, done.returncode, done.stderr)
        return json.loads(done.stdout.strip().splitlines()[-1])

    def test_choosing_a_unit_asks_for_that_unit_not_the_whole_portfolio(self):
        """The only portfolio choice used to be every held site, so checking
        one company also sent requests to the sites of all the others."""
        calls = self._run("""
            const calls = [];
            requestJson = async url => { calls.push(url); return { domains: [] }; };
            (async () => {
                $('vcScope').value = 'unit:7';
                await vcPortfolioDomains();
                $('vcScope').value = 'portfolio';
                await vcPortfolioDomains();
                console.log(JSON.stringify(calls));
            })();
        """)
        self.assertEqual(["/api/advisories/sites?unit=7", "/api/advisories/sites"], calls)

    def test_a_failed_unit_load_is_tried_again_and_fills_the_list_once(self):
        """The list was marked as filled before the request; one failed load
        left it without units until the page was reloaded."""
        out = self._run("""
            const calls = [];
            let attempt = 0;
            requestJson = async url => {
                calls.push(url);
                if (attempt++ === 0) throw new Error('down');
                return { units: [{ id: 3, path: 'North' }] };
            };
            const paste = makeEl('option');
            paste.value = 'paste';
            $('vcScope').children.push(paste);
            (async () => {
                await vcLoadUnits().catch(() => {});
                await Promise.all([vcLoadUnits(), vcLoadUnits()]);
                await vcLoadUnits();
                const groups = $('vcScope').children.filter(c => c.tagName === 'OPTGROUP');
                console.log(JSON.stringify({ calls, groups: groups.map(g => g.children.map(o => o.value)),
                                             last: $('vcScope').children.at(-1).value }));
            })();
        """)
        self.assertEqual([["unit:3"]], out["groups"])
        self.assertEqual("paste", out["last"])
        self.assertEqual(["/api/advisories/units"] * 3, out["calls"])

    def test_a_pasted_slash_before_the_domain_does_not_lose_it(self):
        """"/example.org" became an empty name, and the check said "No
        domains to check" for a domain that was plainly there."""
        out = self._run("""
            $('vcDomains').value = '/example.org https://example.net/home //www.example.com';
            console.log(JSON.stringify(vcPasted()));
        """)
        self.assertEqual(["example.org", "example.net", "www.example.com"], out)

    def test_a_domain_without_a_website_is_listed_with_why(self):
        out = self._run("""
            vcRows = [{ domain: 'gone.example.org', state: 'no_address', error: 'No address in DNS', advisories: [] }];
            vcRender();
            console.log(JSON.stringify($('vcResult').innerHTML));
        """)
        self.assertIn("gone.example.org", out)
        self.assertIn("No website in DNS", out.split("vc-table")[-1])
        self.assertIn("No address in DNS", out)

    def test_the_details_show_every_step_and_whose_it_is(self):
        out = self._run("""
            vcRows = [{ domain: 'example.org', state: 'measured', server: 'Apache', advisories: [],
                        lookups: [{ host: 'example.org', address: 'public' }],
                        attempts: [{ url: 'https://example.org/', error: 'ConnectionError' },
                                   { url: 'http://example.org/', error: null }],
                        hops: [{ url: 'http://example.org/', status: 301, server: 'Apache', own: true },
                               { url: 'https://example.net/', status: 200, server: 'nginx', powered_by: 'PHP/8.3.36', own: false }],
                        redirect: { domain: 'example.net', server: 'nginx', powered_by: 'PHP/8.3.36', advisories: [] } },
                      { domain: 'gone.example.org', state: 'no_address', error: 'No address in DNS', advisories: [],
                        lookups: [{ host: 'gone.example.org', address: 'none' }, { host: 'www.gone.example.org', address: 'none' }],
                        attempts: [], hops: [] }];
            vcRender();
            console.log(JSON.stringify($('vcResult').innerHTML));
        """)
        self.assertEqual(2, out.count('<details class="vc-details">'))
        first, second = out.split('<details class="vc-details">')[1:]
        for part in ("Public address", "No answer: ConnectionError", "Answered", "This domain",
                     "Other domain: example.net", "PHP/8.3.36", ">301<"):
            self.assertIn(part, first)
        self.assertLess(first.index("http://example.org/</code> <span class=\"vc-hop-status\">301"),
                        first.index("https://example.net/</code> <span class=\"vc-hop-status\">200"))
        self.assertIn("www.gone.example.org", second)
        self.assertIn("No address", second)
        self.assertNotIn("Steps", second)

    def test_a_redirect_target_is_shown_under_the_domains_own_result(self):
        out = self._run("""
            vcRows = [{ domain: 'example.org', state: 'measured', server: 'Apache', advisories: [],
                        redirect: { domain: 'example.net', server: 'nginx', powered_by: 'PHP/8.2.7',
                                    advisories: [{ name: 'PHP2Shell', verdict: 'vulnerable', reason: 'too old' }] } }];
            vcRender();
            console.log(JSON.stringify($('vcResult').innerHTML));
        """)
        own, _, rest = out.partition("Redirects to")
        self.assertIn("None of the software seen", own)
        self.assertNotIn("Vulnerable", own.split("vc-table")[-1])
        self.assertIn("example.net", rest)
        self.assertIn("Vulnerable", rest)
        self.assertIn("On example.net:", rest)
        self.assertIn("PHP/8.2.7", rest)


if __name__ == "__main__":
    unittest.main()

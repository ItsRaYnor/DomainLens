"""Vulnerability rules as data, written by an administrator.

A new vulnerable version used to need a new release of DomainLens: the
advisories were a list in the code, with PHP2Shell's texts written into the
scan. Now a rule is data -- product, the token it shows itself by, where to
read it, the release with the fix per branch -- and one engine judges every
rule the same way. These tests keep that engine honest for rules nobody at
DomainLens wrote, keep PHP2Shell reading exactly as it did, and keep the
admin page from becoming a way to run code or to break every scan.
"""

import json
import pathlib
import shutil
import subprocess
import unittest
from unittest import mock

import audit_log
import security_checks
import software_advisories as sa
from enterprise_harness import EnterpriseAppTestCase

PHP2SHELL = sa.builtin_rules()[0]


def _nginx(**changes):
    raw = {"id": "nginx-resolver", "name": "nginx resolver", "product": "nginx", "token": "nginx",
           "severity": "high", "summary": "A resolver overflow.", "cves": ["CVE-2026-11111"],
           "sources": ["server"], "fixed": ["1.27.3", "1.25.5"], "older_branches": "unfixed"}
    raw.update(changes)
    return raw


def _verdicts(rule, header):
    return [(m["verdict"], m["version"]) for m in sa.match({"server": header}, rules=[rule])]


class EngineTests(unittest.TestCase):
    """The PHP logic, made general: what held for PHP must hold for any
    product a rule names, or an administrator's rule reports wrongly."""

    def test_a_custom_rule_is_judged_like_the_built_in_one(self):
        rule = sa.compile_rule(_nginx())
        cases = {
            "nginx/1.27.1": "vulnerable", "nginx/1.27.3": "fixed", "nginx/1.25.9": "fixed",
            "nginx/1.29.0": "fixed",          # newer than any branch listed
            "nginx/1.24.0": "vulnerable",     # a branch that no longer gets fixes
            "nginx/1.26.2": "cannot_tell",    # a branch the rule says nothing about
            "nginx/1.27": "cannot_tell",      # no patch release shown
            "nginx": "cannot_tell",           # in use, version hidden
        }
        for header, expected in cases.items():
            self.assertEqual(expected, _verdicts(rule, header)[0][0], header)

    def test_a_distribution_named_after_the_version_is_a_distribution_build(self):
        """Apache/2.4.52 (Ubuntu) carries the fix in Ubuntu's package without
        a new number; calling it vulnerable would send a team to patch a
        server that may already be patched."""
        rule = sa.compile_rule(_nginx())
        self.assertEqual([("cannot_tell", "nginx/1.27.1 (Ubuntu)")], _verdicts(rule, "nginx/1.27.1 (Ubuntu)"))

    def test_a_distribution_of_one_product_does_not_excuse_the_next(self):
        """"Apache/2.4.52 (Ubuntu) PHP/8.2.7": the (Ubuntu) belongs to Apache;
        PHP after it is still judged on its own number."""
        found = sa.match({"server": "Apache/2.4.52 (Ubuntu) PHP/8.2.7"}, rules=[PHP2SHELL])
        self.assertEqual("vulnerable", found[0]["verdict"])

    def test_older_branches_can_be_declared_not_affected_instead_of_vulnerable(self):
        """A flaw introduced in 1.25 does not make 1.22 vulnerable; without a
        way to say so, every old server would be reported as critical."""
        rule = sa.compile_rule(_nginx(older_branches="not_affected"))
        self.assertEqual("not_affected", _verdicts(rule, "nginx/1.22.1")[0][0])
        self.assertIsNone(sa.finding(sa.match({"server": "nginx/1.22.1"}, rules=[rule])[0]))

    def test_software_not_seen_is_not_applicable_rather_than_fixed(self):
        rule = sa.compile_rule(_nginx())
        self.assertEqual([], sa.match({"server": "Apache/2.4.58"}, rules=[rule]))

    def test_the_token_is_literal_so_a_rule_cannot_bring_an_expression(self):
        """The token goes into the pattern escaped: "Node.js" must not match
        "NodeXjs", and characters an expression needs are refused outright."""
        rule = sa.compile_rule(_nginx(token="Node.js", product="Node.js"))
        self.assertEqual([], sa.match({"server": "NodeXjs/20.1.0"}, rules=[rule]))
        self.assertEqual("vulnerable", sa.match({"server": "Node.js/1.24.0"}, rules=[rule])[0]["verdict"])
        for token in ("nginx(.*)+", "a|b", "x{1000}"):
            with self.assertRaises(sa.RuleError, msg=token):
                sa.compile_rule(_nginx(token=token))

    def test_fields_the_engine_does_not_know_are_dropped(self):
        rule = sa.compile_rule(_nginx(pattern="(a+)+$", code="import os"))
        self.assertNotIn("pattern", rule["public"])
        self.assertNotIn("code", rule["public"])

    def test_every_problem_is_named_at_once(self):
        with self.assertRaises(sa.RuleError) as raised:
            sa.compile_rule(_nginx(severity="urgent", fixed=["1.27", "1.25.5", "1.25.6"], cves=["CVE-1"],
                                   sources=["set-cookie"]))
        text = " ".join(raised.exception.problems)
        for part in ("severity", "1.27 is not a release", "Two releases", "CVE-1", "set-cookie"):
            self.assertIn(part, text)

    def test_the_version_can_come_from_the_generator_tag(self):
        rule = sa.compile_rule(_nginx(id="wp-x", product="WordPress", token="WordPress",
                                      sources=["meta:generator"], fixed=["6.4.3"]))
        resp = mock.Mock(headers={"Server": "nginx"}, history=[], url="https://example.org/",
                         text='<html><meta name="generator" content="WordPress 6.4.2"></html>')
        measured = sa.measure(resp, "example.org", [rule])
        self.assertEqual("WordPress 6.4.2", measured["generator"])
        self.assertEqual("vulnerable", measured["advisories"][0]["verdict"])

    def test_php2shell_findings_read_exactly_as_before(self):
        """Accepted risks are keyed on the finding's title. PHP2Shell's title
        changing with the move to rules would have dropped every acceptance
        of it -- and scans stored before carry no rule texts at all."""
        stored = {"advisory": "php2shell", "name": "PHP2Shell", "cves": ["CVE-2026-109618", "CVE-2026-109619"],
                  "severity": "critical", "verdict": "vulnerable", "version": "PHP/8.2.7",
                  "reason": "PHP/8.2.7 is older than 8.2.35, the release with the fix."}
        found = sa.finding(stored)
        self.assertEqual("PHP2Shell (CVE-2026-109618, CVE-2026-109619): the PHP version shown is vulnerable",
                         found["title"])
        self.assertTrue(found["detail"].endswith("The flaw lets anyone run code on the server without signing in."))
        self.assertIn("PHP-FPM", found["fix"])
        hidden = sa.finding({**stored, "verdict": "cannot_tell", "reason": "The PHP version is not shown."})
        self.assertEqual("PHP2Shell (CVE-2026-109618, CVE-2026-109619): PHP in use, fix not visible from outside",
                         hidden["title"])
        self.assertEqual("info", hidden["severity"])

    def test_a_custom_rule_that_cannot_be_read_leaves_the_built_in_rules(self):
        """The custom rules come from the database; a broken table must not
        take the PHP2Shell check down with it."""
        with mock.patch("advisory_rules.enabled", side_effect=RuntimeError("no table")):
            self.assertEqual(["php2shell"], [r["id"] for r in sa.active_rules()])


WORDPRESS = sa.compile_rule(_nginx(id="wp-x", product="WordPress", token="WordPress",
                                   sources=["meta:generator"], fixed=["6.4.3"]))


def _page(text, url="https://example.org/"):
    resp = mock.Mock(headers={"Server": "nginx"}, history=[], url=url, text=text)
    return sa.measure(resp, "example.org", [WORDPRESS])


def _wordpress(text, url="https://example.org/"):
    return [(a["verdict"], a["reason"]) for a in _page(text, url)["advisories"]]


class PageReadTests(unittest.TestCase):
    """A WordPress site was tested and only the PHP rule answered: its theme
    inlined 55,000 characters of CSS before the generator tag, only the first
    20,000 were read, the one tag found was a plugin's, and the core tag had
    been removed anyway. The WordPress rule fell silent on a site full of
    /wp-content/, as if WordPress were not there."""

    def test_a_generator_tag_far_into_the_page_is_read(self):
        body = "<html><head><style>" + "x" * 60000 + '</style><meta name="generator" content="WordPress 6.4.2">'
        self.assertEqual("vulnerable", _page(body)["advisories"][0]["verdict"])

    def test_the_generator_of_the_software_counts_after_a_plugins(self):
        body = ('<meta name="generator" content="WordPress Download Manager 3.3.74" />'
                '<meta name="generator" content="WordPress 6.4.2" />')
        measured = _page(body)
        self.assertEqual("WordPress Download Manager 3.3.74; WordPress 6.4.2", measured["generator"])
        self.assertEqual([("vulnerable", "WordPress 6.4.2 is older than 6.4.3, the release with the fix.")],
                         _wordpress(body))

    def test_wordpress_without_its_generator_tag_is_cannot_tell_not_silent(self):
        for body in ('<link rel="stylesheet" href="/wp-content/themes/x/style.css">',
                     '<script src="https://www.example.org/wp-includes/js/jquery.js"></script>'):
            self.assertEqual([("cannot_tell", "The WordPress version is not shown.")], _wordpress(body), body)

    def test_a_link_to_wordpress_on_another_site_is_not_this_sites(self):
        body = '<img src="https://media.example.net/wp-content/uploads/logo.png">'
        self.assertEqual([], _wordpress(body))

    def test_the_rule_test_on_a_pasted_page_sees_it_too(self):
        source = (pathlib.Path(__file__).resolve().parent.parent / "routes" / "advisories.py").read_text(
            encoding="utf-8")
        self.assertIn("engine.match(headers, cookies, url, generator, rules=[rule], page=body)", source)


class RuleAdminTests(EnterpriseAppTestCase):
    """The admin page and its API: who may change rules, what is refused,
    and that a saved rule reaches the scans."""

    def setUp(self):
        super().setUp()
        self.login_as("admin")

    def _create(self, **changes):
        return self.client.post("/api/admin/advisories", json=_nginx(**changes))

    def _scan(self, server):
        resp = mock.Mock(headers={"Server": server}, text="<html></html>", history=[], url="https://example.org/")
        with mock.patch.object(security_checks, "_safe_host", return_value=True), \
             mock.patch.object(security_checks, "_get", return_value=resp):
            info = security_checks.check_info_disclosure("example.org")
        return security_checks.audit_findings({"info_disclosure": info})

    def test_a_saved_rule_reaches_the_scans_and_the_version_check(self):
        self.assertEqual(201, self._create(impact="Anyone can crash the resolver.").status_code)
        findings = [f for f in self._scan("nginx/1.27.1") if "nginx resolver" in f["title"]]
        self.assertEqual("high", findings[0]["severity"])
        self.assertEqual("nginx resolver (CVE-2026-11111): the nginx version shown is vulnerable", findings[0]["title"])
        self.assertIn("Anyone can crash the resolver.", findings[0]["detail"])
        result = sa.check_host("example.org", address=lambda host: "public", get=lambda url: mock.Mock(
            status_code=200, headers={"Server": "nginx/1.27.1"}, history=[], url=url))
        self.assertIn("nginx-resolver", [a["advisory"] for a in result["advisories"]])
        html = self.client.get("/tools/versions").get_data(as_text=True)
        self.assertIn("nginx resolver", html)
        self.assertIn('href="/admin/advisories"', html)

    def test_a_rule_switched_off_is_not_used_and_comes_back_when_on(self):
        self._create()
        self.client.post("/api/admin/advisories/nginx-resolver/enabled", json={"enabled": False})
        self.assertFalse([f for f in self._scan("nginx/1.27.1") if "nginx resolver" in f["title"]])
        self.client.post("/api/admin/advisories/nginx-resolver/enabled", json={"enabled": True})
        self.assertTrue([f for f in self._scan("nginx/1.27.1") if "nginx resolver" in f["title"]])

    def test_a_change_and_a_removal_take_effect(self):
        self._create()
        resp = self.client.put("/api/admin/advisories/nginx-resolver", json=_nginx(fixed=["1.27.1"]))
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertEqual("fixed", sa.match({"server": "nginx/1.27.1"}, rules=sa.active_rules())[-1]["verdict"])
        self.assertEqual(200, self.client.delete("/api/admin/advisories/nginx-resolver").status_code)
        self.assertEqual(404, self.client.delete("/api/admin/advisories/nginx-resolver").status_code)
        self.assertEqual(["php2shell"], [r["id"] for r in sa.active_rules()])

    def test_every_change_is_in_the_audit_log(self):
        self._create()
        self.client.put("/api/admin/advisories/nginx-resolver", json=_nginx(severity="critical"))
        self.client.post("/api/admin/advisories/nginx-resolver/enabled", json={"enabled": False})
        self.client.delete("/api/admin/advisories/nginx-resolver")
        actions = [e["action"] for e in audit_log.list_entries(limit=50)["entries"] if e["action"].startswith("advisory_rule.")]
        self.assertEqual(sorted(["advisory_rule.create", "advisory_rule.update", "advisory_rule.disable",
                                 "advisory_rule.delete"]), sorted(actions))
        update = audit_log.list_entries(action="advisory_rule.update")["entries"][0]
        self.assertIn("severity", json.dumps(update.get("details")))

    def test_a_refused_rule_names_every_problem_and_is_not_stored(self):
        resp = self._create(severity="urgent", fixed=["1.27"])
        self.assertEqual(400, resp.status_code)
        self.assertEqual(2, len(resp.get_json()["problems"]))
        self.assertEqual(["php2shell"], [r["id"] for r in self.client.get("/api/admin/advisories").get_json()["rules"]])

    def test_built_in_rules_cannot_be_taken_changed_switched_off_or_removed(self):
        self.assertEqual(400, self._create(id="php2shell").status_code)
        self.assertEqual(400, self.client.put("/api/admin/advisories/php2shell", json=_nginx()).status_code)
        self.assertEqual(400, self.client.post("/api/admin/advisories/php2shell/enabled",
                                               json={"enabled": False}).status_code)
        self.assertEqual(400, self.client.delete("/api/admin/advisories/php2shell").status_code)
        self.assertIn("php2shell", [r["id"] for r in sa.active_rules()])

    def test_an_id_cannot_be_taken_twice(self):
        self._create()
        resp = self._create(name="Another")
        self.assertEqual(400, resp.status_code)
        self.assertIn("already exists", " ".join(resp.get_json()["problems"]))

    def test_only_an_administrator_may_see_or_change_rules(self):
        for role in ("user", "viewer"):
            self.login_as(role)
            self.assertEqual(403, self._create().status_code, role)
            self.assertEqual(403, self.client.get("/api/admin/advisories").status_code, role)
            self.assertEqual(403, self.client.post("/api/admin/advisories/test", json={}).status_code, role)
            self.assertNotIn('href="/admin/advisories"', self.client.get("/tools/versions").get_data(as_text=True))
        self.login_as("admin")
        self.assertEqual(200, self.client.get("/admin/advisories").status_code)

    def test_the_test_button_judges_pasted_headers_and_saves_nothing(self):
        resp = self.client.post("/api/admin/advisories/test", json={
            "rule": _nginx(), "headers": "HTTP/2 200\nServer: nginx/1.27.1 (Ubuntu)\nSet-Cookie: a=b"})
        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        body = resp.get_json()
        self.assertEqual({"server": "nginx/1.27.1 (Ubuntu)"}, body["read"]["headers"])
        self.assertEqual("cannot_tell", body["results"][0]["verdict"])
        self.assertEqual("info", body["finding"]["severity"])
        self.assertEqual(["php2shell"], [r["id"] for r in sa.active_rules()])

    def test_the_test_button_refuses_a_rule_the_engine_cannot_use(self):
        resp = self.client.post("/api/admin/advisories/test", json={"rule": _nginx(token="a|b"), "headers": ""})
        self.assertEqual(400, resp.status_code)
        self.assertTrue(resp.get_json()["problems"])

    def test_a_stored_rule_that_no_longer_compiles_is_shown_and_skipped(self):
        """A tighter check in a later version must not stop the scans; the
        page says which rule is not used, and why."""
        with self.db._connect() as conn:
            conn.execute("INSERT INTO advisory_rules (id, rule, enabled, created_at, updated_at) VALUES "
                         "('old-rule', ?, 1, '2026-01-01', '2026-01-01')", (json.dumps(_nginx(id="old-rule", token="a|b")),))
        self.assertEqual(["php2shell"], [r["id"] for r in sa.active_rules()])
        listed = {r["id"]: r for r in self.client.get("/api/admin/advisories").get_json()["rules"]}
        self.assertTrue(listed["old-rule"]["problems"])


_EXAMPLES = json.loads((pathlib.Path(__file__).resolve().parent.parent / "advisory_examples.json")
                       .read_text(encoding="utf-8"))


class ExampleRuleTests(unittest.TestCase):
    """The example rules are offered as serious, exploited flaws. A wrong
    release in one would tell a team a patched server is vulnerable, or a
    vulnerable one is fine; each is checked against versions on both sides
    of its fix, taken from the vendor's advisory."""

    CASES = {
        "apache-path-traversal-2021": {
            "Apache/2.4.48": "not_affected", "Apache/2.4.49 (Unix)": "vulnerable", "Apache/2.4.50": "vulnerable",
            "Apache/2.4.51": "fixed", "Apache/2.2.34": "not_affected", "Apache/2.4.49 (Ubuntu)": "cannot_tell"},
        "apache-mod-rewrite-2024": {
            "Apache/2.4.59": "vulnerable", "Apache/2.4.60": "fixed", "Apache/2.4.62": "fixed",
            "Apache/2.4.52 (Ubuntu)": "cannot_tell", "Apache": "cannot_tell"},
        "nginx-resolver-2021": {
            "nginx/1.20.0": "vulnerable", "nginx/1.20.1": "fixed", "nginx/1.21.0": "fixed",
            "nginx/1.18.0": "vulnerable", "nginx/0.6.17": "not_affected", "nginx/1.24.0": "fixed",
            "nginx/1.18.0 (Ubuntu)": "cannot_tell"},
        "php-fpm-underflow-2019": {
            "PHP/7.3.10": "vulnerable", "PHP/7.3.11": "fixed", "PHP/7.2.23": "vulnerable", "PHP/7.2.24": "fixed",
            "PHP/7.1.33": "fixed", "PHP/7.0.33": "vulnerable", "PHP/7.4.0": "fixed", "PHP/8.2.7": "fixed"},
    }

    def test_every_example_is_judged_right_on_both_sides_of_its_fix(self):
        rules = {r["id"]: sa.compile_rule(r) for r in _EXAMPLES["rules"]}
        self.assertEqual(set(self.CASES), set(rules))
        for rule_id, cases in self.CASES.items():
            source = rules[rule_id]["sources"][0]
            for shown, expected in cases.items():
                found = sa.match({source: shown}, rules=[rules[rule_id]])
                self.assertEqual(expected, found[0]["verdict"], f"{rule_id}: {shown}")

    def test_every_example_names_its_cves_and_where_they_are_described(self):
        for raw in _EXAMPLES["rules"]:
            rule = sa.compile_rule(raw)
            self.assertTrue(rule["cves"] and rule["references"] and rule["fix"] and rule["check"], rule["id"])
            self.assertIn(rule["severity"], ("critical", "high"), rule["id"])
            self.assertNotIn(rule["id"], sa.BUILTIN_IDS)

    def test_tomcat_is_not_read_as_the_apache_web_server(self):
        """"Apache-Coyote/1.1" is Tomcat. Read as Apache HTTP Server, every
        Tomcat site would get an "Apache in use, fix not visible" finding."""
        rules = [sa.compile_rule(r) for r in _EXAMPLES["rules"] if r["token"] == "Apache"]
        self.assertEqual([], sa.match({"server": "Apache-Coyote/1.1"}, rules=rules))

    def test_introduced_must_come_before_the_fix(self):
        with self.assertRaises(sa.RuleError):
            sa.compile_rule(_nginx(introduced="1.27.3"))
        with self.assertRaises(sa.RuleError):
            sa.compile_rule(_nginx(introduced="1.27"))

    def test_without_a_patch_release_the_introduced_branch_cannot_be_told(self):
        """"Apache/2.4" could be 2.4.48 (not affected) or 2.4.50 (vulnerable)."""
        rule = sa.compile_rule(next(r for r in _EXAMPLES["rules"] if r["id"] == "apache-path-traversal-2021"))
        self.assertEqual("cannot_tell", sa.match({"server": "Apache/2.4"}, rules=[rule])[0]["verdict"])


class TransferTests(EnterpriseAppTestCase):
    """Export, import and the examples. Rules written on one DomainLens had
    no way to another, and the examples are only useful if adding one is a
    choice: nobody should get findings they did not ask for."""

    def setUp(self):
        super().setUp()
        self.login_as("admin")

    def _ids(self):
        return [r["id"] for r in self.client.get("/api/admin/advisories").get_json()["rules"]]

    def _file(self, *rules):
        return {"format": "domainlens-advisory-rules", "version": 1, "rules": list(rules)}

    def test_an_export_imports_again_with_its_switched_off_rules_still_off(self):
        self.client.post("/api/admin/advisories", json=_nginx())
        self.client.post("/api/admin/advisories", json=_nginx(id="second", name="Second"))
        self.client.post("/api/admin/advisories/second/enabled", json={"enabled": False})
        resp = self.client.get("/api/admin/advisories/export")
        self.assertIn("domainlens-advisory-rules-", resp.headers["Content-Disposition"])
        exported = json.loads(resp.get_data(as_text=True))
        self.assertEqual(["nginx-resolver", "second"], [r["id"] for r in exported["rules"]])
        for rule_id in ("nginx-resolver", "second"):
            self.client.delete(f"/api/admin/advisories/{rule_id}")
        result = self.client.post("/api/admin/advisories/import", json=exported).get_json()
        self.assertEqual(["nginx-resolver", "second"], result["added"])
        listed = {r["id"]: r for r in self.client.get("/api/admin/advisories").get_json()["rules"]}
        self.assertTrue(listed["nginx-resolver"]["enabled"])
        self.assertFalse(listed["second"]["enabled"])
        self.assertEqual(["php2shell", "nginx-resolver"], [r["id"] for r in sa.active_rules()])

    def test_one_bad_rule_imports_nothing_and_every_reason_is_named(self):
        """A half-imported set would run some rules and silently not others."""
        resp = self.client.post("/api/admin/advisories/import", json=self._file(
            _nginx(), _nginx(id="bad-one", token="a|b"), _nginx(id="php2shell"), _nginx(id="nginx-resolver")))
        self.assertEqual(400, resp.status_code)
        problems = " ".join(resp.get_json()["problems"])
        self.assertIn("Rule 2 (bad-one)", problems)
        self.assertIn("built-in", problems)
        self.assertIn("twice", problems)
        self.assertEqual(["php2shell"], self._ids())

    def test_an_existing_rule_is_skipped_unless_replace_is_asked(self):
        self.client.post("/api/admin/advisories", json=_nginx())
        changed = self._file(_nginx(severity="critical"))
        skipped = self.client.post("/api/admin/advisories/import", json=changed).get_json()
        self.assertEqual(["nginx-resolver"], skipped["skipped"])
        self.assertEqual("high", self.client.get("/api/admin/advisories").get_json()["rules"][1]["severity"])
        replaced = self.client.post("/api/admin/advisories/import?replace=1", json=changed).get_json()
        self.assertEqual(["nginx-resolver"], replaced["replaced"])
        self.assertEqual("critical", self.client.get("/api/admin/advisories").get_json()["rules"][1]["severity"])

    def test_a_file_that_is_not_a_rules_file_is_refused(self):
        for body in ({"rules": [_nginx()]}, {**self._file(_nginx()), "version": 2}, self._file(), [_nginx()]):
            self.assertEqual(400, self.client.post("/api/admin/advisories/import", json=body).status_code, body)
        self.assertEqual(["php2shell"], self._ids())

    def test_examples_are_not_used_until_added(self):
        examples = self.client.get("/api/admin/advisories/examples").get_json()["examples"]
        self.assertEqual(4, len(examples))
        self.assertFalse(any(e["added"] for e in examples))
        self.assertEqual(["php2shell"], [r["id"] for r in sa.active_rules()])
        resp = self.client.post("/api/admin/advisories/examples", json={"ids": ["nginx-resolver-2021"]})
        self.assertEqual(["nginx-resolver-2021"], resp.get_json()["added"])
        self.assertIn("nginx-resolver-2021", [r["id"] for r in sa.active_rules()])
        added = {e["id"]: e["added"] for e in self.client.get("/api/admin/advisories/examples").get_json()["examples"]}
        self.assertTrue(added["nginx-resolver-2021"])
        again = self.client.post("/api/admin/advisories/examples", json={"ids": ["nginx-resolver-2021"]}).get_json()
        self.assertEqual(["nginx-resolver-2021"], again["skipped"])
        self.assertEqual(404, self.client.post("/api/admin/advisories/examples", json={"ids": ["nope"]}).status_code)

    def test_the_examples_file_imports_as_a_rules_file(self):
        result = self.client.post("/api/admin/advisories/import", json=_EXAMPLES).get_json()
        self.assertEqual(4, len(result["added"]))

    def test_export_and_import_are_in_the_audit_log(self):
        self.client.get("/api/admin/advisories/export")
        self.client.post("/api/admin/advisories/import", json=self._file(_nginx()))
        actions = [e["action"] for e in audit_log.list_entries(limit=50)["entries"]]
        self.assertIn("advisory_rule.export", actions)
        entry = audit_log.list_entries(action="advisory_rule.import")["entries"][0]
        self.assertIn("nginx-resolver", json.dumps(entry.get("details")))

    def test_only_an_administrator_may_export_import_or_add_examples(self):
        self.login_as("user")
        self.assertEqual(403, self.client.get("/api/admin/advisories/export").status_code)
        self.assertEqual(403, self.client.post("/api/admin/advisories/import", json=self._file(_nginx())).status_code)
        self.assertEqual(403, self.client.get("/api/admin/advisories/examples").status_code)
        self.assertEqual(403, self.client.post("/api/admin/advisories/examples",
                                               json={"ids": ["nginx-resolver-2021"]}).status_code)


_ADMIN_JS = pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "advisories_admin.js"

# Just enough of a page for advisories_admin.js.
_STUB = r"""
function makeEl() {
    return { value: '', textContent: '', innerHTML: '', disabled: false, dataset: {},
        classList: { hidden: true, toggle(name, on) { if (name === 'hidden') this.hidden = on; } },
        addEventListener() {}, scrollIntoView() {} };
}
const els = {};
const $ = id => (els[id] = els[id] || makeEl());
const document = { addEventListener() {} };
let toast = () => {};
const esc = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const calls = [];
let reply = { ok: true, data: {} };
globalThis.fetch = async (url, options) => {
    calls.push({ url, method: options.method, body: options.body ? JSON.parse(options.body) : null });
    return { ok: reply.ok, json: async () => reply.data };
};
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class RuleAdminPageTests(unittest.TestCase):
    """The page itself, run in Node: what the form sends."""

    def _run(self, scenario):
        script = _STUB + _ADMIN_JS.read_text(encoding="utf-8") + "\n" + scenario
        done = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, encoding="utf-8",
                              timeout=30)
        self.assertEqual(0, done.returncode, done.stderr)
        return json.loads(done.stdout.strip().splitlines()[-1])

    def test_a_built_in_rule_used_as_start_saves_as_a_new_rule_with_its_lists_intact(self):
        """Starting from PHP2Shell must create a new rule, never try to
        overwrite the built-in one, and keep every CVE and release."""
        out = self._run("""
            (async () => {
                arFill({ id: 'php2shell', name: 'PHP2Shell', product: 'PHP', token: 'PHP', severity: 'critical',
                         cves: ['CVE-2026-109618', 'CVE-2026-109619'], fixed: ['8.5.12', '8.4.27'],
                         sources: ['x-powered-by', 'server'], seen_cookies: ['phpsessid'], seen_paths: ['.php'],
                         references: ['https://example.org/a'] }, false);
                $('arId').value = 'php-copy';
                reply = { ok: true, data: { rule: { id: 'php-copy' }, rules: [] } };
                await arSave();
                console.log(JSON.stringify(calls[0]));
            })();
        """)
        self.assertEqual(("/api/admin/advisories", "POST"), (out["url"], out["method"]))
        body = out["body"]
        self.assertEqual("php-copy", body["id"])
        self.assertEqual(["CVE-2026-109618", "CVE-2026-109619"], body["cves"])
        self.assertEqual(["8.5.12", "8.4.27"], body["fixed"])
        self.assertEqual(["x-powered-by", "server"], body["sources"])

    def test_every_reason_a_rule_is_refused_is_shown(self):
        out = self._run("""
            (async () => {
                reply = { ok: false, data: { error: 'The rule cannot be used.', problems: ['name is required.', 'cves needs at least one CVE.'] } };
                await arSave();
                console.log(JSON.stringify({ html: $('arProblems').innerHTML, hidden: $('arProblems').classList.hidden }));
            })();
        """)
        self.assertFalse(out["hidden"])
        self.assertIn("name is required.", out["html"])
        self.assertIn("cves needs at least one CVE.", out["html"])

    def test_an_import_sends_the_file_as_it_is_with_the_replace_choice(self):
        out = self._run("""
            (async () => {
                $('arImportFile').files = [{ text: async () => '{"format": "domainlens-advisory-rules", "version": 1, "rules": []}' }];
                $('arImportReplace').checked = true;
                reply = { ok: true, data: { added: ['a'], replaced: [], skipped: [], rules: [], examples: [] } };
                await arImport();
                console.log(JSON.stringify({ call: calls[0], result: $('arImportResult').textContent }));
            })();
        """)
        self.assertEqual("/api/admin/advisories/import?replace=1", out["call"]["url"])
        self.assertEqual("domainlens-advisory-rules", out["call"]["body"]["format"])
        self.assertIn("Added 1", out["result"])

    def test_a_file_that_is_not_json_is_said_so_and_not_sent(self):
        out = self._run("""
            (async () => {
                $('arImportFile').files = [{ text: async () => 'not json' }];
                await arImport();
                console.log(JSON.stringify({ calls: calls.length, html: $('arImportProblems').innerHTML }));
            })();
        """)
        self.assertEqual(0, out["calls"])
        self.assertIn("The file is not JSON.", out["html"])


if __name__ == "__main__":
    unittest.main()

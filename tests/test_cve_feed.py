"""Known CVEs of the versions a site shows, from the NVD and NCSC-NL.

The advisory rules covered only the flaws someone wrote a rule for, so a
server showing a PHP release with thirty published CVEs got no word about
them unless one of the thirty had a rule. These tests keep the CVE data
honest about what it knows: a version inside a range is vulnerable, data
that is old or was never fetched is "not measured" and never "no CVEs", a
distribution build is "cannot tell", and switched off it says nothing.
"""

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from urllib.parse import parse_qs, unquote, urlparse

import cve_feed
import ncsc_advisories
import security_checks
import software_advisories as sa

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
_tempdir = None


def setUpModule():
    global _tempdir
    _tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    os.environ["DOMAINLENS_DB"] = os.path.join(_tempdir.name, "cve-feed.db")
    import db
    db.init_db()


def tearDownModule():
    os.environ.pop("DOMAINLENS_DB", None)
    _tempdir.cleanup()


def _clear():
    import db
    with db._lock, db._connect() as conn:
        for table in ("cve_items", "cve_ranges", "cve_feed_state", "ncsc_advisories", "ncsc_cves"):
            conn.execute(f"DELETE FROM {table}")


def _match(cpe, vulnerable=True, version="*", update="*", **bounds):
    return {"vulnerable": vulnerable, "criteria": f"cpe:2.3:a:{cpe}:{version}:{update}:*:*:*:*:*:*", **bounds}


def _cve(cve_id, matches, score=7.5, kev=None, status="Analyzed", operator=None, extra_nodes=()):
    config = {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}, *extra_nodes]}
    if operator:
        config["operator"] = operator
    record = {"id": cve_id, "published": "2026-01-01T00:00:00.000", "lastModified": "2026-10-01T00:00:00.000",
              "vulnStatus": status, "descriptions": [{"lang": "en", "value": f"{cve_id} in PHP."}],
              "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score,
                                                                              "baseSeverity": "HIGH"}}]},
              "configurations": [config]}
    if kev:
        record["cisaExploitAdd"] = kev
    return {"cve": record}


def _page(entries, total=None):
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"totalResults": len(entries) if total is None else total,
                              "vulnerabilities": entries}
    return resp


PHP = next(p for p in cve_feed.PRODUCTS if p["key"] == "php")
NGINX = next(p for p in cve_feed.PRODUCTS if p["key"] == "nginx")

PHP_RECORDS = [
    # 8.1 branch fixed in 8.1.30, 8.2 in 8.2.25: exploited.
    _cve("CVE-2026-10001", [_match("php:php", versionStartIncluding="8.1.0", versionEndExcluding="8.1.30"),
                            _match("php:php", versionStartIncluding="8.2.0", versionEndExcluding="8.2.25")],
         score=9.8, kev="2026-06-01"),
    # Only 8.1 up to 8.1.10.
    _cve("CVE-2026-10002", [_match("php:php", versionStartIncluding="8.1.0", versionEndExcluding="8.1.11")],
         score=5.3),
    # Applies only on Windows: an AND with a platform.
    _cve("CVE-2026-10003", [_match("php:php", versionStartIncluding="8.1.0", versionEndExcluding="8.1.40")],
         score=8.1, operator="AND",
         extra_nodes=[{"operator": "OR", "cpeMatch": [{"vulnerable": False,
                                                        "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]),
    # A record that names PHP with no versions at all.
    _cve("CVE-2026-10004", [_match("php:php")], score=6.0),
]


def _enabled(**changes):
    cfg = {"enabled": True, "ncsc": False, "max_age_days": 3}
    cfg.update(changes)
    return mock.patch.object(cve_feed, "settings", return_value=cfg)


def _load_php(records=PHP_RECORDS, now=NOW):
    get = mock.Mock(return_value=_page(records))
    with _enabled():
        cve_feed.sync_nvd([PHP], get=get, sleep=mock.Mock(), now=now)
    return get


def _shown(text, product=PHP):
    reader = {**product, **sa.reader(product["token"], product["sources"])}
    return sa.parse_version(reader, [text])


def _assess(text, now=NOW, product=PHP):
    with _enabled(), mock.patch.object(cve_feed, "_now", return_value=now):
        return cve_feed.assess_product(product, _shown(text, product))


class OverviewTests(unittest.TestCase):
    """Tools -> Versions listed "Known CVEs (NVD)" without what the data
    holds, where every rule beside it shows its CVEs and releases."""

    def setUp(self):
        _clear()

    def _php(self):
        return next(p for p in cve_feed.overview() if p["key"] == "php")

    def test_per_branch_the_release_from_which_no_known_cve_applies(self):
        _load_php()
        php = self._php()
        self.assertEqual(["8.2.25", "8.1.30"], php["clean_from"])
        self.assertEqual((4, 1, 1), (php["cves"], php["exploited"], php["not_versioned"]))
        self.assertEqual("CVE-2026-10004", php["newest"]["cve"])

    def test_a_cve_in_a_later_release_of_the_branch_withholds_it(self):
        """lighttpd was offered as clean from 1.4.67 while a CVE named 1.4.80:
        "from" has to hold for the rest of the branch."""
        _load_php(PHP_RECORDS + [_cve("CVE-2026-10006", [_match("php:php", version="8.2.30")])])
        self.assertEqual(["8.1.30"], self._php()["clean_from"])

    def test_an_open_ended_cve_withholds_its_branch(self):
        _load_php(PHP_RECORDS + [_cve("CVE-2026-10007", [_match("php:php", versionStartIncluding="8.2.0")])])
        self.assertEqual(["8.1.30"], self._php()["clean_from"])


class RecordTests(unittest.TestCase):
    def test_only_vulnerable_matches_of_the_product_count(self):
        cve = _cve("CVE-2026-1", [_match("php:php", versionEndExcluding="8.1.30"),
                                  _match("php:php", vulnerable=False, versionEndExcluding="9.0.0"),
                                  _match("f5:nginx", versionEndExcluding="1.27.0"),
                                  _match("php:php", version="8.1.0", update="rc1")])["cve"]
        self.assertEqual([(None, None, 0, "8.1.30", 0, 0)], cve_feed.ranges_for(cve, "php:php"))

    def test_a_cve_that_needs_a_platform_too_is_conditional(self):
        cve = PHP_RECORDS[2]["cve"]
        self.assertEqual(1, cve_feed.ranges_for(cve, "php:php")[0][5])


class SyncTests(unittest.TestCase):
    def setUp(self):
        _clear()

    def test_the_first_sync_asks_for_everything_and_keeps_the_ranges(self):
        get = _load_php()
        url = get.call_args.args[0]
        query = parse_qs(urlparse(url).query, keep_blank_values=True)
        self.assertEqual(["cpe:2.3:a:php:php"], query["virtualMatchString"])
        self.assertIn("noRejected", query)
        self.assertNotIn("lastModStartDate", query)
        self.assertEqual(["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003", "CVE-2026-10004"],
                         cve_feed.stored_cves("php"))

    def test_the_next_sync_asks_only_what_changed_and_drops_rejected_cves(self):
        _load_php()
        rejected = _cve("CVE-2026-10002", [], status="Rejected")
        get = mock.Mock(return_value=_page([rejected]))
        later = NOW + timedelta(days=1)
        with _enabled():
            cve_feed.sync_nvd([PHP], get=get, sleep=mock.Mock(), now=later)
        query = parse_qs(urlparse(get.call_args.args[0]).query, keep_blank_values=True)
        self.assertNotIn("noRejected", query)
        self.assertTrue(unquote(query["lastModStartDate"][0]).startswith("2026-10-28T11:00:00"))
        self.assertTrue(unquote(query["lastModEndDate"][0]).startswith("2026-10-29T12:00:00"))
        self.assertNotIn("CVE-2026-10002", cve_feed.stored_cves("php"))
        self.assertIn("CVE-2026-10001", cve_feed.stored_cves("php"))

    def test_a_long_gap_starts_over_instead_of_asking_past_the_nvd_window(self):
        _load_php()
        get = mock.Mock(return_value=_page(PHP_RECORDS))
        with _enabled():
            cve_feed.sync_nvd([PHP], get=get, sleep=mock.Mock(), now=NOW + timedelta(days=200))
        self.assertIn("noRejected", get.call_args.args[0])

    def test_pages_are_followed_and_paced_as_the_nvd_asks(self):
        pages = [_page(PHP_RECORDS[:2], total=3), _page(PHP_RECORDS[2:3], total=3)]
        get = mock.Mock(side_effect=pages)
        sleep = mock.Mock()
        with _enabled(), mock.patch.object(cve_feed, "_api_key", return_value=""):
            cve_feed.sync_nvd([PHP], get=get, sleep=sleep, now=NOW)
        self.assertEqual(["0", "2"], [parse_qs(urlparse(c.args[0]).query)["startIndex"][0]
                                      for c in get.call_args_list])
        sleep.assert_called_once_with(6.0)

    def test_a_failed_sync_keeps_what_was_there_and_says_why(self):
        _load_php()
        with _enabled():
            report = cve_feed.sync_nvd([PHP], get=mock.Mock(return_value=mock.Mock(status_code=503)),
                                       sleep=mock.Mock(), now=NOW + timedelta(days=1))
        self.assertIn("HTTP 503", report["php"])
        self.assertEqual(4, len(cve_feed.stored_cves("php")))
        state = cve_feed._state("nvd:php")
        self.assertEqual(NOW.isoformat(), state["synced_at"])
        self.assertIn("HTTP 503", state["error"])

    def test_a_key_is_sent_as_the_nvd_asks(self):
        get = mock.Mock(return_value=_page([]))
        with _enabled(), mock.patch.object(cve_feed, "_api_key", return_value="k-123"):
            cve_feed.sync_nvd([PHP], get=get, sleep=mock.Mock(), now=NOW)
        self.assertEqual("k-123", get.call_args.kwargs["headers"]["apiKey"])

    def test_the_nvd_is_not_asked_again_within_two_hours(self):
        _load_php()
        cve_feed._save_state("nvd:php", attempted_at=NOW.isoformat())
        with _enabled():
            result = cve_feed.sync(get=mock.Mock(), sleep=mock.Mock(), now=NOW + timedelta(minutes=30))
        self.assertFalse(result["started"])
        self.assertIn("two hours", result["reason"])

    def test_switched_off_nothing_is_fetched(self):
        get = mock.Mock()
        with _enabled(enabled=False):
            result = cve_feed.sync(get=get, sleep=mock.Mock(), now=NOW)
            self.assertIsNone(cve_feed.maybe_sync())
        self.assertFalse(result["started"])
        get.assert_not_called()


def _all_synced(now=NOW):
    for product in cve_feed.PRODUCTS:
        cve_feed._save_state(f"nvd:{product['key']}", synced_at=now.isoformat(), attempted_at=now.isoformat())


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        _clear()
        _load_php()
        _all_synced()

    def test_a_version_inside_the_ranges_is_vulnerable_with_the_release_to_move_to(self):
        result = _assess("PHP/8.1.5")
        self.assertEqual("vulnerable", result["state"])
        self.assertEqual(["CVE-2026-10001", "CVE-2026-10002"], [c["cve"] for c in result["cves"]])
        self.assertEqual(1, result["counts"]["exploited"])
        self.assertEqual("8.1.30", result["fixed_in"])

    def test_a_cve_without_any_version_is_counted_apart_not_as_vulnerable(self):
        result = _assess("PHP/8.1.35")
        self.assertEqual(1, result["counts"]["not_versioned"])
        self.assertNotIn("CVE-2026-10004", [c["cve"] for c in result["cves"]])

    def test_a_platform_only_cve_cannot_be_told_from_outside(self):
        result = _assess("PHP/8.1.35")
        self.assertEqual("cannot_tell", result["state"])
        self.assertEqual(["CVE-2026-10003"], [c["cve"] for c in result["cves"]])

    def test_past_every_range_there_are_no_known_cves_and_it_says_what_that_covers(self):
        result = _assess("PHP/8.3.1")
        self.assertEqual("no_known_cves", result["state"])
        self.assertIn("not analysed yet", result["reason"])
        self.assertIsNone(cve_feed.finding(result))

    def test_a_distribution_build_cannot_be_told_from_outside(self):
        result = _assess("PHP/8.1.5-1ubuntu1")
        self.assertEqual("cannot_tell", result["state"])
        self.assertIn("distribution build", result["reason"])
        self.assertEqual("info", cve_feed.finding(result)["severity"])

    def test_a_missing_patch_release_is_not_a_guess(self):
        nginx = _cve("CVE-2026-20001", [_match("f5:nginx", versionStartIncluding="1.25.0",
                                                versionEndExcluding="1.25.4")])
        with _enabled():
            cve_feed.sync_nvd([NGINX], get=mock.Mock(return_value=_page([nginx])), sleep=mock.Mock(), now=NOW)
        self.assertEqual("cannot_tell", _assess("nginx/1.25", product=NGINX)["state"])
        whole = _assess("PHP/8.2", product=PHP)
        self.assertEqual("cannot_tell", whole["state"])

    def test_a_whole_branch_inside_a_range_is_vulnerable_without_the_patch(self):
        old = _cve("CVE-2026-20002", [_match("f5:nginx", versionEndExcluding="1.26.0")])
        with _enabled():
            cve_feed.sync_nvd([NGINX], get=mock.Mock(return_value=_page([old])), sleep=mock.Mock(), now=NOW)
        result = _assess("nginx/1.24", product=NGINX)
        self.assertEqual("vulnerable", result["state"])
        self.assertIsNone(result["fixed_in"], "the fix is in a newer branch, not a 1.24 release")

    def test_old_data_is_not_measured_never_no_cves(self):
        result = _assess("PHP/8.3.1", now=NOW + timedelta(days=4))
        self.assertEqual("unmeasured", result["state"])
        self.assertIn("older than 3 days", result["reason"])
        self.assertEqual("info", cve_feed.finding(result)["severity"])

    def test_a_product_never_fetched_is_not_compared(self):
        import db
        with db._lock, db._connect() as conn:
            conn.execute("DELETE FROM cve_feed_state WHERE source = 'nvd:php'")
        self.assertEqual("unmeasured", _assess("PHP/8.3.1")["state"])
        with _enabled():
            self.assertEqual("never", cve_feed.freshness(NOW)["state"], "the data as a whole is not current")

    def test_a_hidden_version_gives_no_finding(self):
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW):
            result = cve_feed.assess_product(PHP, None)
        self.assertEqual("unmeasured", result["state"])
        self.assertIsNone(cve_feed.finding(result))

    def test_switched_off_it_says_nothing_at_all(self):
        with _enabled(enabled=False):
            self.assertIsNone(cve_feed.assess({"x-powered-by": "PHP/8.1.5"}))
            self.assertEqual([], cve_feed.readers())


class FindingTests(unittest.TestCase):
    def setUp(self):
        _clear()
        _load_php()
        _all_synced()

    def test_one_finding_per_product_with_the_worst_score_and_the_exploited_ones(self):
        found = cve_feed.finding(_assess("PHP/8.1.5"))
        self.assertEqual("critical", found["severity"])
        self.assertEqual("PHP/8.1.5: 2 known CVE(s), 1 exploited", found["title"])
        self.assertIn("8.1.30", found["fix"])
        self.assertIn("CVE-2026-10001 (KEV)", found["evidence"])
        self.assertIn(cve_feed.ATTRIBUTION, found["detail"])

    def test_an_exploited_cve_with_a_modest_score_is_at_least_high(self):
        _clear()
        _load_php([_cve("CVE-2026-30001", [_match("php:php", versionEndExcluding="8.1.30")], score=5.0,
                        kev="2026-01-01")])
        _all_synced()
        self.assertEqual("high", cve_feed.finding(_assess("PHP/8.1.5"))["severity"])

    def test_the_scan_reports_it_beside_the_rules(self):
        resp = mock.Mock(headers={"X-Powered-By": "PHP/8.1.5"}, text="<html></html>", history=[],
                         url="https://example.org/")
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW), \
                mock.patch.object(security_checks, "_safe_host", return_value=True), \
                mock.patch.object(security_checks, "_get", return_value=resp):
            info = security_checks.check_info_disclosure("example.org")
            findings = security_checks.audit_findings({"info_disclosure": info})
        self.assertEqual("vulnerable", info["cves"][0]["state"])
        titles = [f["title"] for f in findings]
        self.assertIn("PHP/8.1.5: 2 known CVE(s), 1 exploited", titles)

    def test_switched_off_the_scan_payload_says_not_applicable(self):
        resp = mock.Mock(headers={"X-Powered-By": "PHP/8.1.5"}, text="<html></html>", history=[],
                         url="https://example.org/")
        with _enabled(enabled=False), mock.patch.object(security_checks, "_safe_host", return_value=True), \
                mock.patch.object(security_checks, "_get", return_value=resp):
            info = security_checks.check_info_disclosure("example.org")
        self.assertIsNone(info["cves"])

    def test_a_header_only_the_cve_data_reads_is_kept(self):
        """Drupal names itself in X-Generator, which no rule reads; dropped
        from the response, the version was never seen."""
        resp = mock.Mock(status_code=200, headers={"X-Generator": "Drupal 10.2.3 (https://www.drupal.org)"},
                         history=[], url="https://example.org/", text="")
        with _enabled():
            hops = sa.hops_of(resp, sa.builtin_rules() + cve_feed.readers())
        self.assertIn("x-generator", hops[0]["headers"])


def _sha(body):
    return hashlib.sha512(body).hexdigest().encode()


def _advisory(advisory_id, cves, product="PHP", kans="medium", schade="high", vendor="The PHP Group"):
    return json.dumps({
        "document": {"title": f"Kwetsbaarheden verholpen in {product}",
                     "tracking": {"id": advisory_id, "initial_release_date": "2026-10-20T08:00:00Z",
                                  "current_release_date": "2026-10-21T08:00:00Z"},
                     "notes": [{"category": "general", "title": "Kans", "text": kans},
                               {"category": "general", "title": "Schade", "text": schade},
                               {"category": "description", "title": "Feiten", "text": "Feiten over de fout."}]},
        "product_tree": {"branches": [{"category": "vendor", "name": vendor, "branches": [
            {"category": "product_name", "name": product, "branches": [
                {"category": "product_version_range", "name": "vers:unknown/*"}]}]}]},
        "vulnerabilities": [{"cve": c} for c in cves],
    }).encode()


class NcscTests(unittest.TestCase):
    def setUp(self):
        _clear()

    def _get(self, files):
        def get(url, **kwargs):
            name = url.rsplit("/csaf/v2/", 1)[-1]
            if name not in files:
                return mock.Mock(status_code=404, content=b"")
            return mock.Mock(status_code=200, content=files[name])
        return get

    def _files(self, body, sha=None):
        return {"changes.csv": b'"2026/ncsc-2026-0459.json","2026-10-21T08:00:00+00:00"\n'
                               b'"2024/ncsc-2024-0001.json","2024-01-01T00:00:00+00:00"\n',
                "2026/ncsc-2026-0459.json": body,
                "2026/ncsc-2026-0459.json.sha512": (sha or _sha(body)) + b"  ncsc-2026-0459.json\n"}

    def test_recent_advisories_are_read_checked_and_linked_to_their_cves(self):
        body = _advisory("NCSC-2026-0459", ["CVE-2026-10001"])
        read = ncsc_advisories.sync(get=self._get(self._files(body)), sleep=mock.Mock(), now=NOW)
        self.assertEqual(1, read, "the 2024 advisory is older than the first window and is not read")
        found = ncsc_advisories.for_cves(["CVE-2026-10001"])["CVE-2026-10001"][0]
        self.assertEqual(("NCSC-2026-0459", "medium", "high"), (found["id"], found["kans"], found["schade"]))
        self.assertEqual("https://advisories.ncsc.nl/advisory?id=NCSC-2026-0459", found["url"])

    def test_an_advisory_that_does_not_match_its_hash_is_not_used(self):
        body = _advisory("NCSC-2026-0459", ["CVE-2026-10001"])
        result = ncsc_advisories.sync(get=self._get(self._files(body, sha=b"00" * 64)), sleep=mock.Mock(), now=NOW)
        self.assertIn("SHA-512", result)
        self.assertEqual({}, ncsc_advisories.for_cves(["CVE-2026-10001"]))
        self.assertIsNone(cve_feed._state("ncsc")["cursor"], "a failed advisory is asked again next time")

    def test_an_advisory_about_a_followed_product_is_offered_as_a_rule_to_finish(self):
        body = _advisory("NCSC-2026-0459", ["CVE-2026-10001"])
        ncsc_advisories.sync(get=self._get(self._files(body)), sleep=mock.Mock(), now=NOW)
        candidate = ncsc_advisories.candidates()[0]
        self.assertEqual("PHP", candidate["product"])
        rule = candidate["rule"]
        self.assertEqual("high", rule["severity"])
        with self.assertRaises(sa.RuleError):
            sa.compile_rule(rule)  # no NVD data: the releases with the fix are the admin's to add
        compiled = sa.compile_rule({**rule, "fixed": ["8.1.30"]})
        self.assertEqual(["CVE-2026-10001"], compiled["cves"])
        self.assertTrue(ncsc_advisories.candidates([rule["id"]])[0]["rule_added"])

    def test_an_advisory_about_other_software_is_not_offered(self):
        body = _advisory("NCSC-2026-0459", ["CVE-2026-10001"], product="macOS")
        ncsc_advisories.sync(get=self._get(self._files(body)), sleep=mock.Mock(), now=NOW)
        self.assertEqual([], ncsc_advisories.candidates())

    def _candidate(self, cves, **advisory):
        body = _advisory("NCSC-2026-0459", cves, **advisory)
        ncsc_advisories.sync(get=self._get(self._files(body)), sleep=mock.Mock(), now=NOW)
        return ncsc_advisories.candidates()

    def test_a_rule_started_from_an_advisory_gets_the_releases_with_the_fix_from_the_nvd(self):
        """The advisory names no versions, so "Use as start" gave a rule that
        could not be saved until the admin looked up every release; the NVD
        data already synced has them per branch."""
        _load_php()
        candidate = self._candidate(["CVE-2026-10001", "CVE-2026-10002"])[0]
        rule = candidate["rule"]
        self.assertEqual(["8.2.25", "8.1.30"], rule["fixed"])
        self.assertEqual("8.1.0", rule["introduced"])
        self.assertEqual(["8.2.25", "8.1.30"], candidate["nvd"]["fixed"])
        compiled = sa.compile_rule(rule)
        self.assertEqual(["CVE-2026-10001", "CVE-2026-10002"], compiled["cves"])

    def test_only_the_cves_the_nvd_lists_for_the_product_go_into_the_rule(self):
        """An advisory about a suite names many CVEs of other software; a rule
        about PHP listing them would claim PHP has them."""
        _load_php()
        rule = self._candidate(["CVE-2026-99999", "CVE-2026-10002"])[0]["rule"]
        self.assertEqual(["CVE-2026-10002"], rule["cves"])
        self.assertEqual(["8.1.11"], rule["fixed"])

    def test_a_cve_without_a_fixed_release_is_named_not_guessed(self):
        """An inclusive end says where the flaw is, not which release left it
        behind; a conditional CVE or one without bounds says nothing."""
        _load_php(PHP_RECORDS + [_cve("CVE-2026-10005", [
            _match("php:php", versionStartIncluding="8.0.0", versionEndIncluding="8.0.30")])])
        candidate = self._candidate(["CVE-2026-10002", "CVE-2026-10005"])[0]
        self.assertEqual(["8.1.11"], candidate["rule"]["fixed"])
        self.assertEqual(["CVE-2026-10005"], candidate["nvd"]["without_fix"])
        nothing = cve_feed.fix_releases("php", ["CVE-2026-10003", "CVE-2026-10004"])
        self.assertEqual({"cves": [], "fixed": [], "introduced": "", "without_fix": []}, nothing)

    def test_without_nvd_data_the_advisory_cves_stay_and_the_list_says_so(self):
        candidate = self._candidate(["CVE-2026-10001"])[0]
        self.assertEqual(["CVE-2026-10001"], candidate["rule"]["cves"])
        self.assertEqual(0, candidate["nvd"]["listed"])

    def test_oracle_http_server_is_not_the_apache_http_server(self):
        """An Oracle Fusion Middleware advisory was offered as an Apache rule:
        its product is "HTTP Server", under vendor Oracle."""
        self.assertEqual([], self._candidate(["CVE-2026-10001"], vendor="Oracle", product="HTTP Server"))
        _clear()
        found = self._candidate(["CVE-2026-10001"], vendor="Apache", product="HTTP Server")
        self.assertEqual(["Apache HTTP Server"], [c["product"] for c in found])

    def test_a_cve_finding_names_the_ncsc_advisory(self):
        _load_php()
        _all_synced()
        body = _advisory("NCSC-2026-0459", ["CVE-2026-10001"])
        ncsc_advisories.sync(get=self._get(self._files(body)), sleep=mock.Mock(), now=NOW)
        with _enabled(ncsc=True), mock.patch.object(cve_feed, "_now", return_value=NOW):
            assessments = cve_feed.assess({"x-powered-by": "PHP/8.1.5"})
        found = cve_feed.finding(assessments[0])
        self.assertIn("NCSC-NL: NCSC-2026-0459 (likelihood medium, damage high).", found["detail"])


class PageMarkerTests(unittest.TestCase):
    def test_wordpress_without_a_generator_tag_is_still_compared(self):
        """The CVE data looked only at the generator tag too, so a WordPress
        site that removed it got no word about WordPress at all."""
        _clear()
        page = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
        with _enabled(), mock.patch.object(cve_feed, "_now", return_value=NOW):
            found = cve_feed.assess({}, None, "", "https://example.org/", page)
            without = cve_feed.assess({}, None, "", "https://example.org/")
        self.assertEqual(["wordpress"], [a["key"] for a in found])
        self.assertEqual([], without)


class CandidateListTests(unittest.TestCase):
    def test_the_list_says_which_releases_use_as_start_fills_in(self):
        """Without it the admin could not tell a filled-in rule from an empty one."""
        import pathlib
        js = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "advisories_admin.js").read_text(
            encoding="utf-8")
        self.assertIn("${cfNvdLine(c)}</td>", js)
        self.assertIn("The NVD lists none of these CVEs for", js)


from enterprise_harness import EnterpriseAppTestCase  # noqa: E402


class AdminRouteTests(EnterpriseAppTestCase):
    def setUp(self):
        super().setUp()
        self.login_as("admin")

    def test_the_page_shows_the_state_and_the_nvd_notice(self):
        html = self.client.get("/admin/advisories").get_data(as_text=True)
        self.assertIn('id="cfSection"', html)
        state = self.client.get("/api/admin/cve-feed").get_json()
        self.assertFalse(state["enabled"])
        self.assertEqual("off", state["freshness"]["state"])
        self.assertEqual(cve_feed.ATTRIBUTION, state["attribution"])
        self.assertEqual(len(cve_feed.PRODUCTS), len(state["products"]))

    def test_a_sync_is_refused_while_switched_off(self):
        with mock.patch("threading.Thread") as thread:
            resp = self.client.post("/api/admin/cve-feed/sync")
        self.assertEqual(400, resp.status_code)
        thread.assert_not_called()

    def test_a_sync_starts_in_the_background_and_is_audited(self):
        import audit_log
        with _enabled(), mock.patch("threading.Thread") as thread, \
                mock.patch.object(audit_log, "record") as record:
            resp = self.client.post("/api/admin/cve-feed/sync")
        self.assertEqual(202, resp.status_code)
        thread.return_value.start.assert_called_once()
        record.assert_called_once_with("cve_feed.sync", target_type="settings")

    def test_the_button_also_waits_two_hours(self):
        cve_feed._save_state("nvd:php", attempted_at=datetime.now(timezone.utc).isoformat())
        with _enabled(), mock.patch("threading.Thread") as thread:
            resp = self.client.post("/api/admin/cve-feed/sync")
        self.assertEqual(429, resp.status_code)
        thread.assert_not_called()

    def test_only_an_admin_sees_or_starts_it(self):
        self.login_as("user")
        self.assertIn(self.client.get("/api/admin/cve-feed").status_code, (302, 401, 403))
        self.assertIn(self.client.post("/api/admin/cve-feed/sync").status_code, (302, 401, 403))


class SettingsTests(unittest.TestCase):
    def test_off_until_an_admin_switches_it_on(self):
        from settings import defaults, registry
        self.assertFalse(defaults.DEFAULTS["cve_feed"]["enabled"])
        self.assertIn("cve_feed", registry.ADMIN_SECTIONS)
        self.assertIn("NVD_API_KEY", [i["env"] for i in defaults.OPTIONAL_INTEGRATIONS])


if __name__ == "__main__":
    unittest.main()

"""Links in a mail checked without handing them to anyone.

A link often carries something personal -- a reset token, a customer number,
a session -- and a submission to a reputation service is searchable by its
subscribers, attackers included. These tests pin that a link never leaves
the server except as a SHA-256 to VirusTotal, and only when switched on;
that lookalikes of the organisation's own domains are spotted locally; that
threat lists are searched locally; and that "not known" or "not checked" is
never shown as "clean".
"""

import hashlib
import unittest
from unittest import mock

import link_check
import mail_test
from enterprise_harness import EnterpriseAppTestCase


class _Resp:
    def __init__(self, status=200, json_body=None, text=""):
        self.status_code = status
        self._json = json_body or {}
        self._text = text.encode()

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, size):
        yield self._text


class NormaliseTests(unittest.TestCase):
    def test_case_empty_path_and_fragment_do_not_change_the_hash(self):
        self.assertEqual("https://example.org/", link_check.normalise("HTTPS://Example.ORG#top"))
        self.assertEqual(link_check.url_hash("https://example.org"), link_check.url_hash("https://EXAMPLE.org/"))


class LookalikeTests(unittest.TestCase):
    OWN = {"example.org"}

    def test_imitations_are_spotted(self):
        for host in ("examp1e.org", "example.com", "exampel.org", "example-login.com", "secure.examp1e.net",
                     "xn--mple-43d3a6i.org"):   # "ехаmple" with Cyrillic е, х, а
            self.assertEqual("example.org", link_check.lookalike(host, self.OWN), host)

    def test_the_domain_under_the_same_tld_is_named(self):
        """With example.com and example.org both held, examp1e.org was
        reported as imitating example.com, the one that sorts first."""
        self.assertEqual("example.org", link_check.lookalike("examp1e.org", {"example.com", "example.org"}))

    def test_the_own_domain_and_unrelated_names_are_not(self):
        for host in ("example.org", "www.example.org", "sample.org", "shop.otherbrand.org", "news.net"):
            self.assertIsNone(link_check.lookalike(host, self.OWN), host)


class FeedTests(EnterpriseAppTestCase):
    LIST = "# a comment\nhttps://bad.example.net/login\nhttp://phish.example.com/a?b=1\n"

    def _refresh(self, body=LIST, status=200, sources=("https://lists.example.com/feed.txt",)):
        return link_check.refresh(list(sources), get=lambda url, headers: _Resp(status, text=body))

    def test_before_any_list_is_loaded_nothing_is_checked(self):
        self.assertIsNone(link_check.check_feeds(["https://bad.example.net/login"]))

    def test_listed_host_listed_and_not_listed(self):
        self._refresh()
        found = link_check.check_feeds(["https://bad.example.net/login", "https://bad.example.net/other",
                                        "https://fine.example.org/"])
        self.assertEqual(["listed", "host_listed", "not_listed"], list(found.values()))

    def test_a_failed_download_keeps_the_previous_list_and_says_why(self):
        self._refresh()
        self._refresh(status=500)
        self.assertEqual("listed", link_check.check_feeds(["https://bad.example.net/login"])
                         ["https://bad.example.net/login"])
        with mock.patch.object(link_check, "_settings", return_value={"link_feeds": ["https://lists.example.com/feed.txt"]}):
            self.assertIn("500", link_check.feed_status()[0]["error"])

    def test_only_https_lists_are_fetched_and_a_dropped_list_is_forgotten(self):
        report = link_check.refresh(["http://lists.example.com/feed.txt"], get=lambda u, h: self.fail("fetched"))
        self.assertIn("skipped", report["http://lists.example.com/feed.txt"])
        self._refresh()
        link_check.refresh([], get=lambda u, h: self.fail("fetched"))
        self.assertIsNone(link_check.check_feeds(["https://bad.example.net/login"]))


class UrlhausTests(EnterpriseAppTestCase):
    """The abuse.ch key was set for the OSINT tab, yet using URLhaus for
    links meant finding its download address and typing it in, key and all,
    into a settings field anyone with the settings page could read."""

    KEY = "secret-abusech-key-123"

    def _with_key(self, settings=None):
        return (mock.patch("settings.api_keys.resolve", lambda name, **kw: self.KEY if name == "ABUSECH_AUTH_KEY" else ""),
                mock.patch.object(link_check, "_settings", return_value=settings or {}))

    def test_the_key_already_set_is_enough(self):
        keyed, settings = self._with_key()
        with keyed, settings:
            sources = link_check.configured_sources()
        self.assertEqual([link_check.URLHAUS], [name for name, _ in sources])
        self.assertIn(f"/exports/{self.KEY}/", sources[0][1])

    def test_without_the_key_or_when_switched_off_it_is_not_used(self):
        with mock.patch.object(link_check, "_settings", return_value={}):
            self.assertEqual([], link_check.configured_sources())
        keyed, settings = self._with_key({"urlhaus_list": False})
        with keyed, settings:
            self.assertEqual([], link_check.configured_sources())

    def test_the_key_never_reaches_a_message_or_the_status(self):
        def fail(url, headers):
            raise RuntimeError(f"404 Client Error: Not Found for url: {url}")
        keyed, settings = self._with_key()
        with keyed, settings:
            report = link_check.refresh(get=fail)
            status = link_check.feed_status()
        self.assertNotIn(self.KEY, str(report))
        self.assertNotIn(self.KEY, str(status))
        self.assertIn(link_check.URLHAUS, status[0]["error"])

    def test_a_zipped_export_is_read(self):
        import io
        import zipfile
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("recent.csv", '"id","dateadded","url"\n"1","2026-10-06","https://bad.example.net/x"\n')
        link_check.refresh([("zipped", "https://lists.example.com/recent.zip")],
                           get=lambda url, headers: _ZipResp(buffer.getvalue()))
        self.assertEqual("listed", link_check.check_feeds(["https://bad.example.net/x"])["https://bad.example.net/x"])


class _ZipResp(_Resp):
    def __init__(self, body):
        super().__init__(200)
        self._text = body


class VirusTotalTests(EnterpriseAppTestCase):
    URL = "https://login.example.net/reset?token=SECRET-123"

    def _get(self, responses):
        self.asked = []

        def get(url, headers):
            self.asked.append(url)
            return responses.pop(0)
        return get

    def test_only_the_hash_is_sent_never_the_link(self):
        get = self._get([_Resp(404)])
        result = link_check.check_virustotal([self.URL], get=get, key="k", limit=4)
        digest = hashlib.sha256(link_check.normalise(self.URL).encode()).hexdigest()
        self.assertEqual([f"https://www.virustotal.com/api/v3/urls/{digest}"], self.asked)
        self.assertNotIn("SECRET-123", self.asked[0])
        self.assertNotIn("login.example.net", self.asked[0])
        self.assertEqual("unknown", result[self.URL]["state"])

    def test_detections_are_counted(self):
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 50, "undetected": 20}}}}
        result = link_check.check_virustotal([self.URL], get=self._get([_Resp(200, body)]), key="k", limit=4)
        self.assertEqual(("malicious", 3, 74), (result[self.URL]["state"], result[self.URL]["malicious"],
                                               result[self.URL]["engines"]))

    def test_the_rate_limit_stops_the_round_and_is_not_a_verdict(self):
        urls = [f"https://a{i}.example.net/" for i in range(3)]
        result = link_check.check_virustotal(urls, get=self._get([_Resp(429)]), key="k", limit=4)
        self.assertEqual(1, len(self.asked))
        self.assertEqual({"unmeasured"}, {r["state"] for r in result.values()})

    def test_over_the_limit_is_not_checked_and_a_known_answer_is_reused(self):
        urls = [f"https://b{i}.example.net/" for i in range(3)]
        result = link_check.check_virustotal(urls, get=self._get([_Resp(404), _Resp(404)]), key="k", limit=2)
        self.assertEqual(["unknown", "unknown", "not_checked"], [r["state"] for r in result.values()])
        link_check.check_virustotal(urls[:1], get=self._get([]), key="k", limit=2)
        self.assertEqual([], self.asked)

    def test_it_is_off_until_an_admin_switches_it_on(self):
        self.assertEqual("off", link_check.virustotal_state())


class _Lookups(mail_test.Lookups):
    def __init__(self, own=(), checks=None):
        self.own, self.checks = set(own), checks

    def txt(self, name):
        return []

    def spf(self, ip, mail_from, helo):
        return ("pass", "")

    def ptr(self, ip):
        return []

    def addresses(self, host):
        return []

    def own_domains(self):
        return self.own

    def check_links(self, urls):
        return self.checks(urls) if self.checks else super().check_links(urls)


def _mail(sender="news@example.org", html='<p>Read <a href="https://www.example.org/a">here</a> please.</p>'):
    return (f"From: {sender}\r\nTo: x@example.net\r\nSubject: s\r\nDate: Mon, 5 Oct 2026 10:00:00 +0000\r\n"
            f"Message-ID: <1@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n{html}\r\n").encode()


def _titles(result):
    return [f["title"] for f in result["findings"]]


class MailTestLinkTests(unittest.TestCase):
    def test_a_sender_imitating_an_own_domain_is_named(self):
        result = mail_test.analyse(_mail(sender="ceo@examp1e.org"), lookups=_Lookups(own={"example.org"}))
        self.assertIn("The sender's domain looks like your own", _titles(result))

    def test_a_link_to_a_lookalike_is_named(self):
        html = '<p>Log in <a href="https://example-login.com/x">here</a> today.</p>'
        result = mail_test.analyse(_mail(html=html), lookups=_Lookups(own={"example.org"}))
        self.assertIn("A link goes to a lookalike of your domain", _titles(result))

    def test_without_lists_or_virustotal_links_are_not_checked_rather_than_clean(self):
        result = mail_test.analyse(_mail(), lookups=_Lookups())
        link = result["content"]["links"][0]
        self.assertEqual(("not_checked", "not_checked"), (link["feed"], link["virustotal"]["state"]))
        self.assertEqual("not_configured", result["link_checks"]["feeds"])

    def test_listed_and_flagged_links_are_findings(self):
        def checks(urls):
            return {"feeds": {u: "listed" for u in urls},
                    "virustotal": {"state": "on", "results": {u: {"state": "malicious", "malicious": 5, "engines": 90} for u in urls}}}
        result = mail_test.analyse(_mail(), lookups=_Lookups(checks=checks))
        self.assertIn("A link is on a threat list", _titles(result))
        self.assertIn("VirusTotal engines flag a link as malicious", _titles(result))


class RouteTests(EnterpriseAppTestCase):
    def test_the_page_can_say_how_links_are_checked(self):
        self.login_as("user")
        data = self.client.get("/api/mailtest/checks").get_json()
        self.assertEqual(("off", []), (data["virustotal"], data["feeds"]))

    def test_only_an_admin_refreshes_the_lists(self):
        self.login_as("user")
        self.assertEqual(403, self.client.post("/api/mailtest/feeds/refresh").status_code)
        self.login_as("admin")
        self.assertEqual(400, self.client.post("/api/mailtest/feeds/refresh").status_code)


if __name__ == "__main__":
    unittest.main()

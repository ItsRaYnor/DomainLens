"""A monitor is a scheduled scan that also watches one DNS record.

It was presented as an A-record monitor: named "example.com (A)" by default,
listed as "example.com · A · daily · all checks", with the record type in the
first row of the form. Each run is a full scan of mail, web, TLS and DNS as
chosen; the record type only picks the one record compared for changes.
"""

import pathlib
import re

from enterprise_harness import EnterpriseAppTestCase

ROOT = pathlib.Path(__file__).resolve().parent.parent


class MonitorWordingTests(EnterpriseAppTestCase):
    def test_a_new_monitor_is_named_after_its_host(self):
        self.login_as("user")
        resp = self.client.post("/api/monitors", json={"domain": "example.com", "record_type": "A"})
        self.assertEqual("example.com", resp.get_json()["monitor"]["name"])

    def test_the_form_asks_what_runs_before_which_record_is_watched(self):
        form = ROOT.joinpath("templates", "partials", "_monitoring_block.html").read_text(encoding="utf-8")
        self.assertLess(form.index('id="monitorChecksAll"'), form.index('id="monitorTypeInput"'))
        self.assertIn("Also watch one DNS record for changes", form)

    def test_the_list_says_full_scan_and_which_record_it_watches(self):
        js = ROOT.joinpath("static", "js", "app.js").read_text(encoding="utf-8")
        render = js[js.index("function renderMonitorList"):]
        render = render[:render.index("\n}\n")]
        self.assertIn("watches ${escapeHtml(m.record_type || 'A')} record", render)
        self.assertRegex(js, re.compile(r"includes\('all'\)\) return 'full scan'"))

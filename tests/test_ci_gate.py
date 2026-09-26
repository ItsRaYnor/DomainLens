"""A pipeline can refuse to ship when a domain has open high findings.

With tokens, the API could be scripted, but every team would have written
its own poll loop and its own idea of what "fails" means -- including
treating "could not reach DomainLens" as a pass.
"""

import importlib.util
import io
import os
from unittest import mock

from enterprise_harness import EnterpriseAppTestCase

_spec = importlib.util.spec_from_file_location(
    "ci_gate", os.path.join(os.path.dirname(__file__), "..", "scripts", "ci_gate.py"))
ci_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_gate)

_SPF_MISSING = {"apex_domain": "example.com",
                "spf": {"success": True, "found": False, "measured": True}}


class GateDecisionTests(EnterpriseAppTestCase):
    def _run(self, fail_on="high", results=_SPF_MISSING):
        import api_tokens
        raw, _ = api_tokens.create(self.db.get_user(self.users["user"]), name="ci")

        def call(base, token, method, path, body=None, timeout=60):
            resp = self.client.open(path, method=method, json=body,
                                    headers={"Authorization": f"Bearer {token}"})
            return resp.status_code, resp.get_json() or {}

        out = io.StringIO()
        with mock.patch.object(ci_gate, "_call", side_effect=call), \
             mock.patch.object(self.app_module, "run_selected_checks", return_value=dict(results)):
            code = ci_gate.run("example.com", base="http://dl", token=raw, fail_on=fail_on,
                               checks=["spf"], timeout=30, poll=0.05, out=out)
        return code, out.getvalue()

    def test_an_open_high_finding_fails_the_pipeline(self):
        code, output = self._run("high")
        self.assertEqual(1, code)
        self.assertIn("SPF record missing", output)

    def test_below_the_threshold_passes(self):
        code, _ = self._run("critical")
        self.assertEqual(0, code)

    def test_an_accepted_risk_does_not_fail_it(self):
        import recommendations
        import risk_acceptance
        from datetime import date, timedelta
        rec = next(r for r in recommendations.generate({"domain": "example.com", **_SPF_MISSING})
                   if r["title"] == "SPF record missing")
        risk_acceptance.create(domain="example.com", finding_key=rec["finding_key"],
                               title=rec["title"], severity=rec["severity"], reason="known",
                               owner="CISO", created_by="admin@example.com",
                               expires_on=(date.today() + timedelta(days=30)).isoformat())
        code, output = self._run("high")
        self.assertEqual(0, code)
        self.assertIn("1 accepted risk(s) not counted", output)

    def test_an_unreachable_or_refusing_server_is_not_a_pass(self):
        """Exit 2, not 0: the gate did not look, so it cannot say 'clean'."""
        out = io.StringIO()
        with mock.patch.object(ci_gate, "_call", return_value=(401, {"error": "bad token"})):
            code = ci_gate.run("example.com", base="http://dl", token="dlk_x", fail_on="high",
                               checks=["all"], timeout=5, out=out)
        self.assertEqual(2, code)

"""Registration data for a list of domains, without getting blocked.

Registries throttle an address that asks too fast, and a blocked registry
is blocked for every lookup this installation makes afterwards -- scans
included. A batch is paced per registry server, honours a 429, and never
reports a lookup it could not make as "not registered".
"""

import time
import unittest
from unittest import mock

import whois_batch
from enterprise_harness import EnterpriseAppTestCase


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(seconds, 3))
        self.now += seconds


class ParseTests(unittest.TestCase):
    def test_a_pasted_list_and_a_csv_give_the_same_domains(self):
        text = ("domain,owner\nhttps://www.Example.nl/pad,team a\n"
                "example.com; example.org\nexample.com\nbad..example")
        domains, rejected = whois_batch.parse_domains(text)
        self.assertEqual(["example.nl", "example.com", "example.org"], domains)
        # Headers and other columns are skipped quietly; a broken name is not.
        self.assertEqual(["bad..example"], rejected)

    def test_more_than_the_cap_is_refused_not_truncated(self):
        """Silently dropping the tail would look like those had no data."""
        with self.assertRaises(ValueError):
            whois_batch.start([f"d{i}.example" for i in range(whois_batch.MAX_DOMAINS + 1)])


class PacingTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeClock()
        self.pacer = whois_batch._Pacer(interval=2.0, clock=self.fake.clock, sleep=self.fake.sleep)

    def test_one_registry_is_asked_at_most_once_per_interval(self):
        for _ in range(3):
            self.pacer.wait("https://rdap.example-registry/")
        self.assertEqual([2.0, 2.0], self.fake.slept)

    def test_different_registries_do_not_wait_for_each_other(self):
        self.pacer.wait("https://rdap.one/")
        self.pacer.wait("https://rdap.two/")
        self.assertEqual([], self.fake.slept)

    def test_a_429_is_honoured_and_then_retried_once(self):
        answers = iter([{"success": False, "state": "unmeasured", "retry_after": 30},
                        {"success": True, "source": "rdap"}])
        with mock.patch.object(whois_batch.rdap, "server_for", return_value="https://rdap.one/"):
            result = whois_batch.lookup_paced("example.nl", pacer=self.pacer,
                                              fetch=lambda d: next(answers))
        self.assertTrue(result["success"])
        self.assertIn(30.0, self.fake.slept)

    def test_a_throttled_registry_is_not_asked_again_over_port_43(self):
        """Port 43 is the same registry, and stricter than RDAP."""
        text = mock.Mock()
        throttled = {"success": False, "state": "unmeasured", "retry_after": 1}
        with mock.patch.object(whois_batch.rdap, "server_for", return_value="https://rdap.one/"):
            whois_batch.lookup_paced("example.nl", pacer=self.pacer,
                                     fetch=lambda d: throttled, text_lookup=text)
        text.assert_not_called()

    def test_a_registry_without_rdap_falls_back_to_whois(self):
        text = mock.Mock(return_value={"success": True, "data": {"registrar": "Example Registrar"}})
        with mock.patch.object(whois_batch.rdap, "server_for", return_value=None):
            result = whois_batch.lookup_paced(
                "example.zz", pacer=self.pacer,
                fetch=lambda d: {"success": False, "state": "not_applicable"}, text_lookup=text)
        self.assertEqual("Example Registrar", result["registrar"]["name"])


class RowTests(unittest.TestCase):
    def test_a_failed_lookup_is_not_measured_rather_than_not_registered(self):
        row = whois_batch._row("example.nl", {"success": False, "state": "unmeasured",
                                              "error": "timeout"})
        self.assertEqual("unmeasured", row["state"])

    def test_an_unregistered_domain_is_a_measured_answer(self):
        row = whois_batch._row("example.nl", {"success": False, "registered": False})
        self.assertEqual("not_registered", row["state"])

    def test_the_csv_cannot_carry_a_formula(self):
        job = whois_batch.start(["example.nl"], runner=lambda fn: None)
        whois_batch._jobs[job["id"]]["rows"].append(
            whois_batch._row("example.nl", {"success": True, "registrar": {"name": "=HYPERLINK(1)"}}))
        self.assertIn("'=HYPERLINK(1)", whois_batch.to_csv(job["id"]))


class BatchApiTests(EnterpriseAppTestCase):
    def _wait(self, job_id):
        for _ in range(100):
            job = self.client.get(f"/api/whois/batch/{job_id}").get_json()
            if job["status"] != "running":
                return job
            time.sleep(0.02)
        self.fail("batch did not finish")

    def test_an_analyst_runs_a_batch_and_downloads_it(self):
        self.login_as("user")
        with mock.patch.object(whois_batch, "lookup_paced",
                               return_value={"success": True, "source": "rdap",
                                             "registrar": {"name": "Example Registrar"}}):
            resp = self.client.post("/api/whois/batch", json={"text": "example.nl\nexample.com"})
            self.assertEqual(202, resp.status_code)
            job = self._wait(resp.get_json()["id"])
        self.assertEqual(["example.nl", "example.com"], [r["domain"] for r in job["rows"]])
        csv_body = self.client.get(f"/api/whois/batch/{job['id']}/csv").get_data(as_text=True)
        self.assertIn("Example Registrar", csv_body)

    def test_a_viewer_cannot_start_one(self):
        self.login_as("viewer")
        self.assertEqual(403, self.client.post("/api/whois/batch", json={"text": "example.nl"}).status_code)

    def test_input_without_a_domain_is_refused(self):
        self.login_as("user")
        self.assertEqual(400, self.client.post("/api/whois/batch", json={"text": "hello"}).status_code)


if __name__ == "__main__":
    unittest.main()

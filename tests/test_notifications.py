"""Monitor alerts reach the channels an organisation actually watches.

ServiceNow was the only outbound channel. Without it, a regression found by
the scheduler at night sat on the Monitoring page until someone opened it.
"""

import hashlib
import hmac
import json
import unittest
from unittest import mock

import notifications


def _cfg(**overrides):
    base = {
        "enabled": True, "min_severity": "high", "send_digest": False,
        "webhook_url": "", "webhook_secret": "", "slack_url": "", "teams_url": "",
        "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls", "smtp_from": "",
        "smtp_user": "", "smtp_password": "", "email_to": [],
    }
    base.update(overrides)
    return base


class _Resp:
    def __init__(self, status=200):
        self.status_code = status


class FilterTests(unittest.TestCase):
    def test_a_regression_at_the_threshold_is_sent(self):
        self.assertTrue(notifications.should_notify(
            {"event_type": "regression", "severity": "high"}, _cfg()))

    def test_below_the_threshold_is_not(self):
        self.assertFalse(notifications.should_notify(
            {"event_type": "change", "severity": "medium"}, _cfg()))

    def test_nothing_changed_is_never_an_alert(self):
        """A channel that fires on every unchanged scan gets muted, and then
        the real alert is missed too."""
        self.assertFalse(notifications.should_notify(
            {"event_type": "scan_unchanged", "severity": "critical"}, _cfg()))

    def test_switched_off_sends_nothing(self):
        self.assertFalse(notifications.should_notify(
            {"event_type": "regression", "severity": "critical"}, _cfg(enabled=False)))


class ChannelTests(unittest.TestCase):
    MESSAGE = {"event_type": "regression", "severity": "high", "summary": "TLS got worse",
               "target": "example.com", "url": "https://dl.example/report/7", "scan_id": 7}

    def test_the_generic_webhook_is_signed(self):
        """So the receiver can tell a real alert from someone who found the URL."""
        cfg = _cfg(webhook_url="https://hooks.example/in", webhook_secret="s3cret")
        with mock.patch.object(notifications.requests, "post", return_value=_Resp()) as post:
            notifications.send_webhook(cfg, self.MESSAGE)
        body = post.call_args.kwargs["data"]
        expected = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        self.assertEqual(f"sha256={expected}", post.call_args.kwargs["headers"]["X-DomainLens-Signature"])

    def test_a_plain_http_webhook_is_refused(self):
        """An alert names what is weak about the organisation's domains."""
        with self.assertRaises(ValueError):
            notifications.send_webhook(_cfg(webhook_url="http://hooks.example/in"), self.MESSAGE)

    def test_teams_gets_an_adaptive_card(self):
        """Office 365 connector MessageCards were retired; Workflows webhooks
        reject them."""
        with mock.patch.object(notifications.requests, "post", return_value=_Resp()) as post:
            notifications.send_teams(_cfg(teams_url="https://teams.example/wf"), self.MESSAGE)
        payload = json.loads(post.call_args.kwargs["data"])
        attachment = payload["attachments"][0]
        self.assertEqual("application/vnd.microsoft.card.adaptive", attachment["contentType"])
        self.assertEqual("AdaptiveCard", attachment["content"]["type"])

    def test_slack_carries_the_link(self):
        with mock.patch.object(notifications.requests, "post", return_value=_Resp()) as post:
            notifications.send_slack(_cfg(slack_url="https://hooks.slack.example/x"), self.MESSAGE)
        self.assertIn("https://dl.example/report/7", post.call_args.kwargs["data"].decode())

    def test_email_uses_starttls_and_logs_in(self):
        cfg = _cfg(smtp_host="smtp.example", smtp_from="dl@example.com",
                   email_to=["soc@example.com"], smtp_user="u", smtp_password="p")
        with mock.patch.object(notifications.smtplib, "SMTP") as smtp:
            notifications.send_email(cfg, self.MESSAGE)
        server = smtp.return_value
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("u", "p")
        server.send_message.assert_called_once()

    def test_one_failing_channel_does_not_stop_the_others(self):
        cfg = _cfg(slack_url="https://hooks.slack.example/x", teams_url="https://teams.example/wf")
        responses = [_Resp(500), _Resp(200)]
        with mock.patch.object(notifications, "config", return_value=cfg), \
             mock.patch.object(notifications.requests, "post", side_effect=responses):
            results = notifications.dispatch({"event_type": "regression", "severity": "critical",
                                              "summary": "x"}, {"target": "example.com"})
        self.assertFalse(results["slack"]["ok"])
        self.assertTrue(results["teams"]["ok"])

    def test_a_crash_never_reaches_the_scan(self):
        with mock.patch.object(notifications, "config", side_effect=RuntimeError("boom")):
            self.assertIsNone(notifications.dispatch({"severity": "critical"}, {}))


class MonitorWiringTests(unittest.TestCase):
    def test_a_monitor_event_is_dispatched_with_its_scan(self):
        import os
        import tempfile
        import importlib
        tempdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tempdir.cleanup)
        saved = os.environ.get("DOMAINLENS_DB")
        self.addCleanup(lambda: os.environ.__setitem__("DOMAINLENS_DB", saved) if saved
                        else os.environ.pop("DOMAINLENS_DB", None))
        os.environ["DOMAINLENS_DB"] = os.path.join(tempdir.name, "n.db")
        os.environ["DOMAINLENS_DISABLE_SCHEDULER"] = "1"
        import db
        importlib.reload(db).init_db()
        import app
        app = importlib.reload(app)
        with mock.patch.object(app.notifications, "dispatch", return_value={"slack": {"ok": True}}) as dispatch, \
             mock.patch.object(app.servicenow, "create_incident", return_value=None):
            app._notify_event(1, {"event_type": "regression", "severity": "high"},
                              {"target": "example.com"}, scan_id=42)
        self.assertEqual(42, dispatch.call_args.kwargs["scan_id"])

    def test_the_digest_goes_out_when_asked(self):
        cfg = _cfg(send_digest=True, slack_url="https://hooks.slack.example/x")
        with mock.patch.object(notifications, "config", return_value=cfg), \
             mock.patch.object(notifications.requests, "post", return_value=_Resp()) as post:
            notifications.send_digest({"window_days": 7, "overview": {"scans": 12, "domains": 3},
                                       "monitors": {"enabled_monitors": 4}})
        self.assertIn("12 scans", post.call_args.kwargs["data"].decode())


if __name__ == "__main__":
    unittest.main()

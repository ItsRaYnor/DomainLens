"""Monitor alerts to where people already look: webhook, Slack, Teams, email.

ServiceNow was the only outbound channel, and most organisations that would
run this do not have ServiceNow. A regression found at 03:00 then sat in the
Monitoring page until someone happened to open it.

Every channel is optional and independent: one failing (a rotated Slack URL,
an SMTP outage) is logged and reported for that channel, and never stops the
others or the scan that raised the event. The digest the scheduler has
always computed, and until now kept to itself, goes out the same way.

Webhook URLs for Slack and Teams embed their own secret, so they are managed
credentials (encrypted, write-only in the UI), not plain settings. The
generic webhook is signed with HMAC-SHA256 when a secret is set, so the
receiver can tell a real alert from someone who found the URL.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage

import requests

log = logging.getLogger("domainlens.notifications")

_TIMEOUT = 10
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Routine outcomes: a first baseline and "nothing changed" are not alerts.
QUIET_EVENT_TYPES = {"scan_unchanged", "baseline_created"}

CHANNELS = ("webhook", "slack", "teams", "email")


def _secret(name):
    try:
        from settings import api_keys
        return api_keys.resolve(name)
    except Exception:
        return ""


def config():
    try:
        from settings.store import get_store
        raw = dict(get_store().section("notifications", force_reload=True))
    except Exception:
        raw = {}
    min_severity = str(raw.get("min_severity") or "high").lower()
    if min_severity not in _SEVERITY_RANK:
        min_severity = "high"
    recipients = [str(r).strip() for r in (raw.get("email_to") or []) if str(r).strip()]
    return {
        "enabled": bool(raw.get("enabled", False)),
        "min_severity": min_severity,
        "send_digest": bool(raw.get("send_digest", False)),
        "webhook_url": _secret("NOTIFY_WEBHOOK_URL"),
        "webhook_secret": _secret("NOTIFY_WEBHOOK_SECRET"),
        "slack_url": _secret("NOTIFY_SLACK_WEBHOOK_URL"),
        "teams_url": _secret("NOTIFY_TEAMS_WEBHOOK_URL"),
        "smtp_host": str(raw.get("smtp_host") or "").strip(),
        "smtp_port": int(raw.get("smtp_port") or 587),
        "smtp_security": str(raw.get("smtp_security") or "starttls").lower(),
        "smtp_from": str(raw.get("smtp_from") or "").strip(),
        "smtp_user": _secret("SMTP_USERNAME"),
        "smtp_password": _secret("SMTP_PASSWORD"),
        "email_to": recipients,
    }


def configured_channels(cfg=None):
    cfg = cfg or config()
    out = []
    if cfg["webhook_url"]:
        out.append("webhook")
    if cfg["slack_url"]:
        out.append("slack")
    if cfg["teams_url"]:
        out.append("teams")
    if cfg["smtp_host"] and cfg["smtp_from"] and cfg["email_to"]:
        out.append("email")
    return out


def should_notify(event, cfg):
    if not cfg["enabled"]:
        return False
    if event.get("event_type") in QUIET_EVENT_TYPES:
        return False
    severity = str(event.get("severity") or "info").lower()
    return _SEVERITY_RANK.get(severity, 4) <= _SEVERITY_RANK[cfg["min_severity"]]


def _public_url():
    try:
        import config as domainlens_config
        return str(domainlens_config.load_settings().general().get("public_url") or "").rstrip("/")
    except Exception:
        return ""


def build_message(event, monitor, scan_id=None):
    """One channel-neutral description of the alert."""
    base = _public_url()
    link = None
    if base:
        link = f"{base}/report/{scan_id}" if scan_id else f"{base}/monitoring"
    target = (monitor or {}).get("target") or (event.get("details") or {}).get("target")
    return {
        "source": "domainlens",
        "event_type": event.get("event_type"),
        "severity": str(event.get("severity") or "info").lower(),
        "summary": event.get("summary") or "DomainLens monitor alert",
        "target": target,
        "monitor": {"id": (monitor or {}).get("id"), "name": (monitor or {}).get("name")},
        "scan_id": scan_id,
        "url": link,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _post_json(url, payload, headers=None):
    if not url.lower().startswith("https://"):
        raise ValueError("Webhook URLs must use https://")
    body = json.dumps(payload).encode("utf-8")
    resp = requests.post(url, data=body, timeout=_TIMEOUT,
                         headers={"Content-Type": "application/json", **(headers or {})})
    if resp.status_code >= 300:
        raise RuntimeError(f"HTTP {resp.status_code}")
    return body


def send_webhook(cfg, message):
    body = json.dumps(message).encode("utf-8")
    headers = {"X-DomainLens-Event": str(message.get("event_type") or "")}
    if cfg["webhook_secret"]:
        digest = hmac.new(cfg["webhook_secret"].encode("utf-8"), body, hashlib.sha256).hexdigest()
        headers["X-DomainLens-Signature"] = f"sha256={digest}"
    if not cfg["webhook_url"].lower().startswith("https://"):
        raise ValueError("Webhook URLs must use https://")
    resp = requests.post(cfg["webhook_url"], data=body, timeout=_TIMEOUT,
                         headers={"Content-Type": "application/json", **headers})
    if resp.status_code >= 300:
        raise RuntimeError(f"HTTP {resp.status_code}")


def _headline(message):
    return f"[{message['severity'].upper()}] {message['summary']}"


def send_slack(cfg, message):
    lines = [f"*{_headline(message)}*"]
    if message.get("target"):
        lines.append(f"Target: `{message['target']}`")
    if message.get("url"):
        lines.append(f"<{message['url']}|Open in DomainLens>")
    _post_json(cfg["slack_url"], {
        "text": _headline(message),
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}],
    })


def send_teams(cfg, message):
    """An Adaptive Card, which is what Teams Workflows webhooks accept.

    The older Office 365 connector MessageCard format was retired by
    Microsoft; Workflows ("Post to a channel when a webhook request is
    received") takes this shape.
    """
    facts = [{"title": "Severity", "value": message["severity"]}]
    if message.get("target"):
        facts.append({"title": "Target", "value": message["target"]})
    if message.get("event_type"):
        facts.append({"title": "Event", "value": message["event_type"]})
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "text": _headline(message), "weight": "Bolder", "wrap": True},
            {"type": "FactSet", "facts": facts},
        ],
    }
    if message.get("url"):
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in DomainLens",
                            "url": message["url"]}]
    _post_json(cfg["teams_url"], {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                         "content": card}],
    })


def send_email(cfg, message, subject=None, body=None):
    mail = EmailMessage()
    mail["Subject"] = subject or f"DomainLens: {_headline(message)}"
    mail["From"] = cfg["smtp_from"]
    mail["To"] = ", ".join(cfg["email_to"])
    if body is None:
        body = "\n".join(filter(None, [
            _headline(message),
            f"Target: {message['target']}" if message.get("target") else None,
            f"Event: {message['event_type']}" if message.get("event_type") else None,
            f"Details: {message['url']}" if message.get("url") else None,
            "",
            "Sent by DomainLens monitoring.",
        ]))
    mail.set_content(body)
    context = ssl.create_default_context()
    if cfg["smtp_security"] == "ssl":
        server = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=_TIMEOUT)
    with server:
        if cfg["smtp_security"] == "starttls":
            server.starttls(context=context)
        if cfg["smtp_user"]:
            server.login(cfg["smtp_user"], cfg["smtp_password"])
        server.send_message(mail)


_SENDERS = {"webhook": send_webhook, "slack": send_slack, "teams": send_teams, "email": send_email}


def _deliver(cfg, message, channels=None):
    results = {}
    for channel in channels or configured_channels(cfg):
        try:
            _SENDERS[channel](cfg, message)
            results[channel] = {"ok": True}
        except Exception as exc:
            # The channel's failure is the channel's: logged, reported, and
            # never allowed to stop the next one.
            log.warning("Notification via %s failed: %s", channel, exc)
            results[channel] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
    return results


def dispatch(event, monitor, scan_id=None):
    """Send a monitor event to every configured channel, if it qualifies."""
    try:
        cfg = config()
        if not should_notify(event, cfg):
            return None
        return _deliver(cfg, build_message(event, monitor, scan_id))
    except Exception:
        log.exception("Notification dispatch failed")
        return None


def send_digest(digest):
    """Deliver the scheduler's periodic summary, when asked to."""
    try:
        cfg = config()
        if not (cfg["enabled"] and cfg["send_digest"] and digest):
            return None
        overview = digest.get("overview") or {}
        monitors = digest.get("monitors") or {}
        severities = overview.get("events_by_severity") or {}
        summary = (f"Last {digest.get('window_days', 7)} days: {overview.get('scans', 0)} scans "
                   f"of {overview.get('domains', 0)} domains, "
                   f"{severities.get('critical', 0)} critical and {severities.get('high', 0)} high "
                   f"monitor events, {monitors.get('enabled_monitors', 0)} active monitors")
        message = {**build_message({"event_type": "digest", "severity": "info",
                                    "summary": summary}, None),
                   "digest": digest}
        return _deliver(cfg, message)
    except Exception:
        log.exception("Digest delivery failed")
        return None


def send_test():
    """A clearly labelled test message to every configured channel."""
    cfg = config()
    channels = configured_channels(cfg)
    if not channels:
        return {"ok": False, "detail": "No channel is configured yet."}
    message = build_message({"event_type": "test", "severity": "info",
                             "summary": "Test notification from DomainLens"}, None)
    results = _deliver(cfg, message, channels)
    failed = {c: r["error"] for c, r in results.items() if not r["ok"]}
    if failed:
        return {"ok": False, "detail": "; ".join(f"{c}: {e}" for c, e in failed.items())}
    return {"ok": True, "detail": "Delivered to " + ", ".join(results)}

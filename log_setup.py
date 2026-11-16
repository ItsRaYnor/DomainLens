"""Logging that a log collector can read, and a request id to follow a request by.

Plain text lines are fine on a terminal and useless in a SIEM: a multi-line
traceback becomes a dozen unrelated events, and nothing ties the warning a
scan logged to the request that started it. With DOMAINLENS_LOG_FORMAT=json
each record is one JSON object on one line, traceback included.

Every request gets an id: the caller's X-Request-ID when a proxy in front sets
one (so its access log and ours line up), otherwise a fresh one. It is sent
back in the response header and put on every log record written while the
request runs, in both formats.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _current_request_id():
    try:
        from flask import g, has_request_context
        if has_request_context():
            return g.get("request_id")
    except Exception:
        pass
    return None


class _RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = _current_request_id() or "-"
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", "-")
        if request_id and request_id != "-":
            entry["request_id"] = request_id
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            entry["stack"] = self.formatStack(record.stack_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


_TEXT_FORMAT = "%(asctime)s %(levelname)s [%(name)s] [%(request_id)s] %(message)s"


def configure(level="INFO", fmt="text"):
    """Install one handler on the root logger, replacing any set before."""
    handler = logging.StreamHandler()
    handler.addFilter(_RequestIdFilter())
    if str(fmt).strip().lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(_TEXT_FORMAT))
    root = logging.getLogger()
    for old in list(root.handlers):
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(str(level or "INFO").upper())
    return handler


def install_request_id(app):
    from flask import g, request

    @app.before_request
    def _assign_request_id():
        given = request.headers.get("X-Request-ID", "")
        # Only a well-formed id is taken over: it ends up in every log line,
        # and a header is attacker-controlled text.
        g.request_id = given if _REQUEST_ID.match(given) else uuid.uuid4().hex

    @app.after_request
    def _return_request_id(response):
        request_id = g.get("request_id")
        if request_id:
            response.headers["X-Request-ID"] = request_id
        return response

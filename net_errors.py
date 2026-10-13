"""Short, readable words for an outbound request that failed.

A lookup that could not reach its source showed the exception itself:
"HTTPSConnectionPool(host='web.archive.org', port=443): Max retries exceeded
with url: /cdx/search/cdx?... (Caused by NameResolutionError(...))". That says
nothing an operator can act on, and hides the one thing that matters: the
source was not reached, so nothing was measured -- and when DNS on this
server is the reason, every other third-party source fails the same way.
"""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

import requests

DNS = "dns"
TIMEOUT = "timeout"
TLS = "tls"
CONNECT = "connect"
HTTP = "http"
RATE_LIMIT = "rate_limit"
OTHER = "other"

# Every message for a failure that may pass by itself ends with this, so a
# cache can tell "try again" from "this will not change" without the exception.
AGAIN = "Not measured; try again later."

# getaddrinfo's "try again" (EAI_AGAIN; WSATRY_AGAIN 11002 on Windows): the
# resolver did not answer, as opposed to answering that the name does not exist.
_TEMPORARY = ("temporary failure in name resolution", "eai_again", "[errno 11002]", "try again")
_RESOLUTION = ("nameresolutionerror", "failed to resolve", "name or service not known",
               "nodename nor servname", "getaddrinfo failed", "no address associated",
               "name resolution", "[errno 11001]")


def _host(exc, default=None):
    request = getattr(exc, "request", None)
    url = getattr(request, "url", None)
    if url:
        return urlparse(url).hostname or default
    match = re.search(r"host='([^']+)'", str(exc))
    return match.group(1) if match else default


def classify(exc, host=None):
    """(kind, message) for a failed outbound request or lookup."""
    text = str(exc).lower()
    name = _host(exc, host) or "the source"
    if isinstance(exc, socket.gaierror) or any(k in text for k in _RESOLUTION):
        if any(k in text for k in _TEMPORARY):
            return DNS, f"This server could not look up {name}: its DNS did not answer. {AGAIN}"
        return DNS, f"This server could not find {name} in DNS. Not measured."
    if isinstance(exc, requests.Timeout) or isinstance(exc, socket.timeout) or "timed out" in text:
        return TIMEOUT, f"{name} did not answer in time. {AGAIN}"
    if isinstance(exc, requests.exceptions.SSLError) or "ssl" in text and "certificate" in text:
        return TLS, f"The secure connection to {name} failed. Not measured."
    if isinstance(exc, requests.HTTPError):
        # Before the connection errors: an HTTPError is an OSError too, and a
        # refused key read as "could not connect".
        response = getattr(exc, "response", None)
        if response is not None:
            return http_status(response.status_code, name)
        code = re.match(r"\s*(\d{3})\b", str(exc))
        if code:
            return http_status(int(code.group(1)), name)
        return HTTP, f"{name} answered with an error. Not measured."
    if isinstance(exc, (requests.ConnectionError, ConnectionError, OSError)):
        return CONNECT, f"Could not connect to {name}. {AGAIN}"
    detail = str(exc)
    return OTHER, detail[:300]


def http_status(code, name):
    """(kind, message) for an HTTP answer that is not a result."""
    if code == 429:
        return RATE_LIMIT, (f"{name} limits how often it may be asked, and that limit was reached. "
                            f"{AGAIN}")
    if code >= 500:
        return HTTP, f"{name} answered HTTP {code}. {AGAIN}"
    return HTTP, f"{name} answered HTTP {code}. Not measured."


def is_transient(message):
    """True for a failure that may pass by itself (DNS, timeout, rate limit)."""
    return str(message or "").endswith(AGAIN)


def describe(exc, host=None):
    return classify(exc, host)[1]


def is_dns(exc):
    return classify(exc)[0] == DNS


def is_temporary_dns(exc):
    text = str(exc).lower()
    return is_dns(exc) and any(k in text for k in _TEMPORARY)

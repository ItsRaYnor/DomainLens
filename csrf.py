"""Refuse state-changing requests that another site made the browser send.

The session cookie is SameSite=Lax, which keeps it off a cross-site POST in
current browsers -- but not off a request from a sibling subdomain (same-site
is not same-origin), not in browsers that predate Lax-by-default, and not at
all when login is switched off. With login off there is no cookie to ride,
yet any web page a user opens could still post to DomainLens on the LAN and
add monitors, change settings or start scans in their name.

So every POST, PUT, PATCH and DELETE must show that it came from DomainLens's
own pages. The browser says so itself: Sec-Fetch-Site, which a page cannot
set or forge, and failing that the Origin or Referer header. The decision is
made on what the browser reports, not on a token in the form, so no template
or fetch() call has to remember to carry one.

What is left alone, and why:
- A request with an Authorization header. A browser never attaches one to a
  cross-site request by itself, so it was put there by a script or client
  that holds the credential -- an API token, SCIM's bearer token.
- The SAML assertion consumer. The identity provider posts to it from its own
  origin by design; the signed assertion is what protects it.
- /oauth/token and /scim/: called by servers with their own credentials,
  never with the session cookie.
- A request with none of the three headers. Every browser in use sends at
  least Origin on a POST, so this is curl or a script, which has no victim's
  cookie to borrow.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import jsonify, request

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_EXEMPT_PATHS = ("/auth/saml/acs",)
_EXEMPT_PREFIXES = ("/scim/", "/oauth/token")


def _exempt(path: str) -> bool:
    return path in _EXEMPT_PATHS or any(path.startswith(p) for p in _EXEMPT_PREFIXES)


def _host_of(url: str) -> str:
    """host[:port] of a URL, lowercased; empty for 'null' or garbage."""
    try:
        return (urlsplit(url).netloc or "").lower()
    except ValueError:
        return ""


def _own_hosts(public_url: str) -> set[str]:
    """The hosts this installation answers on.

    The scheme is left out on purpose: behind a TLS-terminating proxy the app
    sees http while the browser reports https, and refusing every form post
    for that would be a self-inflicted outage. The host still has to match.
    """
    hosts = {request.host.lower()}
    configured = _host_of(public_url or "")
    if configured:
        hosts.add(configured)
    return hosts


def check(public_url: str = ""):
    """None when the request may proceed, else the 403 response."""
    if request.method not in _UNSAFE_METHODS:
        return None
    if _exempt(request.path):
        return None
    if request.headers.get("Authorization"):
        return None

    site = (request.headers.get("Sec-Fetch-Site") or "").lower()
    if site:
        # "none" is a navigation the user started themselves (a bookmark,
        # the address bar); it cannot carry another site's intent.
        if site in ("same-origin", "none"):
            return None
        return _refuse(f"Sec-Fetch-Site: {site}")

    origin = request.headers.get("Origin")
    if origin is not None:
        if _host_of(origin) in _own_hosts(public_url):
            return None
        return _refuse(f"Origin: {origin}")

    referer = request.headers.get("Referer")
    if referer:
        if _host_of(referer) in _own_hosts(public_url):
            return None
        return _refuse("Referer from another host")

    return None


def _refuse(reason: str):
    import logging
    logging.getLogger("domainlens.csrf").warning(
        "Refused cross-site %s %s (%s)", request.method, request.path, reason)
    return jsonify({
        "error": "This request did not come from a DomainLens page and was refused. "
                 "If DomainLens runs behind a reverse proxy that changes the Host header, "
                 "set its public URL (DOMAINLENS_PUBLIC_URL).",
    }), 403

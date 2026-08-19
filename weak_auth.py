"""
Weak / default authentication probing.

Only run against targets you own or are explicitly authorized to test.
Disabled by default — enable in config (weak_auth.enabled).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import requests

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _load_pairs_from_file(path: str | None) -> list[tuple[str, str]]:
    if not path or not Path(path).is_file():
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    pairs = []
    if isinstance(data, dict) and isinstance(data.get("pairs"), list):
        for item in data["pairs"]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                pairs.append((str(item[0]), str(item[1])))
    return pairs


def _load_wordlist(path: str | None) -> list[str]:
    if not path or not Path(path).is_file():
        return []
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                word = line.strip()
                if word and not word.startswith("#"):
                    words.append(word)
    except OSError:
        return []
    return words


def build_credential_list(settings: dict) -> list[tuple[str, str]]:
    """Merge inline config, credential pairs file, and optional wordlists."""
    pairs: list[tuple[str, str]] = []
    seen = set()

    def add_pair(user: str, password: str):
        key = (user, password)
        if key in seen:
            return
        seen.add(key)
        pairs.append(key)

    for user, password in _load_pairs_from_file(settings.get("credentials_file")):
        add_pair(user, password)

    usernames = list(settings.get("usernames") or [])
    passwords = list(settings.get("passwords") or [])
    usernames.extend(_load_wordlist(settings.get("usernames_file")))
    passwords.extend(_load_wordlist(settings.get("wordlist_file")))

    for user in usernames:
        for password in passwords:
            add_pair(str(user), str(password))

    max_attempts = int(settings.get("max_attempts_per_scan", 25))
    return pairs[:max_attempts]


def _uses_basic_auth(response) -> bool:
    header = (response.headers.get("WWW-Authenticate") or "").lower()
    return response.status_code == 401 and "basic" in header


def _probe_url(url: str, timeout: int) -> dict | None:
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": _BROWSER_UA, "Accept": "*/*"},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    if not _uses_basic_auth(resp):
        return None
    return {
        "url": url,
        "status_code": resp.status_code,
        "www_authenticate": resp.headers.get("WWW-Authenticate", ""),
    }


def _mask_password(password: str) -> str:
    """Mask a password so it is never persisted or served in plaintext."""
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    return f"{password[0]}{'*' * (len(password) - 2)}{password[-1]}"


def _redact_finding(hit: dict) -> dict:
    """Return a copy of a weak-auth hit with the password masked.

    The operator still learns which username/endpoint accepted a default
    credential, but the working secret is never written to the scan history
    (which is served by /api/history) or exports.
    """
    redacted = dict(hit)
    if "password" in redacted:
        redacted["password_masked"] = _mask_password(str(redacted.pop("password")))
    redacted["note"] = "Password masked; the account accepted a known default credential."
    return redacted


def _try_basic(url: str, username: str, password: str, timeout: int) -> dict | None:
    try:
        resp = requests.get(
            url,
            auth=(username, password),
            headers={"User-Agent": _BROWSER_UA, "Accept": "*/*"},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    if resp.status_code in {200, 204, 301, 302, 303, 307, 308}:
        return {
            "url": url,
            "username": username,
            "password": password,
            "status_code": resp.status_code,
            "method": "http_basic",
        }
    return None


def _detect_form_login(html: str) -> bool:
    if not html:
        return False
    lower = html.lower()
    return (
        "<form" in lower
        and ("password" in lower or 'type="password"' in lower)
        and ("login" in lower or "sign in" in lower or "username" in lower)
    )


def _try_form_login(url: str, username: str, password: str, timeout: int) -> dict | None:
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": _BROWSER_UA})
        resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None
    if not _detect_form_login(resp.text or ""):
        return None

    data = {
        "username": username,
        "user": username,
        "email": username,
        "password": password,
        "pass": password,
    }
    try:
        post = session.post(url, data=data, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None

    if post.status_code in {200, 204, 301, 302, 303, 307, 308}:
        body = (post.text or "").lower()
        if "invalid" in body or "incorrect" in body or "failed" in body:
            return None
        if _detect_form_login(post.text or "") and post.status_code == 200:
            return None
        return {
            "url": url,
            "username": username,
            "password": password,
            "status_code": post.status_code,
            "method": "html_form",
        }
    return None


def scan(domain: str, settings: dict | None = None) -> dict:
    """
    Probe for weak/default credentials on HTTP Basic protected paths.

    Returns a structured result suitable for scan JSON and recommendations.
    """
    settings = settings or {}
    if not settings.get("enabled"):
        return {
            "success": True,
            "skipped": True,
            "enabled": False,
            "detail": (
                "Weak-auth scanning is disabled. Enable weak_auth.enabled in "
                "config/domainlens.json only for systems you are authorized to test."
            ),
        }

    timeout = int(settings.get("timeout_seconds", 8))
    delay = float(settings.get("delay_seconds", 0.35))
    # Hard, scan-wide ceiling on live login attempts. This bounds the TOTAL
    # number of authentication requests across all endpoints and both probe
    # types — not just the credential-list length.
    max_attempts = max(1, int(settings.get("max_attempts_per_scan", 25)))
    paths = settings.get("paths") or ["/"]
    schemes = ["https"]
    if settings.get("include_http", True):
        schemes.append("http")

    credentials = build_credential_list(settings)
    if not credentials:
        return {
            "success": False,
            "enabled": True,
            "error": "No credentials configured for weak-auth scan",
        }

    protected_endpoints = []
    findings = []
    attempts = 0

    for scheme in schemes:
        for path in paths:
            path = path if str(path).startswith("/") else f"/{path}"
            url = f"{scheme}://{domain}{path}"
            endpoint = _probe_url(url, timeout)
            if endpoint:
                protected_endpoints.append(endpoint)

    if not protected_endpoints:
        return {
            "success": True,
            "enabled": True,
            "protected_endpoints": [],
            "findings": [],
            "attempts": 0,
            "weak_credentials_found": False,
            "detail": "No HTTP Basic authentication endpoints discovered on configured paths.",
        }

    capped = False
    for endpoint in protected_endpoints:
        if attempts >= max_attempts:
            capped = True
            break
        for username, password in credentials:
            if attempts >= max_attempts:
                capped = True
                break
            attempts += 1
            hit = _try_basic(endpoint["url"], username, password, timeout)
            if hit:
                findings.append(_redact_finding(hit))
                break
            if delay > 0:
                time.sleep(delay)

        # Limited form-login probe for the first few credential pairs only.
        if len(findings) < 3:
            for username, password in credentials[:5]:
                if attempts >= max_attempts:
                    capped = True
                    break
                attempts += 1
                hit = _try_form_login(endpoint["url"], username, password, timeout)
                if hit:
                    findings.append(_redact_finding(hit))
                    break
                if delay > 0:
                    time.sleep(delay)

    detail = (
        f"Tested {attempts} credential attempt(s) on {len(protected_endpoints)} "
        f"protected endpoint(s)."
    )
    if capped:
        detail += f" Stopped at the max_attempts_per_scan ceiling ({max_attempts})."
    return {
        "success": True,
        "enabled": True,
        "protected_endpoints": protected_endpoints,
        "findings": findings,
        "attempts": attempts,
        "max_attempts": max_attempts,
        "capped": capped,
        "weak_credentials_found": len(findings) > 0,
        "detail": detail,
    }

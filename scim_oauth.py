"""OAuth 2.0 client-credentials tokens for SCIM (preferred) + legacy bearer."""

from __future__ import annotations

import base64
import hmac
import logging
import os
import time
from typing import Optional

import jwt  # PyJWT

log = logging.getLogger("domainlens.scim_oauth")

SCIM_SCOPE = "scim"
TOKEN_TYPE = "Bearer"
DEFAULT_EXPIRES = 3600
_ISSUER = "domainlens"
_AUDIENCE = "scim"


class _NoSigningKey(Exception):
    """Raised when no secure signing key is configured."""


def _signing_key() -> str:
    """Return the SCIM token signing key.

    Fails closed: there is NO hardcoded fallback. Uses an explicit env key,
    else the persistent random app secret from the DB. If neither is available
    token issuing/verification is refused rather than using a guessable key.
    """
    raw = (
        os.environ.get("SCIM_TOKEN_SIGNING_KEY")
        or os.environ.get("DOMAINLENS_SECRET_KEY")
        or os.environ.get("FLASK_SECRET_KEY")
        or ""
    ).strip()
    if raw:
        return raw
    try:
        import db as _db
        secret = _db.get_or_create_app_secret()
        if secret:
            return secret
    except Exception as exc:
        log.error("SCIM signing key unavailable: %s", exc)
    raise _NoSigningKey(
        "No SCIM signing key configured. Set SCIM_TOKEN_SIGNING_KEY or "
        "DOMAINLENS_SECRET_KEY."
    )


def oauth_client_id() -> str:
    return (
        os.environ.get("SCIM_CLIENT_ID")
        or os.environ.get("AZURE_CLIENT_ID")
        or os.environ.get("OAUTH_CLIENT_ID")
        or ""
    ).strip()


def _managed_secret(*env_names):
    """Resolve a credential: environment first, then the encrypted store.

    Falls back to a plain environment read if the settings package is
    unavailable, so this can never be the reason an integration breaks.
    """
    try:
        from settings import api_keys
        return api_keys.resolve_first(*env_names)
    except Exception:
        for name in env_names:
            value = (os.environ.get(name) or "").strip()
            if value:
                return value
        return ""


def oauth_client_secret() -> str:
    return _managed_secret(
        "SCIM_CLIENT_SECRET", "AZURE_CLIENT_SECRET", "OAUTH_CLIENT_SECRET")


def oauth_client_configured() -> bool:
    return bool(oauth_client_id() and oauth_client_secret())


def legacy_bearer_token() -> str:
    return _managed_secret("SCIM_BEARER_TOKEN", "SCIM_TOKEN")


def legacy_bearer_configured() -> bool:
    return bool(legacy_bearer_token())


def issue_access_token(
    *,
    client_id: str,
    scope: str = SCIM_SCOPE,
    expires_in: int = DEFAULT_EXPIRES,
) -> dict:
    now = int(time.time())
    ttl = max(60, int(expires_in))
    payload = {
        "iss": _ISSUER,
        "sub": client_id,
        "aud": _AUDIENCE,
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
        "token_use": "access",
    }
    token = jwt.encode(payload, _signing_key(), algorithm="HS256")
    return {
        "access_token": token,
        "token_type": TOKEN_TYPE,
        "expires_in": ttl,
        "scope": scope,
    }


def verify_access_token(token: str) -> tuple[bool, str]:
    try:
        key = _signing_key()
    except _NoSigningKey as exc:
        return False, str(exc)
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["HS256"],
            audience=_AUDIENCE,
            issuer=_ISSUER,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError as exc:
        return False, f"Invalid token: {exc}"
    scope = str(payload.get("scope") or "")
    if SCIM_SCOPE not in scope.split():
        return False, "Token missing scim scope"
    # Defense in depth: the token subject must match the configured client.
    expected_id = oauth_client_id()
    if expected_id and not hmac.compare_digest(str(payload.get("sub") or ""), expected_id):
        return False, "Token subject mismatch"
    return True, "ok"


def _parse_basic_auth(header: str) -> tuple[str, str]:
    if not header or not header.lower().startswith("basic "):
        return "", ""
    try:
        raw = base64.b64decode(header.split(" ", 1)[1].strip()).decode("utf-8")
        if ":" not in raw:
            return "", ""
        client_id, client_secret = raw.split(":", 1)
        return client_id, client_secret
    except Exception:
        return "", ""


def authenticate_token_request(form: dict, authorization_header: str | None) -> tuple[Optional[dict], Optional[str]]:
    """Validate client_credentials and return token response or error string."""
    grant = (form.get("grant_type") or "").strip()
    if grant != "client_credentials":
        return None, "unsupported_grant_type"
    scope = (form.get("scope") or SCIM_SCOPE).strip() or SCIM_SCOPE
    if SCIM_SCOPE not in scope.split():
        return None, "invalid_scope"

    client_id = (form.get("client_id") or "").strip()
    client_secret = (form.get("client_secret") or "").strip()
    if not client_id or not client_secret:
        basic_id, basic_secret = _parse_basic_auth(authorization_header or "")
        client_id = client_id or basic_id
        client_secret = client_secret or basic_secret

    expected_id = oauth_client_id()
    expected_secret = oauth_client_secret()
    if not expected_id or not expected_secret:
        return None, "server_error"
    if not hmac.compare_digest(client_id, expected_id) or not hmac.compare_digest(
        client_secret, expected_secret
    ):
        return None, "invalid_client"

    expires = int(form.get("expires_in") or DEFAULT_EXPIRES)
    return issue_access_token(client_id=client_id, scope=SCIM_SCOPE, expires_in=expires), None


def authenticate_scim_request(request, cfg: dict) -> tuple[bool, str]:
    """
    Preferred: OAuth 2 access token from /oauth/token.
    Legacy: static SCIM_BEARER_TOKEN.
    """
    auth = request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        return False, "Bearer token required"
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return False, "Bearer token required"

    oauth_ok = False
    oauth_err = "OAuth token rejected"
    if cfg.get("prefer_oauth"):
        oauth_ok, oauth_err = verify_access_token(token)
        if oauth_ok:
            return True, "oauth"

    if cfg.get("allow_legacy_bearer") and legacy_bearer_configured():
        if hmac.compare_digest(token, legacy_bearer_token()):
            return True, "legacy_bearer"

    if cfg.get("prefer_oauth") and not cfg.get("allow_legacy_bearer"):
        return False, oauth_err or "OAuth bearer token required (preferred over legacy static token)"
    if cfg.get("allow_legacy_bearer") and not legacy_bearer_configured():
        return False, "Legacy bearer not configured; use OAuth 2 client credentials"
    return False, oauth_err or "Unauthorized"

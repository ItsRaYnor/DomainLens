"""Authentication for DomainLens: OAuth2/OIDC, local users, password policy, and MFA."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional
from urllib.parse import quote, urlencode

import requests
from flask import Flask, jsonify, redirect, request, session, url_for

import db

log = logging.getLogger("domainlens.auth")

SESSION_USER_KEY = "user"
SESSION_MFA_PENDING_KEY = "mfa_pending_user_id"
SESSION_MFA_SETUP_SECRET = "mfa_setup_secret"

_PROVIDER_PRESETS = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": "openid email profile",
        "display_name": "Google",
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes": "read:user user:email",
        "display_name": "GitHub",
    },
    "microsoft": {
        # Multi-tenant fallback; prefer provider=azure + tenant_id for App Registration
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scopes": "openid email profile offline_access User.Read",
        "display_name": "Microsoft",
    },
    "azure": {
        "authorize_url": "",
        "token_url": "",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scopes": "openid email profile offline_access User.Read",
        "display_name": "Microsoft Entra ID",
    },
}

_AZURE_CLOUD_HOSTS = {
    "public": "https://login.microsoftonline.com",
    "germany": "https://login.microsoftonline.de",
    "china": "https://login.chinacloudapi.cn",
    "usgov": "https://login.microsoftonline.us",
}

_AZURE_GRAPH_HOSTS = {
    "public": "https://graph.microsoft.com",
    "germany": "https://graph.microsoft.de",
    "china": "https://microsoftgraph.chinacloudapi.cn",
    "usgov": "https://graph.microsoft.us",
}

_HASH_PREFIX = "pbkdf2_sha256"
_HASH_ITERATIONS = 390000


def azure_endpoint_urls(tenant_id: str | None = None, cloud: str = "public") -> dict:
    """Build Entra ID OAuth2 v2 endpoints for an Azure App Registration."""
    tenant = (tenant_id or "organizations").strip() or "organizations"
    cloud_key = (cloud or "public").strip().lower() or "public"
    host = _AZURE_CLOUD_HOSTS.get(cloud_key, _AZURE_CLOUD_HOSTS["public"])
    graph = _AZURE_GRAPH_HOSTS.get(cloud_key, _AZURE_GRAPH_HOSTS["public"])
    base = f"{host}/{tenant}/oauth2/v2.0"
    return {
        "authorize_url": f"{base}/authorize",
        "token_url": f"{base}/token",
        "userinfo_url": f"{graph}/v1.0/me",
        "graph_scope_default": f"{graph}/.default",
        "issuer": f"{host}/{tenant}/v2.0",
        "tenant_id": tenant,
        "cloud": cloud_key,
    }


def is_azure_provider(provider: str) -> bool:
    return (provider or "").strip().lower() in {"azure", "entra", "microsoft", "aad", "azuread", "azure_ad"}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Password hashing + policy
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _HASH_ITERATIONS)
    return (
        f"{_HASH_PREFIX}${_HASH_ITERATIONS}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(dk).decode()}"
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != _HASH_PREFIX:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters_s))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _dummy_password_verify(password: str) -> None:
    """Spend the same work as a real verify for a non-existent account.

    Prevents a timing side-channel that would let an attacker enumerate valid
    local-account emails by measuring response time.
    """
    try:
        hashlib.pbkdf2_hmac(
            "sha256", (password or "").encode("utf-8"), b"domainlens-dummy-salt", _HASH_ITERATIONS
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _settings_section(name: str) -> dict:
    try:
        from settings.store import get_store
        return dict(get_store().section(name, force_reload=True))
    except Exception:
        return {}


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


def oauth_config() -> dict:
    raw = _settings_section("auth_oauth")
    provider = (raw.get("provider") or os.environ.get("OAUTH_PROVIDER") or "oidc").strip().lower()
    if provider in {"entra", "aad", "azuread", "azure_ad"}:
        provider = "azure"
    enabled = bool(raw.get("enabled", False))

    client_id = (
        os.environ.get("AZURE_CLIENT_ID")
        or os.environ.get("OAUTH_CLIENT_ID")
        or ""
    ).strip()
    client_secret = _managed_secret("AZURE_CLIENT_SECRET", "OAUTH_CLIENT_SECRET")
    redirect_uri = (
        os.environ.get("AZURE_REDIRECT_URI")
        or os.environ.get("OAUTH_REDIRECT_URI")
        or ""
    ).strip() or None

    tenant_id = (
        (raw.get("tenant_id") or "")
        or os.environ.get("AZURE_TENANT_ID")
        or os.environ.get("OAUTH_TENANT_ID")
        or ""
    ).strip() or None
    azure_cloud = (
        (raw.get("azure_cloud") or "")
        or os.environ.get("AZURE_CLOUD")
        or "public"
    ).strip().lower() or "public"

    preset = dict(_PROVIDER_PRESETS.get(provider, {}))
    if provider == "azure" or (provider == "microsoft" and tenant_id):
        endpoints = azure_endpoint_urls(tenant_id or "organizations", azure_cloud)
        preset.update(endpoints)
        if provider == "microsoft" and tenant_id:
            provider = "azure"

    authorize_url = (os.environ.get("OAUTH_AUTHORIZE_URL") or preset.get("authorize_url") or "").strip()
    token_url = (os.environ.get("OAUTH_TOKEN_URL") or preset.get("token_url") or "").strip()
    userinfo_url = (os.environ.get("OAUTH_USERINFO_URL") or preset.get("userinfo_url") or "").strip()
    scopes = (
        os.environ.get("OAUTH_SCOPES")
        or os.environ.get("AZURE_SCOPES")
        or (raw.get("scopes") if isinstance(raw.get("scopes"), str) else None)
        or preset.get("scopes")
        or "openid email profile"
    ).strip()

    configured = bool(enabled and client_id and client_secret and authorize_url and token_url and userinfo_url)

    allowed_emails = raw.get("allowed_emails") or []
    allowed_domains = raw.get("allowed_domains") or []
    if not allowed_emails and os.environ.get("OAUTH_ALLOWED_EMAILS"):
        allowed_emails = [e.strip().lower() for e in os.environ["OAUTH_ALLOWED_EMAILS"].split(",") if e.strip()]
    if not allowed_domains and os.environ.get("OAUTH_ALLOWED_DOMAINS"):
        allowed_domains = [d.strip().lower().lstrip("@") for d in os.environ["OAUTH_ALLOWED_DOMAINS"].split(",") if d.strip()]

    display_name = preset.get("display_name") or provider
    if is_azure_provider(provider):
        display_name = "Microsoft Entra ID" if (provider == "azure" or tenant_id) else "Microsoft"

    return {
        "enabled": enabled,
        "configured": configured,
        "require_login": bool(raw.get("require_login", True)),
        "provider": provider,
        "display_name": display_name,
        "client_id": client_id,
        "client_secret": client_secret,
        "authorize_url": authorize_url,
        "token_url": token_url,
        "userinfo_url": userinfo_url,
        "scopes": scopes,
        "redirect_uri": redirect_uri,
        "session_hours": max(1, int(raw.get("session_hours") or _env_int("OAUTH_SESSION_HOURS", 12))),
        "allowed_emails": {e.strip().lower() for e in allowed_emails if str(e).strip()},
        "allowed_domains": {d.strip().lower().lstrip("@") for d in allowed_domains if str(d).strip()},
        "tenant_id": tenant_id,
        "azure_cloud": azure_cloud,
        "azure_app_registration": is_azure_provider(provider),
        "azure_tenant_configured": bool(tenant_id),
        "issuer": preset.get("issuer"),
        "prompt": (raw.get("prompt") or os.environ.get("AZURE_PROMPT") or "select_account").strip(),
        "jit_provision": bool(raw.get("jit_provision", False)),
    }


def local_config() -> dict:
    raw = _settings_section("auth_local")
    return {
        "enabled": bool(raw.get("enabled", False)),
        "require_login": bool(raw.get("require_login", True)),
        "mfa_required": bool(raw.get("mfa_required", False)),
        "mfa_available": bool(raw.get("mfa_enabled", True)),
        "max_failed_attempts": max(3, int(raw.get("max_failed_attempts") or 5)),
        "lockout_minutes": max(1, int(raw.get("lockout_minutes") or 15)),
        "password_policy": password_policy(),
    }


def password_policy() -> dict:
    raw = _settings_section("auth_local")
    return {
        "min_length": max(8, int(raw.get("password_min_length") or 12)),
        "require_upper": bool(raw.get("password_require_upper", True)),
        "require_lower": bool(raw.get("password_require_lower", True)),
        "require_digit": bool(raw.get("password_require_digit", True)),
        "require_special": bool(raw.get("password_require_special", True)),
    }


def config() -> dict:
    oauth = oauth_config()
    local = local_config()
    try:
        from scim import scim_config, scim_status
        scim_cfg = scim_config()
        scim_st = scim_status()
    except Exception:
        scim_cfg = {"enabled": False}
        scim_st = {"enabled": False, "configured": False}
    try:
        from saml_sp import saml_config, saml_status
        saml_cfg = saml_config()
        saml_st = saml_status()
    except Exception:
        saml_cfg = {"enabled": False, "configured": False}
        saml_st = {"enabled": False, "configured": False}

    enabled = oauth["enabled"] or local["enabled"] or bool(saml_cfg.get("enabled"))
    require_login = False
    if oauth["enabled"] and oauth["require_login"]:
        require_login = True
    if local["enabled"] and local["require_login"]:
        require_login = True
    if saml_cfg.get("enabled") and saml_cfg.get("configured"):
        # SAML alone can require login when OAuth/local require flags are on via oauth/local
        pass
    # Preferred interactive SSO is OAuth; SAML is legacy; local is outage backup
    preferred_sso = "oauth" if oauth["configured"] else ("saml" if saml_cfg.get("configured") else None)
    return {
        **oauth,
        "oauth_enabled": oauth["enabled"],
        "oauth_configured": oauth["configured"],
        "local_enabled": local["enabled"],
        "local": local,
        "local_backup": bool(local["enabled"]),
        "enabled": enabled,
        "require_login": require_login,
        "preferred_sso": preferred_sso,
        "sso_preference": ["oauth", "saml", "local_backup"],
        "scim": scim_st,
        "saml": {
            **saml_st,
            "enabled": bool(saml_cfg.get("enabled")),
            "configured": bool(saml_cfg.get("configured")),
            "display_name": saml_cfg.get("display_name"),
        },
        "auth_methods": {
            "oauth": oauth["configured"],
            "saml": bool(saml_cfg.get("configured")),
            "local": local["enabled"],
            "scim": bool(scim_st.get("configured")),
        },
    }


def init_app(app: Flask) -> None:
    secret = (os.environ.get("DOMAINLENS_SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or "").strip()
    if not secret:
        # No env secret: use a persistent, cryptographically random secret
        # (stored in the DB). NEVER derive it from public config values — that
        # would make session cookies forgeable by anyone reading the source.
        try:
            import db as _db
            secret = _db.get_or_create_app_secret()
            log.warning(
                "DOMAINLENS_SECRET_KEY not set; using a persisted random secret. "
                "Set DOMAINLENS_SECRET_KEY explicitly for multi-instance deployments."
            )
        except Exception as exc:
            secret = secrets.token_hex(32)
            log.error("Could not persist app secret (%s); using ephemeral secret", exc)
    app.secret_key = secret
    oauth = oauth_config()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_env_bool("OAUTH_COOKIE_SECURE", False)
        or _env_bool("SESSION_COOKIE_SECURE", False),
        PERMANENT_SESSION_LIFETIME=oauth.get("session_hours", 12) * 3600,
    )
    try:
        bootstrap_admin()
    except Exception as exc:
        log.error("Local admin bootstrap failed: %s", exc)


def validate_password(password: str, email: str = "") -> list[str]:
    policy = password_policy()
    errors = []
    if not isinstance(password, str) or len(password) < policy["min_length"]:
        errors.append(f"Password must be at least {policy['min_length']} characters.")
    if policy["require_upper"] and not any(c.isupper() for c in password or ""):
        errors.append("Password must include an uppercase letter.")
    if policy["require_lower"] and not any(c.islower() for c in password or ""):
        errors.append("Password must include a lowercase letter.")
    if policy["require_digit"] and not any(c.isdigit() for c in password or ""):
        errors.append("Password must include a digit.")
    if policy["require_special"] and not any(not c.isalnum() for c in password or ""):
        errors.append("Password must include a special character.")
    local = (email or "").lower().split("@")[0]
    if local and len(local) >= 3 and password and local in password.lower():
        errors.append("Password must not contain your email local-part.")
    return errors


# ---------------------------------------------------------------------------
# TOTP MFA (RFC 6238) + backup codes
# ---------------------------------------------------------------------------

def _b32_encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32_decode(secret: str) -> bytes:
    s = secret.strip().upper().replace(" ", "")
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad, casefold=True)


def generate_totp_secret() -> str:
    return _b32_encode(secrets.token_bytes(20))


def totp_at(secret: str, for_time: Optional[float] = None, digits: int = 6, period: int = 30) -> str:
    if for_time is None:
        for_time = time.time()
    counter = int(for_time) // period
    key = _b32_decode(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code:
        return False
    cleaned = "".join(c for c in str(code) if c.isdigit())
    if len(cleaned) < 6:
        return False
    now = time.time()
    target = cleaned[-6:].zfill(6)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(totp_at(secret, now + drift * 30), target):
            return True
    return False


def otpauth_uri(secret: str, email: str, issuer: str = "DomainLens") -> str:
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(email)}"
        f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


def otpauth_qr_svg(uri: str, box: int = 4, border: int = 2) -> Optional[str]:
    """Render an otpauth URI as inline SVG, or None if it cannot be drawn.

    Enrolling meant copying a long otpauth:// string into a phone by hand,
    which is exactly the kind of transcription people get wrong once and then
    give up on.

    Inline SVG rather than a data: URI in an <img>, so no CSP img-src
    exception is needed, and the code never leaves this process - handing an
    MFA seed to a third-party QR service would be giving away the second
    factor.

    Colours are fixed black-on-white instead of following the theme: a dark
    QR on a dark background does not scan, and a code that renders but cannot
    be read is worse than no code at all.
    """
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None
    try:
        code = qrcode.QRCode(
            box_size=box, border=border,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
        )
        code.add_data(uri)
        code.make(fit=True)
        image = code.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        buffer = io.BytesIO()
        image.save(buffer)
        markup = buffer.getvalue().decode("utf-8")
    except Exception:
        log.warning("Could not render the MFA QR code", exc_info=True)
        return None

    # Drop the XML declaration so this embeds in an HTML document, and give
    # the code a white plate of its own.
    markup = re.sub(r"<\?xml[^>]*\?>\s*", "", markup, count=1)
    markup = markup.replace(
        "<path ", '<rect width="100%" height="100%" fill="#ffffff"/><path fill="#000000" ',
        1,
    )
    return markup


def generate_backup_codes(count: int = 8) -> list[str]:
    return [secrets.token_hex(4) for _ in range(count)]


def hash_backup_codes(codes: list[str]) -> list[str]:
    return [hashlib.sha256(c.lower().encode("utf-8")).hexdigest() for c in codes]


def consume_backup_code(user: dict, code: str) -> bool:
    cleaned = (code or "").strip().lower().replace("-", "").replace(" ", "")
    if not cleaned:
        return False
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
    stored = list(user.get("mfa_backup_codes") or [])
    if digest not in stored:
        return False
    stored.remove(digest)
    db.update_user(user["id"], mfa_backup_codes=stored)
    return True


def bootstrap_admin() -> Optional[dict]:
    if not local_config()["enabled"]:
        return None
    email = (os.environ.get("LOCAL_ADMIN_EMAIL") or "").strip().lower()
    password = os.environ.get("LOCAL_ADMIN_PASSWORD") or ""
    if not email or not password:
        return None
    existing = db.get_user_by_email(email, include_secrets=True)
    if existing:
        return existing
    if db.count_users() > 0:
        return None
    errors = validate_password(password, email)
    if errors:
        raise RuntimeError("LOCAL_ADMIN_PASSWORD does not meet policy: " + "; ".join(errors))
    user_id = db.create_user(
        email=email,
        password_hash=hash_password(password),
        name=(os.environ.get("LOCAL_ADMIN_NAME") or "Admin").strip() or "Admin",
        role="admin",
        enabled=True,
        provider="local",
        user_name=email,
    )
    log.info("Bootstrapped local admin user %s", email)
    return db.get_user(user_id, include_secrets=True)


def current_user() -> Optional[dict]:
    user = session.get(SESSION_USER_KEY)
    return user if isinstance(user, dict) else None


def login_user(user: dict) -> None:
    session.clear()
    session[SESSION_USER_KEY] = {
        "id": user.get("id") or user.get("sub") or user.get("email") or "unknown",
        "email": user.get("email"),
        "name": user.get("name") or user.get("login") or user.get("email"),
        "picture": user.get("picture") or user.get("avatar_url"),
        "provider": user.get("provider"),
        "role": user.get("role") or "user",
        "mfa_enabled": bool(user.get("mfa_enabled")),
    }
    session.permanent = True


def login_local_user_record(row: dict) -> None:
    login_user(
        {
            "id": row["id"],
            "email": row.get("email"),
            "name": row.get("name") or row.get("email"),
            "role": row.get("role") or "user",
            "provider": "local",
            "mfa_enabled": bool(row.get("mfa_enabled")),
        }
    )
    db.update_user(row["id"], last_login_at=datetime.now(timezone.utc).isoformat())


def logout_user() -> None:
    session.clear()


def mfa_pending_user_id() -> Optional[int]:
    uid = session.get(SESSION_MFA_PENDING_KEY)
    try:
        return int(uid) if uid is not None else None
    except (TypeError, ValueError):
        return None


def set_mfa_pending(user_id: int) -> None:
    session.clear()
    session[SESSION_MFA_PENDING_KEY] = int(user_id)
    session.permanent = True


def user_allowed(user: dict) -> bool:
    cfg = oauth_config()
    email = (user.get("email") or "").strip().lower()
    if cfg["allowed_emails"]:
        return email in cfg["allowed_emails"]
    if cfg["allowed_domains"]:
        if "@" not in email:
            return False
        return email.split("@", 1)[1] in cfg["allowed_domains"]
    return True


def _public_path(path: str) -> bool:
    public_prefixes = (
        "/health",
        "/api/health",
        "/api/version",
        "/api/auth/me",
        "/login",
        "/auth/",
        "/static/",
        "/scim/",
        "/oauth/token",
    )
    if path == "/favicon.ico":
        return True
    return any(path == p or path.startswith(p) for p in public_prefixes)


def require_login(view=None, *, api=False):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            cfg = config()
            if not (cfg["enabled"] and cfg["require_login"]):
                return fn(*args, **kwargs)
            if current_user():
                return fn(*args, **kwargs)
            if api or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required", "login_url": "/login"}), 401
            next_url = request.full_path if request.query_string else request.path
            return redirect(url_for("login_page", next=next_url.rstrip("?")))

        return wrapped

    if view is not None:
        return decorator(view)
    return decorator


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        cfg = config()
        if not cfg.get("enabled"):
            return view(*args, **kwargs)
        user = current_user()
        if not user or user.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "Admin required"}), 403
            return redirect(url_for("login_page", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def enforce_login_before_request():
    cfg = config()
    if not (cfg["enabled"] and cfg["require_login"]):
        return None
    if _public_path(request.path):
        return None
    if current_user():
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "Authentication required", "login_url": "/login"}), 401
    next_url = request.full_path if request.query_string else request.path
    return redirect(url_for("login_page", next=next_url.rstrip("?")))


def _is_locked(user: dict) -> bool:
    locked_until = user.get("locked_until")
    if not locked_until:
        return False
    try:
        until = datetime.fromisoformat(str(locked_until).replace("Z", "+00:00"))
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return until > datetime.now(timezone.utc)
    except Exception:
        return False


def is_locked(user: dict) -> bool:
    """Public wrapper: True if the user is currently locked out."""
    return _is_locked(user)


def register_mfa_failure(user: dict) -> bool:
    """Count a failed MFA attempt; lock the account after the threshold.

    Reuses the same failed_logins / locked_until mechanism as the password
    step so TOTP codes can't be brute-forced without limit. Returns True if
    the account is now locked.
    """
    local = local_config()
    attempts = int(user.get("failed_logins") or 0) + 1
    updates = {"failed_logins": attempts}
    locked = False
    if attempts >= local["max_failed_attempts"]:
        until = datetime.now(timezone.utc) + timedelta(minutes=local["lockout_minutes"])
        updates["locked_until"] = until.isoformat().replace("+00:00", "Z")
        updates["failed_logins"] = 0
        locked = True
    try:
        db.update_user(user["id"], **updates)
    except Exception:
        pass
    return locked


def clear_login_failures(user_id) -> None:
    try:
        db.update_user(user_id, failed_logins=0, locked_until=None)
    except Exception:
        pass


def resolve_federated_user(profile: dict) -> dict:
    """
    Link IdP profile to a provisioned DB user when present.

    SCIM-provisioned accounts carry role/enabled from the directory.
    OAuth-only users (no DB row) keep session-only access when allowlists pass.
    """
    email = (profile.get("email") or "").strip().lower()
    external = (profile.get("sub") or profile.get("id") or "").strip()
    row = None
    if external:
        row = db.get_user_by_external_id(external)
    if not row and email:
        row = db.get_user_by_email(email)
    if not row:
        # No provisioned account. Honor the jit_provision setting: when it is
        # disabled, only pre-provisioned (e.g. SCIM-synced) users may sign in.
        if not oauth_config().get("jit_provision", True):
            raise PermissionError("Just-in-time provisioning disabled; user not provisioned")
        return profile
    if not row.get("enabled"):
        raise PermissionError("Account disabled")
    return {
        "id": row["id"],
        "email": row.get("email") or email,
        "name": row.get("name") or profile.get("name") or email,
        "picture": profile.get("picture"),
        "provider": profile.get("provider") or row.get("provider") or "oauth",
        "role": row.get("role") or "user",
        "mfa_enabled": bool(row.get("mfa_enabled")),
        "db_user": True,
    }


def attempt_local_login(email: str, password: str) -> tuple[Optional[dict], Optional[str], bool]:
    """Return (user_row, error, needs_mfa_challenge)."""
    local = local_config()
    if not local["enabled"]:
        return None, "Local login is disabled.", False
    email = (email or "").strip().lower()
    if not email or not password:
        return None, "Email and password are required.", False
    user = db.get_user_by_email(email, include_secrets=True)
    if not user or not user.get("enabled"):
        # Perform equivalent work so response time doesn't reveal whether the
        # account exists (timing-based user enumeration).
        _dummy_password_verify(password)
        return None, "Invalid email or password.", False
    if _is_locked(user):
        return None, "Account temporarily locked due to failed logins.", False

    stored_hash = user.get("password_hash") or ""
    if not stored_hash:
        return (
            None,
            "This account has no local password. Sign in with SSO, or ask an admin to set a backup password.",
            False,
        )

    if not verify_password(password, stored_hash):
        attempts = int(user.get("failed_logins") or 0) + 1
        updates = {"failed_logins": attempts}
        if attempts >= local["max_failed_attempts"]:
            until = datetime.now(timezone.utc) + timedelta(minutes=local["lockout_minutes"])
            updates["locked_until"] = until.isoformat().replace("+00:00", "Z")
            updates["failed_logins"] = 0
        db.update_user(user["id"], **updates)
        return None, "Invalid email or password.", False

    db.update_user(user["id"], failed_logins=0, locked_until=None)
    user = db.get_user(user["id"], include_secrets=True)
    if local["mfa_available"] and user.get("mfa_enabled"):
        return user, None, True
    return user, None, False


def build_authorize_url(state: str, redirect_uri: str) -> str:
    cfg = oauth_config()
    params = {
        "client_id": cfg["client_id"],
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": cfg["scopes"],
        "state": state,
    }
    if is_azure_provider(cfg["provider"]):
        # Azure App Registration (auth code + PKCE optional later)
        params["response_mode"] = "query"
        params["prompt"] = cfg.get("prompt") or "select_account"
    elif cfg["provider"] in {"google", "oidc"}:
        params["access_type"] = "online"
        params["include_granted_scopes"] = "true"
        params["prompt"] = "select_account"
    return f"{cfg['authorize_url']}?{urlencode(params)}"


def _normalize_oauth_profile(provider: str, profile: dict) -> dict:
    """Map provider-specific profile fields to a common shape."""
    out = dict(profile or {})
    out["provider"] = provider
    if is_azure_provider(provider):
        # Microsoft Graph /me uses mail / userPrincipalName / displayName
        email = out.get("email") or out.get("mail") or out.get("userPrincipalName")
        out["email"] = (email or "").strip().lower() or None
        out["name"] = out.get("name") or out.get("displayName") or out.get("email")
        out["sub"] = out.get("sub") or out.get("id") or out.get("oid")
    if not out.get("name"):
        out["name"] = out.get("login") or out.get("email") or out.get("sub")
    return out


def exchange_code(code: str, redirect_uri: str) -> dict:
    cfg = oauth_config()
    headers = {"Accept": "application/json"}
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "scope": cfg["scopes"],
    }
    resp = requests.post(cfg["token_url"], data=data, headers=headers, timeout=20)
    resp.raise_for_status()
    token = resp.json()
    access_token = token.get("access_token")
    if not access_token:
        raise RuntimeError("OAuth token response missing access_token")

    user_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    user_resp = requests.get(cfg["userinfo_url"], headers=user_headers, timeout=20)
    user_resp.raise_for_status()
    profile = user_resp.json()

    if cfg["provider"] == "github" and not profile.get("email"):
        email_resp = requests.get(
            "https://api.github.com/user/emails",
            headers=user_headers,
            timeout=20,
        )
        if email_resp.ok:
            emails = email_resp.json()
            primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
            if primary:
                profile["email"] = primary.get("email")
            elif emails:
                profile["email"] = emails[0].get("email")

    return _normalize_oauth_profile(cfg["provider"], profile)


def azure_client_credentials_token(*, scope: str | None = None) -> dict:
    """
    App-only token via Azure App Registration (client credentials).

    Useful for daemon/service integrations (Graph, custom APIs). Requires
    Application permissions granted + admin consent in Entra ID.
    """
    cfg = oauth_config()
    if not (cfg.get("client_id") and cfg.get("client_secret") and cfg.get("token_url")):
        raise RuntimeError("Azure App Registration not configured for client credentials")
    endpoints = azure_endpoint_urls(cfg.get("tenant_id") or "organizations", cfg.get("azure_cloud") or "public")
    # Default Graph application scope; override for custom API App ID URI
    token_scope = (
        scope
        or os.environ.get("AZURE_CLIENT_CREDENTIALS_SCOPE")
        or endpoints.get("graph_scope_default")
        or "https://graph.microsoft.com/.default"
    )
    data = {
        "grant_type": "client_credentials",
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "scope": token_scope,
    }
    # Prefer tenant-specific token URL (required for client credentials)
    token_url = cfg["token_url"]
    if (
        not token_url
        or "/common/" in token_url
        or "/organizations/" in token_url
        or "/consumers/" in token_url
    ):
        if not cfg.get("tenant_id"):
            raise RuntimeError(
                "Azure client credentials require AZURE_TENANT_ID (or auth_oauth.tenant_id)"
            )
        token_url = endpoints["token_url"]
    resp = requests.post(token_url, data=data, headers={"Accept": "application/json"}, timeout=20)
    resp.raise_for_status()
    return resp.json()


def status_payload():
    """Auth state for the caller — scoped to who is asking.

    This used to answer every caller with the full configuration: the Entra
    tenant id and issuer URL, the exact password policy, whether MFA is
    required, the SCIM endpoint and its auth mode. All of it before login.

    None of that helps someone sign in. Together it tells whoever is deciding
    where to push exactly which door is weakest — whether a stolen password
    alone suffices, how long a sprayed password has to be, and whether a
    local account exists beside the SSO. An admin can read the same values on
    the settings page, having authenticated first.

    So an anonymous caller gets what the login screen needs to draw itself,
    and nothing else.
    """
    cfg = config()
    user = current_user()

    public = {
        "enabled": cfg["enabled"],
        "configured": cfg["configured"],
        "require_login": cfg["require_login"],
        # Which buttons to show, and what to label them.
        "provider": cfg["provider"],
        "display_name": cfg.get("display_name") or cfg["provider"],
        "local_enabled": cfg["local_enabled"],
        "oauth_enabled": cfg["oauth_enabled"],
        "preferred_sso": cfg.get("preferred_sso"),
        "saml_enabled": bool((cfg.get("saml") or {}).get("enabled")),
        "authenticated": bool(user),
        "user": user,
    }
    if not (user and user.get("role") == "admin"):
        return public

    local = local_config()
    public.update({
        "local_backup": cfg.get("local_backup"),
        "sso_preference": cfg.get("sso_preference"),
        "auth_methods": cfg["auth_methods"],
        "azure": {
            "app_registration": bool(cfg.get("azure_app_registration")),
            "tenant_configured": bool(cfg.get("azure_tenant_configured")),
            "tenant_id": cfg.get("tenant_id"),
            "cloud": cfg.get("azure_cloud"),
            "issuer": cfg.get("issuer"),
        },
        "scim": cfg.get("scim") or {},
        "saml": cfg.get("saml") or {},
        "mfa": {
            "available": local["mfa_available"],
            "required": local["mfa_required"],
        },
        "password_policy": password_policy(),
    })
    return public

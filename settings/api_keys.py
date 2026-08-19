"""Resolution and at-rest protection for the optional OSINT API keys.

These three keys (abuse.ch, AlienVault OTX, Spamhaus DQS) unlock read-only
threat-feed lookups. They were environment-only, which on a Portainer/NAS
deployment means editing the stack and recreating the container just to add
an optional enrichment key — enough friction that they tend to stay unset.

They are stored apart from the normal settings sections on purpose:

  * The section name is NOT in DEFAULTS, so settings/store.py never merges it
    into the shared config dict. That keeps the values out of merged(),
    public_snapshot(), the admin form schema and every export that walks
    those structures — they cannot leak by being carried along.
  * Values are only ever handed out through resolve() at the point of use.
    The admin API returns status and a masked hint, never the secret.

Only these low-privilege, read-only keys are UI-editable. Credentials that
grant access to other systems (ServiceNow, OAuth, SAML, SCIM, Rapid7, the
local admin password) stay environment-only by design.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

from settings.defaults import MANAGED_CREDENTIALS, OPTIONAL_INTEGRATIONS

log = logging.getLogger("domainlens.api_keys")

# Stored under its own settings section, deliberately absent from DEFAULTS.
SECTION = "api_keys"

# Everything this module is allowed to store. Anything not listed here is
# rejected outright, so the admin API can never be pointed at an arbitrary
# environment variable.
_ALL_MANAGED = list(OPTIONAL_INTEGRATIONS) + list(MANAGED_CREDENTIALS)

# v1 derived the Fernet key with a bare SHA-256 of the secret — fast to brute
# force if DOMAINLENS_SECRET_KEY happens to be a weak passphrase. v2 uses scrypt
# with a per-install random salt, so guessing the secret costs real time and
# memory per attempt and no work carries over between installations. v1 is
# still readable so nothing written by an earlier build is lost.
_ENC_PREFIX_V1 = "enc:v1:"
_ENC_PREFIX = "enc:v2:"

# Salt is not a secret — it exists to make each install's derived key unique
# and to stop one brute-force run from applying to every DomainLens out there.
# Keeping it in the database alongside the ciphertext is the normal, correct
# arrangement; the secret that must stay outside the database is the key.
_SALT_SECTION = "_api_key_salt"
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1

# scrypt costs ~100 ms per derivation by design; resolve() runs on every scan,
# so cache the derived cipher per (secret, salt) pair.
_fernet_cache = {}

# env var -> storage key
_STORAGE_KEYS = {item["env"]: item["env"].lower() for item in _ALL_MANAGED}

MANAGED_ENV_VARS = tuple(_STORAGE_KEYS)


def is_managed(env_name):
    return env_name in _STORAGE_KEYS


# ---------------------------------------------------------------------------
# At-rest protection
# ---------------------------------------------------------------------------

def protection_state(db=None):
    """Describe how strong the at-rest protection actually is.

    Encryption is only meaningful when the key lives outside the database.
    DOMAINLENS_SECRET_KEY is an environment variable, so it does. The fallback
    app secret is itself stored in the same SQLite file as the ciphertext, so
    anyone who can read the database can also read the key — that is
    obfuscation against casual disclosure (backups, screenshots, support
    dumps), not protection against filesystem compromise. Report it honestly
    instead of labelling both cases "encrypted".
    """
    if (os.environ.get("DOMAINLENS_SECRET_KEY") or "").strip():
        return {
            "mode": "encrypted",
            "detail": "Encrypted with a key derived (scrypt, per-install salt) from "
                      "DOMAINLENS_SECRET_KEY, which is not stored in the database. "
                      "A copy of the database alone does not reveal these keys.",
        }
    return {
        "mode": "obfuscated",
        "detail": "DOMAINLENS_SECRET_KEY is not set, so the encryption key falls back "
                  "to the app secret stored in the same database as the values. "
                  "Anyone who can read the database can recover these keys. "
                  "Set DOMAINLENS_SECRET_KEY for real at-rest encryption.",
    }


def _key_material(db=None):
    secret = (os.environ.get("DOMAINLENS_SECRET_KEY") or "").strip()
    if secret:
        return secret
    if db is not None:
        try:
            return db.get_or_create_app_secret()
        except Exception:
            return ""
    return ""


def _get_salt(db):
    """Fetch (or create) this installation's random KDF salt."""
    if db is None:
        return None
    try:
        section = db.get_setting_section(_SALT_SECTION) or {}
        existing = section.get("salt")
        if isinstance(existing, str) and len(existing) >= 22:
            return base64.urlsafe_b64decode(existing.encode("ascii"))
        salt = os.urandom(16)
        db.set_setting_section(
            _SALT_SECTION, {"salt": base64.urlsafe_b64encode(salt).decode("ascii")}
        )
        return salt
    except Exception:
        return None


def _fernet(db=None, version=None):
    secret = _key_material(db)
    if not secret:
        return None
    if version == 1:
        digest = hashlib.sha256(secret.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    salt = _get_salt(db)
    if salt is None:
        return None
    cache_key = (secret, salt)
    cached = _fernet_cache.get(cache_key)
    if cached is not None:
        return cached
    digest = hashlib.scrypt(
        secret.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32,
    )
    f = Fernet(base64.urlsafe_b64encode(digest))
    _fernet_cache[cache_key] = f
    return f


def _encrypt(value, db=None):
    f = _fernet(db)
    if f is None:
        raise RuntimeError("No key material available to protect API keys")
    return _ENC_PREFIX + f.encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt(stored, db=None):
    if not isinstance(stored, str) or not stored:
        return ""
    if stored.startswith(_ENC_PREFIX):
        prefix, version = _ENC_PREFIX, 2
    elif stored.startswith(_ENC_PREFIX_V1):
        prefix, version = _ENC_PREFIX_V1, 1
    else:
        # Not written by us (hand-edited row); treat as plaintext rather than
        # silently dropping a key the operator believes is configured.
        return stored
    f = _fernet(db, version=version)
    if f is None:
        return ""
    try:
        return f.decrypt(stored[len(prefix):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        # Wrong/rotated DOMAINLENS_SECRET_KEY: the value is unrecoverable, but a
        # scan must not crash over an optional enrichment key.
        log.warning("Stored API key could not be decrypted; treating as unset")
        return ""


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def _load(db):
    if db is None:
        return {}
    try:
        section = db.get_setting_section(SECTION)
    except Exception:
        return {}
    return section if isinstance(section, dict) else {}


def _db_module():
    try:
        import db as db_module
        return db_module
    except Exception:
        return None


def stored_value(env_name, db=None):
    """Decrypted value from the database, ignoring the environment."""
    if not is_managed(env_name):
        return ""
    db = db or _db_module()
    raw = _load(db).get(_STORAGE_KEYS[env_name])
    return _decrypt(raw, db) if raw else ""


def resolve(env_name, db=None):
    """The effective key: environment first, then the stored value.

    Environment wins so existing deployments keep working exactly as before
    and an operator can always override what is in the database.
    """
    env_value = (os.environ.get(env_name) or "").strip()
    if env_value:
        return env_value
    return stored_value(env_name, db=db)


def resolve_first(*env_names, db=None):
    """First non-empty value across a fallback chain.

    Every environment variable in the chain is checked before any stored
    value, so an existing deployment resolves to exactly the same credential
    it did before: a stored AZURE_CLIENT_SECRET must not outrank an
    environment OAUTH_CLIENT_SECRET that used to win.
    """
    for name in env_names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    for name in env_names:
        value = stored_value(name, db=db)
        if value:
            return value
    return ""


def is_env_locked(env_name):
    return bool((os.environ.get(env_name) or "").strip())


def set_key(env_name, value, user_id=None, db=None):
    if not is_managed(env_name):
        raise ValueError(f"Unknown API key: {env_name}")
    value = (value or "").strip()
    if not value:
        raise ValueError("Value must not be empty")
    if len(value) > 512:
        raise ValueError("Value is too long")
    db = db or _db_module()
    if db is None:
        raise RuntimeError("Database not available")
    current = _load(db)
    current[_STORAGE_KEYS[env_name]] = _encrypt(value, db)
    db.set_setting_section(SECTION, current, user_id=user_id)
    # Never log the value itself.
    log.info("API key %s updated by user %s", env_name, user_id)


def clear_key(env_name, user_id=None, db=None):
    if not is_managed(env_name):
        raise ValueError(f"Unknown API key: {env_name}")
    db = db or _db_module()
    if db is None:
        raise RuntimeError("Database not available")
    current = _load(db)
    current.pop(_STORAGE_KEYS[env_name], None)
    db.set_setting_section(SECTION, current, user_id=user_id)
    log.info("API key %s cleared by user %s", env_name, user_id)


# ---------------------------------------------------------------------------
# Status for the admin UI (never returns a secret)
# ---------------------------------------------------------------------------

def _mask(value):
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return "•" * 8 + value[-4:]


def credential_status(db=None):
    """Managed credentials grouped by integration. Contains no secret values."""
    db = db or _db_module()
    groups = {}
    for item in MANAGED_CREDENTIALS:
        row = _status_row(item, db)
        groups.setdefault(item["group"], []).append(row)
    return [
        {"group": name, "items": rows,
         "configured": any(r["configured"] for r in rows)}
        for name, rows in groups.items()
    ]


def _status_row(item, db):
    env_name = item["env"]
    env_locked = is_env_locked(env_name)
    stored = stored_value(env_name, db=db)
    effective = (os.environ.get(env_name) or "").strip() if env_locked else stored
    return {
        **item,
        "configured": bool(effective),
        "source": "environment" if env_locked else ("database" if stored else None),
        "env_locked": env_locked,
        "editable": not env_locked,
        "hint": _mask(effective),
    }


def status(db=None):
    """Per-key status for the admin UI. Contains no secret values."""
    db = db or _db_module()
    out = []
    for item in OPTIONAL_INTEGRATIONS:
        env_name = item["env"]
        env_locked = is_env_locked(env_name)
        stored = stored_value(env_name, db=db)
        effective = (os.environ.get(env_name) or "").strip() if env_locked else stored
        out.append({
            **item,
            "configured": bool(effective),
            "source": "environment" if env_locked else ("database" if stored else None),
            "env_locked": env_locked,
            "editable": not env_locked,
            "hint": _mask(effective),
        })
    return out

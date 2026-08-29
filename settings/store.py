"""Merge defaults, file config, database, and environment overrides."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

from settings.defaults import DEFAULTS, ENV_OVERRIDES, SECRET_ENV_KEYS

_ROOT = Path(__file__).resolve().parent.parent


def _deep_merge(base: dict, override: dict) -> dict:
    result = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _set_nested(data: dict, path: str, value):
    parts = path.split(".")
    cur = data
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = value


def _get_nested(data: dict, path: str, default=None):
    cur = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _parse_env_value(raw: str, typ: str):
    if typ == "bool":
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if typ == "int":
        return int(raw)
    return raw


def _validate_field(section: str, key: str, value):
    """Coerce a submitted value, or refuse it.

    Only types that have a way to be wrong are checked here. A colour is the
    first: it is rendered into a `style` attribute, so a value that is not a
    plain hex colour is a CSS injection rather than a bad-looking button.
    `theming` refuses it again at render time — this is so the administrator
    is told, instead of watching their choice quietly do nothing.
    """
    from settings.registry import FIELD_META

    # No settings value may carry a PGP private key. disclosure.pgp_public_key
    # is reachable through the admin settings API as well as through key
    # generation, and pasting the wrong half of an export there would publish
    # it at /.well-known/pgp-key.asc. Checked for every section: there is no
    # field anywhere that has a legitimate reason to hold one.
    if isinstance(value, str) and "-----BEGIN PGP PRIVATE KEY BLOCK-----" in value:
        raise ValueError(
            f"{section}.{key} contains a PGP PRIVATE key block. Only the "
            "public half belongs in settings; DomainLens never stores a "
            "private key.")

    meta = (FIELD_META.get(section) or {}).get(key) or {}
    if meta.get("type") == "color":
        import theming
        normalized = theming.normalize_accent(value)
        if normalized is None:
            raise ValueError(f"{section}.{key} must be a hex colour like #5b8def")
        return normalized
    if meta.get("type") == "select" and meta.get("options") is not None:
        if value not in meta["options"]:
            raise ValueError(
                f"{section}.{key} must be one of: {', '.join(map(str, meta['options']))}")
    return value


def _load_file_config(path: Path | None) -> dict:
    if not path or not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _load_db_sections(db_module) -> dict:
    if not db_module:
        return {}
    try:
        return db_module.get_all_settings()
    except Exception:
        return {}


def _apply_env_overrides(merged: dict) -> tuple[dict, list[str]]:
    locked = []
    for env_name, (section, key_path, typ) in ENV_OVERRIDES.items():
        raw = os.environ.get(env_name)
        if raw is None or not str(raw).strip():
            continue
        if section not in merged:
            merged[section] = {}
        try:
            _set_nested(merged[section], key_path, _parse_env_value(raw, typ))
            locked.append(f"{section}.{key_path}")
        except (ValueError, TypeError):
            continue
    return merged, locked


def _optional_key_configured(env_name: str) -> bool:
    """True when the key is set in the environment OR stored by an admin."""
    if os.environ.get(env_name, "").strip():
        return True
    try:
        from settings import api_keys
        return bool(api_keys.stored_value(env_name))
    except Exception:
        return False


def _integration_flags() -> dict:
    return {
        "spamhaus_dqs_configured": _optional_key_configured("SPAMHAUS_DQS_KEY"),
        "abusech_configured": _optional_key_configured("ABUSECH_AUTH_KEY"),
        "otx_configured": _optional_key_configured("OTX_API_KEY"),
        "ovh_configured": all(
            os.environ.get(k, "").strip()
            for k in ("OVH_APP_KEY", "OVH_APP_SECRET", "OVH_CONSUMER_KEY")
        ),
    }


class SettingsStore:
    def __init__(self, config_path: Path | None = None, db_module=None):
        if config_path is not None and not isinstance(config_path, Path):
            config_path = Path(config_path)
        self.config_path = config_path or self._resolve_config_path()
        self.db = db_module
        self._cache: dict | None = None
        self._env_locked: list[str] = []

    @staticmethod
    def _resolve_config_path() -> Path:
        env = os.environ.get("DOMAINLENS_CONFIG", "").strip()
        if env:
            return Path(env).expanduser().resolve()
        local = _ROOT / "config" / "domainlens.json"
        return local if local.is_file() else _ROOT / "config" / "domainlens.example.json"

    def invalidate(self):
        self._cache = None

    def merged(self, force_reload: bool = False) -> dict:
        if self._cache is not None and not force_reload:
            return deepcopy(self._cache)

        base = deepcopy(DEFAULTS)
        file_data = _load_file_config(self.config_path)
        db_data = _load_db_sections(self.db)

        # File config may use nested structure matching DEFAULTS sections
        for section, values in file_data.items():
            if section in base and isinstance(values, dict):
                base[section] = _deep_merge(base.get(section, {}), values)
            elif section == "monitors":
                base["monitors"] = values

        for section, values in db_data.items():
            if section in base and isinstance(values, dict):
                base[section] = _deep_merge(base.get(section, {}), values)

        merged, locked = _apply_env_overrides(base)
        merged["integrations"] = _integration_flags()
        merged["_meta"] = {
            "config_path": str(self.config_path) if self.config_path.is_file() else None,
            "env_locked": locked,
            "secrets_configured": {
                key: bool(os.environ.get(key, "").strip()) for key in SECRET_ENV_KEYS
            },
        }
        self._cache = merged
        self._env_locked = locked
        return deepcopy(merged)

    def section(self, name: str, force_reload: bool = False) -> dict:
        return dict(self.merged(force_reload).get(name) or {})

    def update_section(self, name: str, patch: dict, user_id: int | None = None) -> dict:
        if name not in DEFAULTS or name == "integrations":
            raise ValueError(f"Unknown or read-only settings section: {name}")
        if not self.db:
            raise RuntimeError("Database not available for settings persistence")
        current = self.section(name, force_reload=True)
        updated = deepcopy(current)
        for key, value in (patch or {}).items():
            value = _validate_field(name, key, value)
            if "." in key:
                _set_nested(updated, key, value)
            else:
                updated[key] = deepcopy(value)
        self.db.set_setting_section(name, updated, user_id=user_id)
        self.invalidate()
        return self.section(name)

    def public_snapshot(self) -> dict:
        data = self.merged()
        weak = data.get("weak_auth") or {}
        return {
            "general": data.get("general"),
            "scheduler": data.get("scheduler"),
            "scan": {
                "rate_limit": (data.get("scan") or {}).get("rate_limit"),
                "thread_pool_workers": (data.get("scan") or {}).get("thread_pool_workers"),
                "dkim_selectors_count": len((data.get("scan") or {}).get("dkim_selectors") or []),
                "ports_count": len((data.get("scan") or {}).get("ports") or {}),
            },
            "reporting": data.get("reporting"),
            "updates": data.get("updates"),
            "weak_auth": {
                "enabled": weak.get("enabled"),
                "max_attempts_per_scan": weak.get("max_attempts_per_scan"),
                "paths": weak.get("paths"),
            },
            "auth_local": {k: v for k, v in (data.get("auth_local") or {}).items()},
            "auth_oauth": {k: v for k, v in (data.get("auth_oauth") or {}).items()},
            "servicenow": {
                k: v for k, v in (data.get("servicenow") or {}).items() if k != "password"
            },
            "rapid7": {
                k: v for k, v in (data.get("rapid7") or {}).items()
                if k not in {"password", "api_key"}
            },
            "integrations": data.get("integrations"),
            "meta": data.get("_meta"),
        }

    def admin_form_schema(self) -> dict:
        from settings.registry import (
            ADMIN_SECTIONS, FIELD_META, SETTING_CATEGORIES, section_defaults)

        schema = {}
        merged = self.merged()
        locked = set(merged.get("_meta", {}).get("env_locked") or [])
        for section in ADMIN_SECTIONS:
            fields = {}
            for key, meta in (FIELD_META.get(section) or {}).items():
                field_path = f"{section}.{key}"
                sec_data = merged.get(section) or {}
                if "." in key:
                    value = _get_nested(sec_data, key)
                else:
                    value = sec_data.get(key)
                fields[key] = {
                    **meta,
                    "value": value,
                    "locked": any(field_path.startswith(l) or l.startswith(field_path) for l in locked),
                }
            schema[section] = {
                "fields": fields,
                # Explicit, because the schema is serialised with sorted keys:
                # without this every section renders alphabetically, which put
                # the mandatory contact field third and the on/off switch
                # fourth in the disclosure panel.
                "order": list((FIELD_META.get(section) or {}).keys()),
                "defaults": section_defaults(section),
            }
        return {
            "sections": schema,
            "categories": [dict(category) for category in SETTING_CATEGORIES],
        }


_store: SettingsStore | None = None


def get_store(config_path: Path | None = None, db_module=None, force_new: bool = False) -> SettingsStore:
    global _store
    if force_new or _store is None:
        _store = SettingsStore(config_path=config_path, db_module=db_module)
    elif db_module and _store.db is None:
        _store.db = db_module
    return _store

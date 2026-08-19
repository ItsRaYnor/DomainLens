"""
Configuration facade — delegates to settings store (defaults + file + DB + env).
"""

from __future__ import annotations

import os
from pathlib import Path

from settings.defaults import DEFAULTS
from settings.store import SettingsStore, get_store

_ROOT = Path(__file__).resolve().parent


class Settings:
    """Backward-compatible view over merged settings."""

    def __init__(self, store: SettingsStore):
        self._store = store
        self.raw = store.merged()
        self.config_path = store.config_path
        self.config_dir = store.config_path.parent if store.config_path.is_file() else _ROOT / "config"

    def reload(self):
        self.raw = self._store.merged(force_reload=True)
        return self

    @property
    def version(self) -> int:
        return 1

    def server(self) -> dict:
        return dict(self.raw.get("server") or {})

    def database_path(self) -> str:
        path = (self.raw.get("database") or {}).get("path", "domainlens.db")
        if os.environ.get("DOMAINLENS_DB"):
            return os.environ["DOMAINLENS_DB"]
        p = Path(path)
        if p.is_absolute():
            return str(p)
        return str((_ROOT / path).resolve())

    def scheduler(self) -> dict:
        return dict(self.raw.get("scheduler") or {})

    def scan(self) -> dict:
        return dict(self.raw.get("scan") or {})

    def reporting(self) -> dict:
        return dict(self.raw.get("reporting") or {})

    def weak_auth(self) -> dict:
        w = dict(self.raw.get("weak_auth") or {})
        cred = w.get("credentials_file")
        if cred and not Path(str(cred)).is_absolute():
            w["credentials_file"] = str((self.config_dir / cred).resolve())
        for key in ("wordlist_file", "usernames_file"):
            val = w.get(key)
            if val and not Path(str(val)).is_absolute():
                w[key] = str((self.config_dir / val).resolve())
        return w

    def active_scan(self) -> dict:
        return dict(self.raw.get("active_scan") or {})

    def rapid7(self) -> dict:
        return dict(self.raw.get("rapid7") or {})

    def general(self) -> dict:
        return dict(self.raw.get("general") or {})

    def appearance(self) -> dict:
        return dict(self.raw.get("appearance") or {})

    def bootstrap_monitors(self) -> list:
        return list(self.raw.get("monitors") or [])

    def public_snapshot(self) -> dict:
        return self._store.public_snapshot()


_settings: Settings | None = None


def load_settings(force_reload: bool = False, db_module=None) -> Settings:
    global _settings
    store = get_store(db_module=db_module, force_new=force_reload)
    if force_reload or _settings is None:
        _settings = Settings(store)
    else:
        _settings.reload()
    return _settings


def apply_database_env(settings: Settings | None = None) -> None:
    settings = settings or load_settings()
    os.environ["DOMAINLENS_DB"] = settings.database_path()


def config_path() -> Path:
    return get_store().config_path


def bootstrap_monitors(db_module) -> int:
    settings = load_settings(db_module=db_module)
    created = 0
    defaults_cfg = settings.scheduler().get("defaults") or {}
    for item in settings.bootstrap_monitors():
        if not isinstance(item, dict):
            continue
        domain = (item.get("domain") or "").strip().lower()
        target = (item.get("target") or domain).strip().lower()
        record_type = (item.get("record_type") or "A").strip().upper()
        if not domain or not target:
            continue
        name = item.get("name") or f"{target} ({record_type})"
        defaults = {
            "name": name,
            "record_value": item.get("record_value"),
            "source_type": item.get("source_type") or "config",
            "source_label": item.get("source_label") or str(config_path()),
            "provider": item.get("provider"),
            "schedule_minutes": int(item.get("schedule_minutes", defaults_cfg.get("schedule_minutes", 1440))),
            "checks": item.get("checks") or defaults_cfg.get("checks") or ["all"],
            "enabled": item.get("enabled", defaults_cfg.get("enabled", True)),
            "metadata": item.get("metadata") or {},
        }
        db_module.upsert_monitor(
            domain=domain,
            target=target,
            record_type=record_type,
            defaults=defaults,
        )
        created += 1
    return created

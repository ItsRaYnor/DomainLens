"""Internationalization for DomainLens (English + Dutch)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_SUPPORTED = {"en", "nl"}
_DEFAULT_LOCALE = "en"
_LOCALES_DIR = Path(__file__).resolve().parent / "locales"


@lru_cache(maxsize=8)
def load_locale(locale: str) -> dict:
    code = locale if locale in _SUPPORTED else _DEFAULT_LOCALE
    path = _LOCALES_DIR / f"{code}.json"
    if not path.is_file():
        path = _LOCALES_DIR / f"{_DEFAULT_LOCALE}.json"
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _lookup(data: dict, key: str):
    cur = data
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def t(key: str, locale: str | None = None, **kwargs) -> str:
    """Translate key (dot notation). Falls back to English then key."""
    loc = locale if locale in _SUPPORTED else _DEFAULT_LOCALE
    value = _lookup(load_locale(loc), key)
    if value is None and loc != _DEFAULT_LOCALE:
        value = _lookup(load_locale(_DEFAULT_LOCALE), key)
    if value is None:
        value = key
    if kwargs and isinstance(value, str):
        try:
            return value.format(**kwargs)
        except (KeyError, ValueError):
            return value
    return str(value)


def resolve_locale(request=None, user=None, settings_general: dict | None = None) -> str:
    """Pick locale: session → settings → Accept-Language → default."""
    if request is not None:
        try:
            from flask import has_request_context, session

            if has_request_context():
                sess_locale = session.get("locale")
                if sess_locale in _SUPPORTED:
                    return sess_locale
        except Exception:
            pass
        query = (request.args.get("lang") or "").strip().lower()
        if query in _SUPPORTED:
            return query

    if settings_general:
        pref = (settings_general.get("locale") or "").strip().lower()
        if pref in _SUPPORTED:
            return pref

    if request is not None:
        header = (request.headers.get("Accept-Language") or "").lower()
        if header.startswith("nl") or ",nl" in header:
            return "nl"

    return _DEFAULT_LOCALE


def supported_locales():
    return sorted(_SUPPORTED)

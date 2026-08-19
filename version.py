"""Application version metadata (single source of truth for UI, health, Docker)."""

from __future__ import annotations

import os
import platform
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent


def _read_version_file() -> str:
    path = _ROOT / "VERSION"
    try:
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return text.splitlines()[0].strip()
    except OSError:
        pass
    return "0.0.0-dev"


@lru_cache(maxsize=1)
def get_version() -> str:
    """Return semantic version string (env override: DOMAINLENS_VERSION)."""
    env = (os.environ.get("DOMAINLENS_VERSION") or "").strip()
    if env:
        return env.lstrip("vV")
    return _read_version_file()


def get_git_revision() -> str | None:
    env = (os.environ.get("DOMAINLENS_GIT_SHA") or os.environ.get("GIT_COMMIT") or "").strip()
    if env:
        return env[:12]
    git_dir = _ROOT / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref = head.split(" ", 1)[1].strip()
            ref_path = git_dir / ref
            if ref_path.is_file():
                return ref_path.read_text(encoding="utf-8").strip()[:12]
        if len(head) >= 7:
            return head[:12]
    except OSError:
        pass
    return None


def get_image_info() -> dict[str, Any]:
    return {
        "name": (os.environ.get("DOMAINLENS_IMAGE") or "").strip() or None,
        "tag": (os.environ.get("DOMAINLENS_IMAGE_TAG") or "").strip() or None,
        "digest": (os.environ.get("DOMAINLENS_IMAGE_DIGEST") or "").strip() or None,
        "running_in_docker": Path("/.dockerenv").exists()
        or bool(os.environ.get("DOMAINLENS_IN_DOCKER")),
    }


def parse_semver(value: str) -> tuple[int, ...]:
    cleaned = (value or "").strip().lstrip("vV").split("+", 1)[0].split("-", 1)[0]
    parts: list[int] = []
    for piece in cleaned.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer(candidate: str, current: str | None = None) -> bool:
    cur = current or get_version()
    return parse_semver(candidate) > parse_semver(cur)


def info() -> dict[str, Any]:
    """Public version payload for /api/version and health."""
    image = get_image_info()
    return {
        "name": "DomainLens",
        "version": get_version(),
        "git_revision": get_git_revision(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "docker": image,
        "api": "v1",
    }


def clear_cache() -> None:
    get_version.cache_clear()

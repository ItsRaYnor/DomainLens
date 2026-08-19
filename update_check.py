"""Check for newer DomainLens releases (GitHub) and Docker update guidance."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

import version as app_version

log = logging.getLogger("domainlens.updates")

_CACHE: dict[str, Any] = {"at": 0.0, "payload": None}
_CACHE_TTL = 3600


def _updates_config() -> dict[str, Any]:
    try:
        import config as domainlens_config

        cfg = domainlens_config.load_settings().raw.get("updates") or {}
    except Exception:
        cfg = {}
    repo = (
        (os.environ.get("DOMAINLENS_UPDATE_REPO") or "").strip()
        or (cfg.get("github_repo") or "ItsRaYnor/DomainLens")
    )
    return {
        "enabled": bool(cfg.get("check_enabled", True))
        if os.environ.get("DOMAINLENS_UPDATE_CHECK") is None
        else os.environ.get("DOMAINLENS_UPDATE_CHECK", "1") not in {"0", "false", "False"},
        "github_repo": repo,
        "include_prereleases": bool(cfg.get("include_prereleases", False)),
        "docker_image": (cfg.get("docker_image") or os.environ.get("DOMAINLENS_IMAGE") or "domainlens").strip(),
        "compose_file": (cfg.get("compose_file") or "docker-compose.yml").strip(),
    }


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"DomainLens/{app_version.get_version()}",
    }
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("DOMAINLENS_GITHUB_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _rate_limited(resp) -> bool:
    return resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0"


def _fetch_latest_release(repo: str, *, include_prereleases: bool = False):
    """Return (release, error).

    error is None on success, otherwise a human-readable reason. "Nothing
    published yet" and "could not reach GitHub" are genuinely different
    situations and used to collapse into the same network-sounding message,
    which sent people looking for a connectivity problem that wasn't there.
    """
    base = f"https://api.github.com/repos/{repo}"
    reachable = False
    try:
        if include_prereleases:
            resp = requests.get(
                f"{base}/releases",
                headers=_github_headers(),
                timeout=8,
                params={"per_page": 5},
            )
            if _rate_limited(resp):
                return None, "GitHub API rate limit reached — set GITHUB_TOKEN to raise it"
            if resp.status_code == 200:
                reachable = True
                for item in resp.json() or []:
                    if item.get("draft"):
                        continue
                    return item, None

        resp = requests.get(f"{base}/releases/latest", headers=_github_headers(), timeout=8)
        if _rate_limited(resp):
            return None, "GitHub API rate limit reached — set GITHUB_TOKEN to raise it"
        if resp.status_code == 200:
            return resp.json(), None
        if resp.status_code == 404:
            # Either the repo has no published release, or the repo itself is
            # not visible. The tags call below tells those apart.
            reachable = True
        elif resp.status_code == 401:
            return None, "GitHub rejected the configured token (GITHUB_TOKEN)"

        # Fallback: tags when releases are empty
        resp = requests.get(
            f"{base}/tags",
            headers=_github_headers(),
            timeout=8,
            params={"per_page": 5},
        )
        if _rate_limited(resp):
            return None, "GitHub API rate limit reached — set GITHUB_TOKEN to raise it"
        if resp.status_code == 200:
            reachable = True
            tags = resp.json() or []
            if tags:
                name = tags[0].get("name") or ""
                return {
                    "tag_name": name,
                    "html_url": f"https://github.com/{repo}/releases/tag/{name}",
                    "name": name,
                    "prerelease": False,
                    "published_at": None,
                }, None
        elif resp.status_code == 404:
            return None, f"Repository {repo} not found or not public"
    except requests.RequestException as exc:
        log.warning("Update check failed for %s: %s", repo, exc)
        return None, "Could not reach GitHub (network error)"

    if reachable:
        return None, (
            f"No releases or tags published in {repo} yet, so there is nothing to "
            "compare against. Publish a release or push a vX.Y.Z tag to enable "
            "update checks."
        )
    return None, "Could not reach GitHub releases (network or rate limit)"


def docker_update_commands(cfg: dict[str, Any] | None = None) -> list[str]:
    cfg = cfg or _updates_config()
    image = cfg.get("docker_image") or "domainlens"
    compose = cfg.get("compose_file") or "docker-compose.yml"
    return [
        f"# Preferred: rebuild from Git (preserves /data volume)",
        f"git pull origin main",
        f"docker compose -f {compose} build --pull",
        f"docker compose -f {compose} up -d",
        f"# Or run: ./scripts/docker-update.sh",
        f"# Image label reference: {image}:latest",
    ]


def check_for_updates(*, force: bool = False) -> dict[str, Any]:
    """Return update status relative to the running app version."""
    cfg = _updates_config()
    current = app_version.get_version()
    now = time.time()
    if not force and _CACHE["payload"] and (now - float(_CACHE["at"])) < _CACHE_TTL:
        cached = dict(_CACHE["payload"])
        cached["cached"] = True
        return cached

    result: dict[str, Any] = {
        "enabled": cfg["enabled"],
        "current_version": current,
        "latest_version": None,
        "update_available": False,
        "release_url": None,
        "release_name": None,
        "published_at": None,
        "github_repo": cfg["github_repo"],
        "docker": app_version.get_image_info(),
        "docker_commands": docker_update_commands(cfg),
        "checked_at": None,
        "error": None,
        "cached": False,
    }
    if not cfg["enabled"]:
        result["error"] = "Update checks disabled"
        return result

    release, fetch_error = _fetch_latest_release(
        cfg["github_repo"],
        include_prereleases=cfg["include_prereleases"],
    )
    result["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not release:
        result["error"] = fetch_error
        _CACHE.update({"at": now, "payload": result})
        return result

    tag = (release.get("tag_name") or release.get("name") or "").strip()
    latest = tag.lstrip("vV")
    result["latest_version"] = latest
    result["release_name"] = release.get("name") or tag
    result["release_url"] = release.get("html_url")
    result["published_at"] = release.get("published_at")
    result["prerelease"] = bool(release.get("prerelease"))
    result["update_available"] = app_version.is_newer(latest, current) if latest else False

    _CACHE.update({"at": now, "payload": result})
    return result


def clear_cache() -> None:
    _CACHE["at"] = 0.0
    _CACHE["payload"] = None

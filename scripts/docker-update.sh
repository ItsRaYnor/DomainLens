#!/usr/bin/env bash
# Update DomainLens Docker deployment while preserving the /data volume.
# Usage:
#   ./scripts/docker-update.sh
#   COMPOSE_FILE=docker-compose.portainer.yml ./scripts/docker-update.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
BRANCH="${DOMAINLENS_UPDATE_BRANCH:-main}"

echo "==> DomainLens Docker update"
echo "    compose: ${COMPOSE_FILE}"
echo "    branch:  ${BRANCH}"

if [[ -d .git ]]; then
  echo "==> git fetch / pull (${BRANCH})"
  git fetch --tags origin "${BRANCH}" || true
  git pull --ff-only origin "${BRANCH}" || {
    echo "WARNING: git pull failed — continuing with local tree" >&2
  }
fi

if [[ -f VERSION ]]; then
  echo "==> App version file: $(tr -d '\n' < VERSION)"
fi

echo "==> Building image"
docker compose -f "${COMPOSE_FILE}" build --pull

echo "==> Recreating container (volumes preserved)"
docker compose -f "${COMPOSE_FILE}" up -d --remove-orphans

echo "==> Health check"
sleep 2
PORT_LINE="$(docker compose -f "${COMPOSE_FILE}" port domainlens 5000 2>/dev/null || true)"
HOST_PORT="${PORT_LINE##*:}"
HOST_PORT="${HOST_PORT:-5050}"
if curl -fsS "http://127.0.0.1:${HOST_PORT}/api/version" >/tmp/domainlens-version.json 2>/dev/null; then
  echo "==> Running version:"
  cat /tmp/domainlens-version.json
  echo
else
  echo "WARNING: could not reach /api/version on :${HOST_PORT}" >&2
fi

echo "==> Done. Data volume was not removed."

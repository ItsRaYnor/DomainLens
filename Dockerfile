# Debian-based image (python:3.12-slim-bookworm). Prefer this over Alpine on
# Synology/Portainer: better OpenSSL/whois compatibility and fewer musl issues.
FROM python:3.12-slim-bookworm

ARG DOMAINLENS_VERSION=0.0.0-dev
ARG DOMAINLENS_GIT_SHA=
ARG DOMAINLENS_BUILD_DATE=

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOMAINLENS_DB=/data/domainlens.db \
    DOMAINLENS_HOST=0.0.0.0 \
    DOMAINLENS_PORT=5000 \
    DOMAINLENS_MONITOR_AUTORUN=1 \
    DOMAINLENS_MONITOR_POLL_SECONDS=60 \
    DOMAINLENS_LOG_LEVEL=INFO \
    DOMAINLENS_DATA_DIR=/data \
    DOMAINLENS_IN_DOCKER=1 \
    DOMAINLENS_VERSION=${DOMAINLENS_VERSION} \
    DOMAINLENS_GIT_SHA=${DOMAINLENS_GIT_SHA} \
    DOMAINLENS_IMAGE=domainlens \
    DOMAINLENS_IMAGE_TAG=latest

LABEL org.opencontainers.image.title="DomainLens" \
      org.opencontainers.image.description="Domain Intelligence Toolkit" \
      org.opencontainers.image.version="${DOMAINLENS_VERSION}" \
      org.opencontainers.image.revision="${DOMAINLENS_GIT_SHA}" \
      org.opencontainers.image.created="${DOMAINLENS_BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/ItsRaYnor/DomainLens" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# whois CLI improves python-whois reliability; curl is used by HEALTHCHECK
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        whois \
        curl \
        ca-certificates \
        gosu \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin domainlens \
    && chown -R domainlens:domainlens /app /data \
    && chmod +x /app/docker-entrypoint.sh /app/scripts/docker-update.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${DOMAINLENS_PORT}/health" || exit 1

# Start as root so Synology bind mounts can be chowned, then drop to domainlens.
ENTRYPOINT ["/app/docker-entrypoint.sh"]

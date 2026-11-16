# Docker deploy & update guide

## Versioning

- App version lives in [`VERSION`](../VERSION) (semver).
- Runtime: `GET /api/version` and `GET /health` include `version`.
- Override with `DOMAINLENS_VERSION` / `DOMAINLENS_GIT_SHA` / `DOMAINLENS_IMAGE*` env vars (set automatically in Docker builds).

## Local / generic Compose

```bash
docker compose up --build -d
# http://127.0.0.1:5050
```

Update in place (keeps named volume `domainlens-data`):

```bash
./scripts/docker-update.sh
# or:
git pull
docker compose build --pull && docker compose up -d
```

## Synology / Portainer

Use [`docker-compose.portainer.yml`](../docker-compose.portainer.yml). Bind mount `/volume1/docker/domainlens` is preserved across image rebuilds.

```bash
COMPOSE_FILE=docker-compose.portainer.yml ./scripts/docker-update.sh
```

Watchtower is **disabled** by default (`com.centurylinklabs.watchtower.enable=false`) so updates stay intentional. To enable automatic image pulls, change that label to `"true"` and run a Watchtower sidecar — only after pinning a registry image tag.

## Docker Hub images (no build on the NAS)

`.github/workflows/docker-publish.yml` builds and pushes a multi-arch (`linux/amd64` + `linux/arm64`) image to Docker Hub when a push to `main` carries a version that has not been released yet, tagged `latest` and the app version (from [`VERSION`](../VERSION)). A push that keeps the version publishes nothing. The commit is in the image's `org.opencontainers.image.revision` label.

Requires two repo secrets (**Settings → Secrets and variables → Actions**):

| Secret | Value |
|--------|-------|
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub **access token** (Account Settings → Security → New Access Token) — not the account password |

Then deploy [`docker-compose.dockerhub.yml`](../docker-compose.dockerhub.yml) in Portainer (Web editor is fine — no build context needed, it only pulls). Update by clicking **Pull and redeploy** on the stack, or:

```bash
docker pull itsraynor/domainlens:latest
docker compose -f docker-compose.dockerhub.yml up -d
```

### Verifying an image

Every published image is signed by the workflow that built it, with
[cosign](https://docs.sigstore.dev/) and no long-lived key: the signature names the
repository and the workflow file, and is recorded in the public Sigstore transparency log.
An image pushed by anyone else -- with a stolen Docker Hub token, say -- carries no such
signature.

```bash
cosign verify itsraynor/domainlens:0.1.22 \
  --certificate-identity-regexp '^https://github.com/ItsRaYnor/DomainLens/\.github/workflows/docker-publish\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Versions before 0.1.22 were published unsigned.

## In-app update check

Admins: **Settings → Updates**, or `GET /api/updates/check`.

Compares the running `VERSION` to the latest GitHub release on `updates.github_repo` (default `ItsRaYnor/DomainLens`). Response includes suggested `docker compose` commands.

Env overrides:

| Variable | Meaning |
|----------|---------|
| `DOMAINLENS_UPDATE_CHECK` | `0` to disable checks |
| `DOMAINLENS_UPDATE_REPO` | `owner/repo` |
| `DOMAINLENS_GITHUB_TOKEN` | optional, raises GitHub API rate limits |
| `DOMAINLENS_VERSION` | force reported version |
| `DOMAINLENS_IN_DOCKER=1` | mark runtime as container |

## Image labels

The Dockerfile sets OCI labels (`org.opencontainers.image.version`, revision, source) so Portainer / registries show the DomainLens version next to the image.

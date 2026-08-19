# Migrating from NetProbe to DomainLens (0.0.1)

The tool was renamed. Every `NETPROBE_*` environment variable became
`DOMAINLENS_*`, the image became `<your-dockerhub-user>/domainlens`, and the
default database filename became `domainlens.db`.

**There is no fallback to the old names.** That was a deliberate choice: an
alias layer would mean two spellings of every setting living side by side for
years, and a typo in one of them failing silently. The cost is that the stack
has to be updated in one go, which is what this page is for.

## Two things that lose data if they are wrong

Both fail quietly rather than loudly, so check them before you deploy.

### 1. `DOMAINLENS_SECRET_KEY` must carry the *exact* value of `NETPROBE_SECRET_KEY`

Stored integration credentials are encrypted with a key derived from it. A
different value does not raise an error — it makes every stored credential
unreadable and logs everyone out. Copy the value across verbatim.

If you have lost it, you can still proceed: re-enter the integration
credentials afterwards from **Settings → Integrations**. Nothing else depends
on it.

### 2. `DOMAINLENS_DB` must point at your existing database

Scans, monitors, users, MFA secrets and settings all live in that one file. A
path that does not exist is not an error — SQLite creates an empty database and
the app starts up looking brand new.

## Order of work on the NAS

Copy rather than move, so the old container can still be started if something
disappoints.

```sh
# 1. Stop the old stack (Portainer → Stacks → netprobe → Stop)

# 2. Copy the database beside the original
cp /volume1/docker/netprobe/netprobe.db /volume1/docker/netprobe/domainlens.db

# 3. Deploy the DomainLens stack with the variables below
# 4. Check the app: your scan history and monitors should be there
# 5. Only then remove the old stack and delete the old Docker Hub repository
```

If you would rather not copy the file, set `DOMAINLENS_DB=/data/netprobe.db`
instead and leave it where it is. The filename carries no meaning to the app.

## Variable names, old → new

| Old | New |
| --- | --- |
| `NETPROBE_ACTIVE_SCAN_ENABLED` | `DOMAINLENS_ACTIVE_SCAN_ENABLED` |
| `NETPROBE_BASE_URL` | `DOMAINLENS_BASE_URL` |
| `NETPROBE_BUILD_DATE` | `DOMAINLENS_BUILD_DATE` |
| `NETPROBE_CONFIG` | `DOMAINLENS_CONFIG` |
| `NETPROBE_DATA_DIR` | `DOMAINLENS_DATA_DIR` |
| `NETPROBE_DB` | `DOMAINLENS_DB` |
| `NETPROBE_DISABLE_SCHEDULER` | `DOMAINLENS_DISABLE_SCHEDULER` |
| `NETPROBE_GITHUB_TOKEN` | `DOMAINLENS_GITHUB_TOKEN` |
| `NETPROBE_GIT_SHA` | `DOMAINLENS_GIT_SHA` |
| `NETPROBE_HOST` | `DOMAINLENS_HOST` |
| `NETPROBE_IMAGE` | `DOMAINLENS_IMAGE` |
| `NETPROBE_IMAGE_DIGEST` | `DOMAINLENS_IMAGE_DIGEST` |
| `NETPROBE_IMAGE_TAG` | `DOMAINLENS_IMAGE_TAG` |
| `NETPROBE_IN_DOCKER` | `DOMAINLENS_IN_DOCKER` |
| `NETPROBE_JS_SCAN_ENABLED` | `DOMAINLENS_JS_SCAN_ENABLED` |
| `NETPROBE_LOCALE` | `DOMAINLENS_LOCALE` |
| `NETPROBE_LOG_LEVEL` | `DOMAINLENS_LOG_LEVEL` |
| `NETPROBE_MONITOR_AUTORUN` | `DOMAINLENS_MONITOR_AUTORUN` |
| `NETPROBE_MONITOR_POLL_SECONDS` | `DOMAINLENS_MONITOR_POLL_SECONDS` |
| `NETPROBE_PORT` | `DOMAINLENS_PORT` |
| `NETPROBE_PUBLIC_URL` | `DOMAINLENS_PUBLIC_URL` |
| `NETPROBE_RATE_LIMIT` | `DOMAINLENS_RATE_LIMIT` |
| `NETPROBE_RATE_WINDOW` | `DOMAINLENS_RATE_WINDOW` |
| `NETPROBE_SCHEMA` | `DOMAINLENS_SCHEMA` |
| `NETPROBE_SECRET_KEY` | `DOMAINLENS_SECRET_KEY` ⚠ same value |
| `NETPROBE_TRUSTED_PROXY_HOPS` | `DOMAINLENS_TRUSTED_PROXY_HOPS` |
| `NETPROBE_UPDATE_BRANCH` | `DOMAINLENS_UPDATE_BRANCH` |
| `NETPROBE_UPDATE_CHECK` | `DOMAINLENS_UPDATE_CHECK` |
| `NETPROBE_UPDATE_REPO` | `DOMAINLENS_UPDATE_REPO` |
| `NETPROBE_URL_FIELD` | `DOMAINLENS_URL_FIELD` |
| `NETPROBE_VERSION` | `DOMAINLENS_VERSION` |
| `NETPROBE_WEAK_AUTH_ENABLED` | `DOMAINLENS_WEAK_AUTH_ENABLED` |
| `NETPROBE_WSGI_THREADS` | `DOMAINLENS_WSGI_THREADS` |

Variables without the prefix are unchanged — `LOCAL_ADMIN_EMAIL`,
`LOCAL_ADMIN_PASSWORD`, the OAuth and SCIM settings, and the integration API
keys all keep their names.

## Also worth changing

- **Image**: `itsraynor/netprobe` → `itsraynor/domainlens`. Watchtower will not
  follow the rename on its own; point it at the new image.
- **Container and stack name**, and the bind-mount path if you like them tidy.
  Neither affects the app.
- **Update checks**: `updates.github_repo` now defaults to
  `ItsRaYnor/DomainLens` and `updates.docker_image` to `domainlens`. If you had
  overridden either in **Settings → Automation → Updates**, update them, or the
  app will keep checking a repository that no longer exists.
- **ServiceNow**: the `servicenow.netprobe_url_field` setting is now
  `servicenow.domainlens_url_field`. The value — the name of the field on your
  ServiceNow side — does not change.

## What did not change

The database schema. DomainLens 0.0.1 opens a NetProbe database as it is; the
only new column is a per-user display preference, added automatically on first
start. Downgrading back to a NetProbe image works too — SQLite ignores a column
the older code does not know about.

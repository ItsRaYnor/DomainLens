#!/bin/sh
set -eu

DATA_DIR="${DOMAINLENS_DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# On Synology bind mounts, the shared-folder owner is often not UID 1000.
# If we start as root, normalize ownership then drop privileges.
if [ "$(id -u)" = "0" ]; then
  chown -R domainlens:domainlens "$DATA_DIR" || true
  exec gosu domainlens python app.py
fi

exec python app.py

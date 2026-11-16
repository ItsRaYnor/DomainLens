# The vulnerability scanner CI runs (.github/workflows/tests.yml reads the
# image from the FROM line below; nothing is built from this file).
#
# Pinned to a release and its digest: `latest` let whatever was pushed under
# that tag run in CI with the Docker socket mounted, which is the kind of
# unpinned dependency the rest of this pipeline refuses. It lives in a
# Dockerfile so Dependabot proposes updates, as it does for the base image.
FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb

"""Shared pytest setup for the unittest-style test modules."""

import os

import pytest


@pytest.fixture(autouse=True, scope="module")
def _restore_environment():
    """Undo whatever a test module did to os.environ.

    Modules set DOMAINLENS_DB, DOMAINLENS_DISABLE_SCHEDULER and the like for
    their own run. One that forgot to put a value back changed what every
    later module saw, so a test passed or failed depending on the order the
    files ran in.
    """
    before = dict(os.environ)
    yield
    for key in set(os.environ) - set(before):
        del os.environ[key]
    for key, value in before.items():
        if os.environ.get(key) != value:
            os.environ[key] = value

"""Roles, ordered by what they may do.

  viewer  reads scans, reports, monitors and trends; changes nothing
  user    the analyst: also scans, manages monitors, imports findings
  admin   also settings, users, credentials, the audit log

Each role includes everything below it, so a check is "at least X" and never a
list of names that has to be kept in step with every new role. "user" keeps its
name, rather than becoming "analyst", because it is stored on every existing
account and sent by SCIM directories that already provision it; the interface
calls it Analyst.
"""

from __future__ import annotations

VIEWER = "viewer"
USER = "user"
ADMIN = "admin"

ROLES = (VIEWER, USER, ADMIN)
_RANK = {name: rank for rank, name in enumerate(ROLES)}

LABELS = {VIEWER: "Viewer", USER: "Analyst", ADMIN: "Admin"}


def normalize(value, default=USER):
    """A known role name, or the default for anything else.

    "analyst" is accepted as a synonym for "user" because that is what the
    interface calls it and what an operator will type into a directory.
    """
    name = str(value or "").strip().lower()
    if name == "analyst":
        name = USER
    return name if name in _RANK else default


def rank(value):
    """Position in the order; an unknown role ranks below viewer."""
    return _RANK.get(str(value or "").strip().lower(), -1)


def at_least(role, minimum):
    return rank(role) >= rank(minimum)


def lower_of(a, b):
    """The less privileged of two roles, for tokens scoped below their owner."""
    return a if rank(a) <= rank(b) else b

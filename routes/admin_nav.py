"""Sub-navigation shared by every admin page.

Admin pages used to be reachable only from two header buttons. With audit
and domain verification added there are more of them than the header should
carry, so they share one row of tabs, defined here once.
"""

ADMIN_SUBNAV = [
    ("nav.admin_settings", "/admin/settings"),
    ("nav.admin_users", "/admin/users"),
    ("nav.admin_audit", "/admin/audit"),
]


def subnav(current):
    return [{"key": key, "href": href, "active": href == current}
            for key, href in ADMIN_SUBNAV]

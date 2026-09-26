"""Who may change what.

There were two roles, and "user" could do everything short of settings --
including wiping the entire scan history. An organisation that wanted to give
management or auditors a look at the reports had to hand them the ability to
start scans against arbitrary domains and delete the evidence.
"""

import unittest
from unittest import mock

import roles
from enterprise_harness import EnterpriseAppTestCase


class RoleOrderTests(unittest.TestCase):
    def test_each_role_includes_the_ones_below_it(self):
        self.assertTrue(roles.at_least("admin", "user"))
        self.assertTrue(roles.at_least("user", "viewer"))
        self.assertFalse(roles.at_least("viewer", "user"))

    def test_an_unknown_role_holds_nothing(self):
        """A typo in a directory attribute must not grant analyst rights."""
        self.assertFalse(roles.at_least("superuser", "viewer"))

    def test_analyst_is_accepted_as_the_stored_user_role(self):
        self.assertEqual("user", roles.normalize("Analyst"))


class ViewerIsReadOnlyTests(EnterpriseAppTestCase):
    def test_a_viewer_cannot_start_a_scan(self):
        self.login_as("viewer")
        resp = self.client.post("/api/scan/start", json={"domain": "example.com"})
        self.assertEqual(403, resp.status_code)

    def test_a_viewer_cannot_create_a_monitor(self):
        self.login_as("viewer")
        resp = self.client.post("/api/monitors", json={"domain": "example.com"})
        self.assertEqual(403, resp.status_code)

    def test_a_viewer_can_still_read_history(self):
        self.login_as("viewer")
        self.assertEqual(200, self.client.get("/api/history").status_code)

    def test_a_viewer_can_still_change_their_own_preferences(self):
        """Read-only means the organisation's data, not their own account."""
        self.login_as("viewer")
        resp = self.client.post("/api/locale", json={"locale": "nl"})
        self.assertEqual(200, resp.status_code)

    def test_an_analyst_is_not_blocked_by_the_viewer_rule(self):
        self.login_as("user")
        with mock.patch.object(self.app_module.scan_jobs, "start",
                               return_value={"job_id": "x"}):
            resp = self.client.post("/api/scan/start", json={"domain": "example.com"})
        self.assertEqual(202, resp.status_code)


class ClearingHistoryIsAdminOnlyTests(EnterpriseAppTestCase):
    def test_an_analyst_cannot_wipe_every_scan(self):
        self.login_as("user")
        self.assertEqual(403, self.client.delete("/api/history").status_code)

    def test_an_admin_can(self):
        self.login_as("admin")
        self.assertEqual(200, self.client.delete("/api/history").status_code)


class RoleRefusedPageTests(EnterpriseAppTestCase):
    def test_a_signed_in_caller_without_the_role_gets_403_not_a_login_loop(self):
        """The refusal redirected to /login?next=<page>, and the login page
        sends a signed-in caller straight back to next: a Viewer opening
        /admin/domains bounced until the browser gave up, writing an
        access.denied audit row on every hop."""
        self.login_as("viewer")
        resp = self.client.get("/admin/domains")
        self.assertEqual(403, resp.status_code)

    def test_an_anonymous_caller_is_still_sent_to_sign_in(self):
        resp = self.client.get("/admin/audit")
        self.assertEqual(302, resp.status_code)
        self.assertIn("/login", resp.headers["Location"])


class RoleChangesTakeEffectImmediatelyTests(EnterpriseAppTestCase):
    """The session used to keep its role until it expired, twelve hours by
    default -- so disabling an account left it working until tomorrow."""

    def test_a_demoted_admin_loses_admin_on_the_next_request(self):
        self.login_as("admin")
        self.assertEqual(200, self.client.get("/api/admin/users").status_code)
        self.db.update_user(self.users["admin"], role="viewer")
        self.assertEqual(403, self.client.get("/api/admin/users").status_code)

    def test_a_disabled_account_is_signed_out_on_the_next_request(self):
        self.login_as("user")
        self.db.update_user(self.users["user"], enabled=False)
        self.assertEqual(401, self.client.get("/api/history").status_code)

    def test_an_oauth_session_is_not_mistaken_for_a_local_row(self):
        """GitHub ids are plain integers. An OAuth-only session whose id
        happens to equal a local admin's row id must not inherit that role."""
        admin_id = self.users["admin"]
        with self.client.session_transaction() as sess:
            sess[self.auth.SESSION_USER_KEY] = {
                "id": admin_id, "email": "someone@github.example",
                "role": "viewer", "provider": "github",
            }
        self.assertEqual(403, self.client.get("/api/admin/users").status_code)


class AdminAssignsRolesTests(EnterpriseAppTestCase):
    def test_an_admin_can_make_someone_a_viewer(self):
        self.login_as("admin")
        resp = self.client.post(f"/admin/users/{self.users['user']}/role",
                                data={"role": "viewer"})
        self.assertEqual(302, resp.status_code)
        self.assertEqual("viewer", self.db.get_user(self.users["user"])["role"])

    def test_an_admin_cannot_demote_themselves(self):
        """Otherwise the last admin can lock everyone out of this page."""
        self.login_as("admin")
        self.client.post(f"/admin/users/{self.users['admin']}/role", data={"role": "user"})
        self.assertEqual("admin", self.db.get_user(self.users["admin"])["role"])

    def test_an_unknown_role_is_refused_rather_than_defaulted(self):
        self.login_as("admin")
        self.client.post(f"/admin/users/{self.users['viewer']}/role", data={"role": "root"})
        self.assertEqual("viewer", self.db.get_user(self.users["viewer"])["role"])


class ScimViewerMappingTests(unittest.TestCase):
    def test_a_viewer_group_provisions_a_viewer(self):
        import scim
        self.assertEqual("viewer", scim._role_from_payload(
            {"roles": [{"value": "Viewer"}]}, "user"))

    def test_a_named_viewer_group_is_not_promoted_to_analyst(self):
        """Admin matched anywhere in the name, viewer only exactly: a group
        called "DomainLens-Viewers" fell through to the default role and
        gave read-only staff the right to scan and delete."""
        import scim
        for name in ("DomainLens-Viewers", "domainlens viewer", "DL Read-Only"):
            with self.subTest(name=name):
                self.assertEqual("viewer", scim._role_from_payload(
                    {"roles": [{"value": name}]}, "user"))

    def test_admin_still_wins_over_viewer(self):
        import scim
        self.assertEqual("admin", scim._role_from_payload(
            {"roles": ["viewer", "DomainLens Admin"]}, "user"))

    def test_no_roles_falls_back_to_the_default(self):
        import scim
        self.assertEqual("viewer", scim._role_from_payload({}, "viewer"))


if __name__ == "__main__":
    unittest.main()

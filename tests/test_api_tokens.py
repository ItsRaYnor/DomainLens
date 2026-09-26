"""Scripts and pipelines get their own credentials.

Automation could reach the API only with a copied session cookie: the
person's full role, no name to recognise it by, no revocation short of
signing out, and no record of which job used it.
"""

import re
import unittest
from datetime import datetime, timedelta, timezone

from enterprise_harness import EnterpriseAppTestCase


class TokenTests(EnterpriseAppTestCase):
    def _issue(self, role_of_owner="user", **kwargs):
        import api_tokens
        owner = self.db.get_user(self.users[role_of_owner])
        raw, record = api_tokens.create(owner, name=kwargs.pop("name", "ci"), **kwargs)
        return raw, record

    def _get(self, path, raw):
        return self.client.get(path, headers={"Authorization": f"Bearer {raw}"})

    def test_a_token_authenticates_an_api_call(self):
        raw, _ = self._issue()
        self.assertEqual(200, self._get("/api/history", raw).status_code)

    def test_only_the_hash_is_stored(self):
        import sqlite3
        raw, _ = self._issue()
        conn = sqlite3.connect(self.db._db_path())
        dump = "\n".join(conn.iterdump())
        conn.close()
        self.assertNotIn(raw, dump)

    def test_a_revoked_token_is_refused_even_with_a_session(self):
        """Falling back to the cookie would make revocation look like it
        did nothing whenever the same browser is signed in."""
        import api_tokens
        raw, record = self._issue()
        api_tokens.revoke(record["id"])
        self.login_as("user")
        self.assertEqual(401, self._get("/api/history", raw).status_code)

    def test_an_expired_token_is_refused(self):
        raw, record = self._issue()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with self.db._connect() as conn:
            conn.execute("UPDATE api_tokens SET expires_at=? WHERE id=?", (past, record["id"]))
        self.assertEqual(401, self._get("/api/history", raw).status_code)

    def test_a_disabled_owner_disables_the_token(self):
        raw, _ = self._issue()
        self.db.update_user(self.users["user"], enabled=False)
        self.assertEqual(401, self._get("/api/history", raw).status_code)

    def test_demoting_the_owner_demotes_the_token(self):
        raw, _ = self._issue("admin", role="admin")
        self.assertEqual(200, self._get("/api/admin/audit", raw).status_code)
        self.db.update_user(self.users["admin"], role="user")
        self.assertEqual(403, self._get("/api/admin/audit", raw).status_code)

    def test_a_viewer_token_on_an_analyst_account_is_read_only(self):
        raw, _ = self._issue(role="viewer")
        resp = self.client.post("/api/scan/start", json={"domain": "example.com"},
                                headers={"Authorization": f"Bearer {raw}"})
        self.assertEqual(403, resp.status_code)

    def test_a_token_cannot_outrank_its_owner(self):
        with self.assertRaises(ValueError):
            self._issue("viewer", role="admin")

    def test_a_token_cannot_live_forever(self):
        with self.assertRaises(ValueError):
            self._issue(days=10000)

    def test_a_token_cannot_render_pages(self):
        """Tokens are for the API; account and admin pages need a person."""
        raw, _ = self._issue("admin", role="admin")
        resp = self.client.get("/admin/users", headers={"Authorization": f"Bearer {raw}"})
        self.assertEqual(403, resp.status_code)

    def test_a_token_cannot_mint_more_tokens(self):
        """One leaked CI secret must not become many long-lived ones."""
        raw, _ = self._issue("admin", role="admin")
        resp = self.client.post("/api/tokens", json={"name": "more"},
                                headers={"Authorization": f"Bearer {raw}"})
        self.assertEqual(403, resp.status_code)

    def test_actions_through_a_token_are_audited_as_token(self):
        import audit_log
        raw, _ = self._issue("admin", role="admin")
        self.client.delete("/api/history", headers={"Authorization": f"Bearer {raw}"})
        entry = audit_log.list_entries(action="history.clear")["entries"][0]
        self.assertEqual("token", entry["auth_method"])
        self.assertEqual("admin@example.com", entry["actor_email"])

    def test_scim_bearer_tokens_are_left_to_scim(self):
        """Only dlk_ tokens are ours; SCIM's own bearer must reach SCIM."""
        resp = self.client.get("/scim/v2/Users", headers={"Authorization": "Bearer something-else"})
        self.assertNotEqual(b"Invalid, expired or revoked API token", resp.data)


class TokenPagesTests(EnterpriseAppTestCase):
    def test_creating_a_token_shows_it_once(self):
        self.login_as("user")
        self.client.post("/account/tokens", data={"name": "ci", "role": "user", "days": "30"})
        first = self.client.get("/account").get_data(as_text=True)
        second = self.client.get("/account").get_data(as_text=True)
        shown = re.search(r"dlk_[A-Za-z0-9_-]{40,}", first)
        self.assertIsNotNone(shown, "the new token was not shown after creating it")
        self.assertNotIn(shown.group(0), second)

    def test_the_admin_sees_every_token(self):
        import api_tokens
        api_tokens.create(self.db.get_user(self.users["user"]), name="someones-ci")
        self.login_as("admin")
        self.assertIn(b"someones-ci", self.client.get("/admin/users").data)


class OpenApiTests(EnterpriseAppTestCase):
    def test_every_documented_operation_exists(self):
        """A spec that describes endpoints that are gone sends integrators
        chasing 404s."""
        import openapi
        rules = {}
        for rule in self.app_module.app.url_map.iter_rules():
            path = rule.rule.replace("<int:", "{").replace("<path:", "{").replace("<", "{").replace(">", "}")
            rules.setdefault(path, set()).update(m.lower() for m in rule.methods)
        for path, ops in openapi.spec()["paths"].items():
            self.assertIn(path, rules, f"{path} is documented but not routed")
            for method in ops:
                self.assertIn(method, rules[path], f"{method.upper()} {path} is documented but not routed")

    def test_the_spec_is_served(self):
        self.login_as("viewer")
        body = self.client.get("/api/openapi.json").get_json()
        self.assertEqual("3.1.0", body["openapi"])


if __name__ == "__main__":
    unittest.main()

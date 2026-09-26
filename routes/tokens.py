"""Creating, listing and revoking personal API tokens.

Minting a token needs a signed-in browser session. A token that could mint
further tokens would turn one leaked CI secret into as many long-lived ones
as the attacker cares to make, each surviving the revocation of the first.
"""

from __future__ import annotations

from flask import g, jsonify, redirect, request, session, url_for

import api_tokens
import audit_log
import roles

SESSION_NEW_TOKEN = "api_token_once"


def _owner_row(auth, db):
    """The users-table row for the caller, or None for a session without one."""
    user = auth.current_user()
    if not user:
        return None
    if not (user.get("db_user") or user.get("provider") in {"local", "api_token"}):
        return None
    try:
        return db.get_user(int(user["id"]))
    except (TypeError, ValueError):
        return None


def register(app, *, auth, db):
    def _via_token():
        return getattr(g, "api_token_user", None) is not None

    def _create(row, form):
        raw, record = api_tokens.create(
            row, name=form.get("name"), role=form.get("role") or None,
            days=form.get("days") or api_tokens.DEFAULT_DAYS)
        audit_log.record("token.create", target_type="api_token", target_id=record["id"],
                         details={"name": record["name"], "role": record["role"],
                                  "expires_at": record["expires_at"]})
        return raw, record

    @app.route("/account/tokens", methods=["POST"])
    def account_token_create():
        row = _owner_row(auth, db)
        if not row:
            return redirect(url_for("account_security",
                                    error="API tokens need an account in the user list; ask an admin to provision you."))
        try:
            raw, _ = _create(row, request.form)
        except ValueError as exc:
            return redirect(url_for("account_security", error=str(exc)))
        # Shown on the next page load and then gone, like MFA backup codes.
        session[SESSION_NEW_TOKEN] = raw
        return redirect(url_for("account_security", message="token_created") + "#api-tokens")

    @app.route("/account/tokens/<int:token_id>/revoke", methods=["POST"])
    def account_token_revoke(token_id):
        row = _owner_row(auth, db)
        if row and api_tokens.revoke(token_id, user_id=row["id"]):
            audit_log.record("token.revoke", target_type="api_token", target_id=token_id)
        return redirect(url_for("account_security", message="token_revoked") + "#api-tokens")

    @app.route("/api/tokens", methods=["GET"])
    def api_tokens_list():
        row = _owner_row(auth, db)
        if not row:
            return jsonify({"error": "No account to hold tokens"}), 400
        return jsonify({"tokens": api_tokens.list_for_user(row["id"])})

    @app.route("/api/tokens", methods=["POST"])
    def api_tokens_create():
        if _via_token():
            return jsonify({"error": "Tokens can only be created from a signed-in session"}), 403
        row = _owner_row(auth, db)
        if not row:
            return jsonify({"error": "No account to hold tokens"}), 400
        try:
            raw, record = _create(row, request.get_json(silent=True) or {})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({**record, "token": raw,
                        "warning": "This is the only time the token is shown."}), 201

    @app.route("/api/tokens/<int:token_id>", methods=["DELETE"])
    def api_tokens_revoke(token_id):
        row = _owner_row(auth, db)
        if not row or not api_tokens.revoke(token_id, user_id=row["id"]):
            return jsonify({"error": "Token not found"}), 404
        audit_log.record("token.revoke", target_type="api_token", target_id=token_id)
        return jsonify({"revoked": True})

    @app.route("/api/admin/tokens", methods=["GET"])
    @auth.require_admin
    def api_admin_tokens():
        return jsonify({"tokens": api_tokens.list_all()})

    @app.route("/admin/tokens/<int:token_id>/revoke", methods=["POST"])
    @auth.require_admin
    def admin_token_revoke(token_id):
        if api_tokens.revoke(token_id):
            audit_log.record("token.revoke", target_type="api_token", target_id=token_id,
                             details={"by_admin": True})
        return redirect(url_for("admin_users_page", message="user_updated") + "#api-tokens")

    @app.route("/api/admin/tokens/<int:token_id>", methods=["DELETE"])
    @auth.require_admin
    def api_admin_token_revoke(token_id):
        if not api_tokens.revoke(token_id):
            return jsonify({"error": "Token not found"}), 404
        audit_log.record("token.revoke", target_type="api_token", target_id=token_id,
                         details={"by_admin": True})
        return jsonify({"revoked": True})

    @app.context_processor
    def _token_roles():
        # The roles a caller may issue a token with: their own and below.
        user = auth.current_user() or {}
        own = roles.normalize(user.get("role"))
        return {"token_roles": [(r, roles.LABELS[r]) for r in roles.ROLES if roles.at_least(own, r)]}

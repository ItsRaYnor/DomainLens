"""User administration: the list, adding users, roles, resets and removal.

Moved out of app.py as it was; the endpoint names are unchanged, so every
url_for("admin_users_page") and template link keeps working.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import jsonify, redirect, render_template, request, url_for

import api_tokens
import audit_log
import db
import roles
from routes import admin_nav


def register(app, *, auth):
    @app.route("/admin/users")
    @auth.require_admin
    def admin_users_page():
        return render_template(
            "admin_users.html",
            section="admin",
            subnav=admin_nav.subnav("/admin/users"),
            users=db.list_users(),
            all_tokens=api_tokens.list_all(),
            password_policy=auth.password_policy(),
            message=request.args.get("message"),
            error=request.args.get("error"),
        )


    @app.route("/admin/users", methods=["POST"])
    @auth.require_admin
    def admin_users_create():
        email = (request.form.get("email") or "").strip().lower()
        name = (request.form.get("name") or "").strip()
        role = roles.normalize(request.form.get("role"))
        password = request.form.get("password") or ""
        if not email:
            return redirect(url_for("admin_users_page", error="Email is required."))
        if db.get_user_by_email(email):
            return redirect(url_for("admin_users_page", error="A user with that email already exists."))
        errors = auth.validate_password(password, email)
        if errors:
            return redirect(url_for("admin_users_page", error="; ".join(errors)))
        db.create_user(
            email=email,
            password_hash=auth.hash_password(password),
            name=name or email.split("@")[0],
            role=role,
            enabled=True,
        )
        audit_log.record("user.create", target_type="user", target_id=email, details={"role": role})
        return redirect(url_for("admin_users_page", message="user_created"))


    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @auth.require_admin
    def admin_users_toggle(user_id):
        me = auth.current_user()
        if me and int(me.get("id") or 0) == user_id:
            return redirect(url_for("admin_users_page", error="You cannot disable your own account."))
        row = db.get_user(user_id)
        if not row:
            return redirect(url_for("admin_users_page", error="User not found."))
        db.update_user(user_id, enabled=not row.get("enabled"))
        audit_log.record("user.disable" if row.get("enabled") else "user.enable",
                         target_type="user", target_id=row.get("email"))
        return redirect(url_for("admin_users_page", message="user_updated"))


    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @auth.require_admin
    def admin_users_set_role(user_id):
        role = roles.normalize(request.form.get("role"), default=None)
        if role is None:
            return redirect(url_for("admin_users_page", error="Unknown role."))
        me = auth.current_user()
        if me and str(me.get("id")) == str(user_id) and role != roles.ADMIN:
            # The last step before nobody can reach this page to undo it.
            return redirect(url_for("admin_users_page", error="You cannot remove your own admin role."))
        row = db.get_user(user_id)
        if not row:
            return redirect(url_for("admin_users_page", error="User not found."))
        db.update_user(user_id, role=role)
        audit_log.record("user.role_change", target_type="user", target_id=row.get("email"),
                         details={"from": row.get("role"), "to": role})
        return redirect(url_for("admin_users_page", message="user_updated"))


    @app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
    @auth.require_admin
    def admin_users_reset_password(user_id):
        password = request.form.get("password") or ""
        row = db.get_user(user_id)
        if not row:
            return redirect(url_for("admin_users_page", error="User not found."))
        errors = auth.validate_password(password, row.get("email") or "")
        if errors:
            return redirect(url_for("admin_users_page", error="; ".join(errors)))
        db.update_user(
            user_id,
            password_hash=auth.hash_password(password),
            password_changed_at=datetime.now(timezone.utc).isoformat(),
            failed_logins=0,
            locked_until=None,
        )
        audit_log.record("user.password_reset", target_type="user", target_id=row.get("email"))
        return redirect(url_for("admin_users_page", message="password_reset"))


    @app.route("/admin/users/<int:user_id>/reset-mfa", methods=["POST"])
    @auth.require_admin
    def admin_users_reset_mfa(user_id):
        """Take MFA off an account whose owner lost the authenticator and the
        backup codes, or whose secret is compromised. The account is signed out
        everywhere; where MFA is required, it enrols again at the next sign-in."""
        me = auth.current_user() or {}
        row = db.get_user(user_id)
        if not row:
            return redirect(url_for("admin_users_page", error="User not found."))
        if str(me.get("id")) == str(user_id):
            return redirect(url_for("admin_users_page",
                                    error="Replace your own authenticator under Account; it asks for a code, this does not."))
        db.update_user(user_id, mfa_enabled=False, mfa_secret=None, mfa_backup_codes=[])
        auth.revoke_all_sessions(user_id)
        audit_log.record("user.mfa_reset", target_type="user", target_id=row.get("email"))
        return redirect(url_for("admin_users_page", message="mfa_reset"))


    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @auth.require_admin
    def admin_users_delete(user_id):
        me = auth.current_user()
        if me and int(me.get("id") or 0) == user_id:
            return redirect(url_for("admin_users_page", error="You cannot delete your own account."))
        row = db.get_user(user_id)
        db.delete_user(user_id)
        if row:
            audit_log.record("user.delete", target_type="user", target_id=row.get("email"))
        return redirect(url_for("admin_users_page", message="user_deleted"))


    @app.route("/api/admin/users")
    @auth.require_admin
    def api_admin_users():
        return jsonify({"users": db.list_users()})

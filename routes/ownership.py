"""Domain ownership verification: request, check, attest, revoke.

Analysts may start and check a verification -- publishing the DNS record or
the file is itself the proof, so no one needs to vouch for them. Attesting
without a proof and revoking are admin decisions and land in the audit log.
"""

from __future__ import annotations

from flask import jsonify, redirect, render_template, request, url_for

import audit_log
import domain_ownership
import roles
from routes.admin_nav import subnav


def register(app, *, auth, normalize_domain, is_valid_domain):
    def _domain_or_none(value):
        domain = normalize_domain(value or "")
        return domain if is_valid_domain(domain) else None

    def _actor_email():
        return (auth.current_user() or {}).get("email")

    def _check(domain):
        entry = domain_ownership.check(domain, checked_by=_actor_email())
        audit_log.record("ownership.check", target_type="domain", target_id=domain,
                         outcome="success" if entry["status"] == "verified" and not entry["expired"]
                         else "failure",
                         details={"method": entry.get("method"), "error": entry.get("last_error")})
        return entry

    @app.route("/admin/domains")
    @auth.require_role(roles.USER)
    def ownership_page():
        is_admin = (not auth.config().get("enabled")) or roles.at_least(auth.current_role(), roles.ADMIN)
        return render_template(
            "admin_domains.html",
            section="admin",
            subnav=subnav("/admin/domains") if is_admin else None,
            domains=domain_ownership.list_domains(),
            is_admin=is_admin,
            message=request.args.get("message"),
            error=request.args.get("error"),
        )

    @app.route("/admin/domains", methods=["POST"])
    @auth.require_role(roles.USER)
    def ownership_request_form():
        domain = _domain_or_none(request.form.get("domain"))
        if not domain:
            return redirect(url_for("ownership_page", error="Enter a valid domain name."))
        domain_ownership.request_verification(domain, requested_by=_actor_email())
        audit_log.record("ownership.request", target_type="domain", target_id=domain)
        return redirect(url_for("ownership_page") + f"#d-{domain}")

    @app.route("/admin/domains/<path:domain>/check", methods=["POST"])
    @auth.require_role(roles.USER)
    def ownership_check_form(domain):
        domain = _domain_or_none(domain)
        if not domain or not domain_ownership.get(domain):
            return redirect(url_for("ownership_page", error="Unknown domain."))
        entry = _check(domain)
        if entry["status"] == "verified" and not entry["expired"]:
            return redirect(url_for("ownership_page", message=f"{domain} verified."))
        return redirect(url_for("ownership_page", error=f"{domain}: {entry.get('last_error')}"))

    @app.route("/admin/domains/<path:domain>/attest", methods=["POST"])
    @auth.require_admin
    def ownership_attest_form(domain):
        domain = _domain_or_none(domain)
        if not domain:
            return redirect(url_for("ownership_page", error="Enter a valid domain name."))
        try:
            domain_ownership.attest(domain, _actor_email(), request.form.get("note"))
        except ValueError as exc:
            return redirect(url_for("ownership_page", error=str(exc)))
        audit_log.record("ownership.attest", target_type="domain", target_id=domain,
                         details={"note": request.form.get("note")})
        return redirect(url_for("ownership_page", message=f"{domain} attested."))

    @app.route("/admin/domains/<path:domain>/revoke", methods=["POST"])
    @auth.require_admin
    def ownership_revoke_form(domain):
        domain = domain_ownership.normalize(domain)
        if domain_ownership.revoke(domain):
            audit_log.record("ownership.revoke", target_type="domain", target_id=domain)
        return redirect(url_for("ownership_page", message=f"{domain} revoked."))

    # JSON for scripts and the API.
    @app.route("/api/ownership", methods=["GET"])
    @auth.require_role(roles.USER)
    def api_ownership_list():
        return jsonify({"domains": domain_ownership.list_domains()})

    @app.route("/api/ownership", methods=["POST"])
    @auth.require_role(roles.USER)
    def api_ownership_request():
        domain = _domain_or_none((request.get_json(silent=True) or {}).get("domain"))
        if not domain:
            return jsonify({"error": "Invalid domain name"}), 400
        entry = domain_ownership.request_verification(domain, requested_by=_actor_email())
        audit_log.record("ownership.request", target_type="domain", target_id=domain)
        return jsonify(entry), 201

    @app.route("/api/ownership/<path:domain>/check", methods=["POST"])
    @auth.require_role(roles.USER)
    def api_ownership_check(domain):
        domain = _domain_or_none(domain)
        if not domain or not domain_ownership.get(domain):
            return jsonify({"error": "Unknown domain; request verification first"}), 404
        return jsonify(_check(domain))

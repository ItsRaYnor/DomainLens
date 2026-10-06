"""Accepted risks: list them, accept a finding, revoke an acceptance.

Accepting a risk is an admin decision -- it takes a finding out of the
counts everyone else looks at -- so creating and revoking are admin-only and
audited. Analysts and viewers can see what has been accepted, by whom, and
until when.
"""

from __future__ import annotations

from datetime import date, timedelta

from flask import jsonify, redirect, render_template, request, url_for

import audit_log
import contacts
import domain_portfolio
import recommendations
import risk_acceptance
import roles
from routes.admin_nav import subnav


def _owner_label(contact):
    """The owner as stored with the acceptance: the name as it is now."""
    name, email = contact.get("name"), contact.get("email")
    return f"{name} ({email})" if email and email != name else (name or email or "")


def _resolve_owner(form):
    """(owner text, contact id) from the form. The owner is a contact, an
    account (made a contact), or someone new; a client that still sends the
    free-text field gets that."""
    choice = (form.get("owner_contact") or "").strip()
    if not choice:
        return (form.get("owner") or "").strip(), None
    if choice == "new":
        made = contacts.create(name=form.get("owner_name"), email=form.get("owner_email"))
    elif choice.startswith("u") and choice[1:].isdigit():
        made = contacts.create(user_id=int(choice[1:]))
    elif choice.startswith("c") and choice[1:].isdigit():
        made = contacts.get(int(choice[1:]))
        if not made:
            raise ValueError("That contact no longer exists.")
    else:
        raise ValueError("Choose who owns the risk.")
    return _owner_label(made), made["id"]


def register(app, *, auth, db, normalize_domain, is_valid_domain):
    def _latest_findings(domain):
        """Open findings from the newest saved scan of this domain."""
        latest = db.list_scans(domain=domain, limit=1)
        if not latest:
            return None, []
        record = db.get_scan(latest[0]["id"])
        return record, recommendations.generate(record["data"])

    @app.route("/admin/risks")
    @auth.require_role(roles.VIEWER)
    def risks_page():
        domain = normalize_domain(request.args.get("domain") or "")
        domain = domain if is_valid_domain(domain) else ""
        scan, findings = _latest_findings(domain) if domain else (None, [])
        # Coming from "Accept risk" on a report or a scan result: that
        # finding is the one to fill in. A report of an older scan may name
        # one the latest scan no longer has, and that is said, not hidden.
        focus = request.args.get("finding") or ""
        error = request.args.get("error")
        if focus and scan and not any(f.get("finding_key") == focus for f in findings):
            error = error or "That finding is not in the latest scan of this domain."
        is_admin = (not auth.config().get("enabled")) or roles.at_least(auth.current_role(), roles.ADMIN)
        return render_template(
            "admin_risks.html",
            section="admin",
            subnav=subnav("/admin/risks") if is_admin else None,
            exceptions=risk_acceptance.list_all(),
            domain=domain,
            scan=scan,
            findings=findings,
            focus=focus,
            # Who can own the risk: the domain's contact (or its unit's)
            # first, then every contact and account, or someone new.
            owner_default=domain_portfolio.contact_of(domain) if domain else None,
            owner_contacts=contacts.list_contacts() if is_admin and findings else [],
            owner_accounts=contacts.accounts() if is_admin and findings else [],
            is_admin=is_admin,
            default_expiry=(date.today() + timedelta(days=90)).isoformat(),
            max_expiry=(date.today() + timedelta(days=risk_acceptance.MAX_DAYS)).isoformat(),
            message=request.args.get("message"),
            error=error,
        )

    @app.route("/admin/risks", methods=["POST"])
    @auth.require_admin
    def risks_accept():
        domain = normalize_domain(request.form.get("domain") or "")
        key = request.form.get("finding_key") or ""
        if not is_valid_domain(domain):
            return redirect(url_for("risks_page", error="Invalid domain."))
        _, findings = _latest_findings(domain)
        finding = next((f for f in findings if f.get("finding_key") == key), None)
        if not finding:
            # Only a finding the latest scan actually reported can be
            # accepted; a free-typed key would match nothing, or the wrong thing.
            return redirect(url_for("risks_page", domain=domain,
                                    error="That finding is not in the latest scan of this domain."))
        user = auth.current_user() or {}
        try:
            risk_acceptance.check_terms(request.form.get("reason"), request.form.get("expires_on"))
            owner, owner_contact_id = _resolve_owner(request.form)
            exception_id = risk_acceptance.create(
                domain=domain, finding_key=key, title=finding["title"],
                severity=finding["severity"], reason=request.form.get("reason"),
                owner=owner, expires_on=request.form.get("expires_on"),
                created_by=user.get("email"), owner_contact_id=owner_contact_id)
        except ValueError as exc:
            return redirect(url_for("risks_page", domain=domain, finding=key, error=str(exc)))
        audit_log.record("risk.accept", target_type="domain", target_id=domain, details={
            "exception_id": exception_id, "finding": finding["title"],
            "severity": finding["severity"], "owner": owner, "owner_contact_id": owner_contact_id,
            "expires_on": request.form.get("expires_on"), "reason": request.form.get("reason")})
        return redirect(url_for("risks_page", domain=domain, message="Risk accepted."))

    @app.route("/admin/risks/<int:exception_id>/revoke", methods=["POST"])
    @auth.require_admin
    def risks_revoke(exception_id):
        entry = risk_acceptance.get(exception_id)
        if entry and risk_acceptance.revoke(exception_id):
            audit_log.record("risk.revoke", target_type="domain", target_id=entry["domain"],
                             details={"exception_id": exception_id, "finding": entry["title"]})
        return redirect(url_for("risks_page", message="Acceptance revoked."))

    @app.route("/api/risks", methods=["GET"])
    @auth.require_role(roles.VIEWER)
    def api_risks():
        domain = normalize_domain(request.args.get("domain") or "") or None
        return jsonify({"exceptions": risk_acceptance.list_all(domain)})

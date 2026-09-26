"""Admin views of the audit log: page, JSON, CSV and chain verification."""

from __future__ import annotations

from datetime import date, timedelta
from urllib.parse import urlencode

from flask import Response, jsonify, render_template, request

import audit_log
from routes.admin_nav import subnav

_PAGE_SIZE = 50


def _filters_from_request():
    """Filters from the query string; dates are whole days, until inclusive."""
    raw = {k: (request.args.get(k) or "").strip() for k in
           ("action", "actor", "outcome", "since", "until")}
    filters = {"action": raw["action"] or None,
               "actor": raw["actor"] or None,
               "outcome": raw["outcome"] if raw["outcome"] in {"success", "failure", "denied"} else None,
               "since": None, "until": None}
    try:
        if raw["since"]:
            filters["since"] = date.fromisoformat(raw["since"]).isoformat()
        if raw["until"]:
            filters["until"] = (date.fromisoformat(raw["until"]) + timedelta(days=1)).isoformat()
    except ValueError:
        pass
    shown = {k: v for k, v in raw.items() if v}
    return filters, shown


def register(app, *, auth):
    @app.route("/admin/audit")
    @auth.require_admin
    def admin_audit_page():
        filters, shown = _filters_from_request()
        try:
            page = max(1, int(request.args.get("page") or 1))
        except ValueError:
            page = 1
        result = audit_log.list_entries(limit=_PAGE_SIZE, offset=(page - 1) * _PAGE_SIZE, **filters)
        pages = max(1, -(-result["total"] // _PAGE_SIZE))
        return render_template(
            "admin_audit.html",
            section="admin",
            subnav=subnav("/admin/audit"),
            entries=result["entries"],
            total=result["total"],
            page=min(page, pages),
            pages=pages,
            filters=shown,
            query_string=urlencode(shown),
            chain=audit_log.verify(),
        )

    @app.route("/api/admin/audit")
    @auth.require_admin
    def api_admin_audit():
        filters, _ = _filters_from_request()
        try:
            limit = min(500, max(1, int(request.args.get("limit") or 100)))
            offset = max(0, int(request.args.get("offset") or 0))
        except ValueError:
            return jsonify({"error": "limit and offset must be integers"}), 400
        return jsonify(audit_log.list_entries(limit=limit, offset=offset, **filters))

    @app.route("/api/admin/audit.csv")
    @auth.require_admin
    def api_admin_audit_csv():
        filters, _ = _filters_from_request()
        audit_log.record("audit.export", details={k: v for k, v in filters.items() if v})
        return Response(
            audit_log.export_csv(**filters),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=domainlens-audit.csv"},
        )

    @app.route("/api/admin/audit/verify")
    @auth.require_admin
    def api_admin_audit_verify():
        return jsonify(audit_log.verify())

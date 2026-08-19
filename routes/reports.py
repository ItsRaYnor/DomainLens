"""Report view + multi-format export routes."""

from __future__ import annotations

from flask import Response, abort, jsonify, render_template, request

import reporting_export
import version as app_version


def register(app, *, db, recommendations):
    @app.route("/report/<int:scan_id>")
    def report_view(scan_id):
        record = db.get_scan(scan_id)
        if not record:
            abort(404)
        recs = recommendations.generate(record["data"])
        counts = recommendations.summarize_counts(recs)
        return render_template(
            "report.html",
            scan=record,
            results=record["data"],
            recommendations=recs,
            counts=counts,
            app_version=app_version.get_version(),
        )

    @app.route("/api/reports/<int:scan_id>")
    @app.route("/api/reports/<int:scan_id>/export")
    def api_report_export(scan_id):
        record = db.get_scan(scan_id)
        if not record:
            return jsonify({"error": "Scan not found"}), 404
        recs = recommendations.generate(record["data"])
        counts = recommendations.summarize_counts(recs)
        bundle = reporting_export.build_report_bundle(record, recs, counts)
        fmt = (request.args.get("format") or "json").strip().lower()
        domain = (record.get("domain") or "scan").replace(".", "_")
        filename = f"domainlens-{domain}-{scan_id}"

        if fmt in {"md", "markdown"}:
            body = reporting_export.to_markdown(bundle)
            return Response(
                body,
                mimetype="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}.md"'},
            )
        if fmt == "csv":
            body = reporting_export.to_csv_advies(recs)
            return Response(
                body,
                mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}-advies.csv"'},
            )
        # Default JSON (inline or download)
        download = request.args.get("download") in {"1", "true", "yes"} or fmt == "json-download"
        body = reporting_export.to_json_text(bundle)
        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="{filename}.json"'
        return Response(body, mimetype="application/json; charset=utf-8", headers=headers)

"""System routes: health, version, update checks."""

from __future__ import annotations

from flask import jsonify, request

import update_check
import version as app_version


def register(app, *, db, auth, servicenow, domainlens_config, scheduler_config_fn):
    @app.route("/api/version")
    def api_version():
        return jsonify(app_version.info())

    @app.route("/metrics")
    def prometheus_metrics():
        """Prometheus text format. Behind login like the rest of the app when
        authentication is on: scrape with an API token (any role)."""
        import metrics
        import scan_jobs
        import scheduler as monitor_scheduler
        body = metrics.render(db=db, scheduler_state=monitor_scheduler.state_snapshot(),
                              running_jobs=scan_jobs.count_running(),
                              version=app_version.get_version())
        return app.response_class(body, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @app.route("/api/admin/backup")
    @auth.require_admin
    def api_admin_backup():
        """A consistent snapshot of the live database, as a download.

        It contains credentials encrypted with DOMAINLENS_SECRET_KEY; a
        restore needs the same key to read them back.
        """
        import os
        import audit_log
        import maintenance
        from flask import send_file
        path = maintenance.backup_to_tempfile()
        audit_log.record("backup.download")
        response = send_file(path, mimetype="application/vnd.sqlite3", as_attachment=True,
                             download_name=maintenance.backup_filename())
        response.call_on_close(lambda: os.path.exists(path) and os.remove(path))
        return response

    @app.route("/api/openapi.json")
    def api_openapi():
        import openapi
        return jsonify(openapi.spec())

    @app.route("/api/updates/check")
    def api_updates_check():
        """Admins (or open when auth disabled) can check for newer releases."""
        force = request.args.get("force") in {"1", "true", "yes"}
        cfg = auth.config()
        if cfg.get("enabled"):
            user = auth.current_user()
            if not user or user.get("role") != "admin":
                # Non-admins get a reduced payload (no docker commands noise)
                payload = update_check.check_for_updates(force=force)
                return jsonify({
                    "enabled": payload.get("enabled"),
                    "current_version": payload.get("current_version"),
                    "latest_version": payload.get("latest_version"),
                    "update_available": payload.get("update_available"),
                    "release_url": payload.get("release_url"),
                    "error": payload.get("error"),
                })
        return jsonify(update_check.check_for_updates(force=force))

    @app.route("/health")
    @app.route("/api/health")
    def api_health():
        """Minimal liveness/readiness endpoint for Docker / Portainer / Synology.

        Public by design (used by container healthchecks), so it exposes only
        non-sensitive liveness data. Detailed config/monitor/auth internals —
        which include SSO allowlists and a secrets-presence map — are served
        only to authenticated admins to avoid handing reconnaissance to
        unauthenticated visitors.
        """
        # Version info is non-sensitive (name/version only) and stays public.
        payload = {
            "status": "ok",
            "version": app_version.info(),
        }
        cfg = auth.config()
        is_admin = False
        if cfg.get("enabled"):
            user = auth.current_user()
            is_admin = bool(user and user.get("role") == "admin")
        else:
            # When auth is disabled the app is meant for a trusted local
            # operator, so the richer payload is acceptable on localhost.
            is_admin = True

        if is_admin:
            stats = db.monitor_stats()
            payload.update({
                "scheduler": scheduler_config_fn(),
                "config": domainlens_config.load_settings().public_snapshot(),
                "monitors": {
                    "total": stats.get("total_monitors", 0),
                    "enabled": stats.get("enabled_monitors", 0),
                    "due": stats.get("due_monitors", 0),
                },
                "servicenow": servicenow.config()["enabled"],
                "auth": {
                    "enabled": cfg["enabled"],
                    "configured": cfg["configured"],
                    "local_enabled": cfg.get("local_enabled", False),
                    "oauth_enabled": cfg.get("oauth_enabled", False),
                    "authenticated": bool(auth.current_user()),
                },
            })
        return jsonify(payload)

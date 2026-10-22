"""Admin -> Advisories: the rules the version check and every scan use.

The built-in rules are shown read-only; an administrator adds, changes,
switches off and removes their own, exports them to a file and imports such
a file, and adds the example rules that come with DomainLens. The test
button runs a rule, saved or not, against headers pasted from a response:
nothing is fetched, nothing is stored. Every change is in the audit log.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Response, jsonify, render_template, request

import advisory_rules
import audit_log
import software_advisories as engine
from routes.admin_nav import subnav

_SAMPLE_MAX = 20000


def _problems(exc):
    return jsonify({"error": "The rule cannot be used.", "problems": exc.problems}), 400


def parse_headers(text):
    """"Name: value" lines, as copied from a browser or curl -I, into the
    lower-case header map the engine reads. Set-Cookie lines become the
    cookie string; a status line or anything without a colon is skipped."""
    headers, cookies = {}, []
    for line in str(text or "")[:_SAMPLE_MAX].splitlines():
        name, sep, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if not sep or not name or " " in name:
            continue
        if name == "set-cookie":
            cookies.append(value)
        elif value:
            headers[name] = f"{headers[name]} {value}" if name in headers else value
    return headers, " ".join(cookies)


def register(app, *, auth):
    def _user():
        return (auth.current_user() or {}).get("email")

    @app.route("/admin/advisories")
    @auth.require_admin
    def admin_advisories_page():
        return render_template("admin_advisories.html", section="admin", subnav=subnav("/admin/advisories"),
                               severities=engine.SEVERITIES, generator=engine.GENERATOR)

    @app.route("/api/admin/advisories", methods=["GET"])
    @auth.require_admin
    def api_admin_advisories():
        return jsonify({"rules": advisory_rules.list_rules()})

    @app.route("/api/admin/advisories", methods=["POST"])
    @auth.require_admin
    def api_admin_advisories_create():
        try:
            rule = advisory_rules.save(request.get_json(silent=True), user=_user())
        except engine.RuleError as exc:
            return _problems(exc)
        audit_log.record("advisory_rule.create", target_type="advisory_rule", target_id=rule["id"],
                         details={"name": rule["name"], "cves": rule["cves"], "fixed": rule["fixed"]})
        return jsonify({"rule": rule}), 201

    @app.route("/api/admin/advisories/<rule_id>", methods=["PUT"])
    @auth.require_admin
    def api_admin_advisories_update(rule_id):
        if rule_id in engine.BUILTIN_IDS:
            return jsonify({"error": "A built-in rule cannot be changed."}), 400
        before = advisory_rules.get(rule_id)
        try:
            rule = advisory_rules.save(request.get_json(silent=True), user=_user(), rule_id=rule_id)
        except engine.RuleError as exc:
            return _problems(exc)
        except LookupError:
            return jsonify({"error": "Unknown rule"}), 404
        changed = sorted(k for k in rule if k in (before or {}) and k not in ("updated_at", "updated_by")
                         and rule[k] != before[k])
        audit_log.record("advisory_rule.update", target_type="advisory_rule", target_id=rule["id"],
                         details={"name": rule["name"], "changed": changed})
        return jsonify({"rule": rule})

    @app.route("/api/admin/advisories/<rule_id>/enabled", methods=["POST"])
    @auth.require_admin
    def api_admin_advisories_enabled(rule_id):
        if rule_id in engine.BUILTIN_IDS:
            return jsonify({"error": "A built-in rule cannot be switched off."}), 400
        on = (request.get_json(silent=True) or {}).get("enabled")
        if not isinstance(on, bool):
            return jsonify({"error": "enabled must be true or false"}), 400
        try:
            rule = advisory_rules.set_enabled(rule_id, on, user=_user())
        except LookupError:
            return jsonify({"error": "Unknown rule"}), 404
        audit_log.record("advisory_rule.enable" if on else "advisory_rule.disable", target_type="advisory_rule",
                         target_id=rule_id, details={"name": rule.get("name")})
        return jsonify({"rule": rule})

    @app.route("/api/admin/advisories/<rule_id>", methods=["DELETE"])
    @auth.require_admin
    def api_admin_advisories_delete(rule_id):
        if rule_id in engine.BUILTIN_IDS:
            return jsonify({"error": "A built-in rule cannot be removed."}), 400
        before = advisory_rules.get(rule_id)
        try:
            advisory_rules.delete(rule_id)
        except LookupError:
            return jsonify({"error": "Unknown rule"}), 404
        audit_log.record("advisory_rule.delete", target_type="advisory_rule", target_id=rule_id,
                         details={"name": (before or {}).get("name"), "rule": before})
        return jsonify({"deleted": rule_id})

    @app.route("/api/admin/advisories/test", methods=["POST"])
    @auth.require_admin
    def api_admin_advisories_test():
        """The rule against a pasted response: what it reads and its verdict.
        Nothing is fetched and nothing is saved."""
        data = request.get_json(silent=True) or {}
        try:
            rule = engine.compile_rule(data.get("rule"))
        except engine.RuleError as exc:
            return _problems(exc)
        headers, cookies = parse_headers(data.get("headers"))
        url = str(data.get("url") or "")[:500]
        generator = engine.generator_of(str(data.get("body") or ""))
        results = engine.match(headers, cookies, url, generator, rules=[rule])
        return jsonify({"read": {"headers": {k: v for k, v in headers.items() if k in rule["sources"]},
                                 "generator": generator if engine.GENERATOR in rule["sources"] else None},
                        "results": results,
                        "finding": engine.finding(results[0]) if results else None})

    @app.route("/api/admin/advisories/export", methods=["GET"])
    @auth.require_admin
    def api_admin_advisories_export():
        payload = advisory_rules.export()
        audit_log.record("advisory_rule.export", target_type="advisory_rule",
                         details={"count": len(payload["rules"])})
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return Response(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", mimetype="application/json",
                        headers={"Content-Disposition":
                                 f"attachment; filename=domainlens-advisory-rules-{stamp}.json"})

    def _import(payload, replace, source):
        try:
            result = advisory_rules.import_rules(payload, user=_user(), replace=replace)
        except engine.RuleError as exc:
            return jsonify({"error": "Nothing was imported.", "problems": exc.problems}), 400
        audit_log.record("advisory_rule.import", target_type="advisory_rule",
                         details={"source": source, **result})
        return jsonify(result)

    @app.route("/api/admin/advisories/import", methods=["POST"])
    @auth.require_admin
    def api_admin_advisories_import():
        """An exported rules file as the request body. `?replace=1` replaces
        rules whose id already exists; without it they are skipped."""
        return _import(request.get_json(silent=True), request.args.get("replace") == "1", "file")

    @app.route("/api/admin/advisories/examples", methods=["GET"])
    @auth.require_admin
    def api_admin_advisories_examples():
        return jsonify({"examples": advisory_rules.examples()})

    @app.route("/api/admin/advisories/examples", methods=["POST"])
    @auth.require_admin
    def api_admin_advisories_examples_add():
        """Add example rules by id, as rules of your own. One already added is
        left as it is."""
        ids = (request.get_json(silent=True) or {}).get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            return jsonify({"error": "ids must be a list of example ids"}), 400
        payload = advisory_rules.example_payload(ids)
        unknown = sorted(set(ids) - {r["id"] for r in payload["rules"]})
        if unknown:
            return jsonify({"error": "Unknown example: " + ", ".join(unknown)}), 404
        return _import(payload, False, "examples")

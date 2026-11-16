"""The disclosure tools: this installation's own PGP key, and PGP keys and
security.txt files of other domains (inspect, validate, generate).

Moved out of app.py unchanged; the helpers it shares with the rest of the
app are passed in by register().
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import jsonify, redirect, render_template, request

import audit_log
import pgp_keys
import security_checks
import security_txt

log = logging.getLogger("domainlens")


def register(app, *, auth, check_rate_limit, subnav, safe_error, normalize_domain,
             is_valid_domain, disclosure_config, custom_resolvers, tools_subnav, settings_store):
    _check_rate_limit = check_rate_limit
    _subnav = subnav
    _safe_error = safe_error
    _normalize_domain = normalize_domain
    _is_valid_domain = is_valid_domain
    _disclosure_config = disclosure_config
    _custom_resolvers = custom_resolvers
    _TOOLS_SUBNAV = tools_subnav
    _settings_store = settings_store

    @app.route("/api/admin/pgp/status", methods=["GET"])
    @auth.require_admin
    def api_admin_pgp_status():
        config = _disclosure_config()
        return jsonify({
            "gpg_available": pgp_keys.available(),
            "gpg_version": pgp_keys.version(),
            "fingerprint": config.get("pgp_fingerprint") or None,
            "uid": config.get("pgp_uid") or None,
            "generated_at": config.get("pgp_generated_at") or None,
            "has_public_key": bool((config.get("pgp_public_key") or "").strip()),
            "public_key_url": security_txt.PUBLIC_KEY_PATH,
            "security_txt_url": security_txt.SECURITY_TXT_PATH,
        })


    @app.route("/api/admin/pgp/generate", methods=["POST"])
    @auth.require_admin
    def api_admin_pgp_generate():
        """Generate a keypair, keep the public half, return the private half once.

        The private key is in this response body and nowhere else. It is not
        written to the database, not logged, and not recoverable afterwards --
        which is the entire point, and why the UI has to make the operator save
        it before they navigate away.
        """
        if not pgp_keys.available():
            return jsonify({"error": "gpg is not installed on this server, so a key cannot be generated here. The Docker image ships with it; on a native install, install GnuPG (Gpg4win on Windows) and restart DomainLens."}), 503
        payload = request.get_json(silent=True) or {}
        try:
            result = pgp_keys.generate(
                payload.get("name", ""),
                payload.get("email", ""),
                payload.get("passphrase", "") or "",
                payload.get("expiry", "2y"),
            )
        except pgp_keys.PgpInputError as exc:
            return jsonify({"error": str(exc)}), 400
        except pgp_keys.PgpError as exc:
            return jsonify({"error": str(exc)}), 502

        _settings_store.update_section("disclosure", {
            "pgp_public_key": result["public_key"],
            "pgp_fingerprint": result["fingerprint"],
            "pgp_uid": result["uid"],
            "pgp_generated_at": datetime.now(timezone.utc).isoformat(),
        }, user_id=(auth.current_user() or {}).get("id"))
        log.info("Generated disclosure PGP key %s (private half not stored)",
                 result["fingerprint"])
        audit_log.record("disclosure.pgp_generate", target_type="pgp_key",
                         target_id=result["fingerprint"])

        return jsonify({
            "fingerprint": result["fingerprint"],
            "uid": result["uid"],
            "public_key": result["public_key"],
            # Returned once. Nothing server-side keeps a copy.
            "private_key": result["private_key"],
            "protected": result["protected"],
            "warning": "This is the only copy of the private key. Save it now; "
                       "DomainLens does not store it and cannot show it again.",
        }), 201


    @app.route("/tools/disclosure")
    def lookup_pgp_view():
        return render_template(
            "lookup_pgp.html", section="tools",
            subnav=_subnav(_TOOLS_SUBNAV, "/tools/disclosure"))


    @app.route("/lookup/pgp")
    def lookup_pgp_view_legacy():
        return redirect("/tools/disclosure", code=301)


    @app.route("/api/pgp/inspect", methods=["GET"])
    def api_pgp_inspect():
        """Read one domain's security.txt and check the key it points at.

        Rate limited on the same bucket as DNS lookups: it makes outbound
        requests on behalf of whoever can reach this page.
        """
        if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
            return jsonify({"error": "Too many lookups in a short time. Wait a moment."}), 429
        domain = _normalize_domain(request.args.get("domain", ""))
        if not _is_valid_domain(domain):
            return jsonify({"error": "Enter a valid public domain name"}), 400
        try:
            return jsonify(security_checks.inspect_security_txt(domain))
        except Exception as exc:
            return jsonify({"error": _safe_error(exc)}), 502


    @app.route("/api/pgp/validate-securitytxt", methods=["POST"])
    def api_pgp_validate_securitytxt():
        """Check a pasted security.txt against RFC 9116.

        Nothing is fetched and nothing is stored: it reads the text it was given,
        which is what makes it usable on a file you have not published yet.
        """
        payload = request.get_json(silent=True) or {}
        body = payload.get("body", "")
        if len(body) > 100_000:
            return jsonify({"error": "That is larger than any security.txt should be"}), 400
        return jsonify(security_txt.validate(body))


    @app.route("/api/pgp/validate-key", methods=["POST"])
    def api_pgp_validate_key():
        """Describe a pasted armoured key: algorithm, fingerprint, uids, expiry.

        A private key pasted here is reported rather than refused. Someone
        checking "does my key work" with the wrong half needs to be told that,
        not handed a validation error.
        """
        if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
            return jsonify({"error": "Too many checks in a short time. Wait a moment."}), 429
        # No gpg check here on purpose: inspect_key can tell a signature from a
        # key without it, and answering "gpg is not installed" to someone who
        # pasted the wrong block sends them after the wrong problem.
        payload = request.get_json(silent=True) or {}
        armored = payload.get("key", "")
        if len(armored) > 500_000:
            return jsonify({"error": "That is larger than any armoured key should be"}), 400
        try:
            return jsonify(pgp_keys.inspect_key(armored))
        except pgp_keys.PgpError as exc:
            return jsonify({"error": str(exc)}), 502


    @app.route("/api/pgp/generate", methods=["POST"])
    def api_pgp_generate_throwaway():
        """Generate a keypair and keep nothing at all.

        The counterpart in /api/admin/pgp/generate stores the public half so this
        installation can publish it. This one is a tool: it is for a domain that
        is not this one, so neither half is persisted and the caller gets both.
        """
        if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
            return jsonify({"error": "Too many requests in a short time. Wait a moment."}), 429
        if not pgp_keys.available():
            return jsonify({"error": "gpg is not installed on this server, so a key cannot be generated here. The Docker image ships with it; on a native install, install GnuPG (Gpg4win on Windows) and restart DomainLens."}), 503
        payload = request.get_json(silent=True) or {}
        try:
            result = pgp_keys.generate(
                payload.get("name", ""),
                payload.get("email", ""),
                payload.get("passphrase", "") or "",
                payload.get("expiry", "2y"),
            )
        except pgp_keys.PgpInputError as exc:
            return jsonify({"error": str(exc)}), 400
        except pgp_keys.PgpError as exc:
            return jsonify({"error": _safe_error(exc)}), 502
        log.info("Generated a throwaway PGP key %s (nothing stored)", result["fingerprint"])
        return jsonify({
            **result,
            "warning": "Neither half of this key is stored. Save it now; it cannot "
                       "be shown again.",
        }), 201

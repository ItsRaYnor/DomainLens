"""The mail analysis tool: a received message or attachment, its links, and
the threat lists it is checked against.

Moved out of app.py unchanged; the helpers it shares with the rest of the
app are passed in by register().
"""

from __future__ import annotations

import threading

from flask import jsonify, render_template, request

import audit_log
import ip_lists
import link_check
import mail_test
import msg_file
import sandbox
import url_check


# Filled by register(): app.py's blocklist check, which these lookups share
# with the scan. Module level, so a test can replace a lookup class.
_deps: dict = {}


class _MailLookups(mail_test.Lookups):
    """The mail analysis's lookups, with the blocklists the scan uses."""

    def blocklist(self, ip):
        result = _deps["check_blacklist"](ip)
        return None if result.get("error") else result

    def own_domains(self):
        return link_check.own_domains()

    def check_hashes(self, digests):
        import file_reputation
        return file_reputation.check(digests)

    def check_links(self, urls):
        # Threat lists are searched here; VirusTotal is asked by hash, and
        # only when an admin switched it on (link_check.py).
        state = link_check.virustotal_state()
        return {"feeds": link_check.check_feeds(urls),
                "virustotal": {"state": state,
                               "results": link_check.check_virustotal(urls) if state == "on" else {}}}


def _is_outlook_message(raw):
    """An OLE file that holds the streams of an Outlook message, told apart
    from an older Word or Excel file, which is OLE too. Only the directory
    names are read here; the content is read in the sandbox."""
    return any(marker in raw for marker in ("__substg1.0_".encode("utf-16-le"), "__properties_version1.0".encode("utf-16-le")))


_FILE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"MZ", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"{\\rt", b"Rar!",
               b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b", b"MSCF", b"\x7fELF", b"\x4c\x00\x00\x00\x01\x14\x02\x00")


def _looks_like_file(raw):
    """A file rather than a message, by its first bytes alone: whether a
    binary file's first line happens to hold a colon must not decide it."""
    return raw.startswith(_FILE_MAGIC) or b"%PDF-" in raw[:1024] or b"\x00" in raw[:4096]

class _LinkLookups(url_check.Lookups):
    """The link check's lookups, with the blocklists and IP threat lists the scan uses."""

    def reputation(self, ip):
        result = _deps["check_blacklist"](ip)
        return None if result.get("error") else result



def register(app, *, auth, check_rate_limit, subnav, safe_error, normalize_domain,
             is_valid_domain, disclosure_config, custom_resolvers, tools_subnav, check_blacklist):
    _check_rate_limit = check_rate_limit
    _subnav = subnav
    _safe_error = safe_error
    _normalize_domain = normalize_domain
    _is_valid_domain = is_valid_domain
    _disclosure_config = disclosure_config
    _custom_resolvers = custom_resolvers
    _TOOLS_SUBNAV = tools_subnav
    _deps["check_blacklist"] = check_blacklist

    @app.route("/tools/mail")
    def mail_test_view():
        return render_template(
            "lookup_mail.html", section="tools",
            subnav=_subnav(_TOOLS_SUBNAV, "/tools/mail"))



    @app.route("/api/mailtest", methods=["POST"])
    def api_mail_test():
        """Judge one received message (.eml, Outlook .msg or pasted text), or one PDF.

        The message is analysed and not kept; only the DKIM selectors it shows
        to be in use are remembered, for later scans of that domain.
        """
        if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
            return jsonify({"error": "Too many lookups in a short time. Wait a moment."}), 429
        upload = request.files.get("file")
        if upload is not None:
            raw = upload.read(mail_test.MAX_BYTES + 1)
            ip = request.form.get("ip")
        else:
            data = request.get_json(silent=True) or {}
            raw = str(data.get("message") or "").encode("utf-8", "surrogateescape")
            ip = data.get("ip")
        if len(raw) > mail_test.MAX_BYTES:
            return jsonify({"error": "The message is larger than 10 MB."}), 413
        if not raw.strip():
            return jsonify({"error": "Paste the message source or choose an .eml file."}), 400
        # Told apart by what the file is, not by its name: an Outlook message
        # (read in the sandbox process, like every attachment), a message as
        # received, or any other file on its own.
        origin = "eml"
        if upload is not None and msg_file.is_msg(raw) and _is_outlook_message(raw):
            try:
                raw, msg_info = sandbox.convert_msg(raw)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
            origin = "msg"
        elif upload is not None and _looks_like_file(raw):
            return jsonify(mail_test.analyse_file(raw, upload.filename, lookups=_MailLookups()))
        elif b":" not in raw.lstrip().split(b"\n", 1)[0]:
            if upload is None:
                return jsonify({"error": "This does not look like a message: it should start with header lines."}), 400
            return jsonify(mail_test.analyse_file(raw, upload.filename, lookups=_MailLookups()))
        try:
            result = mail_test.analyse(raw, lookups=_MailLookups(), ip=(ip or None), origin=origin)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if origin == "msg":
            result["msg"] = msg_info
        if result["learned"]:
            mail_test.remember((x["domain"], x["selector"]) for x in result["learned"])
        return jsonify(result)


    @app.route("/api/linkcheck", methods=["POST"])
    def api_link_check():
        """Judge links pasted on their own, without opening them (url_check.py)."""
        if not _check_rate_limit(request.remote_addr, bucket="dns_lookup"):
            return jsonify({"error": "Too many lookups in a short time. Wait a moment."}), 429
        data = request.get_json(silent=True) or {}
        text = str(data.get("text") or "")[:20000]
        if not text.strip():
            return jsonify({"error": "Paste one or more links."}), 400
        result = url_check.check(text, _LinkLookups())
        if not result["links"]:
            return jsonify({"error": "No link was found in the text."}), 400
        return jsonify(result)


    @app.route("/api/iplists", methods=["GET"])
    def api_ip_lists():
        """The IP threat lists in use: when each was fetched, how many ranges."""
        return jsonify({"lists": ip_lists.status()})


    @app.route("/api/iplists/refresh", methods=["POST"])
    @auth.require_admin
    def api_ip_lists_refresh():
        """Download the IP threat lists now instead of waiting for the scheduler."""
        if not ip_lists.status():
            return jsonify({"error": "No IP threat lists are switched on (Admin -> Settings -> IP threat lists)."}), 400
        threading.Thread(target=ip_lists.refresh, daemon=True, name="ip-lists").start()
        audit_log.record("iplists.refresh", target_type="settings")
        return jsonify({"started": True}), 202


    @app.route("/api/mailtest/checks", methods=["GET"])
    def api_mail_test_checks():
        """How links are checked here: the threat lists and their age, whether
        VirusTotal is on, how many own domains lookalikes are compared with."""
        return jsonify({"feeds": link_check.feed_status(), "virustotal": link_check.virustotal_state(),
                        "own_domains": len(link_check.own_domains())})


    @app.route("/api/mailtest/feeds/refresh", methods=["POST"])
    @auth.require_admin
    def api_mail_test_feeds_refresh():
        """Download the threat lists now instead of waiting for the scheduler."""
        if not link_check.feed_status():
            return jsonify({"error": "No threat lists are configured (Admin -> Settings -> Mail analysis)."}), 400
        threading.Thread(target=link_check.refresh, daemon=True, name="link-feeds").start()
        audit_log.record("mailtest.feeds_refresh", target_type="settings")
        return jsonify({"started": True}), 202

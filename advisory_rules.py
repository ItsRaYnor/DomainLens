"""Advisory rules an administrator adds: known vulnerable versions as data.

A new vulnerability used to need a release of DomainLens: the advisories
were a list in software_advisories.py. Now an administrator writes the rule
on Admin -> Advisories -- the product, the token it shows itself by, where
to read it, the release with the fix per branch -- and every scan and the
version check use it from then on.

A rule is stored as the JSON it was written as and checked by
software_advisories.compile_rule on every write and every read, so a rule
the engine cannot use never reaches a scan. Rules are data only: there is no
field that runs code, sends a request or carries a regular expression.

The built-in rules (software_advisories.BUILTIN_RULES) are not stored here
and cannot be changed or switched off from the page; a custom rule cannot
take a built-in rule's id.

The custom rules export to one JSON file and import from one, all or
nothing. advisory_examples.json holds example rules for serious, exploited
flaws in that same format; they are suggestions an administrator adds, not
built-in rules, so nobody gets findings they did not choose.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import db
import software_advisories as engine

log = logging.getLogger("domainlens.advisories")

MAX_RULES = 200


def init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS advisory_rules (
            id TEXT PRIMARY KEY,
            rule TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_by TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )


def _now():
    return datetime.now(timezone.utc).isoformat()


def _entry(row):
    """A stored rule as the page shows it: the data as written, whether it is
    on, who wrote it, and why the engine refuses it if it does."""
    data = json.loads(row["rule"])
    try:
        public, problems = engine.compile_rule(data)["public"], []
    except engine.RuleError as exc:
        public, problems = data, exc.problems
    return {**public, "builtin": False, "enabled": bool(row["enabled"]), "problems": problems,
            "created_by": row["created_by"], "created_at": row["created_at"],
            "updated_by": row["updated_by"], "updated_at": row["updated_at"]}


def list_rules():
    """Built-in rules first, then the custom ones by name."""
    with db._connect() as conn:
        rows = conn.execute("SELECT * FROM advisory_rules").fetchall()
    custom = sorted((_entry(r) for r in rows), key=lambda r: (str(r.get("name") or "").lower(), r["id"]))
    builtin = [{**r["public"], "builtin": True, "enabled": True, "problems": []}
               for r in engine.builtin_rules()]
    return builtin + custom


def get(rule_id):
    with db._connect() as conn:
        row = conn.execute("SELECT * FROM advisory_rules WHERE id = ?", (str(rule_id),)).fetchone()
    return _entry(row) if row else None


def enabled():
    """The custom rules that are on, compiled for the engine. One that no
    longer compiles (an engine change tightened a check) is logged and left
    out rather than stopping every scan."""
    with db._connect() as conn:
        rows = conn.execute("SELECT id, rule FROM advisory_rules WHERE enabled = 1 ORDER BY id").fetchall()
    out = []
    for row in rows:
        try:
            out.append(engine.compile_rule(json.loads(row["rule"])))
        except (engine.RuleError, ValueError) as exc:
            log.warning("Advisory rule %s is not used: %s", row["id"], exc)
    return out


def save(raw, *, user, rule_id=None):
    """Create a rule (rule_id None) or replace the one with rule_id. Returns
    the stored rule. RuleError for a rule the engine cannot use, LookupError
    when the rule to replace does not exist."""
    if rule_id is not None:
        if not isinstance(raw, dict):
            raise engine.RuleError(["A rule is an object."])
        raw = {**raw, "id": rule_id}
    rule = engine.compile_rule(raw)
    if rule["id"] in engine.BUILTIN_IDS:
        raise engine.RuleError([f"{rule['id']} is a built-in rule; give the new rule an id of its own."])
    stored = json.dumps(rule["public"], sort_keys=True)
    now = _now()
    with db._lock, db._connect() as conn:
        exists = conn.execute("SELECT 1 FROM advisory_rules WHERE id = ?", (rule["id"],)).fetchone()
        if rule_id is None:
            if exists:
                raise engine.RuleError([f"A rule with id {rule['id']} already exists."])
            count = conn.execute("SELECT COUNT(*) FROM advisory_rules").fetchone()[0]
            if count >= MAX_RULES:
                raise engine.RuleError([f"There are already {MAX_RULES} rules."])
            conn.execute("INSERT INTO advisory_rules (id, rule, enabled, created_by, created_at, updated_by, "
                         "updated_at) VALUES (?, ?, 1, ?, ?, ?, ?)", (rule["id"], stored, user, now, user, now))
        else:
            if not exists:
                raise LookupError("Unknown rule")
            conn.execute("UPDATE advisory_rules SET rule = ?, updated_by = ?, updated_at = ? WHERE id = ?",
                         (stored, user, now, rule["id"]))
    return get(rule["id"])


def set_enabled(rule_id, on, *, user):
    with db._lock, db._connect() as conn:
        changed = conn.execute("UPDATE advisory_rules SET enabled = ?, updated_by = ?, updated_at = ? WHERE id = ?",
                               (1 if on else 0, user, _now(), str(rule_id))).rowcount
    if not changed:
        raise LookupError("Unknown rule")
    return get(rule_id)


def delete(rule_id):
    with db._lock, db._connect() as conn:
        removed = conn.execute("DELETE FROM advisory_rules WHERE id = ?", (str(rule_id),)).rowcount
    if not removed:
        raise LookupError("Unknown rule")


# ---------------------------------------------------------------------------
# Export, import and the example rules
# ---------------------------------------------------------------------------

FORMAT = "domainlens-advisory-rules"
FORMAT_VERSION = 1
EXAMPLES_PATH = Path(__file__).resolve().parent / "advisory_examples.json"


def export():
    """The custom rules as one file, in the format import() reads: to move
    them to another DomainLens, or keep them under version control. Built-in
    rules are left out; every DomainLens has them. A stored rule the engine
    no longer accepts is exported as it is stored, so nothing is lost."""
    with db._connect() as conn:
        rows = conn.execute("SELECT id, rule, enabled FROM advisory_rules ORDER BY id").fetchall()
    return {"format": FORMAT, "version": FORMAT_VERSION, "exported_at": _now(),
            "rules": [{**json.loads(r["rule"]), "enabled": bool(r["enabled"])} for r in rows]}


def _payload_rules(payload):
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise engine.RuleError([f"This is not a DomainLens rules file (format {FORMAT})."])
    if payload.get("version") != FORMAT_VERSION:
        raise engine.RuleError([f"Version {payload.get('version')} of the rules file is not one this "
                                f"DomainLens reads (it reads {FORMAT_VERSION})."])
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise engine.RuleError(["The file has no rules."])
    if len(rules) > MAX_RULES:
        raise engine.RuleError([f"The file has more than {MAX_RULES} rules."])
    return rules


def import_rules(payload, *, user, replace=False):
    """Add the rules of an exported file. All or nothing: one rule the engine
    cannot use refuses the whole file, with the reasons of every rule, so a
    half-imported set never runs. A rule whose id exists is replaced when
    `replace`, else left as it is and reported as skipped.

    {"added": [ids], "replaced": [ids], "skipped": [ids]}."""
    compiled, problems, seen_ids = [], [], set()
    for number, raw in enumerate(_payload_rules(payload), 1):
        label = f"Rule {number}" + (f" ({raw.get('id')})" if isinstance(raw, dict) and raw.get("id") else "")
        try:
            rule = engine.compile_rule(raw)
        except engine.RuleError as exc:
            problems += [f"{label}: {p}" for p in exc.problems]
            continue
        if rule["id"] in engine.BUILTIN_IDS:
            problems.append(f"{label}: {rule['id']} is a built-in rule.")
        elif rule["id"] in seen_ids:
            problems.append(f"{label}: the id {rule['id']} is in the file twice.")
        enabled_flag = raw.get("enabled", True)
        if not isinstance(enabled_flag, bool):
            problems.append(f"{label}: enabled must be true or false.")
        seen_ids.add(rule["id"])
        compiled.append((rule, enabled_flag is not False))
    if problems:
        raise engine.RuleError(problems)

    result = {"added": [], "replaced": [], "skipped": []}
    now = _now()
    with db._lock, db._connect() as conn:
        existing = {r["id"] for r in conn.execute("SELECT id FROM advisory_rules").fetchall()}
        new = [rule for rule, _ in compiled if rule["id"] not in existing]
        if len(existing) + len(new) > MAX_RULES:
            raise engine.RuleError([f"Importing would make more than {MAX_RULES} rules."])
        for rule, on in compiled:
            stored = json.dumps(rule["public"], sort_keys=True)
            if rule["id"] not in existing:
                conn.execute("INSERT INTO advisory_rules (id, rule, enabled, created_by, created_at, updated_by, "
                             "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (rule["id"], stored, 1 if on else 0, user, now, user, now))
                result["added"].append(rule["id"])
            elif replace:
                conn.execute("UPDATE advisory_rules SET rule = ?, enabled = ?, updated_by = ?, updated_at = ? "
                             "WHERE id = ?", (stored, 1 if on else 0, user, now, rule["id"]))
                result["replaced"].append(rule["id"])
            else:
                result["skipped"].append(rule["id"])
    return result


def examples():
    """The example rules that come with DomainLens, each with whether a rule
    of that id is already stored. They are suggestions, not built-in rules:
    nothing looks for them until an administrator adds one."""
    payload = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))
    with db._connect() as conn:
        stored = {r["id"] for r in conn.execute("SELECT id FROM advisory_rules").fetchall()}
    return [{**engine.compile_rule(raw)["public"], "added": raw["id"] in stored}
            for raw in _payload_rules(payload)]


def example_payload(ids):
    """The examples with these ids, in the import format."""
    payload = json.loads(EXAMPLES_PATH.read_text(encoding="utf-8"))
    wanted = set(ids)
    return {**payload, "rules": [r for r in payload["rules"] if r.get("id") in wanted]}

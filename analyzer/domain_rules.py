"""Domain rules: sites that are never recorded, or kept as metadata only, in any audit."""

from __future__ import annotations

from recorder import rules
from shared import db
from shared.protocol import ProtocolError

VALID_RULES = (rules.METADATA_ONLY, rules.DONT_TRACK)


def list_domain_rules(conn, payload) -> dict:
    return {"domains": [{"domain": m, "rule": r} for m, r in conn.execute(
        "SELECT match, rule FROM app_rules WHERE kind = 'domain' AND rule IN (?, ?) ORDER BY match", VALID_RULES)]}


def set_domain_rule(conn, payload: dict) -> dict:
    domain = payload.get("domain")
    rule = payload.get("rule")
    if rule is not None and rule not in VALID_RULES:
        raise ProtocolError("bad_payload", "rule must be metadata_only, dont_track or null")
    if not isinstance(domain, str):
        raise ProtocolError("bad_payload", "domain is required")
    domain = domain.strip().lower().lstrip(".").rstrip(".")
    if not domain or len(domain) > 253 or not all(c.isalnum() or c in "-." for c in domain):
        raise ProtocolError("bad_payload", "not a valid domain")
    if rule is None:
        conn.execute("DELETE FROM app_rules WHERE kind = 'domain' AND match = ?", (domain,))
    else:
        conn.execute(
            "INSERT INTO app_rules (kind, match, rule, source, updated_at) VALUES ('domain', ?, ?, 'user', ?) "
            "ON CONFLICT(kind, match) DO UPDATE SET rule = excluded.rule, source = 'user', updated_at = excluded.updated_at",
            (domain, rule, db.now_ms()))
    return {"ok": True}

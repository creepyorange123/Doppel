"""App list and capture rules, as served to the settings screen."""

from __future__ import annotations

from recorder import rules
from shared import db
from shared.protocol import ProtocolError

VALID_RULES = (rules.TRACK, rules.METADATA_ONLY, rules.DONT_TRACK)


def _running_apps() -> list[tuple[str, str]]:
    """(path, display name) of visible, non-system apps running now."""
    try:
        from mitmproxy_rs import process_info

        out = []
        for p in process_info.active_executables():
            path = str(p.executable)
            if p.is_system or rules.is_system_process(path, p.display_name):
                continue
            out.append((path, p.display_name))
        return out
    except Exception:
        return []


def list_apps(conn) -> dict:
    apps: dict[str, dict] = {}
    for path, name, count, last in conn.execute(
        "SELECT app_path, max(app_name), count(*), max(captured_at) FROM requests "
        "WHERE app_path IS NOT NULL GROUP BY app_path"
    ):
        key = rules.normalize_app_path(path)
        apps[key] = {"key": key, "path": path, "name": name, "requests": count, "last_seen_at": last,
                     "running": False, "rule": None, "rule_source": None}
    for path, name in _running_apps():
        key = rules.normalize_app_path(path)
        entry = apps.setdefault(key, {"key": key, "path": path, "name": name, "requests": 0,
                                      "last_seen_at": None, "running": False, "rule": None, "rule_source": None})
        entry["running"] = True
    domains = []
    for kind, match, rule, source in conn.execute("SELECT kind, match, rule, source FROM app_rules ORDER BY match"):
        if kind == "action":
            continue  # block/strip actions are shown on the report screen
        if kind == "app":
            entry = apps.setdefault(match, {"key": match, "path": match, "name": rules.app_display_name(match),
                                            "requests": 0, "last_seen_at": None, "running": False})
            entry["rule"], entry["rule_source"] = rule, source
        else:
            domains.append({"domain": match, "rule": rule})
    return {
        "mode": db.get_setting(conn, "tracking_mode", "blocklist"),
        "apps": sorted(apps.values(), key=lambda a: (-(a["requests"] or 0), (a["name"] or "").lower())),
        "domains": domains,
    }


def _check_rule(rule) -> str:
    if rule not in VALID_RULES and rule is not None:
        raise ProtocolError("bad_payload", "rule must be track, metadata_only, dont_track or null")
    return rule


def set_app_rule(conn, payload: dict) -> dict:
    key = payload.get("key")
    rule = _check_rule(payload.get("rule"))
    if not isinstance(key, str) or not key or len(key) > 4096:
        raise ProtocolError("bad_payload", "key is required")
    key = rules.normalize_app_path(key) or key
    _upsert(conn, "app", key, rule)
    return {"ok": True}


def set_domain_rule(conn, payload: dict) -> dict:
    domain = payload.get("domain")
    rule = _check_rule(payload.get("rule"))
    if not isinstance(domain, str):
        raise ProtocolError("bad_payload", "domain is required")
    domain = domain.strip().lower().lstrip(".").rstrip(".")
    if not domain or len(domain) > 253 or not all(c.isalnum() or c in "-." for c in domain):
        raise ProtocolError("bad_payload", "not a valid domain")
    _upsert(conn, "domain", domain, rule)
    return {"ok": True}


def _upsert(conn, kind: str, match: str, rule: str | None) -> None:
    if rule is None:
        conn.execute("DELETE FROM app_rules WHERE kind = ? AND match = ?", (kind, match))
        return
    conn.execute(
        "INSERT INTO app_rules (kind, match, rule, source, updated_at) VALUES (?, ?, ?, 'user', ?) "
        "ON CONFLICT(kind, match) DO UPDATE SET rule = excluded.rule, source = 'user', updated_at = excluded.updated_at",
        (kind, match, rule, db.now_ms()),
    )


def set_tracking_mode(conn, payload: dict) -> dict:
    mode = payload.get("mode")
    if mode not in ("blocklist", "allowlist"):
        raise ProtocolError("bad_payload", "mode must be blocklist or allowlist")
    db.set_setting(conn, "tracking_mode", mode)
    return {"ok": True}


def delete_app_data(conn, payload: dict) -> dict:
    key = payload.get("key")
    if not isinstance(key, str) or not key:
        raise ProtocolError("bad_payload", "key is required")
    key = rules.normalize_app_path(key) or key
    # Match case-insensitively on Windows paths (keys are normalized lowercase there).
    cur = conn.execute("DELETE FROM requests WHERE lower(app_path) = lower(?)", (key,))
    deleted = cur.rowcount
    db.checkpoint_truncate(conn)  # secure_delete is on; also fold the WAL so nothing survives there
    return {"deleted": deleted}

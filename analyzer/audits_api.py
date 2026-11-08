"""Audit requests: pick apps, create/finish audits, live counts, self-audit result."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from recorder import rules
from shared import audits, browsers, db
from shared.audits import AuditError, app_bundle_root
from shared.protocol import ProtocolError

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_FOLDERS = ("/Applications/", str(Path.home() / "Applications") + "/")
LIVE_TOP = 15


def _err(exc: AuditError) -> ProtocolError:
    return ProtocolError("bad_payload", str(exc))


def _audit_id(payload: dict) -> int:
    audit_id = payload.get("audit_id")
    if not isinstance(audit_id, int) or isinstance(audit_id, bool):
        raise ProtocolError("bad_payload", "audit_id is required")
    return audit_id


def get_audit(conn, payload: dict) -> audits.Audit:
    try:
        return audits.get(conn, _audit_id(payload))
    except AuditError as exc:
        raise ProtocolError("unknown_audit", str(exc)) from None


def _is_doppel(path: str) -> bool:
    """Doppel's own processes are audited only through the self-audit."""
    return path.startswith(str(REPO_ROOT) + os.sep) or "/Doppel.app" in path or path == sys.executable


def _executables() -> list[tuple[str, str, bool, bool]]:
    try:
        from mitmproxy_rs import process_info

        return [(str(p.executable), p.display_name, p.is_visible, p.is_system) for p in process_info.active_executables()]
    except Exception:
        return []


def list_running_apps(conn, payload, executables=_executables) -> dict:
    """Running apps you can audit: one entry per app, its helpers folded in."""
    groups: dict[str, dict] = {}
    for path, display, visible, system in executables():
        if system or rules.is_system_process(path, display) or _is_doppel(path) or "," in path or "@" in path:
            continue
        root = app_bundle_root(path)
        name = Path(root).stem if root.endswith(".app") else display
        g = groups.setdefault(root, {"path": root, "name": name, "processes": 0, "visible": False})
        g["processes"] += 1
        g["visible"] |= visible
    apps = [g for g in groups.values()
            if g["visible"] or (g["path"].endswith(".app") and g["path"].startswith(APP_FOLDERS))]
    apps.sort(key=lambda g: (not g["visible"], g["name"].lower()))
    out = []
    for g in apps:
        info = browsers.detect(g["path"])
        out.append({"path": g["path"], "name": g["name"], "processes": g["processes"],
                    "is_browser": info.is_browser, "hint": info.hint})
    return {"apps": out}


def list_audits(conn, payload) -> dict:
    audits.settle(conn)
    return {"audits": [a.public() for a in audits.all_audits(conn)]}


def create_audit(conn, payload) -> dict:
    try:
        return {"audit": audits.create(conn, payload).public()}
    except AuditError as exc:
        raise _err(exc) from None


def finish_audit(conn, payload) -> dict:
    status = payload.get("status", "done")
    error = payload.get("error")
    if error is not None and not isinstance(error, str):
        raise ProtocolError("bad_payload", "error must be a string")
    try:
        return {"audit": audits.finish(conn, _audit_id(payload), status, error).public()}
    except AuditError as exc:
        raise _err(exc) from None


def delete_audit(conn, payload) -> dict:
    audit = get_audit(conn, payload)
    if audit.status == "running":
        raise ProtocolError("audit_running", "stop the audit before deleting it")
    deleted = audit.requests
    conn.execute("DELETE FROM audits WHERE id = ?", (audit.id,))  # requests, findings, scores cascade
    db.checkpoint_truncate(conn)  # secure_delete is on; also fold the WAL so nothing survives there
    return {"deleted": deleted}


def audit_live(conn, payload) -> dict:
    """Metadata-only counts for the live audit panel (no URLs or content)."""
    audit = get_audit(conn, payload)
    aid = audit.id
    total, last = conn.execute("SELECT count(*), max(captured_at) FROM requests WHERE audit_id = ?", (aid,)).fetchone()
    apps = [{"name": n or "Unknown app", "requests": c} for n, c in conn.execute(
        "SELECT app_name, count(*) c FROM requests WHERE audit_id = ? GROUP BY app_name ORDER BY c DESC", (aid,))]
    procs = [{"app": a or "Unknown app", "process": p or a or "Unknown", "requests": c} for a, p, c in conn.execute(
        "SELECT app_name, process_name, count(*) c FROM requests WHERE audit_id = ? "
        "GROUP BY app_name, process_name ORDER BY c DESC LIMIT ?", (aid, LIVE_TOP))]
    domains = [{"domain": d, "requests": c} for d, c in conn.execute(
        "SELECT dest_domain, count(*) c FROM requests WHERE audit_id = ? GROUP BY dest_domain ORDER BY c DESC LIMIT ?",
        (aid, LIVE_TOP))]
    return {"audit": audit.public(), "requests": total, "last_at": last, "apps": apps, "processes": procs,
            "domains": domains}


def self_audit_result(conn, payload) -> dict:
    """Every connection Doppel's own processes made during a self-audit, checked
    against the tamper-evident list of outgoing calls (the ledger)."""
    audit = get_audit(conn, payload)
    if not audit.self_audit:
        raise ProtocolError("bad_payload", "that audit is not a self-audit")
    until = audit.ended_at or db.now_ms()
    ledger_hosts: dict[str, int] = {}
    for (dest,) in conn.execute("SELECT destination FROM ledger WHERE sent_at BETWEEN ? AND ?",
                                (audit.started_at, until)):
        ledger_hosts[dest.lower()] = ledger_hosts.get(dest.lower(), 0) + 1
    connections = []
    for process, domain, count in conn.execute(
            "SELECT process_name, dest_domain, count(*) FROM requests WHERE audit_id = ? "
            "GROUP BY process_name, dest_domain ORDER BY count(*) DESC", (audit.id,)):
        connections.append({"process": process or "Doppel", "domain": domain, "requests": count,
                            "in_ledger": domain.lower() in ledger_hosts})
    unexpected = sum(1 for c in connections if not c["in_ledger"])
    verdict = "no_traffic" if not connections else ("unexpected" if unexpected else "clean")
    return {"audit": audit.public(), "connections": connections, "ledger_entries": sum(ledger_hosts.values()),
            "unexpected": unexpected, "verdict": verdict}

"""Dispatch table for analyzer requests. Each handler: (conn, payload) -> dict."""

from __future__ import annotations

from typing import Any, Callable

from analyzer import audits_api, domain_rules, export, pipeline, privacy_checks, report, settings_api
from shared import audits, db, protocol


def _int_or_none(value: str | None) -> int | None:
    return int(value) if value is not None else None


def hello(conn, payload) -> dict:
    return {"version": protocol.PROTOCOL_VERSION, "db_path_set": True}


def status(conn, payload) -> dict:
    total, unanalyzed = conn.execute(
        "SELECT count(*), coalesce(sum(analyzed = 0), 0) FROM requests"
    ).fetchone()
    audits.settle(conn)
    active = audits.running(conn)
    return {
        "request_count": total,
        "unanalyzed_count": unanalyzed,
        "install_at": _int_or_none(db.get_setting(conn, "install_at")),
        "consent_at": _int_or_none(db.get_setting(conn, "consent_at")),
        "active_audit_id": active.id if active else None,
    }


HANDLERS: dict[str, Callable[[Any, dict], dict]] = {
    "hello": hello,
    "status": status,
    "list_running_apps": audits_api.list_running_apps,
    "list_audits": audits_api.list_audits,
    "audit_live": audits_api.audit_live,
    "analyze_audit": pipeline.analyze_audit,
    "delete_audit": audits_api.delete_audit,
    "self_audit_result": audits_api.self_audit_result,
    "list_domain_rules": domain_rules.list_domain_rules,
    "set_domain_rule": domain_rules.set_domain_rule,
    "get_settings": settings_api.get_settings,
    "set_setting": settings_api.set_setting,
    "ledger_verify": settings_api.ledger_verify,
    "ledger_list": settings_api.ledger_list,
    "report": report.report,
    "company_detail": report.company_detail,
    "list_requests": report.list_requests,
    "take_action": report.take_action,
    "export_blocklist": export.export_blocklist,
    "privacy_checks": privacy_checks.handle,
    "create_audit": audits_api.create_audit,
    "finish_audit": audits_api.finish_audit,
}


def handle(conn, msg_type: str, payload: dict, emit: Callable[[str, dict], None] | None = None) -> dict:
    fn = HANDLERS.get(msg_type)
    if fn is None:
        raise protocol.ProtocolError("unknown_type", msg_type)
    if getattr(fn, "streams", False):
        return fn(conn, payload, emit or (lambda *_: None))
    return fn(conn, payload)

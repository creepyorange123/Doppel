"""Dispatch table for analyzer requests. Each handler: (conn, payload) -> dict."""

from __future__ import annotations

from typing import Any, Callable

from analyzer import app_rules, pipeline, report, settings_api
from shared import db, protocol


def _int_or_none(value: str | None) -> int | None:
    return int(value) if value is not None else None


def hello(conn, payload) -> dict:
    return {"version": protocol.PROTOCOL_VERSION, "db_path_set": True}


def status(conn, payload) -> dict:
    total, unanalyzed = conn.execute(
        "SELECT count(*), coalesce(sum(analyzed = 0), 0) FROM requests"
    ).fetchone()
    return {
        "request_count": total,
        "unanalyzed_count": unanalyzed,
        "install_at": _int_or_none(db.get_setting(conn, "install_at")),
        "last_opened_at": _int_or_none(db.get_setting(conn, "last_opened_at")),
        "recorder_heartbeat_at": _int_or_none(db.get_setting(conn, "recorder_heartbeat_at")),
        "consent_at": _int_or_none(db.get_setting(conn, "consent_at")),
    }


HANDLERS: dict[str, Callable[[Any, dict], dict]] = {
    "hello": hello,
    "status": status,
    "list_apps": lambda c, p: app_rules.list_apps(c),
    "set_app_rule": app_rules.set_app_rule,
    "set_domain_rule": app_rules.set_domain_rule,
    "set_tracking_mode": app_rules.set_tracking_mode,
    "delete_app_data": app_rules.delete_app_data,
    "analyze_since_last_open": pipeline.analyze_since_last_open,
    "get_settings": settings_api.get_settings,
    "set_setting": settings_api.set_setting,
    "ledger_verify": settings_api.ledger_verify,
    "ledger_list": settings_api.ledger_list,
    "report": report.report,
    "company_detail": report.company_detail,
    "take_action": report.take_action,
    "undo_action": report.undo_action,
}


def handle(conn, msg_type: str, payload: dict, emit: Callable[[str, dict], None] | None = None) -> dict:
    fn = HANDLERS.get(msg_type)
    if fn is None:
        raise protocol.ProtocolError("unknown_type", msg_type)
    if getattr(fn, "streams", False):
        return fn(conn, payload, emit or (lambda *_: None))
    return fn(conn, payload)

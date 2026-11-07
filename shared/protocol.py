"""Analyzer <-> app message format. See shared/PROTOCOL.md.

Keep REQUEST_TYPES in sync with app/src/shared/protocol.ts.
"""

from __future__ import annotations

import json
from typing import Any

PROTOCOL_VERSION = "0.1.0"
MAX_LINE_BYTES = 1_000_000

REQUEST_TYPES = frozenset({
    "hello", "status",
    # Phase 1: app list
    "list_apps", "set_app_rule", "set_domain_rule", "set_tracking_mode", "delete_app_data",
})
EVENT_TYPES = frozenset({"ready", "progress"})


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str, msg_id: int | None = None):
        super().__init__(message)
        self.code = code
        self.msg_id = msg_id


def parse_request(line: str) -> tuple[int, str, dict[str, Any]]:
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise ProtocolError("too_large", "message exceeds 1 MB")
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError("bad_json", str(exc)) from None
    if not isinstance(msg, dict):
        raise ProtocolError("bad_message", "message must be an object")
    msg_id, msg_type, payload = msg.get("id"), msg.get("type"), msg.get("payload", {})
    if not isinstance(msg_id, int) or isinstance(msg_id, bool):
        raise ProtocolError("bad_message", "id must be an integer")
    if msg_type not in REQUEST_TYPES:
        raise ProtocolError("unknown_type", f"unknown request type: {msg_type!r}", msg_id)
    if not isinstance(payload, dict):
        raise ProtocolError("bad_message", "payload must be an object", msg_id)
    return msg_id, msg_type, payload


def result(msg_id: int, payload: dict[str, Any]) -> str:
    return json.dumps({"id": msg_id, "type": "result", "payload": payload}, separators=(",", ":"))


def error(msg_id: int | None, code: str, message: str) -> str:
    return json.dumps(
        {"id": msg_id, "type": "error", "payload": {"code": code, "message": message}},
        separators=(",", ":"),
    )


def event(event_type: str, payload: dict[str, Any]) -> str:
    assert event_type in EVENT_TYPES
    return json.dumps({"type": event_type, "payload": payload}, separators=(",", ":"))

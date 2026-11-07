"""User-facing toggles and the 'What left this device' ledger."""

from __future__ import annotations

from analyzer.research import ledger
from shared import db
from shared.protocol import ProtocolError

TOGGLES = ("zero_network", "gpc", "local_ai")


def get_settings(conn, payload) -> dict:
    out = {k: db.get_setting(conn, k, "0") == "1" for k in TOGGLES}
    out["tracking_mode"] = db.get_setting(conn, "tracking_mode", "blocklist")
    return out


def set_setting(conn, payload) -> dict:
    key, value = payload.get("key"), payload.get("value")
    if key not in TOGGLES or not isinstance(value, bool):
        raise ProtocolError("bad_payload", f"key must be one of {', '.join(TOGGLES)} and value a boolean")
    db.set_setting(conn, key, "1" if value else "0")
    return {"ok": True}


def ledger_verify(conn, payload) -> dict:
    return ledger.verify(conn)


def ledger_list(conn, payload) -> dict:
    return {"entries": ledger.entries(conn), "latest_hash": ledger.latest_hash(conn)}

"""Shared test helpers."""

import json

from shared import db


def make_audit(conn, *, label="Test audit", apps=None, started_at=0, ends_at=None, status="done",
               self_audit=False, ended_at=None) -> int:
    """Insert an audit row directly (no path checks) and return its id."""
    apps = apps if apps is not None else [{"name": "App", "path": "/Applications/App.app", "capture": "full"}]
    ends_at = ends_at if ends_at is not None else max(db.now_ms(), started_at) + 3_600_000
    cur = conn.execute(
        "INSERT INTO audits (label, apps, self_audit, started_at, ends_at, ended_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (label, json.dumps(apps), int(self_audit), started_at, ends_at,
         ended_at if ended_at is not None or status == "running" else ends_at, status))
    return cur.lastrowid

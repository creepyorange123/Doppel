"""'What left this device': an append-only, hash-chained ledger.

Each entry's hash covers its own fields and the previous entry's hash, so
editing or deleting any entry breaks the chain from that point on. Deleting
the *newest* entries can't be detected from the chain alone, which is why the
UI shows the latest hash (security checklist #8).
"""

from __future__ import annotations

import hashlib
import json

from shared import db

GENESIS = "0" * 64


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(entry_id: int, sent_at: int, destination: str, payload: str, prev_hash: str) -> str:
    material = _canonical({"id": entry_id, "sent_at": sent_at, "destination": destination,
                           "payload": payload, "prev_hash": prev_hash})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def latest_hash(conn) -> str:
    row = conn.execute("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else GENESIS


def append(conn, destination: str, payload: dict) -> str:
    """Record an outgoing call. Must be called before the call is made."""
    body = _canonical(payload)
    sent_at = db.now_ms()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT id, hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
        prev_id, prev = (row[0], row[1]) if row else (0, GENESIS)
        new_id = prev_id + 1
        h = entry_hash(new_id, sent_at, destination, body, prev)
        conn.execute("INSERT INTO ledger (id, sent_at, destination, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
                     (new_id, sent_at, destination, body, prev, h))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return h


def verify(conn) -> dict:
    prev = GENESIS
    expected_id = 1
    count = 0
    for entry_id, sent_at, dest, payload, prev_hash, h in conn.execute(
        "SELECT id, sent_at, destination, payload, prev_hash, hash FROM ledger ORDER BY id"
    ):
        count += 1
        if (entry_id != expected_id or prev_hash != prev
                or entry_hash(entry_id, sent_at, dest, payload, prev_hash) != h):
            return {"ok": False, "entries": count, "broken_at": entry_id, "latest_hash": latest_hash(conn)}
        prev = h
        expected_id += 1
    return {"ok": True, "entries": count, "broken_at": None, "latest_hash": prev}


def entries(conn, limit: int = 200) -> list[dict]:
    rows = conn.execute("SELECT id, sent_at, destination, payload, hash FROM ledger ORDER BY id DESC LIMIT ?",
                        (limit,)).fetchall()
    return [{"id": r[0], "sent_at": r[1], "destination": r[2], "payload": json.loads(r[3]), "hash": r[4]}
            for r in rows]

"""Phase 2: analyze everything logged since the app was last opened.

Selection: every request with ``captured_at > last_opened_at`` (install time on
first launch) **or** ``analyzed = 0`` - the second condition is the safety net,
so a crash or clock change never skips a request.

Crash safety: findings and scores are written with INSERT OR REPLACE, so a
re-run is idempotent. Only after every request has been processed do we, in one
transaction, mark them analyzed, delete their raw content and save the new
``last_opened_at``.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable

from shared import db

BATCH = 200

# Raw content removed after analysis; findings, scores and the HMAC flags stay.
RAW_COLUMNS = ("body", "headers", "cookies", "url", "page_url")

Step = Callable[[Any, dict], None]


def _basic_finding(conn, row: dict) -> None:
    """Fallback step: record that the request was seen. Phase 3 replaces this."""
    conn.execute(
        "INSERT OR REPLACE INTO findings (request_id, company, category, flags, topic, summary) "
        "VALUES (?, NULL, NULL, ?, NULL, ?)",
        (row["id"], row["flags"] or "[]", f"Sent to {row['dest_domain']}."),
    )


STEPS: list[Step] = [_basic_finding]


def since_label(count: int, since_ms: int) -> str:
    t = dt.datetime.fromtimestamp(since_ms / 1000)
    hour = t.hour % 12 or 12
    when = f"{t.strftime('%A')} {hour}:{t.minute:02d} {'am' if t.hour < 12 else 'pm'}"
    return f"Analyzing {count:,} request{'s' if count != 1 else ''} since {when}"


def select_new(conn, since: int) -> list[int]:
    return [r[0] for r in conn.execute(
        "SELECT id FROM requests WHERE captured_at > ? OR analyzed = 0 ORDER BY captured_at DESC, id DESC",
        (since,),
    )]


def _rows(conn, ids: list[int]) -> list[dict]:
    q = f"SELECT * FROM requests WHERE id IN ({','.join('?' * len(ids))}) ORDER BY captured_at DESC, id DESC"
    cur = conn.execute(q, ids)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def analyze_since_last_open(conn, payload: dict, emit: Callable[[str, dict], None]) -> dict:
    started = db.now_ms()
    last = db.get_setting(conn, "last_opened_at")
    since = int(last) if last is not None else int(db.get_setting(conn, "install_at") or 0)
    ids = select_new(conn, since)
    total = len(ids)
    label = since_label(total, since)
    emit("progress", {"done": 0, "total": total, "label": label})

    for start in range(0, total, BATCH):
        chunk = ids[start:start + BATCH]
        conn.execute("BEGIN")
        try:
            for row in _rows(conn, chunk):
                for step in STEPS:
                    step(conn, row)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        emit("progress", {"done": min(start + BATCH, total), "total": total, "label": label})

    conn.execute("BEGIN")
    try:
        for start in range(0, total, BATCH):
            chunk = ids[start:start + BATCH]
            marks = ",".join("?" * len(chunk))
            sets = ", ".join(f"{c} = NULL" for c in RAW_COLUMNS)
            conn.execute(f"UPDATE requests SET analyzed = 1, {sets} WHERE id IN ({marks})", chunk)
        db.set_setting(conn, "last_opened_at", str(started))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    db.checkpoint_truncate(conn)  # deleted content must not survive in the WAL
    return {"analyzed": total, "since": since, "finished_at": db.now_ms()}


analyze_since_last_open.streams = True  # type: ignore[attr-defined]

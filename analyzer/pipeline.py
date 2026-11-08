"""Analyze an audit's requests once it ends.

Selection: every request of the audit with ``analyzed = 0``. Called without an
audit, it analyses every unanalysed request (the safety net after a crash).

Crash safety: findings and scores are written with INSERT OR REPLACE, so a
re-run is idempotent. Only after every request has been processed do we, in one
transaction, mark them analyzed, delete their raw content and stamp the audit.
"""

from __future__ import annotations

from typing import Any, Callable

from analyzer import context
from shared import audits, db
from shared.protocol import ProtocolError

BATCH = 50  # short write-lock holds so the recorder never waits long

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


# Stage 1 (identify, record ID sightings) runs over every new request before
# stage 2 (score), so cross-site checks see the whole batch.
STEPS: list[Step] = [_basic_finding]
SCORE_STEPS: list[Step] = []


def run_label(count: int, audit_label: str | None) -> str:
    what = f"{count:,} request{'s' if count != 1 else ''}"
    return f"Analyzing {what} from {audit_label}" if audit_label else f"Analyzing {what}"


def select_new(conn, audit_id: int | None) -> list[int]:
    if audit_id is None:
        # Every finished audit's leftovers; a running audit is analysed when it ends.
        sql, args = ("SELECT r.id FROM requests r JOIN audits a ON a.id = r.audit_id "
                     "WHERE r.analyzed = 0 AND a.status != 'running' ORDER BY r.captured_at DESC, r.id DESC", ())
    else:
        sql, args = ("SELECT id FROM requests WHERE audit_id = ? AND analyzed = 0 ORDER BY captured_at DESC, id DESC",
                     (audit_id,))
    return [r[0] for r in conn.execute(sql, args)]


def _rows(conn, ids: list[int]) -> list[dict]:
    q = f"SELECT * FROM requests WHERE id IN ({','.join('?' * len(ids))}) ORDER BY captured_at DESC, id DESC"
    cur = conn.execute(q, ids)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def analyze_audit(conn, payload: dict, emit: Callable[[str, dict], None]) -> dict:
    audit_id = payload.get("audit_id")
    label = None
    if audit_id is not None:
        try:
            audit = audits.get(conn, audit_id)
        except audits.AuditError as exc:
            raise ProtocolError("unknown_audit", str(exc)) from None
        if audit.status == "running":
            raise ProtocolError("audit_running", "the audit is still recording")
        label = f"your {audit.label} audit"
    ids = select_new(conn, audit_id)
    total = len(ids)
    text = run_label(total, label)
    emit("progress", {"done": 0, "total": total, "label": text})

    if total:
        # Metadata-only requests have no Referer: attribute them to the page you had open.
        conn.execute("BEGIN IMMEDIATE")
        try:
            context.infer_pages(conn, ids)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    stages = [s for s in (STEPS, SCORE_STEPS) if s]
    work = total * len(stages)
    done = 0
    for steps in stages:
        for start in range(0, total, BATCH):
            chunk = ids[start:start + BATCH]
            conn.execute("BEGIN IMMEDIATE")  # take the write lock now; see test_survives_recorder_writing_at_the_same_time
            try:
                for row in _rows(conn, chunk):
                    for step in steps:
                        step(conn, row)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            done += len(chunk)
            # Report in requests, not request-stages.
            emit("progress", {"done": done * total // max(work, 1), "total": total, "label": text})

    conn.execute("BEGIN IMMEDIATE")
    try:
        for start in range(0, total, BATCH):
            chunk = ids[start:start + BATCH]
            marks = ",".join("?" * len(chunk))
            sets = ", ".join(f"{c} = NULL" for c in RAW_COLUMNS)
            conn.execute(f"UPDATE requests SET analyzed = 1, {sets} WHERE id IN ({marks})", chunk)
        now = db.now_ms()
        if audit_id is not None:
            conn.execute("UPDATE audits SET analyzed_at = ? WHERE id = ? AND status != 'running'", (now, audit_id))
        else:
            conn.execute("UPDATE audits SET analyzed_at = ? WHERE status != 'running' AND NOT EXISTS "
                         "(SELECT 1 FROM requests r WHERE r.audit_id = audits.id AND r.analyzed = 0)", (now,))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    db.checkpoint_truncate(conn)  # deleted content must not survive in the WAL
    return {"analyzed": total, "audit_id": audit_id, "finished_at": db.now_ms()}


analyze_audit.streams = True  # type: ignore[attr-defined]

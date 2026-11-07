"""Analyzer sidecar: started by the Electron app on open, speaks JSON lines on stdio.

Phase 0 only answers `hello` and `status`. Steps 1-4 (fetch since last open,
identify, score) arrive in phases 2-4.
"""

from __future__ import annotations

import logging
import sys

from shared import db, protocol

# Security checklist #9: no request logging. Diagnostics go to stderr and must
# never include captured content.
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="analyzer: %(message)s")
log = logging.getLogger("analyzer")


def _int_or_none(value: str | None) -> int | None:
    return int(value) if value is not None else None


def handle(conn, msg_type: str, payload: dict) -> dict:
    if msg_type == "hello":
        return {"version": protocol.PROTOCOL_VERSION, "db_path_set": True}
    if msg_type == "status":
        total, unanalyzed = conn.execute(
            "SELECT count(*), coalesce(sum(analyzed = 0), 0) FROM requests"
        ).fetchone()
        return {
            "request_count": total,
            "unanalyzed_count": unanalyzed,
            "install_at": _int_or_none(db.get_setting(conn, "install_at")),
            "last_opened_at": _int_or_none(db.get_setting(conn, "last_opened_at")),
            "recorder_heartbeat_at": _int_or_none(db.get_setting(conn, "recorder_heartbeat_at")),
        }
    raise protocol.ProtocolError("unknown_type", msg_type)


def write(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def main() -> int:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    conn = db.open_db()
    write(protocol.event("ready", {"version": protocol.PROTOCOL_VERSION}))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg_id = None
        try:
            msg_id, msg_type, payload = protocol.parse_request(line)
            write(protocol.result(msg_id, handle(conn, msg_type, payload)))
        except protocol.ProtocolError as exc:
            write(protocol.error(msg_id if msg_id is not None else exc.msg_id, exc.code, str(exc)))
        except Exception as exc:  # never echo captured data back in errors
            log.warning("internal error: %s", type(exc).__name__)
            write(protocol.error(msg_id, "internal", type(exc).__name__))
    db.checkpoint_truncate(conn)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

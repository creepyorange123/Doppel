"""Analyzer sidecar: started by the Electron app on open, speaks JSON lines on stdio."""

from __future__ import annotations

import logging
import sys

from analyzer import handlers, pipeline, setup
from shared import db, protocol

# Security checklist #9: no request logging. Diagnostics go to stderr and must
# never include captured content.
logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="analyzer: %(message)s")
log = logging.getLogger("shadow.analyzer")


def write(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def emit(event_type: str, payload: dict) -> None:
    write(protocol.event(event_type, payload))


def main() -> int:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    conn = db.open_db()
    pipeline.STEPS[:] = setup.build_steps(conn)
    emit("ready", {"version": protocol.PROTOCOL_VERSION})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg_id = None
        try:
            msg_id, msg_type, payload = protocol.parse_request(line)
            write(protocol.result(msg_id, handlers.handle(conn, msg_type, payload, emit)))
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

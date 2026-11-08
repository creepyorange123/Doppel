"""DEVELOPMENT ONLY: a plaintext log of every connection the proxy sees.

This deliberately breaks security checklist #9 (no request logging), so it is
off unless the recorder is started by hand with ``run --dev-traffic-log PATH``.
The login service never passes that flag. The file holds full URLs, which can
include tokens in query strings: keep it out of git and delete it when done.

One tab-separated line per event:
    time  kind  app  decision  method  status  target  note
kind is TLS (a new HTTPS connection; target is the site name), HTTP (a request;
target is the full URL), QUIC (blocked HTTP/3) or TLS-FAIL (handshake failed).
"""

from __future__ import annotations

import datetime as dt
import os
import threading
from pathlib import Path

HEADER = "time\tkind\tapp\tdecision\tmethod\tstatus\ttarget\tnote\n"


def _clean(value: object) -> str:
    return str(value if value is not None else "").replace("\t", " ").replace("\n", " ").replace("\r", " ")


class TrafficLog:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Owner-only, append, never truncate an existing log.
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self.file = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()
        if self.path.stat().st_size == 0:
            self.file.write(HEADER)

    def write(self, kind: str, app: str | None, decision: str | None, target: str,
              method: str = "", status: int | str | None = "", note: str = "") -> None:
        now = dt.datetime.now().isoformat(timespec="milliseconds")
        line = "\t".join(_clean(v) for v in (now, kind, app or "Unknown app", decision or "", method, status, target, note))
        with self.lock:
            self.file.write(line + "\n")

    def close(self) -> None:
        with self.lock:
            self.file.close()

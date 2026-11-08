"""Audits: "use these apps as you normally would for this long".

Shared by the analyzer (creates, lists, reports) and the recorder (reads the
audit it was started for and marks it finished). Nothing is recorded outside an
audit; every request row carries its audit's id.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath

from shared import browsers, db

MAX_APPS = 20
MAX_MINUTES = 240
CAPTURES = ("full", "metadata_only")
STATUSES = ("running", "done", "interrupted", "failed")
# A "running" audit this long past its end time has lost its recorder.
STALE_AFTER_MS = 2 * 60 * 1000
# The redirector's process filter is a comma-separated list where "!" excludes and
# a bare number is a PID; "@" splits off a listen address in mitmproxy's mode spec.
_UNSAFE_PATH_CHARS = (",", "@", "\n", "\r", "\0")


class AuditError(ValueError):
    pass


@dataclass(frozen=True)
class AuditApp:
    name: str
    path: str | None
    capture: str = "full"
    pids: tuple[int, ...] = ()
    is_browser: bool = False
    engine: str | None = None  # browsers only: chromium | gecko | webkit

    def as_json(self) -> dict:
        out = {"name": self.name, "path": self.path, "capture": self.capture, "is_browser": self.is_browser}
        if self.engine:
            out["engine"] = self.engine
        if self.pids:
            out["pids"] = list(self.pids)
        return out


@dataclass
class Audit:
    id: int
    label: str
    apps: list[AuditApp]
    self_audit: bool
    started_at: int
    ends_at: int
    ended_at: int | None
    status: str
    error: str | None
    analyzed_at: int | None
    requests: int = 0
    extra: dict = field(default_factory=dict)

    def public(self) -> dict:
        """What the app sees (PIDs are an internal detail of self-audits)."""
        return {
            "id": self.id, "label": self.label,
            "apps": [{"path": a.path or "", "name": a.name, "capture": a.capture, "is_browser": a.is_browser}
                     for a in self.apps],
            "self_audit": self.self_audit, "started_at": self.started_at, "ends_at": self.ends_at,
            "ended_at": self.ended_at, "status": self.status, "requests": self.requests,
            "analyzed": self.analyzed_at is not None, "error": self.error,
        }


def app_bundle_root(path: str) -> str:
    """The outermost ``.app`` folder for a macOS executable, else the path itself.

    /Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper
    -> /Applications/Slack.app
    """
    if "\\" in path:
        return str(PureWindowsPath(path))
    parts = PurePosixPath(path).parts
    for i, part in enumerate(parts):
        if part.endswith(".app"):
            return str(PurePosixPath(*parts[: i + 1]))
    return str(PurePosixPath(path))


def _clean_app(raw: object, *, allow_pids: bool) -> AuditApp:
    if not isinstance(raw, dict):
        raise AuditError("each app must be an object")
    name, path = raw.get("name"), raw.get("path")
    capture = raw.get("capture") or "full"
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise AuditError("each app needs a name")
    if capture not in CAPTURES:
        raise AuditError("capture must be full or metadata_only")
    pids: tuple[int, ...] = ()
    if allow_pids and raw.get("pids") is not None:
        got = raw["pids"]
        if not isinstance(got, list) or not all(isinstance(p, int) and not isinstance(p, bool) and p > 1 for p in got):
            raise AuditError("pids must be a list of process ids")
        pids = tuple(sorted(set(got)))
    if path is not None:
        if not isinstance(path, str) or len(path) > 4096:
            raise AuditError("path must be a string")
        if not (path.startswith("/") or (len(path) > 2 and path[1] == ":")):
            raise AuditError("path must be absolute")
        if any(c in path for c in _UNSAFE_PATH_CHARS):
            raise AuditError(f"{name} can't be audited: its location contains a comma or @")
        from recorder.rules import is_system_process  # local import: recorder depends on shared

        path = app_bundle_root(path)
        if is_system_process(path, name):
            raise AuditError(f"{name} is a system process and can't be audited")
        if not os.path.exists(path):
            raise AuditError(f"{name} is not at {path}")
    if path is None and not pids:
        raise AuditError("each app needs a path")
    info = browsers.detect(path) if not allow_pids else browsers.NOT_A_BROWSER  # self-audits: Doppel is an app
    return AuditApp(name=name.strip(), path=path, capture=capture, pids=pids, is_browser=info.is_browser,
                    engine=info.engine)


def create(conn, payload: dict) -> Audit:
    apps_raw, minutes = payload.get("apps"), payload.get("minutes")
    self_audit = payload.get("self_audit") is True
    if not isinstance(apps_raw, list) or not 1 <= len(apps_raw) <= MAX_APPS:
        raise AuditError(f"choose between 1 and {MAX_APPS} apps")
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= MAX_MINUTES:
        raise AuditError(f"minutes must be a whole number from 1 to {MAX_MINUTES}")
    apps = [_clean_app(a, allow_pids=self_audit) for a in apps_raw]
    seen = set()
    apps = [a for a in apps if not ((a.path, a.pids) in seen or seen.add((a.path, a.pids)))]
    label = payload.get("label")
    if label is not None and (not isinstance(label, str) or len(label) > 120):
        raise AuditError("label must be a short string")
    label = (label or "").strip() or ", ".join(a.name for a in apps)[:120]

    settle(conn)
    if running(conn) is not None:
        raise AuditError("an audit is already running")
    now = db.now_ms()
    cur = conn.execute(
        "INSERT INTO audits (label, apps, self_audit, started_at, ends_at, status) VALUES (?, ?, ?, ?, ?, 'running')",
        (label, json.dumps([a.as_json() for a in apps]), int(self_audit), now, now + minutes * 60_000))
    return get(conn, cur.lastrowid)


def _from_row(row) -> Audit:
    (id_, label, apps, self_audit, started, ends, ended, status, error, analyzed_at, requests) = row
    parsed = []
    for a in json.loads(apps):
        if "is_browser" not in a and not a.get("pids"):  # audits made before browsers were detected
            info = browsers.detect(a.get("path"))
            a = {**a, "is_browser": info.is_browser, "engine": info.engine}
        parsed.append(AuditApp(name=a["name"], path=a.get("path"), capture=a.get("capture", "full"),
                               pids=tuple(a.get("pids") or ()), is_browser=bool(a.get("is_browser")),
                               engine=a.get("engine")))
    return Audit(id=id_, label=label, apps=parsed, self_audit=bool(self_audit), started_at=started, ends_at=ends,
                 ended_at=ended, status=status, error=error, analyzed_at=analyzed_at, requests=requests or 0)


_SELECT = ("SELECT a.id, a.label, a.apps, a.self_audit, a.started_at, a.ends_at, a.ended_at, a.status, a.error, "
           "a.analyzed_at, (SELECT count(*) FROM requests r WHERE r.audit_id = a.id) FROM audits a")


def get(conn, audit_id: int) -> Audit:
    if not isinstance(audit_id, int) or isinstance(audit_id, bool):
        raise AuditError("audit_id must be an integer")
    row = conn.execute(f"{_SELECT} WHERE a.id = ?", (audit_id,)).fetchone()
    if row is None:
        raise AuditError("no such audit")
    return _from_row(row)


def all_audits(conn) -> list[Audit]:
    return [_from_row(r) for r in conn.execute(f"{_SELECT} ORDER BY a.started_at DESC, a.id DESC")]


def running(conn) -> Audit | None:
    row = conn.execute(f"{_SELECT} WHERE a.status = 'running' ORDER BY a.id DESC LIMIT 1").fetchone()
    return _from_row(row) if row else None


def finish(conn, audit_id: int, status: str = "done", error: str | None = None) -> Audit:
    """Mark an audit finished. No change if it already is (first writer wins)."""
    if status not in STATUSES or status == "running":
        raise AuditError("status must be done, interrupted or failed")
    if error is not None:
        error = str(error)[:200]
    conn.execute("UPDATE audits SET status = ?, error = ?, ended_at = ? WHERE id = ? AND status = 'running'",
                 (status, error, min(db.now_ms(), get(conn, audit_id).ends_at), audit_id))
    return get(conn, audit_id)


def settle(conn, now: int | None = None) -> None:
    """Running audits long past their end time lost their recorder (a crash or a
    forced quit): mark them interrupted so a new audit can start."""
    now = now if now is not None else db.now_ms()
    conn.execute("UPDATE audits SET status = 'interrupted', error = 'The recorder stopped unexpectedly.', "
                 "ended_at = ends_at WHERE status = 'running' AND ends_at < ?", (now - STALE_AFTER_MS,))

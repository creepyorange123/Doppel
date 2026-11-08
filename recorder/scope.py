"""Which processes an audit captures.

During an audit the OS redirector sends only the audited apps' connections to
the recorder; every other process on the computer talks to the network
directly, so VPNs, ad blockers and everything else are left alone.

A target app matches by its app bundle (``/Applications/Slack.app/`` also covers
the helper apps inside it) and by process tree: anything it spawns, even from
elsewhere on disk (``node``, ``curl``, an updater), is captured as well. The
filter is rebuilt five times a second as processes come and go; a process stays
in scope for as long as it lives, even if it replaces itself with another
program. A child outside the app's folder that starts and connects within that
fraction of a second can still be missed.
"""

from __future__ import annotations

import ctypes
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Callable

from shared.audits import AuditApp

REFRESH_SECONDS = 0.2  # one process-table read is ~1 ms on macOS: about 0.5% of a core
# One process table entry: pid -> (parent pid, executable path or name)
ProcessTable = dict[int, tuple[int, str]]


_PROC_PIDTBSDINFO = 3
_BSDINFO_SIZE = 136   # sizeof(struct proc_bsdinfo)
_PPID_OFFSET = 16     # pbi_ppid follows pbi_flags, pbi_status, pbi_xstatus, pbi_pid


def _mac_table() -> ProcessTable:
    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    n = lib.proc_listallpids(None, 0)
    pids = (ctypes.c_int * (n + 256))()
    n = lib.proc_listallpids(pids, ctypes.sizeof(pids))
    info = ctypes.create_string_buffer(_BSDINFO_SIZE)
    path = ctypes.create_string_buffer(4096)
    table: ProcessTable = {}
    for pid in pids[:max(n, 0)]:
        # Other users' processes (root daemons) can't be read; they can't be ours anyway.
        if pid <= 0 or lib.proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, info, _BSDINFO_SIZE) != _BSDINFO_SIZE:
            continue
        ppid = struct.unpack_from("I", info.raw, _PPID_OFFSET)[0]
        size = lib.proc_pidpath(pid, path, ctypes.sizeof(path))
        table[pid] = (ppid, path.value.decode("utf-8", "replace") if size > 0 else "")
    return table


def _ps_table() -> ProcessTable:
    try:
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,comm="], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table: ProcessTable = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = (int(parts[1]), parts[2])
    return table


def process_table() -> ProcessTable:
    """Every process's parent and executable. Empty if it can't be read."""
    if sys.platform == "win32":
        return {}  # process-tree tracking is macOS-only for now; app folders still match
    if sys.platform == "darwin":
        try:
            return _mac_table()
        except (OSError, AttributeError):
            pass
    return _ps_table()


def process_label(path: str | None) -> str | None:
    """Slack.app/.../Slack Helper (Renderer).app/Contents/MacOS/Slack Helper (Renderer) -> Slack Helper (Renderer)"""
    if not path:
        return None
    p = PureWindowsPath(path) if "\\" in path else PurePosixPath(path)
    return p.stem if p.suffix.lower() == ".exe" else p.name


def _prefix(app: AuditApp) -> str | None:
    if not app.path:
        return None
    # Bundles match everything inside them; a plain executable matches only itself.
    if app.path.endswith(".app"):
        return app.path.rstrip("/") + "/"
    return app.path


def _under(path: str, prefix: str) -> bool:
    if sys.platform == "win32" or "\\" in prefix:
        return path.lower().startswith(prefix.lower())
    return path.startswith(prefix) if prefix.endswith("/") else path == prefix


class Scope:
    """Audit targets, their live process trees, and the redirector filter for them."""

    def __init__(self, apps: list[AuditApp], *, own_pid: int | None = None,
                 table: Callable[[], ProcessTable] = process_table, any_process: bool = False):
        self.apps = apps
        self.own_pid = own_pid if own_pid is not None else os.getpid()
        self._table = table
        # Tests run mitmproxy as a plain proxy, where the sending process is unknown.
        self.any_process = any_process
        self.pid_targets: dict[int, AuditApp] = {}
        self.refresh()

    def refresh(self) -> str:
        table = self._table()
        children: dict[int, list[int]] = {}
        for pid, (ppid, _) in table.items():
            children.setdefault(ppid, []).append(pid)
        # Still-running processes stay in scope (they may have exec'd another program).
        found: dict[int, AuditApp] = {pid: app for pid, app in self.pid_targets.items() if pid in table}
        for app in self.apps:
            prefix = _prefix(app)
            roots = [p for p in app.pids if p in table or not table]
            if prefix:
                roots += [pid for pid, (_, exe) in table.items() if _under(exe, prefix)]
            roots += [pid for pid, a in found.items() if a is app]
            stack, seen = list(roots), set()
            while stack:
                pid = stack.pop()
                if pid in seen or pid == self.own_pid:
                    continue
                seen.add(pid)
                found.setdefault(pid, app)
                stack.extend(children.get(pid, ()))
        self.pid_targets = found
        return self.spec()

    def spec(self) -> str:
        """Process filter for mitmproxy's local redirector: bundle folders, then the
        PIDs of every process in scope, never the recorder itself."""
        prefixes = [p for p in (_prefix(a) for a in self.apps) if p]
        # Every in-scope PID, even ones a folder already covers: a process that
        # replaces itself with another program keeps being captured with no gap.
        parts = prefixes + [str(p) for p in sorted(self.pid_targets)]
        return ",".join(parts + [f"!{self.own_pid}"]) if parts else ""

    def initial_spec(self) -> str:
        """PIDs only: safe to put in mitmproxy's mode string, which can't hold paths."""
        pids = sorted(self.pid_targets) or [0]  # PID 0 makes no connections: capture nothing yet
        return ",".join(str(p) for p in pids)

    def target_for(self, pid: int | None, path: str | None) -> AuditApp | None:
        """The audited app a connection belongs to, or None (then it is never recorded)."""
        if pid is not None and pid == self.own_pid:
            return None
        if path:
            for app in self.apps:
                prefix = _prefix(app)
                if prefix and _under(path, prefix):
                    return app
        if pid is not None and pid in self.pid_targets:
            return self.pid_targets[pid]
        if self.any_process and pid is None and self.apps:
            return self.apps[0]
        return None

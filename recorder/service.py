"""The recorder's process bookkeeping.

There is no login item or background service any more: the app runs the
recorder as its own child process for the length of an audit. This module keeps
the PID file (so ``uninstall`` can stop a running audit) and removes the login
item that the old always-on recorder installed:

- macOS: the LaunchAgent ``com.shadowprofile.recorder`` in ~/Library/LaunchAgents.
- Windows: the Task Scheduler logon task, or the per-user Run key entry.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from shared import db

TASK_NAME = "ShadowProfile Recorder"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "ShadowProfileRecorder"
LAUNCH_AGENT_LABEL = "com.shadowprofile.recorder"


def pid_file() -> Path:
    return db.data_dir() / "recorder.pid"


def _recorded_pid() -> int | None:
    try:
        return int(pid_file().read_text().strip())
    except (OSError, ValueError):
        return None


def is_running(run=subprocess.run) -> bool:
    """Whether an audit's recorder process is alive right now."""
    pid = _recorded_pid()
    if pid is None:
        return False
    if sys.platform == "win32":
        res = run(["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"], capture_output=True, text=True)
        return f'"{pid}"' in (res.stdout or "")
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_running(run=subprocess.run) -> None:
    """Stop a running audit (the recorder flushes and marks it finished)."""
    pid = _recorded_pid()
    if pid is None:
        return
    if sys.platform == "win32":
        run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    pid_file().unlink(missing_ok=True)


# ------------------------------------------------------- legacy login item

def launch_agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"


class HkcuRun:
    """The current user's Run key."""

    def _key(self, access):
        import winreg
        return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, access)

    def get(self, name: str) -> str | None:
        import winreg
        try:
            with self._key(winreg.KEY_QUERY_VALUE) as k:
                return winreg.QueryValueEx(k, name)[0]
        except FileNotFoundError:
            return None

    def delete(self, name: str) -> None:
        import winreg
        try:
            with self._key(winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, name)
        except FileNotFoundError:
            pass


def legacy_login_item_exists(run=subprocess.run, reg=None) -> bool:
    if sys.platform == "darwin":
        return launch_agent_path().exists()
    if sys.platform == "win32":
        reg = reg or HkcuRun()
        return bool(reg.get(RUN_VALUE)) or run(["schtasks", "/Query", "/TN", TASK_NAME],
                                                capture_output=True).returncode == 0
    return False


def remove_legacy_login_item(run=subprocess.run, reg=None) -> bool:
    """Remove the always-on recorder's login item if present. Returns True if one was removed."""
    if sys.platform == "darwin":
        path = launch_agent_path()
        if not path.exists():
            return False
        run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True)
        path.unlink(missing_ok=True)
        return True
    if sys.platform == "win32":
        reg = reg or HkcuRun()
        found = legacy_login_item_exists(run, reg)
        run(["schtasks", "/End", "/TN", TASK_NAME], capture_output=True)
        run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], capture_output=True)
        reg.delete(RUN_VALUE)
        return found
    return False

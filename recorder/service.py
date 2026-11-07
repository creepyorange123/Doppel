"""Start the recorder at login, with no window.

- Windows: a Task Scheduler task, run at logon with *limited* (not elevated)
  rights. mitmproxy starts its own small elevated redirector for local capture
  mode; all parsing stays in this unprivileged process (security checklist #7).
- macOS: a LaunchAgent in ~/Library/LaunchAgents.

Release builds point at the signed PyInstaller binary installed to a folder the
user can't write to (security checklist #4). In development we point at the
repo's virtualenv, and ``status`` warns that the path is user-writable.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path

TASK_NAME = "ShadowProfile Recorder"
LAUNCH_AGENT_LABEL = "com.shadowprofile.recorder"
REPO_ROOT = Path(__file__).resolve().parent.parent


def recorder_command() -> list[str]:
    if getattr(sys, "frozen", False):  # PyInstaller build
        return [sys.executable, "run"]
    exe = Path(sys.executable)
    if sys.platform == "win32":
        pythonw = exe.with_name("pythonw.exe")  # no console window
        exe = pythonw if pythonw.exists() else exe
    return [str(exe), "-s", str(REPO_ROOT / "run_recorder.py"), "run"]


def launch_agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"


def launch_agent_plist(cmd: list[str]) -> bytes:
    return plistlib.dumps({
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": cmd,
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
        # No request logging anywhere (security checklist #9).
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    })


def schtasks_create_command(cmd: list[str]) -> list[str]:
    tr = subprocess.list2cmdline(cmd)
    return ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr, "/SC", "ONLOGON", "/RL", "LIMITED", "/F"]


def install() -> None:
    cmd = recorder_command()
    if sys.platform == "win32":
        _check(subprocess.run(schtasks_create_command(cmd), capture_output=True, text=True))
        subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
    elif sys.platform == "darwin":
        path = launch_agent_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(launch_agent_plist(cmd))
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(path)], capture_output=True)
        _check(subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(path)], capture_output=True, text=True))
    else:
        raise NotImplementedError("only macOS and Windows are supported")


def uninstall() -> None:
    if sys.platform == "win32":
        subprocess.run(["schtasks", "/End", "/TN", TASK_NAME], capture_output=True)
        subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], capture_output=True)
    elif sys.platform == "darwin":
        path = launch_agent_path()
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True)
        path.unlink(missing_ok=True)


def is_installed() -> bool:
    if sys.platform == "win32":
        return subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True).returncode == 0
    if sys.platform == "darwin":
        return launch_agent_path().exists()
    return False


def command_is_user_writable() -> bool:
    target = Path(recorder_command()[0])
    return os.access(target, os.W_OK) or os.access(target.parent, os.W_OK)


def _check(res: subprocess.CompletedProcess) -> None:
    if res.returncode != 0:
        raise RuntimeError((res.stderr or res.stdout or "command failed").strip())

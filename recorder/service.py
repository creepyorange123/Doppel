"""Start the recorder at login, with no window.

- Windows: a Task Scheduler task run at logon with *limited* (not elevated)
  rights. Creating logon tasks can need admin rights; when Windows refuses, we
  fall back to the per-user Run key (HKCU\\...\\CurrentVersion\\Run), which any
  account can write and which also starts the recorder unelevated at login.
  mitmproxy starts its own small elevated redirector for local capture mode;
  all parsing stays in this unprivileged process (security checklist #7).
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

from shared import db

TASK_NAME = "ShadowProfile Recorder"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "ShadowProfileRecorder"
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


def pid_file() -> Path:
    return db.data_dir() / "recorder.pid"


# --------------------------------------------------------------------- Windows

class HkcuRun:
    """The current user's Run key; no admin rights needed."""

    def _key(self, access):
        import winreg
        return winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, access)

    def set(self, name: str, value: str) -> None:
        import winreg
        with self._key(winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)

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


def schtasks_create_command(cmd: list[str]) -> list[str]:
    tr = subprocess.list2cmdline(cmd)
    return ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr, "/SC", "ONLOGON", "/RL", "LIMITED", "/F"]


def _start_detached(cmd: list[str]) -> None:
    flags = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
    subprocess.Popen(cmd, cwd=str(REPO_ROOT), creationflags=flags, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def install_windows(run=subprocess.run, reg=None) -> str:
    """Returns "task" or "run_key" depending on which login item was created."""
    reg = reg or HkcuRun()
    cmd = recorder_command()
    res = run(schtasks_create_command(cmd), capture_output=True, text=True)
    if res.returncode == 0:
        run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
        reg.delete(RUN_VALUE)
        return "task"
    reg.set(RUN_VALUE, subprocess.list2cmdline(cmd))
    _start_detached(cmd)  # start now, not only at the next login
    return "run_key"


def stop_running(run=subprocess.run) -> None:
    pf = pid_file()
    try:
        pid = int(pf.read_text().strip())
    except (OSError, ValueError):
        return
    if sys.platform == "win32" or run is not subprocess.run:
        run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    pf.unlink(missing_ok=True)


def _recorded_pid() -> int | None:
    try:
        return int(pid_file().read_text().strip())
    except (OSError, ValueError):
        return None


def is_running_windows(run=subprocess.run) -> bool:
    pid = _recorded_pid()
    if pid is None:
        return False
    res = run(["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"], capture_output=True, text=True)
    return f'"{pid}"' in (res.stdout or "")


def start_windows(run=subprocess.run, reg=None) -> str:
    """Start the recorder now, using whichever login item install created."""
    reg = reg or HkcuRun()
    if is_running_windows(run):
        return "already_running"
    if run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True).returncode == 0:
        run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
        return "started"
    if reg.get(RUN_VALUE):
        _start_detached(recorder_command())
        return "started"
    raise RuntimeError("recorder is not installed")


def stop_windows(run=subprocess.run, reg=None) -> None:
    """Pause until the next login: the login item is kept."""
    run(["schtasks", "/End", "/TN", TASK_NAME], capture_output=True)
    stop_running(run)


def uninstall_windows(run=subprocess.run, reg=None) -> None:
    reg = reg or HkcuRun()
    run(["schtasks", "/End", "/TN", TASK_NAME], capture_output=True)
    run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], capture_output=True)
    reg.delete(RUN_VALUE)
    stop_running(run)


def is_installed_windows(run=subprocess.run, reg=None) -> bool:
    reg = reg or HkcuRun()
    if reg.get(RUN_VALUE):
        return True
    return run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True).returncode == 0


# ----------------------------------------------------------------------- macOS

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


# -------------------------------------------------------------------- dispatch

def install() -> str:
    if sys.platform == "win32":
        return install_windows()
    if sys.platform == "darwin":
        path = launch_agent_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(launch_agent_plist(recorder_command()))
        uid = os.getuid()
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(path)], capture_output=True)
        _check(subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(path)], capture_output=True, text=True))
        return "launch_agent"
    raise NotImplementedError("only macOS and Windows are supported")


def uninstall() -> None:
    if sys.platform == "win32":
        uninstall_windows()
    elif sys.platform == "darwin":
        path = launch_agent_path()
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(path)], capture_output=True)
        path.unlink(missing_ok=True)
        stop_running()


def start() -> str:
    if sys.platform == "win32":
        return start_windows()
    if sys.platform == "darwin":
        path = launch_agent_path()
        if not path.exists():
            raise RuntimeError("recorder is not installed")
        if is_running():
            return "already_running"
        subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], capture_output=True)
        return "started"
    raise NotImplementedError("only macOS and Windows are supported")


def stop() -> None:
    if sys.platform == "win32":
        stop_windows()
    elif sys.platform == "darwin":
        # bootout, not kill: KeepAlive would restart a killed recorder. The plist stays,
        # so it starts again at the next login.
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(launch_agent_path())], capture_output=True)
        stop_running()


def is_running() -> bool:
    if sys.platform == "win32":
        return is_running_windows()
    pid = _recorded_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_installed() -> bool:
    if sys.platform == "win32":
        return is_installed_windows()
    if sys.platform == "darwin":
        return launch_agent_path().exists()
    return False


def command_is_user_writable() -> bool:
    target = Path(recorder_command()[0])
    return os.access(target, os.W_OK) or os.access(target.parent, os.W_OK)


def _check(res: subprocess.CompletedProcess) -> None:
    if res.returncode != 0:
        raise RuntimeError((res.stderr or res.stdout or "command failed").strip())

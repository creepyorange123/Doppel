"""Turning the recorder on and off from Settings (`recorder start` / `recorder stop`)."""

import subprocess

import pytest

from recorder import service


class FakeRun:
    def __init__(self, task=True, alive=()):
        self.task = task
        self.alive = set(alive)
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[:2] == ["schtasks", "/Query"]:
            return subprocess.CompletedProcess(cmd, 0 if self.task else 1, "", "")
        if cmd[0] == "tasklist":
            pid = cmd[cmd.index("/FI") + 1].split()[-1]
            out = f'"pythonw.exe","{pid}","Console","1","40,000 K"' if int(pid) in self.alive else "INFO: No tasks"
            return subprocess.CompletedProcess(cmd, 0, out, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


class FakeReg:
    def __init__(self, value=None):
        self.value = value

    def get(self, name):
        return self.value

    def set(self, name, value):
        self.value = value

    def delete(self, name):
        self.value = None


@pytest.fixture
def pidfile(tmp_path, monkeypatch):
    p = tmp_path / "recorder.pid"
    monkeypatch.setattr(service, "pid_file", lambda: p)
    return p


def test_not_running_without_pid_file(pidfile):
    assert service.is_running_windows(run=FakeRun()) is False


def test_running_when_pid_alive(pidfile):
    pidfile.write_text("4242")
    assert service.is_running_windows(run=FakeRun(alive={4242})) is True


def test_stale_pid_file_is_not_running(pidfile):
    pidfile.write_text("4242")
    assert service.is_running_windows(run=FakeRun(alive=())) is False


def test_start_uses_scheduled_task(pidfile, monkeypatch):
    run = FakeRun(task=True)
    monkeypatch.setattr(service, "_start_detached", lambda cmd: pytest.fail("should use the task"))
    assert service.start_windows(run=run, reg=FakeReg()) == "started"
    assert ["schtasks", "/Run", "/TN", service.TASK_NAME] in run.calls


def test_start_uses_run_key_when_no_task(pidfile, monkeypatch):
    started = []
    monkeypatch.setattr(service, "_start_detached", lambda cmd: started.append(cmd))
    assert service.start_windows(run=FakeRun(task=False), reg=FakeReg("x run")) == "started"
    assert started == [service.recorder_command()]


def test_start_does_nothing_if_already_running(pidfile, monkeypatch):
    pidfile.write_text("4242")
    run = FakeRun(task=True, alive={4242})
    assert service.start_windows(run=run, reg=FakeReg()) == "already_running"
    assert ["schtasks", "/Run", "/TN", service.TASK_NAME] not in run.calls


def test_start_refuses_when_not_installed(pidfile):
    with pytest.raises(RuntimeError, match="not installed"):
        service.start_windows(run=FakeRun(task=False), reg=FakeReg(None))


def test_stop_ends_task_and_kills_process_but_keeps_login_item(pidfile):
    pidfile.write_text("4242")
    run, reg = FakeRun(task=True, alive={4242}), FakeReg("x run")
    service.stop_windows(run=run, reg=reg)
    assert ["schtasks", "/End", "/TN", service.TASK_NAME] in run.calls
    assert ["taskkill", "/PID", "4242", "/T", "/F"] in run.calls
    assert not pidfile.exists()
    # Stopping is a pause, not an uninstall: it still starts at the next login.
    assert reg.value == "x run"
    assert ["schtasks", "/Delete", "/TN", service.TASK_NAME, "/F"] not in run.calls


def test_cli_start_stop_report_state(pidfile, monkeypatch, capsys):
    from recorder import __main__ as cli

    monkeypatch.setattr(service, "start", lambda: "started")
    monkeypatch.setattr(service, "stop", lambda: None)
    assert cli.main(["start"]) == 0
    assert "started" in capsys.readouterr().out.lower()
    assert cli.main(["stop"]) == 0
    assert "stopped" in capsys.readouterr().out.lower()


def test_cli_start_not_installed_fails_cleanly(monkeypatch, capsys):
    from recorder import __main__ as cli

    def boom():
        raise RuntimeError("recorder is not installed")

    monkeypatch.setattr(service, "start", boom)
    assert cli.main(["start"]) == 1
    assert "not installed" in capsys.readouterr().out

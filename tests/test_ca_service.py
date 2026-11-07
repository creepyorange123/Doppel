import plistlib

from recorder import ca, service


def test_ca_is_short_lived_ec_and_valid():
    key, cert = ca.generate()
    assert ca.is_valid(cert)
    life = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert life.days <= 31
    assert key.curve.name == "secp256r1"


def test_trust_commands_target_user_store_only():
    _, cert = ca.generate()
    win = ca.trust_command(__import__("pathlib").Path("c.crt"), "win32")
    assert win[:3] == ["certutil", "-user", "-addstore"]
    mac = ca.trust_command(__import__("pathlib").Path("c.crt"), "darwin")
    assert "login.keychain-db" in mac[-2]
    assert ca.untrust_command(cert, "win32")[:3] == ["certutil", "-user", "-delstore"]


def test_scheduled_task_is_not_elevated():
    cmd = service.schtasks_create_command(["C:/x/pythonw.exe", "run_recorder.py", "run"])
    assert cmd[cmd.index("/RL") + 1] == "LIMITED"
    assert cmd[cmd.index("/SC") + 1] == "ONLOGON"


def test_launch_agent_discards_output():
    plist = plistlib.loads(service.launch_agent_plist(["/x/recorder", "run"]))
    assert plist["RunAtLoad"] is True
    assert plist["StandardErrorPath"] == "/dev/null" and plist["StandardOutPath"] == "/dev/null"


# --------------------------------------------- Windows login item without admin

class FakeRun:
    def __init__(self, deny_schtasks=True):
        self.deny = deny_schtasks
        self.calls = []

    def __call__(self, cmd, **kw):
        import subprocess
        self.calls.append(cmd)
        if cmd[0] == "schtasks" and cmd[1] == "/Create" and self.deny:
            return subprocess.CompletedProcess(cmd, 1, "", "ERROR: Access is denied.")
        if cmd[0] == "schtasks" and cmd[1] == "/Query":
            return subprocess.CompletedProcess(cmd, 1, "", "not found")
        return subprocess.CompletedProcess(cmd, 0, "", "")


class FakeReg:
    def __init__(self):
        self.values = {}

    def set(self, name, value):
        self.values[name] = value

    def get(self, name):
        return self.values.get(name)

    def delete(self, name):
        self.values.pop(name, None)


def test_access_denied_falls_back_to_per_user_run_key(monkeypatch):
    run, reg, started = FakeRun(), FakeReg(), []
    monkeypatch.setattr(service, "_start_detached", lambda cmd: started.append(cmd))
    method = service.install_windows(run=run, reg=reg)
    assert method == "run_key"
    value = reg.get(service.RUN_VALUE)
    assert "run_recorder.py" in value and value.rstrip().endswith("run")
    assert started  # recorder starts now, not only at next login
    assert service.is_installed_windows(run=run, reg=reg)


def test_task_scheduler_used_when_allowed(monkeypatch):
    run, reg = FakeRun(deny_schtasks=False), FakeReg()
    monkeypatch.setattr(service, "_start_detached", lambda cmd: None)
    assert service.install_windows(run=run, reg=reg) == "task"
    assert reg.get(service.RUN_VALUE) is None


def test_uninstall_removes_both_and_stops_recorder(monkeypatch, tmp_path):
    run, reg = FakeRun(), FakeReg()
    reg.set(service.RUN_VALUE, "x")
    pidfile = tmp_path / "recorder.pid"
    pidfile.write_text("4242")
    monkeypatch.setattr(service, "pid_file", lambda: pidfile)
    service.uninstall_windows(run=run, reg=reg)
    assert reg.get(service.RUN_VALUE) is None
    assert ["taskkill", "/PID", "4242", "/T", "/F"] in run.calls
    assert ["schtasks", "/Delete", "/TN", service.TASK_NAME, "/F"] in run.calls
    assert not pidfile.exists()

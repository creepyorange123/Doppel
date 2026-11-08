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


# ------------------------------------------- no background service any more

class FakeRun:
    def __init__(self, task_exists=False):
        self.task_exists = task_exists
        self.calls = []

    def __call__(self, cmd, **kw):
        import subprocess
        self.calls.append(cmd)
        if cmd[0] == "schtasks" and cmd[1] == "/Query":
            return subprocess.CompletedProcess(cmd, 0 if self.task_exists else 1, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


class FakeReg:
    def __init__(self):
        self.values = {}

    def get(self, name):
        return self.values.get(name)

    def delete(self, name):
        self.values.pop(name, None)


def test_service_module_cannot_install_a_login_item():
    assert not any(hasattr(service, n) for n in ("install", "start", "install_windows", "launch_agent_plist"))


def test_legacy_windows_login_item_is_removed(monkeypatch):
    monkeypatch.setattr(service.sys, "platform", "win32")
    run, reg = FakeRun(task_exists=True), FakeReg()
    reg.values[service.RUN_VALUE] = "old"
    assert service.legacy_login_item_exists(run=run, reg=reg)
    assert service.remove_legacy_login_item(run=run, reg=reg) is True
    assert reg.get(service.RUN_VALUE) is None
    assert ["schtasks", "/Delete", "/TN", service.TASK_NAME, "/F"] in run.calls


def test_legacy_launch_agent_is_removed(monkeypatch, tmp_path):
    monkeypatch.setattr(service.sys, "platform", "darwin")
    plist = tmp_path / "com.shadowprofile.recorder.plist"
    plist.write_text("<plist/>")
    monkeypatch.setattr(service, "launch_agent_path", lambda: plist)
    run = FakeRun()
    assert service.legacy_login_item_exists(run=run)
    assert service.remove_legacy_login_item(run=run) is True
    assert not plist.exists() and run.calls[0][:2] == ["launchctl", "bootout"]
    assert service.remove_legacy_login_item(run=run) is False


def test_running_follows_the_pid_file(monkeypatch, tmp_path):
    import os

    pidfile = tmp_path / "recorder.pid"
    monkeypatch.setattr(service, "pid_file", lambda: pidfile)
    assert not service.is_running()
    pidfile.write_text(str(os.getpid()))
    assert service.is_running()
    pidfile.write_text("999999")
    assert not service.is_running()

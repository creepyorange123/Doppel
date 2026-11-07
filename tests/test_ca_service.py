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
    cmd = service.schtasks_create_command(["C:\x\pythonw.exe", "run_recorder.py", "run"])
    assert cmd[cmd.index("/RL") + 1] == "LIMITED"
    assert cmd[cmd.index("/SC") + 1] == "ONLOGON"


def test_launch_agent_discards_output():
    plist = plistlib.loads(service.launch_agent_plist(["/x/recorder", "run"]))
    assert plist["RunAtLoad"] is True
    assert plist["StandardErrorPath"] == "/dev/null" and plist["StandardOutPath"] == "/dev/null"

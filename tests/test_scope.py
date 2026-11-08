"""Which processes an audit captures: the app bundle, everything it spawns, nothing else."""

from recorder.scope import Scope, process_label, process_table
from shared.audits import AuditApp, app_bundle_root

SLACK = AuditApp(name="Slack", path="/Applications/Slack.app")
OWN = 900

TABLE = {
    1: (0, "/sbin/launchd"),
    100: (1, "/Applications/Slack.app/Contents/MacOS/Slack"),
    101: (100, "/Applications/Slack.app/Contents/Frameworks/Slack Helper (Renderer).app/Contents/MacOS/Slack Helper (Renderer)"),
    102: (100, "/usr/bin/curl"),             # spawned by Slack, outside its bundle
    103: (102, "/bin/sh"),                   # spawned by that
    200: (1, "/Applications/Slack Beta.app/Contents/MacOS/Slack Beta"),  # similar name, different app
    300: (1, "/Applications/Safari.app/Contents/MacOS/Safari"),
    OWN: (1, "/repo/.venv/bin/python"),      # the recorder itself
}


def scope(apps=(SLACK,), table=TABLE, **kw):
    return Scope(list(apps), own_pid=OWN, table=lambda: table, **kw)


def test_bundle_helpers_and_spawned_processes_are_in_scope():
    s = scope()
    assert set(s.pid_targets) == {100, 101, 102, 103}
    assert s.target_for(101, TABLE[101][1]) is SLACK
    assert s.target_for(103, "/bin/sh") is SLACK


def test_other_apps_and_the_recorder_are_out_of_scope():
    s = scope()
    assert s.target_for(200, TABLE[200][1]) is None   # "Slack Beta.app" is not inside "Slack.app/"
    assert s.target_for(300, TABLE[300][1]) is None
    assert s.target_for(OWN, TABLE[OWN][1]) is None
    assert s.target_for(None, None) is None           # unknown sender: never recorded


def test_redirector_filter_lists_bundle_then_pids_and_excludes_itself():
    spec = scope().spec()
    assert spec == "/Applications/Slack.app/,100,101,102,103,!900"


def test_initial_filter_holds_only_pids():
    first = scope().initial_spec()
    assert first and all(part.isdigit() for part in first.split(","))
    assert scope(table={}).initial_spec() == "0"  # nothing running yet: capture nothing


def test_process_stays_in_scope_after_exec():
    table = dict(TABLE)
    table[105] = (1, "/Applications/Slack.app/Contents/MacOS/updater")
    s = scope(table=table)
    table[105] = (1, "/usr/bin/curl")  # replaced itself; no longer inside the bundle
    table[106] = (105, "/bin/sh")      # and spawned something
    s.refresh()
    assert s.target_for(105, "/usr/bin/curl") is SLACK and s.target_for(106, "/bin/sh") is SLACK
    del table[105]
    s.refresh()
    assert 105 not in s.pid_targets   # gone once it exits


def test_refresh_follows_new_and_exited_processes():
    table = dict(TABLE)
    s = scope(table=table)
    table[104] = (101, "/usr/local/bin/node")
    del table[102], table[103]
    assert s.refresh() == "/Applications/Slack.app/,100,101,104,!900"


def test_self_audit_targets_by_pid_and_their_children():
    table = {**TABLE, 500: (1, "/x/Electron.app/Contents/MacOS/Electron"), 501: (500, "/repo/.venv/bin/python"),
             502: (501, "/usr/bin/git")}
    me = AuditApp(name="Doppel", path="/x/Electron.app", pids=(500, 501))
    s = scope(apps=(me,), table=table)
    assert {500, 501, 502} <= set(s.pid_targets)
    assert s.target_for(502, "/usr/bin/git") is me
    assert "/x/Electron.app/" in s.spec() and "501" in s.spec()


def test_plain_executable_matches_only_itself():
    curl = AuditApp(name="curl", path="/usr/bin/curl")
    s = scope(apps=(curl,), table={7: (1, "/usr/bin/curl"), 8: (1, "/usr/bin/curly")})
    assert set(s.pid_targets) == {7}
    assert s.spec() == "/usr/bin/curl,7,!900"


def test_plain_proxy_mode_counts_unknown_senders_as_the_first_app():
    assert scope(any_process=True).target_for(None, None) is SLACK


def test_bundle_root_and_labels():
    helper = TABLE[101][1]
    assert app_bundle_root(helper) == "/Applications/Slack.app"
    assert app_bundle_root("/usr/bin/curl") == "/usr/bin/curl"
    assert process_label(helper) == "Slack Helper (Renderer)"
    assert process_label("C:\\Program Files\\Slack\\slack.exe") == "slack"


def test_real_process_table_includes_this_process():
    import os

    table = process_table()
    assert os.getpid() in table and table[os.getpid()][0] == os.getppid()

import json

import pytest

from analyzer import audits_api, handlers
from analyzer.research import ledger
from shared import audits, db
from shared.protocol import ProtocolError
from tests.helpers import make_audit


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


@pytest.fixture
def app_dir(tmp_path):
    """A real folder standing in for an installed app bundle."""
    path = tmp_path / "Applications" / "Slack.app"
    (path / "Contents" / "MacOS").mkdir(parents=True)
    return str(path)


def call(conn, t, p=None):
    return handlers.handle(conn, t, p or {})


def add_request(conn, audit_id, *, at=None, app="Slack", process="Slack", domain="t.example"):
    conn.execute("INSERT INTO requests (audit_id, captured_at, app_name, process_name, dest_domain) VALUES (?, ?, ?, ?, ?)",
                 (audit_id, at if at is not None else db.now_ms(), app, process, domain))


# ----------------------------------------------------------------- create

def test_create_audit(conn, app_dir):
    out = call(conn, "create_audit", {"apps": [{"path": app_dir + "/Contents/MacOS/Slack", "name": "Slack"}],
                                      "minutes": 30})["audit"]
    assert out["status"] == "running" and out["label"] == "Slack" and out["self_audit"] is False
    assert out["apps"] == [{"path": app_dir, "name": "Slack", "capture": "full", "is_browser": False}]  # bundle
    assert out["ends_at"] - out["started_at"] == 30 * 60_000
    assert call(conn, "status")["active_audit_id"] == out["id"]


@pytest.mark.parametrize("payload,why", [
    ({"apps": [], "minutes": 10}, "no apps"),
    ({"apps": [{"path": "/x", "name": "X"}] * 21, "minutes": 10}, "too many"),
    ({"apps": [{"path": "APP", "name": "Slack"}], "minutes": 0}, "zero minutes"),
    ({"apps": [{"path": "APP", "name": "Slack"}], "minutes": 241}, "too long"),
    ({"apps": [{"path": "APP", "name": "Slack"}], "minutes": 1.5}, "fraction"),
    ({"apps": [{"path": "relative/Slack.app", "name": "Slack"}], "minutes": 5}, "relative path"),
    ({"apps": [{"path": "/Applications/Nope.app", "name": "Nope"}], "minutes": 5}, "missing"),
    ({"apps": [{"path": "/System/Library/CoreServices/Finder.app", "name": "Finder"}], "minutes": 5}, "system"),
    ({"apps": [{"path": "/tmp/a,b.app", "name": "X"}], "minutes": 5}, "comma"),
    ({"apps": [{"path": "APP", "name": "Slack", "capture": "everything"}], "minutes": 5}, "bad capture"),
    ({"apps": [{"name": "Slack", "pids": [123]}], "minutes": 5}, "pids without self_audit"),
])
def test_create_rejects(conn, app_dir, payload, why):
    payload = json.loads(json.dumps(payload).replace("APP", app_dir))
    with pytest.raises(ProtocolError):
        call(conn, "create_audit", payload)


def test_only_one_audit_at_a_time(conn, app_dir):
    call(conn, "create_audit", {"apps": [{"path": app_dir, "name": "Slack"}], "minutes": 5})
    with pytest.raises(ProtocolError):
        call(conn, "create_audit", {"apps": [{"path": app_dir, "name": "Slack"}], "minutes": 5})


def test_self_audit_may_name_pids(conn, app_dir):
    out = call(conn, "create_audit", {"apps": [{"path": app_dir, "name": "Doppel", "pids": [4242, 4243]}],
                                      "minutes": 2, "label": "Doppel self-audit", "self_audit": True})["audit"]
    assert out["self_audit"] is True and "pids" not in out["apps"][0]  # internal detail, not shown
    assert audits.get(conn, out["id"]).apps[0].pids == (4242, 4243)


# ----------------------------------------------------------------- finish / settle

def test_finish_is_idempotent(conn):
    aid = make_audit(conn, status="running", started_at=db.now_ms())
    first = call(conn, "finish_audit", {"audit_id": aid, "status": "done"})["audit"]
    assert first["status"] == "done" and first["ended_at"] is not None
    again = call(conn, "finish_audit", {"audit_id": aid, "status": "failed", "error": "late"})["audit"]
    assert again["status"] == "done" and again["error"] is None


def test_stale_running_audit_is_marked_interrupted(conn):
    aid = make_audit(conn, status="running", started_at=1000, ends_at=2000)
    assert call(conn, "status")["active_audit_id"] is None
    a = call(conn, "list_audits")["audits"][0]
    assert a["id"] == aid and a["status"] == "interrupted" and a["ended_at"] == 2000


# ----------------------------------------------------------------- list / live / delete

def test_list_audits_newest_first_with_counts(conn):
    old = make_audit(conn, label="Old", started_at=1)
    new = make_audit(conn, label="New", started_at=2)
    add_request(conn, new)
    add_request(conn, new)
    listed = call(conn, "list_audits")["audits"]
    assert [(a["id"], a["requests"]) for a in listed] == [(new, 2), (old, 0)]
    assert listed[0]["analyzed"] is False


def test_audit_live_counts_by_app_process_and_domain(conn):
    aid = make_audit(conn, status="running", started_at=db.now_ms())
    add_request(conn, aid, process="Slack Helper", domain="a.example", at=5)
    add_request(conn, aid, process="Slack Helper", domain="a.example", at=6)
    add_request(conn, aid, process="Slack", domain="b.example", at=7)
    add_request(conn, make_audit(conn), domain="elsewhere.example")
    live = call(conn, "audit_live", {"audit_id": aid})
    assert live["requests"] == 3 and live["last_at"] == 7
    assert live["apps"] == [{"name": "Slack", "requests": 3}]
    assert live["processes"][0] == {"app": "Slack", "process": "Slack Helper", "requests": 2}
    assert [d["domain"] for d in live["domains"]] == ["a.example", "b.example"]
    assert set(live) == {"audit", "requests", "last_at", "apps", "processes", "domains"}  # no URLs or content


def test_delete_audit_removes_its_requests_only(conn):
    keep, gone = make_audit(conn), make_audit(conn)
    add_request(conn, keep)
    add_request(conn, gone)
    assert call(conn, "delete_audit", {"audit_id": gone}) == {"deleted": 1}
    assert [r[0] for r in conn.execute("SELECT audit_id FROM requests")] == [keep]
    with pytest.raises(ProtocolError):
        call(conn, "delete_audit", {"audit_id": gone})


def test_running_audit_cannot_be_deleted(conn):
    aid = make_audit(conn, status="running", started_at=db.now_ms())
    with pytest.raises(ProtocolError):
        call(conn, "delete_audit", {"audit_id": aid})


# ----------------------------------------------------------------- running apps

def test_running_apps_fold_helpers_and_hide_system_and_doppel():
    fake = [
        ("/Applications/Slack.app/Contents/MacOS/Slack", "Slack", True, False),
        ("/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper", "Slack Helper", False, False),
        ("/Applications/Zoom.app/Contents/MacOS/zoom.us", "zoom.us", False, False),   # not visible, but an installed app
        ("/usr/local/bin/some-daemon", "some-daemon", False, False),                 # background tool: hidden
        ("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "Finder", True, True),
        ("/usr/libexec/trustd", "trustd", False, False),
        (str(audits_api.REPO_ROOT / "app/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron"), "Electron", True, False),
    ]
    apps = audits_api.list_running_apps(None, {}, executables=lambda: fake)["apps"]
    assert [(a["path"], a["name"], a["processes"]) for a in apps] == [
        ("/Applications/Slack.app", "Slack", 2), ("/Applications/Zoom.app", "Zoom", 1)]
    assert all(a["is_browser"] is False and a["hint"] is None for a in apps)


# ----------------------------------------------------------------- self-audit

def test_self_audit_checks_every_connection_against_the_ledger(conn):
    start = db.now_ms() - 60_000
    aid = make_audit(conn, label="Doppel self-audit", self_audit=True, started_at=start, ended_at=db.now_ms() + 1)
    ledger.append(conn, "api.tavily.com", {"query": "Criteo privacy policy"})
    add_request(conn, aid, app="Doppel", process="python3.12", domain="api.tavily.com")
    add_request(conn, aid, app="Doppel", process="Electron", domain="clients2.google.com")
    out = call(conn, "self_audit_result", {"audit_id": aid})
    assert out["verdict"] == "unexpected" and out["unexpected"] == 1 and out["ledger_entries"] == 1
    by_domain = {c["domain"]: c for c in out["connections"]}
    assert by_domain["api.tavily.com"]["in_ledger"] is True
    assert by_domain["clients2.google.com"]["in_ledger"] is False


def test_self_audit_with_no_traffic(conn):
    aid = make_audit(conn, self_audit=True, started_at=db.now_ms() - 1000)
    assert call(conn, "self_audit_result", {"audit_id": aid})["verdict"] == "no_traffic"


def test_self_audit_result_only_for_self_audits(conn):
    with pytest.raises(ProtocolError):
        call(conn, "self_audit_result", {"audit_id": make_audit(conn)})


# ----------------------------------------------------------------- domain rules

def test_domain_rules_round_trip(conn):
    call(conn, "set_domain_rule", {"domain": " .Bank.Example. ", "rule": "dont_track"})
    call(conn, "set_domain_rule", {"domain": "health.example", "rule": "metadata_only"})
    assert call(conn, "list_domain_rules")["domains"] == [
        {"domain": "bank.example", "rule": "dont_track"}, {"domain": "health.example", "rule": "metadata_only"}]
    call(conn, "set_domain_rule", {"domain": "bank.example", "rule": None})
    assert [d["domain"] for d in call(conn, "list_domain_rules")["domains"]] == ["health.example"]


@pytest.mark.parametrize("p", [{"domain": "x.example", "rule": "track"}, {"domain": "x.example", "rule": "block"},
                               {"domain": "not a domain!", "rule": "dont_track"}, {"rule": "dont_track"}])
def test_domain_rule_rejects(conn, p):
    with pytest.raises(ProtocolError):
        call(conn, "set_domain_rule", p)


def test_status_and_hello(conn):
    assert call(conn, "hello")["version"]
    s = call(conn, "status")
    assert s["request_count"] == 0 and s["active_audit_id"] is None and "last_opened_at" not in s

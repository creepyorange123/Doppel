import pytest

from analyzer import handlers
from shared import db
from shared.protocol import ProtocolError


@pytest.fixture
def conn(tmp_path, db_key, monkeypatch):
    monkeypatch.setattr("analyzer.app_rules._running_apps", lambda: [("C:/Apps/Running.exe", "Running")])
    return db.open_db(tmp_path / "t.db", db_key)


def add_request(conn, app_path, app_name="App", domain="x.example"):
    conn.execute("INSERT INTO requests (captured_at, app_name, app_path, dest_domain) VALUES (?, ?, ?, ?)",
                 (db.now_ms(), app_name, app_path, domain))


def call(conn, t, payload=None):
    return handlers.handle(conn, t, payload or {})


def test_list_apps_merges_seen_running_and_rules(conn):
    add_request(conn, "C:/Apps/Seen.exe", "Seen")
    add_request(conn, "C:/Apps/Seen.exe", "Seen")
    call(conn, "set_app_rule", {"key": "C:/Apps/Ruled.exe", "rule": "dont_track"})
    out = call(conn, "list_apps")
    names = {a["name"]: a for a in out["apps"]}
    assert names["Seen"]["requests"] == 2
    assert names["Running"]["running"] is True
    assert any(a["rule"] == "dont_track" for a in out["apps"])
    assert out["mode"] == "blocklist"


def test_set_and_clear_rules(conn):
    call(conn, "set_domain_rule", {"domain": "WWW.MyBank.example.", "rule": "dont_track"})
    assert call(conn, "list_apps")["domains"] == [{"domain": "www.mybank.example", "rule": "dont_track"}]
    call(conn, "set_domain_rule", {"domain": "www.mybank.example", "rule": None})
    assert call(conn, "list_apps")["domains"] == []


def test_user_rule_replaces_auto_rule(conn):
    conn.execute("INSERT INTO app_rules (kind, match, rule, source, updated_at) VALUES ('app', 'c:\\apps\\a.exe', 'metadata_only', 'auto', 1)")
    call(conn, "set_app_rule", {"key": "C:\\Apps\\A.exe", "rule": "track"})
    assert conn.execute("SELECT rule, source FROM app_rules").fetchall() == [("track", "user")]


@pytest.mark.parametrize("t,payload", [
    ("set_app_rule", {"key": "x", "rule": "everything"}),
    ("set_app_rule", {"rule": "track"}),
    ("set_domain_rule", {"domain": "bad domain!", "rule": "track"}),
    ("set_tracking_mode", {"mode": "spy"}),
    ("delete_app_data", {}),
])
def test_rejects_bad_payloads(conn, t, payload):
    with pytest.raises(ProtocolError):
        call(conn, t, payload)


def test_tracking_mode(conn):
    call(conn, "set_tracking_mode", {"mode": "allowlist"})
    assert call(conn, "list_apps")["mode"] == "allowlist"


def test_delete_app_data_removes_only_that_app(conn):
    add_request(conn, "C:\\Apps\\Chat.exe")
    add_request(conn, "C:\\Apps\\Other.exe")
    assert call(conn, "delete_app_data", {"key": "c:\\apps\\chat.exe"}) == {"deleted": 1}
    assert conn.execute("SELECT app_path FROM requests").fetchall() == [("C:\\Apps\\Other.exe",)]


def test_status_and_hello(conn):
    assert call(conn, "hello")["version"]
    assert call(conn, "status")["request_count"] == 0

"""The Privacy screen's live checks: each must pass on clean data and catch a real violation."""

import json

import pytest

from analyzer import privacy_checks as pc
from analyzer.research import ledger
from shared import db
from tests.helpers import make_audit

KNOWN = {"Criteo", "Meta"}
H = "a" * 64  # looks like a keyed hash


@pytest.fixture
def env(tmp_path, db_key):
    path = tmp_path / "shadow.db"
    conn = db.open_db(path, db_key)
    make_audit(conn, started_at=db.now_ms() - 60_000)  # audit 1
    return {"conn": conn, "path": path, "dir": tmp_path, "key": db_key}


def run(env, **overrides):
    args = dict(db_file=env["path"], data_dir=env["dir"], db_key=env["key"], pids={1},
                listeners=lambda pids: [], known_companies=KNOWN)
    args.update(overrides)
    out = pc.run_checks(env["conn"], **args)
    return {c["id"]: c for c in out["checks"]}


def add(conn, **cols):
    base = {"audit_id": 1, "captured_at": db.now_ms(), "dest_domain": "t.example", "analyzed": 0}
    base.update(cols)
    names = ", ".join(base)
    conn.execute(f"INSERT INTO requests ({names}) VALUES ({', '.join('?' * len(base))})", list(base.values()))


def test_clean_install_passes_everything_that_applies(env):
    checks = run(env)
    assert set(checks) == {"only_during_audits", "no_background", "encrypted", "key_not_on_disk", "ids_hashed", "no_credentials", "no_search_queries",
                           "raw_deleted", "no_listeners", "local_ai_local", "only_company_names", "gate_allowlist",
                           "zero_network"}
    for c in checks.values():
        assert c["ok"] in (True, None), c
        assert c["title"] and c["detail"]


def test_details_never_include_captured_content(env):
    add(env["conn"], url="https://secret.example/?token=SUPERSECRET", headers=json.dumps({"x": "SUPERSECRET"}))
    blob = json.dumps(run(env))
    assert "SUPERSECRET" not in blob and "secret.example" not in blob


# ------------------------------------------------------------------ encryption

def test_plain_sqlite_file_fails_encryption(env, tmp_path):
    import sqlite3
    plain = tmp_path / "plain.db"
    sqlite3.connect(plain).execute("CREATE TABLE t (x)").connection.commit()
    checks = run(env, db_file=plain)
    assert checks["encrypted"]["ok"] is False


def test_key_written_to_a_file_is_caught(env):
    (env["dir"] / "notes.txt").write_text("key=" + env["key"].hex())
    assert run(env)["key_not_on_disk"]["ok"] is False


# ------------------------------------------------------------------ stored data

def test_raw_cookie_value_is_caught(env):
    add(env["conn"], cookies=json.dumps({"sent": {"sid": "raw-session-value"}}))
    assert run(env)["ids_hashed"]["ok"] is False


def test_hashed_cookies_and_sightings_pass(env):
    add(env["conn"], cookies=json.dumps({"sent": {"sid": H}, "set": {"uid": H}}))
    env["conn"].execute("INSERT INTO id_sightings VALUES (?, 'Criteo', 'a.example', 1, 1)", (H,))
    assert run(env)["ids_hashed"]["ok"] is True


def test_unhashed_id_sighting_is_caught(env):
    env["conn"].execute("INSERT INTO id_sightings VALUES ('user-12345', 'Criteo', 'a.example', 1, 1)")
    assert run(env)["ids_hashed"]["ok"] is False


@pytest.mark.parametrize("headers,body", [
    ({"cookie": "sid=abc"}, None),
    ({"authorization": "Bearer abc.def"}, None),
    ({"x-session-token": "plainvalue"}, None),
    ({}, json.dumps({"user": "me", "password": "hunter2"}).encode()),
    ({}, b"user=me&passwd=hunter2"),
])
def test_credentials_are_caught(env, headers, body):
    add(env["conn"], headers=json.dumps(headers), body=body)
    assert run(env)["no_credentials"]["ok"] is False


def test_sanitized_credentials_pass(env):
    add(env["conn"], headers=json.dumps({"authorization": "Bearer [removed]", "x-session-token": "hmac:" + H}),
        body=json.dumps({"user": "me"}).encode())
    assert run(env)["no_credentials"]["ok"] is True


@pytest.mark.parametrize("url", [
    "https://www.google.com/search?q=rash+on+arm",
    "https://shop.example/find?keyword=pregnancy+test",
    "https://www.google.com/complete/search?client=x",
])
def test_search_queries_are_caught(env, url):
    add(env["conn"], url=url, dest_domain=url.split("/")[2])
    assert run(env)["no_search_queries"]["ok"] is False


def test_raw_content_left_after_analysis_is_caught(env):
    add(env["conn"], analyzed=1, body=b"x")
    assert run(env)["raw_deleted"]["ok"] is False
    env["conn"].execute("UPDATE requests SET body = NULL")
    assert run(env)["raw_deleted"]["ok"] is True


# ------------------------------------------------------------------ network

def test_listener_is_caught(env):
    assert run(env, listeners=lambda pids: ["TCP 127.0.0.1:8080"])["no_listeners"]["ok"] is False


def test_parse_netstat_finds_only_listening_sockets_of_our_pids():
    text = """
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1736
  TCP    127.0.0.1:8899         0.0.0.0:0              LISTENING       42
  TCP    10.0.0.2:5000          1.2.3.4:443            ESTABLISHED     42
  UDP    0.0.0.0:51805          172.217.118.4:443                      42
  UDP    0.0.0.0:5353           *:*                                    42
  UDP    0.0.0.0:5355           *:*                                    999
"""
    assert pc.parse_netstat(text, {42}) == ["TCP 127.0.0.1:8899", "UDP 0.0.0.0:5353"]


def test_remote_ollama_host_fails(env):
    assert run(env, ollama_host="http://192.168.1.5:11434")["local_ai_local"]["ok"] is False
    assert run(env)["local_ai_local"]["ok"] is True


def test_ledger_with_only_company_queries_passes(env):
    ledger.append(env["conn"], "api.tavily.com", {"query": "Criteo opt out of data collection", "max_results": 5,
                                                   "search_depth": "basic"})
    c = run(env)["only_company_names"]
    assert c["ok"] is True and "1" in c["detail"]


@pytest.mark.parametrize("dest,payload", [
    ("api.tavily.com", {"query": "rash on arm", "max_results": 5}),            # not a company query
    ("api.tavily.com", {"query": "Criteo opt out of data collection", "page": "https://x"}),  # extra field
    ("evil.example", {"query": "Criteo opt out of data collection"}),           # wrong destination
])
def test_ledger_with_anything_else_fails(env, dest, payload):
    ledger.append(env["conn"], dest, payload)
    assert run(env)["only_company_names"]["ok"] is False


def test_tampered_ledger_fails(env):
    ledger.append(env["conn"], "api.tavily.com", {"query": "Meta opt out of data collection"})
    env["conn"].execute("UPDATE ledger SET payload = '{\"query\":\"Meta data broker registration\"}'")
    assert run(env)["only_company_names"]["ok"] is False


def test_gate_allowlist_and_zero_network(env):
    checks = run(env)
    assert checks["gate_allowlist"]["ok"] is True
    assert checks["zero_network"]["ok"] is None  # off: nothing to prove
    db.set_setting(env["conn"], "zero_network", "1")
    assert run(env)["zero_network"]["ok"] is True
    assert env["conn"].execute("SELECT count(*) FROM ledger").fetchone()[0] == 0  # the test itself sent nothing


def test_handler_is_registered():
    from analyzer import handlers
    assert "privacy_checks" in handlers.HANDLERS


def test_requests_outside_their_audit_window_are_caught(env):
    add(env["conn"])
    assert run(env)["only_during_audits"]["ok"] is True
    add(env["conn"], captured_at=1)  # long before audit 1 started
    out = run(env)["only_during_audits"]
    assert out["ok"] is False and "1 stored request" in out["detail"]


def test_background_recorder_or_login_item_is_caught(env):
    assert run(env)["no_background"]["ok"] is True
    assert run(env, legacy_login_item=True)["no_background"]["ok"] is False
    assert run(env, recorder_running=True)["no_background"]["ok"] is False
    make_audit(env["conn"], status="running", started_at=db.now_ms())
    assert run(env, recorder_running=True)["no_background"]["ok"] is True

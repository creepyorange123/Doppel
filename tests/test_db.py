import secrets

import pytest
import sqlcipher3

from shared import db
from tests.helpers import make_audit


def test_init_creates_all_tables(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"settings", "audits", "app_rules", "requests", "findings", "scores",
            "companies", "ledger", "actions"} <= tables
    assert db.get_setting(conn, "install_at") is not None
    assert db.get_setting(conn, "schema_version") == db.SCHEMA_VERSION


def test_init_is_idempotent_and_keeps_install_time(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    first = db.get_setting(conn, "install_at")
    db.init(conn)
    assert db.get_setting(conn, "install_at") == first


def test_file_is_encrypted(tmp_path, db_key):
    path = tmp_path / "t.db"
    conn = db.open_db(path, db_key)
    make_audit(conn)
    conn.execute(
        "INSERT INTO requests (audit_id, captured_at, dest_domain, url) VALUES (1, ?, ?, ?)",
        (db.now_ms(), "tracker.example", "https://tracker.example/very-distinctive-marker"),
    )
    db.checkpoint_truncate(conn)
    conn.close()
    raw = path.read_bytes()
    assert b"SQLite format 3" not in raw
    assert b"very-distinctive-marker" not in raw
    assert b"tracker.example" not in raw


def test_wrong_key_is_rejected(tmp_path, db_key):
    path = tmp_path / "t.db"
    db.open_db(path, db_key).close()
    with pytest.raises(sqlcipher3.DatabaseError):
        db.connect(path, secrets.token_bytes(32))


def test_secure_delete_on(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_request_must_belong_to_an_audit(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    with pytest.raises(sqlcipher3.IntegrityError):
        conn.execute("INSERT INTO requests (captured_at, dest_domain) VALUES (1, 'x.example')")


def test_deleting_an_audit_deletes_its_requests(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    aid = make_audit(conn)
    conn.execute("INSERT INTO requests (id, audit_id, captured_at, dest_domain) VALUES (1, ?, 1, 'x.example')", (aid,))
    conn.execute("INSERT INTO findings (request_id, summary) VALUES (1, 's')")
    conn.execute("DELETE FROM audits WHERE id = ?", (aid,))
    assert conn.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 0


V1_SCHEMA = """
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE app_rules (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, match TEXT NOT NULL, rule TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'user', updated_at INTEGER NOT NULL, UNIQUE (kind, match));
CREATE TABLE requests (id INTEGER PRIMARY KEY, captured_at INTEGER NOT NULL, app_name TEXT, app_path TEXT,
    page_site TEXT, page_url TEXT, dest_domain TEXT NOT NULL, method TEXT, url TEXT, status INTEGER, headers TEXT,
    cookies TEXT, body BLOB, body_truncated INTEGER NOT NULL DEFAULT 0, size_bytes INTEGER, flags TEXT,
    metadata_only INTEGER NOT NULL DEFAULT 0, analyzed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE findings (request_id INTEGER PRIMARY KEY REFERENCES requests (id) ON DELETE CASCADE, company TEXT,
    category TEXT, flags TEXT, topic TEXT, summary TEXT);
CREATE TABLE scores (request_id INTEGER PRIMARY KEY REFERENCES requests (id) ON DELETE CASCADE,
    score INTEGER NOT NULL, tier TEXT NOT NULL, breakdown TEXT NOT NULL);
CREATE TABLE id_sightings (hmac TEXT NOT NULL, company TEXT NOT NULL, context TEXT NOT NULL,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY (hmac, company, context));
CREATE TABLE companies (name TEXT PRIMARY KEY, policy_summary TEXT, is_data_broker INTEGER, opt_out_url TEXT,
    news TEXT, sources TEXT, researched_at INTEGER, from_snapshot INTEGER NOT NULL DEFAULT 0);
CREATE TABLE ledger (id INTEGER PRIMARY KEY, sent_at INTEGER NOT NULL, destination TEXT NOT NULL,
    payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE actions (id INTEGER PRIMARY KEY, company TEXT NOT NULL, action TEXT NOT NULL, taken_at INTEGER NOT NULL);
"""


def test_migration_wipes_always_on_data_and_keeps_research(tmp_path, db_key):
    path = tmp_path / "old.db"
    old = db.connect(path, db_key)
    old.executescript(V1_SCHEMA)
    old.execute("INSERT INTO settings VALUES ('install_at', '5', 1), ('tracking_mode', 'allowlist', 1), "
                "('last_opened_at', '9', 1), ('consent_at', '7', 1)")
    old.execute("INSERT INTO requests (id, captured_at, dest_domain, url) "
                "VALUES (1, 1, 'tracker.example', 'https://tracker.example/always-on-marker')")
    old.execute("INSERT INTO findings (request_id, summary) VALUES (1, 's')")
    old.execute("INSERT INTO scores VALUES (1, 50, 'Profile building', '[]')")
    old.execute("INSERT INTO id_sightings VALUES ('h', 'Co', 'site', 1, 1)")
    old.execute("INSERT INTO app_rules (kind, match, rule, updated_at) VALUES ('app', '/A.app', 'track', 1), "
                "('action', 'criteo.com', 'block', 1), ('domain', 'bank.example', 'dont_track', 1)")
    old.execute("INSERT INTO actions (company, action, taken_at) VALUES ('Criteo', 'block', 1), ('Criteo', 'letter', 1)")
    old.execute("INSERT INTO companies (name, policy_summary) VALUES ('Criteo', 'Uses cookies.')")
    old.execute("INSERT INTO ledger VALUES (1, 1, 'api.exa.ai', '{}', 'p', 'h')")
    old.close()

    conn = db.open_db(path, db_key)
    assert "audit_id" in {r[1] for r in conn.execute("PRAGMA table_info(requests)")}
    for table in ("requests", "findings", "scores", "id_sightings"):
        assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table
    assert conn.execute("SELECT kind, match FROM app_rules").fetchall() == [("domain", "bank.example")]
    assert conn.execute("SELECT action FROM actions").fetchall() == [("letter",)]
    assert conn.execute("SELECT count(*) FROM companies").fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM ledger").fetchone()[0] == 1
    assert db.get_setting(conn, "tracking_mode") is None and db.get_setting(conn, "last_opened_at") is None
    assert db.get_setting(conn, "install_at") == "5" and db.get_setting(conn, "consent_at") == "7"
    conn.close()
    assert b"always-on-marker" not in path.read_bytes()
    # A second open is a no-op.
    db.open_db(path, db_key).close()

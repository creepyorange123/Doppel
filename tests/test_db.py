import secrets

import pytest
import sqlcipher3

from shared import db


def test_init_creates_all_tables(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"settings", "app_rules", "requests", "findings", "scores",
            "companies", "ledger", "actions"} <= tables
    assert db.get_setting(conn, "tracking_mode") == "blocklist"
    assert db.get_setting(conn, "install_at") is not None


def test_init_is_idempotent_and_keeps_install_time(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    first = db.get_setting(conn, "install_at")
    db.init(conn)
    assert db.get_setting(conn, "install_at") == first


def test_file_is_encrypted(tmp_path, db_key):
    path = tmp_path / "t.db"
    conn = db.open_db(path, db_key)
    conn.execute(
        "INSERT INTO requests (captured_at, dest_domain, url) VALUES (?, ?, ?)",
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

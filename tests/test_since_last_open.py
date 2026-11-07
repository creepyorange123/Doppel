import json

import pytest

from analyzer import handlers, pipeline
from shared import db


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


def add(conn, captured_at, analyzed=0, domain="t.example", body=b"payload"):
    cur = conn.execute(
        "INSERT INTO requests (captured_at, app_name, dest_domain, url, headers, cookies, body, page_url, flags, analyzed) "
        "VALUES (?, 'App', ?, 'https://t.example/x?id=1', '{}', '{}', ?, 'https://page.example/', '[]', ?)",
        (captured_at, domain, body, analyzed))
    return cur.lastrowid


def run(conn):
    events = []
    result = handlers.handle(conn, "analyze_since_last_open", {}, lambda t, p: events.append((t, p)))
    return result, events


def test_first_launch_uses_install_time(conn):
    install = int(db.get_setting(conn, "install_at"))
    add(conn, install + 10)
    add(conn, install + 20)
    result, _ = run(conn)
    assert result["analyzed"] == 2
    assert result["since"] == install


def test_count_matches_manual_count(conn):
    db.set_setting(conn, "last_opened_at", "1000")
    add(conn, 500, analyzed=1)            # old, done
    add(conn, 1500)                       # new
    add(conn, 2000)                       # new
    add(conn, 700, analyzed=0)            # old but never analyzed: safety net
    manual = conn.execute("SELECT count(*) FROM requests WHERE captured_at > 1000 OR analyzed = 0").fetchone()[0]
    result, events = run(conn)
    assert result["analyzed"] == manual == 3
    progress = [p for t, p in events if t == "progress"]
    assert progress[0]["total"] == 3 and progress[-1]["done"] == 3
    assert "3 requests since" in progress[0]["label"]


def test_last_opened_saved_and_raw_content_deleted(conn):
    rid = add(conn, db.now_ms())
    run(conn)
    assert int(db.get_setting(conn, "last_opened_at")) > 0
    row = conn.execute("SELECT body, headers, cookies, url, page_url, analyzed, dest_domain, flags FROM requests WHERE id=?",
                       (rid,)).fetchone()
    assert row[:5] == (None, None, None, None, None)
    assert row[5] == 1 and row[6] == "t.example" and row[7] == "[]"
    assert conn.execute("SELECT count(*) FROM findings WHERE request_id=?", (rid,)).fetchone()[0] == 1


def test_crash_does_not_skip_requests(conn, monkeypatch):
    add(conn, db.now_ms())
    add(conn, db.now_ms())

    def boom(conn, row):
        raise RuntimeError("crash")

    monkeypatch.setattr(pipeline, "STEPS", [boom])
    with pytest.raises(RuntimeError):
        run(conn)
    assert db.get_setting(conn, "last_opened_at") is None
    assert conn.execute("SELECT count(*) FROM requests WHERE analyzed=0 AND body IS NOT NULL").fetchone()[0] == 2
    monkeypatch.undo()
    result, _ = run(conn)
    assert result["analyzed"] == 2


def test_newest_first(conn):
    seen = []
    add(conn, db.now_ms() - 5000)
    add(conn, db.now_ms())
    pipeline.STEPS.insert(0, lambda c, row: seen.append(row["captured_at"]))
    try:
        run(conn)
    finally:
        pipeline.STEPS.pop(0)
    assert seen == sorted(seen, reverse=True)


def test_nothing_new(conn):
    result, events = run(conn)
    assert result["analyzed"] == 0

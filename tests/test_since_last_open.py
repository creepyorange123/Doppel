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


def test_survives_recorder_writing_at_the_same_time(tmp_path, db_key, monkeypatch):
    """The recorder commits new rows while the analyzer is mid-batch. With a plain
    BEGIN the analyzer's read snapshot goes stale and its first write fails at once
    with 'database is locked'; it must take the write lock up front instead."""
    import threading

    path = tmp_path / "shared.db"
    conn = db.open_db(path, db_key)
    for i in range(3):
        add(conn, db.now_ms() + i)
    recorder = db.connect(path, db_key)  # a second connection, like the recorder's writer
    done = threading.Event()

    def recorder_writes():
        recorder.execute("INSERT INTO requests (captured_at, dest_domain) VALUES (?, 'new.example')", (db.now_ms(),))
        done.set()

    def step(c, row):
        if not done.is_set() and not getattr(step, "started", False):
            step.started = True
            t = threading.Thread(target=recorder_writes)
            t.start()
            t.join(timeout=0.5)  # with BEGIN IMMEDIATE the recorder waits for us instead
        c.execute("INSERT OR REPLACE INTO findings (request_id, summary) VALUES (?, 's')", (row["id"],))

    monkeypatch.setattr(pipeline, "STEPS", [step])
    result, _ = run(conn)
    assert result["analyzed"] == 3
    assert done.wait(timeout=15)  # the recorder's write still lands afterwards
    assert conn.execute("SELECT count(*) FROM requests WHERE dest_domain = 'new.example'").fetchone()[0] == 1


def test_nothing_new(conn):
    result, events = run(conn)
    assert result["analyzed"] == 0


def test_recorder_writer_retries_instead_of_dropping_rows(tmp_path, db_key, monkeypatch):
    import sqlcipher3

    from recorder import addon

    real = db.open_db(tmp_path / "w.db", db_key)

    class Flaky:
        """Fails the first two transactions with 'database is locked', like a busy analyzer."""
        fails = 2

        def execute(self, sql, *a):
            if sql.startswith("BEGIN") and Flaky.fails:
                Flaky.fails -= 1
                raise sqlcipher3.OperationalError("database is locked")
            return real.execute(sql, *a)

        def executemany(self, *a):
            return real.executemany(*a)

    monkeypatch.setattr(addon, "RETRY_DELAY", 0.01)
    w = addon.Writer(Flaky())
    w._flush([{"captured_at": 1, "dest_domain": "a.example", "body_truncated": 0, "metadata_only": 1}])
    assert real.execute("SELECT count(*) FROM requests").fetchone()[0] == 1
    assert w.written == 1

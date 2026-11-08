import json

import pytest

from analyzer import handlers, pipeline
from shared import db
from shared.protocol import ProtocolError
from tests.helpers import make_audit


@pytest.fixture
def conn(tmp_path, db_key):
    c = db.open_db(tmp_path / "t.db", db_key)
    make_audit(c)
    return c


def add(conn, captured_at, analyzed=0, domain="t.example", body=b"payload", audit_id=1):
    cur = conn.execute(
        "INSERT INTO requests (audit_id, captured_at, app_name, dest_domain, url, headers, cookies, body, page_url, flags, analyzed) "
        "VALUES (?, ?, 'App', ?, 'https://t.example/x?id=1', '{}', '{}', ?, 'https://page.example/', '[]', ?)",
        (audit_id, captured_at, domain, body, analyzed))
    return cur.lastrowid


def run(conn, audit_id=1):
    events = []
    payload = {} if audit_id is None else {"audit_id": audit_id}
    result = handlers.handle(conn, "analyze_audit", payload, lambda t, p: events.append((t, p)))
    return result, events


def test_analyzes_only_that_audits_requests(conn):
    other = make_audit(conn, label="Other")
    mine = [add(conn, 10), add(conn, 20)]
    add(conn, 30, audit_id=other)
    result, events = run(conn)
    assert result == {"analyzed": 2, "audit_id": 1, "finished_at": result["finished_at"]}
    progress = [p for t, p in events if t == "progress"]
    assert progress[0]["total"] == 2 and progress[-1]["done"] == 2
    assert "2 requests from your Test audit audit" in progress[0]["label"]
    done = {r[0] for r in conn.execute("SELECT id FROM requests WHERE analyzed = 1")}
    assert done == set(mine)
    assert conn.execute("SELECT analyzed_at FROM audits WHERE id = 1").fetchone()[0] is not None
    assert conn.execute("SELECT analyzed_at FROM audits WHERE id = ?", (other,)).fetchone()[0] is None


def test_already_analysed_requests_are_skipped(conn):
    add(conn, 10, analyzed=1)
    add(conn, 20)
    assert run(conn)[0]["analyzed"] == 1


def test_raw_content_deleted(conn):
    rid = add(conn, db.now_ms())
    run(conn)
    row = conn.execute("SELECT body, headers, cookies, url, page_url, analyzed, dest_domain, flags FROM requests WHERE id=?",
                       (rid,)).fetchone()
    assert row[:5] == (None, None, None, None, None)
    assert row[5] == 1 and row[6] == "t.example" and row[7] == "[]"
    assert conn.execute("SELECT count(*) FROM findings WHERE request_id=?", (rid,)).fetchone()[0] == 1


def test_running_audit_is_not_analysed(conn):
    live = make_audit(conn, status="running")
    add(conn, 10, audit_id=live)
    with pytest.raises(ProtocolError):
        run(conn, live)
    # The catch-up run (no audit) leaves a running audit's rows alone too.
    add(conn, 20)
    assert run(conn, None)[0]["analyzed"] == 1
    assert conn.execute("SELECT analyzed FROM requests WHERE audit_id = ?", (live,)).fetchone()[0] == 0


def test_catch_up_run_covers_every_finished_audit(conn):
    other = make_audit(conn, label="Other")
    add(conn, 10)
    add(conn, 20, audit_id=other)
    result, _ = run(conn, None)
    assert result["analyzed"] == 2 and result["audit_id"] is None
    assert conn.execute("SELECT count(*) FROM audits WHERE analyzed_at IS NULL").fetchone()[0] == 0


def test_unknown_audit(conn):
    with pytest.raises(ProtocolError):
        run(conn, 999)


def test_crash_does_not_skip_requests(conn, monkeypatch):
    add(conn, db.now_ms())
    add(conn, db.now_ms())

    def boom(conn, row):
        raise RuntimeError("crash")

    monkeypatch.setattr(pipeline, "STEPS", [boom])
    with pytest.raises(RuntimeError):
        run(conn)
    assert conn.execute("SELECT analyzed_at FROM audits WHERE id = 1").fetchone()[0] is None
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
    make_audit(conn)
    for i in range(3):
        add(conn, db.now_ms() + i)
    recorder = db.connect(path, db_key)  # a second connection, like the recorder's writer
    done = threading.Event()

    def recorder_writes():
        recorder.execute("INSERT INTO requests (audit_id, captured_at, dest_domain) VALUES (1, ?, 'new.example')",
                         (db.now_ms(),))
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
    make_audit(real)

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
    w._flush([{"audit_id": 1, "captured_at": 1, "dest_domain": "a.example", "body_truncated": 0, "metadata_only": 1}])
    assert real.execute("SELECT count(*) FROM requests").fetchone()[0] == 1
    assert w.written == 1

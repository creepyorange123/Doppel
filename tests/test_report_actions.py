import json

import pytest

from analyzer import handlers, report, trackers
from recorder import rules
from shared import db
from shared.protocol import ProtocolError

TDB = trackers.TrackerDB({
    "criteo.com": {"company": "Criteo", "category": "Advertising"},
    "criteo.net": {"company": "Criteo", "category": "Advertising"},
    "hotjar.com": {"company": "Hotjar", "category": "Session Replay"},
})


@pytest.fixture
def conn(tmp_path, db_key, monkeypatch):
    monkeypatch.setattr(trackers, "default", lambda: TDB)
    c = db.open_db(tmp_path / "t.db", db_key)
    db.set_setting(c, "last_run_since", "1000")
    return c


def add(conn, rid, company, category, score, tier, app="Chrome", dest="x.criteo.com", at=2000, topic="Shopping"):
    conn.execute("INSERT INTO requests (id, captured_at, app_name, dest_domain, analyzed) VALUES (?, ?, ?, ?, 1)",
                 (rid, at, app, dest))
    conn.execute("INSERT INTO findings (request_id, company, category, flags, topic, summary) VALUES (?, ?, ?, ?, ?, ?)",
                 (rid, company, category, json.dumps([{"flag": "tracking_id", "where": "q"}]), topic, f"summary {rid}"))
    conn.execute("INSERT INTO scores (request_id, score, tier, breakdown) VALUES (?, ?, ?, ?)",
                 (rid, score, tier, json.dumps([{"signal": "tracking_id", "label": "A long-lived ID", "points": score}])))


def call(conn, t, p=None):
    return handlers.handle(conn, t, p or {})


# ----------------------------------------------------------------------- report

def test_summary_and_ranking(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern", app="Chrome")
    add(conn, 2, "Criteo", "Advertising", 40, "Moderate", app="Spotify")
    add(conn, 3, "Hotjar", "Session Replay", 30, "Moderate", dest="script.hotjar.com")
    add(conn, 4, None, "First party", 0, "Low", dest="news.example")
    add(conn, 5, "Hotjar", "Session Replay", 99, "High concern", dest="script.hotjar.com", at=500)  # before window
    r = call(conn, "report")
    assert r["summary"] == {"since": 1000, "requests": 4, "companies": 2, "high_concern": 1}
    assert [c["name"] for c in r["companies"]] == ["Criteo", "Hotjar"]
    criteo = r["companies"][0]
    assert criteo["max_score"] == 80 and criteo["tier"] == "High concern"
    assert sorted(criteo["apps"]) == ["Chrome", "Spotify"] and criteo["requests"] == 2


def test_company_detail_has_card_requests_and_breakdown(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern")
    conn.execute("INSERT INTO companies (name, policy_summary, is_data_broker, opt_out_url, news, sources, researched_at, from_snapshot) "
                 "VALUES ('Criteo', 'Uses cookies.', 0, 'https://www.criteo.com/privacy/disable/', '[]', '[]', 1, 1)")
    d = call(conn, "company_detail", {"company": "Criteo"})
    assert d["card"]["policy_summary"] == "Uses cookies."
    assert d["card"]["opt_out_url"] == "https://www.criteo.com/privacy/disable/"
    assert d["card"]["opt_out_domain"] == "www.criteo.com"
    assert d["requests"][0]["breakdown"][0]["points"] == 80
    assert "tracking_id" in d["card"]["exposure"]["flags"]


def test_opt_out_link_off_domain_is_hidden(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern")
    conn.execute("INSERT INTO companies (name, policy_summary, opt_out_url, from_snapshot) VALUES ('Criteo', 'x', 'https://evil.example/optout', 1)")
    assert call(conn, "company_detail", {"company": "Criteo"})["card"]["opt_out_url"] is None


def test_actions_offered_by_tier(conn):
    assert set(report.actions_for("High concern", has_opt_out=True)) == {"block", "strip", "opt-out", "letter"}
    assert set(report.actions_for("Profile-building", has_opt_out=False)) == {"block", "strip", "letter"}
    assert set(report.actions_for("Low", has_opt_out=False)) == {"letter"}


# ---------------------------------------------------------------------- actions

def test_block_writes_recorder_rules_for_all_company_domains(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern", dest="dis.criteo.com")
    call(conn, "take_action", {"company": "Criteo", "action": "block"})
    got = set(conn.execute("SELECT match, rule FROM app_rules WHERE kind='action'").fetchall())
    assert {("criteo.com", "block"), ("criteo.net", "block"), ("dis.criteo.com", "block")} <= got
    assert conn.execute("SELECT company, action FROM actions").fetchall() == [("Criteo", "block")]
    book = rules.RuleBook(conn, reload_seconds=0)
    assert book.snapshot().blocked("static.criteo.net")
    assert not book.snapshot().blocked("example.com")


def test_strip_rule_and_undo(conn):
    add(conn, 1, "Hotjar", "Session Replay", 60, "Profile-building", dest="script.hotjar.com")
    call(conn, "take_action", {"company": "Hotjar", "action": "strip"})
    assert rules.RuleBook(conn, reload_seconds=0).snapshot().stripped("vars.hotjar.com")
    call(conn, "undo_action", {"company": "Hotjar", "action": "strip"})
    assert not rules.RuleBook(conn, reload_seconds=0).snapshot().stripped("vars.hotjar.com")


def test_letter_is_generated_locally(conn):
    out = call(conn, "take_action", {"company": "Criteo", "action": "letter"})
    assert "Criteo" in out["letter"] and "access" in out["letter"].lower()


@pytest.mark.parametrize("p", [{"company": "Nope", "action": "block"}, {"company": "Criteo", "action": "nuke"}, {}])
def test_bad_actions_rejected(conn, p):
    with pytest.raises(ProtocolError):
        call(conn, "take_action", p)


def test_block_and_strip_do_not_change_track_decisions(conn):
    call(conn, "take_action", {"company": "Criteo", "action": "block"})
    book = rules.RuleBook(conn, reload_seconds=0)
    assert book.decide("C:/a.exe", "a", "x.criteo.com") == rules.TRACK


def test_gpc_setting_reaches_recorder(conn):
    call(conn, "set_setting", {"key": "gpc", "value": True})
    assert rules.RuleBook(conn, reload_seconds=0).snapshot().gpc is True

import json

import pytest

from analyzer import handlers, report, trackers
from shared import db
from shared.protocol import ProtocolError
from tests.helpers import make_audit

TDB = trackers.TrackerDB({
    "criteo.com": {"company": "Criteo", "category": "Advertising"},
    "criteo.net": {"company": "Criteo", "category": "Advertising"},
    "hotjar.com": {"company": "Hotjar", "category": "Session Replay"},
})


@pytest.fixture
def conn(tmp_path, db_key, monkeypatch):
    monkeypatch.setattr(trackers, "default", lambda: TDB)
    c = db.open_db(tmp_path / "t.db", db_key)
    make_audit(c)                 # audit 1: the one reported on
    make_audit(c, label="Other")  # audit 2: must never leak into audit 1's report
    return c


def add(conn, rid, company, category, score, tier, app="Chrome", dest="x.criteo.com", at=2000, topic="Shopping",
        audit=1, process=None, page=None, own=False):
    conn.execute("INSERT INTO requests (id, audit_id, captured_at, app_name, process_name, dest_domain, page_site, analyzed) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (rid, audit, at, app, process, dest, page))
    fl = [{"flag": "tracking_id", "where": "q"}] + ([{"flag": "app_own_domain", "where": "audit"}] if own else [])
    conn.execute("INSERT INTO findings (request_id, company, category, flags, topic, summary) VALUES (?, ?, ?, ?, ?, ?)",
                 (rid, company, category, json.dumps(fl), topic, f"summary {rid}"))
    conn.execute("INSERT INTO scores (request_id, score, tier, breakdown) VALUES (?, ?, ?, ?)",
                 (rid, score, tier, json.dumps([{"signal": "tracking_id", "label": "A long-lived ID", "points": score}])))


def call(conn, t, p=None):
    return handlers.handle(conn, t, {"audit_id": 1, **(p or {})})


# ----------------------------------------------------------------------- report

def test_summary_and_ranking(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern", app="Chrome")
    add(conn, 2, "Criteo", "Advertising", 40, "Measurement", app="Spotify")
    add(conn, 3, "Hotjar", "Session Replay", 30, "Measurement", dest="script.hotjar.com")
    add(conn, 4, None, "First party", 0, "Minimum utility", dest="news.example")
    add(conn, 5, "Hotjar", "Session Replay", 99, "High concern", dest="script.hotjar.com", audit=2)  # other audit
    r = call(conn, "report")
    assert r["audit"]["id"] == 1 and r["audit"]["label"] == "Test audit"
    assert r["summary"] == {"requests": 4, "companies": 2, "high_concern": 1}
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


def test_report_breaks_down_each_app_by_process(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern", app="Slack", process="Slack Helper (Renderer)")
    add(conn, 2, "Hotjar", "Session Replay", 30, "Measurement", app="Slack", process="Slack Helper (Renderer)")
    add(conn, 3, None, "First party", 0, "Minimum utility", app="Slack", process="Slack")
    add(conn, 4, "Criteo", "Advertising", 40, "Measurement", app="Zoom", process="zoom.us")
    apps = call(conn, "report")["apps"]
    assert [a["name"] for a in apps] == ["Slack", "Zoom"]
    slack = apps[0]
    assert slack["requests"] == 3 and slack["companies"] == 2 and slack["tier"] == "High concern"
    assert slack["processes"] == [{"name": "Slack Helper (Renderer)", "requests": 2}, {"name": "Slack", "requests": 1}]


def test_browsers_by_site_and_apps_by_destination(tmp_path, db_key, monkeypatch):
    monkeypatch.setattr(trackers, "default", lambda: TDB)
    conn = db.open_db(tmp_path / "b.db", db_key)
    make_audit(conn, apps=[{"name": "Zen", "path": "/Applications/Zen.app", "is_browser": True},
                           {"name": "Discord", "path": "/Applications/Discord.app", "is_browser": False}])
    add(conn, 1, "Criteo", "Advertising", 75, "Profile building", app="Zen", page="healthline.com")
    add(conn, 2, "Hotjar", "Session Replay", 40, "Measurement", app="Zen", page="healthline.com")
    add(conn, 3, "Criteo", "Advertising", 30, "Measurement", app="Zen", page="nytimes.com")
    add(conn, 4, None, None, 0, "Minimum utility", app="Discord", dest="gateway.discord.gg", own=True)
    add(conn, 5, None, None, 0, "Minimum utility", app="Discord", dest="cdn.discordapp.com", own=True)
    add(conn, 6, "Sentry", "Analytics", 10, "Minimum utility", app="Discord", dest="o1.ingest.sentry.io")
    apps = {a["name"]: a for a in call(conn, "report")["apps"]}
    zen, disc = apps["Zen"], apps["Discord"]
    assert zen["is_browser"] is True and "destinations" not in zen
    assert [(x["name"], x["companies"], x["tier"]) for x in zen["sites"]] == [
        ("healthline.com", ["Criteo", "Hotjar"], "Profile building"), ("nytimes.com", ["Criteo"], "Measurement")]
    assert disc["is_browser"] is False and "sites" not in disc
    assert [(x["name"], x["own"], x["requests"]) for x in disc["destinations"]] == [
        ("Sentry", False, 1), ("Its own servers", True, 2)]


def test_only_opt_out_and_letter_are_offered(conn):
    assert report.actions_for("High concern", has_opt_out=True) == ["opt-out", "letter"]
    assert report.actions_for("Minimum utility", has_opt_out=False) == ["letter"]


# ---------------------------------------------------------------------- actions

def test_letter_is_generated_locally(conn):
    out = call(conn, "take_action", {"company": "Criteo", "action": "letter"})
    assert "Criteo" in out["letter"] and "access" in out["letter"].lower()
    assert "not legal advice" in out["letter"]


def test_opt_out_is_recorded_and_shown(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern")
    call(conn, "take_action", {"company": "Criteo", "action": "opt-out"})
    assert call(conn, "report")["companies"][0]["actions_taken"] == ["opt-out"]


@pytest.mark.parametrize("p", [{"company": "Criteo", "action": "block"}, {"company": "Criteo", "action": "strip"},
                               {"company": "Criteo", "action": "nuke"}, {"action": "letter"}])
def test_bad_actions_rejected(conn, p):
    with pytest.raises(ProtocolError):
        call(conn, "take_action", p)


@pytest.mark.parametrize("t", ["report", "list_requests"])
def test_report_needs_a_real_audit(conn, t):
    with pytest.raises(ProtocolError):
        handlers.handle(conn, t, {})
    with pytest.raises(ProtocolError):
        handlers.handle(conn, t, {"audit_id": 99})


# ------------------------------------------------------------- requests and charts

def test_report_tier_and_day_counts(conn):
    day = 86_400_000
    add(conn, 1, "Criteo", "Advertising", 80, "High concern", at=2000)
    add(conn, 2, "Criteo", "Advertising", 40, "Measurement", at=2000 + day)
    add(conn, 3, "Hotjar", "Session Replay", 30, "Measurement", dest="script.hotjar.com", at=2000 + day)
    add(conn, 4, "Hotjar", "Session Replay", 99, "High concern", dest="script.hotjar.com", audit=2)  # other audit
    r = call(conn, "report")
    assert r["tier_requests"] == {"Minimum utility": 0, "Measurement": 2, "Profile building": 0, "High concern": 1}
    assert [sum(d["counts"].values()) for d in r["by_day"]] == [1, 2]
    assert r["by_day"][0]["date"] < r["by_day"][1]["date"]


def test_list_requests_newest_first_with_limit(conn):
    add(conn, 1, "Criteo", "Advertising", 80, "High concern", at=2000, topic="Medical Health")
    add(conn, 2, "Hotjar", "Session Replay", 30, "Measurement", dest="script.hotjar.com", at=3000)
    add(conn, 3, "Hotjar", "Session Replay", 30, "Measurement", dest="script.hotjar.com", at=9000, audit=2)
    r = call(conn, "list_requests")
    assert [x["id"] for x in r["requests"]] == [2, 1] and r["truncated"] is False
    first = r["requests"][1]
    assert first["company"] == "Criteo" and first["sensitive"] is True and first["breakdown"][0]["points"] == 80
    r = call(conn, "list_requests", {"limit": 1})
    assert [x["id"] for x in r["requests"]] == [2] and r["truncated"] is True
    with pytest.raises(ProtocolError):
        call(conn, "list_requests", {"limit": 0})

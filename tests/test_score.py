import json

import pytest

from analyzer import score
from shared import db


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


def finding(category=None, company=None, flags=(), topic="Uncategorized", metadata_only=False, app="Chrome",
            page_site="news.example"):
    return score.Input(company=company, category=category, flags=list(flags), topic=topic,
                       metadata_only=metadata_only, app_name=app, page_site=page_site)


def f(name, h=None):
    d = {"flag": name, "where": "x"}
    if h:
        d["hmac"] = h
    return d


def test_first_party_nothing_is_zero():
    r = score.score(finding(category="First party"), history=score.NoHistory())
    assert r.score == 0 and r.tier == "Low" and r.breakdown == []


def test_ad_company_with_id_and_page():
    r = score.score(finding("Advertising", "Google", [f("tracking_id", "h1"), f("page_url")]), score.NoHistory())
    pts = {b["signal"]: b["points"] for b in r.breakdown}
    assert pts == {"third_party_advertising": 20, "tracking_id": 15, "page_url": 10}
    assert r.score == 45 and r.tier == "Moderate"


def test_sensitive_topic_multiplies_and_caps():
    flags = [f("tracking_id", "h"), f("page_url"), f("fingerprinting"), f("hashed_email"), f("behavioural_events")]
    r = score.score(finding("Advertising", "X", flags, topic="Medical Health"), score.NoHistory())
    assert r.score == 100 and r.tier == "High concern"
    assert any(b["signal"] == "sensitive_topic" for b in r.breakdown)


def test_sensitive_app_multiplies():
    base = score.score(finding("Analytics", "X", [f("tracking_id", "h")], app="Chrome"), score.NoHistory())
    sens = score.score(finding("Analytics", "X", [f("tracking_id", "h")], app="MyFitnessPal"), score.NoHistory())
    assert sens.score == round(base.score * 1.5)


def test_tiers_boundaries():
    assert [score.tier_for(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)] == [
        "Low", "Low", "Moderate", "Moderate", "Profile-building", "Profile-building", "High concern", "High concern"]


def test_metadata_only_scores_destination_only():
    r = score.score(finding("Advertising", "X", [], metadata_only=True), score.NoHistory())
    assert r.score == 20


def test_cross_site_id_uses_all_history(conn):
    hist = score.DbHistory(conn)
    # Last week: same ID seen on another site.
    hist.record("h-xsite", "Google", "othersite.example")
    hist.record("h-xsite", "Google", "news.example")
    r = score.score(finding("Advertising", "Google", [f("tracking_id", "h-xsite")]), hist)
    assert "cross_site_id" in {b["signal"] for b in r.breakdown}


def test_cookie_syncing_same_id_two_companies(conn):
    hist = score.DbHistory(conn)
    hist.record("h-sync", "Google", "news.example")
    hist.record("h-sync", "Criteo", "news.example")
    r = score.score(finding("Advertising", "Google", [f("tracking_id", "h-sync")]), hist)
    assert "cookie_syncing" in {b["signal"] for b in r.breakdown}


def test_breakdown_sums_to_score_before_multiplier():
    r = score.score(finding("Data Broker", "LiveRamp", [f("tracking_id", "h"), f("hashed_email")]), score.NoHistory())
    assert sum(b["points"] for b in r.breakdown if b["signal"] != "sensitive_topic") == r.score


def test_score_step_writes_scores_and_history(conn):
    conn.execute("INSERT INTO requests (id, captured_at, app_name, page_site, dest_domain) VALUES (1, 1, 'Chrome', 'a.example', 'ads.example')")
    conn.execute("INSERT INTO findings (request_id, company, category, flags, topic, summary) VALUES "
                 "(1, 'Google', 'Advertising', ?, 'News and Politics', 's')", (json.dumps([f("tracking_id", "hh")]),))
    row = dict(zip(("id", "app_name", "page_site", "metadata_only"), (1, "Chrome", "a.example", 0)))
    score.record_step(conn, row)
    score.score_step(conn, row)
    s, tier, breakdown = conn.execute("SELECT score, tier, breakdown FROM scores WHERE request_id=1").fetchone()
    assert s == 35 and tier == "Moderate" and json.loads(breakdown)
    assert conn.execute("SELECT count(*) FROM id_sightings").fetchone()[0] == 1


def test_agreement_report():
    labels = [("Low", "Low"), ("High concern", "Profile-building"), ("Moderate", "Moderate"), ("Low", "Low")]
    rep = score.agreement(labels)
    assert rep["agreement"] == 0.75 and rep["n"] == 4
    assert rep["confusion"]["High concern"]["Profile-building"] == 1


def test_pipeline_scores_after_all_sightings_recorded(conn, monkeypatch):
    from analyzer import handlers, pipeline

    for i, site in enumerate(("a.example", "b.example"), start=1):
        conn.execute("INSERT INTO requests (id, captured_at, app_name, page_site, dest_domain) VALUES (?, ?, 'Chrome', ?, 'ads.example')",
                     (i, db.now_ms() + i, site))

    def fake_identify(conn, row):
        conn.execute("INSERT OR REPLACE INTO findings (request_id, company, category, flags, topic, summary) VALUES "
                     "(?, 'Ad Co', 'Advertising', ?, 'Uncategorized', 's')", (row["id"], json.dumps([f("tracking_id", "same")])))

    monkeypatch.setattr(pipeline, "STEPS", [fake_identify, score.record_step])
    monkeypatch.setattr(pipeline, "SCORE_STEPS", [score.score_step])
    handlers.handle(conn, "analyze_since_last_open", {}, lambda *a: None)
    for (b,) in conn.execute("SELECT breakdown FROM scores"):
        assert "cross_site_id" in {x["signal"] for x in json.loads(b)}


def test_review_export_and_report(conn, tmp_path):
    import csv, io
    from analyzer import review

    conn.execute("INSERT INTO requests (id, captured_at, app_name, dest_domain, body) VALUES (1, 1, 'Chrome', 'ads.example', X'73656372657421')")
    conn.execute("INSERT INTO findings (request_id, company, category, flags, topic, summary) VALUES (1, 'Ad', 'Advertising', '[]', 'x', 'Sent')")
    conn.execute("INSERT INTO scores (request_id, score, tier, breakdown) VALUES (1, 20, 'Low', '[]')")
    buf = io.StringIO()
    assert review.export(conn, 10, buf) == 1
    assert "secret" not in buf.getvalue()
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    rows[0]["human_tier"] = "Low"
    p = tmp_path / "l.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=review.FIELDS); w.writeheader(); w.writerows(rows)
    assert review.report(str(p))["agreement"] == 1.0

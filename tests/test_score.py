"""Scoring follows the original project plan's tiers and signals table."""

import json

import pytest

from analyzer import score
from shared import db


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


def inp(category=None, company=None, flags=(), topic="Uncategorized", metadata_only=False, app="Chrome",
        page_site="news.example", dest="ads.adco.example", is_data_broker=None, breakage=None):
    return score.Input(company=company, category=category, flags=list(flags), topic=topic,
                       metadata_only=metadata_only, app_name=app, page_site=page_site, dest_domain=dest,
                       is_data_broker=is_data_broker, breakage=breakage)


def f(name, h=None):
    d = {"flag": name, "where": "x"}
    if h:
        d["hmac"] = h
    return d


def pts(r):
    return {b["signal"]: b["points"] for b in r.breakdown}


class Hist:
    def __init__(self, contexts=1, companies=1):
        self._c, self._k = contexts, companies

    def contexts(self, h):
        return self._c

    def companies(self, h):
        return self._k


# ------------------------------------------------------------------------- tiers

def test_tiers_match_original_plan():
    cases = {0: "Minimum utility", 19: "Minimum utility", 20: "Measurement", 49: "Measurement",
             50: "Profile building", 79: "Profile building", 80: "High concern", 100: "High concern"}
    for value, tier in cases.items():
        assert score.tier_for(value) == tier, value


# ----------------------------------------------------------------------- signals

def test_first_party_font_is_minimum_utility():
    r = score.score(inp(category="CDN", company=None, dest="fonts.news.example"), score.NoHistory())
    assert r.score == 0 and r.tier == "Minimum utility"


def test_third_party_recipient_10():
    r = score.score(inp(category="CDN", company="Fonts Co", dest="cdn.fonts.example"), score.NoHistory())
    assert pts(r) == {"third_party": 10}


def test_advertising_and_ad_motivated_20():
    for cat in ("Advertising", "Ad Motivated Tracking"):
        assert pts(score.score(inp(cat, "X"), score.NoHistory()))["advertising"] == 20


def test_session_replay_25_by_category_or_payload():
    assert pts(score.score(inp("Session Replay", "Hotjar"), score.NoHistory()))["session_replay"] == 25
    r = score.score(inp("Analytics", "X", [f("behavioural_events")]), score.NoHistory())
    assert pts(r)["session_replay"] == 25


def test_cross_site_identifier_25_with_site_count():
    r = score.score(inp("Advertising", "X", [f("tracking_id", "h")]), Hist(contexts=9))
    assert pts(r)["cross_site_id"] == 25
    assert next(b for b in r.breakdown if b["signal"] == "cross_site_id")["label"] == "cross-site ID seen on 9 sites"


def test_page_url_counts_only_alongside_an_identifier():
    alone = score.score(inp("Analytics", "X", [f("page_url")]), score.NoHistory())
    assert "page_url" not in pts(alone)
    with_id = score.score(inp("Analytics", "X", [f("page_url"), f("tracking_id", "h")]), score.NoHistory())
    assert pts(with_id)["page_url"] == 10


def test_fingerprinting_20():
    assert pts(score.score(inp("Analytics", "X", [f("fingerprinting")]), score.NoHistory()))["fingerprinting"] == 20
    assert pts(score.score(inp("Fingerprinting", "X"), score.NoHistory()))["fingerprinting"] == 20


@pytest.mark.parametrize("flag", ["hashed_email", "hashed_phone", "raw_email"])
def test_hashed_personal_identifier_30(flag):
    assert pts(score.score(inp("Analytics", "X", [f(flag)]), score.NoHistory()))["personal_identifier"] == 30


def test_cookie_syncing_30():
    r = score.score(inp("Advertising", "X", [f("tracking_id", "h")]), Hist(companies=2))
    assert pts(r)["cookie_syncing"] == 30


def test_registered_data_broker_15():
    assert pts(score.score(inp("Advertising", "X", is_data_broker=True), score.NoHistory()))["data_broker"] == 15


def test_breakage_probe_adjusts():
    works = score.score(inp("Advertising", "X", breakage="works"), score.NoHistory())
    breaks = score.score(inp("Advertising", "X", breakage="breaks"), score.NoHistory())
    assert pts(works)["page_works_without_it"] == 10
    assert pts(breaks)["page_breaks_without_it"] == -20
    assert breaks.score == 10  # 10 + 20 - 20


def test_score_never_negative():
    r = score.score(inp("CDN", "X", breakage="breaks"), score.NoHistory())
    assert r.score == 0


def test_original_plan_example_breakdown():
    # "advertising company (+20), third party (+10), cross-site ID seen on 9 sites (+25),
    #  sent the page address (+10), page works without it (+10)"
    r = score.score(inp("Advertising", "AdCo", [f("tracking_id", "h"), f("page_url")], breakage="works"),
                    Hist(contexts=9))
    assert r.score == 75 and r.tier == "Profile building"
    assert [b["label"] for b in r.breakdown] == [
        "third party", "advertising company", "cross-site ID seen on 9 sites",
        "sent the page address", "page works without it"]


@pytest.mark.parametrize("topic", ["Medical Health", "Personal Finance", "Religion & Spirituality", "Sexuality"])
def test_sensitive_topic_x1_5_capped(topic):
    r = score.score(inp("Advertising", "X", [f("tracking_id", "h"), f("page_url")], topic=topic), score.NoHistory())
    assert r.score == round(40 * 1.5)
    big = score.score(inp("Advertising", "X", [f("tracking_id", "h"), f("hashed_email")], topic=topic), Hist(9, 2))
    assert big.score == 100 and big.tier == "High concern"


def test_sensitive_app_x1_5():
    base = score.score(inp("Analytics", "X", app="Chrome"), score.NoHistory())
    sens = score.score(inp("Analytics", "X", app="MyFitnessPal"), score.NoHistory())
    assert sens.score == round(base.score * 1.5)


def test_metadata_only_scores_recipient_only():
    r = score.score(inp("Advertising", "X", [f("tracking_id", "h")], metadata_only=True), Hist(9, 2))
    assert pts(r) == {"third_party": 10, "advertising": 20}


def test_app_traffic_without_page_is_third_party_only_for_known_companies():
    assert pts(score.score(inp(None, None, page_site=None, dest="api.app.example"), score.NoHistory())) == {}
    assert pts(score.score(inp("Analytics", "Mixpanel", page_site=None), score.NoHistory())) == {"third_party": 10}


# ------------------------------------------------------------------ history/steps

def test_cross_site_id_uses_all_history(conn):
    hist = score.DbHistory(conn)
    hist.record("h-xsite", "Google", "othersite.example")
    hist.record("h-xsite", "Google", "news.example")
    r = score.score(inp("Advertising", "Google", [f("tracking_id", "h-xsite")]), hist)
    assert "cross_site_id" in pts(r)


def test_cookie_syncing_same_id_two_companies(conn):
    hist = score.DbHistory(conn)
    hist.record("h-sync", "Google", "news.example")
    hist.record("h-sync", "Criteo", "news.example")
    assert "cookie_syncing" in pts(score.score(inp("Advertising", "Google", [f("tracking_id", "h-sync")]), hist))


def test_score_step_uses_research_and_breakage(conn):
    conn.execute("INSERT INTO requests (id, captured_at, app_name, page_site, dest_domain) "
                 "VALUES (1, 1, 'Chrome', 'a.example', 'ads.criteo.com')")
    conn.execute("INSERT INTO findings (request_id, company, category, flags, topic, summary) VALUES "
                 "(1, 'Criteo', 'Advertising', ?, 'News and Politics', 's')", (json.dumps([f("tracking_id", "hh")]),))
    conn.execute("INSERT INTO companies (name, is_data_broker, from_snapshot) VALUES ('Criteo', 1, 1)")
    conn.execute("INSERT INTO breakage (domain, result, probed_at) VALUES ('criteo.com', 'works', 1)")
    row = {"id": 1, "app_name": "Chrome", "page_site": "a.example", "metadata_only": 0, "dest_domain": "ads.criteo.com"}
    score.record_step(conn, row)
    score.score_step(conn, row)
    s, tier, breakdown = conn.execute("SELECT score, tier, breakdown FROM scores WHERE request_id=1").fetchone()
    assert s == 10 + 20 + 15 + 10 and tier == "Profile building"
    assert {b["signal"] for b in json.loads(breakdown)} == {"third_party", "advertising", "data_broker",
                                                            "page_works_without_it"}


def test_agreement_report():
    labels = [("Minimum utility", "Minimum utility"), ("High concern", "Profile building"),
              ("Measurement", "Measurement"), ("Minimum utility", "Minimum utility")]
    rep = score.agreement(labels)
    assert rep["agreement"] == 0.75 and rep["n"] == 4
    assert rep["confusion"]["High concern"]["Profile building"] == 1


def test_pipeline_scores_after_all_sightings_recorded(conn, monkeypatch):
    from analyzer import handlers, pipeline

    for i, site in enumerate(("a.example", "b.example"), start=1):
        conn.execute("INSERT INTO requests (id, captured_at, app_name, page_site, dest_domain) "
                     "VALUES (?, ?, 'Chrome', ?, 'ads.example')", (i, db.now_ms() + i, site))

    def fake_identify(conn, row):
        conn.execute("INSERT OR REPLACE INTO findings (request_id, company, category, flags, topic, summary) VALUES "
                     "(?, 'Ad Co', 'Advertising', ?, 'Uncategorized', 's')",
                     (row["id"], json.dumps([f("tracking_id", "same")])))

    monkeypatch.setattr(pipeline, "STEPS", [fake_identify, score.record_step])
    monkeypatch.setattr(pipeline, "SCORE_STEPS", [score.score_step])
    handlers.handle(conn, "analyze_since_last_open", {}, lambda *a: None)
    for (b,) in conn.execute("SELECT breakdown FROM scores"):
        assert "cross_site_id" in {x["signal"] for x in json.loads(b)}


def test_review_export_and_report(conn, tmp_path):
    import csv
    import io

    from analyzer import review

    conn.execute("INSERT INTO requests (id, captured_at, app_name, dest_domain, body) "
                 "VALUES (1, 1, 'Chrome', 'ads.example', X'73656372657421')")
    conn.execute("INSERT INTO findings (request_id, company, category, flags, topic, summary) "
                 "VALUES (1, 'Ad', 'Advertising', '[]', 'x', 'Sent')")
    conn.execute("INSERT INTO scores (request_id, score, tier, breakdown) VALUES (1, 20, 'Measurement', '[]')")
    buf = io.StringIO()
    assert review.export(conn, 10, buf) == 1
    assert "secret" not in buf.getvalue()
    rows = list(csv.DictReader(io.StringIO(buf.getvalue())))
    rows[0]["human_tier"] = "Measurement"
    p = tmp_path / "l.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=review.FIELDS)
        w.writeheader()
        w.writerows(rows)
    assert review.report(str(p))["agreement"] == 1.0


def test_rows_saved_under_old_tier_names_are_renamed_from_their_score(tmp_path, db_key):
    from shared import db as _db

    c = _db.open_db(tmp_path / "m.db", db_key)
    for rid, s, old in [(1, 10, "Low"), (2, 22, "Low"), (3, 40, "Moderate"), (4, 60, "Profile-building"),
                        (5, 90, "High concern"), (6, 30, "Measurement")]:
        c.execute("INSERT INTO requests (id, captured_at, dest_domain) VALUES (?, 1, 'x')", (rid,))
        c.execute("INSERT INTO scores (request_id, score, tier, breakdown) VALUES (?, ?, ?, '[]')", (rid, s, old))
    assert score.migrate_legacy_tiers(c) == 4
    tiers = dict(c.execute("SELECT request_id, tier FROM scores"))
    assert tiers == {1: "Minimum utility", 2: "Measurement", 3: "Measurement", 4: "Profile building",
                     5: "High concern", 6: "Measurement"}
    assert score.migrate_legacy_tiers(c) == 0  # safe to run on every start

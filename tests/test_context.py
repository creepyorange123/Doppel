"""Metadata-only requests get the page they were probably loaded by."""

import json

import pytest

from analyzer import context, trackers
from shared import db
from tests.helpers import make_audit

TDB = trackers.TrackerDB({
    "facebook.net": {"company": "Meta", "category": "Advertising"},
    "doubleclick.net": {"company": "Google", "category": "Advertising"},
})


@pytest.fixture
def conn(tmp_path, db_key):
    c = db.open_db(tmp_path / "t.db", db_key)
    make_audit(c, apps=[{"name": "Zen", "path": "/Applications/Zen.app", "is_browser": True, "engine": "gecko"},
                        {"name": "Discord", "path": "/Applications/Discord.app", "is_browser": False}])
    return c


def add(conn, at, host, process="zen", meta=1, page=None, app="Zen"):
    return conn.execute(
        "INSERT INTO requests (audit_id, captured_at, app_name, process_name, dest_domain, page_site, metadata_only, flags) "
        "VALUES (1, ?, ?, ?, ?, ?, ?, '[]')", (at, app, process, host, page, meta)).lastrowid


def pages(conn):
    return {h: (p, "page_inferred" in f) for h, p, f in conn.execute("SELECT dest_domain, page_site, flags FROM requests")}


def test_trackers_after_a_page_belong_to_it(conn):
    ids = [add(conn, 1000, "www.healthline.com"), add(conn, 1500, "assets.healthline.com"),
           add(conn, 2000, "connect.facebook.net"), add(conn, 2500, "stats.g.doubleclick.net"),
           add(conn, 9000, "www.nytimes.com"), add(conn, 9200, "static01.nytimes.com"),
           add(conn, 9500, "connect.facebook.net")]
    assert context.infer_pages(conn, ids, TDB) == 7
    rows = conn.execute("SELECT dest_domain, page_site, flags FROM requests ORDER BY id").fetchall()
    assert [r[1] for r in rows] == ["healthline.com"] * 4 + ["nytimes.com"] * 3
    assert ["page_inferred" in r[2] for r in rows] == [False, False, True, True, False, False, True]


def test_a_host_that_loads_nothing_of_its_own_is_not_a_page(conn):
    """e.g. ad-delivery.net, an ad-blocker probe, contacted between page loads."""
    ids = [add(conn, 1000, "www.healthline.com"), add(conn, 1100, "assets.healthline.com"),
           add(conn, 2000, "ad-delivery.net"), add(conn, 2100, "connect.facebook.net")]
    context.infer_pages(conn, ids, TDB)
    assert pages(conn)["connect.facebook.net"] == ("healthline.com", True)


def test_trackers_and_infrastructure_are_never_the_page(conn):
    ids = [add(conn, 1000, "www.example.org"), add(conn, 1050, "cdn.example.org"), add(conn, 1100, "facebook.net"),
           add(conn, 1200, "fonts.googleapis.com"), add(conn, 1300, "googleapis.com"), add(conn, 1400, "x.doubleclick.net")]
    context.infer_pages(conn, ids, TDB)
    assert pages(conn)["x.doubleclick.net"][0] == "example.org"


def test_processes_are_kept_apart_and_old_pages_expire(conn):
    ids = [add(conn, 1000, "www.healthline.com", process="zen"), add(conn, 1100, "img.healthline.com", process="zen"),
           add(conn, 2000, "connect.facebook.net", process="zen-2"),                 # other process: no page
           add(conn, 1000 + context.WINDOW_MS + 1, "x.doubleclick.net", process="zen")]  # too late
    context.infer_pages(conn, ids, TDB)
    p = pages(conn)
    assert p["connect.facebook.net"][0] is None and p["x.doubleclick.net"][0] is None


def test_full_capture_rows_keep_their_real_page(conn):
    ids = [add(conn, 1000, "www.healthline.com"), add(conn, 1100, "img.healthline.com"),
           add(conn, 1500, "connect.facebook.net", meta=0, page="news.example")]
    context.infer_pages(conn, ids, TDB)
    assert pages(conn)["connect.facebook.net"] == ("news.example", False)


def test_end_to_end_facebook_on_healthline_is_flagged(conn, monkeypatch):
    """Metadata-only Zen audit: healthline.com, then Facebook. Must not score as Measurement."""
    from analyzer import handlers, identify, pipeline, score

    monkeypatch.setattr(trackers, "default", lambda: TDB)
    ctx = identify.Context(conn, hmac_key=b"k" * 32, personal=identify.PersonalIds.from_values([], [], b"k" * 32),
                           topic_model=None, resolve_cname=None, tracker_db=TDB)
    monkeypatch.setattr(pipeline, "STEPS", [identify.make_step(ctx), score.record_step])
    monkeypatch.setattr(pipeline, "SCORE_STEPS", [score.score_step])
    add(conn, 1000, "www.healthline.com")
    add(conn, 1100, "assets.healthline.com")
    add(conn, 2000, "connect.facebook.net")
    add(conn, 9000, "www.nytimes.com")
    add(conn, 9100, "static01.nytimes.com")
    add(conn, 9500, "connect.facebook.net")
    handlers.handle(conn, "analyze_audit", {"audit_id": 1}, lambda *a: None)
    rows = conn.execute("SELECT r.page_site, s.tier, s.breakdown FROM requests r JOIN scores s ON s.request_id = r.id "
                        "WHERE r.dest_domain = 'connect.facebook.net' ORDER BY r.id").fetchall()
    assert [r[1] for r in rows] != ["Measurement", "Measurement"]
    assert all(r[1] in ("Profile building", "High concern") for r in rows)
    signals = {b["signal"] for b in json.loads(rows[0][2])}
    assert {"likely_cross_site", "company_across_sites"} <= signals


def test_a_burst_from_an_unknown_ad_exchange_is_not_a_page(conn):
    ids = [add(conn, 1000, "www.healthline.com"), add(conn, 1100, "assets.healthline.com"),
           add(conn, 5000, "hm.adspsp.com"), add(conn, 5001, "adspsp.com"), add(conn, 5100, "pbs1.adspsp.com"),
           add(conn, 6000, "connect.facebook.net")]
    context.infer_pages(conn, ids, TDB)
    assert pages(conn)["connect.facebook.net"][0] == "healthline.com"


def test_unknown_pages_are_not_cached_so_better_rules_get_a_chance(conn):
    from analyzer import topics

    cache = topics.TopicCache(conn, b"k" * 32)
    assert cache.get_or_classify("https://some-unknown-site.example/", None) == "Uncategorized"
    assert cache.get_or_classify("https://www.webmd.com/", None) == "Medical Health"
    assert conn.execute("SELECT count(*) FROM topic_cache").fetchone()[0] == 1
    assert topics.keyword_topic("https://healthline.com/") == "Medical Health"


def flags_of(conn, host):
    return [f["flag"] for f in json.loads(conn.execute("SELECT flags FROM requests WHERE dest_domain = ?",
                                                       (host,)).fetchone()[0])]


def test_apps_that_are_not_browsers_never_get_a_page(conn):
    """Discord opening discord.com then Sentry is not 'a page with a tracker'."""
    ids = [add(conn, 1000, "discord.com", process="Discord", app="Discord"),
           add(conn, 1100, "cdn.discordapp.com", process="Discord", app="Discord"),
           add(conn, 1200, "o64374.ingest.sentry.io", process="Discord", app="Discord")]
    context.infer_pages(conn, ids, TDB)
    assert {h: p for h, (p, _) in pages(conn).items()} == {
        "discord.com": None, "cdn.discordapp.com": None, "o64374.ingest.sentry.io": None}


def test_app_makers_own_domains_are_first_party(conn):
    ids = [add(conn, t, h, process="Discord", app="Discord") for t, h in
           [(1, "discord.com"), (2, "gateway.discord.gg"), (3, "cdn.discordapp.com"), (4, "o1.ingest.sentry.io"),
            (5, "connect.facebook.net")]]
    context.infer_pages(conn, ids, TDB)
    assert "app_own_domain" in flags_of(conn, "gateway.discord.gg")
    assert "app_own_domain" not in flags_of(conn, "o1.ingest.sentry.io")
    assert "app_own_domain" not in flags_of(conn, "connect.facebook.net")  # a tracker is never "own"


def test_unknown_apps_own_their_most_contacted_domain():
    hosts = ["api.someapp.io"] * 6 + ["cdn.someapp.io", "o1.ingest.sentry.io", "api.segment.io"]
    assert "someapp.io" in context.app_domains("Some App", hosts, TDB)
    assert context.app_domains("Some App", ["a.one.io", "b.two.io"], TDB) == set()  # no clear owner


def test_own_domain_is_not_scored_as_third_party():
    from analyzer import score

    i = score.Input(company=None, category=None, flags=[{"flag": "app_own_domain"}], topic=None,
                    metadata_only=True, app_name="Discord", page_site=None, dest_domain="discord.com")
    assert not score.is_third_party(i)

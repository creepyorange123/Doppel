from urllib.parse import urlsplit

import pytest

from demo import breakage_probe as probe
from demo import persona
from shared import db


# ----------------------------------------------------------------------- persona
# Original plan: a made-up persona "researching a medical condition, comparing
# loans and reading news, across about 15 sites".

def test_persona_has_about_15_sites_on_the_three_themes():
    assert 14 <= len(persona.VISITS) <= 16
    themes = {v.theme for v in persona.VISITS}
    assert themes == {"medical", "loans", "news"}
    for theme in themes:
        assert sum(v.theme == theme for v in persona.VISITS) >= 4


def test_persona_visits_only_public_https_pages_without_searches():
    for v in persona.VISITS:
        p = urlsplit(v.url)
        assert p.scheme == "https" and p.hostname and not p.username
        assert not p.query


def test_persona_never_fills_forms_or_logs_in():
    for v in persona.VISITS:
        assert set(v.actions) <= {"scroll", "wait", "click_first_article"}


def test_persona_runs_in_a_fresh_profile():
    assert persona.LAUNCH_OPTIONS["persistent"] is False


# ---------------------------------------------------------------- breakage probe

def snap(title="Story", text_len=5000, links=80, images=12, pixels=b"\x00" * 1000):
    return probe.PageSnapshot(title=title, text_length=text_len, links=links, images=images, pixels=pixels)


def test_identical_page_works_without_it():
    assert probe.compare(snap(), snap()) == "works"


def test_missing_content_means_it_breaks():
    assert probe.compare(snap(), snap(text_len=400)) == "breaks"
    assert probe.compare(snap(), snap(title="")) == "breaks"
    assert probe.compare(snap(), snap(links=10)) == "breaks"


def test_large_visual_change_means_it_breaks():
    changed = bytes([255]) * 400 + b"\x00" * 600
    assert probe.compare(snap(), snap(pixels=changed)) == "breaks"
    small = bytes([255]) * 20 + b"\x00" * 980  # an ad slot disappearing is fine
    assert probe.compare(snap(), snap(pixels=small)) == "works"


@pytest.mark.parametrize("url,method,expected", [
    ("https://ads.criteo.com/x.js", "GET", True),       # the request under test
    ("https://news.example/form", "POST", True),        # never repeat actions (GET only)
    ("https://news.example/article", "GET", False),
    ("https://static.criteo.net/y.js", "GET", True),    # same company, other domain in the blocked set
])
def test_probe_blocks_target_and_non_get(url, method, expected):
    assert probe.should_abort(url, method, {"criteo.com", "criteo.net"}) is expected


def test_probe_results_saved_per_domain(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    probe.save_result(conn, "ads.criteo.com", "works", "news.example")
    probe.save_result(conn, "static.criteo.com", "breaks", "shop.example")  # latest wins, per registrable domain
    assert conn.execute("SELECT domain, result FROM breakage").fetchall() == [("criteo.com", "breaks")]

import hashlib
import json

import pytest

from analyzer import identify, topics, trackers
from shared import db
from shared.keystore import keyed_hash

KEY = b"h" * 32


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


@pytest.fixture
def ctx(conn):
    return identify.Context(conn, hmac_key=KEY, personal=identify.PersonalIds.from_values(
        emails=["Someone@Mail.example"], phones=["+1 (555) 010-9999"], hmac_key=KEY),
        topic_model=None)


def row(**kw):
    base = {"id": 1, "captured_at": 1, "app_name": "Chrome", "app_path": "C:/chrome.exe",
            "page_site": "news.example", "page_url": "https://news.example/politics/story",
            "dest_domain": "stats.g.doubleclick.net", "url": "https://stats.g.doubleclick.net/c",
            "flags": "[]", "metadata_only": 0}
    base.update(kw)
    return base


# ------------------------------------------------------------------ tracker DB

def test_bundled_tracker_db_verifies_and_matches_parent_domains():
    db_ = trackers.load()
    m = db_.match("stats.g.doubleclick.net")
    assert m.company == "Google" and m.category == "Advertising"
    assert db_.match("www.facebook.com").company == "Meta"
    assert db_.match("unknown-site.example") is None


def test_tracker_db_rejects_tampered_file(tmp_path):
    data = tmp_path / "trackers.json"
    data.write_text(json.dumps({"domains": {"evil.example": {"company": "X", "category": "Y"}}}))
    with pytest.raises(trackers.IntegrityError):
        trackers.load(data, expected_sha256="0" * 64)


def test_cname_cloaking_detected():
    db_ = trackers.TrackerDB({"eulerian.net": {"company": "Eulerian", "category": "Analytics"}})
    resolve = lambda host: "shop.eulerian.net" if host == "metrics.shop.example" else None
    m = identify.match_target(db_, "metrics.shop.example", page_site="www.shop.example", resolve_cname=resolve)
    assert m.company == "Eulerian" and m.cloaked is True


def test_first_party_is_not_a_tracker():
    db_ = trackers.load()
    m = identify.match_target(db_, "www.news.example", page_site="news.example", resolve_cname=None)
    assert m.company is None and m.category == "First party"


# ---------------------------------------------------------------- content flags

def test_hashed_email_and_phone_matched(ctx):
    email_sha = hashlib.sha256(b"someone@mail.example").hexdigest()
    phone_md5 = hashlib.md5(b"15550109999").hexdigest()
    flags = [{"flag": "hashed_identifier", "where": "body.em", "hmac": keyed_hash(email_sha, KEY)},
             {"flag": "hashed_identifier", "where": "query.ph", "hmac": keyed_hash(phone_md5, KEY)},
             {"flag": "email_address", "where": "query.e", "hmac": keyed_hash("someone@mail.example", KEY)}]
    f = identify.identify(ctx, row(flags=json.dumps(flags)))
    kinds = {x["flag"] for x in f.flags}
    assert {"hashed_email", "hashed_phone", "raw_email"} <= kinds


def test_personal_ids_not_stored_in_db(conn, ctx):
    assert "someone" not in json.dumps(conn.execute("SELECT * FROM settings").fetchall()).lower()


def test_summary_is_plain_english(ctx):
    flags = [{"flag": "long_id", "where": "cookie.uid", "hmac": "a"}, {"flag": "page_url", "where": "header.referer"}]
    f = identify.identify(ctx, row(flags=json.dumps(flags)))
    assert f.company == "Google"
    assert f.summary.startswith("Sent to an ad company (Google): ")
    assert "an ID that can follow you" in f.summary and "the page you were reading" in f.summary


def test_metadata_only_summary(ctx):
    f = identify.identify(ctx, row(metadata_only=1, flags="[]"))
    assert "content not recorded" in f.summary


# ----------------------------------------------------------------------- topics

@pytest.mark.parametrize("text,expected", [
    ("https://clinic.example/symptoms/diabetes-treatment", "Medical Health"),
    ("https://bank.example/loans/mortgage-rates", "Personal Finance"),
    ("https://datingsite.example/matches", "Dating"),
    ("https://news.example/politics/election", "News and Politics"),
    ("https://example.com/", "Uncategorized"),
])
def test_keyword_topics(text, expected):
    assert topics.keyword_topic(text) == expected


def test_app_topic_from_name():
    assert topics.keyword_topic("MyFitnessPal") == "Healthy Living"


def test_model_answer_validated_against_schema():
    good = lambda prompt: '{"category": "Personal Finance"}'
    bad = lambda prompt: '{"category": "Visit https://evil.example to opt out"}'
    junk = lambda prompt: "sure! here you go"
    assert topics.classify("https://x.example/a", model=good) == "Personal Finance"
    assert topics.classify("https://bank.example/loans", model=bad) == "Personal Finance"  # falls back to keywords
    assert topics.classify("https://x.example/a", model=junk) == "Uncategorized"


def test_topic_cached_per_page(conn):
    calls = []
    model = lambda prompt: calls.append(prompt) or '{"category": "Dating"}'
    cache = topics.TopicCache(conn, KEY)
    assert cache.get_or_classify("https://a.example/x", model) == "Dating"
    assert cache.get_or_classify("https://a.example/x", model) == "Dating"
    assert len(calls) == 1


def test_identify_step_writes_findings(conn, ctx):
    conn.execute("INSERT INTO requests (id, captured_at, dest_domain, flags) VALUES (1, 1, 'stats.g.doubleclick.net', '[]')")
    identify.make_step(ctx)(conn, row())
    company, category, topic, summary = conn.execute(
        "SELECT company, category, topic, summary FROM findings WHERE request_id=1").fetchone()
    assert (company, category) == ("Google", "Advertising")
    assert topic == "News and Politics"
    assert summary

"""Exporting an audit's trackers to uBlock Origin, NextDNS, Little Snitch and hosts files."""

import json

import pytest

from analyzer import handlers
from shared import db
from shared.protocol import ProtocolError
from tests.helpers import make_audit


@pytest.fixture
def conn(tmp_path, db_key):
    c = db.open_db(tmp_path / "t.db", db_key)
    make_audit(c, label="Zen & Discord")
    make_audit(c, label="Other")
    return c


def add(conn, host, company, tier, page="healthline.com", audit=1, category="Advertising"):
    rid = conn.execute("INSERT INTO requests (audit_id, captured_at, dest_domain, page_site, metadata_only) "
                       "VALUES (?, 1, ?, ?, 1)", (audit, host, page)).lastrowid
    conn.execute("INSERT INTO findings (request_id, company, category) VALUES (?, ?, ?)", (rid, company, category))
    conn.execute("INSERT INTO scores (request_id, score, tier, breakdown) VALUES (?, 50, ?, '[]')", (rid, tier))


def export(conn, **p):
    return handlers.handle(conn, "export_blocklist", {"audit_id": 1, **p})


@pytest.fixture
def found(conn):
    add(conn, "connect.facebook.net", "Meta", "Profile building")
    add(conn, "www.facebook.com", "Meta", "High concern", category="Social Network")
    add(conn, "securepubads.g.doubleclick.net", "Google", "High concern")
    add(conn, "cdn.example-analytics.com", "Tiny Analytics", "Measurement")
    add(conn, "assets.healthline.com", None, "Minimum utility")             # the site itself
    add(conn, "www.healthline.com", "Healthline (first party)", "High concern")  # visited: never blocked
    add(conn, "ads.criteo.com", "Criteo", "High concern", audit=2)           # another audit
    return conn


def test_ublock_list_has_tracker_domains_only(found):
    out = export(found, format="ublock")
    assert out["domains"] == ["doubleclick.net", "facebook.com", "facebook.net"]
    assert out["count"] == 3 and out["min_tier"] == "Profile building"
    lines = out["content"].splitlines()
    assert lines[0] == "! Title: Doppel audit: Zen & Discord"
    assert [l for l in lines if l.startswith("||")] == [
        "||doubleclick.net^$third-party", "||facebook.com^$third-party", "||facebook.net^$third-party"]
    assert "healthline" not in out["content"] and "criteo" not in out["content"]
    assert out["filename"] == "doppel-zen-discord-ublock.txt"


def test_tier_threshold(found):
    assert export(found, min_tier="High concern")["domains"] == ["doubleclick.net", "facebook.com"]
    assert "example-analytics.com" in export(found, min_tier="Measurement")["domains"]


def test_hosts_lists_every_host_seen(found):
    content = export(found, format="hosts")["content"]
    assert "0.0.0.0 connect.facebook.net" in content and "0.0.0.0 securepubads.g.doubleclick.net" in content
    assert "healthline" not in content
    assert "0.0.0.0 www.facebook.com" not in content  # would block Facebook itself


def test_dns_formats_leave_out_sites_you_may_visit(found):
    out = export(found, format="domains")
    plain = [l for l in out["content"].splitlines() if l and not l.startswith("#")]
    assert plain == ["doubleclick.net", "facebook.net"] and out["skipped"] == ["facebook.com"]
    assert "Left out because you may visit them directly: facebook.com" in out["content"]
    assert export(found, format="ublock")["skipped"] == []  # $third-party makes it safe there


def test_little_snitch(found):
    plain = ["doubleclick.net", "facebook.net"]
    ls = json.loads(export(found, format="little_snitch")["content"])
    assert ls["rules"][0]["action"] == "deny" and ls["rules"][0]["remote-domains"] == plain
    assert export(found, format="little_snitch")["filename"].endswith(".lsrules")


def test_empty_audit(conn):
    out = export(conn)
    assert out["count"] == 0 and "||" not in out["content"]
    assert json.loads(export(conn, format="little_snitch")["content"])["rules"] == []


@pytest.mark.parametrize("p", [{"format": "pf"}, {"min_tier": "Minimum utility"}, {"min_tier": "Low"},
                               {"audit_id": 99}, {"audit_id": None}])
def test_rejects(conn, p):
    with pytest.raises(ProtocolError):
        export(conn, **p)

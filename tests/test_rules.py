import pytest

from recorder import rules as r
from shared import db


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


def add_rule(conn, kind, match, rule):
    conn.execute("INSERT INTO app_rules (kind, match, rule, updated_at) VALUES (?, ?, ?, ?)",
                 (kind, match, rule, db.now_ms()))


@pytest.mark.parametrize("path,platform", [
    ("C:\\Windows\\System32\\svchost.exe", "win32"),
    ("c:/windows/explorer.exe", "win32"),
    ("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "darwin"),
    ("/usr/libexec/nsurlsessiond", "darwin"),
    ("/usr/sbin/mDNSResponder", "darwin"),
])
def test_system_processes(path, platform):
    assert r.is_system_process(path, platform=platform)


@pytest.mark.parametrize("path,platform", [
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "win32"),
    ("/Applications/Spotify.app/Contents/MacOS/Spotify", "darwin"),
    ("/usr/bin/curl", "darwin"),
])
def test_user_processes(path, platform):
    assert not r.is_system_process(path, platform=platform)


def test_display_name():
    assert r.app_display_name("/Applications/Spotify.app/Contents/MacOS/Spotify", "darwin") == "Spotify"
    assert r.app_display_name("C:\\Program Files\\Slack\\slack.exe", "win32") == "slack"


def test_domain_rule_applies_to_subdomains_and_is_strictest(conn):
    add_rule(conn, "domain", "bank.example", r.DONT_TRACK)
    add_rule(conn, "domain", "health.example", r.METADATA_ONLY)
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide("/A.app", "www.bank.example") == r.DONT_TRACK
    assert book.decide("/A.app", "portal.health.example") == r.METADATA_ONLY
    assert book.decide("/A.app", "news.example") == r.TRACK
    # A metadata-only app can't be raised to full capture by anything.
    assert book.decide("/A.app", "news.example", base=r.METADATA_ONLY) == r.METADATA_ONLY
    assert book.decide("/A.app", "www.bank.example", base=r.METADATA_ONLY) == r.DONT_TRACK


def test_old_app_and_action_rows_are_ignored(conn):
    add_rule(conn, "app", "/A.app", r.DONT_TRACK)
    add_rule(conn, "action", "criteo.com", "block")
    add_rule(conn, "domain", "x.example", r.TRACK)
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.snapshot().domain_rules == {}
    assert book.decide("/A.app", "criteo.com") == r.TRACK


def test_rules_reload_without_restart(conn):
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide("/A.app", "bank.example") == r.TRACK
    add_rule(conn, "domain", "bank.example", r.DONT_TRACK)
    assert book.decide("/A.app", "bank.example") == r.DONT_TRACK


def test_pinning_falls_back_per_domain_then_per_app_for_this_audit_only(conn):
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.report_pinning_failure("/A.app", "one.example") is False
    assert book.decide("/A.app", "one.example") == r.METADATA_ONLY
    assert book.decide("/A.app", "two.example") == r.TRACK
    book.report_pinning_failure("/A.app", "two.example")
    assert book.report_pinning_failure("/A.app", "three.example") is True
    assert book.decide("/A.app", "anything.example") == r.METADATA_ONLY
    assert book.decide("/B.app", "anything.example") == r.TRACK
    # Nothing is written: the next audit starts fresh.
    assert conn.execute("SELECT count(*) FROM app_rules").fetchone()[0] == 0
    assert r.RuleBook(conn, reload_seconds=0).decide("/A.app", "anything.example") == r.TRACK

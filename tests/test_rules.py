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


def test_system_never_tracked_even_if_user_says_track():
    snap = r.RuleSnapshot(app_rules={"c:\\windows\\system32\\svchost.exe": r.TRACK})
    assert snap.decide("C:\\Windows\\System32\\svchost.exe", "svchost", "x.com") == r.DONT_TRACK


def test_blocklist_mode(conn):
    chrome = "C:\\Program Files\\Chrome\\chrome.exe"
    add_rule(conn, "app", r.normalize_app_path(chrome), r.DONT_TRACK)
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide(chrome, "chrome", "ads.example") == r.DONT_TRACK
    assert book.decide("C:\\Apps\\other.exe", "other", "ads.example") == r.TRACK


def test_allowlist_mode(conn):
    slack = "C:\\Apps\\slack.exe"
    db.set_setting(conn, "tracking_mode", "allowlist")
    add_rule(conn, "app", r.normalize_app_path(slack), r.TRACK)
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide(slack, "slack", "a.example") == r.TRACK
    assert book.decide("C:\\Apps\\other.exe", "other", "a.example") == r.DONT_TRACK


def test_domain_rule_applies_across_apps_and_subdomains(conn):
    add_rule(conn, "domain", "mybank.example", r.DONT_TRACK)
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide("C:\\a.exe", "a", "www.mybank.example") == r.DONT_TRACK
    assert book.decide("C:\\b.exe", "b", "mybank.example") == r.DONT_TRACK
    assert book.decide("C:\\b.exe", "b", "notmybank.example") == r.TRACK


def test_strictest_rule_wins(conn):
    add_rule(conn, "app", r.normalize_app_path("C:\\a.exe"), r.METADATA_ONLY)
    add_rule(conn, "domain", "x.example", r.TRACK)
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide("C:\\a.exe", "a", "x.example") == r.METADATA_ONLY


def test_unknown_process_is_metadata_only(conn):
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide(None, None, "x.example", process_known=False) == r.METADATA_ONLY


def test_rules_reload_without_restart(conn):
    book = r.RuleBook(conn, reload_seconds=0)
    assert book.decide("C:\\a.exe", "a", "x.example") == r.TRACK
    add_rule(conn, "app", r.normalize_app_path("C:\\a.exe"), r.DONT_TRACK)
    assert book.decide("C:\\a.exe", "a", "x.example") == r.DONT_TRACK


def test_pinning_falls_back_per_domain_then_per_app(conn):
    book = r.RuleBook(conn, reload_seconds=0)
    app = "C:\\bank\\bank.exe"
    assert not book.report_pinning_failure(app, "bank", "a.example")
    assert book.decide(app, "bank", "a.example") == r.METADATA_ONLY
    assert book.decide(app, "bank", "z.example") == r.TRACK
    book.report_pinning_failure(app, "bank", "b.example")
    assert book.report_pinning_failure(app, "bank", "c.example")
    assert book.decide(app, "bank", "z.example") == r.METADATA_ONLY
    row = conn.execute("SELECT rule, source FROM app_rules").fetchone()
    assert row == (r.METADATA_ONLY, "auto")


def test_pinning_never_overrides_user_rule(conn):
    app = "C:\\bank\\bank.exe"
    add_rule(conn, "app", r.normalize_app_path(app), r.TRACK)
    book = r.RuleBook(conn, reload_seconds=0)
    for d in ("a.example", "b.example", "c.example"):
        assert not book.report_pinning_failure(app, "bank", d)

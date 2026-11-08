"""Which audited apps are browsers."""

import plistlib

import pytest

from shared import audits, browsers, db


def bundle(tmp_path, name, ident, schemes, gecko=False, frameworks=()):
    app = tmp_path / f"{name}.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    info = {"CFBundleIdentifier": ident, "CFBundleURLTypes": [{"CFBundleURLSchemes": list(schemes)}]}
    (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
    if gecko:
        (app / "Contents" / "MacOS" / "XUL").write_bytes(b"")
    for fw in frameworks:
        (app / "Contents" / "Frameworks" / fw).mkdir(parents=True)
    return str(app)


def test_http_handlers_are_browsers_with_their_engine(tmp_path):
    zen = browsers.detect(bundle(tmp_path, "Zen", "app.zen-browser.zen", ["http", "https", "file"], gecko=True))
    assert zen == browsers.BrowserInfo(True, "gecko") and "security.enterprise_roots.enabled" in zen.hint
    odd = browsers.detect(bundle(tmp_path, "Odd", "x.odd", ["https"], frameworks=["Odd Framework.framework"]))
    assert odd == browsers.BrowserInfo(True, "chromium") and odd.hint is None


def test_electron_apps_are_not_browsers(tmp_path):
    for name, ident, scheme in [("Discord", "com.hnc.Discord", "discord"), ("Slack", "com.tinyspeck.slackmacgap", "slack"),
                                ("Code", "com.microsoft.VSCode", "vscode")]:
        assert browsers.detect(bundle(tmp_path, name, ident, [scheme],
                                      frameworks=["Electron Framework.framework"])).is_browser is False


def test_known_ids_and_exes_are_a_fallback(tmp_path):
    assert browsers.detect(bundle(tmp_path, "Brave", "com.brave.Browser", [])).engine == "chromium"
    assert browsers.detect("C:\\Program Files\\Mozilla Firefox\\firefox.exe") == browsers.BrowserInfo(True, "gecko")
    assert browsers.detect("/usr/bin/curl") == browsers.NOT_A_BROWSER
    assert browsers.detect(str(tmp_path / "Missing.app")) == browsers.NOT_A_BROWSER


def test_audit_remembers_which_apps_are_browsers(tmp_path, db_key):
    conn = db.open_db(tmp_path / "t.db", db_key)
    zen = bundle(tmp_path, "Zen", "app.zen-browser.zen", ["http", "https"], gecko=True)
    disc = bundle(tmp_path, "Discord", "com.hnc.Discord", ["discord"])
    a = audits.create(conn, {"apps": [{"path": zen, "name": "Zen"}, {"path": disc, "name": "Discord"}], "minutes": 5})
    again = audits.get(conn, a.id)
    assert [(x.name, x.is_browser, x.engine) for x in again.apps] == [("Zen", True, "gecko"), ("Discord", False, None)]
    assert [x["is_browser"] for x in again.public()["apps"]] == [True, False]

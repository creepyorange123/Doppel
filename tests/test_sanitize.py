import json

import pytest

from recorder import sanitize as s
from shared.keystore import keyed_hash

KEY = b"k" * 32


def hasher(v: str) -> str:
    return keyed_hash(v, KEY)


def req(url, headers=(), body=None, method="GET", response_headers=()):
    from urllib.parse import urlsplit

    p = urlsplit(url)
    path = p.path + ("?" + p.query if p.query else "")
    return s.RawRequest(method, url, p.hostname, path, list(headers), body, list(response_headers))


def blob(stored) -> str:
    """Everything that would be written to the database, as one string."""
    return json.dumps({
        "url": stored.url, "page_url": stored.page_url, "headers": stored.headers,
        "cookies": stored.cookies, "flags": stored.flags,
        "body": stored.body.decode("utf-8", "replace") if stored.body else None,
    })


# ---------------------------------------------------------------- search queries

@pytest.mark.parametrize("url", [
    "https://www.google.com/search?q=embarrassing+rash&hl=en",
    "https://www.bing.com/search?q=embarrassing+rash",
    "https://duckduckgo.com/?q=embarrassing+rash&t=h_",
    "https://search.yahoo.com/search?p=embarrassing+rash",
    "https://yandex.ru/search/?text=embarrassing+rash",
    "https://www.baidu.com/s?wd=embarrassing+rash",
    "https://www.google.co.uk/search?q=embarrassing+rash",
])
def test_search_engine_request_keeps_only_contact(url):
    out = s.sanitize_request(req(url, body=b'{"q":"embarrassing rash"}', method="POST"), hasher)
    assert out.search_engine
    assert "embarrassing" not in blob(out)
    assert out.body is None and out.headers is None


@pytest.mark.parametrize("url", [
    "https://www.google.com/complete/search?q=embarr&client=chrome",
    "https://duckduckgo.com/ac/?q=embarr",
    "https://www.bing.com/AS/Suggestions?qry=embarr",
])
def test_search_suggestions_are_dropped(url):
    assert s.sanitize_request(req(url), hasher) is None


# --------------------------------------------------------------- DNS over HTTPS

@pytest.mark.parametrize("url,headers,method", [
    ("https://chrome.cloudflare-dns.com/dns-query", [("Content-Type", "application/dns-message")], "POST"),
    ("https://dns.google/resolve?name=clinic.example&type=A", [], "GET"),
    ("https://dns.quad9.net/dns-query?dns=AAABAAABAAAAAAAA", [], "GET"),
    ("https://doh.example.net/custom", [("Accept", "application/dns-json")], "GET"),
])
def test_dns_over_https_lookups_are_dropped(url, headers, method):
    assert s.sanitize_request(req(url, headers=headers, body=b"\x00\x01", method=method), hasher) is None


def test_other_requests_to_dns_providers_are_kept():
    assert s.sanitize_request(req("https://www.cloudflare.com/learning/"), hasher) is not None
    assert not s.is_dns_over_https("cloudflare-dns.com", "/about")
    assert s.is_doh_host("mozilla.cloudflare-dns.com")


def test_search_term_in_referer_and_tracker_pixel_is_removed():
    page = "https://www.google.com/search?q=embarrassing+rash"
    pixel = "https://tracker.example/p?dl=" + page.replace(":", "%3A").replace("/", "%2F") + "&cid=abc"
    out = s.sanitize_request(req(pixel, headers=[("Referer", page)]), hasher)
    assert "embarrassing" not in blob(out)
    assert out.page_site == "www.google.com"


def test_site_search_param_removed_anywhere():
    out = s.sanitize_request(req("https://shop.example/find?query=pregnancy+test&page=2"), hasher)
    assert "pregnancy" not in blob(out)
    assert "page=2" in out.url


def test_search_terms_in_json_body_removed():
    body = json.dumps({"event": "view", "search_query": "divorce lawyer",
                       "page": "https://site.example/r?q=divorce+lawyer"}).encode()
    out = s.sanitize_request(req("https://t.example/collect", [("Content-Type", "application/json")], body, "POST"), hasher)
    assert "divorce" not in blob(out)


def test_host_matching_is_not_fooled():
    assert not s.is_search_engine("notgoogle.com")
    assert not s.is_search_engine("google")
    assert s.is_search_engine("www.google.de")


# ------------------------------------------------------------------ credentials

SESSION = "s3ss10n-SECRET-value-9f8e7d6c5b4a"


def test_cookie_values_never_stored():
    out = s.sanitize_request(req(
        "https://site.example/api",
        headers=[("Cookie", f"sid={SESSION}; theme=dark"), ("Authorization", "Bearer " + SESSION)],
        response_headers=[("Set-Cookie", f"sid={SESSION}; HttpOnly; Secure")],
    ), hasher)
    b = blob(out)
    assert SESSION not in b
    assert "dark" not in b
    assert out.cookies["sent"]["sid"] == hasher(SESSION)
    assert out.cookies["set"]["sid"] == hasher(SESSION)
    assert out.headers["authorization"] == "Bearer [removed]"
    assert "cookie" not in out.headers


def test_token_like_headers_are_hashed():
    out = s.sanitize_request(req("https://x.example/", headers=[("X-Api-Key", SESSION), ("X-CSRF-Token", SESSION)]), hasher)
    assert SESSION not in blob(out)


@pytest.mark.parametrize("ctype,body", [
    ("application/json", json.dumps({"user": "a@b.co", "password": "hunter2hunter2"}).encode()),
    ("application/x-www-form-urlencoded", b"user=a%40b.co&pwd=hunter2hunter2"),
    ("text/plain", b"user=a password=hunter2hunter2"),
])
def test_password_bodies_dropped(ctype, body):
    out = s.sanitize_request(req("https://x.example/api/v1/update", [("Content-Type", ctype)], body, "POST"), hasher)
    assert "hunter2" not in blob(out)
    assert out.body is None
    assert not any(f.get("hmac") == hasher("hunter2hunter2") for f in out.flags)


def test_login_path_bodies_dropped():
    out = s.sanitize_request(req("https://x.example/oauth/token", [("Content-Type", "application/json")], b'{"code":"abc"}', "POST"), hasher)
    assert out.body is None
    assert any(f["flag"] == "login_body_removed" for f in out.flags)


# ------------------------------------------------------------------------ flags

def test_flags_capture_ids_fingerprint_and_page():
    body = json.dumps({"uid": "a8F3kLq92xZpQ7mN4vB1", "sr": "1920x1080", "fonts": ["Arial"],
                       "mousemove": [[1, 2]], "em": "5d41402abc4b2a76b9719d911017c592",
                       "dl": "https://news.example/article"}).encode()
    out = s.sanitize_request(req("https://ads.example/c", [("Content-Type", "application/json")], body, "POST"), hasher)
    names = {f["flag"] for f in out.flags}
    assert {"long_id", "fingerprinting", "behavioural_events", "hashed_identifier", "page_url"} <= names
    id_flag = next(f for f in out.flags if f["flag"] == "long_id")
    assert id_flag["hmac"] == hasher("a8F3kLq92xZpQ7mN4vB1")


def test_raw_email_flagged_by_hash():
    out = s.sanitize_request(req("https://ads.example/c?e=someone%40mail.example"), hasher)
    f = next(f for f in out.flags if f["flag"] == "email_address")
    assert f["hmac"] == hasher("someone@mail.example")


def test_timestamps_are_not_ids():
    assert not s.looks_like_id("1730000000000")
    assert not s.looks_like_id("aaaaaaaaaaaaaaaaaaaa")
    assert s.looks_like_id("GA1.2.1234567890.1730000000")


def test_body_truncated_at_64kb():
    body = b"x" * (s.MAX_BODY_BYTES + 10)
    out = s.sanitize_request(req("https://x.example/upload", [("Content-Type", "text/plain")], body, "POST"), hasher)
    assert len(out.body) <= s.MAX_BODY_BYTES and out.body_truncated


def test_binary_bodies_not_stored():
    out = s.sanitize_request(req("https://x.example/b", [("Content-Type", "application/x-protobuf")], b"\x00\x01", "POST"), hasher)
    assert out.body is None

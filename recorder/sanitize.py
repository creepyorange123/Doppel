"""Turn a raw request into what is allowed to be stored.

Everything here is pure (no I/O) so it can be tested exhaustively. The rules:

- Never store Cookie, Set-Cookie, Authorization (or other credential-like)
  header values. Cookies are stored as ``{name: HMAC(value)}``.
- Never store password fields or login bodies.
- Never store search queries: search parameters are removed from every URL we
  keep (request URL, Referer, Origin, page URL, and URLs embedded in query
  strings and bodies). Requests to search engines keep only the fact that the
  engine was contacted; search-suggestion requests are dropped entirely.
- Bodies are cut off at 64 KB.
- Capture-time flags (long IDs, page URLs, fingerprinting values, behavioural
  events, hashed identifiers) are extracted now and store HMACs, not values.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_BODY_BYTES = 64 * 1024

Hasher = Callable[[str], str]

# --------------------------------------------------------------------------- search

SEARCH_ENGINE_DOMAINS = (
    "google.", "bing.com", "duckduckgo.com", "search.yahoo.com", "yahoo.co.jp",
    "yandex.", "baidu.com", "ecosia.org", "search.brave.com", "startpage.com",
    "kagi.com", "ask.com", "naver.com", "qwant.com", "you.com", "perplexity.ai",
    "sogou.com", "seznam.cz", "mojeek.com",
)

# Removed from URLs on search engines (the plan's q, query, p, text, plus the
# parameter names other engines use).
SEARCH_ENGINE_PARAMS = frozenset({
    "q", "query", "p", "text", "wd", "word", "kw", "oq", "aq", "pq", "qs",
    "search", "searchterm", "search_query", "term", "prefix", "eq",
})

# Removed from every URL anywhere (site searches, tracker pixels that copy the
# page URL, ...). Search queries are never stored.
GLOBAL_SEARCH_PARAMS = frozenset({
    "q", "query", "search", "search_query", "searchterm", "search_term",
    "keyword", "keywords", "searchtext", "search_text", "_nkw", "field-keywords",
})

SUGGEST_PATH_RE = re.compile(
    r"(complete/search|/suggest|/autosuggest|/autocomplete|/ac/|/sugrec|/qbox|"
    r"/AS/Suggestions|/osjson|/typeahead)",
    re.IGNORECASE,
)


def host_matches(host: str, patterns: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    for pat in patterns:
        if pat.endswith("."):  # "google." matches google.com, www.google.co.uk
            label = pat[:-1]
            parts = host.split(".")
            if label in parts[:-1]:
                return True
        elif host == pat or host.endswith("." + pat):
            return True
    return False


def is_search_engine(host: str) -> bool:
    return host_matches(host, SEARCH_ENGINE_DOMAINS)


def is_search_suggestion(host: str, path_and_query: str) -> bool:
    return is_search_engine(host) and bool(SUGGEST_PATH_RE.search(path_and_query))


URL_IN_TEXT_RE = re.compile(r"https?(?::|%3A)(?://|%2F%2F)[^\s\"'<>\\]+", re.IGNORECASE)


def sanitize_url(url: str | None, *, depth: int = 0) -> str | None:
    """Remove search parameters (and the fragment) from a URL.

    URLs embedded as parameter values are sanitized too, so a tracker pixel
    that copies the page URL never carries a search term into the log.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    drop = SEARCH_ENGINE_PARAMS | GLOBAL_SEARCH_PARAMS if is_search_engine(host) else GLOBAL_SEARCH_PARAMS
    kept = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in drop:
            continue
        if depth < 3 and URL_IN_TEXT_RE.match(value):
            value = sanitize_url(value, depth=depth + 1) or ""
        kept.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), ""))


def scrub_urls_in_text(text: str) -> str:
    """Sanitize every URL that appears inside free text (bodies)."""
    from urllib.parse import unquote

    def repl(m: re.Match) -> str:
        raw = m.group(0)
        decoded = unquote(raw) if "%3A" in raw[:12].upper() else raw
        return sanitize_url(decoded) or ""

    return URL_IN_TEXT_RE.sub(repl, text)


def page_site(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except ValueError:
        return None


# ------------------------------------------------------------------- credentials

CREDENTIAL_HEADERS = frozenset({
    "cookie", "set-cookie", "authorization", "proxy-authorization",
})
SENSITIVE_HEADER_RE = re.compile(r"auth|token|secret|session|passw|api-?key|csrf|xsrf|signature|credential", re.I)
PASSWORD_FIELD_RE = re.compile(r"^(pass(word|wd|code|phrase)?|pwd|pin|otp|secret|cvv|cvc|card_?number|ssn|new_?password|current_?password)$", re.I)
LOGIN_PATH_RE = re.compile(r"(login|log-in|signin|sign-in|signup|sign-up|register|oauth|/token|/auth|session|password|passwd|2fa|mfa|otp)", re.I)


def parse_cookie_header(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def parse_set_cookie(value: str) -> tuple[str, str] | None:
    first = value.split(";", 1)[0]
    if "=" not in first:
        return None
    k, v = first.split("=", 1)
    return (k.strip(), v.strip()) if k.strip() else None


def sanitize_headers(headers: list[tuple[str, str]], hasher: Hasher) -> dict[str, str]:
    """Keep header names; replace credential values with a keyed hash or drop them."""
    out: dict[str, str] = {}
    for name, value in headers:
        lname = name.lower()
        if lname in ("cookie", "set-cookie"):
            continue  # stored separately as {name: hmac}
        if lname in ("authorization", "proxy-authorization"):
            scheme = value.split(" ", 1)[0] if " " in value else ""
            out[lname] = f"{scheme} [removed]".strip()
            continue
        if SENSITIVE_HEADER_RE.search(lname):
            out[lname] = "hmac:" + hasher(value)
            continue
        if lname in ("referer", "origin"):
            out[lname] = sanitize_url(value) or ""
            continue
        out[lname] = value[:2048]
    return out


# ------------------------------------------------------------------------- flags

FINGERPRINT_KEYS = re.compile(
    r"^(sr|vp|sd|screen|screen_?(res|resolution|width|height)|resolution|viewport|"
    r"fonts?|canvas|canvas_?hash|webgl|webgl_?(vendor|renderer)|audio(_?fp)?|plugins|"
    r"timezone|tz|tzo|hardware_?concurrency|device_?memory|color_?depth|cd|pixel_?ratio|dpr|"
    r"touch_?points|platform|ua_?(full|platform|model)|fp|fingerprint|visitor_?fp)$",
    re.I,
)
BEHAVIOUR_KEYS = re.compile(
    r"(mouse|mousemove|keystroke|keydown|keyup|keypress|click(s|map)?|scroll|"
    r"touch(start|move|end)|session_?replay|recording|rrweb|heatmap)",
    re.I,
)
PAGE_URL_KEYS = re.compile(r"^(dl|url|u|ref|referrer|referer|page|page_?url|location|href|loc|dr|current_?url)$", re.I)
HEX_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
ID_CHARS_RE = re.compile(r"^[A-Za-z0-9._\-|:=]{16,256}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_like_id(value: str) -> bool:
    if not ID_CHARS_RE.match(value):
        return False
    if value.isdigit() and len(value) < 19:  # timestamps, counters
        return False
    return shannon_entropy(value) >= 3.0 and sum(ch.isdigit() for ch in value) >= 2


@dataclass
class FlagSet:
    hasher: Hasher
    flags: list[dict[str, str]] = field(default_factory=list)
    _seen: set[tuple[str, str, str]] = field(default_factory=set)

    def add(self, flag: str, where: str, value: str | None = None) -> None:
        h = self.hasher(value) if value is not None else ""
        key = (flag, where, h)
        if key in self._seen:
            return
        self._seen.add(key)
        entry = {"flag": flag, "where": where}
        if h:
            entry["hmac"] = h
        self.flags.append(entry)

    def inspect(self, where: str, key: str, value: Any) -> None:
        if key and BEHAVIOUR_KEYS.search(key):
            self.add("behavioural_events", where)
        if key and FINGERPRINT_KEYS.match(key):
            self.add("fingerprinting", where)
        if isinstance(value, (dict, list)):
            for k, v in (value.items() if isinstance(value, dict) else enumerate(value)):
                self.inspect(f"{where}.{k}", str(k), v)
            return
        if value is None:
            return
        sval = str(value)
        if PAGE_URL_KEYS.match(key) and URL_IN_TEXT_RE.match(sval):
            self.add("page_url", where)
        if EMAIL_RE.match(sval):
            # A raw email address leaving the device. Store only its HMAC.
            self.add("email_address", where, sval.strip().lower())
        elif HEX_HASH_RE.match(sval):
            self.add("hashed_identifier", where, sval.lower())
        elif looks_like_id(sval):
            self.add("long_id", where, sval)


# ------------------------------------------------------------------------ bodies

def _strip_passwords(obj: Any) -> tuple[Any, bool]:
    removed = False
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if PASSWORD_FIELD_RE.match(str(k)):
                removed = True
                continue
            out[k], r = _strip_passwords(v)
            removed |= r
        return out, removed
    if isinstance(obj, list):
        items = [_strip_passwords(v) for v in obj]
        return [i for i, _ in items], any(r for _, r in items)
    if isinstance(obj, str):
        return scrub_urls_in_text(obj) if "http" in obj.lower() else obj, False
    return obj, False


def _drop_search_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _drop_search_keys(v) for k, v in obj.items() if str(k).lower() not in GLOBAL_SEARCH_PARAMS}
    if isinstance(obj, list):
        return [_drop_search_keys(v) for v in obj]
    return obj


@dataclass
class SanitizedBody:
    body: bytes | None
    truncated: bool
    notes: list[str]


def sanitize_body(raw: bytes | None, content_type: str, path: str, flags: FlagSet) -> SanitizedBody:
    """Return the body that may be stored (or None), after flag extraction."""
    if not raw:
        return SanitizedBody(None, False, [])
    ctype = (content_type or "").lower()
    notes: list[str] = []
    truncated = len(raw) > MAX_BODY_BYTES

    if LOGIN_PATH_RE.search(path):
        return SanitizedBody(None, False, ["login_body_removed"])

    if "json" in ctype or raw[:1] in (b"{", b"["):
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            data = None
        if data is not None:
            data, removed = _strip_passwords(_drop_search_keys(data))
            if removed:
                # Don't inspect it either: not even a keyed hash of a password is kept.
                return SanitizedBody(None, False, ["login_body_removed"])
            flags.inspect("body", "", data)
            out = json.dumps(data, separators=(",", ":")).encode("utf-8")
            return SanitizedBody(out[:MAX_BODY_BYTES], truncated or len(out) > MAX_BODY_BYTES, notes)

    if "x-www-form-urlencoded" in ctype:
        try:
            pairs = parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            pairs = []
        if any(PASSWORD_FIELD_RE.match(k) for k, _ in pairs):
            return SanitizedBody(None, False, ["login_body_removed"])
        kept = []
        for k, v in pairs:
            if k.lower() in GLOBAL_SEARCH_PARAMS:
                continue
            flags.inspect(f"body.{k}", k, v)
            kept.append((k, scrub_urls_in_text(v)))
        out = urlencode(kept).encode("utf-8")
        return SanitizedBody(out[:MAX_BODY_BYTES], truncated or len(out) > MAX_BODY_BYTES, notes)

    if ctype.startswith("text/") or "xml" in ctype or "javascript" in ctype:
        try:
            text = raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
        except Exception:
            return SanitizedBody(None, truncated, ["body_undecodable"])
        if re.search(r"(?i)\b(password|passwd|pwd)\b\s*[=:]", text):
            return SanitizedBody(None, False, ["login_body_removed"])
        return SanitizedBody(scrub_urls_in_text(text).encode("utf-8"), truncated, notes)

    if "multipart/form-data" in ctype:
        # File uploads and forms; never kept.
        return SanitizedBody(None, truncated, ["multipart_body_removed"])

    # Opaque binary (protobuf, images, ...): keep only its size.
    return SanitizedBody(None, truncated, ["binary_body_not_stored"])


# ---------------------------------------------------------------------- requests

@dataclass
class RawRequest:
    method: str
    url: str
    host: str
    path: str  # path + query
    headers: list[tuple[str, str]]
    body: bytes | None
    response_headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class StoredRequest:
    """Columns for the ``requests`` table (minus app/time/status/size)."""

    dest_domain: str
    method: str | None
    url: str | None
    page_site: str | None
    page_url: str | None
    headers: dict[str, str] | None
    cookies: dict[str, dict[str, str]] | None
    body: bytes | None
    body_truncated: bool
    flags: list[dict[str, str]]
    search_engine: bool = False


def sanitize_request(raw: RawRequest, hasher: Hasher) -> StoredRequest | None:
    """Apply every storage rule. Returns None when the request must not be stored at all."""
    host = raw.host.lower().rstrip(".")
    if is_search_suggestion(host, raw.path):
        return None

    header_map = {k.lower(): v for k, v in raw.headers}
    referer = header_map.get("referer") or header_map.get("origin")
    page_url = sanitize_url(referer) if referer else None

    if is_search_engine(host):
        # Keep only that a search engine was contacted.
        parts = urlsplit(raw.url)
        return StoredRequest(
            dest_domain=host, method=raw.method,
            url=urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")),
            page_site=page_site(referer), page_url=None,
            headers=None, cookies=None, body=None, body_truncated=False,
            flags=[{"flag": "search_engine_contacted", "where": "dest"}], search_engine=True,
        )

    flags = FlagSet(hasher)
    url = sanitize_url(raw.url)
    for k, v in parse_qsl(urlsplit(url or "").query, keep_blank_values=True):
        flags.inspect(f"query.{k}", k, v)

    sent = {}
    if "cookie" in header_map:
        for name, value in parse_cookie_header(header_map["cookie"]).items():
            sent[name] = hasher(value)
            if looks_like_id(value) or HEX_HASH_RE.match(value):
                flags.add("long_id", f"cookie.{name}", value)
    set_ = {}
    for name, value in raw.response_headers:
        if name.lower() == "set-cookie":
            parsed = parse_set_cookie(value)
            if parsed:
                set_[parsed[0]] = hasher(parsed[1])
                if looks_like_id(parsed[1]):
                    flags.add("long_id", f"set_cookie.{parsed[0]}", parsed[1])
    cookies = {"sent": sent, "set": set_} if (sent or set_) else None

    if page_url and page_site(page_url) and page_site(page_url) != host:
        flags.add("page_url", "header.referer")

    body = sanitize_body(raw.body, header_map.get("content-type", ""), raw.path, flags)
    for note in body.notes:
        flags.add(note, "body")

    return StoredRequest(
        dest_domain=host, method=raw.method, url=url,
        page_site=page_site(page_url), page_url=page_url,
        headers=sanitize_headers(raw.headers, hasher), cookies=cookies,
        body=body.body, body_truncated=body.truncated, flags=flags.flags,
    )

"""Live proof of the privacy promises, for the app's Privacy screen.

Each check tests the real data on this computer rather than restating a claim,
and each one can fail. Results contain only counts and fixed wording, never
captured content (no URLs, header values or bodies).

ok: True = verified, False = a problem was found, None = not applicable right now.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import parse_qsl, urlsplit

from analyzer import topics
from analyzer.research import egress, ledger
from analyzer.research.research import QUERY_TEMPLATES, known_companies as _known_companies
from recorder import sanitize
from shared import audits, db, keystore

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SQLITE_HEADER = b"SQLite format 3\x00"
RAW_COLUMNS = ("body", "headers", "cookies", "url", "page_url")
SCAN_LIMIT = 20_000  # most recent unanalysed rows scanned for stored content
KEY_SCAN_MAX_BYTES = 50_000_000

# The only fields research sends besides the query, with their fixed values.
FIXED_FIELDS = {
    "api.tavily.com": {"max_results": 5, "search_depth": "basic"},
    "api.exa.ai": {"numResults": 5, "contents": {"text": {"maxCharacters": 1500}}},
}

Listeners = Callable[[set], list]


def _check(id_: str, title: str, ok: bool | None, detail: str) -> dict:
    return {"id": id_, "title": title, "ok": ok, "detail": detail}


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n:,} {word if n == 1 else (many or word + 's')}"


# ------------------------------------------------------------------ storage

def check_encrypted(db_file: Path) -> dict:
    title = "Your log is encrypted"
    try:
        with open(db_file, "rb") as f:
            head = f.read(16)
    except OSError:
        return _check("encrypted", title, None, "No log file yet.")
    if head == SQLITE_HEADER:
        return _check("encrypted", title, False, "The log file is a plain, unencrypted database.")
    try:
        plain = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        try:
            plain.execute("SELECT count(*) FROM sqlite_master").fetchone()
            readable = True
        finally:
            plain.close()
    except sqlite3.DatabaseError:
        readable = False
    if readable:
        return _check("encrypted", title, False, "The log file opened without the key.")
    return _check("encrypted", title, True,
                  "Opened the log file without the key just now: it is unreadable random-looking data.")


def check_key_not_on_disk(data_dir: Path, db_key: bytes, db_file: Path) -> dict:
    title = "The key is only in Credential Manager"
    skip = {db_file.name, db_file.name + "-wal", db_file.name + "-shm"}
    needles = (db_key.hex().encode(), db_key.hex().upper().encode(), db_key)
    scanned = 0
    for p in data_dir.rglob("*"):
        try:
            if not p.is_file() or p.name in skip or p.stat().st_size > KEY_SCAN_MAX_BYTES:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        scanned += 1
        if any(n in data for n in needles):
            return _check("key_not_on_disk", title, False, "The database key was found in a file in the data folder.")
    store = "the macOS Keychain" if sys.platform == "darwin" else "Windows Credential Manager"
    return _check("key_not_on_disk", title, True,
                  f"Searched {_plural(scanned, 'file')} in the data folder: no copy of the key. It is kept in {store}.")


def _unanalysed(conn, cols: str) -> Iterable[tuple]:
    return conn.execute(f"SELECT {cols} FROM requests WHERE analyzed = 0 ORDER BY id DESC LIMIT ?", (SCAN_LIMIT,))


def _json(text) -> object:
    try:
        return json.loads(text) if text else None
    except (TypeError, ValueError):
        return None


def check_ids_hashed(conn) -> dict:
    title = "Identifiers are stored only as keyed hashes"
    bad_sightings, sightings = conn.execute(
        "SELECT coalesce(sum(length(hmac) != 64 OR hmac GLOB '*[^0-9a-f]*'), 0), count(*) FROM id_sightings"
    ).fetchone()
    bad_cookies = cookies = 0
    for (raw,) in _unanalysed(conn, "cookies"):
        parsed = _json(raw)
        if not isinstance(parsed, dict):
            continue
        for group in parsed.values():
            for value in (group or {}).values() if isinstance(group, dict) else ():
                cookies += 1
                if not (isinstance(value, str) and HEX64.match(value)):
                    bad_cookies += 1
    if bad_sightings or bad_cookies:
        return _check("ids_hashed", title, False,
                      f"Found {_plural(bad_sightings + bad_cookies, 'identifier')} stored as a raw value.")
    return _check("ids_hashed", title, True,
                  f"Checked {_plural(sightings, 'tracking ID')} and {_plural(cookies, 'cookie')}: all are keyed hashes.")


def _keys(obj) -> Iterable[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _keys(v)


def _body_keys(body: bytes | None) -> list[str]:
    if not body:
        return []
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
    parsed = _json(text)
    if parsed is not None:
        return list(_keys(parsed))
    if "=" in text:
        return [k for k, _ in parse_qsl(text, keep_blank_values=True)]
    return []


def _header_problem(name: str, value: object) -> bool:
    name = name.lower()
    if name in ("cookie", "set-cookie"):
        return True
    value = value if isinstance(value, str) else ""
    if name in ("authorization", "proxy-authorization"):
        return not value.endswith("[removed]")
    if sanitize.SENSITIVE_HEADER_RE.search(name):
        return not value.startswith("hmac:")
    return False


def check_no_credentials(conn) -> dict:
    title = "No cookies or passwords are stored"
    rows = bad = 0
    for headers, body in _unanalysed(conn, "headers, body"):
        rows += 1
        h = _json(headers)
        if isinstance(h, dict) and any(_header_problem(k, v) for k, v in h.items()):
            bad += 1
            continue
        if any(sanitize.PASSWORD_FIELD_RE.match(k) for k in _body_keys(body)):
            bad += 1
    if bad:
        return _check("no_credentials", title, False, f"Found credentials in {_plural(bad, 'stored request')}.")
    return _check("no_credentials", title, True,
                  f"Checked {_plural(rows, 'stored request')}: no cookie, login or password values.")


def _is_search(url: str | None) -> bool:
    if not url:
        return False
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    host = (p.hostname or "").lower()
    keys = {k.lower() for k, _ in parse_qsl(p.query, keep_blank_values=True)}
    if sanitize.is_search_suggestion(host, p.path + ("?" + p.query if p.query else "")):
        return True
    if keys & sanitize.GLOBAL_SEARCH_PARAMS:
        return True
    return sanitize.is_search_engine(host) and bool(keys & sanitize.SEARCH_ENGINE_PARAMS)


def check_no_search_queries(conn) -> dict:
    title = "No search queries are stored"
    rows = bad = 0
    for url, page_url in _unanalysed(conn, "url, page_url"):
        rows += 1
        if _is_search(url) or _is_search(page_url):
            bad += 1
    if bad:
        return _check("no_search_queries", title, False, f"Found search terms in {_plural(bad, 'stored request')}.")
    return _check("no_search_queries", title, True,
                  f"Checked {_plural(rows, 'stored address', 'stored addresses')}: no search terms or search suggestions.")


def check_raw_deleted(conn) -> dict:
    title = "Raw content is deleted after analysis"
    left = " OR ".join(f"{c} IS NOT NULL" for c in RAW_COLUMNS)
    analysed, with_raw = conn.execute(
        f"SELECT count(*), coalesce(sum({left}), 0) FROM requests WHERE analyzed = 1").fetchone()
    if with_raw:
        return _check("raw_deleted", title, False,
                      f"{_plural(with_raw, 'analysed request')} still hold raw content.")
    return _check("raw_deleted", title, True,
                  f"{_plural(analysed, 'analysed request')}: none still holds a body, headers, cookies or address.")


# ------------------------------------------------------------------ audits

AUDIT_SLACK_MS = 10_000  # writes land a moment after the request; allow for it


def check_only_during_audits(conn) -> dict:
    title = "Nothing is recorded outside an audit"
    n_audits = conn.execute("SELECT count(*) FROM audits").fetchone()[0]
    total, outside = conn.execute(
        "SELECT count(*), coalesce(sum(a.id IS NULL OR r.captured_at < a.started_at - ? "
        "OR r.captured_at > coalesce(a.ended_at, a.ends_at) + ?), 0) "
        "FROM requests r LEFT JOIN audits a ON a.id = r.audit_id", (AUDIT_SLACK_MS, AUDIT_SLACK_MS)).fetchone()
    if outside:
        return _check("only_during_audits", title, False,
                      f"{_plural(outside, 'stored request')} fall outside the audit they belong to.")
    if total == 0:
        return _check("only_during_audits", title, True,
                      f"{_plural(n_audits, 'audit')} so far and no stored requests.")
    return _check("only_during_audits", title, True,
                  f"Checked {_plural(total, 'stored request')} across {_plural(n_audits, 'audit')}: "
                  "each was recorded during the audit it belongs to, for an app you chose.")


def check_no_background(conn, *, legacy_login_item: bool, recorder_running: bool) -> dict:
    title = "Nothing runs in the background"
    active = audits.running(conn)
    if legacy_login_item:
        return _check("no_background", title, False,
                      "The old always-on recorder's login item is still installed. Remove the certificate "
                      "in Settings and install it again to clear it.")
    if recorder_running and active is None:
        return _check("no_background", title, False, "A recorder process is running with no audit in progress.")
    if active is not None:
        return _check("no_background", title, True,
                      f"An audit is running ({active.label}); its recorder stops on its own when the audit ends. "
                      "No login item is installed.")
    return _check("no_background", title, True,
                  "No audit is running and no recorder process exists. No login item is installed.")


# ------------------------------------------------------------------ network

def parse_netstat(text: str, pids: set) -> list[str]:
    """Listening sockets owned by `pids` in `netstat -ano` output (Windows)."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[-1].isdigit() or int(parts[-1]) not in pids:
            continue
        proto = parts[0].upper()
        if proto.startswith("TCP") and len(parts) >= 5 and parts[3] == "LISTENING":
            out.append(f"TCP {parts[1]}")
        elif proto.startswith("UDP") and parts[2] == "*:*":
            out.append(f"UDP {parts[1]}")
    return out


def system_listeners(pids: set) -> list[str] | None:
    try:
        if sys.platform == "win32":
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=20,
                                 creationflags=0x08000000)  # no console window
            return parse_netstat(res.stdout, pids)
        if sys.platform == "darwin":
            out = []
            for pid in pids:
                res = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", "-sTCP:LISTEN"],
                                     capture_output=True, text=True, timeout=20)
                out += [f"TCP {line.split()[8]}" for line in res.stdout.splitlines()[1:] if len(line.split()) > 8]
            return out
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def our_pids(data_dir: Path) -> set[int]:
    pids = {os.getpid(), os.getppid()}  # analyzer, and the app that started it
    try:
        pids.add(int((data_dir / "recorder.pid").read_text().strip()))
    except (OSError, ValueError):
        pass
    return pids


def check_no_listeners(pids: set, listeners: Listeners) -> dict:
    title = "Nothing listens on a network port"
    found = listeners(pids)
    if found is None:
        return _check("no_listeners", title, None, "Couldn't list open ports on this system.")
    if found:
        return _check("no_listeners", title, False, f"Found {_plural(len(found), 'listening port')}: {', '.join(found)}.")
    return _check("no_listeners", title, True,
                  "Listed the open ports of the app, the analyzer and any running audit just now: none is listening.")


def _default_ollama_host() -> str:
    return inspect.signature(topics.ollama_model).parameters["host"].default


def check_local_ai(conn, ollama_host: str) -> dict:
    title = "The local AI stays on this computer"
    host = (urlsplit(ollama_host).hostname or "").lower()
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if not local:
        return _check("local_ai_local", title, False, "The AI model address is not on this computer.")
    on = db.get_setting(conn, "local_ai", "0") == "1"
    state = "On" if on else "Off (keyword rules are used)"
    return _check("local_ai_local", title, True,
                  f"{state}. The model is only ever called at {host}, which can't be reached from other computers; "
                  "its answers are checked against a fixed list before use.")


def check_only_company_names(conn, known: set[str]) -> dict:
    title = "Only company names have left this device"
    v = ledger.verify(conn)
    if not v["ok"]:
        return _check("only_company_names", title, False,
                      f"The list of outgoing calls was edited (entry {v['broken_at']}).")
    allowed = {t.format(c=c) for c in known for t in QUERY_TEMPLATES}
    companies: set[str] = set()
    n = bad = 0
    for dest, payload in conn.execute("SELECT destination, payload FROM ledger"):
        n += 1
        body = _json(payload)
        fixed = FIXED_FIELDS.get(dest)
        if (fixed is None or not isinstance(body, dict) or body.get("query") not in allowed
                or any(k != "query" and fixed.get(k) != val for k, val in body.items())):
            bad += 1
            continue
        companies |= {c for c in known if any(body["query"] == t.format(c=c) for t in QUERY_TEMPLATES)}
    if bad:
        return _check("only_company_names", title, False,
                      f"{_plural(bad, 'outgoing call')} sent something other than a company-name search.")
    if n == 0:
        return _check("only_company_names", title, True, "Nothing has been sent. The list of outgoing calls is empty.")
    return _check("only_company_names", title, True,
                  f"{_plural(n, 'outgoing call')}, each a search for one of {_plural(len(companies), 'company', 'companies')}; "
                  "the tamper-evident list is intact.")


class _NoSend(RuntimeError):
    pass


def _refuse_to_send(url, body, headers):
    raise _NoSend("a privacy check must never send anything")


def check_gate_allowlist(conn) -> dict:
    title = "Every other destination is blocked"

    class Probe(egress.Gate):
        def zero_network(self) -> bool:  # test the allowlist on its own
            return False

    gate = Probe(conn, sender=_refuse_to_send)
    tries = ("https://example.com/", "http://api.tavily.com/search", "https://api.tavily.com:8443/search",
             "https://user@api.exa.ai/search")
    let_through = 0
    for url in tries:
        try:
            gate.check(url)
            let_through += 1
        except egress.Blocked:
            pass
    if let_through:
        return _check("gate_allowlist", title, False, "The outgoing gate let a disallowed address through.")
    hosts = " and ".join(sorted(egress.ALLOWED_HOSTS))
    return _check("gate_allowlist", title, True,
                  f"Tried {_plural(len(tries), 'disallowed address', 'disallowed addresses')} at the outgoing gate just now: all blocked. "
                  f"Only {hosts} over HTTPS are allowed.")


def check_zero_network(conn) -> dict:
    title = "Zero-network mode blocks everything"
    if db.get_setting(conn, "zero_network", "0") != "1":
        return _check("zero_network", title, None,
                      "Off. Research sends company names to Tavily or Exa only when you run it.")
    before = conn.execute("SELECT count(*) FROM ledger").fetchone()[0]
    try:
        egress.Gate(conn, sender=_refuse_to_send).post("https://api.tavily.com/search", {"query": "test"}, {})
        blocked = False
    except egress.Blocked:
        blocked = True
    except _NoSend:
        blocked = False
    after = conn.execute("SELECT count(*) FROM ledger").fetchone()[0]
    if not blocked or after != before:
        return _check("zero_network", title, False, "A test request got past zero-network mode.")
    return _check("zero_network", title, True, "On. A test request to Tavily was refused before anything was sent.")


# ------------------------------------------------------------------ entry points

def run_checks(conn, *, db_file: Path, data_dir: Path, db_key: bytes, pids: set,
               listeners: Listeners = system_listeners, known_companies: set[str] | None = None,
               ollama_host: str | None = None, legacy_login_item: bool = False,
               recorder_running: bool = False) -> dict:
    known = known_companies if known_companies is not None else _known_companies()
    audits.settle(conn)
    checks = [
        check_only_during_audits(conn),
        check_no_background(conn, legacy_login_item=legacy_login_item, recorder_running=recorder_running),
        check_encrypted(Path(db_file)),
        check_key_not_on_disk(Path(data_dir), db_key, Path(db_file)),
        check_ids_hashed(conn),
        check_no_credentials(conn),
        check_no_search_queries(conn),
        check_raw_deleted(conn),
        check_no_listeners(pids, listeners),
        check_local_ai(conn, ollama_host or _default_ollama_host()),
        check_only_company_names(conn, known),
        check_gate_allowlist(conn),
        check_zero_network(conn),
    ]
    return {
        "checks": checks,
        "ran_at": db.now_ms(),
        "passed": sum(c["ok"] is True for c in checks),
        "failed": sum(c["ok"] is False for c in checks),
    }


def handle(conn, payload) -> dict:
    from recorder import service

    return run_checks(conn, db_file=db.db_path(), data_dir=db.data_dir(), db_key=keystore.db_key(),
                      pids=our_pids(db.data_dir()), legacy_login_item=service.legacy_login_item_exists(),
                      recorder_running=service.is_running())

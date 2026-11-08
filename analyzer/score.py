"""Phase 4: score each request 0-100 with plain, explainable rules (no AI).

Tiers and signal weights come from the original project plan ("Concern scoring").
They are starting weights to tune against hand-labelled requests, not standards.

score = max(0, sum(points)); x1.5 if the page topic or the app is sensitive; cap 100.

Every score is saved with its breakdown, so each badge can explain itself.
Cross-site IDs and cookie syncing compare keyed hashes against *all* stored
history (``id_sightings``), not only the new batch.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from analyzer import datatypes, topics
from analyzer.identify import registrable_domain
from shared import db

# Original plan, "Tiers".
TIERS = ((80, "High concern"), (50, "Profile building"), (20, "Measurement"), (0, "Minimum utility"))
TIER_NAMES = tuple(name for _, name in reversed(TIERS))

# Original plan, "Signals".
POINTS = {
    "third_party": 10,
    "advertising": 20,
    "session_replay": 25,
    "cross_site_id": 25,
    "page_url": 10,
    "fingerprinting": 20,
    "personal_identifier": 30,
    "cookie_syncing": 30,
    "data_broker": 15,
    # Added with payload data types (analyzer/datatypes.py); not in the original table.
    "sensitive_data": 30,   # health, finance, sexuality, religion, children, politics, ethnicity
    "personal_data": 20,    # name, birth date, address, gender, ID numbers, precise location
    "page_works_without_it": 10,
    "page_breaks_without_it": -20,
}
AD_CATEGORIES = frozenset({"Advertising", "Ad Motivated Tracking"})
PERSONAL_FLAGS = frozenset({"hashed_email", "hashed_phone", "raw_email"})
IDENTIFIER_FLAGS = frozenset({"tracking_id"}) | PERSONAL_FLAGS
SENSITIVE_MULTIPLIER = 1.5
SPECIAL_DATA = {f"data_{c}": c for c in datatypes.SPECIAL}
PERSONAL_DATA = {"data_personal": "personal details", "data_location": "precise location"}


def tier_for(value: int) -> str:
    for floor, name in TIERS:
        if value >= floor:
            return name
    return "Minimum utility"


def migrate_legacy_tiers(conn) -> int:
    """Rows scored before the tiers were renamed (Low, Moderate, Profile-building) get
    the current tier name for their saved score. Safe to run on every start."""
    names = ", ".join("?" * len(TIER_NAMES))
    rows = conn.execute(f"SELECT request_id, score FROM scores WHERE tier NOT IN ({names})", TIER_NAMES).fetchall()
    if rows:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany("UPDATE scores SET tier = ? WHERE request_id = ?",
                             [(tier_for(s), rid) for rid, s in rows])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return len(rows)


@dataclass
class Input:
    company: str | None
    category: str | None
    flags: list[dict]
    topic: str | None
    metadata_only: bool
    app_name: str | None
    page_site: str | None
    dest_domain: str | None = None
    is_data_broker: bool | None = None
    breakage: str | None = None  # "works" | "breaks" | None (not probed)


@dataclass
class Result:
    score: int
    tier: str
    breakdown: list[dict] = field(default_factory=list)


class NoHistory:
    def contexts(self, h: str) -> int:
        return 1

    def companies(self, h: str) -> int:
        return 1


class DbHistory:
    def __init__(self, conn):
        self.conn = conn

    def record(self, h: str, company: str | None, context: str | None) -> None:
        self.conn.execute(
            "INSERT INTO id_sightings (hmac, company, context, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(hmac, company, context) DO UPDATE SET last_seen = excluded.last_seen",
            (h, company or "", context or "", db.now_ms(), db.now_ms()),
        )

    def contexts(self, h: str) -> int:
        return self.conn.execute("SELECT count(DISTINCT context) FROM id_sightings WHERE hmac = ? AND context != ''",
                                 (h,)).fetchone()[0]

    def companies(self, h: str) -> int:
        return self.conn.execute("SELECT count(DISTINCT company) FROM id_sightings WHERE hmac = ? AND company != ''",
                                 (h,)).fetchone()[0]


def _entry(signal: str, label: str) -> dict:
    return {"signal": signal, "label": label, "points": POINTS[signal]}


def is_third_party(inp: Input) -> bool:
    if inp.category == "First party":
        return False
    if inp.page_site and inp.dest_domain:
        return registrable_domain(inp.dest_domain) != registrable_domain(inp.page_site)
    # App traffic with no page: only a known company counts as a third party.
    return inp.company is not None


def score(inp: Input, history) -> Result:
    b: list[dict] = []
    kinds = set() if inp.metadata_only else {f["flag"] for f in inp.flags}

    if is_third_party(inp):
        b.append(_entry("third_party", "third party"))
    if inp.category in AD_CATEGORIES:
        b.append(_entry("advertising", "advertising company"))
    if inp.category == "Session Replay" or "behavioural_events" in kinds:
        b.append(_entry("session_replay", "session replay (mouse and keystroke events)"))

    id_hashes = [] if inp.metadata_only else [
        f["hmac"] for f in inp.flags if f["flag"] == "tracking_id" and f.get("hmac")]
    sites = max((history.contexts(h) for h in id_hashes), default=0)
    if sites >= 2:
        b.append(_entry("cross_site_id", f"cross-site ID seen on {sites} sites"))
    if "page_url" in kinds and kinds & IDENTIFIER_FLAGS:
        b.append(_entry("page_url", "sent the page address"))
    if "fingerprinting" in kinds or inp.category == "Fingerprinting":
        b.append(_entry("fingerprinting", "fingerprinting values"))
    if kinds & PERSONAL_FLAGS:
        b.append(_entry("personal_identifier", "hashed personal identifier (your email or phone)"))
    if any(history.companies(h) >= 2 for h in id_hashes):
        b.append(_entry("cookie_syncing", "cookie syncing: the same ID went to another company"))
    if inp.is_data_broker or inp.category == "Data Broker":
        b.append(_entry("data_broker", "registered data broker"))
    third_party = is_third_party(inp)
    special = sorted({SPECIAL_DATA[k] for k in kinds if k in SPECIAL_DATA}) if third_party else []
    personal = sorted({PERSONAL_DATA[k] for k in kinds if k in PERSONAL_DATA}) if third_party else []
    if special:
        b.append(_entry("sensitive_data", f"sensitive data in the request: {', '.join(special)}"))
    if personal:
        b.append(_entry("personal_data", f"personal data in the request: {', '.join(personal)}"))
    if inp.breakage == "works":
        b.append(_entry("page_works_without_it", "page works without it"))
    elif inp.breakage == "breaks":
        b.append(_entry("page_breaks_without_it", "page breaks without it"))

    base = max(0, sum(e["points"] for e in b))
    total = base
    sensitive = (inp.topic in topics.SENSITIVE_TOPICS
                 or topics.keyword_topic(inp.app_name) in topics.SENSITIVE_TOPICS
                 or bool(special))
    if sensitive and base:
        total = round(base * SENSITIVE_MULTIPLIER)
        b.append({"signal": "sensitive_topic", "label": "sensitive topic, app or data (x1.5)", "points": total - base})
    total = min(100, total)
    return Result(total, tier_for(total), b)


# --------------------------------------------------------------- pipeline steps

def _finding(conn, request_id: int):
    return conn.execute("SELECT company, category, flags, topic FROM findings WHERE request_id = ?",
                        (request_id,)).fetchone()


def record_step(conn, row: dict) -> None:
    """Stage 1: remember every tracking ID sighting (keyed hashes only)."""
    f = _finding(conn, row["id"])
    if not f:
        return
    company, _cat, flags, _topic = f
    hist = DbHistory(conn)
    for fl in json.loads(flags or "[]"):
        if fl.get("flag") == "tracking_id" and fl.get("hmac"):
            hist.record(fl["hmac"], company, row.get("page_site") or row.get("app_name"))


def _breakage(conn, dest: str | None) -> str | None:
    if not dest:
        return None
    row = conn.execute("SELECT result FROM breakage WHERE domain = ?", (registrable_domain(dest),)).fetchone()
    return row[0] if row else None


def score_step(conn, row: dict) -> None:
    """Stage 2: runs after every sighting in the batch is recorded."""
    f = _finding(conn, row["id"])
    if not f:
        return
    company, category, flags, topic = f
    broker = None
    if company:
        r = conn.execute("SELECT is_data_broker FROM companies WHERE name = ?", (company,)).fetchone()
        broker = bool(r[0]) if r and r[0] is not None else None
    dest = row.get("dest_domain")
    res = score(Input(company, category, json.loads(flags or "[]"), topic, bool(row.get("metadata_only")),
                      row.get("app_name"), row.get("page_site"), dest, broker, _breakage(conn, dest)),
                DbHistory(conn))
    conn.execute("INSERT OR REPLACE INTO scores (request_id, score, tier, breakdown) VALUES (?, ?, ?, ?)",
                 (row["id"], res.score, res.tier, json.dumps(res.breakdown, separators=(",", ":"))))


# ------------------------------------------------------------- hand-label check

def agreement(pairs: list[tuple[str, str]]) -> dict:
    """pairs: (human tier, scorer tier). Returns agreement rate and confusion matrix."""
    confusion: dict[str, Counter] = defaultdict(Counter)
    for human, scorer in pairs:
        confusion[human][scorer] += 1
    n = len(pairs)
    agree = sum(1 for h, s in pairs if h == s)
    return {"n": n, "agreement": agree / n if n else 0.0,
            "confusion": {h: dict(c) for h, c in confusion.items()}}

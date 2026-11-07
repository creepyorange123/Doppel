"""Phase 4: score each request 0-100 with plain, explainable rules (no AI).

score = min(100, round(sum(points) x 1.5 if the topic or the app is sensitive))

Every score is saved with its breakdown, so each badge can explain itself.
Cross-site IDs and cookie syncing compare keyed hashes against *all* stored
history (``id_sightings``), not only the new batch.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from analyzer import topics
from shared import db

# Points for the destination (third parties only).
CATEGORY_POINTS = {
    "Data Broker": 25,
    "Advertising": 20,
    "Ad Motivated Tracking": 20,
    "Fingerprinting": 20,
    "Session Replay": 15,
    "Analytics": 10,
    "Audience Measurement": 10,
    "Social Network": 10,
    "Social - Share": 10,
    "Tag Manager": 5,
    "Embedded Content": 5,
    "CDN": 0,
    "First party": 0,
}

# Points for what was sent.
SIGNAL_POINTS = {
    "raw_email": 30,
    "hashed_email": 25,
    "hashed_phone": 25,
    "cross_site_id": 20,
    "tracking_id": 15,
    "cookie_syncing": 15,
    "fingerprinting": 15,
    "behavioural_events": 15,
    "email_address": 15,
    "page_url": 10,
    "cname_cloaked": 10,
}

LABELS = {
    "raw_email": "Your email address",
    "hashed_email": "A hash of your email",
    "hashed_phone": "A hash of your phone number",
    "cross_site_id": "The same ID seen on other sites or apps",
    "tracking_id": "A long-lived ID",
    "cookie_syncing": "The same ID shared between companies",
    "fingerprinting": "Device fingerprinting values",
    "behavioural_events": "Mouse or keyboard activity",
    "email_address": "An email address",
    "page_url": "The page you were on",
    "cname_cloaked": "Disguised as the site's own address",
    "sensitive_topic": "Sensitive topic or app (x1.5)",
}

SENSITIVE_MULTIPLIER = 1.5

TIERS = ((75, "High concern"), (50, "Profile-building"), (25, "Moderate"), (0, "Low"))


def tier_for(value: int) -> str:
    for floor, name in TIERS:
        if value >= floor:
            return name
    return "Low"


@dataclass
class Input:
    company: str | None
    category: str | None
    flags: list[dict]
    topic: str | None
    metadata_only: bool
    app_name: str | None
    page_site: str | None


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


def _entry(signal: str, points: int, label: str | None = None) -> dict:
    return {"signal": signal, "label": label or LABELS.get(signal, signal), "points": points}


def score(inp: Input, history) -> Result:
    breakdown: list[dict] = []
    third_party = inp.category not in (None, "First party")
    if third_party and CATEGORY_POINTS.get(inp.category or "", 5):
        pts = CATEGORY_POINTS.get(inp.category or "", 5)
        key = "third_party_" + (inp.category or "other").lower().replace(" - ", "_").replace(" ", "_")
        breakdown.append(_entry(key, pts, f"Sent to {inp.category.lower() if inp.category else 'a third party'}"
                                          + (f" ({inp.company})" if inp.company else "")))

    if not inp.metadata_only:
        kinds = {f["flag"] for f in inp.flags}
        for name in SIGNAL_POINTS:
            if name in kinds:
                breakdown.append(_entry(name, SIGNAL_POINTS[name]))
        id_hashes = [f["hmac"] for f in inp.flags if f["flag"] == "tracking_id" and f.get("hmac")]
        if third_party and any(history.contexts(h) >= 2 for h in id_hashes):
            breakdown.append(_entry("cross_site_id", SIGNAL_POINTS["cross_site_id"]))
        if third_party and any(history.companies(h) >= 2 for h in id_hashes):
            breakdown.append(_entry("cookie_syncing", SIGNAL_POINTS["cookie_syncing"]))

    base = sum(b["points"] for b in breakdown)
    sensitive = (inp.topic in topics.SENSITIVE_TOPICS
                 or topics.keyword_topic(inp.app_name) in topics.SENSITIVE_TOPICS)
    total = base
    if sensitive and base:
        total = round(base * SENSITIVE_MULTIPLIER)
        breakdown.append(_entry("sensitive_topic", total - base))
    total = min(100, total)
    return Result(total, tier_for(total), breakdown)


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


def score_step(conn, row: dict) -> None:
    """Stage 2: runs after every sighting in the batch is recorded."""
    f = _finding(conn, row["id"])
    if not f:
        return
    company, category, flags, topic = f
    r = score(Input(company, category, json.loads(flags or "[]"), topic, bool(row.get("metadata_only")),
                    row.get("app_name"), row.get("page_site")), DbHistory(conn))
    conn.execute("INSERT OR REPLACE INTO scores (request_id, score, tier, breakdown) VALUES (?, ?, ?, ?)",
                 (row["id"], r.score, r.tier, json.dumps(r.breakdown, separators=(",", ":"))))


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

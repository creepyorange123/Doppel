"""Phase 5: research the most common tracker companies.

Only company names leave the device: queries are built from fixed templates
around a company name that must already be in the bundled tracker map.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Iterable

import keyring

from analyzer import trackers
from analyzer.research import egress, summarize
from shared import db
from shared.keystore import SERVICE

MAX_AGE_MS = 7 * 24 * 3600 * 1000  # refresh weekly
NAME_RE = re.compile(r"^[\w .,&'()\-]{1,80}$", re.UNICODE)

QUERY_TEMPLATES = (
    "{c} privacy policy what data is collected",
    "{c} opt out of data collection",
    "{c} data broker registration",
    "{c} privacy fine OR lawsuit OR enforcement",
)

Searcher = Callable[[egress.Gate, str], list[dict]]


def known_companies(tracker_db: trackers.TrackerDB | None = None) -> set[str]:
    tdb = tracker_db or trackers.default()
    return {e["company"] for e in tdb.domains.values() if e.get("company")}


def build_queries(company: str, known: set[str]) -> list[str]:
    if company not in known:
        raise ValueError("not a known tracker company")
    if not NAME_RE.match(company) or "http" in company.lower() or "@" in company:
        raise ValueError("company name contains unexpected characters")
    return [t.format(c=company) for t in QUERY_TEMPLATES]


def top_companies(conn, limit: int = 50) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT company, count(*) AS n FROM findings WHERE company IS NOT NULL GROUP BY company "
        "ORDER BY n DESC, company LIMIT ?", (limit,))]


def is_fresh(conn, company: str, now: int) -> bool:
    row = conn.execute("SELECT researched_at, from_snapshot FROM companies WHERE name = ?", (company,)).fetchone()
    return bool(row and not row[1] and row[0] and now - row[0] < MAX_AGE_MS)


def save(conn, company: str, s: dict) -> None:
    conn.execute(
        "INSERT INTO companies (name, policy_summary, is_data_broker, opt_out_url, news, sources, researched_at, from_snapshot) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0) ON CONFLICT(name) DO UPDATE SET policy_summary=excluded.policy_summary, "
        "is_data_broker=excluded.is_data_broker, opt_out_url=excluded.opt_out_url, news=excluded.news, "
        "sources=excluded.sources, researched_at=excluded.researched_at, from_snapshot=0",
        (company, s["policy_summary"], None if s["is_data_broker"] is None else int(s["is_data_broker"]),
         s["opt_out_url"], json.dumps(s["news"]), json.dumps(s["sources"]), db.now_ms()),
    )


def refresh(conn, companies: Iterable[str], *, gate: egress.Gate, searchers: list[Searcher],
            model, tracker_db: trackers.TrackerDB, known: set[str] | None = None) -> int:
    if gate.zero_network():
        raise egress.Blocked("zero-network mode is on")
    known = known if known is not None else known_companies(tracker_db)
    now = db.now_ms()
    done = 0
    for company in companies:
        if is_fresh(conn, company, now):
            continue
        try:
            queries = build_queries(company, known)
        except ValueError:
            continue
        sources: list[dict] = []
        for q in queries:
            for search in searchers:
                try:
                    sources.extend(search(gate, q))
                except egress.Blocked:
                    raise
                except Exception:
                    continue  # one failed search shouldn't stop the rest
        save(conn, company, summarize.summarize(company, sources, model, tracker_db))
        done += 1
    return done


# ---------------------------------------------------------------- real clients

TAVILY_KEY = "tavily-api-key"
EXA_KEY = "exa-api-key"


def tavily(api_key: str) -> Searcher:
    def search(gate: egress.Gate, query: str) -> list[dict]:
        res = gate.post("https://api.tavily.com/search", {"query": query, "max_results": 5,
                                                          "search_depth": "basic"},
                        headers={"Authorization": f"Bearer {api_key}"})
        return [{"url": r.get("url"), "content": r.get("content")} for r in res.get("results", [])]
    return search


def exa(api_key: str) -> Searcher:
    def search(gate: egress.Gate, query: str) -> list[dict]:
        res = gate.post("https://api.exa.ai/search", {"query": query, "numResults": 5,
                                                      "contents": {"text": {"maxCharacters": 1500}}},
                        headers={"x-api-key": api_key})
        return [{"url": r.get("url"), "content": r.get("text")} for r in res.get("results", [])]
    return search


def searchers_from_keystore() -> list[Searcher]:
    out = []
    t = keyring.get_password(SERVICE, TAVILY_KEY)
    e = keyring.get_password(SERVICE, EXA_KEY)
    if t:
        out.append(tavily(t))
    if e:
        out.append(exa(e))
    return out

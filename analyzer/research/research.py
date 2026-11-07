"""Phase 5: research the most common tracker companies.

Original plan's split:
- Tavily search finds the company's privacy policy on its own domain; Tavily
  extract reads it.
- Tavily search, restricted to the California and Vermont data broker
  registries, decides whether it's a registered data broker.
- Exa finds news coverage, lawsuits, regulatory actions and data-sharing partners.

Only public company information leaves the device: queries are fixed templates
around a company name that must already be in the bundled tracker map, and the
only URL sent (to extract) is the company's own policy page.
"""

from __future__ import annotations

import json
import re
from typing import Iterable
from urllib.parse import urlsplit

import keyring

from analyzer import trackers
from analyzer.identify import registrable_domain
from analyzer.research import egress, summarize
from shared import db
from shared.keystore import SERVICE

MAX_AGE_MS = 7 * 24 * 3600 * 1000  # refresh weekly
NAME_RE = re.compile(r"^[\w .,&'()\-]{1,80}$", re.UNICODE)

QUERY_TEMPLATES = {
    "policy": "{c} privacy policy",
    "registry": "{c} data broker registration",
    "news": "{c} privacy lawsuit OR fine OR regulatory action OR data sharing partners",
}
REGISTRY_DOMAINS = ("cppa.ca.gov", "oag.ca.gov", "oag.vermont.gov", "sos.vermont.gov", "bizfilings.vermont.gov")


def known_companies(tracker_db: trackers.TrackerDB | None = None) -> set[str]:
    tdb = tracker_db or trackers.default()
    return {e["company"] for e in tdb.domains.values() if e.get("company")}


def build_queries(company: str, known: set[str]) -> dict[str, str]:
    if company not in known:
        raise ValueError("not a known tracker company")
    if not NAME_RE.match(company) or "http" in company.lower() or "@" in company:
        raise ValueError("company name contains unexpected characters")
    return {k: t.format(c=company) for k, t in QUERY_TEMPLATES.items()}


def top_companies(conn, limit: int = 50) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT company, count(*) AS n FROM findings WHERE company IS NOT NULL GROUP BY company "
        "ORDER BY n DESC, company LIMIT ?", (limit,))]


def is_fresh(conn, company: str, now: int) -> bool:
    row = conn.execute("SELECT researched_at, from_snapshot FROM companies WHERE name = ?", (company,)).fetchone()
    return bool(row and not row[1] and row[0] and now - row[0] < MAX_AGE_MS)


def save(conn, company: str, s: dict) -> None:
    conn.execute(
        "INSERT INTO companies (name, policy_summary, is_data_broker, opt_out_url, news, sources, policy_source, "
        "broker_source, researched_at, from_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0) "
        "ON CONFLICT(name) DO UPDATE SET policy_summary=excluded.policy_summary, "
        "is_data_broker=excluded.is_data_broker, opt_out_url=excluded.opt_out_url, news=excluded.news, "
        "sources=excluded.sources, policy_source=excluded.policy_source, broker_source=excluded.broker_source, "
        "researched_at=excluded.researched_at, from_snapshot=0",
        (company, s["policy_summary"], None if s["is_data_broker"] is None else int(s["is_data_broker"]),
         s["opt_out_url"], json.dumps(s["news"]), json.dumps(s["sources"]), s.get("policy_source"),
         s.get("broker_source"), db.now_ms()),
    )


def own_domain_url(results: list[dict], company: str, tracker_db: trackers.TrackerDB) -> str | None:
    domains = summarize.company_domains(tracker_db, company)
    for r in results:
        url = r.get("url") or ""
        if url.startswith("https://") and registrable_domain(urlsplit(url).hostname) in domains:
            return url
    return None


def registry_hit(results: list[dict], company: str) -> str | None:
    name = company.split(" (")[0].lower()
    for r in results:
        url = r.get("url") or ""
        host = (urlsplit(url).hostname or "").lower()
        on_registry = any(host == d or host.endswith("." + d) for d in REGISTRY_DOMAINS)
        if on_registry and name in (r.get("content") or "").lower():
            return url
    return None


def research_company(company: str, *, gate: egress.Gate, clients, model, tracker_db: trackers.TrackerDB,
                     known: set[str]) -> dict:
    q = build_queries(company, known)
    sources: list[dict] = []

    policy_url = own_domain_url(clients.tavily_search(gate, q["policy"]), company, tracker_db)
    if policy_url:
        text = clients.tavily_extract(gate, policy_url)
        if text:
            sources.append({"url": policy_url, "content": text})

    broker_url = registry_hit(
        clients.tavily_search(gate, q["registry"], include_domains=list(REGISTRY_DOMAINS)), company)
    sources.extend(clients.exa_search(gate, q["news"]))

    s = summarize.summarize(company, sources, model, tracker_db)
    # The registry check decides; no registry hit means "unknown", not "not a broker".
    s["is_data_broker"] = True if broker_url else None
    s["broker_source"] = broker_url
    s["policy_source"] = policy_url
    if broker_url and broker_url not in s["sources"]:
        s["sources"].append(broker_url)
    return s


def refresh(conn, companies: Iterable[str], *, gate: egress.Gate, clients, model,
            tracker_db: trackers.TrackerDB, known: set[str] | None = None) -> int:
    if gate.zero_network():
        raise egress.Blocked("zero-network mode is on")
    known = known if known is not None else known_companies(tracker_db)
    now = db.now_ms()
    done = 0
    for company in companies:
        if is_fresh(conn, company, now):
            continue
        try:
            s = research_company(company, gate=gate, clients=clients, model=model, tracker_db=tracker_db,
                                 known=known)
        except ValueError:
            continue
        save(conn, company, s)
        done += 1
    return done


# ---------------------------------------------------------------- real clients

TAVILY_KEY = "tavily-api-key"
EXA_KEY = "exa-api-key"


class Clients:
    """Real Tavily and Exa calls. Every call goes through the egress gate."""

    def __init__(self, tavily_key: str | None, exa_key: str | None):
        self.tavily_key, self.exa_key = tavily_key, exa_key

    def _tavily_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.tavily_key}"}

    def tavily_search(self, gate, query: str, include_domains: list[str] | None = None) -> list[dict]:
        if not self.tavily_key:
            return []
        body: dict = {"query": query, "max_results": 5, "search_depth": "basic"}
        if include_domains:
            body["include_domains"] = include_domains
        res = gate.post("https://api.tavily.com/search", body, headers=self._tavily_headers())
        return [{"url": r.get("url"), "content": r.get("content")} for r in res.get("results", [])]

    def tavily_extract(self, gate, url: str) -> str | None:
        if not self.tavily_key:
            return None
        res = gate.post("https://api.tavily.com/extract", {"urls": [url]}, headers=self._tavily_headers())
        results = res.get("results") or []
        return (results[0].get("raw_content") or "")[:20_000] if results else None

    def exa_search(self, gate, query: str) -> list[dict]:
        if not self.exa_key:
            return []
        res = gate.post("https://api.exa.ai/search",
                        {"query": query, "numResults": 5, "contents": {"text": {"maxCharacters": 1500}}},
                        headers={"x-api-key": self.exa_key})
        return [{"url": r.get("url"), "content": r.get("text")} for r in res.get("results", [])]


def clients_from_keystore() -> Clients | None:
    t = keyring.get_password(SERVICE, TAVILY_KEY)
    e = keyring.get_password(SERVICE, EXA_KEY)
    return Clients(t, e) if (t or e) else None

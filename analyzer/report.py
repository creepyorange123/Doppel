"""The report for one audit, and next-step actions (opt-out links, data-request letters).

Audits observe; they don't block. Block/strip were removed with the always-on
recorder: use an ad blocker or VPN for that.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from urllib.parse import urlsplit

from analyzer import topics, trackers
from analyzer.audits_api import get_audit
from analyzer.identify import registrable_domain
from analyzer.research.summarize import safe_opt_out
from shared import db
from shared.protocol import ProtocolError

TIER_ORDER = {"Minimum utility": 0, "Measurement": 1, "Profile building": 2, "High concern": 3}
ACTIONS = ("opt-out", "letter")


def actions_for(tier: str, has_opt_out: bool) -> list[str]:
    return (["opt-out"] if has_opt_out else []) + ["letter"]


def report(conn, payload) -> dict:
    audit = get_audit(conn, payload)
    rows = conn.execute(
        "SELECT f.company, f.category, s.score, s.tier, r.app_name, r.captured_at, r.process_name, r.page_site, "
        "r.dest_domain, f.flags FROM requests r "
        "JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id "
        "WHERE r.audit_id = ?", (audit.id,)).fetchall()
    companies: dict[str, dict] = {}
    per_tier = {t: 0 for t in TIER_ORDER}
    by_day: dict[str, dict[str, int]] = {}
    apps: dict[str, dict] = {}
    is_browser = {x.name: x.is_browser for x in audit.apps}
    for company, category, score, tier, app, at, process, page, dest, fflags in rows:
        per_tier[tier] = per_tier.get(tier, 0) + 1
        a = apps.setdefault(app or "Unknown app", {
            "name": app or "Unknown app", "is_browser": is_browser.get(app, False), "requests": 0,
            "companies": set(), "max_score": 0, "tier": "Minimum utility", "processes": Counter(),
            "sites": {}, "destinations": {}})
        a["requests"] += 1
        a["processes"][process or a["name"]] += 1
        if a["is_browser"]:
            # Browsers: which companies each site you visited brought along.
            site = a["sites"].setdefault(page or "", {"name": page, "requests": 0, "companies": set(),
                                                      "max_score": 0, "tier": "Minimum utility"})
            _tally(site, company, score, tier)
        else:
            # Apps: who they phone home to (their maker, bundled SDKs, trackers).
            own = '"app_own_domain"' in (fflags or "")
            key = "own" if own else (company or registrable_domain(dest) or dest)
            d = a["destinations"].setdefault(key, {"name": "Its own servers" if own else key, "own": own,
                                                   "requests": 0, "companies": set(), "max_score": 0,
                                                   "tier": "Minimum utility"})
            _tally(d, company, score, tier)
        if company:
            a["companies"].add(company)
        if score > a["max_score"]:
            a["max_score"], a["tier"] = score, tier
        day = dt.datetime.fromtimestamp(at / 1000).date().isoformat()  # local day
        counts = by_day.setdefault(day, {t: 0 for t in TIER_ORDER})
        counts[tier] = counts.get(tier, 0) + 1
        if not company:
            continue
        c = companies.setdefault(company, {"name": company, "category": category, "max_score": 0, "tier": "Minimum utility",
                                           "apps": set(), "requests": 0})
        c["requests"] += 1
        if app:
            c["apps"].add(app)
        if score > c["max_score"]:
            c["max_score"], c["tier"] = score, tier
    taken: dict[str, set[str]] = {}
    for company, action in conn.execute("SELECT company, action FROM actions WHERE action IN (?, ?)", ACTIONS):
        taken.setdefault(company, set()).add(action)
    out = []
    for c in sorted(companies.values(), key=lambda c: (-c["max_score"], c["name"])):
        c["apps"] = sorted(c["apps"])
        c["actions_taken"] = sorted(taken.get(c["name"], set()))
        out.append(c)
    app_rows = []
    for a in sorted(apps.values(), key=lambda a: (-a["max_score"], -a["requests"], a["name"])):
        sites, dests = a.pop("sites"), a.pop("destinations")
        row = {**a, "companies": len(a["companies"]),
               "processes": [{"name": n, "requests": k} for n, k in a["processes"].most_common()]}
        if a["is_browser"]:
            row["sites"] = _ranked(v for k, v in sites.items() if k)  # requests with no known page are left out
        else:
            row["destinations"] = _ranked(dests.values())
        app_rows.append(row)
    return {
        "audit": audit.public(),
        "summary": {"requests": len(rows), "companies": len(companies),
                    "high_concern": sum(1 for c in companies.values() if c["tier"] == "High concern")},
        "apps": app_rows,
        "companies": out,
        "tier_requests": per_tier,
        "by_day": [{"date": d, "counts": by_day[d]} for d in sorted(by_day)],
    }


def _tally(group: dict, company: str | None, score: int, tier: str) -> None:
    group["requests"] += 1
    if company:
        group["companies"].add(company)
    if score > group["max_score"]:
        group["max_score"], group["tier"] = score, tier


def _ranked(groups) -> list[dict]:
    out = [{**g, "companies": sorted(g["companies"])} for g in groups]
    return sorted(out, key=lambda g: (-g["max_score"], -g["requests"], str(g["name"])))[:25]


def list_requests(conn, payload) -> dict:
    """Every scored request in an audit, newest first (capped)."""
    audit = get_audit(conn, payload)
    limit = payload.get("limit", 1000)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 5000:
        raise ProtocolError("bad_payload", "limit must be an integer from 1 to 5000")
    rows = conn.execute(
        "SELECT r.id, r.captured_at, r.app_name, r.process_name, r.dest_domain, f.company, f.summary, f.topic, "
        "s.score, s.tier, s.breakdown FROM requests r "
        "JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id "
        "WHERE r.audit_id = ? ORDER BY r.captured_at DESC LIMIT ?", (audit.id, limit + 1)).fetchall()
    out = [{"id": rid, "captured_at": at, "app_name": app, "process_name": proc, "dest_domain": dest, "company": company,
            "summary": summary, "topic": topic, "sensitive": topic in topics.SENSITIVE_TOPICS or '"sensitive_data"' in (breakdown or ""),
            "score": score, "tier": tier, "breakdown": json.loads(breakdown or "[]")}
           for rid, at, app, proc, dest, company, summary, topic, score, tier, breakdown in rows[:limit]]
    return {"requests": out, "truncated": len(rows) > limit}


def company_detail(conn, payload) -> dict:
    company = payload.get("company")
    if not isinstance(company, str) or not company:
        raise ProtocolError("bad_payload", "company is required")
    audit = get_audit(conn, payload)
    tdb = trackers.default()
    reqs = conn.execute(
        "SELECT r.id, r.captured_at, r.app_name, r.process_name, r.dest_domain, f.summary, f.flags, f.topic, "
        "s.score, s.tier, s.breakdown "
        "FROM requests r JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id "
        "WHERE f.company = ? AND r.audit_id = ? ORDER BY s.score DESC, r.captured_at DESC LIMIT 200",
        (company, audit.id)).fetchall()
    flags, topics_, apps = Counter(), Counter(), Counter()
    requests = []
    for rid, at, app, proc, dest, summary, fl, topic, score, tier, breakdown in reqs:
        for f in json.loads(fl or "[]"):
            flags[f["flag"]] += 1
        topics_[topic] += 1
        apps[app] += 1
        requests.append({"id": rid, "captured_at": at, "app_name": app, "process_name": proc, "dest_domain": dest,
                         "summary": summary,
                         "score": score, "tier": tier, "breakdown": json.loads(breakdown or "[]")})
    row = conn.execute("SELECT policy_summary, is_data_broker, opt_out_url, news, sources, researched_at, from_snapshot "
                       "FROM companies WHERE name = ?", (company,)).fetchone()
    opt_out = safe_opt_out(row[2], company, tdb) if row else None
    card = {
        "name": company,
        "policy_summary": row[0] if row else None,
        "is_data_broker": None if not row or row[1] is None else bool(row[1]),
        "opt_out_url": opt_out,
        "opt_out_domain": urlsplit(opt_out).hostname if opt_out else None,
        "news": json.loads(row[3] or "[]") if row else [],
        "sources": json.loads(row[4] or "[]") if row else [],
        "researched_at": row[5] if row else None,
        "from_snapshot": bool(row[6]) if row else None,
        "exposure": {"requests": len(requests), "apps": dict(apps), "topics": dict(topics_), "flags": dict(flags)},
    }
    top_tier = max((r["tier"] for r in requests), key=lambda t: TIER_ORDER.get(t, 0), default="Minimum utility")
    return {"card": card, "requests": requests, "actions": actions_for(top_tier, opt_out is not None),
            "california": db.get_setting(conn, "california", "0") == "1"}


LETTER = """[This is a template, not legal advice. Check which laws apply to you before sending.]

Subject: Request to access my personal data

To {company}'s privacy team,

Under the data protection laws that apply to me (including, where applicable, the GDPR Article 15
and the California Consumer Privacy Act), I am requesting access to the personal data you hold
about me, including:

1. The categories and specific pieces of personal data you have collected about me.
2. The sources from which it was collected.
3. The purposes for which it is used.
4. The third parties with whom it has been shared or sold.
5. How long it will be kept.

Identifiers that may help you locate my data (cookie IDs, device IDs, or advertising IDs):
[add what you are comfortable sharing]

Please respond within the time the law requires.

Sincerely,
[your name]
"""


def take_action(conn, payload) -> dict:
    company, action = payload.get("company"), payload.get("action")
    if action not in ACTIONS:
        raise ProtocolError("bad_payload", f"action must be one of {', '.join(ACTIONS)}")
    if not isinstance(company, str) or not company:
        raise ProtocolError("bad_payload", "company is required")
    conn.execute("INSERT INTO actions (company, action, taken_at) VALUES (?, ?, ?)", (company, action, db.now_ms()))
    if action == "letter":
        return {"ok": True, "letter": LETTER.format(company=company)}  # generated locally; nothing is sent
    return {"ok": True}

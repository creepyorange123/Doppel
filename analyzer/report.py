"""Phase 6: the 'since you last opened' report and next-step actions."""

from __future__ import annotations

import json
from collections import Counter
from urllib.parse import urlsplit

from analyzer import trackers
from analyzer.identify import registrable_domain
from analyzer.research.summarize import safe_opt_out
from shared import db
from shared.protocol import ProtocolError

TIER_ORDER = {"Minimum utility": 0, "Measurement": 1, "Profile building": 2, "High concern": 3}
ACTIONS = ("block", "strip", "opt-out", "letter")
RULE_ACTIONS = ("block", "strip")  # written into the recorder's rules


def _since(conn) -> int:
    v = db.get_setting(conn, "last_run_since")
    return int(v) if v is not None else 0


def actions_for(tier: str, has_opt_out: bool) -> list[str]:
    """Original plan defaults: Minimum utility = leave alone; Measurement = show, optionally
    block; Profile building = recommend blocking; High concern = block and flag."""
    out = []
    level = TIER_ORDER.get(tier, 0)
    if level >= TIER_ORDER["Measurement"]:
        out.append("block")
    if level >= TIER_ORDER["Profile building"]:
        out.append("strip")
    if has_opt_out:
        out.append("opt-out")
    out.append("letter")
    return out


def report(conn, payload) -> dict:
    since = _since(conn)
    rows = conn.execute(
        "SELECT f.company, f.category, s.score, s.tier, r.app_name FROM requests r "
        "JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id "
        "WHERE r.captured_at > ?", (since,)).fetchall()
    companies: dict[str, dict] = {}
    for company, category, score, tier, app in rows:
        if not company:
            continue
        c = companies.setdefault(company, {"name": company, "category": category, "max_score": 0, "tier": "Minimum utility",
                                           "apps": set(), "requests": 0})
        c["requests"] += 1
        if app:
            c["apps"].add(app)
        if score > c["max_score"]:
            c["max_score"], c["tier"] = score, tier
    taken = {}
    for company, action in conn.execute("SELECT company, action FROM actions ORDER BY taken_at"):
        taken.setdefault(company, set()).add(action)
    active = _active_rule_actions(conn)
    out = []
    for c in sorted(companies.values(), key=lambda c: (-c["max_score"], c["name"])):
        c["apps"] = sorted(c["apps"])
        c["actions_taken"] = sorted(active.get(c["name"], set()) | (taken.get(c["name"], set()) - set(RULE_ACTIONS)))
        out.append(c)
    return {
        "summary": {"since": since, "requests": len(rows), "companies": len(companies),
                    "high_concern": sum(1 for c in companies.values() if c["tier"] == "High concern")},
        "companies": out,
    }


def _active_rule_actions(conn) -> dict[str, set[str]]:
    """Which companies currently have a block/strip rule in force."""
    tdb = trackers.default()
    rules = dict(conn.execute("SELECT match, rule FROM app_rules WHERE kind = 'action'").fetchall())
    out: dict[str, set[str]] = {}
    for name in {r[0] for r in conn.execute("SELECT DISTINCT company FROM actions")}:
        for d in company_domains(conn, name, tdb):
            if d in rules:
                out.setdefault(name, set()).add(rules[d])
    return out


def company_domains(conn, company: str, tdb: trackers.TrackerDB | None = None) -> set[str]:
    tdb = tdb or trackers.default()
    domains = {d for d, e in tdb.domains.items() if e.get("company") == company}
    domains |= {r[0] for r in conn.execute(
        "SELECT DISTINCT r.dest_domain FROM requests r JOIN findings f ON f.request_id = r.id WHERE f.company = ?",
        (company,))}
    return {d.lower() for d in domains if d}


def company_detail(conn, payload) -> dict:
    company = payload.get("company")
    if not isinstance(company, str) or not company:
        raise ProtocolError("bad_payload", "company is required")
    tdb = trackers.default()
    reqs = conn.execute(
        "SELECT r.id, r.captured_at, r.app_name, r.dest_domain, f.summary, f.flags, f.topic, s.score, s.tier, s.breakdown "
        "FROM requests r JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id "
        "WHERE f.company = ? AND r.captured_at > ? ORDER BY s.score DESC, r.captured_at DESC LIMIT 200",
        (company, _since(conn))).fetchall()
    flags, topics_, apps = Counter(), Counter(), Counter()
    requests = []
    for rid, at, app, dest, summary, fl, topic, score, tier, breakdown in reqs:
        for f in json.loads(fl or "[]"):
            flags[f["flag"]] += 1
        topics_[topic] += 1
        apps[app] += 1
        requests.append({"id": rid, "captured_at": at, "app_name": app, "dest_domain": dest, "summary": summary,
                         "score": score, "tier": tier, "breakdown": json.loads(breakdown or "[]")})
    row = conn.execute("SELECT policy_summary, is_data_broker, opt_out_url, news, sources, researched_at, from_snapshot, "
                       "policy_source, broker_source FROM companies WHERE name = ?", (company,)).fetchone()
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
    exposure, lines = card_lines(conn, company, card, row)
    card["exposure"].update(exposure)
    card["lines"] = lines
    top_tier = max((r["tier"] for r in requests), key=lambda t: TIER_ORDER.get(t, 0), default="Minimum utility")
    return {"card": card, "requests": requests, "actions": actions_for(top_tier, opt_out is not None),
            "california": db.get_setting(conn, "california", "0") == "1"}


SENSITIVE_GROUPS = {
    "Medical Health": "health", "Healthy Living": "health", "Personal Finance": "finance",
    "Religion & Spirituality": "religion", "Sexuality": "sexuality", "Dating": "dating",
}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def card_lines(conn, company: str, card: dict, research_row) -> tuple[dict, list[dict]]:
    """Profile card lines, each labelled measured (your traffic) or inferred (research or
    inference from what it saw). Every inferred line cites its source."""
    since = _since(conn)
    all_sites = {r[0] for r in conn.execute(
        "SELECT DISTINCT page_site FROM requests WHERE page_site IS NOT NULL AND captured_at > ?", (since,))}
    site_topics: dict[str, str] = {}
    ids: set[str] = set()
    apps: set[str] = set()
    for site, topic, flags, app in conn.execute(
        "SELECT r.page_site, f.topic, f.flags, r.app_name FROM requests r JOIN findings f ON f.request_id = r.id "
        "WHERE f.company = ? AND r.captured_at > ?", (company, since)):
        if site:
            site_topics.setdefault(site, topic)
        if app:
            apps.add(app)
        for fl in json.loads(flags or "[]"):
            if fl.get("flag") == "tracking_id" and fl.get("hmac"):
                ids.add(fl["hmac"])

    lines: list[dict] = []
    share = len(site_topics) / len(all_sites) if all_sites else 0.0
    if site_topics:
        groups = Counter(SENSITIVE_GROUPS[t] for t in site_topics.values() if t in SENSITIVE_GROUPS)
        extra = ""
        if groups:
            name, n = groups.most_common(1)[0]
            extra = f", including {_plural(n, name + ' page')}"
        lines.append({"kind": "measured", "source": None, "text":
                      f"Present on {len(site_topics)} of the {_plural(len(all_sites), 'site')} you visited "
                      f"({round(share * 100)}%){extra}."})
    if ids:
        lines.append({"kind": "measured", "source": None, "text": f"Holds {_plural(len(ids), 'identifier')} for you."})
    if apps:
        lines.append({"kind": "measured", "source": None, "text": f"Contacted from {', '.join(sorted(apps))}."})

    # Inferences from what it saw, phrased as possibilities (original plan: no overstating).
    for topic, n in Counter(site_topics.values()).most_common(3):
        if topic and topic != "Uncategorized":
            lines.append({"kind": "inferred", "source": "Pages it saw on this computer",
                          "text": f"It could infer an interest in {topic} from {_plural(n, 'page')} it saw."})

    if research_row:
        summary, broker, _opt, news, sources = research_row[0], research_row[1], research_row[2], research_row[3], research_row[4]
        srcs = json.loads(sources or "[]")
        policy_src = (research_row[7] if len(research_row) > 7 else None) or (srcs[0] if srcs else None)
        broker_src = (research_row[8] if len(research_row) > 8 else None) or policy_src
        if summary and policy_src:
            lines.append({"kind": "inferred", "source": policy_src, "text": summary})
        if broker and broker_src:
            lines.append({"kind": "inferred", "source": broker_src, "text": "Registered data broker."})
        for item in json.loads(news or "[]"):
            if srcs:
                lines.append({"kind": "inferred", "source": srcs[-1], "text": item})
    return {"site_share": share, "sites_seen": len(site_topics), "sites_total": len(all_sites),
            "identifiers": len(ids)}, lines


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
    if not isinstance(company, str):
        raise ProtocolError("bad_payload", "company is required")
    if action == "letter":
        # Generated locally; nothing is sent.
        conn.execute("INSERT INTO actions (company, action, taken_at) VALUES (?, 'letter', ?)", (company, db.now_ms()))
        return {"ok": True, "letter": LETTER.format(company=company)}
    domains = company_domains(conn, company)
    if not domains:
        raise ProtocolError("unknown_company", "no domains known for that company")
    if action in RULE_ACTIONS:
        for d in domains:
            existing = conn.execute("SELECT rule FROM app_rules WHERE kind = 'action' AND match = ?", (d,)).fetchone()
            if existing and existing[0] == "block" and action == "strip":
                continue  # block already covers strip
            conn.execute(
                "INSERT INTO app_rules (kind, match, rule, source, updated_at) VALUES ('action', ?, ?, 'user', ?) "
                "ON CONFLICT(kind, match) DO UPDATE SET rule = excluded.rule, updated_at = excluded.updated_at",
                (d, action, db.now_ms()))
    conn.execute("INSERT INTO actions (company, action, taken_at) VALUES (?, ?, ?)", (company, action, db.now_ms()))
    return {"ok": True, "domains": sorted(domains)}


def undo_action(conn, payload) -> dict:
    company, action = payload.get("company"), payload.get("action")
    if action not in RULE_ACTIONS or not isinstance(company, str):
        raise ProtocolError("bad_payload", "only block and strip can be undone")
    for d in company_domains(conn, company):
        conn.execute("DELETE FROM app_rules WHERE kind = 'action' AND match = ? AND rule = ?", (d, action))
    return {"ok": True}

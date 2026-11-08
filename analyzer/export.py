"""Hand an audit's findings to the tools people already use to block trackers.

Doppel observes; blocking is better done by uBlock Origin, AdGuard, NextDNS,
Pi-hole, Little Snitch and friends. This builds a ready-to-import list of the
tracker domains an audit found, at or above a risk tier.

Only domains of known tracking companies, or requests that scored at or above
the tier, are listed, and never a site you visited in the audit (blocking
healthline.com would break healthline.com). Nothing here is sent anywhere: the
app copies the text or saves it to a file you choose.
"""

from __future__ import annotations

import datetime as dt
import json
import re

from analyzer.audits_api import get_audit
from analyzer.identify import registrable_domain
from analyzer.report import TIER_ORDER
from shared.protocol import ProtocolError

FORMATS = {
    # format: (file extension, tools it works with)
    "ublock": ("txt", "uBlock Origin, AdGuard, Brave"),
    "hosts": ("hosts", "a hosts file, Gas Mask, SwitchHosts"),
    "domains": ("txt", "NextDNS, Pi-hole, AdGuard Home, Cloudflare Gateway, Control D"),
    "little_snitch": ("lsrules", "Little Snitch"),
}
DEFAULT_TIER = "Profile building"
# Sites people also visit directly. Filter lists block them only when another site
# loads them ($third-party); DNS-level tools can't tell, so they leave them out.
SITE_CATEGORIES = frozenset({"Social Network", "Social - Share", "Embedded Content"})
DNS_FORMATS = ("hosts", "domains", "little_snitch")


def _domains(conn, audit_id: int, min_tier: str) -> tuple[list[str], list[str], set[str]]:
    """(blockable registrable domains, exact hosts seen, domains that are also sites people visit)."""
    floor = TIER_ORDER[min_tier]
    visited = {registrable_domain(p) for (p,) in conn.execute(
        "SELECT DISTINCT page_site FROM requests WHERE audit_id = ? AND page_site IS NOT NULL", (audit_id,))}
    sites, hosts, visitable = set(), set(), set()
    for host, company, category, tier in conn.execute(
            "SELECT r.dest_domain, f.company, f.category, s.tier FROM requests r "
            "JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id WHERE r.audit_id = ?",
            (audit_id,)):
        if TIER_ORDER.get(tier, 0) < floor or not company:
            continue
        site = registrable_domain(host)
        if not site or site in visited:
            continue
        sites.add(site)
        hosts.add(host.lower())
        if category in SITE_CATEGORIES or (host.lower() in (site, f"www.{site}")):
            visitable.add(site)
    return sorted(sites), sorted(hosts), visitable


def render(fmt: str, label: str, sites: list[str], hosts: list[str], min_tier: str, when: str,
           skipped: list[str] = ()) -> str:
    title = f"Doppel audit: {label}"
    about = f"Trackers rated {min_tier} or higher, found {when}. Made on this computer by Doppel."
    note = (f"Left out because you may visit them directly: {', '.join(skipped)}." if skipped else "")
    if fmt == "ublock":
        lines = [f"! Title: {title}", f"! Description: {about}", "! Expires: 30 days",
                 "! $third-party: blocked only when another site loads them, never when you visit them.", ""]
        return "\n".join(lines + [f"||{d}^$third-party" for d in sites]) + "\n"
    if fmt == "hosts":
        lines = [f"# {title}", f"# {about}", "# hosts files can't block whole domains, so every host seen is listed."]
        lines += [f"# {note}"] if note else []
        return "\n".join(lines + [""] + [f"0.0.0.0 {h}" for h in sorted(set(hosts) | set(sites))]) + "\n"
    if fmt == "domains":
        return "\n".join([f"# {title}", f"# {about}"] + ([f"# {note}"] if note else []) + [""] + sites) + "\n"
    if fmt == "little_snitch":
        return json.dumps({
            "name": title, "description": f"{about} {note}".strip(),
            "rules": [{"action": "deny", "process": "any", "remote-domains": sites, "notes": about}] if sites else [],
        }, indent=2) + "\n"
    raise ProtocolError("bad_payload", f"format must be one of {', '.join(FORMATS)}")


def export_blocklist(conn, payload) -> dict:
    audit = get_audit(conn, payload)
    fmt = payload.get("format", "ublock")
    min_tier = payload.get("min_tier", DEFAULT_TIER)
    if fmt not in FORMATS:
        raise ProtocolError("bad_payload", f"format must be one of {', '.join(FORMATS)}")
    if min_tier not in TIER_ORDER or min_tier == "Minimum utility":
        raise ProtocolError("bad_payload", "min_tier must be Measurement, Profile building or High concern")
    sites, hosts, visitable = _domains(conn, audit.id, min_tier)
    skipped: list[str] = []
    if fmt in DNS_FORMATS:
        skipped = sorted(d for d in sites if d in visitable)
        sites = [d for d in sites if d not in visitable]
        hosts = [h for h in hosts if registrable_domain(h) not in visitable]
    when = dt.datetime.fromtimestamp(audit.started_at / 1000).strftime("%-d %b %Y")
    ext, works_with = FORMATS[fmt]
    slug = re.sub(r"[^a-z0-9]+", "-", audit.label.lower()).strip("-")[:40] or "audit"
    return {
        "format": fmt, "min_tier": min_tier, "domains": sites, "count": len(sites), "works_with": works_with,
        "filename": f"doppel-{slug}-{fmt.replace('_', '-')}.{ext}",
        "skipped": skipped,
        "content": render(fmt, audit.label, sites, hosts, min_tier, when, skipped),
    }

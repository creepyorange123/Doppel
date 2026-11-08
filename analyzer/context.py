"""Which page a metadata-only request probably came from.

Without decrypting, a request carries no Referer, so a Facebook pixel loaded by
healthline.com looks like an app talking to Facebook on its own. In an audit we
can do better: requests from one browser process arrive in bursts right after
you open a page, so a tracker contacted a few seconds after
``www.healthline.com`` was most likely loaded by it.

Only browsers visit pages. Other apps (Discord, Slack, VS Code) talk to their
maker and to SDKs bundled inside them, so for them there is no page: instead the
maker's own domains are marked ``app_own_domain`` and count as first party
(see ``app_domains``), and the app itself is the topic context.

A host counts as a visited page when it is a site's own name (``example.com`` or
``www.example.com``), not a known tracker or shared infrastructure, it is the
first request to its site for a while, and the site then loads more of its own
resources from another host (``assets.example.com``) within ``CONFIRM_MS``: real
pages do; beacons, ad-block probes and ad exchanges mid-page don't. Each later
metadata-only request from the same process, within ``WINDOW_MS``, is attributed
to the most recent such page and flagged ``page_inferred`` so reports can say
"probably".
"""

from __future__ import annotations

import json

from collections import Counter

from analyzer import trackers
from analyzer.identify import registrable_domain
from shared import audits as audits_mod

WINDOW_MS = 60_000
CONFIRM_MS = 15_000
# Shared hosting and CDN names that are never "the page you were on".
INFRASTRUCTURE = frozenset({
    "googleapis.com", "gstatic.com", "cloudfront.net", "akamaihd.net", "akamaized.net", "fastly.net",
    "jsdelivr.net", "cloudflare.com", "cloudflare-dns.com", "unpkg.com", "amazonaws.com", "azureedge.net",
    "msecnd.net", "windows.net", "apple.com", "icloud.com", "mozilla.org", "mozilla.net", "firefox.com",
    "zen-browser.app", "googleusercontent.com", "ggpht.com", "ytimg.com", "fbcdn.net",
})


# The maker's own domains for common desktop apps, matched on the app's name.
VENDOR_DOMAINS = {
    "discord": {"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"},
    "slack": {"slack.com", "slack-edge.com", "slack-msgs.com", "slack-imgs.com", "slackb.com"},
    "visual studio code": {"visualstudio.com", "vscode-cdn.net", "vsassets.io", "vscode-unpkg.net", "github.com"},
    "spotify": {"spotify.com", "scdn.co", "spotifycdn.com", "spotify.net"},
    "zoom": {"zoom.us", "zoom.com", "zoomgov.com"},
    "microsoft": {"microsoft.com", "office.com", "office.net", "live.com", "microsoftonline.com", "msftauth.net"},
    "claude": {"anthropic.com", "claude.ai", "claude.com"},
    "notion": {"notion.so", "notion.com", "notion-static.com"},
    "telegram": {"telegram.org", "t.me"},
    "whatsapp": {"whatsapp.net", "whatsapp.com"},
}
# Otherwise: the app's most-contacted non-tracker domain, if it is this big a share.
TOP_DOMAIN_SHARE = 0.2
MIN_TOP_REQUESTS = 3


def app_domains(app_name: str, hosts: list[str], tdb: trackers.TrackerDB) -> set[str]:
    """Registrable domains that belong to the app's maker."""
    name = app_name.lower()
    own = set().union(*(d for key, d in VENDOR_DOMAINS.items() if key in name))
    counts = Counter(registrable_domain(h) for h in hosts if h and tdb.match(h) is None)
    counts.pop(None, None)
    if counts:
        top, n = counts.most_common(1)[0]
        if n >= MIN_TOP_REQUESTS and n >= TOP_DOMAIN_SHARE * len(hosts):
            own.add(top)
    return own


def is_page_host(host: str, tdb: trackers.TrackerDB) -> bool:
    site = registrable_domain(host)
    if not site or host not in (site, f"www.{site}"):
        return False
    return site not in INFRASTRUCTURE and tdb.match(host) is None


def _confirmed_pages(rows: list, tdb: trackers.TrackerDB) -> set[int]:
    """Indexes of rows that open a page, in the same process: a page host that is the
    first request to its site for a while (not part of a burst already under way),
    followed by a *different* host of the same site within CONFIRM_MS."""
    out = set()
    for i, (_, at, process, app, host, *_rest) in enumerate(rows):
        if not is_page_host(host, tdb):
            continue
        site, who = registrable_domain(host), process or app or ""
        same = lambda r: (r[2] or r[3] or "") == who and registrable_domain(r[4]) == site  # noqa: E731
        earlier = (r for r in reversed(rows[:i]) if at - r[1] <= CONFIRM_MS)
        if any(same(r) and r[4] != host and not is_page_host(r[4], tdb) for r in earlier):
            continue  # e.g. hm.adspsp.com, then adspsp.com: an ad exchange mid-page, not a visit
        for r in rows[i + 1:]:
            if r[1] - at > CONFIRM_MS:
                break
            if same(r) and r[4] != host and not is_page_host(r[4], tdb):
                out.add(i)
                break
    return out


def _mark_app_domains(rows: list, wanted: set[int], tdb: trackers.TrackerDB) -> list[tuple]:
    """Non-browser apps: flag requests to the app maker's own domains (first party)."""
    by_app: dict[str, list] = {}
    for r in rows:
        by_app.setdefault(r[3] or "", []).append(r)
    updates = []
    for app, app_rows in by_app.items():
        own = app_domains(app, [r[4] for r in app_rows], tdb)
        for rid, _at, _p, _a, host, page, meta, flags in app_rows:
            if rid not in wanted:
                continue
            fl = [f for f in json.loads(flags or "[]") if f.get("flag") not in ("page_inferred", "app_own_domain")]
            if registrable_domain(host) in own and tdb.match(host) is None:
                fl.append({"flag": "app_own_domain", "where": "audit"})
            updates.append((None if meta else page, json.dumps(fl, separators=(",", ":")), rid))
    return updates


def infer_pages(conn, ids: list[int], tdb: trackers.TrackerDB | None = None) -> int:
    """Fill ``page_site`` for metadata-only requests (recomputed on re-analysis). Returns how many."""
    if not ids:
        return 0
    tdb = tdb or trackers.default()
    marks = ",".join("?" * len(ids))
    audits = [r[0] for r in conn.execute(f"SELECT DISTINCT audit_id FROM requests WHERE id IN ({marks})", ids)]
    wanted = set(ids)
    updates = []
    for audit_id in audits:
        browsers = {a.name for a in audits_mod.get(conn, audit_id).apps if a.is_browser}
        all_rows = conn.execute(
            "SELECT id, captured_at, process_name, app_name, dest_domain, page_site, metadata_only, flags "
            "FROM requests WHERE audit_id = ? ORDER BY captured_at, id", (audit_id,)).fetchall()
        updates += _mark_app_domains([r for r in all_rows if r[3] not in browsers], wanted, tdb)
        rows = [r for r in all_rows if r[3] in browsers]  # only browsers visit pages
        confirmed = _confirmed_pages(rows, tdb)
        current: dict[str, tuple[str, int]] = {}  # process -> (page site, when it was opened)
        for i, (rid, at, process, app, host, page, meta, flags) in enumerate(rows):
            who = process or app or ""
            if page and not meta:  # a real page, from the Referer of a fully captured request
                current[who] = (registrable_domain(page) or page, at)
                continue
            if i in confirmed:
                current[who] = (registrable_domain(host), at)
            if rid not in wanted or not meta or who not in current:
                continue
            site, opened = current[who]
            if at - opened > WINDOW_MS:
                continue
            fl = [f for f in json.loads(flags or "[]") if f.get("flag") != "page_inferred"]  # re-analysis
            if registrable_domain(host) != site:
                fl.append({"flag": "page_inferred", "where": "audit"})
            updates.append((site, json.dumps(fl, separators=(",", ":")), rid))
    conn.executemany("UPDATE requests SET page_site = ?, flags = ? WHERE id = ?", updates)
    return len(updates)

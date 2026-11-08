"""Rebuild shared/data/trackers.json, then write its SHA-256 manifest.

Sources, strongest first (a later source never overrides an earlier one):
  1. The hand-curated entries already in trackers.json (company names), kept with --keep-curated.
  2. DuckDuckGo Tracker Radar (company + category). CC BY-NC-SA 4.0.
  3. EasyList: uBlock Origin's ad list. Whole-domain rules become "Advertising".
  4. EasyPrivacy: uBlock Origin's tracker list. Whole-domain rules become "Analytics".
EasyList and EasyPrivacy are dual-licensed GPLv3 / CC BY-SA 3.0 (https://easylist.to).

Download the lists yourself, then run, for example:

    curl -o easylist.txt https://easylist.to/easylist/easylist.txt
    curl -o easyprivacy.txt https://easylist.to/easylist/easyprivacy.txt
    python scripts/build_tracker_db.py --keep-curated --easylist easylist.txt --easyprivacy easyprivacy.txt

No network access happens here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "shared" / "data" / "trackers.json"


def from_radar(folder: Path) -> dict[str, dict]:
    out = {}
    for f in folder.glob("*.json"):
        d = json.loads(f.read_text(encoding="utf-8"))
        owner = (d.get("owner") or {}).get("displayName") or (d.get("owner") or {}).get("name")
        cats = d.get("categories") or []
        if owner or cats:
            out[d["domain"].lower()] = {"company": owner, "category": cats[0] if cats else None}
    return out


# Only rules that block a whole domain: ||example.com^ or ||example.com^$third-party.
# Path rules, cosmetic rules and rules with other options say less about who the
# recipient is, so they are skipped.
DOMAIN_RULE = re.compile(r"^\|\|([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\^(\$third-party)?$")
EXCEPTION_RULE = re.compile(r"^@@\|\|([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\^")


def from_filter_list(path: Path, category: str) -> dict[str, dict]:
    """Whole-domain block rules from an Adblock Plus / uBlock Origin filter list."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    allowed = {m.group(1) for line in lines if (m := EXCEPTION_RULE.match(line.strip()))}
    out = {}
    for line in lines:
        m = DOMAIN_RULE.match(line.strip())
        if m and m.group(1) not in allowed:
            out.setdefault(m.group(1), {"company": None, "category": category})
    return out


def from_easyprivacy(path: Path) -> dict[str, dict]:
    return from_filter_list(path, "Analytics")


def from_easylist(path: Path) -> dict[str, dict]:
    return from_filter_list(path, "Advertising")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--keep-curated", action="store_true", help="keep the entries already in trackers.json (they win)")
    p.add_argument("--radar", type=Path, help="tracker-radar/domains/<region> folder")
    p.add_argument("--easylist", type=Path)
    p.add_argument("--easyprivacy", type=Path)
    a = p.parse_args()
    layers: list[tuple[str, dict[str, dict]]] = []
    if a.keep_curated and OUT.exists():
        layers.append(("curated", json.loads(OUT.read_text(encoding="utf-8"))["domains"]))
    if a.radar:
        layers.append(("DuckDuckGo Tracker Radar", from_radar(a.radar)))
    if a.easylist:
        layers.append(("EasyList", from_easylist(a.easylist)))
    if a.easyprivacy:
        layers.append(("EasyPrivacy", from_easyprivacy(a.easyprivacy)))
    if not layers:
        p.error("give at least one source")
    domains: dict[str, dict] = {}
    for name, entries in layers:
        before = len(domains)
        for d, e in entries.items():
            domains.setdefault(d.lower(), e)
        print(f"{name}: {len(entries)} domains, {len(domains) - before} new")
    # A subdomain already covered by a listed parent adds nothing, and would hide
    # the parent's company name (g.doubleclick.net vs curated doubleclick.net -> Google).
    covered = [d for d in domains if any(".".join(d.split(".")[i:]) in domains for i in range(1, d.count(".")))]
    for d in covered:
        del domains[d]
    print(f"dropped {len(covered)} subdomains already covered by a parent")
    data = {"source": " + ".join(n for n, _ in layers),
            "licences": "EasyList/EasyPrivacy: GPLv3 or CC BY-SA 3.0 (easylist.to); "
                        "Tracker Radar: CC BY-NC-SA 4.0",
            "domains": dict(sorted(domains.items()))}
    raw = (json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n").encode()
    OUT.write_bytes(raw)
    Path(str(OUT) + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", newline="\n")
    print(f"wrote {len(domains)} domains ({len(raw) // 1024} KB)")


if __name__ == "__main__":
    main()

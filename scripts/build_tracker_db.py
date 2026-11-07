"""Rebuild shared/data/trackers.json from local copies of DuckDuckGo Tracker
Radar and EasyPrivacy, then write its SHA-256 manifest.

Download both yourself (check their licences: Tracker Radar is CC BY-NC-SA 4.0),
verify them, then run:

    python scripts/build_tracker_db.py --radar path/to/tracker-radar/domains/US \
        --easyprivacy path/to/easyprivacy.txt

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


def from_easyprivacy(path: Path) -> dict[str, dict]:
    out = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\|\|([a-z0-9.-]+)\^", line.strip())
        if m:
            out.setdefault(m.group(1), {"company": None, "category": "Analytics"})
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--radar", type=Path, required=True)
    p.add_argument("--easyprivacy", type=Path)
    a = p.parse_args()
    domains = from_easyprivacy(a.easyprivacy) if a.easyprivacy else {}
    domains.update(from_radar(a.radar))  # Tracker Radar wins; EasyPrivacy is the fallback
    data = {"source": "DuckDuckGo Tracker Radar + EasyPrivacy", "domains": dict(sorted(domains.items()))}
    raw = (json.dumps(data, indent=1, sort_keys=True) + "\n").encode()
    OUT.write_bytes(raw)
    Path(str(OUT) + ".sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n", newline="\n")
    print(f"wrote {len(domains)} domains")


if __name__ == "__main__":
    main()

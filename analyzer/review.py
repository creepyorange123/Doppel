"""Hand-check helpers for the phase 3 and 4 checks.

    python -m analyzer.review export --n 100 labels.csv   # sample to label by hand
    python -m analyzer.review report labels.csv           # scorer agreement

The CSV holds only summaries, companies and flag names - never raw content.
Fill the empty ``human_tier`` column with Low / Moderate / Profile-building /
High concern. Keep the file on this computer.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys

from analyzer import score
from shared import db

FIELDS = ["request_id", "app_name", "dest_domain", "company", "category", "flags", "summary",
          "scorer_score", "scorer_tier", "human_tier"]


def export(conn, n: int, out) -> int:
    rows = conn.execute(
        "SELECT r.id, r.app_name, r.dest_domain, f.company, f.category, f.flags, f.summary, s.score, s.tier "
        "FROM requests r JOIN findings f ON f.request_id = r.id JOIN scores s ON s.request_id = r.id "
        "ORDER BY random() LIMIT ?", (n,)).fetchall()
    w = csv.writer(out)
    w.writerow(FIELDS)
    for r in rows:
        kinds = sorted({f["flag"] for f in json.loads(r[5] or "[]")})
        w.writerow([*r[:5], " ".join(kinds), *r[6:], ""])
    return len(rows)


def report(path: str) -> dict:
    with open(path, newline="", encoding="utf-8") as fh:
        pairs = [(r["human_tier"].strip(), r["scorer_tier"]) for r in csv.DictReader(fh) if r["human_tier"].strip()]
    return score.agreement(pairs)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="analyzer.review")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--n", type=int, default=100)
    e.add_argument("out")
    r = sub.add_parser("report")
    r.add_argument("csv")
    a = p.parse_args(argv)
    if a.cmd == "export":
        with open(a.out, "w", newline="", encoding="utf-8") as fh:
            print(f"exported {export(db.open_db(), a.n, fh)} requests", file=sys.stderr)
    else:
        print(json.dumps(report(a.csv), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

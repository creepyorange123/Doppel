"""Research agent: a separate process from the analyzer, so the analyzer itself
can be firewalled to localhost only.

    python -m analyzer.research refresh [--top 50]   pre-fetch the most common companies
    python -m analyzer.research set-key tavily|exa   store an API key (read from stdin)
    python -m analyzer.research sign-snapshot --key PRIVATE.pem   (release builds)
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

import keyring

from analyzer import topics, trackers
from analyzer.research import egress, research, snapshot
from shared import db
from shared.keystore import SERVICE


def cmd_refresh(args) -> int:
    conn = db.open_db()
    gate = egress.Gate(conn)
    if gate.zero_network():
        print("Zero-network mode is on: nothing was sent.")
        return 0
    clients = research.clients_from_keystore()
    if clients is None:
        print("No Tavily or Exa API key stored; run set-key first.", file=sys.stderr)
        return 1
    model = None
    if db.get_setting(conn, "local_ai", "0") == "1":
        model = topics.ollama_model(db.get_setting(conn, "research_model", "qwen2.5:7b") or "qwen2.5:7b",
                                    timeout=120)
    companies = research.top_companies(conn, args.top)
    n = research.refresh(conn, companies, gate=gate, clients=clients, model=model,
                         tracker_db=trackers.default())
    print(f"Researched {n} companies.")
    return 0


def cmd_set_key(args) -> int:
    name = {"tavily": research.TAVILY_KEY, "exa": research.EXA_KEY}[args.provider]
    value = getpass.getpass(f"{args.provider} API key: ").strip()
    if not value:
        return 1
    keyring.set_password(SERVICE, name, value)
    print("Stored in the system credential store.")
    return 0


def cmd_sign_snapshot(args) -> int:
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    conn = db.open_db()
    companies = {}
    for name, summary, broker, opt_out, news, sources, at, psrc, bsrc in conn.execute(
        "SELECT name, policy_summary, is_data_broker, opt_out_url, news, sources, researched_at, "
        "policy_source, broker_source "
        "FROM companies WHERE from_snapshot = 0"
    ):
        companies[name] = {"policy_summary": summary, "is_data_broker": None if broker is None else bool(broker),
                           "opt_out_url": opt_out, "news": json.loads(news or "[]"),
                           "sources": json.loads(sources or "[]"), "researched_at": at,
                           "policy_source": psrc, "broker_source": bsrc}
    snapshot.write_signed(snapshot.DEFAULT_SNAPSHOT, {"version": 1, "companies": companies}, priv)
    print(f"Signed snapshot with {len(companies)} companies.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="analyzer.research")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("refresh")
    r.add_argument("--top", type=int, default=50)
    k = sub.add_parser("set-key")
    k.add_argument("provider", choices=["tavily", "exa"])
    s = sub.add_parser("sign-snapshot")
    s.add_argument("--key", required=True)
    a = p.parse_args(argv)
    return {"refresh": cmd_refresh, "set-key": cmd_set_key, "sign-snapshot": cmd_sign_snapshot}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())

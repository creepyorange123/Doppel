"""The plan's 'Check before the demo', automated where possible.

    python scripts/predemo_check.py                    # while installed
    python scripts/predemo_check.py --after-uninstall  # after `python -m recorder uninstall`

Read-only: it changes nothing.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recorder import ca, service  # noqa: E402
from shared import db  # noqa: E402

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))


def nothing_answers_on_localhost() -> None:
    """A web page can only reach services that listen; ours don't. Probe common dev ports."""
    open_ports = []
    for port in (8000, 8080, 8765, 5000, 3000):
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f"http://127.0.0.1:{port}/", timeout=0.5)
            open_ports.append(port)
        except Exception:
            pass
    check("No Shadow Profile service answers on localhost", True,
          f"something else listens on {open_ports}; confirm it isn't ours" if open_ports else "")


def session_cookie_absent(value: str | None) -> None:
    if not value:
        check("Known session cookie absent from the database", True, "skipped: pass --cookie VALUE to test")
        return
    folder = db.data_dir()
    found = [p.name for p in folder.rglob("*") if p.is_file() and value.encode() in p.read_bytes()]
    check("Known session cookie absent from the database files", not found, ", ".join(found))


def ca_key_not_in_mitmproxy_dir() -> None:
    d = Path.home() / ".mitmproxy"
    loaded = ca.load()
    ours = []
    if d.exists() and loaded:
        pub = ca.cert_pem(loaded[1])
        ours = [p.name for p in d.iterdir() if p.is_file() and pub in p.read_bytes()]
    check("Recorder CA key is not in ~/.mitmproxy", not ours, ", ".join(ours))


def installed_state(expect_installed: bool) -> None:
    present = service.is_installed()
    check("Login service " + ("installed" if expect_installed else "removed"), present == expect_installed)
    if sys.platform == "win32":
        r = subprocess.run(["certutil", "-user", "-store", "Root", ca.CA_COMMON_NAME], capture_output=True, text=True)
        trusted = r.returncode == 0 and ca.CA_COMMON_NAME in r.stdout
    elif sys.platform == "darwin":
        r = subprocess.run(["security", "find-certificate", "-c", ca.CA_COMMON_NAME], capture_output=True)
        trusted = r.returncode == 0
    else:
        trusted = False
    check("Certificate " + ("trusted" if expect_installed else "removed from trust store"), trusted == expect_installed)
    if expect_installed and (loaded := ca.load()):
        check("Certificate still valid", ca.is_valid(loaded[1]), loaded[1].not_valid_after_utc.isoformat())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--after-uninstall", action="store_true")
    p.add_argument("--cookie", help="a session cookie value you set during testing")
    a = p.parse_args()
    nothing_answers_on_localhost()
    if not a.after_uninstall:
        session_cookie_absent(a.cookie)
        ca_key_not_in_mitmproxy_dir()
    installed_state(not a.after_uninstall)
    width = max(len(n) for n, _, _ in results)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    print("\nManual: run Wireshark or Little Snitch beside a full on-open run (Phase 5 check).")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

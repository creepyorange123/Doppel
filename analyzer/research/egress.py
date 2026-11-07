"""The single door out of the device.

Every network call made by Shadow Profile goes through :class:`Gate`, which:
1. refuses everything in zero-network mode,
2. allows only HTTPS on port 443 to Tavily and Exa,
3. writes the call's payload (never its API key) to the ledger *before* sending.

The OS firewall rules in scripts/firewall/ back this up at the operating-system level.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Callable
from urllib.parse import urlsplit

from analyzer.research import ledger
from shared import db

ALLOWED_HOSTS = frozenset({"api.tavily.com", "api.exa.ai"})
TIMEOUT = 30

Sender = Callable[[str, dict, dict], dict]


class Blocked(RuntimeError):
    pass


def https_post(url: str, body: dict, headers: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # TLS verified by default
        return json.loads(resp.read(5_000_000))


class Gate:
    def __init__(self, conn, sender: Sender | None = None):
        self.conn = conn
        self.sender = sender or https_post

    def zero_network(self) -> bool:
        return db.get_setting(self.conn, "zero_network", "0") == "1"

    def check(self, url: str) -> str:
        if self.zero_network():
            raise Blocked("zero-network mode is on")
        p = urlsplit(url)
        if p.scheme != "https" or p.username or p.password or p.port not in (None, 443):
            raise Blocked("only plain HTTPS on port 443 is allowed")
        host = (p.hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise Blocked(f"{host or 'that host'} is not on the allowlist")
        return host

    def post(self, url: str, body: dict, headers: dict) -> dict:
        host = self.check(url)
        ledger.append(self.conn, host, body)
        return self.sender(url, body, headers)

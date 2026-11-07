"""Map destination domains to the company that owns them and a category.

Data is bundled as a local file (no network calls) and its SHA-256 is checked
against the manifest next to it before use (security checklist #10).
Rebuild from DuckDuckGo Tracker Radar + EasyPrivacy with scripts/build_tracker_db.py.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "shared" / "data"
DEFAULT_PATH = DATA_DIR / "trackers.json"


class IntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Match:
    company: str | None
    category: str | None
    cloaked: bool = False
    matched_domain: str | None = None


class TrackerDB:
    def __init__(self, domains: dict[str, dict]):
        self.domains = {k.lower(): v for k, v in domains.items()}

    def match(self, host: str | None) -> Match | None:
        if not host:
            return None
        parts = host.lower().rstrip(".").split(".")
        for i in range(len(parts) - 1):
            entry = self.domains.get(".".join(parts[i:]))
            if entry:
                return Match(entry.get("company"), entry.get("category"), matched_domain=".".join(parts[i:]))
        return None


def load(path: Path = DEFAULT_PATH, expected_sha256: str | None = None) -> TrackerDB:
    raw = Path(path).read_bytes()
    if expected_sha256 is None:
        manifest = Path(str(path) + ".sha256")
        if not manifest.exists():
            raise IntegrityError(f"missing checksum manifest for {Path(path).name}")
        expected_sha256 = manifest.read_text().split()[0]
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256.lower():
        raise IntegrityError(f"{Path(path).name} does not match its checksum")
    return TrackerDB(json.loads(raw)["domains"])


@lru_cache(maxsize=1)
def default() -> TrackerDB:
    return load()

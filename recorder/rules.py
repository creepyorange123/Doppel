"""Decide, per connection in an audit, whether to record it fully, keep metadata
only, or not record it.

Inputs: the audited app's capture setting (full or metadata only), your domain
rules (``app_rules`` rows of kind 'domain'), and certificate pinning seen during
this audit. Domain rules are reloaded every few seconds, so changes apply to a
running audit.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath

from shared import db

TRACK = "track"
METADATA_ONLY = "metadata_only"
DONT_TRACK = "dont_track"
_STRICTNESS = {TRACK: 0, METADATA_ONLY: 1, DONT_TRACK: 2}

RELOAD_SECONDS = 2.0

# Never recorded, and can't be chosen for an audit.
SYSTEM_PREFIXES_MAC = ("/system/", "/usr/libexec/", "/usr/sbin/")
SYSTEM_PREFIXES_WIN = ("c:\\windows\\",)
SYSTEM_NAMES = frozenset({"system", "idle", "registry", "secure system", "memory compression"})

# Pinned-certificate failures on this many distinct domains switch the app to
# metadata only for the rest of the audit.
PINNING_APP_THRESHOLD = 3


def normalize_app_path(path: str | None, platform: str = sys.platform) -> str | None:
    if not path:
        return None
    if platform == "win32":
        return str(PureWindowsPath(path)).lower()
    return str(PurePosixPath(path))


def app_display_name(path: str | None, platform: str = sys.platform) -> str | None:
    if not path:
        return None
    p = PureWindowsPath(path) if platform == "win32" or "\\" in path else PurePosixPath(path)
    # /Applications/Spotify.app/Contents/MacOS/Spotify -> Spotify
    for part in p.parts:
        if part.endswith(".app"):
            return part[:-4]
    return p.stem or p.name


def is_system_process(path: str | None, name: str | None = None, platform: str = sys.platform) -> bool:
    if name and name.strip().lower() in SYSTEM_NAMES:
        return True
    if not path:
        return False
    lower = path.replace("/", "\\").lower() if platform == "win32" else path
    if platform == "win32":
        return lower.startswith(SYSTEM_PREFIXES_WIN)
    return any(path.lower().startswith(p) for p in SYSTEM_PREFIXES_MAC)


def domain_suffixes(domain: str) -> list[str]:
    """www.bank.example -> [www.bank.example, bank.example, example]"""
    parts = domain.lower().rstrip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def strictest(*rules: str | None) -> str:
    present = [r for r in rules if r]
    return max(present, key=_STRICTNESS.__getitem__) if present else TRACK


@dataclass
class RuleSnapshot:
    domain_rules: dict[str, str] = field(default_factory=dict)

    def decide(self, domain: str | None, base: str = TRACK) -> str:
        domain_rule = None
        if domain:
            for suffix in domain_suffixes(domain):
                if suffix in self.domain_rules:
                    domain_rule = self.domain_rules[suffix]
                    break
        return strictest(base, domain_rule)


class RuleBook:
    """Thread-safe, auto-reloading view of the domain rules, plus pinning seen in this audit."""

    def __init__(self, conn, *, reload_seconds: float = RELOAD_SECONDS):
        self._conn = conn
        self._lock = threading.Lock()
        self._loaded_at = 0.0
        self._reload_seconds = reload_seconds
        self._snapshot = RuleSnapshot()
        self._pinned: set[tuple[str, str]] = set()  # (app key, domain) where the app rejected our certificate
        self._metadata_apps: set[str] = set()       # apps switched to metadata only by pinning

    def snapshot(self) -> RuleSnapshot:
        with self._lock:
            if time.monotonic() - self._loaded_at >= self._reload_seconds:
                self._snapshot = self._load()
                self._loaded_at = time.monotonic()
            return self._snapshot

    def _load(self) -> RuleSnapshot:
        snap = RuleSnapshot()
        for match, rule in self._conn.execute("SELECT match, rule FROM app_rules WHERE kind = 'domain'"):
            if rule in (METADATA_ONLY, DONT_TRACK):
                snap.domain_rules[match.lower().lstrip(".").rstrip(".")] = rule
        return snap

    def decide(self, app_key: str | None, domain: str | None, base: str = TRACK) -> str:
        rule = self.snapshot().decide(domain, base)
        if rule == TRACK and app_key is not None:
            with self._lock:
                if app_key in self._metadata_apps or (domain and (app_key, domain.lower()) in self._pinned):
                    return METADATA_ONLY
        return rule

    def report_pinning_failure(self, app_key: str | None, domain: str) -> bool:
        """Remember that this app rejected our certificate for this domain.

        Returns True when the whole app was just switched to metadata only (for
        the rest of this audit; nothing is saved).
        """
        if app_key is None:
            return False
        with self._lock:
            self._pinned.add((app_key, domain.lower()))
            if app_key in self._metadata_apps:
                return False
            if len({d for k, d in self._pinned if k == app_key}) < PINNING_APP_THRESHOLD:
                return False
            self._metadata_apps.add(app_key)
            return True

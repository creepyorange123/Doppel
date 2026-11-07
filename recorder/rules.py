"""Decide, per connection, whether to track, keep metadata only, or not track.

Inputs: the sending app, the destination domain, the ``app_rules`` table and the
``tracking_mode`` setting. Rules are reloaded from the database every few
seconds, so changes from the app apply without restarting the recorder.
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

# Never logged; their traffic passes through untouched.
SYSTEM_PREFIXES_MAC = ("/system/", "/usr/libexec/", "/usr/sbin/")
SYSTEM_PREFIXES_WIN = ("c:\\windows\\",)
SYSTEM_NAMES = frozenset({"system", "idle", "registry", "secure system", "memory compression"})

# Pinned-certificate failures on this many distinct domains switch the whole
# app to metadata only.
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
    mode: str = "blocklist"
    app_rules: dict[str, str] = field(default_factory=dict)
    domain_rules: dict[str, str] = field(default_factory=dict)
    # Stretch goal from the plan: setting store_raw_content = '0' keeps only flags.
    store_bodies: bool = True
    # Phase 6 actions, applied across all apps.
    block_domains: set[str] = field(default_factory=set)
    strip_domains: set[str] = field(default_factory=set)
    gpc: bool = False

    def _has(self, domains: set[str], host: str | None) -> bool:
        return bool(host) and any(s in domains for s in domain_suffixes(host))

    def blocked(self, host: str | None) -> bool:
        return self._has(self.block_domains, host)

    def stripped(self, host: str | None) -> bool:
        return not self.blocked(host) and self._has(self.strip_domains, host)

    def decide(self, app_path: str | None, app_name: str | None, domain: str | None,
               *, process_known: bool = True) -> str:
        if is_system_process(app_path, app_name):
            return DONT_TRACK

        app_key = normalize_app_path(app_path) or (app_name or "").lower() or None
        app_rule = self.app_rules.get(app_key) if app_key else None
        if app_rule is None and app_name:
            app_rule = self.app_rules.get(app_name.lower())

        if app_rule is None:
            app_rule = DONT_TRACK if self.mode == "allowlist" else TRACK
        if not process_known and app_rule == TRACK and self.mode != "fallback":
            # We could not tell which app sent it: keep metadata only.
            app_rule = METADATA_ONLY

        domain_rule = None
        if domain:
            for suffix in domain_suffixes(domain):
                if suffix in self.domain_rules:
                    domain_rule = self.domain_rules[suffix]
                    break
        return strictest(app_rule, domain_rule)


class RuleBook:
    """Thread-safe, auto-reloading view of the rules in the database."""

    def __init__(self, conn, *, reload_seconds: float = RELOAD_SECONDS, fallback_mode: bool = False):
        self._conn = conn
        self._lock = threading.Lock()
        self._loaded_at = 0.0
        self._reload_seconds = reload_seconds
        self._fallback = fallback_mode
        self._snapshot = RuleSnapshot()
        # (app_key, domain) pairs where the app rejected our certificate.
        self._pinned: set[tuple[str, str]] = set()

    def snapshot(self) -> RuleSnapshot:
        with self._lock:
            if time.monotonic() - self._loaded_at >= self._reload_seconds:
                self._snapshot = self._load()
                self._loaded_at = time.monotonic()
            return self._snapshot

    def _load(self) -> RuleSnapshot:
        mode = db.get_setting(self._conn, "tracking_mode", "blocklist")
        if mode not in ("blocklist", "allowlist"):
            mode = "blocklist"
        snap = RuleSnapshot(
            mode="fallback" if self._fallback and mode == "blocklist" else mode,
            store_bodies=db.get_setting(self._conn, "store_raw_content", "1") != "0",
            gpc=db.get_setting(self._conn, "gpc", "0") == "1",
        )
        for kind, match, rule in self._conn.execute("SELECT kind, match, rule FROM app_rules"):
            if kind == "action":
                d = match.lower().strip(".")
                (snap.block_domains if rule == "block" else snap.strip_domains).add(d)
                continue
            if rule not in _STRICTNESS:
                continue
            if kind == "app":
                snap.app_rules[normalize_app_path(match) or match.lower()] = rule
            elif kind == "domain":
                snap.domain_rules[match.lower().lstrip(".").rstrip(".")] = rule
        return snap

    def decide(self, app_path: str | None, app_name: str | None, domain: str | None,
               *, process_known: bool = True) -> str:
        rule = self.snapshot().decide(app_path, app_name, domain, process_known=process_known)
        if rule == TRACK and domain and self._app_key(app_path, app_name) is not None:
            if (self._app_key(app_path, app_name), domain.lower()) in self._pinned:
                return METADATA_ONLY
        return rule

    @staticmethod
    def _app_key(app_path: str | None, app_name: str | None) -> str | None:
        return normalize_app_path(app_path) or (app_name.lower() if app_name else None)

    def report_pinning_failure(self, app_path: str | None, app_name: str | None, domain: str) -> bool:
        """Remember that this app rejected our certificate for this domain.

        Returns True when the whole app was switched to metadata only.
        """
        key = self._app_key(app_path, app_name)
        if key is None:
            return False
        with self._lock:
            self._pinned.add((key, domain.lower()))
            domains = {d for k, d in self._pinned if k == key}
            if len(domains) < PINNING_APP_THRESHOLD:
                return False
            existing = self._conn.execute(
                "SELECT 1 FROM app_rules WHERE kind = 'app' AND match = ?", (key,)
            ).fetchone()
            if existing:
                return False  # never override a rule the user chose
            self._conn.execute(
                "INSERT INTO app_rules (kind, match, rule, source, updated_at) VALUES ('app', ?, ?, 'auto', ?)",
                (key, METADATA_ONLY, db.now_ms()),
            )
            self._loaded_at = 0.0
            return True

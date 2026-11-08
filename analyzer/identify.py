"""Phase 3: what was sent, and to whom.

- Target: the sending app, plus the owning company and category of the
  destination (bundled tracker map), including trackers disguised as the
  site's own subdomain (CNAME cloaking).
- Content: capture-time flags, plus matching hashed emails / phone numbers
  against your own, which live only in the OS credential store.
- Topic: IAB category of the page or app.
- A one-line plain-English summary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Callable

import keyring

from analyzer import datatypes, topics, trackers
from shared.keystore import SERVICE, keyed_hash

PERSONAL_IDS_KEY = "personal-ids"  # JSON {"emails": [...], "phones": [...]} in the credential store

CATEGORY_PHRASES = {
    "Advertising": "an ad company",
    "Ad Motivated Tracking": "an ad-tracking company",
    "Analytics": "an analytics company",
    "Audience Measurement": "an audience-measurement company",
    "Session Replay": "a session-recording company",
    "Social Network": "a social network",
    "Social - Share": "a social-sharing company",
    "Data Broker": "a data broker",
    "Fingerprinting": "a device-fingerprinting company",
    "Tag Manager": "a tag manager",
    "CDN": "a content-delivery network",
    "Embedded Content": "an embedded-content provider",
    "First party": "the site itself",
}

FLAG_PHRASES = {
    # Sensitive data inside the payload (analyzer/datatypes.py), most serious first.
    "data_health": "health information",
    "data_sexuality": "information about sexuality",
    "data_religion": "religious information",
    "data_children": "information about children",
    "data_politics": "political information",
    "data_ethnicity": "information about ethnicity",
    "data_finance": "banking or financial details",
    "data_personal": "personal details (name, birth date, address, gender or ID number)",
    "data_location": "your precise location",
    "raw_email": "your email address",
    "hashed_email": "a hash of your email address",
    "hashed_phone": "a hash of your phone number",
    "tracking_id": "an ID that can follow you across sites",
    "page_url": "the page you were reading",
    "fingerprinting": "details that fingerprint your device",
    "behavioural_events": "your mouse and keyboard activity",
    "email_address": "an email address",
    "hashed_identifier": "a hashed identifier",
}
FLAG_ORDER = list(FLAG_PHRASES)


# ------------------------------------------------------------------ personal ids

def _email_variants(email: str) -> list[str]:
    e = email.strip().lower()
    return [e]


def _phone_variants(phone: str) -> list[str]:
    digits = re.sub(r"\D", "", phone)
    out = {digits, "+" + digits}
    if len(digits) == 11 and digits.startswith("1"):
        out |= {digits[1:]}
    return sorted(out)


def _hex_hashes(value: str) -> list[str]:
    b = value.encode()
    return [hashlib.md5(b).hexdigest(), hashlib.sha1(b).hexdigest(), hashlib.sha256(b).hexdigest()]


@dataclass
class PersonalIds:
    """Keyed hashes of your own identifiers in every form trackers send them."""

    raw_email: set[str] = field(default_factory=set)
    hashed_email: set[str] = field(default_factory=set)
    hashed_phone: set[str] = field(default_factory=set)

    @classmethod
    def from_values(cls, emails: list[str], phones: list[str], hmac_key: bytes) -> "PersonalIds":
        ids = cls()
        for e in emails:
            for v in _email_variants(e):
                ids.raw_email.add(keyed_hash(v, hmac_key))
                ids.hashed_email |= {keyed_hash(h, hmac_key) for h in _hex_hashes(v)}
        for p in phones:
            for v in _phone_variants(p):
                ids.hashed_phone |= {keyed_hash(h, hmac_key) for h in _hex_hashes(v)}
        return ids

    @classmethod
    def from_keystore(cls, hmac_key: bytes) -> "PersonalIds":
        raw = keyring.get_password(SERVICE, PERSONAL_IDS_KEY)
        data = json.loads(raw) if raw else {}
        return cls.from_values(data.get("emails", []), data.get("phones", []), hmac_key)


def save_personal_ids(emails: list[str], phones: list[str]) -> None:
    """Security checklist #13: kept in the credential store, never in the database."""
    keyring.set_password(SERVICE, PERSONAL_IDS_KEY, json.dumps({"emails": emails, "phones": phones}))


# ----------------------------------------------------------------------- target

def registrable_domain(host: str | None) -> str | None:
    if not host:
        return None
    parts = host.lower().rstrip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def match_target(db: trackers.TrackerDB, host: str, page_site: str | None,
                 resolve_cname: Callable[[str], str | None] | None) -> trackers.Match:
    m = db.match(host)
    if m:
        return m
    if page_site and registrable_domain(host) == registrable_domain(page_site):
        if resolve_cname is not None:
            try:
                target = resolve_cname(host)
            except Exception:
                target = None
            if target:
                cm = db.match(target)
                if cm:
                    return trackers.Match(cm.company, cm.category, cloaked=True, matched_domain=cm.matched_domain)
        return trackers.Match(None, "First party")
    return trackers.Match(None, None)


def dns_cname_resolver() -> Callable[[str], str | None] | None:
    """CNAME lookups via dnspython when available. Off in zero-network mode."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None

    def resolve(host: str) -> str | None:
        try:
            ans = dns.resolver.resolve(host, "CNAME", lifetime=2)
            return str(ans[0].target).rstrip(".")
        except Exception:
            return None

    return resolve


# ---------------------------------------------------------------------- content

@dataclass
class Context:
    conn: object
    hmac_key: bytes
    personal: PersonalIds
    topic_model: topics.Model | None
    tracker_db: trackers.TrackerDB = field(default_factory=trackers.default)
    resolve_cname: Callable[[str], str | None] | None = None
    _topic_cache: topics.TopicCache | None = None
    _detector: datatypes.Detector | None = None

    @property
    def topic_cache(self) -> topics.TopicCache:
        if self._topic_cache is None:
            self._topic_cache = topics.TopicCache(self.conn, self.hmac_key)
        return self._topic_cache

    @property
    def detector(self) -> datatypes.Detector:
        """Sensitive data types in payloads; uses the same local model as topics."""
        if self._detector is None:
            self._detector = datatypes.Detector(self.conn, self.hmac_key, self.topic_model)
        return self._detector


def classify_flags(raw_flags: list[dict], personal: PersonalIds) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(flag: str, where: str, h: str | None = None) -> None:
        if (flag, where) in seen:
            return
        seen.add((flag, where))
        entry = {"flag": flag, "where": where}
        if h:
            entry["hmac"] = h
        out.append(entry)

    for f in raw_flags:
        name, where, h = f.get("flag"), f.get("where", ""), f.get("hmac")
        if name == "hashed_identifier":
            if h in personal.hashed_email:
                add("hashed_email", where)
            elif h in personal.hashed_phone:
                add("hashed_phone", where)
            else:
                add("tracking_id", where, h)
        elif name == "email_address":
            add("raw_email" if h in personal.raw_email else "email_address", where)
        elif name == "long_id":
            add("tracking_id", where, h)
        elif name in ("page_url", "fingerprinting", "behavioural_events"):
            add(name, where)
        else:
            add(name, where)  # notes such as certificate_pinned, login_body_removed
    return out


def summarize(company: str | None, category: str | None, flags: list[dict], metadata_only: bool,
              dest: str, cloaked: bool = False) -> str:
    who = CATEGORY_PHRASES.get(category or "", None)
    if who and company:
        target = f"{who} ({company})"
    elif company:
        target = company
    elif who:
        target = who
    else:
        target = dest
    if cloaked:
        target += ", disguised as the site's own address"
    if metadata_only:
        return f"Sent to {target} (content not recorded)."
    kinds = {f["flag"] for f in flags}
    pieces = [FLAG_PHRASES[k] for k in FLAG_ORDER if k in kinds]
    if not pieces:
        return f"Sent to {target}: nothing identifying found."
    if len(pieces) == 1:
        body = pieces[0]
    else:
        body = pieces[0] + ", plus " + (" and ".join(pieces[1:]) if len(pieces) == 2 else ", ".join(pieces[1:-1]) + " and " + pieces[-1])
    return f"Sent to {target}: {body}."


@dataclass
class Finding:
    company: str | None
    category: str | None
    flags: list[dict]
    topic: str
    summary: str
    cloaked: bool = False


def identify(ctx: Context, row: dict) -> Finding:
    target = match_target(ctx.tracker_db, row["dest_domain"], row.get("page_site"), ctx.resolve_cname)
    try:
        raw_flags = json.loads(row.get("flags") or "[]")
    except json.JSONDecodeError:
        raw_flags = []
    flags = classify_flags(raw_flags, ctx.personal)
    if target.cloaked:
        flags.append({"flag": "cname_cloaked", "where": "dest"})
    if not row.get("metadata_only"):
        # Only the category and field name are kept; the AI is used only for known trackers.
        flags += ctx.detector.flags(row.get("body"), row.get("url"), ai_allowed=target.company is not None)
    topic = ctx.topic_cache.get_or_classify(topics.topic_input(row), ctx.topic_model)
    summary = summarize(target.company, target.category, flags, bool(row.get("metadata_only")),
                        row["dest_domain"], target.cloaked)
    return Finding(target.company, target.category, flags, topic, summary, target.cloaked)


def make_step(ctx: Context):
    def step(conn, row: dict) -> None:
        f = identify(ctx, row)
        conn.execute(
            "INSERT OR REPLACE INTO findings (request_id, company, category, flags, topic, summary) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (row["id"], f.company, f.category, json.dumps(f.flags, separators=(",", ":")), f.topic, f.summary),
        )
        row["_finding"] = f  # for the scoring step that follows

    return step

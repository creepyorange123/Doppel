"""Signed research snapshot shipped inside the app (security checklist #10).

Format: {"data": {...}, "signature": "<base64 Ed25519 over canonical JSON of data>"}.
The public key is bundled; the private key is kept by whoever builds releases,
never in the repo. Used for profile cards in zero-network mode.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from shared import db

DATA_DIR = Path(__file__).resolve().parents[2] / "shared" / "data"
DEFAULT_SNAPSHOT = DATA_DIR / "research_snapshot.json"
DEFAULT_PUBKEY = DATA_DIR / "snapshot_public_key.pem"


class BadSignature(RuntimeError):
    pass


def _canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def write_signed(path: Path, data: dict, priv: Ed25519PrivateKey) -> None:
    sig = base64.b64encode(priv.sign(_canonical(data))).decode()
    Path(path).write_text(json.dumps({"data": data, "signature": sig}, indent=1, sort_keys=True) + "\n",
                          encoding="utf-8", newline="\n")


def load_public_key(path: Path = DEFAULT_PUBKEY) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise BadSignature("snapshot key must be Ed25519")
    return key


def load_verified(path: Path = DEFAULT_SNAPSHOT, pub: Ed25519PublicKey | None = None) -> dict:
    pub = pub or load_public_key()
    try:
        wrapper = json.loads(Path(path).read_text(encoding="utf-8"))
        pub.verify(base64.b64decode(wrapper["signature"]), _canonical(wrapper["data"]))
    except (InvalidSignature, KeyError, ValueError, TypeError) as exc:
        raise BadSignature(f"{Path(path).name} failed signature check") from exc
    return wrapper["data"]


def import_into(conn, data: dict) -> int:
    """Load snapshot companies, never overwriting fresher live research."""
    n = 0
    for name, c in (data.get("companies") or {}).items():
        conn.execute(
            "INSERT INTO companies (name, policy_summary, is_data_broker, opt_out_url, news, sources, policy_source, "
            "broker_source, researched_at, from_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(name) DO UPDATE SET policy_summary=excluded.policy_summary, is_data_broker=excluded.is_data_broker, "
            "opt_out_url=excluded.opt_out_url, news=excluded.news, sources=excluded.sources, "
            "policy_source=excluded.policy_source, broker_source=excluded.broker_source, "
            "researched_at=excluded.researched_at, from_snapshot=1 WHERE companies.from_snapshot = 1",
            (name, c.get("policy_summary"), None if c.get("is_data_broker") is None else int(c["is_data_broker"]),
             c.get("opt_out_url"), json.dumps(c.get("news") or []), json.dumps(c.get("sources") or []),
             c.get("policy_source"), c.get("broker_source"), c.get("researched_at") or db.now_ms()),
        )
        n += 1
    return n

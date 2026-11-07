"""Build the analysis steps from settings when the analyzer starts."""

from __future__ import annotations

from analyzer import identify, topics
from shared import db, keystore


def build_steps(conn) -> list:
    hmac_key = keystore.hmac_key()
    zero_network = db.get_setting(conn, "zero_network", "0") == "1"
    model = None
    if db.get_setting(conn, "local_ai", "0") == "1":
        model = topics.ollama_model(db.get_setting(conn, "topic_model", "qwen2.5:3b") or "qwen2.5:3b")
    ctx = identify.Context(
        conn,
        hmac_key=hmac_key,
        personal=identify.PersonalIds.from_keystore(hmac_key),
        topic_model=model,
        resolve_cname=None if zero_network else identify.dns_cname_resolver(),
    )
    return [identify.make_step(ctx)]

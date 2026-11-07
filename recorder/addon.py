"""mitmproxy addon: decide, sanitize and write every request to the encrypted log."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any

from mitmproxy import ctx, http, tls, udp
from mitmproxy.connection import Client

from recorder import procinfo, rules, sanitize
from recorder.procinfo import AppInfo
from shared import db
from shared.keystore import keyed_hash

log = logging.getLogger("shadow.recorder")

HEARTBEAT_SECONDS = 30
FLUSH_SECONDS = 1.0


class Writer(threading.Thread):
    """Single writer thread so database work never blocks the proxy's event loop."""

    def __init__(self, conn):
        super().__init__(name="shadow-writer", daemon=True)
        self.conn = conn
        self.q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=100_000)
        self._last_heartbeat = 0.0
        self.written = 0

    def put(self, row: dict[str, Any]) -> None:
        try:
            self.q.put_nowait(row)
        except queue.Full:
            log.warning("write queue full; dropping a row")

    def stop(self) -> None:
        self.q.put(None)
        self.join(timeout=10)

    def run(self) -> None:
        while True:
            batch: list[dict[str, Any]] = []
            try:
                item = self.q.get(timeout=FLUSH_SECONDS)
                if item is None:
                    break
                batch.append(item)
                while len(batch) < 500:
                    item = self.q.get_nowait()
                    if item is None:
                        self._flush(batch)
                        return self._finish()
                    batch.append(item)
            except queue.Empty:
                pass
            self._flush(batch)
            if time.monotonic() - self._last_heartbeat > HEARTBEAT_SECONDS:
                self.heartbeat()
        self._finish()

    def _finish(self) -> None:
        self.heartbeat()
        db.checkpoint_truncate(self.conn)

    def heartbeat(self) -> None:
        try:
            db.set_setting(self.conn, "recorder_heartbeat_at", str(db.now_ms()))
        except Exception:
            log.warning("heartbeat failed")
        self._last_heartbeat = time.monotonic()

    def _flush(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        cols = ("captured_at", "app_name", "app_path", "page_site", "page_url", "dest_domain", "method",
                "url", "status", "headers", "cookies", "body", "body_truncated", "size_bytes", "flags",
                "metadata_only")
        sql = f"INSERT INTO requests ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
        try:
            self.conn.execute("BEGIN")
            self.conn.executemany(sql, [tuple(r.get(c) for c in cols) for r in batch])
            self.conn.execute("COMMIT")
            self.written += len(batch)
        except Exception as exc:
            self.conn.execute("ROLLBACK")
            log.warning("write failed: %s", type(exc).__name__)


def _json(v: Any) -> str | None:
    return None if v is None else json.dumps(v, separators=(",", ":"))


class ShadowRecorder:
    """The addon. ``ca_ready`` False means TLS is never intercepted (metadata only)."""

    def __init__(self, rulebook: rules.RuleBook, writer: Writer, hmac_key: bytes, *, ca_ready: bool):
        self.rules = rulebook
        self.writer = writer
        self.hmac_key = hmac_key
        self.ca_ready = ca_ready
        self.apps: dict[str, AppInfo] = {}
        self.decisions: dict[str, str] = {}

    # ------------------------------------------------------------------ helpers

    def hasher(self, value: str) -> str:
        return keyed_hash(value, self.hmac_key)

    def app_for(self, client: Client) -> AppInfo:
        return self.apps.get(client.id, procinfo.UNKNOWN)

    def decide(self, client: Client, domain: str | None) -> str:
        app = self.app_for(client)
        return self.rules.decide(app.path, app.name, domain, process_known=app.known)

    def metadata_row(self, client: Client, domain: str, flags: list[dict[str, str]] | None = None,
                     size: int | None = None) -> None:
        app = self.app_for(client)
        self.writer.put({
            "captured_at": db.now_ms(), "app_name": app.name or "Unknown app", "app_path": app.path,
            "dest_domain": domain.lower(), "size_bytes": size, "flags": _json(flags or []),
            "metadata_only": 1, "body_truncated": 0,
        })

    # -------------------------------------------------------------------- hooks

    def configure(self, updated) -> None:
        # Security checklist #11: upstream certificates are always verified.
        if ctx.options.ssl_insecure:
            raise RuntimeError("ssl_insecure must never be enabled")

    def client_connected(self, client: Client) -> None:
        self.apps[client.id] = procinfo.take(client.peername)

    def client_disconnected(self, client: Client) -> None:
        self.apps.pop(client.id, None)
        self.decisions.pop(client.id, None)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        client = data.context.client
        sni = data.client_hello.sni or (data.context.server.address[0] if data.context.server.address else "")
        decision = self.decide(client, sni)
        if decision == rules.TRACK and not self.ca_ready:
            decision = rules.METADATA_ONLY
        self.decisions[client.id] = decision
        snap = self.rules.snapshot()
        if decision == rules.TRACK:
            return
        if self.ca_ready and (snap.blocked(sni) or snap.stripped(sni)):
            # Decrypt only to enforce your block/strip choice; content is still
            # not stored beyond what this app's rule allows.
            return
        # Not decrypted: the connection passes through untouched.
        data.ignore_connection = True
        if decision == rules.METADATA_ONLY and sni and not sanitize.is_search_suggestion(sni, "/"):
            self.metadata_row(client, sni)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        # The app rejected our certificate: most likely certificate pinning.
        client = data.context.client
        sni = client.sni or ""
        if not sni:
            return
        app = self.app_for(client)
        switched = self.rules.report_pinning_failure(app.path, app.name, sni)
        flags = [{"flag": "certificate_pinned", "where": "tls"}]
        if switched:
            flags.append({"flag": "app_switched_to_metadata_only", "where": "tls"})
        self.metadata_row(client, sni, flags)

    def next_layer(self, nextlayer) -> None:
        # HTTP/3 (QUIC): replace with a raw UDP layer so udp_start can block it,
        # making the app fall back to regular HTTPS, which we can record.
        from mitmproxy.proxy import layers

        context = nextlayer.context
        addr = context.server.address
        if context.client.transport_protocol == "udp" and addr and addr[1] == 443:
            nextlayer.layer = layers.UDPLayer(context)

    def udp_start(self, flow: udp.UDPFlow) -> None:
        addr = flow.server_conn.address
        if addr and addr[1] == 443:
            decision = self.decide(flow.client_conn, None)
            if decision != rules.DONT_TRACK:
                self.metadata_row(flow.client_conn, str(addr[0]), [{"flag": "quic_blocked", "where": "udp"}])
            flow.kill()

    def request(self, flow: http.HTTPFlow) -> None:
        """Phase 6 actions, applied before anything is sent upstream."""
        host = (flow.request.pretty_host or "").lower()
        snap = self.rules.snapshot()
        if snap.blocked(host):
            flow.metadata["shadow_blocked"] = True
            flow.response = http.Response.make(204)
            return
        if snap.stripped(host):
            flow.metadata["shadow_stripped"] = True
            flow.request.headers.pop("cookie", None)
            for name in list(flow.request.headers.keys()):
                if sanitize.SENSITIVE_HEADER_RE.search(name) and name.lower() not in ("authorization",):
                    flow.request.headers.pop(name, None)
            q = flow.request.query
            for key in list(q.keys()):
                value = q.get(key, "")
                if sanitize.looks_like_id(value) or sanitize.HEX_HASH_RE.match(value) or sanitize.EMAIL_RE.match(value):
                    del q[key]
        if snap.gpc:
            flow.request.headers["Sec-GPC"] = "1"

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            self._record(flow)

    # ------------------------------------------------------------------- record

    def _record(self, flow: http.HTTPFlow) -> None:
        try:
            self._record_inner(flow)
        except Exception as exc:  # never let a bad request break the proxy
            log.warning("could not record a request: %s", type(exc).__name__)

    def _record_inner(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        client = flow.client_conn
        host = (req.pretty_host or req.host or "").lower()
        decision = self.decide(client, host)
        if decision == rules.DONT_TRACK:
            return
        if sanitize.is_search_suggestion(host, req.path):
            return
        if flow.metadata.get("shadow_blocked"):
            self.metadata_row(client, host, [{"flag": "blocked_by_you", "where": "recorder"}])
            return

        size = len(req.raw_content or b"") + (len(flow.response.raw_content or b"") if flow.response else 0)
        if decision == rules.METADATA_ONLY:
            self.metadata_row(client, host, size=size)
            return

        try:
            body = req.get_content(strict=False)
        except Exception:
            body = None
        stored = sanitize.sanitize_request(
            sanitize.RawRequest(
                method=req.method, url=req.pretty_url, host=host, path=req.path,
                headers=list(req.headers.items(multi=True)), body=body,
                response_headers=list(flow.response.headers.items(multi=True)) if flow.response else [],
            ),
            self.hasher,
        )
        if stored is None:
            return
        if not self.rules.snapshot().store_bodies:
            stored.body = None
        if flow.metadata.get("shadow_stripped"):
            stored.flags.append({"flag": "identifiers_stripped", "where": "recorder"})

        app = self.app_for(client)
        self.writer.put({
            "captured_at": int((req.timestamp_start or time.time()) * 1000),
            "app_name": app.name or "Unknown app", "app_path": app.path,
            "page_site": stored.page_site, "page_url": stored.page_url,
            "dest_domain": stored.dest_domain, "method": stored.method, "url": stored.url,
            "status": flow.response.status_code if flow.response else None,
            "headers": _json(stored.headers), "cookies": _json(stored.cookies),
            "body": stored.body, "body_truncated": int(stored.body_truncated),
            "size_bytes": size, "flags": _json(stored.flags), "metadata_only": 0,
        })

"""mitmproxy addon for one audit: attribute, sanitize and write each request from
the audited apps to the encrypted log.

The redirector already sends only the audited apps' connections here (see
recorder/scope.py). As a second line of defence, a connection that can't be tied
to an audited app passes through untouched and is never recorded.

Audits observe; they never change traffic (no blocking, stripping or added headers).
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any

import sqlcipher3
from mitmproxy import ctx, http, tls, udp
from mitmproxy.connection import Client

from recorder import procinfo, rules, sanitize
from recorder.procinfo import AppInfo
from recorder.scope import Scope, process_label
from shared import db
from shared.audits import AuditApp
from shared.keystore import keyed_hash

log = logging.getLogger("shadow.recorder")

HEARTBEAT_SECONDS = 30
FLUSH_SECONDS = 1.0
# With the 10 s busy timeout per attempt, a write waits well over a minute for the
# analyzer before giving up.
WRITE_ATTEMPTS = 6
RETRY_DELAY = 1.0


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
        cols = ("audit_id", "captured_at", "app_name", "app_path", "process_name", "page_site", "page_url", "dest_domain", "method",
                "url", "status", "headers", "cookies", "body", "body_truncated", "size_bytes", "flags",
                "metadata_only")
        sql = f"INSERT INTO requests ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
        rows = [tuple(r.get(c) for c in cols) for r in batch]
        for attempt in range(WRITE_ATTEMPTS):
            began = False
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                began = True
                self.conn.executemany(sql, rows)
                self.conn.execute("COMMIT")
                self.written += len(batch)
                return
            except sqlcipher3.OperationalError as exc:
                if began:
                    self.conn.execute("ROLLBACK")
                if "locked" not in str(exc) and "busy" not in str(exc):
                    log.warning("write failed: %s", type(exc).__name__)
                    return
                # The analyzer holds the write lock for a batch; wait and retry, don't drop.
                time.sleep(RETRY_DELAY * (attempt + 1))
            except Exception as exc:
                if began:
                    self.conn.execute("ROLLBACK")
                log.warning("write failed: %s", type(exc).__name__)
                return
        log.warning("write failed after retries; %d rows dropped", len(batch))


# Dropped handshakes to one site, with no success in between, before we treat
# them as certificate pinning.
DISCONNECT_THRESHOLD = 3


def classify_tls_failure(error: str | None) -> str:
    """mitmproxy's client TLS error -> "rejected" | "disconnected" | "other".

    Only "rejected" (the client sent a bad-certificate / unknown-CA alert) is
    certain. "disconnected" is usually a browser abandoning a spare connection.
    """
    e = (error or "").lower()
    if "does not trust the proxy's certificate" in e and "may not trust" not in e and "disconnected" not in e:
        return "rejected"
    if "disconnected during the handshake" in e:
        return "disconnected"
    return "other"


def _json(v: Any) -> str | None:
    return None if v is None else json.dumps(v, separators=(",", ":"))


class ShadowRecorder:
    """The addon. ``ca_ready`` False means TLS is never intercepted (metadata only)."""

    def __init__(self, scope: Scope, rulebook: rules.RuleBook, writer: Writer, hmac_key: bytes, *,
                 audit_id: int, ca_ready: bool, devlog=None):
        self.scope = scope
        self.rules = rulebook
        self.audit_id = audit_id
        self.devlog = devlog  # recorder.devlog.TrafficLog, development only; None in normal use
        self.writer = writer
        self.hmac_key = hmac_key
        self.ca_ready = ca_ready
        self.apps: dict[str, AppInfo] = {}
        self.targets: dict[str, AuditApp | None] = {}
        self.decisions: dict[str, str] = {}
        self.tls_ok: set[tuple[str, str]] = set()          # (process, site) handshakes that succeeded
        self.disconnects: dict[tuple[str, str], int] = {}  # dropped handshakes, see tls_failed_client

    # ------------------------------------------------------------------ helpers

    def hasher(self, value: str) -> str:
        return keyed_hash(value, self.hmac_key)

    def app_for(self, client: Client) -> AppInfo:
        return self.apps.get(client.id, procinfo.UNKNOWN)

    def target_for(self, client: Client) -> AuditApp | None:
        return self.targets.get(client.id)

    @staticmethod
    def _key(target: AuditApp) -> str:
        return target.path or target.name

    def decide(self, client: Client, domain: str | None) -> str:
        target = self.target_for(client)
        if target is None:
            return rules.DONT_TRACK
        app = self.app_for(client)
        if rules.is_system_process(app.path, app.name):
            return rules.DONT_TRACK
        base = rules.METADATA_ONLY if target.capture == "metadata_only" else rules.TRACK
        return self.rules.decide(self._key(target), domain, base)

    def _who(self, client: Client) -> dict[str, Any]:
        target = self.target_for(client)
        app = self.app_for(client)
        return {"audit_id": self.audit_id, "app_name": target.name if target else "Unknown app",
                "app_path": target.path if target else None,
                "process_name": process_label(app.path) or app.name or (target.name if target else None)}

    def metadata_row(self, client: Client, domain: str, flags: list[dict[str, str]] | None = None,
                     size: int | None = None) -> None:
        if not domain or sanitize.is_ip_literal(domain):
            return  # no hostname: nothing useful to say about the recipient
        self.writer.put({
            **self._who(client), "captured_at": db.now_ms(),
            "dest_domain": domain.lower(), "size_bytes": size, "flags": _json(flags or []),
            "metadata_only": 1, "body_truncated": 0,
        })

    # -------------------------------------------------------------------- hooks

    def running(self) -> None:
        """Servers are up: install the real process filter (paths can't go in the mode string)."""
        set_intercept(self.scope.spec())

    def configure(self, updated) -> None:
        # Security checklist #11: upstream certificates are always verified.
        if ctx.options.ssl_insecure:
            raise RuntimeError("ssl_insecure must never be enabled")

    def client_connected(self, client: Client) -> None:
        info = procinfo.take(client.peername)
        self.apps[client.id] = info
        self.targets[client.id] = self.scope.target_for(info.pid, info.path)

    def client_disconnected(self, client: Client) -> None:
        self.apps.pop(client.id, None)
        self.targets.pop(client.id, None)
        self.decisions.pop(client.id, None)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        client = data.context.client
        sni = data.client_hello.sni or (data.context.server.address[0] if data.context.server.address else "")
        decision = self.decide(client, sni)
        if decision == rules.TRACK and not self.ca_ready:
            decision = rules.METADATA_ONLY
        self.decisions[client.id] = decision
        if self.devlog:
            self.devlog.write("TLS", self.app_for(client).name, decision, sni)
        if decision == rules.TRACK:
            return
        # Not decrypted: the connection passes through untouched.
        data.ignore_connection = True
        if (decision == rules.METADATA_ONLY and sni and not sanitize.is_search_suggestion(sni, "/")
                and not sanitize.is_doh_host(sni)):
            self.metadata_row(client, sni)

    def _tls_key(self, client: Client) -> tuple[str, str] | None:
        sni = (client.sni or "").lower()
        app = self.app_for(client)
        who = app.path or app.name or (str(app.pid) if app.pid else None)
        return (who, sni) if sni and who else None

    def tls_established_client(self, data: tls.TlsData) -> None:
        # This app accepted our certificate for this site, so later dropped
        # handshakes to it are ordinary connection churn, not pinning.
        key = self._tls_key(data.context.client)
        if key:
            if len(self.tls_ok) > 50_000:
                self.tls_ok.clear()
            self.tls_ok.add(key)
            self.disconnects.pop(key, None)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        client = data.context.client
        sni = client.sni or ""
        if not sni:
            return
        kind = classify_tls_failure(getattr(client, "error", None))
        if self.devlog:
            self.devlog.write("TLS-FAIL", self.app_for(client).name, self.decisions.get(client.id), sni, note=kind)
        if kind == "disconnected":
            # Browsers abandon handshakes constantly. Only repeated drops to a site
            # this app has never completed a handshake with look like pinning.
            key = self._tls_key(client)
            if key is None or key in self.tls_ok:
                return
            self.disconnects[key] = self.disconnects.get(key, 0) + 1
            if self.disconnects[key] < DISCONNECT_THRESHOLD:
                return
        elif kind != "rejected":
            return
        # The app rejected our certificate: most likely certificate pinning.
        target = self.target_for(client)
        if target is None:
            return
        switched = self.rules.report_pinning_failure(self._key(target), sni)
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
        # HTTP/3 is refused so the app retries over regular HTTPS, which is recorded
        # with its hostname. The refused attempt itself is not stored (it has only an IP).
        addr = flow.server_conn.address
        if addr and addr[1] == 443:
            if self.devlog:
                self.devlog.write("QUIC", self.app_for(flow.client_conn).name, self.decide(flow.client_conn, None),
                                  str(addr[0]), note="blocked")
            flow.kill()

    def response(self, flow: http.HTTPFlow) -> None:
        self._record(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            self._record(flow)

    # ------------------------------------------------------------------- record

    def _record(self, flow: http.HTTPFlow) -> None:
        if self.devlog:
            try:
                self._devlog_http(flow)
            except Exception as exc:
                log.warning("dev traffic log failed: %s", type(exc).__name__)
        try:
            self._record_inner(flow)
        except Exception as exc:  # never let a bad request break the proxy
            log.warning("could not record a request: %s", type(exc).__name__)

    def _devlog_http(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = (req.pretty_host or req.host or "").lower()
        notes = []
        if flow.error:
            notes.append(f"error: {flow.error.msg}")
        self.devlog.write("HTTP", self.app_for(flow.client_conn).name, self.decide(flow.client_conn, host),
                          req.pretty_url, method=req.method,
                          status=flow.response.status_code if flow.response else "", note="; ".join(notes))

    def _record_inner(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        client = flow.client_conn
        host = (req.pretty_host or req.host or "").lower()
        decision = self.decide(client, host)
        if decision == rules.DONT_TRACK:
            return
        if sanitize.is_search_suggestion(host, req.path) or sanitize.is_ip_literal(host):
            return
        if sanitize.is_dns_over_https(host, req.path, list(req.headers.items(multi=True))):
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

        self.writer.put({
            **self._who(client),
            "captured_at": int((req.timestamp_start or time.time()) * 1000),
            "page_site": stored.page_site, "page_url": stored.page_url,
            "dest_domain": stored.dest_domain, "method": stored.method, "url": stored.url,
            "status": flow.response.status_code if flow.response else None,
            "headers": _json(stored.headers), "cookies": _json(stored.cookies),
            "body": stored.body, "body_truncated": int(stored.body_truncated),
            "size_bytes": size, "flags": _json(stored.flags), "metadata_only": 0,
        })


def set_intercept(spec: str) -> None:
    """Point the running local redirector at exactly these processes."""
    from mitmproxy.proxy import mode_servers

    server = mode_servers.LocalRedirectorInstance._server
    if server is not None:
        server.set_intercept(spec)

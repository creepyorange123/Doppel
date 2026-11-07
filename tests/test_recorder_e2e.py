"""End-to-end: real mitmproxy (system-proxy fallback mode, 127.0.0.1 only) with
our in-memory CA, a local HTTPS server, and the encrypted log.

Uses only throwaway keys and certificates; nothing touches the OS trust store
or credential store.
"""

import asyncio
import datetime as dt
import http.server
import json
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from recorder import ca
from recorder.__main__ import build_master
from shared import db

SESSION = "s3ss10n-SECRET-value-9f8e7d6c5b4a"
PASSWORD = "hunter2-correct-horse"
SEARCH = "embarrassing-search-term"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def leaf_for(ca_key, ca_cert, host="localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


class Handler(http.server.BaseHTTPRequestHandler):
    def _ok(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Set-Cookie", f"sid={SESSION}; HttpOnly")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = _ok

    def log_message(self, *a):
        pass


def https_server(tmp: Path, key, cert, name: str):
    kf, cf = tmp / f"{name}.key", tmp / f"{name}.crt"
    kf.write_bytes(ca.key_pem(key))
    cf.write_bytes(ca.cert_pem(cert))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", free_port()), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf, kf)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOW_DATA_DIR", str(tmp_path / "data"))
    db_key, hmac_key = secrets.token_bytes(32), secrets.token_bytes(32)
    db_path = tmp_path / "data" / "shadow.db"

    # Upstream server certificate from a separate "public" CA mitmproxy trusts.
    up_ca_key, up_ca_cert = ca.generate()
    up_ca_file = tmp_path / "upstream-ca.crt"
    up_ca_file.write_bytes(ca.cert_pem(up_ca_cert))
    good = https_server(tmp_path, *leaf_for(up_ca_key, up_ca_cert), "good")
    # A server whose certificate nobody trusts (security checklist #11).
    bad_key, bad_cert = leaf_for(*ca.generate())
    bad = https_server(tmp_path, bad_key, bad_cert, "bad")

    mitm_key, mitm_cert = ca.generate()
    mitm_ca_file = tmp_path / "mitm-ca.crt"
    mitm_ca_file.write_bytes(ca.cert_pem(mitm_cert))
    port = free_port()
    state = {}

    def run_proxy():
        async def main():
            master, writer = build_master(
                fallback_port=port, ca_material=(mitm_key, mitm_cert), data_dir=db.data_dir(),
                db_path=db_path, db_key=db_key, hmac_key=hmac_key,
            )
            master.options.update(ssl_verify_upstream_trusted_ca=str(up_ca_file))
            state["master"], state["writer"] = master, writer
            writer.start()
            await master.run()
        asyncio.run(main())

    t = threading.Thread(target=run_proxy, daemon=True)
    t.start()
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    client_ctx = ssl.create_default_context(cafile=str(mitm_ca_file))
    # Also trust the upstream CA, so connections we pass through untouched
    # (dont_track / metadata_only) still succeed.
    client_ctx.load_verify_locations(cafile=str(up_ca_file))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{port}"}),
        urllib.request.HTTPSHandler(context=client_ctx),
    )
    yield {"opener": opener, "good": good, "bad": bad, "state": state, "db_path": db_path,
           "db_key": db_key, "data_dir": tmp_path / "data", "thread": t}
    if t.is_alive():
        state["master"].shutdown()
        t.join(timeout=10)
    if state["writer"].is_alive():
        state["writer"].stop()
    good.shutdown()
    bad.shutdown()


def stop_and_read(env):
    env["state"]["master"].shutdown()
    env["thread"].join(timeout=10)
    env["state"]["writer"].stop()
    conn = db.connect(env["db_path"], env["db_key"])
    conn.row_factory = None
    return conn


def test_records_sanitized_requests(env):
    port = env["good"].server_address[1]
    base = f"https://localhost:{port}"
    op = env["opener"]
    r = urllib.request.Request(
        f"{base}/collect?uid=a8F3kLq92xZpQ7mN4vB1&q={SEARCH}",
        data=json.dumps({"sr": "1920x1080", "dl": "https://news.example/a"}).encode(),
        headers={"Cookie": f"sid={SESSION}", "Content-Type": "application/json",
                 "Referer": f"https://www.google.com/search?q={SEARCH}"},
    )
    assert op.open(r, timeout=10).read() == b"ok"
    login = urllib.request.Request(
        f"{base}/api/update", data=json.dumps({"user": "a", "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {SESSION}"},
    )
    assert op.open(login, timeout=10).read() == b"ok"
    time.sleep(1.5)

    conn = stop_and_read(env)
    rows = conn.execute("SELECT app_name, dest_domain, url, headers, cookies, body, flags, metadata_only "
                        "FROM requests ORDER BY id").fetchall()
    assert len(rows) == 2
    everything = json.dumps([[c.decode("latin-1") if isinstance(c, bytes) else c for c in row] for row in rows])
    for secret in (SESSION, PASSWORD, SEARCH):
        assert secret not in everything
    first = rows[0]
    assert first[0] == "Unknown app" and first[1] == "localhost" and first[7] == 0
    flags = {f["flag"] for f in json.loads(first[6])}
    assert {"long_id", "fingerprinting", "page_url"} <= flags
    assert "sid" in json.loads(first[4])["sent"]
    assert rows[1][5] is None  # password body never stored
    assert conn.execute("SELECT value FROM settings WHERE key='recorder_heartbeat_at'").fetchone()


def test_secrets_absent_from_database_file_on_disk(env):
    port = env["good"].server_address[1]
    r = urllib.request.Request(f"https://localhost:{port}/x", headers={"Cookie": f"sid={SESSION}"})
    env["opener"].open(r, timeout=10).read()
    time.sleep(1.5)
    stop_and_read(env).close()
    for f in env["data_dir"].rglob("*"):
        if f.is_file():
            raw = f.read_bytes()
            assert SESSION.encode() not in raw, f
            assert b"localhost" not in raw or f.suffix == ".pem", f


def test_ca_key_never_written_to_disk(env):
    files = sorted(p.name for p in (env["data_dir"] / "mitm").iterdir())
    assert files == ["dhparam.pem"]
    for p in env["data_dir"].rglob("*.pem"):
        assert b"PRIVATE KEY" not in p.read_bytes()


def test_upstream_certificates_are_verified(env):
    port = env["bad"].server_address[1]
    with pytest.raises(urllib.error.HTTPError) as exc:
        env["opener"].open(f"https://localhost:{port}/", timeout=10)
    assert exc.value.code == 502


def test_dont_track_rule_stores_nothing(env):
    conn = db.connect(env["db_path"], env["db_key"])
    conn.execute("INSERT INTO app_rules (kind, match, rule, updated_at) VALUES ('domain', 'localhost', 'dont_track', ?)",
                 (db.now_ms(),))
    time.sleep(2.5)  # rules reload within seconds, no restart
    port = env["good"].server_address[1]
    assert env["opener"].open(f"https://localhost:{port}/private", timeout=10).read() == b"ok"
    time.sleep(1.5)
    conn = stop_and_read(env)
    assert conn.execute("SELECT count(*) FROM requests").fetchone()[0] == 0


def test_metadata_only_rule_keeps_domain_and_nothing_else(env):
    conn = db.connect(env["db_path"], env["db_key"])
    conn.execute("INSERT INTO app_rules (kind, match, rule, updated_at) VALUES ('domain', 'localhost', 'metadata_only', ?)",
                 (db.now_ms(),))
    time.sleep(2.5)
    port = env["good"].server_address[1]
    r = urllib.request.Request(f"https://localhost:{port}/p?uid=abc", headers={"Cookie": f"sid={SESSION}"})
    assert env["opener"].open(r, timeout=10).read() == b"ok"
    time.sleep(1.5)
    conn = stop_and_read(env)
    rows = conn.execute("SELECT dest_domain, url, headers, cookies, body, metadata_only FROM requests").fetchall()
    assert rows == [("localhost", None, None, None, None, 1)]

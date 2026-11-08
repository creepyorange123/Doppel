"""Only real certificate rejections should switch an app to metadata only.

Browsers abandon TLS handshakes all the time (spare connections, racing), which
mitmproxy reports as "disconnected during the handshake". Treating those as
certificate pinning switched Chrome off entirely.
"""

from types import SimpleNamespace

import pytest

from recorder import addon, procinfo
from recorder.scope import Scope
from shared.audits import AuditApp

# Messages as mitmproxy 12 writes them (mitmproxy/proxy/layers/tls.py).
REJECTED = ("The client does not trust the proxy's certificate for static.xx.fbcdn.net "
            "(sslv3 alert bad certificate)")
DISCONNECTED = ("The client disconnected during the handshake. If this happens consistently for "
                "static.xx.fbcdn.net, this may indicate that the client does not trust the proxy's certificate.")
OTHER = "The client may not trust the proxy's certificate for static.xx.fbcdn.net (OpenSSL Error(...))"


@pytest.mark.parametrize("error,kind", [
    (REJECTED, "rejected"),
    (DISCONNECTED, "disconnected"),
    (OTHER, "other"),
    (None, "other"),
])
def test_classify(error, kind):
    assert addon.classify_tls_failure(error) == kind


class FakeRules:
    def __init__(self):
        self.reports = []

    def report_pinning_failure(self, app_key, domain):
        self.reports.append(domain)
        return False


class FakeWriter:
    def __init__(self):
        self.rows = []

    def put(self, row):
        self.rows.append(row)


CHROME = procinfo.AppInfo(1, r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome")


TARGET = AuditApp(name="Chrome", path=r"C:\Program Files\Google\Chrome\Application")


def make():
    rules, writer = FakeRules(), FakeWriter()
    scope = Scope([TARGET], table=lambda: {}, own_pid=99)
    rec = addon.ShadowRecorder(scope, rules, writer, b"k" * 32, audit_id=1, ca_ready=True)
    return rec, rules, writer


def data(rec, cid, sni, error=None):
    client = SimpleNamespace(id=cid, sni=sni, error=error)
    rec.apps[cid] = CHROME
    rec.targets[cid] = TARGET
    return SimpleNamespace(context=SimpleNamespace(client=client))


def test_real_rejection_counts_immediately():
    rec, rules, writer = make()
    rec.tls_failed_client(data(rec, "c1", "bank.example", REJECTED))
    assert rules.reports == ["bank.example"]
    assert writer.rows[0]["flags"].count("certificate_pinned") == 1
    assert writer.rows[0]["audit_id"] == 1 and writer.rows[0]["app_name"] == "Chrome"
    assert writer.rows[0]["process_name"] == "chrome"


def test_connections_outside_the_audit_are_ignored():
    rec, rules, writer = make()
    d = data(rec, "c1", "bank.example", REJECTED)
    rec.targets["c1"] = None
    rec.tls_failed_client(d)
    assert rules.reports == [] and writer.rows == []


def test_abandoned_handshakes_are_ignored():
    rec, rules, writer = make()
    rec.tls_failed_client(data(rec, "c1", "static.xx.fbcdn.net", DISCONNECTED))
    rec.tls_failed_client(data(rec, "c2", "c.s-microsoft.com", DISCONNECTED))
    rec.tls_failed_client(data(rec, "c3", "fls-na.amazon.com", OTHER))
    assert rules.reports == [] and writer.rows == []


def test_repeated_disconnects_to_one_site_with_no_success_count():
    rec, rules, _ = make()
    for i in range(addon.DISCONNECT_THRESHOLD):
        rec.tls_failed_client(data(rec, f"c{i}", "pinned.example", DISCONNECTED))
    assert rules.reports == ["pinned.example"]


def test_a_successful_handshake_means_disconnects_were_not_pinning():
    rec, rules, _ = make()
    rec.tls_established_client(data(rec, "ok", "static.xx.fbcdn.net"))
    for i in range(addon.DISCONNECT_THRESHOLD + 2):
        rec.tls_failed_client(data(rec, f"c{i}", "static.xx.fbcdn.net", DISCONNECTED))
    assert rules.reports == []


@pytest.mark.parametrize("host", ["104.18.26.193", "2606:4700::6812:1ac1", "[2606:4700::1]"])
def test_ip_only_destinations_are_never_stored(host):
    rec, _, writer = make()
    data(rec, "c1", host)
    rec.metadata_row(SimpleNamespace(id="c1"), host)
    assert writer.rows == []
    rec.metadata_row(SimpleNamespace(id="c1"), "connect.facebook.net")
    assert writer.rows[0]["dest_domain"] == "connect.facebook.net"


def test_refused_http3_is_not_stored():
    rec, _, writer = make()
    killed = []
    data(rec, "c1", "x")
    flow = SimpleNamespace(server_conn=SimpleNamespace(address=("104.18.26.193", 443)),
                           client_conn=SimpleNamespace(id="c1"), kill=lambda: killed.append(1))
    rec.udp_start(flow)
    assert killed == [1] and writer.rows == []

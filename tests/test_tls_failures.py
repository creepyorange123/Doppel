"""Only real certificate rejections should switch an app to metadata only.

Browsers abandon TLS handshakes all the time (spare connections, racing), which
mitmproxy reports as "disconnected during the handshake". Treating those as
certificate pinning switched Chrome off entirely.
"""

from types import SimpleNamespace

import pytest

from recorder import addon, procinfo

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

    def report_pinning_failure(self, path, name, domain):
        self.reports.append(domain)
        return False


class FakeWriter:
    def __init__(self):
        self.rows = []

    def put(self, row):
        self.rows.append(row)


CHROME = procinfo.AppInfo(1, r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome")


def make():
    rules, writer = FakeRules(), FakeWriter()
    rec = addon.ShadowRecorder(rules, writer, b"k" * 32, ca_ready=True)
    return rec, rules, writer


def data(rec, cid, sni, error=None):
    client = SimpleNamespace(id=cid, sni=sni, error=error)
    rec.apps[cid] = CHROME
    return SimpleNamespace(context=SimpleNamespace(client=client))


def test_real_rejection_counts_immediately():
    rec, rules, writer = make()
    rec.tls_failed_client(data(rec, "c1", "bank.example", REJECTED))
    assert rules.reports == ["bank.example"]
    assert writer.rows[0]["flags"].count("certificate_pinned") == 1


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

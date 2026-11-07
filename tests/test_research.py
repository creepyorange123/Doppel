import json

import pytest

from analyzer import trackers
from analyzer.research import egress, ledger, research, snapshot, summarize
from shared import db


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


# ----------------------------------------------------------------------- ledger

def test_ledger_chain_verifies(conn):
    for i in range(3):
        ledger.append(conn, "api.tavily.com", {"query": f"Company {i} privacy policy"})
    rep = ledger.verify(conn)
    assert rep["ok"] and rep["entries"] == 3
    assert rep["latest_hash"] == conn.execute("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()[0]


def test_ledger_detects_edit(conn):
    for i in range(3):
        ledger.append(conn, "api.exa.ai", {"query": f"C{i}"})
    conn.execute("""UPDATE ledger SET payload = '{"query":"edited"}' WHERE id = 2""")
    rep = ledger.verify(conn)
    assert not rep["ok"] and rep["broken_at"] == 2


def test_ledger_detects_deletion(conn):
    for i in range(3):
        ledger.append(conn, "api.exa.ai", {"query": f"C{i}"})
    conn.execute("DELETE FROM ledger WHERE id = 2")
    rep = ledger.verify(conn)
    assert not rep["ok"] and rep["broken_at"] == 3


# ----------------------------------------------------------------------- egress

def test_zero_network_blocks_and_logs_nothing(conn):
    db.set_setting(conn, "zero_network", "1")
    sent = []
    gate = egress.Gate(conn, sender=lambda *a: sent.append(a))
    with pytest.raises(egress.Blocked):
        gate.post("https://api.tavily.com/search", {"query": "Google privacy"}, headers={})
    assert sent == [] and conn.execute("SELECT count(*) FROM ledger").fetchone()[0] == 0


@pytest.mark.parametrize("url", [
    "https://evil.example/x", "http://api.tavily.com/search", "https://api.tavily.com.evil.example/",
    "https://user@api.tavily.com/search", "https://api.tavily.com:8443/search",
])
def test_only_allowlisted_hosts(conn, url):
    gate = egress.Gate(conn, sender=lambda *a: {})
    with pytest.raises(egress.Blocked):
        gate.post(url, {"query": "x"}, headers={})


def test_ledger_written_before_send_and_secrets_not_logged(conn):
    order = []

    def sender(url, body, headers):
        order.append(("send", conn.execute("SELECT count(*) FROM ledger").fetchone()[0]))
        return {"results": []}

    gate = egress.Gate(conn, sender=sender)
    gate.post("https://api.exa.ai/search", {"query": "Criteo opt out"}, headers={"x-api-key": "SECRET-KEY"})
    assert order == [("send", 1)]
    row = conn.execute("SELECT destination, payload FROM ledger").fetchone()
    assert row[0] == "api.exa.ai" and "Criteo opt out" in row[1] and "SECRET-KEY" not in row[1]


# ---------------------------------------------------------------- queries/names

def test_queries_only_carry_company_names():
    known = {"Google", "Criteo"}
    qs = research.build_queries("Criteo", known)
    assert set(qs) == {"policy", "registry", "news"} and all("Criteo" in q for q in qs.values())
    with pytest.raises(ValueError):
        research.build_queries("Unknown Co", known)
    # Even if a bad name somehow got into the known set, it never leaves the device.
    for bad in ("Google\nmy email is a@b.c", "https://x.example", "a" * 200):
        with pytest.raises(ValueError):
            research.build_queries(bad, known | {bad})


def test_top_companies_by_frequency(conn):
    for i, company in enumerate(["A"] * 3 + ["B"] * 2 + ["C"] + [None] * 5):
        conn.execute("INSERT INTO requests (id, captured_at, dest_domain) VALUES (?, 1, 'x')", (i + 1,))
        conn.execute("INSERT INTO findings (request_id, company) VALUES (?, ?)", (i + 1, company))
    assert research.top_companies(conn, limit=2) == ["A", "B"]


# --------------------------------------------------------------------- summarize

TDB = trackers.TrackerDB({"criteo.com": {"company": "Criteo", "category": "Advertising"},
                          "criteo.net": {"company": "Criteo", "category": "Advertising"}})
SOURCES = [{"url": "https://www.criteo.com/privacy/", "content": "Criteo privacy policy text"}]


def test_summary_validated_and_opt_out_on_own_domain():
    model = lambda p: json.dumps({"policy_summary": "Uses cookies for ads.", "is_data_broker": False,
                                  "opt_out_url": "https://www.criteo.com/privacy/disable-criteo-services/",
                                  "news": ["Fined by CNIL in 2023"]})
    s = summarize.summarize("Criteo", SOURCES, model, TDB)
    assert s["opt_out_url"].startswith("https://www.criteo.com/")
    assert s["is_data_broker"] is False and s["news"] == ["Fined by CNIL in 2023"]


def test_injected_opt_out_link_rejected():
    model = lambda p: json.dumps({"policy_summary": "x", "is_data_broker": False,
                                  "opt_out_url": "https://criteo-optout.evil.example/", "news": []})
    assert summarize.summarize("Criteo", SOURCES, model, TDB)["opt_out_url"] is None


@pytest.mark.parametrize("answer", ["not json", json.dumps({"policy_summary": 5}), json.dumps({"extra": 1})])
def test_bad_model_output_falls_back_to_template(answer):
    s = summarize.summarize("Criteo", SOURCES, lambda p: answer, TDB)
    assert s["policy_summary"] and s["opt_out_url"] is None and s["sources"] == ["https://www.criteo.com/privacy/"]


# ---------------------------------------------------------------------- snapshot

def test_snapshot_sign_verify_and_tamper(tmp_path):
    priv, pub = snapshot.generate_keypair()
    data = {"companies": {"Criteo": {"policy_summary": "x", "is_data_broker": False, "opt_out_url": None,
                                     "news": [], "sources": []}}}
    path = tmp_path / "snap.json"
    snapshot.write_signed(path, data, priv)
    assert snapshot.load_verified(path, pub)["companies"]["Criteo"]["policy_summary"] == "x"
    path.write_text(path.read_text().replace('"x"', '"y"'))
    with pytest.raises(snapshot.BadSignature):
        snapshot.load_verified(path, pub)


def test_bundled_snapshot_verifies():
    assert "companies" in snapshot.load_verified()


def test_import_snapshot_marks_rows(conn, tmp_path):
    priv, pub = snapshot.generate_keypair()
    path = tmp_path / "s.json"
    snapshot.write_signed(path, {"companies": {"Criteo": {"policy_summary": "p", "is_data_broker": False,
                                                          "opt_out_url": None, "news": [], "sources": []}}}, priv)
    assert snapshot.import_into(conn, snapshot.load_verified(path, pub)) == 1
    assert conn.execute("SELECT from_snapshot FROM companies WHERE name='Criteo'").fetchone()[0] == 1


# ---------------------------------------------------------------------- research
# Original plan: Tavily extract reads the privacy policy, Tavily search checks the
# California and Vermont broker registries, Exa finds news and enforcement.

class FakeClients:
    def __init__(self, registry_hit=True):
        self.calls = []
        self.registry_hit = registry_hit

    def tavily_search(self, gate, query, include_domains=None):
        self.calls.append(("tavily_search", query, tuple(include_domains or ())))
        gate.post("https://api.tavily.com/search", {"query": query, "include_domains": include_domains or []}, headers={})
        if include_domains:  # registry check
            if not self.registry_hit:
                return []
            return [{"url": "https://cppa.ca.gov/data_broker_registry/", "content": "Criteo Corp. registered 2024"}]
        return [{"url": "https://www.criteo.com/privacy/", "content": "policy page"},
                {"url": "https://criteo-review.evil.example/", "content": "spam"}]

    def tavily_extract(self, gate, url):
        self.calls.append(("tavily_extract", url))
        gate.post("https://api.tavily.com/extract", {"urls": [url]}, headers={})
        return "Criteo collects browsing data and shares it with partners."

    def exa_search(self, gate, query):
        self.calls.append(("exa_search", query))
        gate.post("https://api.exa.ai/search", {"query": query}, headers={})
        return [{"url": "https://news.example/criteo-fine", "content": "CNIL fined Criteo in 2023"}]


SUMMARY_MODEL = lambda p: json.dumps({"policy_summary": "Collects browsing data for ads.", "is_data_broker": False,
                                      "opt_out_url": None, "news": ["Fined by CNIL in 2023"]})


def test_research_uses_extract_registry_and_exa(conn):
    clients = FakeClients()
    gate = egress.Gate(conn, sender=lambda *a: {})
    n = research.refresh(conn, ["Criteo"], gate=gate, clients=clients, model=SUMMARY_MODEL, tracker_db=TDB,
                         known={"Criteo"})
    assert n == 1
    kinds = [c[0] for c in clients.calls]
    assert kinds.count("tavily_extract") == 1 and "exa_search" in kinds
    # Extract only the policy on the company's own domain.
    assert ("tavily_extract", "https://www.criteo.com/privacy/") in clients.calls
    registry = [c for c in clients.calls if c[0] == "tavily_search" and c[2]]
    assert registry and set(registry[0][2]) >= {"cppa.ca.gov", "oag.vermont.gov"}
    row = conn.execute("SELECT policy_summary, is_data_broker, policy_source, broker_source, news, sources "
                       "FROM companies WHERE name='Criteo'").fetchone()
    assert row[0] == "Collects browsing data for ads."
    assert row[1] == 1  # registry check decides, not the model
    assert row[2] == "https://www.criteo.com/privacy/"
    assert row[3] == "https://cppa.ca.gov/data_broker_registry/"
    assert "https://news.example/criteo-fine" in row[5]


def test_no_registry_hit_means_unknown_not_false(conn):
    gate = egress.Gate(conn, sender=lambda *a: {})
    research.refresh(conn, ["Criteo"], gate=gate, clients=FakeClients(registry_hit=False), model=SUMMARY_MODEL,
                     tracker_db=TDB, known={"Criteo"})
    assert conn.execute("SELECT is_data_broker FROM companies").fetchone()[0] is None


def test_only_company_names_and_its_own_policy_url_leave(conn):
    gate = egress.Gate(conn, sender=lambda *a: {})
    research.refresh(conn, ["Criteo"], gate=gate, clients=FakeClients(), model=None, tracker_db=TDB, known={"Criteo"})
    for (payload,) in conn.execute("SELECT payload FROM ledger"):
        p = json.loads(payload)
        if "query" in p:
            assert "Criteo" in p["query"]
        else:
            assert p == {"urls": ["https://www.criteo.com/privacy/"]}
    assert ledger.verify(conn)["ok"]


def test_refresh_is_weekly(conn):
    clients = FakeClients()
    gate = egress.Gate(conn, sender=lambda *a: {})
    research.refresh(conn, ["Criteo"], gate=gate, clients=clients, model=None, tracker_db=TDB, known={"Criteo"})
    before = len(clients.calls)
    research.refresh(conn, ["Criteo"], gate=gate, clients=clients, model=None, tracker_db=TDB, known={"Criteo"})
    assert len(clients.calls) == before


def test_refresh_refuses_in_zero_network(conn):
    db.set_setting(conn, "zero_network", "1")
    gate = egress.Gate(conn, sender=lambda *a: {})
    with pytest.raises(egress.Blocked):
        research.refresh(conn, ["Criteo"], gate=gate, clients=FakeClients(), model=None, tracker_db=TDB,
                         known={"Criteo"})

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
    assert qs and all("Criteo" in q for q in qs)
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

class FakeSearch:
    def __init__(self):
        self.queries = []

    def __call__(self, gate, query):
        self.queries.append(query)
        gate.post("https://api.tavily.com/search", {"query": query}, headers={})
        return [{"url": "https://www.criteo.com/privacy/", "content": "policy"}]




def test_refresh_researches_and_caches(conn):
    search = FakeSearch()
    gate = egress.Gate(conn, sender=lambda *a: {})
    model = lambda p: json.dumps({"policy_summary": "s", "is_data_broker": False, "opt_out_url": None, "news": []})
    n = research.refresh(conn, ["Criteo"], gate=gate, searchers=[search], model=model, tracker_db=TDB, known={"Criteo"})
    assert n == 1 and search.queries
    row = conn.execute("SELECT policy_summary, from_snapshot, sources FROM companies WHERE name='Criteo'").fetchone()
    assert row[0] == "s" and row[1] == 0 and "criteo.com" in row[2]
    before = len(search.queries)  # fresh within a week: no new calls
    research.refresh(conn, ["Criteo"], gate=gate, searchers=[search], model=model, tracker_db=TDB, known={"Criteo"})
    assert len(search.queries) == before
    assert ledger.verify(conn)["ok"]


def test_refresh_refuses_in_zero_network(conn):
    db.set_setting(conn, "zero_network", "1")
    gate = egress.Gate(conn, sender=lambda *a: {})
    with pytest.raises(egress.Blocked):
        research.refresh(conn, ["Criteo"], gate=gate, searchers=[FakeSearch()], model=None, tracker_db=TDB,
                         known={"Criteo"})

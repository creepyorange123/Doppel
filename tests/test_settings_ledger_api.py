import pytest

from analyzer import handlers
from analyzer.research import ledger
from shared import db
from shared.protocol import ProtocolError


@pytest.fixture
def conn(tmp_path, db_key):
    return db.open_db(tmp_path / "t.db", db_key)


def call(conn, t, p=None):
    return handlers.handle(conn, t, p or {})


def test_settings_round_trip(conn):
    s = call(conn, "get_settings")
    assert s == {"zero_network": False, "gpc": False, "local_ai": False, "california": False, "tracking_mode": "blocklist"}
    call(conn, "set_setting", {"key": "zero_network", "value": True})
    assert call(conn, "get_settings")["zero_network"] is True


@pytest.mark.parametrize("p", [{"key": "last_opened_at", "value": True}, {"key": "gpc", "value": "yes"}, {}])
def test_only_user_toggles_can_be_set(conn, p):
    with pytest.raises(ProtocolError):
        call(conn, "set_setting", p)


def test_ledger_handlers(conn):
    ledger.append(conn, "api.exa.ai", {"query": "Criteo opt out"})
    v = call(conn, "ledger_verify")
    assert v["ok"] and v["entries"] == 1 and len(v["latest_hash"]) == 64
    entries = call(conn, "ledger_list")["entries"]
    assert entries[0]["destination"] == "api.exa.ai" and entries[0]["payload"]["query"] == "Criteo opt out"

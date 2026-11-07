import json

import pytest

from shared import protocol


def test_parse_valid_request():
    assert protocol.parse_request('{"id": 1, "type": "status", "payload": {}}') == (1, "status", {})


@pytest.mark.parametrize("line,code", [
    ("not json", "bad_json"),
    ("[1]", "bad_message"),
    ('{"id": "1", "type": "status"}', "bad_message"),
    ('{"id": true, "type": "status"}', "bad_message"),
    ('{"id": 1, "type": "drop_tables"}', "unknown_type"),
    ('{"id": 1, "type": "status", "payload": []}', "bad_message"),
])
def test_parse_rejects_bad_input(line, code):
    with pytest.raises(protocol.ProtocolError) as exc:
        protocol.parse_request(line)
    assert exc.value.code == code


def test_result_and_error_shapes():
    assert json.loads(protocol.result(3, {"a": 1})) == {"id": 3, "type": "result", "payload": {"a": 1}}
    assert json.loads(protocol.error(3, "x", "y"))["payload"] == {"code": "x", "message": "y"}

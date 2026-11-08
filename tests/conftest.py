import os
import secrets

import pytest


@pytest.fixture
def db_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOW_DATA_DIR", str(tmp_path))
    return tmp_path


def pytest_configure(config):
    config.addinivalue_line("markers", "devlog: run the recorder with the development traffic log on")

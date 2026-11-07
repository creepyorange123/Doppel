"""Open the shared, SQLCipher-encrypted database.

Used by the recorder (writes ``requests``) and the analyzer (everything else).
The Electron app never opens the file; it goes through the analyzer over IPC.

Privacy hardening (security checklist #9):
- ``secure_delete`` overwrites deleted content with zeros.
- ``temp_store = MEMORY`` keeps temporary tables and indices off the disk.
- :func:`checkpoint_truncate` folds the write-ahead log back in and truncates it,
  so deleted content does not survive in the ``-wal`` file.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import sqlcipher3

from shared import keystore

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = "1"
APP_DIR_NAME = "ShadowProfile"

SETTINGS_DEFAULTS = {
    "tracking_mode": "blocklist",  # or "allowlist"
    "zero_network": "0",
    "gpc": "0",
}


def now_ms() -> int:
    return int(time.time() * 1000)


def data_dir() -> Path:
    """Per-user data folder. Override with SHADOW_DATA_DIR (tests, dev)."""
    override = os.environ.get("SHADOW_DATA_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_DIR_NAME
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_DIR_NAME
    base.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(base, 0o700)
    return base


def db_path() -> Path:
    return data_dir() / "shadow.db"


def connect(path: Path | str | None = None, key: bytes | None = None) -> sqlcipher3.Connection:
    """Open (and create if needed) the encrypted database.

    ``key`` defaults to the key in the OS credential store. Tests pass their own.
    """
    path = Path(path) if path is not None else db_path()
    key = key if key is not None else keystore.db_key()
    if len(key) != 32:
        raise ValueError("database key must be 32 bytes")

    conn = sqlcipher3.connect(str(path), timeout=10, isolation_level=None, check_same_thread=False)
    # Raw 256-bit key, so no passphrase derivation is involved.
    conn.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
    # Fails here (not later) if the key is wrong.
    conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    conn.execute("PRAGMA secure_delete = ON")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    return conn


def init(conn: sqlcipher3.Connection) -> None:
    """Create tables and default settings. Safe to call on every start."""
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    ts = now_ms()
    defaults = {"install_at": str(ts), "schema_version": SCHEMA_VERSION, **SETTINGS_DEFAULTS}
    for key, value in defaults.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, ts),
        )


def get_setting(conn: sqlcipher3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(conn: sqlcipher3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, now_ms()),
    )


def checkpoint_truncate(conn: sqlcipher3.Connection) -> None:
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def open_db(path: Path | str | None = None, key: bytes | None = None) -> sqlcipher3.Connection:
    conn = connect(path, key)
    init(conn)
    return conn


if __name__ == "__main__":
    # `python -m shared.db` creates the empty encrypted database (Phase 0 check).
    c = open_db()
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    print(f"Database ready at {db_path()}")
    print("Tables:", ", ".join(tables))
    c.close()

"""Secrets kept in the OS credential store, never in the database or on disk.

- macOS: Keychain. Windows: Credential Manager. (via the `keyring` package)

Two secrets:
- ``db-key``: 256-bit raw key for the SQLCipher database.
- ``hmac-key``: 256-bit key for keyed hashes (HMAC) of identifiers, so the log
  can match an ID across requests without ever storing its raw value.

Security checklist #1/#4: on macOS the Keychain item should be restricted to the
signed recorder/analyzer binaries at packaging time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import keyring

SERVICE = "ShadowProfile"
DB_KEY = "db-key"
HMAC_KEY = "hmac-key"


def _get_or_create(name: str) -> bytes:
    value = keyring.get_password(SERVICE, name)
    if value is None:
        value = secrets.token_hex(32)
        keyring.set_password(SERVICE, name, value)
        # Read back so two processes racing on first run agree on one key.
        value = keyring.get_password(SERVICE, name) or value
    return bytes.fromhex(value)


def db_key() -> bytes:
    return _get_or_create(DB_KEY)


def hmac_key() -> bytes:
    return _get_or_create(HMAC_KEY)


def keyed_hash(value: str | bytes, key: bytes) -> str:
    """HMAC-SHA256 of ``value``, hex. Used instead of storing raw identifiers."""
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogatepass")
    return hmac.new(key, value, hashlib.sha256).hexdigest()


def delete_all() -> None:
    """Remove every secret (used by "wipe all" and uninstall)."""
    for name in (DB_KEY, HMAC_KEY):
        try:
            keyring.delete_password(SERVICE, name)
        except keyring.errors.PasswordDeleteError:
            pass

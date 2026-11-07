"""The recorder's own certificate authority (security checklist #1).

mitmproxy normally keeps its CA private key as a plain file in ~/.mitmproxy.
Here the key is generated in memory and kept only in the OS credential store
(Keychain / Credential Manager). It never touches the disk; mitmproxy's
``CertStore.from_store`` is replaced so it never creates ~/.mitmproxy files.

- Short lifetime (``CA_LIFETIME``). An expired CA is never used: the recorder
  falls back to metadata only until the app rotates it with the user's consent.
- Name-constrained? No: it must sign for any site. Its key is EC P-256.
- Only the public certificate is ever written to a file, and only briefly, to
  hand it to the OS trust-store tool.
"""

from __future__ import annotations

import datetime as dt
import subprocess
import sys
import tempfile
from pathlib import Path

import keyring
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from shared.keystore import SERVICE

CA_KEY = "ca-key"
CA_CERT = "ca-cert"
CA_LIFETIME = dt.timedelta(days=30)
CA_COMMON_NAME = "Shadow Profile local recorder"


# ------------------------------------------------------------------ generate/load

def generate() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Shadow Profile (this computer only)"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + CA_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def save(key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
    keyring.set_password(SERVICE, CA_KEY, key_pem(key).decode("ascii"))
    keyring.set_password(SERVICE, CA_CERT, cert_pem(cert).decode("ascii"))


def load() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate] | None:
    k = keyring.get_password(SERVICE, CA_KEY)
    c = keyring.get_password(SERVICE, CA_CERT)
    if not k or not c:
        return None
    key = serialization.load_pem_private_key(k.encode("ascii"), password=None)
    cert = x509.load_pem_x509_certificate(c.encode("ascii"))
    return key, cert  # type: ignore[return-value]


def delete() -> None:
    for name in (CA_KEY, CA_CERT):
        try:
            keyring.delete_password(SERVICE, name)
        except keyring.errors.PasswordDeleteError:
            pass


def is_valid(cert: x509.Certificate, *, margin: dt.timedelta = dt.timedelta(hours=1)) -> bool:
    now = dt.datetime.now(dt.timezone.utc)
    return cert.not_valid_before_utc <= now and now + margin < cert.not_valid_after_utc


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()


# ------------------------------------------------------------- mitmproxy wiring

def install_into_mitmproxy(key, cert, dhparam_dir: Path) -> None:
    """Make mitmproxy use our in-memory CA instead of files in confdir.

    Must be called before the mitmproxy master starts.
    """
    from mitmproxy import certs

    dhparam_file = dhparam_dir / "dhparam.pem"  # public parameters, not secret

    def from_store(cls, path, basename, key_size, passphrase=None):  # noqa: ARG001
        dh = certs.CertStore.load_dhparam(dhparam_file)
        ca = certs.Cert(cert)
        crl = certs.dummy_crl(key, cert)
        return cls(key, ca, None, crl, dh)

    certs.CertStore.from_store = classmethod(from_store)  # type: ignore[method-assign]

    def refuse(*_a, **_k):
        raise RuntimeError("refusing to write a CA key to disk")

    certs.CertStore.create_store = staticmethod(refuse)  # type: ignore[method-assign]


# ------------------------------------------------------------------- trust store

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def trust_command(cert_file: Path, platform: str = sys.platform) -> list[str]:
    if platform == "win32":
        # Current user's Root store; Windows shows its own confirmation dialog.
        return ["certutil", "-user", "-addstore", "Root", str(cert_file)]
    if platform == "darwin":
        login = str(Path.home() / "Library" / "Keychains" / "login.keychain-db")
        return ["security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", login, str(cert_file)]
    raise NotImplementedError("only macOS and Windows are supported")


def untrust_command(cert: x509.Certificate, platform: str = sys.platform) -> list[str]:
    if platform == "win32":
        return ["certutil", "-user", "-delstore", "Root", format(cert.serial_number, "x")]
    if platform == "darwin":
        return ["security", "delete-certificate", "-Z", fingerprint(cert)]
    raise NotImplementedError("only macOS and Windows are supported")


def trust(cert: x509.Certificate) -> None:
    """Add the CA certificate (public part only) to the user's trust store."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "shadow-profile-ca.crt"
        f.write_bytes(cert_pem(cert))
        res = _run(trust_command(f))
    if res.returncode != 0:
        raise RuntimeError(f"could not add certificate to trust store: {res.stderr.strip() or res.stdout.strip()}")


def untrust(cert: x509.Certificate) -> bool:
    return _run(untrust_command(cert)).returncode == 0


def untrust_all_by_name() -> None:
    """Remove every Shadow Profile CA from the trust store (uninstall, failed install)."""
    if sys.platform == "win32":
        _run(["certutil", "-user", "-delstore", "Root", CA_COMMON_NAME])
    elif sys.platform == "darwin":
        for _ in range(10):
            if _run(["security", "delete-certificate", "-c", CA_COMMON_NAME]).returncode != 0:
                break


def provision() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Create a fresh CA, trust it, and store it. Rolls back on any failure."""
    old = load()
    key, cert = generate()
    try:
        trust(cert)
    except Exception:
        untrust(cert)  # in case it was half-added
        raise
    try:
        save(key, cert)
    except Exception:
        untrust(cert)
        if old is not None:
            save(*old)
        raise
    if old is not None:
        untrust(old[1])
    return key, cert


def remove() -> None:
    current = load()
    if current is not None:
        untrust(current[1])
    untrust_all_by_name()
    delete()

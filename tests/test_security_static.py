"""Static checks for the security checklist items that can be verified in code."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_DIRS = [ROOT / "recorder", ROOT / "analyzer", ROOT / "shared"]
TS_DIRS = [ROOT / "app" / "src", ROOT / "app" / "electron"]


def files(dirs, *exts):
    for d in dirs:
        for p in d.rglob("*"):
            if p.suffix in exts and "node_modules" not in p.parts:
                yield p


def test_no_listening_sockets_in_our_code():
    # Checklist #3: nothing listens on a port (mitmproxy's fallback listener is pinned to 127.0.0.1).
    pattern = re.compile(r"\.listen\(|\bbind\(\(|createServer\(|HTTPServer\(|uvicorn|FastAPI\(")
    hits = [str(p) for p in files(PY_DIRS + TS_DIRS, ".py", ".ts", ".tsx") if pattern.search(p.read_text(encoding="utf-8"))]
    assert hits == []


def test_proxy_listens_on_loopback_only():
    src = (ROOT / "recorder" / "__main__.py").read_text(encoding="utf-8")
    assert 'listen_host="127.0.0.1"' in src


def test_never_ssl_insecure():
    # Checklist #11.
    for p in files(PY_DIRS, ".py"):
        assert not re.search(r"ssl_insecure\s*=\s*True", p.read_text(encoding="utf-8")), p


def test_electron_window_hardened():
    # Checklist #5.
    main = (ROOT / "app" / "electron" / "main.ts").read_text(encoding="utf-8")
    for needed in ("contextIsolation: true", "sandbox: true", "nodeIntegration: false"):
        assert needed in main
    html = (ROOT / "app" / "index.html").read_text(encoding="utf-8")
    assert "default-src 'none'" in html and "connect-src 'none'" in html
    for p in files(TS_DIRS, ".ts", ".tsx"):
        text = p.read_text(encoding="utf-8")
        assert "dangerouslySetInnerHTML" not in text, p
        assert "innerHTML" not in text or p.name == "main.ts", p


def test_dependencies_pinned_exactly():
    # Checklist #10.
    for req in ("requirements.txt", "requirements-dev.txt"):
        for line in (ROOT / req).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-r")):
                assert "==" in line, line
    pkg = json.loads((ROOT / "app" / "package.json").read_text())
    for section in ("dependencies", "devDependencies"):
        for name, version in pkg.get(section, {}).items():
            assert re.fullmatch(r"\d+\.\d+\.\d+", version), (name, version)
    assert (ROOT / "app" / "package-lock.json").exists()


def test_no_secrets_or_data_files_tracked():
    ignore = (ROOT / ".gitignore").read_text()
    for pattern in ("*.db", "*.pem", "*.key", "mitmproxy-ca*"):
        assert pattern in ignore


def test_only_public_key_material_in_repo():
    for p in (ROOT / "shared" / "data").iterdir():
        assert b"PRIVATE KEY" not in p.read_bytes(), p


def test_network_calls_only_through_egress_gate():
    # Checklist #8: no network code outside the egress gate (and the loopback-only Ollama client).
    allowed = {ROOT / "analyzer" / "research" / "egress.py", ROOT / "analyzer" / "topics.py"}
    pattern = re.compile(r"urllib\.request\.urlopen|requests\.(get|post)|http\.client|httpx|aiohttp|socket\.create_connection")
    hits = [str(p) for p in files(PY_DIRS, ".py") if p not in allowed and pattern.search(p.read_text(encoding="utf-8"))]
    assert hits == []

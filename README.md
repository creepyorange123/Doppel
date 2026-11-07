# Shadow Profile

Shows what every app on your computer sends, and to whom, since you last looked.
Everything runs locally; captured traffic never leaves the device.

## Layout

| Folder | Owner | What |
|---|---|---|
| `recorder/` | traffic & detection | Always-on mitmproxy (local capture mode) addon that writes each request to the encrypted log |
| `analyzer/` | traffic & detection, research | Python sidecar started by the app on open; steps 1–4 (fetch, identify, score) |
| `app/` | desktop app | Electron + React (TypeScript, Vite) window; talks to the analyzer over stdio IPC |
| `shared/` | data & demo | Database schema, encrypted DB access, key storage, IPC message format |
| `tests/` | data & demo | pytest suites |
| `demo/` | data & demo | Persona script and demo material |

- Data model: [`shared/schema.sql`](shared/schema.sql)
- Analyzer ⇄ app messages: [`shared/PROTOCOL.md`](shared/PROTOCOL.md)

## Privacy rules every change must keep

- The log is a SQLCipher-encrypted SQLite file in your user data folder; its key lives
  only in the macOS Keychain / Windows Credential Manager.
- Never store `Cookie`, `Set-Cookie`, `Authorization` values, passwords or login bodies.
  Identifiers are stored as keyed hashes (HMAC), never raw.
- Never store search queries or search-suggestion requests.
- System-process traffic is never logged.
- No component listens on a network port; the app ⇄ analyzer link is stdio.
- No captured content in logs, stderr, errors, or temp files. Never commit databases,
  keys, or certificates (see `.gitignore`).
- The Electron window: `contextIsolation`, `sandbox`, no `nodeIntegration`, strict CSP,
  no network, never render captured text as HTML.
- Dependencies are pinned to exact versions (`requirements*.txt`, `app/package-lock.json`).

## Setup (Phase 0 check)

Requires Python 3.12+ and Node 22+.

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt   # macOS: .venv/bin/pip
.venv/Scripts/python -m shared.db                   # creates the empty encrypted database
.venv/Scripts/python -m pytest
cd app && npm ci && npm start                       # opens the empty app window
```

`npm run smoke` builds the app, opens the window, prints what it shows, and quits.
Set `SHADOW_DATA_DIR` to use a throwaway data folder during development.

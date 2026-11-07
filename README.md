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

Requires Python 3.12+ and Node 22+. Commands below use macOS/Linux paths; on Windows,
use `.venv\Scripts\python` instead of `.venv/bin/python`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt   # runtime deps + pytest
.venv/bin/python -m shared.db                   # creates the empty encrypted database
.venv/bin/python -m pytest
cd app && npm ci && npm start                   # opens the app window
```

The app starts the analyzer with `.venv/bin/python` (falling back to `python3` if the
venv is missing), so install the Python dependencies before running `npm start`.

`npm run smoke` builds the app, opens the window, prints what it shows, and quits.
Set `SHADOW_DATA_DIR` to use a throwaway data folder during development (default:
`~/Library/Application Support/` on macOS, `%LOCALAPPDATA%` on Windows).

## Running it for real

```bash
.venv/bin/python -m recorder install          # consent, CA into your user trust store, start at login
.venv/bin/python -m recorder status
.venv/bin/python -m recorder run              # what the login item runs
.venv/bin/python -m recorder run --fallback-proxy 8899   # if local capture fails: set system proxy to 127.0.0.1:8899
.venv/bin/python -m recorder rotate-ca        # replace the CA (it expires after 30 days)
.venv/bin/python -m recorder uninstall [--wipe]
```

"Start at login" is a LaunchAgent in `~/Library/LaunchAgents` on macOS. On Windows it is
a Task Scheduler logon task, or, when Windows refuses that without admin rights, an entry
in your user's Run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`); either way
the recorder runs unelevated, and starting the capture driver shows a UAC prompt. The
app's consent screen runs `install` for you; no admin terminal is needed.

Research (optional, Phase 5):

```bash
.venv/bin/python -m analyzer.research set-key tavily
.venv/bin/python -m analyzer.research set-key exa
.venv/bin/python -m analyzer.research refresh --top 50
```

Hand checks: `.venv/bin/python -m analyzer.review export --n 100 labels.csv`, label the
`human_tier` column, then `.venv/bin/python -m analyzer.review report labels.csv`.

## Demo

```bash
.venv/bin/pip install -r requirements-demo.txt
.venv/bin/python -m playwright install chromium
.venv/bin/python -m demo.persona                 # the night before
.venv/bin/python scripts/predemo_check.py        # before judging
.venv/bin/python scripts/predemo_check.py --after-uninstall
```

OS firewall rules are in `scripts/firewall/` (`shadow-profile.lsrules` for macOS,
`windows-firewall.ps1` for Windows); review them, then apply them yourself.

## Known gaps

- Packaging (electron-builder + PyInstaller, signed binaries in a non-user-writable
  folder) is not set up; in development the login task runs the venv's Python, and
  `recorder status` reports it as user-writable.
- Windows local capture starts mitmproxy's own elevated redirector (UAC prompt at login);
  parsing stays in the unprivileged recorder process.
- The bundled tracker map is a curated ~120-domain subset; rebuild from Tracker Radar
  with `scripts/build_tracker_db.py`. The bundled research snapshot is signed but empty
  until a pre-fetch run is signed for release.
- Windows Firewall cannot restrict one program to specific HTTPS hosts; the egress gate
  and ledger enforce that, see `scripts/firewall/windows-firewall.ps1`.

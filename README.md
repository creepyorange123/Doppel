# Shadow Profile

Shows what every app on your computer sends, and to whom, since you last looked.
Everything runs locally; captured traffic never leaves the device.

**Contents:** [Setup](#setup-phase-0-check) ·
[Running it for real](#running-it-for-real) · [Scoring](#how-requests-are-scored) ·
[Local AI and company research](#local-ai-and-company-research-optional) ·
[Demo](#demo) · [Known gaps](#known-gaps)

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

The app's **Privacy** screen tests most of these live on your own data (encryption, key
location, hashed IDs, no credentials or search terms, raw content deleted, no listening
ports, local-only AI, outgoing calls, egress gate); see `analyzer/privacy_checks.py`.

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

To add the local AI model and company research, see
[Local AI and company research](#local-ai-and-company-research-optional).

Hand checks: `.venv/bin/python -m analyzer.review export --n 100 labels.csv`, label the
`human_tier` column, then `.venv/bin/python -m analyzer.review report labels.csv`.

## How requests are scored

Every request gets a score from 0 to 100 and a tier, using the tiers and starting weights
from the original project plan. Scoring is plain rules on this computer; no AI is involved,
and each tier badge in the app opens the breakdown.

| Tier | Score | Meaning | Default action |
|---|---|---|---|
| Minimum utility | 0–19 | Needed for the page to work, no identifier that follows you | Leave alone |
| Measurement | 20–49 | Counts your visit or behaviour on one site, not across sites | Show, optionally block |
| Profile building | 50–79 | Links your activity across sites or ties it to an identity | Recommend blocking |
| High concern | 80–100 | Profile building plus sensitive context, personal identifiers or sharing | Block and flag |

| Signal | Points |
|---|---|
| Third-party recipient | +10 |
| Advertising or ad-motivated tracking company | +20 |
| Session replay (category, or mouse and keystroke events) | +25 |
| Cross-site identifier (same ID seen on 2+ sites) | +25 |
| Page address sent alongside an identifier | +10 |
| Fingerprinting | +20 |
| Hashed personal identifier (your email or phone) | +30 |
| Cookie syncing (same ID sent to another company) | +30 |
| Registered data broker (from research) | +15 |
| Sensitive data inside the request: health, finance, sexuality, religion, children, politics, ethnicity (also triggers ×1.5) | +30 |
| Personal data inside the request: name, birth date, address, gender, ID numbers, precise location | +20 |
| Page still works without it / breaks without it (breakage probe) | +10 / −20 |

Requests from pages or apps on a sensitive topic (health, finance, religion, sexuality,
dating), or carrying sensitive data to a third party, are multiplied by 1.5, capped at 100.

**Sensitive data inside requests** (`analyzer/datatypes.py`): before raw content is deleted, the
analyzer checks each request's query string and body for health, location, banking/finance,
personal details (name, birth date, address, gender, ID numbers, Meta's hashed `ud[...]` fields),
sexuality, religion, children, politics and ethnicity. Rules look at field names and values
(medication and condition words, coordinates, IBANs with a valid checksum, card numbers that pass
the Luhn check, US SSNs). When the rules find nothing and the local AI is on, the model is asked
(for known tracker companies only, up to 300 times per run) to pick from the same fixed list.
Only the category and field name are kept, never the value; the two data signals count only
when the data goes to a third party. The weights live in `analyzer/score.py` and
are meant to be tuned against ~100 hand-labelled requests (see Hand checks above).

## Local AI and company research (optional)

Both are optional. Without them the app still works: page topics come from keyword
rules, and profile cards show only what your own traffic reveals.

| Piece | What it adds | Leaves your computer? |
|---|---|---|
| **Ollama** (local AI) | Better page-topic labels; plain-English company summaries | No. It runs on `127.0.0.1` only |
| **Tavily** | Company privacy policies and data-broker registry checks | Only tracker **company names** |
| **Exa** | News, lawsuits, fines and data-sharing partners | Only tracker **company names** |

Commands below are for Windows (`.venv\Scripts\python`). On macOS use `.venv/bin/python`.

### 1. Local AI with Ollama

1. **Install Ollama** from [ollama.com](https://ollama.com) and keep the default install
   location. On Windows it installs to your user folder with no admin rights needed.
2. **Optional: keep models off a full C: drive.** Models are 2–5 GB each. Before pulling
   any, set the location in the Ollama app's **Settings → Model location**, or run
   `setx OLLAMA_MODELS "D:\Ollama\models"`. Then quit Ollama from the tray and start it
   again so it uses the new location.
3. **Download the models** (in a new terminal, so `ollama` is on your PATH):
   ```bash
   ollama pull qwen2.5:3b     # ~2 GB: page topics (needs ~8 GB RAM)
   ollama pull qwen2.5:7b     # ~4.7 GB: research summaries (needs ~16 GB RAM); optional
   ```
4. **Check it works:**
   ```bash
   ollama run qwen2.5:3b "Reply with the word ready"
   ```
5. **Turn it on:** open the app → **Settings** → tick **Use the local AI model
   (Ollama)**, then **close and reopen the app** (the analyzer reads this setting when it
   starts).
6. **Only have the 3B model?** Point research summaries at it:
   ```bash
   .venv\Scripts\python -c "from shared import db; db.set_setting(db.open_db(), 'research_model', 'qwen2.5:3b')"
   ```
   (`topic_model` sets the model for page topics the same way; the default is `qwen2.5:3b`.)

Keep Ollama local-only: don't set `OLLAMA_HOST=0.0.0.0` or `OLLAMA_ORIGINS=*`. The
analyzer only ever calls `http://127.0.0.1:11434`, and checks the model's answers against a
fixed list or schema, falling back to keyword rules or templates if they don't match.

### 2. Tavily and Exa API keys

1. **Get the keys** (free tiers are enough):
   - Tavily: sign up at [tavily.com](https://tavily.com) and copy your API key (`tvly-…`).
   - Exa (optional): [exa.ai](https://exa.ai) → dashboard → API key.
2. **Store them.** Keys go into Windows Credential Manager / the macOS Keychain, never into a
   file in this repo. Paste each key when asked; nothing shows as you type.
   ```bash
   .venv\Scripts\python -m analyzer.research set-key tavily
   .venv\Scripts\python -m analyzer.research set-key exa
   ```
   Run `set-key` again to replace a key. To remove one, delete the **ShadowProfile**
   entry for it in Credential Manager (Windows Credentials) or Keychain Access.

### 3. Run the research

1. **Open the app once first** so it analyses your log. Research looks up the tracker
   companies found in your own traffic (the 50 most common).
2. **Check Settings → Zero-network mode is off.** When it's on, nothing is sent.
3. **Run:**
   ```bash
   .venv\Scripts\python -m analyzer.research refresh --top 50
   ```
   It prints `Researched N companies.` With the local AI on, this can take several minutes.
   Companies researched in the last 7 days are skipped, so run it again weekly.
4. **See the results:** reopen the app → **Report** → click a company to see its policy
   summary, data-broker status and news.
5. **Check what left your computer:** **Settings → What left this device** lists every
   query sent; there should be only company names. **Verify** confirms nobody edited the
   list.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No Tavily or Exa API key stored` | Run the `set-key` step above. |
| `Zero-network mode is on: nothing was sent.` | Turn off **Settings → Zero-network mode**. |
| `Researched 0 companies.` | No tracker companies found yet: open the app so it analyses your log, or use the computer for a while first. Also skipped: companies researched in the last 7 days. |
| `ollama pull` or `refresh` fails with a certificate or connection error | The recorder intercepted it, and the tool checks certificates against its own list. Run it again: after the first failure the recorder lets that app's traffic to that site through without decrypting it. |
| Topics or summaries look like keyword fallbacks | Make sure Ollama is running (tray icon), the model is pulled (`ollama list`), the setting is on, and you reopened the app afterwards. |

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

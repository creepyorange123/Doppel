# Shadow Profile

An audit tool for the apps on your computer. You say "I'll use Slack and Zoom as I
normally would for the next 30 minutes", and Doppel shows what those apps (and every
process they start) sent, and to whom. Everything runs locally; captured traffic never
leaves the device.

Doppel never monitors in the background. Outside an audit no Doppel process records
anything, and during one, only the apps you picked go through it: your VPN, ad blocker
and every other app talk to the network directly, untouched.

**Contents:** [Setup](#setup-phase-0-check) ·
[Audits](#audits) · [Scoring](#how-requests-are-scored) ·
[Local AI and company research](#local-ai-and-company-research-optional) ·
[Demo](#demo) · [Known gaps](#known-gaps)

## Layout

| Folder | Owner | What |
|---|---|---|
| `recorder/` | traffic & detection | mitmproxy (local capture mode) addon, run only for the length of an audit; captures just the audited apps' processes |
| `analyzer/` | traffic & detection, research | Python sidecar started by the app; creates audits, analyses them when they end (identify, score) |
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

- Nothing is recorded outside an audit, or from an app you didn't pick. No login item,
  no background service; an audit's recorder stops on its own at the end time, on Stop,
  or when Doppel quits. Every stored request carries its audit's id.
- Audits observe; they never change traffic (no blocking, stripping or added headers).
- The log is a SQLCipher-encrypted SQLite file in your user data folder; its key lives
  only in the macOS Keychain / Windows Credential Manager.
- Never store `Cookie`, `Set-Cookie`, `Authorization` values, passwords or login bodies.
  Identifiers are stored as keyed hashes (HMAC), never raw.
- Never store search queries or search-suggestion requests.
- Never store a destination that is only an IP address (refused HTTP/3 attempts included);
  the app's retry over HTTPS is recorded with its hostname.
- System-process traffic is never logged, and system processes can't be audited.
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

## Audits

1. **One-time setup.** The app's consent screen installs a certificate that only this
   computer trusts (its key stays in the Keychain / Credential Manager; it expires after 30
   days). macOS also asks you once to allow mitmproxy's network extension.
2. **Start an audit** on the **Audits** screen: tick the running apps to audit, choose
   *Full* or *Metadata only* for each, pick 15 min / 30 min / 1 h / 2 h, and press Start.
   Then use those apps as you normally would.
3. **Watch it live** (request counts per app, per process and per site), or stop early.
4. **When it ends**, Doppel analyses the audit and opens its report: companies, risk
   tiers, and a per-app breakdown of which processes sent what.

What an audit captures, and what it doesn't:

- **The app and everything inside its bundle**, e.g. `/Applications/Slack.app/` covers
  every Slack helper. This is matched by the OS redirector itself, so nothing is missed.
- **Processes the app starts outside its bundle** (`node`, `curl`, updaters) are found by
  walking the process tree five times a second (about 1 ms each time, macOS only for now),
  and stay in scope for as long as they live, even if they replace themselves with another
  program. A child that starts and connects within that fifth of a second can be missed.
- **Nothing else.** Other apps aren't redirected at all, so they keep using your VPN, ad
  blocker or DNS filter exactly as before, and cost Doppel nothing.
- Domains you mark **Never record** (Settings) are skipped in every audit.

**Browsers and apps are reported differently.** Doppel checks whether each audited app is a
browser (on macOS: it registers as an http/https handler; Electron apps like Discord, Slack
and VS Code don't). A browser's traffic is grouped by the **sites you visited** and the
companies each one loaded; the page a tracker came from is worked out only for browsers. Any
other app is grouped by **who it phones home to**: its maker's own servers (counted as first
party), bundled SDKs such as Sentry or Firebase, and trackers. Firefox-based browsers (Firefox,
Zen, LibreWolf) need `security.enterprise_roots.enabled` set to true in `about:config` to
trust Doppel's certificate; the app picker reminds you.

### Audit Doppel itself

**Privacy → Audit Doppel itself** runs a 2, 5 or 15 minute audit of Doppel's own
processes (the app window and the analyzer) while you keep using Doppel. The result
lists every connection they made and checks each one against the tamper-evident list of
outgoing calls (**Outgoing calls**): *clean* means every connection is a logged
company-name search, *no traffic* means there was none at all. Anything else is flagged.

### Command line

```bash
.venv/bin/python -m recorder install          # consent + certificate (the app does this for you)
.venv/bin/python -m recorder status           # certificate, running audit, leftover login item
.venv/bin/python -m recorder audit --id N     # what the app runs for audit N; stops at its end time
.venv/bin/python -m recorder rotate-ca        # replace the certificate (it expires after 30 days)
.venv/bin/python -m recorder uninstall [--wipe]
```

`install` and `uninstall` also remove the login item that older versions installed
(`~/Library/LaunchAgents/com.shadowprofile.recorder.plist`, or the Windows logon task / Run
key). Upgrading wipes requests recorded by the old always-on recorder; company research,
the outgoing-calls list and your domain rules are kept.

To add the local AI model and company research, see
[Local AI and company research](#local-ai-and-company-research-optional).

Hand checks: `.venv/bin/python -m analyzer.review export --n 100 labels.csv`, label the
`human_tier` column, then `.venv/bin/python -m analyzer.review report labels.csv`.

## How requests are scored

Every request gets a score from 0 to 100 and a tier, using the tiers and starting weights
from the original project plan. Scoring is plain rules on this computer; no AI is involved,
and each tier badge in the app opens the breakdown.

| Tier | Score | Meaning |
|---|---|---|
| Minimum utility | 0–19 | Needed for the page to work, no identifier that follows you |
| Measurement | 20–49 | Counts your visit or behaviour on one site, not across sites |
| Profile building | 50–79 | Links your activity across sites or ties it to an identity |
| High concern | 80–100 | Profile building plus sensitive context, personal identifiers or sharing |

### Block with your own tools

Doppel doesn't block anything itself: the tools people already trust do that better. Each
audit's **Overview** has a **Block them with your own tools** panel that turns what the audit
found into a ready-to-import list, at the risk level you pick:

| Format | Works with |
|---|---|
| Filter list (`\|\|doubleclick.net^`) | uBlock Origin (My filters), AdGuard (User rules), Brave custom filters |
| Domain list | NextDNS, Pi-hole, AdGuard Home, Cloudflare Gateway, Control D |
| `.lsrules` | Little Snitch (double-click to add as a rule group) |
| hosts file | `/etc/hosts`, Gas Mask, SwitchHosts |

Only tracker domains go in the list, never a site you visited in the audit. Filter-list
rules use `$third-party`, so `facebook.com` is blocked when another site loads it but not
when you open Facebook; DNS-level formats can't make that distinction, so they leave out
social and embedded-content sites and say which. It's built on
this computer and copied or saved to a file you choose; nothing is sent. Company cards also
offer the company's opt-out page (when research found one) and a data-access request letter.

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
| Metadata-only audit: known ad, social or broker tracker loaded by a page | +20 |
| The same ad, social or broker company on 2+ sites you visited in the audit (when no shared ID is visible) | +25 |
| Sensitive data inside the request: health, finance, sexuality, religion, children, politics, ethnicity (also triggers ×1.5) | +30 |
| Personal data inside the request: name, birth date, address, gender, ID numbers, precise location | +20 |
| Page still works without it / breaks without it (breakage probe) | +10 / −20 |

**Metadata-only audits** (an app set to *Metadata only*, or no certificate installed) can't see
IDs or the Referer. Doppel infers which page a tracker was loaded by from timing: a site's own
address (`www.healthline.com`), followed by more of that site's hosts, opens a page, and that
process's trackers in the next minute are attributed to it and labelled "probably". So a
Facebook pixel on Healthline scores as Profile building on a health page, not as a lone app call.

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

1. **Run an audit first.** Research looks up the tracker companies found in your own
   audits (the 50 most common).
2. **Check Settings → Zero-network mode is off.** When it's on, nothing is sent.
3. **Run:**
   ```bash
   .venv\Scripts\python -m analyzer.research refresh --top 50
   ```
   It prints `Researched N companies.` With the local AI on, this can take several minutes.
   Companies researched in the last 7 days are skipped, so run it again weekly.
4. **See the results:** reopen the app → **Companies** → click a company to see its policy
   summary, data-broker status and news.
5. **Check what left your computer:** **Settings → What left this device** lists every
   query sent; there should be only company names. **Verify** confirms nobody edited the
   list.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No Tavily or Exa API key stored` | Run the `set-key` step above. |
| `Zero-network mode is on: nothing was sent.` | Turn off **Settings → Zero-network mode**. |
| `Researched 0 companies.` | No tracker companies found yet: run an audit first. Also skipped: companies researched in the last 7 days. |
| An audited app shows certificate errors | It pins certificates or doesn't use the system trust store (Firefox-based browsers: set `security.enterprise_roots.enabled` to true; Node apps ignore the Keychain). After a few failures the audit switches that app to metadata only. |
| Topics or summaries look like keyword fallbacks | Make sure Ollama is running (tray icon), the model is pulled (`ollama list`), the setting is on, and you reopened the app afterwards. |

## Demo

```bash
.venv/bin/pip install -r requirements-demo.txt
.venv/bin/python -m playwright install chromium
.venv/bin/python -m demo.persona                 # during an audit of Playwright's Chromium
.venv/bin/python scripts/predemo_check.py        # before judging
.venv/bin/python scripts/predemo_check.py --after-uninstall
```

OS firewall rules are in `scripts/firewall/` (`shadow-profile.lsrules` for macOS,
`windows-firewall.ps1` for Windows); review them, then apply them yourself.

## Known gaps

- Packaging (electron-builder + PyInstaller, signed binaries in a non-user-writable
  folder) is not set up; in development audits run the venv's Python.
- Process-tree tracking is macOS only; on Windows an audit covers the app's own folder.
  A spawned process that connects within ~0.2 s of starting can be missed (see Audits).
- Safari's page loads go through shared WebKit system processes, so Safari can't be
  audited; audit Chrome, Firefox or another browser instead.
- Windows local capture starts mitmproxy's own elevated redirector (UAC prompt per
  audit); parsing stays in the unprivileged recorder process.
- The bundled tracker map is a curated ~120-domain subset; rebuild from Tracker Radar
  with `scripts/build_tracker_db.py`. The bundled research snapshot is signed but empty
  until a pre-fetch run is signed for release.
- Windows Firewall cannot restrict one program to specific HTTPS hosts; the egress gate
  and ledger enforce that, see `scripts/firewall/windows-firewall.ps1`.

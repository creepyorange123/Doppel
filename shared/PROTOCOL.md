# Analyzer ⇄ App message format

The Electron main process starts the analyzer as a sidecar (`python -m analyzer`)
and talks to it over the child process's **stdin/stdout pipes**. Nothing listens on
a network port, so no website can reach the analyzer through `localhost`
(security checklist #3). The renderer never talks to the analyzer directly: it calls
`window.shadow.request(...)` exposed by the preload script, and the main process
forwards only the message types on its allowlist.

## Framing

- UTF-8 JSON, **one message per line** (`\n`-delimited). Max line: 1 MB.
- stderr is for the analyzer's own diagnostics only and must never contain
  captured content.

## Messages

App → analyzer (request):

```json
{"id": 7, "type": "status", "payload": {}}
```

Analyzer → app (reply to a request, exactly one per `id`):

```json
{"id": 7, "type": "result", "payload": {...}}
{"id": 7, "type": "error",  "payload": {"code": "unknown_type", "message": "..."}}
```

Analyzer → app (event, not tied to a request; no `id`):

```json
{"type": "progress", "payload": {"done": 120, "total": 1240, "label": "Analyzing 1,240 requests from your Slack audit"}}
{"type": "ready",    "payload": {"version": "0.2.0"}}
```

## Audits

Doppel records nothing in the background. You start an **audit**: pick running apps
and a duration. For that time only, the recorder captures traffic from those apps
and every process they spawn; everything else on the computer goes straight to the
network untouched. When the audit ends the recorder process exits.

An `Audit` is `{id, label, apps: [{path, name, capture: "full"|"metadata_only", is_browser}],
self_audit, started_at, ends_at, ended_at, status: "running"|"done"|"interrupted"|"failed",
requests, analyzed, error}`.

## Request types

| type | payload | result |
|---|---|---|
| `hello` | `{}` | `{version, db_path_set}` |
| `status` | `{}` | `{request_count, unanalyzed_count, install_at, consent_at, active_audit_id}` |
| `list_running_apps` | `{}` | `{apps: [{path, name, processes, is_browser, hint}]}`: visible, non-system apps running now, helpers folded into their app |
| `list_audits` | `{}` | `{audits: [Audit]}`, newest first |
| `audit_live` | `{audit_id}` | `{audit, requests, last_at, apps: [{name, requests}], processes: [{app, process, requests}], domains: [{domain, requests}]}` |
| `analyze_audit` | `{audit_id?}` | `{analyzed, audit_id, finished_at}`; streams `progress`. No id: every unanalysed request |
| `delete_audit` | `{audit_id}` | `{deleted}` (requests removed with it) |
| `self_audit_result` | `{audit_id}` | `{audit, connections: [{process, domain, requests, in_ledger}], ledger_entries, unexpected, verdict}` |
| `list_domain_rules` | `{}` | `{domains: [{domain, rule}]}` |
| `set_domain_rule` | `{domain, rule: "metadata_only"\|"dont_track"\|null}` | `{ok}` |
| `get_settings` | `{}` | `{zero_network, local_ai, california}` |
| `set_setting` | `{key: zero_network\|local_ai\|california, value: bool}` | `{ok}` |
| `ledger_verify` | `{}` | `{ok, entries, broken_at, latest_hash}` |
| `ledger_list` | `{}` | `{entries: [{id, sent_at, destination, payload, hash}], latest_hash}` |
| `report` | `{audit_id}` | `{audit, summary: {requests, companies, high_concern}, apps: [{name, is_browser, requests, companies, max_score, tier, processes: [{name, requests}], sites? (browsers), destinations? (apps): [{name, requests, companies, max_score, tier, own?}]}], companies: [...], tier_requests, by_day}` |
| `list_requests` | `{audit_id, limit?}` (default 1000) | `{requests: [{id, captured_at, app_name, process_name, dest_domain, company, summary, topic, sensitive, score, tier, breakdown}], truncated}` |
| `company_detail` | `{company, audit_id}` | `{card, requests, actions, california}` |
| `take_action` | `{company, action: opt-out\|letter}` | `{ok, letter?}` |
| `export_blocklist` | `{audit_id, format: ublock\|hosts\|domains\|little_snitch, min_tier?}` (default Profile building) | `{format, min_tier, domains, count, works_with, skipped, filename, content}`: tracker domains for your own blocker, never a site you visited |
| `privacy_checks` | `{}` | `{checks: [{id, title, ok, detail}], ran_at, passed, failed}` |

Main process only (the renderer is refused; see `MAIN_ONLY_REQUEST_TYPES`):

| type | payload | result |
|---|---|---|
| `create_audit` | `{apps: [{path, name, capture?, pids?}], minutes, label?, self_audit?}` | `{audit}` |
| `finish_audit` | `{audit_id, status: "done"\|"interrupted"\|"failed", error?}` | `{audit}` (no change if already finished) |

## Main-process channels

- `shadow:audit` (`window.shadow.audit(action, payload)`): `start {apps, minutes, label?}`,
  `self {minutes}`, `stop`, `state`, each returning `{ok, audit, error?}`. The main process
  creates the audit, runs `python -m recorder audit --id N` as its child, and stops it at the
  end time, on `stop`, or when Doppel quits. It sends `{type: "audit", payload: {audit_id,
  state: "started"|"ended", ok, message?}}` events.
- `shadow:save` (`window.shadow.saveFile(filename, content)`): shows a save dialog and writes
  the text (at most 1 MB) to the file the user picks; used to save exported blocklists.
- `shadow:recorder` (`window.shadow.recorder(action)`): `install` (consent + certificate),
  `uninstall`, `status`.

Every new type is added to `shared/protocol.py`, `app/src/shared/protocol.ts` (which is
the main process allowlist) and `analyzer/handlers.py` together.

Both sides treat captured text as untrusted data: the renderer never renders it as
HTML (security checklist #5).

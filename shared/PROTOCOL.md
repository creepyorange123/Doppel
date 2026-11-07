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
{"type": "progress", "payload": {"done": 120, "total": 1240, "label": "Analyzing 1,240 requests since Tuesday 9:14 pm"}}
{"type": "ready",    "payload": {"version": "0.1.0"}}
```

## Request types

| type | payload | result |
|---|---|---|
| `hello` | `{}` | `{version, db_path_set}` |
| `status` | `{}` | `{request_count, unanalyzed_count, install_at, last_opened_at, recorder_heartbeat_at, consent_at}` |
| `list_apps` | `{}` | `{mode, apps: [{key, path, name, requests, last_seen_at, running, rule, rule_source}], domains: [{domain, rule}]}` |
| `set_app_rule` | `{key, rule: "track"\|"metadata_only"\|"dont_track"\|null}` | `{ok}` |
| `set_domain_rule` | `{domain, rule \| null}` | `{ok}` |
| `set_tracking_mode` | `{mode: "blocklist"\|"allowlist"}` | `{ok}` |
| `delete_app_data` | `{key}` | `{deleted}` |

| `analyze_since_last_open` | `{}` | `{analyzed, since, finished_at}`; streams `progress` events |
| `get_settings` | `{}` | `{zero_network, gpc, local_ai, california, tracking_mode}` |
| `set_setting` | `{key: zero_network\|gpc\|local_ai\|california, value: bool}` | `{ok}` |
| `ledger_verify` | `{}` | `{ok, entries, broken_at, latest_hash}` |
| `ledger_list` | `{}` | `{entries: [{id, sent_at, destination, payload, hash}], latest_hash}` |
| `report` | `{}` | `{summary: {since, requests, companies, high_concern}, companies: [...]}` |
| `company_detail` | `{company}` | `{card, requests: [{..., score, tier, breakdown}], actions, california}` |
| `take_action` | `{company, action: block\|strip\|opt-out\|letter}` | `{ok, letter?, domains?}` |
| `undo_action` | `{company, action: block\|strip}` | `{ok}` |

Recorder controls (`install`, `uninstall`, `status`) are not analyzer messages: the
main process runs `python -m recorder <action>` itself, on the `shadow:recorder` channel.

Every new type is added to `shared/protocol.py`, `app/src/shared/protocol.ts` (which is
the main process allowlist) and `analyzer/handlers.py` together.

Both sides treat captured text as untrusted data: the renderer never renders it as
HTML (security checklist #5).
